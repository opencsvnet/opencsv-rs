//! Receiver verification driver `Accept` (paper §4.8) and the proof-verifier
//! seam where `opencsv-pcd` plugs in.
//!
//! The driver retains chain I/O, proof verification, key-derived ownership
//! and output construction. It projects those observations into
//! [`opencsv_kernel::accept`], the pure deterministic accept/reject boundary.

use std::collections::HashSet;

use opencsv_kernel::accept as accept_kernel;

use crate::anchor::{binding, nullifier_commit, AnchorRecord};
use crate::asset::AssetId;
use crate::chain::{AnchorChain, AnchorLocation};
use crate::coin::{Coin, OwnerSecret};
use crate::consignment::{CoinOpening, Consignment};
use crate::digest::{Digest, TruncatedDigest};

/// Verification of a transaction validity proof `π` against the predicate's
/// verification key and public input (paper §4.1: `Π.Verify(vk, x, π)`).
///
/// This trait is the seam where the AIR/FRI-based PCD engine (`opencsv-pcd`)
/// plugs in: it will supply an implementation backed by real recursive
/// proofs over BabyBear.
pub trait ProofVerifier {
    /// Return `true` iff `proof` attests the predicate `vk` on public input
    /// `public_input`.
    fn verify(&self, vk: &[u8], public_input: &[u8], proof: &[u8]) -> bool;
}

/// A **mock** verifier for tests and prototypes — NOT a proof system.
///
/// A "proof" is `public_input ∥ checksum(4 bytes)` where `checksum` is the
/// 32-bit FNV-1a hash of `vk ∥ public_input`. It checks nothing but internal
/// consistency of the message; it provides zero soundness. Do not use outside
/// tests.
pub struct MockVerifier;

impl MockVerifier {
    /// Produce a mock "proof" that [`MockVerifier`] accepts (test helper).
    pub fn prove(vk: &[u8], public_input: &[u8]) -> Vec<u8> {
        let mut proof = public_input.to_vec();
        proof.extend_from_slice(&Self::checksum(vk, public_input).to_le_bytes());
        proof
    }

    fn checksum(vk: &[u8], public_input: &[u8]) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        for b in vk.iter().chain(public_input) {
            h = (h ^ u32::from(*b)).wrapping_mul(0x0100_0193);
        }
        h
    }
}

impl ProofVerifier for MockVerifier {
    fn verify(&self, vk: &[u8], public_input: &[u8], proof: &[u8]) -> bool {
        let Some((pi, sum)) = proof.split_at_checked(public_input.len()) else {
            return false;
        };
        pi == public_input && sum == Self::checksum(vk, public_input).to_le_bytes()
    }
}

/// Parameters the recipient brings to [`accept`] (application-level policy,
/// paper §4.7–4.8).
pub struct AcceptParams<'a> {
    /// Verification key of the transaction predicate being claimed.
    pub vk: &'a [u8],
    /// Required confirmation depth `k` (paper §4.7 rule 2; default 6).
    pub required_confirmations: u64,
    /// The recipient's owner secrets, for the ownership check (step 4).
    pub recipient_secrets: &'a [OwnerSecret],
    /// Assets already pinned by this client. If an opening names an asset not
    /// in this list, the consignment must carry matching genesis `aux`.
    pub known_assets: &'a [AssetId],
}

/// The coins credited by a successful [`accept`] (paper §4.8 step 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedCoins {
    /// The recipient's own outputs among the consignment's openings.
    pub coins: Vec<Coin>,
    /// Where the transaction's anchor sits on-chain.
    pub anchor: AnchorLocation,
}

/// Why a consignment was rejected (paper §4.8 steps 1–4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// The consignment carries no coin openings.
    EmptyConsignment,
    /// `aux` genesis does not recompute to the openings' asset ID (step 1).
    GenesisMismatch,
    /// An opening names an asset the client has not pinned, and no (matching)
    /// genesis `aux` was supplied (step 1).
    UnknownAsset,
    /// No anchor record exists at the referenced location / txid (step 3a).
    AnchorNotFound,
    /// The anchor is not buried under `k` confirmations (step 3, rule 2).
    InsufficientConfirmations {
        /// Confirmations the anchor actually has.
        have: u64,
        /// Confirmations required by policy.
        required: u64,
    },
    /// A nullifier of this transaction already occurred *earlier* on
    /// chain — the anchor shown is not the authoritative spend (step 3b,
    /// paper §4.7 rule 1).
    NullifierConflict {
        /// The conflicting nullifier (truncated raw nullifier, or the
        /// nullifier commitment for compressed transfers).
        nullifier: TruncatedDigest,
        /// The first (authoritative) occurrence.
        first: AnchorLocation,
    },
    /// The anchor record does not bind the consignment's raw nullifiers
    /// under the anchor's transaction context — e.g. a byte-copied
    /// (copy-grief) record, whose payloads are bound to the victim's ctx
    /// (step 3a, amended; see [`crate::anchor`]).
    IllFormedAnchor,
    /// `Π.Verify(vk, x, π) = 0` (step 2).
    InvalidProof,
    /// None of the openings belongs to any of the recipient's keys (step 4).
    NoOwnedOutput,
}

impl RejectReason {
    /// Stable machine-readable code for logs, FFI and durable operation
    /// records. The human-readable [`std::fmt::Display`] text may evolve;
    /// these values do not.
    pub const fn code(self) -> &'static str {
        match self {
            Self::EmptyConsignment => "empty_consignment",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::UnknownAsset => "unknown_asset",
            Self::AnchorNotFound => "anchor_not_found",
            Self::InsufficientConfirmations { .. } => "insufficient_confirmations",
            Self::NullifierConflict { .. } => "nullifier_conflict",
            Self::IllFormedAnchor => "ill_formed_anchor",
            Self::InvalidProof => "invalid_proof",
            Self::NoOwnedOutput => "no_owned_output",
        }
    }
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyConsignment => write!(f, "consignment has no coin openings"),
            Self::GenesisMismatch => write!(f, "genesis aux does not match openings' asset ID"),
            Self::UnknownAsset => write!(f, "unknown asset and no genesis aux supplied"),
            Self::AnchorNotFound => write!(f, "anchor not found at the referenced location"),
            Self::InsufficientConfirmations { have, required } => {
                write!(f, "anchor has {have} confirmations, need {required}")
            }
            Self::NullifierConflict { first, .. } => {
                write!(f, "nullifier already occurred earlier at {first:?}")
            }
            Self::IllFormedAnchor => {
                write!(
                    f,
                    "anchor record is not bound to its transaction context (ill-formed)"
                )
            }
            Self::InvalidProof => write!(f, "transaction proof did not verify"),
            Self::NoOwnedOutput => write!(f, "no opening belongs to the recipient"),
        }
    }
}

impl std::error::Error for RejectReason {}

/// Reconstruct the proof public input `x` from the anchor's transaction
/// context, the on-chain anchor record, and the consignment's openings
/// (paper §4.8 step 2): `ctx(32) ∥ anchor_bytes(64) ∥ opening_1 ∥ … ∥
/// opening_n`, each opening encoded as `asset_id(32) ∥ v(8) ∥ owner(32) ∥
/// r(32)`. The context is included so the proof verifier can recompute the
/// bound payloads `H("bind" ∥ nf ∥ ctx)` against the anchor's slots.
pub fn public_input(record: &AnchorRecord, ctx: &[u8; 32], openings: &[CoinOpening]) -> Vec<u8> {
    let mut x = Vec::with_capacity(96 + 104 * openings.len());
    x.extend_from_slice(ctx);
    x.extend_from_slice(&record.to_bytes());
    for opening in openings {
        x.extend_from_slice(&opening.to_public_input_bytes());
    }
    x
}

/// The receiver verification algorithm `Accept` (paper §4.8, steps 1–5).
///
/// Steps: (1) parse/type-check and pin-or-reject genesis aux; (2) proof
/// check via [`ProofVerifier`]; (3) anchor existence, confirmation depth,
/// binding of the consignment's raw nullifiers into the anchor record, and
/// nullifier first-occurrence; (4) ownership check; (5) credit the
/// recipient's coins.
pub fn accept<V: ProofVerifier, C: AnchorChain>(
    consignment: &Consignment,
    chain: &C,
    verifier: &V,
    params: &AcceptParams,
) -> Result<AcceptedCoins, RejectReason> {
    let openings = &consignment.coin_openings;
    reject_if(accept_kernel::preflight_rejection(
        !openings.is_empty(),
        accept_kernel::AssetObservation::Valid,
    ))?;

    // Step 1 — parse & type-check. If genesis aux is present it must
    // recompute to the openings' asset ID; otherwise the asset must already
    // be pinned. (Pinning itself, including any user confirmation for new
    // assets, is client UX outside this crate.)
    let asset_ids: HashSet<AssetId> = openings.iter().map(|o| o.asset_id).collect();
    let asset = match &consignment.aux {
        Some(genesis) => {
            let id = genesis.asset_id();
            if asset_ids.iter().any(|a| *a != id) {
                accept_kernel::AssetObservation::GenesisMismatch
            } else {
                accept_kernel::AssetObservation::Valid
            }
        }
        None => {
            if asset_ids.iter().any(|a| !params.known_assets.contains(a)) {
                accept_kernel::AssetObservation::UnknownAsset
            } else {
                accept_kernel::AssetObservation::Valid
            }
        }
    };
    reject_if(accept_kernel::preflight_rejection(true, asset))?;

    // Anchor lookup (step 3a, performed before the proof check because the
    // public input is reconstructed from the on-chain record and its
    // transaction context).
    let record = chain
        .anchor_at(&consignment.anchor_ref)
        .ok_or_else(|| from_kernel_rejection(accept_kernel::RejectReason::AnchorNotFound))?;
    let ctx = chain
        .ctx_at(&consignment.anchor_ref)
        .ok_or_else(|| from_kernel_rejection(accept_kernel::RejectReason::AnchorNotFound))?;
    // The canonical location: for backends that anchor into a mempool
    // (bitcoind), the consignment's claimed location is a placeholder and
    // the chain resolves the confirmed position by transaction ID.
    let location = chain
        .locate(&consignment.anchor_ref)
        .ok_or_else(|| from_kernel_rejection(accept_kernel::RejectReason::AnchorNotFound))?;

    // Step 2 — proof check.
    let x = public_input(&record, &ctx, openings);
    let proof_valid = verifier.verify(params.vk, &x, &consignment.proof);
    reject_if(accept_kernel::proof_rejection(proof_valid))?;

    // Step 3 — anchor check: confirmation depth (paper §4.7 rule 2), then
    // the binding and occurrence checks for the consignment's raw
    // nullifiers (paper §4.7 rule 1, amended; see `crate::anchor`).
    let have = chain.confirmations_at(location.height);
    reject_if(accept_kernel::chain_prefix_rejection(
        have,
        params.required_confirmations,
        true,
    ))?;

    // (a) The anchor record must bind exactly the consignment's raw
    // nullifiers under the anchor's ctx: every `H("bind" ∥ nf ∥ ctx)`
    // matches a payload slot, and the record carries no unmatched slots
    // (completeness — a consignment may not smuggle a spend past the
    // occurrence check by omitting one of the record's nullifiers). A
    // byte-copy of the record under a different ctx fails here: the copy's
    // payloads are bound to the victim's ctx, not the copier's.
    let binds_nullifiers = record_binds_nullifiers(&record, &ctx, &consignment.nullifiers);
    reject_if(accept_kernel::chain_prefix_rejection(
        have,
        params.required_confirmations,
        binds_nullifiers,
    ))?;

    // (b) No EARLIER record may bind any of these nullifiers: the first
    // occurrence of each occurrence key (recognized via the binding, see
    // `crate::chain`) must be this anchor. Compressed transfers are
    // recognized under their nullifier commitment, like on-chain.
    let occurrence_keys: Vec<Digest> = match &record {
        // Batch headers carry no on-chain payload slots: their
        // occurrences live in the witness envelope (see `crate::batch`),
        // which the consignment format does not yet name — a consignment
        // pointing at a batch header has no occurrence keys to check.
        AnchorRecord::Mint { .. } | AnchorRecord::BatchHeader { .. } => vec![],
        AnchorRecord::Xfer { .. } | AnchorRecord::Redeem { .. } => consignment.nullifiers.clone(),
        AnchorRecord::XferCompressed { .. } => {
            vec![nullifier_commit(&consignment.nullifiers)]
        }
    };
    let kernel_location = crate::kernel::location(&location);
    let mut occurrences = Vec::with_capacity(occurrence_keys.len());
    for key in &occurrence_keys {
        let first = chain.first_nullifier_occurrence(key);
        let observation = accept_kernel::OccurrenceObservation {
            nullifier: key.to_anchor().0,
            first: first.as_ref().map(crate::kernel::location),
        };
        occurrences.push(observation);
        reject_if(accept_kernel::occurrence_rejection(
            kernel_location,
            std::slice::from_ref(&observation),
        ))?;
    }

    // Step 4 — ownership check.
    let owners: HashSet<_> = params.recipient_secrets.iter().map(|s| s.owner()).collect();
    let coins: Vec<Coin> = openings
        .iter()
        .filter(|o| owners.contains(&o.owner))
        .map(CoinOpening::to_coin)
        .collect();
    // Step 5 — the pure kernel is the authoritative decision boundary. The
    // trait-heavy driver above owns all I/O and cryptographic work and passes
    // only explicit observations into this deterministic function.
    let input = accept_kernel::AcceptInput {
        has_openings: true,
        asset,
        anchor: accept_kernel::AnchorObservation::Present {
            location: kernel_location,
            confirmations: have,
            binds_nullifiers,
            occurrences,
        },
        proof_valid,
        required_confirmations: params.required_confirmations,
        has_owned_output: !coins.is_empty(),
    };
    match accept_kernel::decide(&input) {
        accept_kernel::AcceptDecision::Accept { .. } => Ok(AcceptedCoins {
            coins,
            anchor: location,
        }),
        accept_kernel::AcceptDecision::Reject(reason) => Err(from_kernel_rejection(reason)),
    }
}

fn reject_if(reason: Option<accept_kernel::RejectReason>) -> Result<(), RejectReason> {
    match reason {
        Some(reason) => Err(from_kernel_rejection(reason)),
        None => Ok(()),
    }
}

fn from_kernel_rejection(reason: accept_kernel::RejectReason) -> RejectReason {
    match reason {
        accept_kernel::RejectReason::EmptyConsignment => RejectReason::EmptyConsignment,
        accept_kernel::RejectReason::GenesisMismatch => RejectReason::GenesisMismatch,
        accept_kernel::RejectReason::UnknownAsset => RejectReason::UnknownAsset,
        accept_kernel::RejectReason::AnchorNotFound => RejectReason::AnchorNotFound,
        accept_kernel::RejectReason::InsufficientConfirmations { have, required } => {
            RejectReason::InsufficientConfirmations { have, required }
        }
        accept_kernel::RejectReason::NullifierConflict { nullifier, first } => {
            RejectReason::NullifierConflict {
                nullifier: TruncatedDigest(nullifier),
                first: AnchorLocation {
                    height: first.height,
                    position: first.position,
                },
            }
        }
        accept_kernel::RejectReason::IllFormedAnchor => RejectReason::IllFormedAnchor,
        accept_kernel::RejectReason::InvalidProof => RejectReason::InvalidProof,
        accept_kernel::RejectReason::NoOwnedOutput => RejectReason::NoOwnedOutput,
    }
}

/// Check (a) of [`accept`]: does `record` bind exactly `raw_nullifiers`
/// under `ctx`? Mint anchors bind none; XFERC anchors bind the commitment
/// over the whole raw list (occurrence queries then use the commitment as
/// the key, see below); XFER/REDEEM bind each nullifier individually.
fn record_binds_nullifiers(
    record: &AnchorRecord,
    ctx: &[u8; 32],
    raw_nullifiers: &[Digest],
) -> bool {
    let bound = |nf: &Digest| binding(nf, ctx).to_anchor();
    match record {
        // Batch headers bind no nullifiers on-chain (witness envelope).
        AnchorRecord::Mint { .. } | AnchorRecord::BatchHeader { .. } => raw_nullifiers.is_empty(),
        AnchorRecord::Redeem { payload, .. } => {
            raw_nullifiers.len() == 1 && bound(&raw_nullifiers[0]) == *payload
        }
        AnchorRecord::XferCompressed {
            nullifier_commit: slot,
        } => !raw_nullifiers.is_empty() && bound(&nullifier_commit(raw_nullifiers)) == *slot,
        AnchorRecord::Xfer { payloads } => {
            // Multiset equality: the non-zero payload slots are exactly the
            // bound nullifiers.
            let mut slots: Vec<_> = payloads
                .iter()
                .copied()
                .filter(|p| *p != TruncatedDigest([0u8; 24]))
                .collect();
            let mut nfs: Vec<_> = raw_nullifiers.iter().map(bound).collect();
            slots.sort();
            nfs.sort();
            !nfs.is_empty() && slots == nfs
        }
    }
}
