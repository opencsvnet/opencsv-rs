//! On-chain anchor records (paper §4.4–4.7, amended: bound payloads).
//!
//! Every anchor serializes to exactly [`ANCHOR_SIZE`] (64) bytes, carried in
//! an OP_RETURN (or equivalent data-carrier output) of an ordinary Bitcoin
//! transaction. Digests are carried as 24-byte [`TruncatedDigest`] prefixes
//! (see [`crate::digest`]); multi-byte integers are little-endian.
//!
//! ## Bound payloads (anti-grief)
//!
//! Anchor records are copyable bytes: a mempool spy can copy a record into
//! their own transaction and get it mined first, and a naive
//! first-occurrence rule (paper §4.7 rule 1) would then treat the *copy* as
//! the authoritative spend, freezing the victim's coins. Binding the record
//! to its transaction context via a *sidecar* hash does not help: any
//! sidecar `B = H(nf ∥ ctx)` is publicly recomputable from the on-chain
//! `nf`, so the spy can simply forge a "well-formed" record. Instead, the
//! on-chain nullifier payload **is** the bound value:
//!
//! ```text
//! P = H("bind" ∥ raw_nf ∥ ctx)
//! ```
//!
//! where `ctx` (32 bytes) identifies the anchor transaction's context — in
//! production the funding input's outpoint; in the mock/file chains a
//! synthetic outpoint chosen by the anchoring party before the record is
//! constructed (see [`crate::chain`]). The **raw nullifier never appears
//! on-chain**; it travels in the consignment (it is already part of the PCD
//! statement, which is off-chain). A byte-copied record therefore publishes
//! a payload bound to the *victim's* `ctx`: it is not an occurrence of the
//! nullifier under the copier's `ctx`, and a consignment pointing at the
//! copy fails the accept driver's binding check (see [`crate::accept`]).
//! And because `ctx` is committed inside `P`, the spy cannot rebind the
//! payload without knowing `raw_nf` — which only the consignment holders
//! have. Occurrence recognition is likewise restricted to consignment
//! holders (see [`crate::chain`]); that privacy is intended.
//!
//! ## Camouflage
//!
//! Transfer records (XFER/XFERC) are **untagged**: opaque 64-byte strings,
//! indistinguishable from arbitrary OP_RETURN traffic. MINT and REDEEM keep
//! their tag bytes because they are intentionally public — the supply audit
//! (paper §4.9) must recognize them — so tagging them costs no privacy,
//! while tagging transfers would mark exactly the traffic that wants to be
//! private.
//!
//! Layouts:
//!
//! ```text
//! MINT   [0x01][asset_id:24][V:8][mint_commit:24][pad:7]   (§4.4, unchanged)
//! XFER   [P_1:24][P_2:24][pad:16]                          (§4.5, m ≤ 2, untagged)
//! XFERC  [P:24][0:24][pad:16]                              (§4.5, m > 2, untagged)
//! REDEEM [0x04][asset_id:24][V:8][P:24][pad:7]             (§4.6)
//! ```
//!
//! XFER carries one bound payload per consumed coin (`P_2 = 0` when `m =
//! 1`); XFERC carries the single bound nullifier commitment `P = H("bind" ∥
//! nf_commit ∥ ctx)` for `m > 2` inputs, the full nullifier list travelling
//! in the consignment.
//!
//! ## Parsing
//!
//! If the first byte is a known tag (MINT/REDEEM) *and* the tagged record's
//! padding is valid, the record parses as tagged; anything else parses as an
//! untagged transfer candidate. Parsing never fails: any 64-byte string is
//! at worst an untagged transfer candidate (arbitrary OP_RETURN traffic must
//! parse for the camouflage to hold). XFER and XFERC share one layout, so
//! parsing cannot tell bound nullifiers from a bound commitment (the
//! consignment resolves which it is); [`AnchorRecord::from_bytes`] yields
//! [`AnchorRecord::Xfer`] for both and consumers must treat the payload
//! slots generically.
//!
//! One wrinkle: a transfer whose first payload byte collides with the
//! MINT/REDEEM tags (~0.8%) is byte-wise a valid tagged record and misparses
//! for *every* verifier. Because the anchoring party chooses `ctx` freely,
//! it SHOULD simply redraw `ctx` until the bound payload avoids the tag
//! bytes (the CLI does this); a production deployment should enforce the
//! same at anchor time.

use crate::asset::AssetId;
use crate::coin::Nullifier;
use crate::digest::{Digest, TruncatedDigest, TRUNCATED_DIGEST_BYTES};
use crate::field::{bytes_to_felts, hash_felts};

/// Exact byte length of every serialized anchor record.
pub const ANCHOR_SIZE: usize = 64;

const TAG_MINT: u8 = 0x01;
const TAG_REDEEM: u8 = 0x04;
const TAG_BATCH: u8 = 0x05;

/// `mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce)` (paper §4.4).
pub fn mint_commit(asset_id: &AssetId, value: u64, mint_nonce: &Digest) -> Digest {
    hash_felts(
        "mint",
        &[
            &asset_id.to_elems(),
            &crate::field::u64_to_felts(value),
            &mint_nonce.to_elems(),
        ],
    )
}

/// `nf_commit = H("xfer" ∥ nf_1 ∥ … ∥ nf_m)` — the hash-compressed nullifier
/// payload for transfers with `m > 2` consumed coins (paper §4.5). The full
/// nullifier list travels in the consignment.
pub fn nullifier_commit(nullifiers: &[Nullifier]) -> Digest {
    let elems: Vec<p3_baby_bear::BabyBear> =
        nullifiers.iter().flat_map(|nf| nf.to_elems()).collect();
    hash_felts("xfer", &[&elems])
}

/// `P = H("bind" ∥ raw ∥ ctx)` — the transaction-context binding of a raw
/// nullifier (or nullifier commitment) under context `ctx` (see module
/// docs). Records carry the 24-byte prefix ([`Digest::to_anchor`]) of this
/// digest as their payload; the raw value never appears on-chain.
pub fn binding(raw: &Digest, ctx: &[u8; 32]) -> Digest {
    hash_felts("bind", &[&raw.to_elems(), &bytes_to_felts(ctx)])
}

/// An OpenCSV anchor record (paper §4.4–4.6, amended: bound payloads).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorRecord {
    /// `MINT ∥ asset_id ∥ V ∥ mint_commit` — transparent mint (§4.4).
    Mint {
        /// Asset being minted.
        asset_id: TruncatedDigest,
        /// Total minted value `V = Σ v_i` (public).
        value: u64,
        /// `H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`, binding the mint nonce.
        mint_commit: TruncatedDigest,
    },
    /// `P_1 ∥ P_2` — shielded transfer consuming `m ≤ 2` coins (§4.5).
    /// Untagged (camouflage): 64 opaque bytes, see module docs. `P_i =
    /// H("bind" ∥ nf_i ∥ ctx)`; the second slot is zero when `m = 1`.
    Xfer {
        /// Bound nullifier payloads of the consumed coins, in statement
        /// order; `payloads[1]` is zero for single-input transfers.
        payloads: [TruncatedDigest; 2],
    },
    /// `P ∥ 0` — shielded transfer with `m > 2` inputs, the nullifier list
    /// hash-compressed to fit the 64-byte budget (§4.5). `P = H("bind" ∥
    /// nf_commit ∥ ctx)`. Same untagged layout as [`AnchorRecord::Xfer`];
    /// parsing cannot tell the two apart.
    XferCompressed {
        /// Bound commitment to the full nullifier list (the raw list is
        /// carried in the consignment).
        nullifier_commit: TruncatedDigest,
    },
    /// `[0x05][count][batch_commit]` — a batch header committing to N
    /// witness-carried payloads (see [`crate::batch`]). Tagged: batch
    /// transactions are intentionally recognizable (the payloads ride
    /// the witness envelope, so the header is all an OP_RETURN scanner
    /// sees). Carries no payload slots — occurrences live in the
    /// witness envelope.
    BatchHeader {
        /// Number of payloads in the batch (`count` of the envelope).
        count: u8,
        /// `H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)`, committing to the full
        /// witness envelope.
        batch_commit: TruncatedDigest,
    },
    /// `REDEEM ∥ asset_id ∥ V ∥ P` — transparent burn back to the issuer
    /// (§4.6). Tagged (public by design, for the supply audit). `P =
    /// H("bind" ∥ nf ∥ ctx)`.
    Redeem {
        /// Asset being redeemed.
        asset_id: TruncatedDigest,
        /// Redeemed value `V` (public at burn time).
        value: u64,
        /// Bound nullifier payload of the destroyed coin.
        payload: TruncatedDigest,
    },
}

impl AnchorRecord {
    /// An [`AnchorRecord::Xfer`] binding `raw_nullifiers` (1–2 of them) to
    /// transaction context `ctx`.
    pub fn xfer(raw_nullifiers: &[Digest], ctx: &[u8; 32]) -> Self {
        assert!(
            (1..=2).contains(&raw_nullifiers.len()),
            "XFER carries 1–2 bound nullifiers"
        );
        let bound = |nf: &Digest| binding(nf, ctx).to_anchor();
        Self::Xfer {
            payloads: [
                bound(&raw_nullifiers[0]),
                raw_nullifiers
                    .get(1)
                    .map_or(TruncatedDigest([0u8; 24]), bound),
            ],
        }
    }

    /// An [`AnchorRecord::XferCompressed`] binding the nullifier commitment
    /// `raw_nf_commit` (see [`nullifier_commit`]) to transaction context
    /// `ctx`.
    pub fn xfer_compressed(raw_nf_commit: &Digest, ctx: &[u8; 32]) -> Self {
        Self::XferCompressed {
            nullifier_commit: binding(raw_nf_commit, ctx).to_anchor(),
        }
    }

    /// A [`AnchorRecord::BatchHeader`] committing to the batch envelope
    /// `payloads` under transaction context `ctx` (see [`crate::batch`]).
    pub fn batch_header(payloads: &[TruncatedDigest], ctx: &[u8; 32]) -> Self {
        assert!(
            !payloads.is_empty() && payloads.len() <= u8::MAX as usize,
            "a batch carries 1–255 payloads"
        );
        Self::BatchHeader {
            count: payloads.len() as u8,
            batch_commit: crate::batch::batch_commit(payloads, ctx).to_anchor(),
        }
    }

    /// An [`AnchorRecord::Redeem`] binding `raw_nf` to transaction context
    /// `ctx`.
    pub fn redeem(asset_id: TruncatedDigest, value: u64, raw_nf: &Digest, ctx: &[u8; 32]) -> Self {
        Self::Redeem {
            asset_id,
            value,
            payload: binding(raw_nf, ctx).to_anchor(),
        }
    }

    /// The on-chain payload slots this record carries (bound values; MINT
    /// has none, XFERC's second slot is always zero and omitted; batch
    /// headers carry none — occurrences live in the witness envelope).
    pub fn payload_slots(&self) -> Vec<TruncatedDigest> {
        match self {
            Self::Mint { .. } | Self::BatchHeader { .. } => vec![],
            Self::Xfer { payloads } => payloads.to_vec(),
            Self::XferCompressed {
                nullifier_commit, ..
            } => vec![*nullifier_commit],
            Self::Redeem { payload, .. } => vec![*payload],
        }
    }

    /// Occurrence test / well-formedness relative to a raw nullifier
    /// supplied by the verifier (module docs): does some payload slot of
    /// this record equal `H("bind" ∥ raw_nf ∥ ctx)`? Only someone holding
    /// `raw_nf` (the consignment holders) can evaluate this — by design.
    /// For XFERC records, pass the raw nullifier *commitment*.
    pub fn well_formed(&self, ctx: &[u8; 32], raw_nf: &Digest) -> bool {
        let bound = binding(raw_nf, ctx).to_anchor();
        self.payload_slots().contains(&bound)
    }

    /// Serialize to exactly 64 bytes.
    pub fn to_bytes(&self) -> [u8; ANCHOR_SIZE] {
        let mut out = [0u8; ANCHOR_SIZE];
        match self {
            Self::Mint {
                asset_id,
                value,
                mint_commit,
            } => {
                out[0] = TAG_MINT;
                out[1..25].copy_from_slice(asset_id.as_bytes());
                out[25..33].copy_from_slice(&value.to_le_bytes());
                out[33..57].copy_from_slice(mint_commit.as_bytes());
            }
            Self::BatchHeader {
                count,
                batch_commit,
            } => {
                out[0] = TAG_BATCH;
                out[1] = *count;
                out[2..26].copy_from_slice(batch_commit.as_bytes());
            }
            Self::Redeem {
                asset_id,
                value,
                payload,
            } => {
                out[0] = TAG_REDEEM;
                out[1..25].copy_from_slice(asset_id.as_bytes());
                out[25..33].copy_from_slice(&value.to_le_bytes());
                out[33..57].copy_from_slice(payload.as_bytes());
            }
            Self::Xfer { payloads } => {
                out[0..24].copy_from_slice(payloads[0].as_bytes());
                out[24..48].copy_from_slice(payloads[1].as_bytes());
            }
            Self::XferCompressed {
                nullifier_commit, ..
            } => {
                out[0..24].copy_from_slice(nullifier_commit.as_bytes());
            }
        }
        out
    }

    /// Parse a 64-byte anchor record (see module docs for the rules). Never
    /// fails: any 64-byte string is at worst an untagged transfer candidate.
    pub fn from_bytes(bytes: &[u8; ANCHOR_SIZE]) -> Self {
        let td = |range: std::ops::Range<usize>| {
            let mut b = [0u8; TRUNCATED_DIGEST_BYTES];
            b.copy_from_slice(&bytes[range]);
            TruncatedDigest(b)
        };
        let padded = |from: usize| bytes[from..].iter().all(|&b| b == 0);
        match bytes[0] {
            TAG_MINT if padded(57) => Self::Mint {
                asset_id: td(1..25),
                value: u64::from_le_bytes(bytes[25..33].try_into().expect("8 bytes")),
                mint_commit: td(33..57),
            },
            TAG_REDEEM if padded(57) => Self::Redeem {
                asset_id: td(1..25),
                value: u64::from_le_bytes(bytes[25..33].try_into().expect("8 bytes")),
                payload: td(33..57),
            },
            TAG_BATCH if padded(26) => Self::BatchHeader {
                count: bytes[1],
                batch_commit: td(2..26),
            },
            // Untagged transfer candidate (camouflage; module docs). XFER
            // and XFERC share this layout; the canonical parse is `Xfer`.
            // Trailing bytes are opaque padding and left unchecked.
            _ => Self::Xfer {
                payloads: [td(0..24), td(24..48)],
            },
        }
    }

    /// True if the serialization of this record parses back
    /// ([`AnchorRecord::from_bytes`] of [`AnchorRecord::to_bytes`]) as the
    /// same record class. Tagged records (MINT/REDEEM/BATCH) always
    /// qualify; an untagged transfer qualifies iff its first payload byte
    /// avoids the MINT/REDEEM tag bytes (see module docs — the anchoring
    /// party SHOULD redraw `ctx` until this holds). XFER and XFERC count
    /// as one class, since they share a layout. (The BATCH tag byte 0x05
    /// lives in the same leading position, so untagged transfers must
    /// also avoid it — [`parses_cleanly`] catches that case.)
    pub fn parses_cleanly(&self) -> bool {
        matches!(
            (self, Self::from_bytes(&self.to_bytes())),
            (Self::Mint { .. }, Self::Mint { .. })
                | (Self::Redeem { .. }, Self::Redeem { .. })
                | (Self::BatchHeader { .. }, Self::BatchHeader { .. })
                | (
                    Self::Xfer { .. } | Self::XferCompressed { .. },
                    Self::Xfer { .. } | Self::XferCompressed { .. },
                )
        )
    }
}
