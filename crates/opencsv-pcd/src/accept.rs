//! Accept-driver integration (paper §4.8): plug the real recursive verifier
//! into `opencsv-core`'s [`ProofVerifier`] seam.
//!
//! `opencsv-core` must not depend on this crate (the trait seam exists for
//! exactly that reason), so the integration lives here: [`CoinProofVerifier`]
//! implements [`ProofVerifier`] using [`verify_coin_proof`], and
//! [`encode_coin_proof`] serializes a [`CoinProof`] into the opaque proof
//! bytes a consignment carries.
//!
//! # How the trait's shape fits recursive proofs
//!
//! The trait is `verify(vk, public_input, proof) -> bool`, where
//! `public_input` is `ctx(32) ∥ anchor_bytes(64) ∥ openings` reconstructed
//! by the accept driver and `proof` is an opaque blob. A recursive coin
//! proof's statement cannot be fully reconstructed from that public input —
//! anchors carry only 24-byte truncated digests and openings do not carry
//! nullifiers or the mint nonce — so the envelope puts the **full statement
//! inside the proof bytes** (which is sound: [`verify_coin_proof`] checks
//! the statement against the proof's transcript-bound statement-table
//! public values) and the adapter additionally checks the statement
//! *projects* onto the public input:
//!
//! - the anchor's *form* matches the proof mode: transfers (XFER/XFERC) are
//!   untagged opaque 64-byte records, MINT/REDEEM stay tagged (see
//!   `opencsv-core`'s anchor docs);
//! - the anchor's truncated digests match the statement: asset id, mint
//!   commit and `V` directly, and the nullifier payloads as **bound
//!   values** — each payload slot must equal `H("bind" ∥ nf ∥ ctx)` for the
//!   statement's (raw) nullifiers, respectively the nullifier commitment
//!   for compressed transfers, under the public input's `ctx`;
//! - the openings' recomputed commitments equal the statement's output
//!   commitments (mints and transfers), respectively there are no openings
//!   and no outputs (redeems).
//!
//! The transfer payload slots are read straight from the raw anchor bytes:
//! XFER and XFERC share one untagged layout, and a payload whose first byte
//! collides with the MINT/REDEEM tags must still verify. The raw nullifier
//! never appears on-chain; the circuits and statements are unchanged — the
//! binding lives purely at the anchor layer.
//!
//! `vk` must equal the frozen production lineage/profile tag. Recursive
//! predecessor keys are hard-bound; root-circuit commitment registration is
//! tracked separately because recursive circuit shapes depend on predecessor
//! proof metadata (see `README.md`).

use opencsv_core::accept::ProofVerifier;
use opencsv_core::anchor::AnchorRecord;
use opencsv_core::consignment::CoinOpening;
use opencsv_core::digest::Digest;
use serde::{Deserialize, Serialize};

use crate::node::{verify_coin_proof, NODE_OUTPUTS};
use crate::{CoinProof, NodeMode, NodeStatement, COIN_PROOF_VERSION, COIN_VK_TAG};

/// Byte length of one opening inside the accept driver's public input
/// (`asset_id(32) ∥ v(8) ∥ owner(32) ∥ r(32)`, see
/// [`CoinOpening::to_public_input_bytes`]).
const OPENING_BYTES: usize = 104;

/// Unambiguous prefix for versioned coin-proof envelopes.
const PROOF_ENVELOPE_MAGIC: &[u8; 7] = b"OCSVPCD";

/// Versioned serialized form of a [`CoinProof`] after the magic/version
/// prefix: the mode and full statement, plus the postcard-serialized proof.
#[derive(Serialize, Deserialize)]
struct ProofEnvelope {
    mode: NodeMode,
    statement: NodeStatement,
    proof: Vec<u8>,
}

/// Pre-versioning envelope retained solely for read-only inspection. Proofs
/// decoded through this shape are assigned version 1 and fail verification.
#[derive(Serialize, Deserialize)]
struct LegacyProofEnvelope {
    mode: NodeMode,
    statement: NodeStatement,
    proof: Vec<u8>,
}

/// Serialize a coin proof into the opaque bytes a
/// [`opencsv_core::consignment::Consignment`] carries as its `proof` field.
pub fn encode_coin_proof(proof: &CoinProof) -> Vec<u8> {
    assert_eq!(
        proof.version, COIN_PROOF_VERSION,
        "only the current authenticated proof lineage may be encoded"
    );
    let inner = postcard::to_allocvec(&proof.proof).expect("batch-STARK proof serializes");
    let payload = postcard::to_allocvec(&ProofEnvelope {
        mode: proof.mode,
        statement: proof.statement.clone(),
        proof: inner,
    })
    .expect("proof envelope serializes");
    let mut encoded = Vec::with_capacity(PROOF_ENVELOPE_MAGIC.len() + 1 + payload.len());
    encoded.extend_from_slice(PROOF_ENVELOPE_MAGIC);
    encoded.push(proof.version);
    encoded.extend_from_slice(&payload);
    encoded
}

/// Inverse of [`encode_coin_proof`]: decode a coin proof from a
/// consignment's opaque proof bytes.
///
/// Spenders need this: a transfer or redeem must present the proof that
/// *created* each consumed coin as its in-circuit predecessor, so wallets
/// store the received envelope and decode it at spending time.
pub fn decode_coin_proof(bytes: &[u8]) -> Option<CoinProof> {
    if let Some(payload) = bytes.strip_prefix(PROOF_ENVELOPE_MAGIC) {
        let (&version, payload) = payload.split_first()?;
        let envelope: ProofEnvelope = postcard::from_bytes(payload).ok()?;
        let proof = postcard::from_bytes(&envelope.proof).ok()?;
        return Some(CoinProof {
            version,
            mode: envelope.mode,
            statement: envelope.statement,
            proof,
        });
    }

    let envelope: LegacyProofEnvelope = postcard::from_bytes(bytes).ok()?;
    let proof = postcard::from_bytes(&envelope.proof).ok()?;
    Some(CoinProof {
        version: 1,
        mode: envelope.mode,
        statement: envelope.statement,
        proof,
    })
}

/// Parse the openings out of the accept driver's public input
/// (`ctx(32) ∥ anchor_bytes(64) ∥ opening_1 ∥ … ∥ opening_n`).
fn parse_openings(x: &[u8]) -> Option<Vec<CoinOpening>> {
    if x.len() < 96 || !(x.len() - 96).is_multiple_of(OPENING_BYTES) {
        return None;
    }
    let digest = |chunk: &[u8]| Digest::from_bytes(chunk.try_into().expect("32-byte chunk"));
    Some(
        x[96..]
            .chunks_exact(OPENING_BYTES)
            .map(|o| CoinOpening {
                asset_id: digest(&o[0..32]),
                value: u64::from_le_bytes(o[32..40].try_into().expect("8-byte value")),
                owner: digest(&o[40..72]),
                randomness: digest(&o[72..104]),
            })
            .collect(),
    )
}

/// Check that the envelope's statement projects onto the accept driver's
/// public input (module docs): anchor form/mode agreement, digest and value
/// agreement (nullifier payloads as bound values under the public input's
/// `ctx`), and openings == output commitments.
fn statement_matches_public_input(mode: NodeMode, st: &NodeStatement, x: &[u8]) -> bool {
    let Some(openings) = parse_openings(x) else {
        return false;
    };
    let ctx: &[u8; 32] = x[..32].try_into().expect("32-byte ctx");
    let anchor_bytes: &[u8; 64] = x[32..96].try_into().expect("64-byte anchor");
    let record = AnchorRecord::from_bytes(anchor_bytes);
    let zero = Digest::from_bytes([0u8; 32]);
    let zero_td = opencsv_core::digest::TruncatedDigest([0u8; 24]);
    let bound = |nf: &Digest| opencsv_core::anchor::binding(nf, ctx).to_anchor();
    // Mint/transfer: exactly `NODE_OUTPUTS` openings in the stated asset
    // whose recomputed commitments are the statement's outputs.
    let outputs_match = |openings: &[CoinOpening]| {
        openings.len() == NODE_OUTPUTS
            && openings
                .iter()
                .zip(st.output_commitments.iter())
                .all(|(o, c)| o.asset_id == st.asset_id && o.commitment() == *c)
    };
    match (record, mode) {
        (
            AnchorRecord::Mint {
                asset_id,
                value,
                mint_commit,
            },
            NodeMode::Mint,
        ) => {
            st.asset_id.to_anchor() == asset_id
                && st.value == value
                && st.mint_commit.to_anchor() == mint_commit
                && st.nullifiers == [zero; crate::NODE_INPUTS]
                && outputs_match(&openings)
        }
        (
            AnchorRecord::Redeem {
                asset_id,
                value,
                payload,
            },
            NodeMode::Redeem,
        ) => {
            st.asset_id.to_anchor() == asset_id
                && st.value == value
                && st.mint_commit == zero
                && bound(&st.nullifiers[0]) == payload
                && st.nullifiers[1] == zero
                && st.output_commitments == [zero; NODE_OUTPUTS]
                && openings.is_empty()
        }
        // Transfers are untagged (camouflage): the two 24-byte payload slots
        // are bytes 0..48 of the raw anchor, whatever the parsed record says
        // — a payload whose first byte collides with the MINT/REDEEM tags
        // must still verify. Each slot binds one statement nullifier under
        // the anchor's ctx (a zero/padding nullifier binds a zero slot); a
        // compressed transfer instead binds the nullifier commitment into
        // slot 0 and zeroes slot 1.
        (_, NodeMode::Transfer) => {
            let slot = |from: usize| {
                opencsv_core::digest::TruncatedDigest(
                    anchor_bytes[from..from + 24]
                        .try_into()
                        .expect("24-byte slot"),
                )
            };
            let slots = [slot(0), slot(24)];
            let distinct_nullifiers = st.nullifiers[0] == zero
                || st.nullifiers[1] == zero
                || st.nullifiers[0] != st.nullifiers[1];
            let direct = st.nullifiers.iter().zip(slots).all(|(nf, s)| {
                if *nf == zero {
                    s == zero_td
                } else {
                    bound(nf) == s
                }
            });
            let compressed = slots[1] == zero_td
                && bound(&opencsv_core::anchor::nullifier_commit(&st.nullifiers)) == slots[0];
            st.value == 0
                && st.mint_commit == zero
                && outputs_match(&openings)
                && distinct_nullifiers
                && (direct || compressed)
        }
        _ => false,
    }
}

/// The real [`ProofVerifier`] for the accept driver: decodes the coin proof
/// from the consignment's proof bytes, checks the carried statement against
/// the anchor-and-openings public input, then runs the full recursive
/// verification (statement-table comparison + native batch-STARK
/// verification).
pub struct CoinProofVerifier;

fn root_lineage_is_current(version: u8) -> bool {
    version == COIN_PROOF_VERSION
}

impl ProofVerifier for CoinProofVerifier {
    fn verify(&self, vk: &[u8], public_input: &[u8], proof: &[u8]) -> bool {
        if vk != COIN_VK_TAG {
            return false;
        }
        let Some(coin) = decode_coin_proof(proof) else {
            return false;
        };
        // V3 stays decodable/verifiable for explicit migration inspection,
        // but it predates the in-circuit duplicate-input constraint. It must
        // never cross the production receiver boundary as a root proof.
        if !root_lineage_is_current(coin.version) {
            return false;
        }
        if !statement_matches_public_input(coin.mode, &coin.statement, public_input) {
            return false;
        }
        verify_coin_proof(&coin.statement, &coin).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_core::{AssetGenesis, PoseidonIssuerAuthorization};

    #[test]
    fn production_accepts_only_the_current_root_lineage() {
        assert!(root_lineage_is_current(COIN_PROOF_VERSION));
        assert!(!root_lineage_is_current(crate::LEGACY_COIN_PROOF_VERSION));
        assert!(!root_lineage_is_current(2));
    }

    /// The envelope round-trips (guards the postcard encoding the
    /// consignment relies on).
    #[test]
    fn envelope_round_trip() {
        let issuer_secret = [0x42; 32];
        let genesis = AssetGenesis {
            issuer_pk: PoseidonIssuerAuthorization::public_key(&issuer_secret),
            currency_code: *b"USD",
            terms_hash: Digest::from_bytes([0x74; 32]),
            nonce: 1,
        };
        let asset_id = genesis.asset_id();
        let coins = [
            opencsv_core::Coin {
                asset_id,
                value: 60,
                owner: opencsv_core::OwnerSecret::from_bytes([0x22; 32]).owner(),
                randomness: Digest::from_bytes([0x33; 32]),
            },
            opencsv_core::Coin {
                asset_id,
                value: 40,
                owner: opencsv_core::OwnerSecret::from_bytes([0x44; 32]).owner(),
                randomness: Digest::from_bytes([0x55; 32]),
            },
        ];
        let nonce = Digest::from_bytes([0xaa; 32]);
        let proof = crate::prove_genesis_mint(&genesis, &issuer_secret, &nonce, &coins)
            .expect("mint proving");
        let bytes = encode_coin_proof(&proof);
        let decoded = decode_coin_proof(&bytes).expect("envelope decodes");
        assert_eq!(decoded.mode, proof.mode);
        assert_eq!(decoded.statement, proof.statement);
        crate::verify_coin_proof(&proof.statement, &decoded).expect("decoded proof verifies");

        let openings = coins.map(|coin| CoinOpening {
            asset_id: coin.asset_id,
            value: coin.value,
            owner: coin.owner,
            randomness: coin.randomness,
        });
        let ctx = [0x91; 32];
        let record = AnchorRecord::Mint {
            asset_id: asset_id.to_anchor(),
            value: proof.statement.value,
            mint_commit: proof.statement.mint_commit.to_anchor(),
        };
        let public_input = opencsv_core::accept::public_input(&record, &ctx, &openings);
        assert!(CoinProofVerifier.verify(COIN_VK_TAG, &public_input, &bytes));

        let mut legacy_root = bytes.clone();
        legacy_root[PROOF_ENVELOPE_MAGIC.len()] = crate::LEGACY_COIN_PROOF_VERSION;
        assert!(decode_coin_proof(&legacy_root).is_some());
        assert!(!CoinProofVerifier.verify(COIN_VK_TAG, &public_input, &legacy_root));

        // The v2 wire shape remains parseable for migration tooling, but its
        // explicit lineage byte cannot be relabeled as production v3.
        let mut version_two = bytes.clone();
        version_two[PROOF_ENVELOPE_MAGIC.len()] = 2;
        let version_two = decode_coin_proof(&version_two).expect("v2 envelope is inspectable");
        assert_eq!(version_two.version, 2);
        assert!(matches!(
            crate::verify_coin_proof(&version_two.statement, &version_two),
            Err(crate::NodeError::UnsupportedProofVersion { actual: 2 })
        ));

        // The pre-versioning shape remains decodable for inspection but is
        // assigned version 1 and cannot cross the verification boundary.
        let legacy_bytes = postcard::to_allocvec(&LegacyProofEnvelope {
            mode: proof.mode,
            statement: proof.statement.clone(),
            proof: postcard::to_allocvec(&proof.proof).expect("inner proof serializes"),
        })
        .expect("legacy envelope serializes");
        let legacy = decode_coin_proof(&legacy_bytes).expect("legacy envelope is inspectable");
        assert_eq!(legacy.version, 1);
        assert!(crate::verify_coin_proof(&legacy.statement, &legacy).is_err());
        // Garbage does not decode.
        assert!(decode_coin_proof(&bytes[..bytes.len() / 2]).is_none());
    }

    #[test]
    fn duplicate_transfer_nullifiers_do_not_project_to_accept_input() {
        let asset_id = Digest::from_bytes([0x11; 32]);
        let nullifier = Digest::from_bytes([0x22; 32]);
        let ctx = [0x33; 32];
        let openings = [
            CoinOpening {
                asset_id,
                value: 6,
                owner: Digest::from_bytes([0x44; 32]),
                randomness: Digest::from_bytes([0x55; 32]),
            },
            CoinOpening {
                asset_id,
                value: 4,
                owner: Digest::from_bytes([0x66; 32]),
                randomness: Digest::from_bytes([0x77; 32]),
            },
        ];
        let statement = NodeStatement {
            asset_id,
            value: 0,
            mint_commit: Digest::from_bytes([0u8; 32]),
            nullifiers: [nullifier, nullifier],
            output_commitments: [openings[0].commitment(), openings[1].commitment()],
        };

        for record in [
            AnchorRecord::xfer(&[nullifier, nullifier], &ctx),
            AnchorRecord::xfer_compressed(
                &opencsv_core::anchor::nullifier_commit(&[nullifier, nullifier]),
                &ctx,
            ),
        ] {
            let x = opencsv_core::accept::public_input(&record, &ctx, &openings);
            assert!(!statement_matches_public_input(
                NodeMode::Transfer,
                &statement,
                &x
            ));
        }
    }
}
