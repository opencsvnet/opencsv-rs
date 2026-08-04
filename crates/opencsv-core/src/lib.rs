//! # opencsv-core
//!
//! Core types and client-side verification logic for **OpenCSV** —
//! client-side verified RWAs anchored to Bitcoin L1 (see
//! `paper/opencsv.md`, §4 Construction).
//!
//! Implemented here:
//!
//! - [`asset`] — asset genesis and `asset_id = H("OpenCSV-asset" ∥ G)` (§4.2);
//! - [`coin`] — coins, commitments, nullifiers, owner keys (§4.3);
//! - [`issuer`] — Poseidon-native issuer authorization proved inside mint
//!   PCD, plus read-only legacy Ed25519 helpers (§4.1, §4.4);
//! - [`anchor`] — 64-byte MINT / XFER / REDEEM anchor records (§4.4–4.6);
//! - [`chain`] — the [`chain::AnchorChain`] abstraction over Bitcoin plus an
//!   in-memory mock, with first-occurrence nullifier semantics (§4.7);
//! - [`consignment`] — the off-chain sender→recipient message (§4.8);
//! - [`mod@accept`] — the receiver verification driver `Accept` and the
//!   [`accept::ProofVerifier`] seam where the PCD engine plugs in (§4.8);
//! - [`audit`] — the public supply audit `supply(asset_id, h)` (§4.9).
//!
//! ## Deviations from the paper (to be reconciled)
//!
//! 1. **Poseidon2, not Poseidon.** The paper says "Poseidon over 𝔽"; we use
//!    Poseidon2 over BabyBear via Plonky3 (`p3-poseidon2`, width 16, rate 8)
//!    — the field-dedicated hash Plonky3 actually ships.
//! 2. **Issuer authorization is a PCD signature of knowledge.** New mints
//!    prove knowledge of a Poseidon2-committed issuer seed in the same circuit
//!    that binds the mint statement. This is not an independently verifiable
//!    standalone signature; the versioned PCD proof is the authorization
//!    artifact. Legacy Ed25519 records are not accepted for new mints.
//! 3. **32-byte digests, 24-byte anchor prefixes.** The paper both fixes the
//!    anchor at 64 bytes and calls nullifiers "64 pseudorandom bytes"; these
//!    cannot both hold with the MINT/REDEEM layouts of §4.4/§4.6. We hash to
//!    8 BabyBear elements (32 bytes) off-chain and carry 24-byte prefixes in
//!    anchors.
//! 4. **Coin randomness `r` is 32 bytes** (8 field elements), not a single
//!    field element — 31 bits cannot hide anything.
//! 5. **Context-bound nullifier payloads, untagged transfers.** Anchor
//!    records are copyable bytes, so a mempool spy could front-run a copy
//!    and a naive first-occurrence rule would freeze the victim's coins.
//!    Nullifier-bearing records therefore publish only *bound payloads*
//!    `P = H("bind" ∥ raw_nf ∥ ctx)`; the raw nullifier never appears
//!    on-chain — it travels in the consignment, and occurrence recognition
//!    is restricted to consignment holders (paper §4.7 rule 1, amended; see
//!    [`anchor`]). Transfer records additionally drop the tag byte
//!    (camouflage); MINT/REDEEM stay tagged for the public supply audit.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod accept;
pub mod anchor;
pub mod asset;
pub mod audit;
pub mod batch;
pub mod chain;
pub mod coin;
pub mod consignment;
pub mod crosscheck;
pub mod digest;
pub mod field;
pub mod instrument;
pub mod issuer;
mod kernel;

pub use accept::{accept, AcceptParams, AcceptedCoins, MockVerifier, ProofVerifier, RejectReason};
pub use anchor::{binding, mint_commit, nullifier_commit, AnchorRecord, ANCHOR_SIZE};
pub use asset::{AssetGenesis, AssetId};
pub use audit::{supply, SupplyError};
pub use batch::{
    batch_commit, batch_commit_v2, envelope_decode, envelope_encode, envelope_occurrence,
    envelope_v2_encode, versioned_batch_commit, versioned_envelope_occurrence,
    witness_envelope_decode, BatchVersion, MAX_BATCH_V2_PARTICIPANTS, WITNESS_MAGIC,
    WITNESS_MAGIC_V2,
};
pub use chain::{AnchorChain, AnchorLocation, AnchorRef, MockAnchorChain};
pub use coin::{Coin, Commitment, Nullifier, Owner, OwnerSecret};
pub use consignment::{CoinOpening, Consignment};
pub use crosscheck::{CrossCheckError, CrossCheckedChain};
pub use digest::{Digest, TruncatedDigest};
pub use instrument::{
    preview_usd_terms, InstrumentError, InstrumentManifestV1, InstrumentTermsV1,
    INSTRUMENT_TERMS_VERSION, MAX_INSTRUMENT_DECIMALS, PREVIEW_USD_DECIMALS,
    PREVIEW_USD_DISPLAY_NAME, PREVIEW_USD_ISSUER_NAME, PREVIEW_USD_TERMS_URI,
};
#[allow(deprecated)]
pub use issuer::{
    mint_signing_message, Ed25519IssuerSignature, IssuerSignature, PoseidonIssuerAuthorization,
    POSEIDON_ISSUER_KEY_DOMAIN,
};
