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
//! - [`issuer`] — the issuer-signature trait `Σ`, with an Ed25519 prototype
//!   stand-in (§4.1, §4.4);
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
//! 2. **Ed25519 issuer signatures.** The paper requires an AIR-friendly `Σ`;
//!    Ed25519 is a prototype stand-in behind the
//!    [`issuer::IssuerSignature`] trait and must be replaced before in-circuit
//!    mint verification.
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
pub mod batch;
pub mod audit;
pub mod chain;
pub mod coin;
pub mod consignment;
pub mod crosscheck;
pub mod digest;
pub mod field;
pub mod issuer;
mod kernel;

pub use accept::{accept, AcceptParams, AcceptedCoins, MockVerifier, ProofVerifier, RejectReason};
pub use anchor::{binding, mint_commit, nullifier_commit, AnchorRecord, ANCHOR_SIZE};
pub use asset::{AssetGenesis, AssetId};
pub use audit::{supply, SupplyError};
pub use batch::{batch_commit, envelope_decode, envelope_encode, envelope_occurrence, WITNESS_MAGIC};
pub use chain::{AnchorChain, AnchorLocation, AnchorRef, MockAnchorChain};
pub use crosscheck::{CrossCheckError, CrossCheckedChain};
pub use coin::{Coin, Commitment, Nullifier, Owner, OwnerSecret};
pub use consignment::{CoinOpening, Consignment};
pub use digest::{Digest, TruncatedDigest};
pub use issuer::{mint_signing_message, Ed25519IssuerSignature, IssuerSignature};
