//! # opencsv-pcd
//!
//! Proof-carrying data (PCD) for **OpenCSV**, built on the Plonky3 circuit /
//! recursion stack (`p3-circuit`, `p3-circuit-prover` from the pinned
//! Plonky3-recursion git commit — see `Cargo.toml`).
//!
//! All hashes are computed in-circuit exactly as `opencsv-core`'s
//! `hash_felts` does (Poseidon2 `PaddingFreeSponge` over BabyBear, width 16 /
//! rate 8 / digest 8, length-prefixed, domain-separated — see `README.md`).
//!
//! ## Stage 1: commitment opening (paper §4.3)
//!
//! A **non-recursive** circuit proving knowledge of an opening of a coin
//! commitment `C = H("coin" ∥ asset_id ∥ v ∥ owner ∥ r)`:
//!
//! - Public input: `C` as 8 BabyBear elements ([`DIGEST_ELEMS`]).
//! - Private witness: `asset_id` (8), `v` (3 limbs), `owner` (8), `r` (8).
//!
//! Use [`prove_opening`] / [`verify_opening`].
//!
//! ## Stage 2: mint and transfer predicates (paper §4.4–4.5)
//!
//! Still **non-recursive** (recursion is stage 3):
//!
//! - Mint ([`prove_mint`] / [`verify_mint`]): proves knowledge of the issuer
//!   seed committed by the asset genesis, derives the asset id in-circuit,
//!   recomputes output commitments, range-checks values, enforces
//!   `Σ v_i = V`, and binds
//!   `mint_commit = H("mint" ∥ asset_id ∥ V ∥ mint_nonce)`.
//! - Transfer ([`prove_transfer`] / [`verify_transfer`]): 2 inputs / 2
//!   outputs, **single asset** — input commitments recompute, ownership
//!   (`owner_i = H(osk_i)`), nullifiers (`nf_i = H("null" ∥ osk_i ∥ C_i)`),
//!   values in range, conservation `Σ v_in = Σ v_out`, output commitments
//!   recompute.
//!
//! Values are range-checked u64 limb triples (24/24/16 bits) with
//! carry-exact sum constraints — see the `value` module.
//!
//! ## Stage 3: PCD recursion (paper §4.5 item 4)
//!
//! Real proof-carrying data: transfer circuits verify either one (v4
//! forwarding) or two predecessor proofs *in-circuit* (genuine batch-STARK
//! verification via `p3-recursion`), and a dedicated **statement table** exposes every
//! circuit's public statement as STARK instance public values, which the
//! successor `connect`s to its own recomputed input commitments — this is
//! what chains the PCD and binds predecessor public data. See the `node`
//! module docs for the architecture (two circuits: mint genesis + recursive
//! transfer node), and the `statement` module docs for the binding channel.
//!
//! - Genesis: [`prove_genesis_mint`].
//! - Two-input recursive transfer: [`prove_coin_transfer`].
//! - One-input recursive transfer: [`prove_one_input_transfer`].
//! - Root verification: [`verify_coin_proof`] (checks the bound statement
//!   values, then natively verifies the proof).
//!
//! ## Stage 4: redeem and accept-driver integration (paper §4.6, §4.8)
//!
//! - Redeem (burn): [`prove_redeem`] / [`verify_redeem`] — one predecessor
//!   verified in-circuit, statement binds `(mode = REDEEM, asset_id, V, nf)`.
//! - Accept-driver integration: [`CoinProofVerifier`] implements
//!   `opencsv-core`'s `ProofVerifier` trait with the real recursive verifier,
//!   and [`encode_coin_proof`] serializes a [`CoinProof`] for the
//!   consignment's opaque proof bytes. No `opencsv-core` changes were needed:
//!   the full statement travels inside the proof bytes and the adapter checks
//!   it against the anchor-and-openings public input.
//!
//! **Known limitation (inherited from upstream 0.1.0 PoC):** the standalone
//! stage-1/2 verifier (`BatchStarkProver::verify_all_tables`) proves
//! *satisfiability of the circuit for some public inputs* — the public input
//! values are sent on the witness bus but are not exposed as STARK instance
//! public values. This crate therefore stores the public data inside each
//! stage-1/2 proof struct ([`OpeningProof`], [`MintProof`], [`TransferProof`])
//! and the `verify_*` functions compare it against the expected values.
//! Stage 3 closes this gap for the recursive proofs via the statement table
//! (see `README.md` for the remaining root/vk caveats).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod accept;
mod hash;
mod issuer;
mod mint;
mod node;
mod opening;
mod prove;
mod recursion_config;
mod security;
mod setup_cache;
#[cfg(test)]
mod spike;
mod statement;
mod transfer;
mod value;

use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

/// Circuit field: quartic extension of BabyBear (`D = 4`; the upstream
/// prover at the pinned commit only supports Poseidon2 tables for extension
/// degrees `D ∈ {2, 4, 5}` — see `README.md`).
pub type EF = BinomialExtensionField<BabyBear, 4>;

pub use accept::{decode_coin_proof, encode_coin_proof, CoinProofVerifier};
pub use hash::{osk_felts, OSK_ELEMS};
pub use mint::{
    prove_mint, prove_mint_raw, verify_mint, MintError, MintProof, MintStatement, MINT_OUTPUTS,
    MINT_PRIVATE_ELEMS, MINT_PUBLIC_ELEMS,
};
pub use node::prove_transfer as prove_coin_transfer;
pub use node::{
    coin_fri_params, prove_genesis_mint, prove_genesis_mint_raw, prove_one_input_transfer,
    prove_redeem, verify_coin_proof, verify_redeem, CoinProof, NodeError, NodeMode, NodeStatement,
    RedeemProof, COIN_PROOF_VERSION, LEGACY_COIN_PROOF_VERSION, NODE_INPUTS, NODE_OUTPUTS,
    NODE_PRIVATE_ELEMS, ONE_INPUT_PRIVATE_ELEMS, REDEEM_PRIVATE_ELEMS, STATEMENT_ELEMS,
};
pub use opening::{
    prove_opening, prove_opening_raw, verify_opening, CoinWitness, OpeningError, OpeningProof,
    PRIVATE_ELEMS, PUBLIC_ELEMS,
};
pub use security::{
    proof_security_report, ProofSecurityReport, COIN_PROOF_PROFILE_ID, COIN_VK_TAG,
    LEGACY_COIN_PROOF_PROFILE_ID, PRODUCTION_SECURITY_TARGET_BITS,
};
pub use transfer::{
    prove_transfer, verify_transfer, TransferError, TransferProof, TransferStatement,
    TRANSFER_INPUTS, TRANSFER_OUTPUTS, TRANSFER_PRIVATE_ELEMS, TRANSFER_PUBLIC_ELEMS,
};
pub use value::{u64_to_felts, VALUE_LIMBS};

pub use opencsv_core::field::DIGEST_ELEMS;
