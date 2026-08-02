//! The cryptographic boundary of the kernel: the only functions that call
//! into the scheme's Poseidon2 hash (via `opencsv-core`). For the Aeneas
//! translation these are marked **opaque** — the Lean side sees them as
//! uninterpreted functions, exactly the model's `bindHash` axiom
//! (`formal/OpenCsv/Interfaces.lean`).
//!
//! These wrappers are byte-identical delegations, NOT reimplementations.

use crate::types::{Ctx, Payload, RawNf};

/// `H("bind" ∥ raw_nf ∥ ctx)` as a full 32-byte digest
/// (`opencsv_core::anchor::binding`).
pub fn hash_bind(raw_nf: &RawNf, ctx: &Ctx) -> [u8; 32] {
    *opencsv_core::anchor::binding(
        &opencsv_core::Digest::from_bytes(*raw_nf),
        ctx,
    )
    .as_bytes()
}

/// `H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)` as a full 32-byte digest
/// (`opencsv_core::batch::batch_commit`).
pub fn hash_batch(payloads: &[Payload], ctx: &Ctx) -> [u8; 32] {
    let truncated: Vec<opencsv_core::TruncatedDigest> = payloads
        .iter()
        .map(|p| opencsv_core::TruncatedDigest(*p))
        .collect();
    *opencsv_core::batch::batch_commit(&truncated, ctx).as_bytes()
}
