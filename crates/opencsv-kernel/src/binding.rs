//! The transaction-context binding (mirror of `opencsv-core::anchor`).

use crate::hash;
use crate::types::{Ctx, Payload, RawNf};

/// The 24-byte anchor-carrying prefix of a digest (`Digest::to_anchor`).
pub fn truncate24(digest: &[u8; 32]) -> Payload {
    let mut out = [0u8; 24];
    let mut i = 0usize;
    while i < 24 {
        out[i] = digest[i];
        i += 1;
    }
    out
}

/// `P = H("bind" ∥ raw ∥ ctx)` truncated to the on-chain payload
/// (`opencsv_core::anchor::binding` + `Digest::to_anchor`).
pub fn binding(raw: &RawNf, ctx: &Ctx) -> Payload {
    let digest = hash::hash_bind(raw, ctx);
    truncate24(&digest)
}
