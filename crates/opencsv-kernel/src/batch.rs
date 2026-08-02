//! Batch occurrence test (mirror of `opencsv-core::batch::envelope_occurrence`).

use crate::binding::{binding, truncate24};
use crate::hash;
use crate::types::{Ctx, Payload, RawNf};

/// Is `raw_nf` an occurrence of this batch? Returns the envelope index of
/// its payload (mirror of `batch::envelope_occurrence`):
///
/// - the envelope must carry exactly `count` payloads;
/// - the header's `batch_commit` must recompute over the envelope
///   (`H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)`, truncated);
/// - some payload must equal `H("bind" ∥ raw_nf ∥ ctx)` (truncated).
///
/// `count` and `batch_commit` come from the batch header record of the
/// transaction the envelope was taken from; `ctx` is the transaction's
/// funding ctx. Loop-based (Aeneas-compatible shape).
pub fn batch_occurrence(
    count: u8,
    batch_commit: &Payload,
    envelope: &[Payload],
    ctx: &Ctx,
    raw_nf: &RawNf,
) -> Option<u32> {
    if envelope.len() != count as usize {
        return None;
    }
    let committed = truncate24(&hash::hash_batch(envelope, ctx));
    if committed != *batch_commit {
        return None;
    }
    let bound = binding(raw_nf, ctx);
    let mut i = 0usize;
    while i < envelope.len() {
        if envelope[i] == bound {
            return Some(i as u32);
        }
        i += 1;
    }
    None
}
