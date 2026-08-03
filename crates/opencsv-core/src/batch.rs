//! Legacy batch anchors (paper §4.7.1, amended: v1 batching format).
//!
//! This module implements batching v1 for compatibility. It is not the
//! co-funded production design. The frozen v2 protocol, transaction layout,
//! fee allocation, two-round signing flow, migration rules, and threat model
//! live in the repository's `BATCHING_V2.md`. C1 will add v2 alongside this
//! reader before v1 creation is deprecated; callers MUST NOT treat the
//! anyone-can-spend v1 funding stock below as v2 stock.
//!
//! One anchor transaction can carry **N transfer records**: N senders
//! combine under an untrusted coordinator who pre-commits a funding
//! outpoint `X`; each sender computes `P_i = H("bind" ∥ raw_nf_i ∥ X)`
//! locally, so the coordinator assembles the batch without ever learning
//! a raw nullifier.
//!
//! ## The batch transaction (v1)
//!
//! ```text
//! input 0:   a coordinator-owned P2WSH funding UTXO (self-funded
//!            setup output; anyone-can-spend). Its witness carries the
//!            envelope: item 0 is the magic tag `OCSV`, items 1..=n are
//!            one 24-byte TruncatedDigest payload each (all ≤ 80 bytes,
//!            standardness-clean), and the last item is the witness
//!            script. (The original design said bare `OP_TRUE` with
//!            junk arguments — that fails CLEANSTACK ("stack size must
//!            be exactly one after execution"): the witness script is
//!            `OP_DROP×(n+1) OP_TRUE`, which consumes the envelope
//!            arguments and leaves exactly one truthy element. The
//!            funding scriptPubKey is therefore `OP_0 <sha256(script)>`,
//!            sized by payload count but independent of the payloads —
//!            still no EC, still quantum-clean, still anyone-can-spend.)
//! output 0:  OP_RETURN batch header record: [0x05][count:1][batch_commit:24][pad:38]
//! output 1:  the constant marker output (filter discovery, unchanged)
//! output 2..: change (back to the OP_TRUE spk, self-sustaining)
//! ```
//!
//! `ctx = SHA-256(txid ∥ vout_le)` of the OP_TRUE funding outpoint —
//! the canonical [`opencsv-bitcoin`](https://docs.rs/opencsv-bitcoin)
//! `funding_ctx` of vin[0], unchanged.
//!
//! The batch header commits to the whole envelope:
//! `batch_commit = H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)`, so recipients can
//! verify their payload is committed, and today's OP_RETURN scanners
//! still see a well-formed record at output 0.
//!
//! ## Occurrence semantics
//!
//! An occurrence of `raw_nf` is a payload `P` at envelope index `i`
//! with `P == binding(raw_nf, ctx)` (24-byte anchor form) **and** the
//! envelope validating against the header: `envelope.len() == count`
//! and `batch_commit` recomputing over the envelope. Consignments name
//! `(txid, envelope_index)`; solo anchors (the plain OP_RETURN record
//! form) stay fully valid — batching is optional.
//!
//! Payload packing: one 24-byte payload per witness item (not 3-per-72):
//! self-delimiting (no padding ambiguity against `count`), trivially
//! within the 80-byte item limit, and the witness cost of two extra
//! items per payload is negligible at batch sizes anyone should use.

use crate::anchor::{binding, AnchorRecord};
use crate::digest::{Digest, TruncatedDigest, TRUNCATED_DIGEST_BYTES};
use crate::field::{bytes_to_felts, hash_felts};

/// The magic tag of a batch witness envelope (first witness item).
pub const WITNESS_MAGIC: [u8; 4] = *b"OCSV";

/// The magic tag of a signed, co-funded batching-v2 witness envelope.
pub const WITNESS_MAGIC_V2: [u8; 4] = *b"OCS2";

/// The protocol/DoS cap for batching v2 (see `BATCHING_V2.md`).
pub const MAX_BATCH_V2_PARTICIPANTS: usize = 64;

/// A decoded batch envelope's fail-closed protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchVersion {
    /// Legacy coordinator-funded `OCSV` envelope and `batch` hash domain.
    V1,
    /// Signed, participant-funded `OCS2` envelope and `batch-v2` domain.
    V2,
}

/// The largest standard witness item (BIP141 standardness).
pub const MAX_WITNESS_ITEM: usize = 80;

/// `batch_commit = H("batch" ∥ P_1 ∥ … ∥ P_n ∥ ctx)` — the header's
/// commitment to the full payload envelope (module docs).
pub fn batch_commit(payloads: &[TruncatedDigest], ctx: &[u8; 32]) -> Digest {
    let mut concatenated = Vec::with_capacity(payloads.len() * TRUNCATED_DIGEST_BYTES);
    for payload in payloads {
        concatenated.extend_from_slice(payload.as_bytes());
    }
    hash_felts("batch", &[&bytes_to_felts(&concatenated), &bytes_to_felts(ctx)])
}

/// `batch_commit_v2 = H("batch-v2" ∥ P_1 ∥ … ∥ P_n ∥ ctx)` — the
/// fail-closed batching-v2 commitment frozen in `BATCHING_V2.md`.
pub fn batch_commit_v2(payloads: &[TruncatedDigest], ctx: &[u8; 32]) -> Digest {
    let mut concatenated = Vec::with_capacity(payloads.len() * TRUNCATED_DIGEST_BYTES);
    for payload in payloads {
        concatenated.extend_from_slice(payload.as_bytes());
    }
    hash_felts(
        "batch-v2",
        &[&bytes_to_felts(&concatenated), &bytes_to_felts(ctx)],
    )
}

/// Compute the header commitment selected by the decoded envelope version.
pub fn versioned_batch_commit(
    version: BatchVersion,
    payloads: &[TruncatedDigest],
    ctx: &[u8; 32],
) -> Digest {
    match version {
        BatchVersion::V1 => batch_commit(payloads, ctx),
        BatchVersion::V2 => batch_commit_v2(payloads, ctx),
    }
}

/// Encode a payload envelope as witness items: the magic tag followed
/// by one 24-byte item per payload (module docs).
pub fn envelope_encode(payloads: &[TruncatedDigest]) -> Vec<Vec<u8>> {
    let mut items = Vec::with_capacity(payloads.len() + 1);
    items.push(WITNESS_MAGIC.to_vec());
    for payload in payloads {
        items.push(payload.as_bytes().to_vec());
    }
    items
}

/// Encode the non-signature part of a v2 witness envelope: `OCS2`
/// followed by exactly one 24-byte payload per participant. The Bitcoin
/// layer appends the stock signature and signed P2WSH script.
pub fn envelope_v2_encode(payloads: &[TruncatedDigest]) -> Option<Vec<Vec<u8>>> {
    if payloads.is_empty() || payloads.len() > MAX_BATCH_V2_PARTICIPANTS {
        return None;
    }
    let mut items = Vec::with_capacity(payloads.len() + 1);
    items.push(WITNESS_MAGIC_V2.to_vec());
    items.extend(payloads.iter().map(|payload| payload.as_bytes().to_vec()));
    Some(items)
}

/// Decode a witness envelope: the magic tag followed by 24-byte payload
/// items. Returns `None` if the magic is wrong, any item is not exactly
/// 24 bytes (or > [`MAX_WITNESS_ITEM`]), or there are no payloads. The
/// final witness-script item is NOT part of the envelope — callers pass
/// `witness[..witness.len() - 1]`.
pub fn envelope_decode(items: &[Vec<u8>]) -> Option<Vec<TruncatedDigest>> {
    let (magic, payloads) = items.split_first()?;
    if magic.as_slice() != WITNESS_MAGIC || payloads.is_empty() {
        return None;
    }
    payloads
        .iter()
        .map(|item| {
            if item.len() != TRUNCATED_DIGEST_BYTES || item.len() > MAX_WITNESS_ITEM {
                return None;
            }
            Some(TruncatedDigest(
                item.as_slice().try_into().expect("length checked"),
            ))
        })
        .collect()
}

/// Decode a complete input-0 batch witness without version fallback.
///
/// V1 is `OCSV, payloads..., script`; v2 is
/// `OCS2, payloads..., stock_signature, script`. This function checks
/// canonical item counts and payload sizes, but leaves script and ECDSA
/// validation to the Bitcoin layer / Bitcoin consensus.
pub fn witness_envelope_decode(
    witness: &[Vec<u8>],
) -> Option<(BatchVersion, Vec<TruncatedDigest>)> {
    let magic = witness.first()?.as_slice();
    match magic {
        bytes if bytes == WITNESS_MAGIC => {
            let (_, envelope_items) = witness.split_last()?;
            envelope_decode(envelope_items).map(|payloads| (BatchVersion::V1, payloads))
        }
        bytes if bytes == WITNESS_MAGIC_V2 => {
            // magic + at least one payload + signature + witness script
            if witness.len() < 4 || witness.len() > MAX_BATCH_V2_PARTICIPANTS + 3 {
                return None;
            }
            let signature = &witness[witness.len() - 2];
            let script = witness.last()?;
            if signature.is_empty()
                || signature.len() > MAX_WITNESS_ITEM
                || script.is_empty()
                || witness[1..witness.len() - 2]
                    .iter()
                    .any(|item| item.len() != TRUNCATED_DIGEST_BYTES)
            {
                return None;
            }
            let payloads = witness[1..witness.len() - 2]
                .iter()
                .map(|item| TruncatedDigest(item.as_slice().try_into().expect("length checked")))
                .collect();
            Some((BatchVersion::V2, payloads))
        }
        _ => None,
    }
}

/// Batch occurrence test (module docs): is `raw_nf` an occurrence of
/// this batch? Returns the envelope index of its payload. `record` must
/// be the batch header of the transaction the envelope was taken from;
/// `ctx` is the transaction's funding ctx (vin[0]).
pub fn envelope_occurrence(
    record: &AnchorRecord,
    envelope: &[TruncatedDigest],
    ctx: &[u8; 32],
    raw_nf: &Digest,
) -> Option<u32> {
    let AnchorRecord::BatchHeader {
        count,
        batch_commit: committed,
    } = record
    else {
        return None;
    };
    if envelope.len() != *count as usize {
        return None;
    }
    if batch_commit(envelope, ctx).to_anchor() != *committed {
        return None;
    }
    let bound = binding(raw_nf, ctx).to_anchor();
    envelope
        .iter()
        .position(|payload| *payload == bound)
        .map(|index| index as u32)
}

/// Version-aware batch occurrence test. The witness magic selects the
/// commitment domain; a mismatch never falls back to the other version.
pub fn versioned_envelope_occurrence(
    version: BatchVersion,
    record: &AnchorRecord,
    envelope: &[TruncatedDigest],
    ctx: &[u8; 32],
    raw_nf: &Digest,
) -> Option<u32> {
    let AnchorRecord::BatchHeader {
        count,
        batch_commit: committed,
    } = record
    else {
        return None;
    };
    if envelope.len() != *count as usize
        || versioned_batch_commit(version, envelope, ctx).to_anchor() != *committed
    {
        return None;
    }
    let bound = binding(raw_nf, ctx).to_anchor();
    envelope
        .iter()
        .position(|payload| *payload == bound)
        .map(|index| index as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::AnchorRecord;

    fn digest(seed: u8) -> Digest {
        Digest::from_bytes([seed; 32])
    }

    #[test]
    fn envelope_roundtrip() {
        let ctx = [7u8; 32];
        let payloads: Vec<TruncatedDigest> = [1u8, 2, 3]
            .iter()
            .map(|s| binding(&digest(*s), &ctx).to_anchor())
            .collect();
        let items = envelope_encode(&payloads);
        assert_eq!(items.len(), 4);
        assert_eq!(items[0], b"OCSV");
        assert!(items.iter().all(|i| i.len() <= MAX_WITNESS_ITEM));
        assert_eq!(envelope_decode(&items), Some(payloads));
    }

    #[test]
    fn envelope_decode_rejects_bad_envelopes() {
        assert_eq!(envelope_decode(&[]), None);
        assert_eq!(envelope_decode(&[b"OCSX".to_vec(), vec![1u8; 24]]), None);
        assert_eq!(envelope_decode(&[b"OCSV".to_vec()]), None, "no payloads");
        assert_eq!(
            envelope_decode(&[b"OCSV".to_vec(), vec![1u8; 25]]),
            None,
            "payload items are exactly 24 bytes"
        );
    }

    #[test]
    fn batch_occurrence_and_commit_binding() {
        let ctx = [9u8; 32];
        let nf1 = digest(1);
        let nf2 = digest(2);
        let payloads = vec![
            binding(&nf1, &ctx).to_anchor(),
            binding(&nf2, &ctx).to_anchor(),
        ];
        let record = AnchorRecord::batch_header(&payloads, &ctx);
        assert!(record.parses_cleanly());

        // Both payloads are occurrences at their own index.
        assert_eq!(envelope_occurrence(&record, &payloads, &ctx, &nf1), Some(0));
        assert_eq!(envelope_occurrence(&record, &payloads, &ctx, &nf2), Some(1));
        assert_eq!(
            envelope_occurrence(&record, &payloads, &ctx, &digest(3)),
            None,
            "an unrelated nullifier is not an occurrence"
        );

        // batch_commit mismatch (a swapped payload) rejects every
        // occurrence query.
        let mut tampered = payloads.clone();
        tampered[1] = binding(&digest(99), &ctx).to_anchor();
        assert_eq!(envelope_occurrence(&record, &tampered, &ctx, &nf2), None);
        assert_eq!(envelope_occurrence(&record, &tampered, &ctx, &digest(99)), None);

        // Wrong ctx and wrong count reject too.
        assert_eq!(envelope_occurrence(&record, &payloads, &[8u8; 32], &nf1), None);
        assert_eq!(
            envelope_occurrence(&record, &payloads[..1], &ctx, &nf1),
            None,
            "envelope must carry exactly `count` payloads"
        );

        // A solo (non-batch) record never matches the envelope path.
        let solo = AnchorRecord::xfer(&[nf1], &ctx);
        assert_eq!(envelope_occurrence(&solo, &payloads, &ctx, &nf1), None);
        // ...and the solo record keeps its own occurrence semantics.
        assert!(solo.well_formed(&ctx, &nf1));
    }

    #[test]
    fn v2_envelope_is_versioned_and_fail_closed() {
        let ctx = [5u8; 32];
        let nf1 = digest(11);
        let nf2 = digest(12);
        let payloads = vec![
            binding(&nf1, &ctx).to_anchor(),
            binding(&nf2, &ctx).to_anchor(),
        ];
        let mut witness = envelope_v2_encode(&payloads).unwrap();
        witness.push(vec![0x30, 0x01]);
        witness.push(vec![0x51]);
        assert_eq!(
            witness_envelope_decode(&witness),
            Some((BatchVersion::V2, payloads.clone()))
        );

        let record = AnchorRecord::batch_header_v2(&payloads, &ctx);
        assert_eq!(
            versioned_envelope_occurrence(BatchVersion::V2, &record, &payloads, &ctx, &nf2),
            Some(1)
        );
        assert_eq!(
            versioned_envelope_occurrence(BatchVersion::V1, &record, &payloads, &ctx, &nf2),
            None,
            "v2 header must not validate under the v1 hash domain"
        );

        witness[0] = b"OCSV".to_vec();
        assert_eq!(
            witness_envelope_decode(&witness),
            None,
            "changing only the magic cannot reinterpret a v2 stack as v1"
        );
    }

    #[test]
    fn v2_envelope_enforces_protocol_bounds() {
        assert!(envelope_v2_encode(&[]).is_none());
        assert!(envelope_v2_encode(
            &[TruncatedDigest([1u8; TRUNCATED_DIGEST_BYTES]); MAX_BATCH_V2_PARTICIPANTS + 1]
        )
        .is_none());
        assert!(witness_envelope_decode(&[
            WITNESS_MAGIC_V2.to_vec(),
            vec![1u8; 24],
            vec![],
            vec![0x51],
        ])
        .is_none());
    }
}
