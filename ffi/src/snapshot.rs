//! An [`AnchorChain`] over a JSON snapshot of the anchor log.
//!
//! The host app fetches the whole anchor-log view from wherever it likes
//! (the demo `opencsv-anchor-server`, a bundled fixture, eventually a
//! Bitcoin indexer) and passes it in as JSON; verification then runs fully
//! offline. The format matches `opencsv-anchor-server`'s `GET /snapshot`:
//!
//! ```json
//! {
//!   "tip_height": 6,
//!   "entries": [
//!     { "height": 0, "position": 0, "txid": "<64 hex>", "ctx": "<64 hex>",
//!       "record": "<128 hex>" }
//!   ]
//! }
//! ```
//!
//! `ctx` is the anchor transaction's 32-byte context (see `opencsv-core`'s
//! anchor docs): records publish bound payloads `H("bind" ∥ raw_nf ∥ ctx)`,
//! so nullifier occurrences are recognized by scanning the snapshot and
//! testing the binding against the raw nullifier — something only the
//! consignment holders can do.

use opencsv_bitcoin::MEMPOOL_LOCATION;
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{
    versioned_batch_commit, versioned_envelope_occurrence, AnchorRecord, BatchVersion, Digest,
    TruncatedDigest, ANCHOR_SIZE,
};
use serde::{Deserialize, Serialize};

use crate::hex::{from_hex_array, to_hex};

/// Serde form of one anchor entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Block height of the anchor transaction.
    pub height: u64,
    /// In-block position of the anchor transaction.
    pub position: u32,
    /// Transaction id, 32 bytes hex.
    pub txid: String,
    /// Transaction context the record's bound payloads commit to, 32 bytes
    /// hex.
    pub ctx: String,
    /// The 64-byte anchor record, hex.
    pub record: String,
    /// Exact witness envelope for a transaction supplied as unconfirmed raw
    /// bytes. Confirmed snapshots omit this rebuildable data; the CBF index
    /// reads it from the independently fetched full block instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<SnapshotBatchEnvelope>,
}

/// Fail-closed batch witness data attached only to an exact raw transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotBatchEnvelope {
    /// `1` for the legacy `OCSV` hash domain, `2` for signed batching v2.
    pub version: u8,
    /// Canonically ordered 24-byte payloads, hex encoded.
    pub payloads: Vec<String>,
}

/// Serde form of the whole snapshot.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    /// Height of the chain tip (may exceed the highest anchor's height).
    pub tip_height: u64,
    /// All anchor entries, any order (sorted canonically on parse).
    pub entries: Vec<SnapshotEntry>,
}

struct Entry {
    txid: [u8; 32],
    location: AnchorLocation,
    record: AnchorRecord,
    ctx: [u8; 32],
    batch: Option<(BatchVersion, Vec<TruncatedDigest>)>,
}

/// A read-only anchor chain view decoded from a [`Snapshot`].
pub struct SnapshotChain {
    tip_height: u64,
    entries: Vec<Entry>,
}

impl SnapshotChain {
    /// Parse a snapshot JSON string into a chain view.
    pub fn from_json(json: &str) -> Result<Self, String> {
        let snapshot: Snapshot =
            serde_json::from_str(json).map_err(|e| format!("snapshot JSON: {e}"))?;
        Self::from_snapshot(&snapshot)
    }

    /// Build a chain view from a decoded snapshot.
    pub fn from_snapshot(snapshot: &Snapshot) -> Result<Self, String> {
        let mut entries = Vec::with_capacity(snapshot.entries.len());
        for e in &snapshot.entries {
            let txid = from_hex_array::<32>(&e.txid, "snapshot txid")?;
            let ctx = from_hex_array::<32>(&e.ctx, "snapshot ctx")?;
            let record_bytes = from_hex_array::<ANCHOR_SIZE>(&e.record, "snapshot record")?;
            let record = AnchorRecord::from_bytes(&record_bytes);
            let batch = e
                .batch
                .as_ref()
                .map(|batch| {
                    let version = match batch.version {
                        1 => BatchVersion::V1,
                        2 => BatchVersion::V2,
                        version => return Err(format!("snapshot batch version {version}")),
                    };
                    let payloads = batch
                        .payloads
                        .iter()
                        .map(|payload| {
                            from_hex_array::<24>(payload, "snapshot batch payload")
                                .map(TruncatedDigest)
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let AnchorRecord::BatchHeader {
                        count,
                        batch_commit,
                    } = record
                    else {
                        return Err("snapshot envelope accompanies a non-batch record".into());
                    };
                    if payloads.len() != usize::from(count)
                        || versioned_batch_commit(version, &payloads, &ctx).to_anchor()
                            != batch_commit
                    {
                        return Err("snapshot batch envelope does not match its record".into());
                    }
                    Ok((version, payloads))
                })
                .transpose()?;
            entries.push(Entry {
                txid,
                location: AnchorLocation {
                    height: e.height,
                    position: e.position,
                },
                record,
                ctx,
                batch,
            });
        }
        entries.sort_by_key(|e| e.location);
        Ok(Self {
            tip_height: snapshot.tip_height,
            entries,
        })
    }
}

impl SnapshotChain {
    /// Entry lookup: exact on `(location, txid)` — or by transaction id
    /// alone when the reference carries the **mempool sentinel**
    /// location [`MEMPOOL_LOCATION`] (0, 0), the same resolution
    /// contract as `opencsv-bitcoin`'s `find()`/`locate()`: a
    /// consignment written right after broadcast, before the anchor's
    /// mined position was known, still resolves. A sentinel reference
    /// whose txid is absent is the honest not-found; non-sentinel
    /// references keep the exact-match behavior.
    fn find(&self, anchor_ref: &AnchorRef) -> Option<&Entry> {
        self.entries.iter().find(|e| {
            e.txid == anchor_ref.txid
                && (e.location == anchor_ref.location
                    || anchor_ref.location == MEMPOOL_LOCATION)
        })
    }
}

impl AnchorChain for SnapshotChain {
    fn tip_height(&self) -> u64 {
        self.tip_height
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.find(anchor_ref).map(|e| e.record)
    }

    fn proof_record_at(
        &self,
        anchor_ref: &AnchorRef,
        raw_nullifiers: &[Digest],
    ) -> Option<AnchorRecord> {
        let entry = self.find(anchor_ref)?;
        match entry.record {
            AnchorRecord::BatchHeader { .. } => {
                let [raw_nf] = raw_nullifiers else {
                    return None;
                };
                let (version, payloads) = entry.batch.as_ref()?;
                versioned_envelope_occurrence(
                    *version,
                    &entry.record,
                    payloads,
                    &entry.ctx,
                    raw_nf,
                )?;
                Some(AnchorRecord::xfer(raw_nullifiers, &entry.ctx))
            }
            record => Some(record),
        }
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.find(anchor_ref).map(|e| e.ctx)
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        // Resolve by transaction id (the sentinel contract above): the
        // canonical location is the entry's real (height, position).
        self.find(anchor_ref).map(|e| e.location)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        // A confirmed occurrence always wins: it is canonically ordered and
        // proves the provisional transaction is a conflict. If settled
        // history contains none, the exact transaction injected by
        // `snapshot_with_unconfirmed_anchor` is the provisional first
        // occurrence. Returning `None` in that case makes every valid
        // zero-confirmation transfer look like `AnchorNotFound`; mint
        // consignments did not expose the bug because they carry no
        // occurrence keys.
        self.nullifier_occurrences(raw_nf)
            .into_iter()
            .next()
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|e| {
                        e.location == MEMPOOL_LOCATION && entry_matches_nullifier(e, raw_nf)
                    })
                    .map(|e| e.location)
            })
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        // Confirmed anchors have canonical order; mempool transactions do
        // not. Match BitcoinAnchorChain: the provisional transaction is
        // checked for exact binding separately, while only settled history
        // can establish an earlier authoritative occurrence.
        self.entries
            .iter()
            .filter(|e| e.location != MEMPOOL_LOCATION)
            .filter(|e| entry_matches_nullifier(e, raw_nf))
            .map(|e| e.location)
            .collect()
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.entries
            .iter()
            .filter(|e| e.location != MEMPOOL_LOCATION && e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect()
    }

    fn confirmations_at(&self, height: u64) -> u64 {
        if height == MEMPOOL_LOCATION.height || height > self.tip_height {
            0
        } else {
            self.tip_height - height + 1
        }
    }
}

/// Re-encode an entry for snapshot JSON (used by tests and the demo server).
pub fn entry_json(
    location: AnchorLocation,
    txid: &[u8; 32],
    record: &AnchorRecord,
    ctx: &[u8; 32],
) -> SnapshotEntry {
    SnapshotEntry {
        height: location.height,
        position: location.position,
        txid: to_hex(txid),
        ctx: to_hex(ctx),
        record: to_hex(&record.to_bytes()),
        batch: None,
    }
}

fn entry_matches_nullifier(entry: &Entry, raw_nf: &Digest) -> bool {
    match &entry.batch {
        Some((version, payloads)) => versioned_envelope_occurrence(
            *version,
            &entry.record,
            payloads,
            &entry.ctx,
            raw_nf,
        )
        .is_some(),
        None => entry.record.well_formed(&entry.ctx, raw_nf),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_core::accept::public_input;
    use opencsv_core::{
        accept, AcceptParams, AssetGenesis, CoinOpening, Consignment, MockVerifier, OwnerSecret,
    };

    const TEST_VK: &[u8] = b"snapshot-batch-projection-vk";

    fn digest(byte: u8) -> Digest {
        Digest::from_bytes([byte; 32])
    }

    fn location(height: u64, position: u32) -> AnchorLocation {
        AnchorLocation { height, position }
    }

    #[test]
    fn exact_mempool_transfer_is_provisional_first_occurrence() {
        let raw_nf = digest(7);
        let ctx = [8_u8; 32];
        let record = AnchorRecord::xfer(&[raw_nf], &ctx);
        let chain = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![entry_json(MEMPOOL_LOCATION, &[9_u8; 32], &record, &ctx)],
        })
        .unwrap();

        assert_eq!(
            chain.first_nullifier_occurrence(&raw_nf),
            Some(MEMPOOL_LOCATION),
        );
        assert!(chain.nullifier_occurrences(&raw_nf).is_empty());
    }

    #[test]
    fn exact_mempool_batch_envelope_is_provisional_first_occurrence() {
        let raw_nf = digest(20);
        let ctx = [21_u8; 32];
        let payloads = vec![
            opencsv_core::binding(&digest(22), &ctx).to_anchor(),
            opencsv_core::binding(&raw_nf, &ctx).to_anchor(),
        ];
        let record = AnchorRecord::batch_header_v2(&payloads, &ctx);
        let mut entry = entry_json(MEMPOOL_LOCATION, &[23_u8; 32], &record, &ctx);
        entry.batch = Some(SnapshotBatchEnvelope {
            version: 2,
            payloads: payloads
                .iter()
                .map(|payload| to_hex(payload.as_bytes()))
                .collect(),
        });
        let chain = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![entry],
        })
        .unwrap();

        assert_eq!(
            chain.first_nullifier_occurrence(&raw_nf),
            Some(MEMPOOL_LOCATION),
        );
        assert_eq!(
            chain.proof_record_at(
                &AnchorRef {
                    txid: [23_u8; 32],
                    location: MEMPOOL_LOCATION,
                },
                &[raw_nf],
            ),
            Some(AnchorRecord::xfer(&[raw_nf], &ctx)),
        );
        assert_eq!(chain.first_nullifier_occurrence(&digest(24)), None);
        assert_eq!(
            chain.proof_record_at(
                &AnchorRef {
                    txid: [23_u8; 32],
                    location: MEMPOOL_LOCATION,
                },
                &[digest(24)],
            ),
            None,
        );
    }

    #[test]
    fn accept_projects_exact_batch_member_into_its_proof_statement() {
        let raw_nf = digest(30);
        let ctx = [31_u8; 32];
        let recipient = OwnerSecret::from_bytes([32_u8; 32]);
        let genesis = AssetGenesis {
            issuer_pk: [33_u8; 32],
            currency_code: *b"USD",
            terms_hash: digest(34),
            nonce: 35,
        };
        let asset_id = genesis.asset_id();
        let opening = CoinOpening {
            asset_id,
            value: 5,
            owner: recipient.owner(),
            randomness: digest(36),
        };
        let other_nf = digest(37);
        let payloads = vec![
            opencsv_core::binding(&other_nf, &ctx).to_anchor(),
            opencsv_core::binding(&raw_nf, &ctx).to_anchor(),
        ];
        let batch_header = AnchorRecord::batch_header_v2(&payloads, &ctx);
        let txid = [38_u8; 32];
        let mut entry = entry_json(MEMPOOL_LOCATION, &txid, &batch_header, &ctx);
        entry.batch = Some(SnapshotBatchEnvelope {
            version: 2,
            payloads: payloads
                .iter()
                .map(|payload| to_hex(payload.as_bytes()))
                .collect(),
        });
        let chain = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![entry],
        })
        .unwrap();
        let proof_record = AnchorRecord::xfer(&[raw_nf], &ctx);
        let consignment = Consignment {
            coin_openings: vec![opening],
            nullifiers: vec![raw_nf],
            proof: MockVerifier::prove(TEST_VK, &public_input(&proof_record, &ctx, &[opening])),
            anchor_ref: AnchorRef {
                txid,
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };

        let accepted = accept(
            &consignment,
            &chain,
            &MockVerifier,
            &AcceptParams {
                vk: TEST_VK,
                required_confirmations: 0,
                recipient_secrets: &[recipient],
                known_assets: &[asset_id],
            },
        )
        .unwrap();

        assert_eq!(accepted.anchor, MEMPOOL_LOCATION);
        assert_eq!(accepted.coins, vec![opening.to_coin()]);
    }

    #[test]
    fn snapshot_rejects_batch_envelope_that_does_not_match_header() {
        let ctx = [25_u8; 32];
        let payloads = vec![opencsv_core::binding(&digest(26), &ctx).to_anchor()];
        let record = AnchorRecord::batch_header_v2(&payloads, &ctx);
        let mut entry = entry_json(MEMPOOL_LOCATION, &[27_u8; 32], &record, &ctx);
        entry.batch = Some(SnapshotBatchEnvelope {
            version: 2,
            payloads: vec![to_hex(&[28_u8; 24])],
        });

        let error = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![entry],
        })
        .err()
        .unwrap();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn settled_occurrence_wins_over_provisional_transfer() {
        let raw_nf = digest(10);
        let settled_ctx = [11_u8; 32];
        let provisional_ctx = [12_u8; 32];
        let settled_location = location(90, 2);
        let chain = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![
                entry_json(
                    MEMPOOL_LOCATION,
                    &[13_u8; 32],
                    &AnchorRecord::xfer(&[raw_nf], &provisional_ctx),
                    &provisional_ctx,
                ),
                entry_json(
                    settled_location,
                    &[14_u8; 32],
                    &AnchorRecord::xfer(&[raw_nf], &settled_ctx),
                    &settled_ctx,
                ),
            ],
        })
        .unwrap();

        assert_eq!(
            chain.first_nullifier_occurrence(&raw_nf),
            Some(settled_location),
        );
    }

    #[test]
    fn unrelated_mempool_record_is_not_an_occurrence() {
        let raw_nf = digest(15);
        let ctx = [16_u8; 32];
        let chain = SnapshotChain::from_snapshot(&Snapshot {
            tip_height: 100,
            entries: vec![entry_json(
                MEMPOOL_LOCATION,
                &[17_u8; 32],
                &AnchorRecord::xfer(&[digest(18)], &ctx),
                &ctx,
            )],
        })
        .unwrap();

        assert_eq!(chain.first_nullifier_occurrence(&raw_nf), None);
    }
}
