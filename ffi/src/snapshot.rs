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

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{ANCHOR_SIZE, AnchorRecord, Digest};
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
            entries.push(Entry {
                txid,
                location: AnchorLocation {
                    height: e.height,
                    position: e.position,
                },
                record,
                ctx,
            });
        }
        entries.sort_by_key(|e| e.location);
        Ok(Self {
            tip_height: snapshot.tip_height,
            entries,
        })
    }
}

impl AnchorChain for SnapshotChain {
    fn tip_height(&self) -> u64 {
        self.tip_height
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.entries
            .iter()
            .find(|e| e.location == anchor_ref.location && e.txid == anchor_ref.txid)
            .map(|e| e.record)
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.entries
            .iter()
            .find(|e| e.location == anchor_ref.location && e.txid == anchor_ref.txid)
            .map(|e| e.ctx)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        self.nullifier_occurrences(raw_nf).into_iter().next()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        self.entries
            .iter()
            .filter(|e| e.record.well_formed(&e.ctx, raw_nf))
            .map(|e| e.location)
            .collect()
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.entries
            .iter()
            .filter(|e| e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect()
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
    }
}
