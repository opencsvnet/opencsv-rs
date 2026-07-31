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
//!     { "height": 0, "position": 0, "txid": "<64 hex>", "record": "<128 hex>" }
//!   ]
//! }
//! ```

use std::collections::HashMap;

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, TruncatedDigest, ANCHOR_SIZE};
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
}

/// A read-only anchor chain view decoded from a [`Snapshot`].
pub struct SnapshotChain {
    tip_height: u64,
    entries: Vec<Entry>,
    /// First occurrence per nullifier key in canonical order.
    nullifier_index: HashMap<TruncatedDigest, AnchorLocation>,
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
            let record_bytes = from_hex_array::<ANCHOR_SIZE>(&e.record, "snapshot record")?;
            let record = AnchorRecord::from_bytes(&record_bytes)
                .map_err(|err| format!("snapshot record at {}/{}: {err}", e.height, e.position))?;
            entries.push(Entry {
                txid,
                location: AnchorLocation {
                    height: e.height,
                    position: e.position,
                },
                record,
            });
        }
        entries.sort_by_key(|e| e.location);
        let mut nullifier_index = HashMap::new();
        for e in &entries {
            for key in e.record.nullifier_keys() {
                nullifier_index.entry(key).or_insert(e.location);
            }
        }
        Ok(Self {
            tip_height: snapshot.tip_height,
            entries,
            nullifier_index,
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

    fn first_nullifier_occurrence(&self, key: &TruncatedDigest) -> Option<AnchorLocation> {
        self.nullifier_index.get(key).copied()
    }

    fn nullifier_occurrences(&self, key: &TruncatedDigest) -> Vec<AnchorLocation> {
        self.entries
            .iter()
            .filter(|e| e.record.nullifier_keys().contains(key))
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
) -> SnapshotEntry {
    SnapshotEntry {
        height: location.height,
        position: location.position,
        txid: to_hex(txid),
        record: to_hex(&record.to_bytes()),
    }
}
