//! The self-scan-first scan engine (paper §4.7.1, amended): trustless
//! exclusion by default, without any indexer and without downloading
//! every block.
//!
//! Anchor transactions carry the protocol-constant marker output
//! ([`opencsv_bitcoin::MARKER_SPK`], plus the historical marker during
//! migration) at output index 1, so BIP158 basic filters — which exclude
//! direct OP_RETURN outputs but include P2WSH programs — match
//! anchor-bearing blocks. [`ScanIndex::scan_sync`]
//! walks the verified filters from a wallet's birth height to the tip;
//! every match triggers an SPV block fetch (merkle-verified against the
//! PoW-checked header chain, exactly like [`CbfClient::verify_anchor`]),
//! and every 64-byte OP_RETURN candidate is stored with its recomputed
//! funding ctx. [`ScanIndex::scan_check`] then answers occurrence
//! queries **locally** — no network at check time — and the
//! [`AnchorChain`] impl lets [`accept`](opencsv_core::accept) run
//! against the scan alone.
//!
//! Roles (see the crate README for the full comparison): the scan
//! engine is the default (cheap: filters + only anchor blocks);
//! [`crate::FullScanChain`] is the fallback for windows predating the
//! marker or for paranoia about filter correctness; and
//! `opencsv-core`'s `CrossCheckedChain` is the N-of-M posture when
//! indexers are acceptable anyway.
//!
//! Marker-copy noise (someone else putting the constant marker in
//! their own transaction) costs a block download and nothing else: the
//! fetched block is merkle-verified and simply contains no record
//! binding the queried nullifier. False-positive filter matches
//! (probability ~N/784931 per block) cost the same.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use opencsv_bitcoin::{Network, LEGACY_MARKER_SPK, MARKER_SPK};
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest};
use sha2::{Digest as _, Sha256};

use crate::client::CbfClient;
use crate::error::Error;
use crate::fullscan::{anchors_in_block, ScannedAnchor};
use crate::hash::{from_hex, hash_to_display, to_hex};

/// First line of every scan-index file (format version tag).
const MAGIC: &str = "opencsv-cbf-scan-index-v2";

/// How [`ScanIndex::open`] initialized its rebuildable cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanLoadStatus {
    /// No prior index existed.
    Fresh,
    /// A complete checksummed index was loaded.
    Loaded,
    /// A corrupt, partial, or incompatible index was discarded.
    RebuildRequired,
}

/// Bandwidth accounting of [`ScanIndex::scan_sync`] runs (payload bytes
/// fetched from peers; cache hits excluded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanCounters {
    /// BIP158 filter bytes fetched.
    pub filters_bytes: u64,
    /// Block bytes fetched.
    pub blocks_bytes: u64,
    /// Blocks fetched because their filter matched.
    pub blocks_fetched: u64,
}

/// A persistent, rebuildable occurrence index built from BIP158 filter
/// scans (module docs). Load with [`ScanIndex::open`], keep current
/// with [`ScanIndex::scan_sync`], query with [`ScanIndex::scan_check`]
/// or the [`AnchorChain`] impl.
pub struct ScanIndex {
    dir: PathBuf,
    network: Network,
    /// The scan start of the first `scan_sync` (persisted; later calls
    /// with an earlier `from_height` resume from the synced tip — delete
    /// the index to rescan deeper).
    from_height: u64,
    /// Highest height whose filter has been checked.
    synced_tip: u64,
    occurrences: Vec<ScannedAnchor>,
    counters: ScanCounters,
    load_status: ScanLoadStatus,
}

impl ScanIndex {
    /// Open the index at `dir` (created on first sync). A missing file
    /// starts fresh. A corrupt, partial, or incompatible file is
    /// discarded and reported through [`ScanIndex::load_status`]; the
    /// index is a rebuildable cache.
    pub fn open(dir: impl Into<PathBuf>, network: Network) -> Result<Self, Error> {
        let dir = dir.into();
        let mut index = Self {
            dir,
            network,
            from_height: 0,
            synced_tip: 0,
            occurrences: Vec::new(),
            counters: ScanCounters::default(),
            load_status: ScanLoadStatus::Fresh,
        };
        index.load()?;
        Ok(index)
    }

    fn path(&self) -> PathBuf {
        self.dir.join("scan-index.log")
    }

    fn load(&mut self) -> Result<(), Error> {
        let text = match std::fs::read_to_string(self.path()) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(e)),
        };
        let Some(body) = verified_body(&text) else {
            self.load_status = ScanLoadStatus::RebuildRequired;
            return Ok(());
        };
        let Some((from_height, synced_tip, occurrences)) = decode_body(body, self.network) else {
            self.load_status = ScanLoadStatus::RebuildRequired;
            return Ok(());
        };
        self.from_height = from_height;
        self.synced_tip = synced_tip;
        self.occurrences = occurrences;
        self.load_status = ScanLoadStatus::Loaded;
        Ok(())
    }

    fn persist(&self) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        let mut body = format!(
            "{MAGIC}\nnetwork {}\nfrom {}\ntip {}\n",
            self.network.name(),
            self.from_height,
            self.synced_tip
        );
        for e in &self.occurrences {
            let mut line = format!(
                "occurrence {} {} {} {} {}",
                e.location.height,
                e.location.position,
                hash_to_display(&e.txid),
                to_hex(&e.ctx),
                to_hex(&e.record.to_bytes()),
            );
            if let Some(batch) = &e.batch {
                let envelope: Vec<u8> = batch.envelope.iter().flat_map(|p| *p.as_bytes()).collect();
                let kind = match batch.version {
                    opencsv_core::BatchVersion::V1 => "batch1",
                    opencsv_core::BatchVersion::V2 => "batch2",
                };
                line.push_str(&format!(" {kind} {} {}", batch.index, to_hex(&envelope)));
            }
            body.push_str(&line);
            body.push('\n');
        }
        let checksum = Sha256::digest(body.as_bytes());
        let file = format!("{body}checksum {}\n", to_hex(&checksum));
        atomic_write(&self.path(), file.as_bytes())
    }

    /// How this instance initialized its on-disk cache.
    pub fn load_status(&self) -> ScanLoadStatus {
        self.load_status
    }

    /// Sync the index from its resume point up to the client's verified
    /// tip: check every block's basic filter for the protocol marker
    /// output, SPV-fetch (merkle-verified) the matching blocks, and
    /// store every OP_RETURN candidate with its recomputed ctx.
    ///
    /// `from_height` applies to a fresh index only (typically the
    /// wallet's birth height); an existing index resumes from its
    /// synced tip. `from_height == 0` is accepted and clamped to 1
    /// (genesis carries no anchors; 0 is the natural "scan everything"
    /// spelling).
    pub fn scan_sync(&mut self, client: &mut CbfClient, from_height: u64) -> Result<(), Error> {
        let from_height = from_height.max(1);
        if self.from_height == 0 {
            self.from_height = from_height;
            self.synced_tip = from_height.saturating_sub(1);
        }
        let tip = client.tip_height();
        let (filters_before, blocks_before) = client.fetched_bytes();
        for height in (self.synced_tip + 1)..=tip {
            let current_marker = client.filter_matches(height, &MARKER_SPK)?;
            let legacy_marker = client.filter_matches(height, &LEGACY_MARKER_SPK)?;
            if current_marker || legacy_marker {
                let block_hash = client
                    .block_hash(height)
                    .ok_or_else(|| Error::Consensus(format!("no header at height {height}")))?;
                let block = client.fetch_block(&block_hash)?;
                if block.compute_merkle_root() != block.header.merkle_root {
                    return Err(Error::Consensus(format!(
                        "block {} merkle root does not match its header",
                        hash_to_display(&block_hash)
                    )));
                }
                self.counters.blocks_fetched += 1;
                self.occurrences.extend(anchors_in_block(&block, height));
            }
            self.synced_tip = height;
        }
        let (filters_after, blocks_after) = client.fetched_bytes();
        self.counters.filters_bytes += filters_after - filters_before;
        self.counters.blocks_bytes += blocks_after - blocks_before;
        self.persist()?;
        Ok(())
    }

    /// Local-only occurrence check (no network): the earliest indexed
    /// record in `[birth, spend]` binding `raw_nf`, with its ctx.
    pub fn scan_check(
        &self,
        raw_nf: &Digest,
        birth: u64,
        spend: u64,
    ) -> Option<(AnchorLocation, [u8; 32])> {
        self.occurrences
            .iter()
            .filter(|e| e.location.height >= birth && e.location.height <= spend && e.binds(raw_nf))
            .map(|e| (e.location, e.ctx))
            .min_by_key(|(location, _)| *location)
    }

    /// Highest height whose filter has been checked (the synced tip).
    pub fn synced_tip(&self) -> u64 {
        self.synced_tip
    }

    /// Every indexed OP_RETURN candidate, in canonical order.
    pub fn occurrences(&self) -> &[ScannedAnchor] {
        &self.occurrences
    }

    /// Cumulative bandwidth counters over all syncs of this index.
    pub fn counters(&self) -> ScanCounters {
        self.counters
    }

    /// Entry lookup by reference: transaction id plus location — or by
    /// transaction id alone for broadcast-style refs carrying the
    /// mempool placeholder location (the `AnchorChain` contract, as in
    /// `FullScanChain`).
    fn find(&self, anchor_ref: &AnchorRef) -> Option<&ScannedAnchor> {
        let mempool = AnchorLocation {
            height: 0,
            position: 0,
        };
        self.occurrences.iter().find(|e| {
            e.txid == anchor_ref.txid
                && (e.location == anchor_ref.location || anchor_ref.location == mempool)
        })
    }
}

fn verified_body(text: &str) -> Option<&str> {
    let text = text.strip_suffix('\n')?;
    let (body_without_newline, checksum_line) = text.rsplit_once('\n')?;
    let checksum = checksum_line.strip_prefix("checksum ")?;
    let expected = from_hex(checksum).ok()?;
    let body_len = body_without_newline.len().checked_add(1)?;
    let body = text.get(..body_len)?;
    (expected.as_slice() == Sha256::digest(body.as_bytes()).as_slice()).then_some(body)
}

fn decode_body(body: &str, network: Network) -> Option<(u64, u64, Vec<ScannedAnchor>)> {
    let mut lines = body.lines();
    if lines.next().map(str::trim) != Some(MAGIC) {
        return None;
    }
    let mut saw_network = false;
    let mut from_height: Option<u64> = None;
    let mut synced_tip: Option<u64> = None;
    let mut occurrences = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["network", name] => {
                if saw_network || Network::parse(name).ok() != Some(network) {
                    return None;
                }
                saw_network = true;
            }
            ["from", h] if from_height.is_none() => from_height = h.parse().ok(),
            ["tip", h] if synced_tip.is_none() => synced_tip = h.parse().ok(),
            ["occurrence", h, p, txid, ctx, record, rest @ ..] => {
                let txid = {
                    let mut bytes: [u8; 32] = from_hex(txid).ok()?.try_into().ok()?;
                    bytes.reverse();
                    bytes
                };
                let batch = match rest {
                    [] => None,
                    [kind @ ("batch" | "batch1" | "batch2"), index, envelope] => {
                        let envelope_bytes = from_hex(envelope).ok()?;
                        if envelope_bytes.len() % 24 != 0 {
                            return None;
                        }
                        Some(crate::fullscan::BatchCandidate {
                            version: if *kind == "batch2" {
                                opencsv_core::BatchVersion::V2
                            } else {
                                opencsv_core::BatchVersion::V1
                            },
                            index: index.parse().ok()?,
                            envelope: envelope_bytes
                                .chunks_exact(24)
                                .map(|chunk| {
                                    opencsv_core::TruncatedDigest(
                                        chunk.try_into().expect("24-byte chunk"),
                                    )
                                })
                                .collect(),
                        })
                    }
                    _ => return None,
                };
                occurrences.push(ScannedAnchor {
                    location: AnchorLocation {
                        height: h.parse().ok()?,
                        position: p.parse().ok()?,
                    },
                    txid,
                    record: AnchorRecord::from_bytes(&from_hex(record).ok()?.try_into().ok()?),
                    ctx: from_hex(ctx).ok()?.try_into().ok()?,
                    batch,
                });
            }
            _ => return None,
        }
    }
    let from_height = from_height?;
    let synced_tip = synced_tip?;
    if !saw_network
        || (synced_tip > 0 && from_height == 0)
        || synced_tip < from_height.saturating_sub(1)
        || occurrences
            .iter()
            .any(|entry| entry.location.height < from_height || entry.location.height > synced_tip)
        || occurrences
            .windows(2)
            .any(|pair| pair[0].location > pair[1].location)
    {
        return None;
    }
    Some((from_height, synced_tip, occurrences))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Io(std::io::Error::other("scan index path has no parent")))?;
    std::fs::create_dir_all(parent)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
        .as_nanos();
    let temp = parent.join(format!(".scan-index-{}-{nonce}.tmp", std::process::id()));
    let result: std::io::Result<()> = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() && temp.exists() {
        let _ = std::fs::remove_file(&temp);
    }
    result.map_err(Error::Io)
}

/// The scan index as an anchor chain: tip = synced tip, occurrences
/// from the local index only.
impl AnchorChain for ScanIndex {
    fn tip_height(&self) -> u64 {
        self.synced_tip
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.find(anchor_ref).map(|e| e.record)
    }

    fn proof_record_at(
        &self,
        anchor_ref: &AnchorRef,
        raw_nullifiers: &[Digest],
    ) -> Option<AnchorRecord> {
        let [raw_nf] = raw_nullifiers else {
            return self
                .find(anchor_ref)
                .filter(|entry| !matches!(entry.record, AnchorRecord::BatchHeader { .. }))
                .map(|entry| entry.record);
        };
        let mempool = AnchorLocation {
            height: 0,
            position: 0,
        };
        let entry = self.occurrences.iter().find(|entry| {
            entry.txid == anchor_ref.txid
                && (entry.location == anchor_ref.location || anchor_ref.location == mempool)
                && entry.binds(raw_nf)
        })?;
        match entry.record {
            AnchorRecord::BatchHeader { .. } => {
                Some(AnchorRecord::xfer(raw_nullifiers, &entry.ctx))
            }
            record => Some(record),
        }
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        self.find(anchor_ref).map(|e| e.ctx)
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        self.find(anchor_ref).map(|e| e.location)
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        self.occurrences
            .iter()
            .filter(|e| e.binds(raw_nf))
            .map(|e| e.location)
            .min()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        let mut locations: Vec<_> = self
            .occurrences
            .iter()
            .filter(|e| e.binds(raw_nf))
            .map(|e| e.location)
            .collect();
        locations.sort();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.occurrences
            .iter()
            .filter(|e| e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksummed_index_round_trips_and_detects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let mut index = ScanIndex::open(dir.path(), Network::Signet).unwrap();
        assert_eq!(index.load_status(), ScanLoadStatus::Fresh);
        index.from_height = 10;
        index.synced_tip = 20;
        index.persist().unwrap();

        let loaded = ScanIndex::open(dir.path(), Network::Signet).unwrap();
        assert_eq!(loaded.load_status(), ScanLoadStatus::Loaded);
        assert_eq!(loaded.synced_tip(), 20);

        let path = dir.path().join("scan-index.log");
        let mut bytes = std::fs::read(&path).unwrap();
        let offset = bytes
            .iter()
            .position(|byte| *byte == b'2')
            .expect("version byte");
        bytes[offset] = b'1';
        std::fs::write(path, bytes).unwrap();

        let rebuilt = ScanIndex::open(dir.path(), Network::Signet).unwrap();
        assert_eq!(rebuilt.load_status(), ScanLoadStatus::RebuildRequired);
        assert_eq!(rebuilt.synced_tip(), 0);
    }

    #[test]
    fn legacy_index_requires_a_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("scan-index.log"),
            "opencsv-cbf-scan-index-v1\nnetwork signet\nfrom 10\ntip 20\n",
        )
        .unwrap();

        let rebuilt = ScanIndex::open(dir.path(), Network::Signet).unwrap();
        assert_eq!(rebuilt.load_status(), ScanLoadStatus::RebuildRequired);
        assert_eq!(rebuilt.synced_tip(), 0);
    }
}
