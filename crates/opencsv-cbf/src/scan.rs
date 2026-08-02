//! The self-scan-first scan engine (paper §4.7.1, amended): trustless
//! exclusion by default, without any indexer and without downloading
//! every block.
//!
//! Anchor transactions carry the protocol-constant marker output
//! ([`opencsv_bitcoin::MARKER_SPK`]) at output index 1, so BIP158 basic
//! filters — which exclude OP_RETURN but include ordinary
//! scriptPubKeys — match anchor-bearing blocks. [`ScanIndex::scan_sync`]
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

use std::path::PathBuf;

use opencsv_bitcoin::{Network, MARKER_SPK};
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest};

use crate::client::CbfClient;
use crate::error::Error;
use crate::fullscan::{anchors_in_block, ScannedAnchor};
use crate::hash::{from_hex, hash_to_display, to_hex};

/// First line of every scan-index file (format version tag).
const MAGIC: &str = "opencsv-cbf-scan-index-v1";

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
}

impl ScanIndex {
    /// Open the index at `dir` (created on first sync). A missing or
    /// unparseable file starts a fresh index — it is a rebuildable
    /// cache.
    pub fn open(dir: impl Into<PathBuf>, network: Network) -> Result<Self, Error> {
        let dir = dir.into();
        let mut index = Self {
            dir,
            network,
            from_height: 0,
            synced_tip: 0,
            occurrences: Vec::new(),
            counters: ScanCounters::default(),
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
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(MAGIC) {
            // Unknown format: rebuild (rebuildable cache).
            return Ok(());
        }
        for line in lines {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let bad = || Error::Decode(format!("scan index: malformed `{line}`"));
            match fields.as_slice() {
                ["network", name] => {
                    if Network::parse(name).ok() != Some(self.network) {
                        return Err(Error::Decode(format!(
                            "scan index is for network `{name}`, not {}",
                            self.network.name()
                        )));
                    }
                }
                ["from", h] => self.from_height = h.parse().map_err(|_| bad())?,
                ["tip", h] => self.synced_tip = h.parse().map_err(|_| bad())?,
                ["occurrence", h, p, txid, ctx, record] => {
                    self.occurrences.push(ScannedAnchor {
                        location: AnchorLocation {
                            height: h.parse().map_err(|_| bad())?,
                            position: p.parse().map_err(|_| bad())?,
                        },
                        txid: {
                            let mut bytes: [u8; 32] = from_hex(txid)
                                .map_err(|_| bad())?
                                .try_into()
                                .map_err(|_| bad())?;
                            bytes.reverse();
                            bytes
                        },
                        record: AnchorRecord::from_bytes(
                            &from_hex(record)
                                .map_err(|_| bad())?
                                .try_into()
                                .map_err(|_| bad())?,
                        ),
                        ctx: from_hex(ctx).map_err(|_| bad())?.try_into().map_err(|_| bad())?,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        let mut out = format!(
            "{MAGIC}\nnetwork {}\nfrom {}\ntip {}\n",
            self.network.name(),
            self.from_height,
            self.synced_tip
        );
        for e in &self.occurrences {
            out.push_str(&format!(
                "occurrence {} {} {} {} {}\n",
                e.location.height,
                e.location.position,
                hash_to_display(&e.txid),
                to_hex(&e.ctx),
                to_hex(&e.record.to_bytes()),
            ));
        }
        std::fs::write(self.path(), out)?;
        Ok(())
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
            if client.filter_matches(height, &MARKER_SPK)? {
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
            .filter(|e| {
                e.location.height >= birth
                    && e.location.height <= spend
                    && e.record.well_formed(&e.ctx, raw_nf)
            })
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

/// The scan index as an anchor chain: tip = synced tip, occurrences
/// from the local index only.
impl AnchorChain for ScanIndex {
    fn tip_height(&self) -> u64 {
        self.synced_tip
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        self.find(anchor_ref).map(|e| e.record)
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
            .filter(|e| e.record.well_formed(&e.ctx, raw_nf))
            .map(|e| e.location)
            .min()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        let mut locations: Vec<_> = self
            .occurrences
            .iter()
            .filter(|e| e.record.well_formed(&e.ctx, raw_nf))
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
