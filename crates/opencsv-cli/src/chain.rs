//! A persistent [`AnchorChain`] backed by an append-only file, plus the
//! write-side seam a real Bitcoin backend will implement.
//!
//! [`FileAnchorChain`] is a **demo anchor**: it simulates the L1 with a text
//! file, sharing [`opencsv_core::MockAnchorChain`]'s semantics exactly:
//!
//! - anchors are appended to the *current tip block* (in-block `position` is
//!   the count of anchors already at that height);
//! - the tip only moves via [`FileAnchorChain::advance_blocks`] — callers
//!   decide when "blocks" are mined (the CLI has `chain advance`);
//! - confirmations are `tip − height + 1` ([`AnchorChain::confirmations_at`]);
//! - first occurrence wins for every nullifier key (paper §4.7 rule 1), with
//!   the index rebuilt on load by replaying the log;
//! - transaction IDs are derived from the entry ordinal exactly as
//!   `MockAnchorChain` does.
//!
//! A consignment's `anchor_ref` is only meaningful against the chain the
//! sender anchored to, so in multi-wallet demos every wallet must open the
//! *same* chain file (`--chain <path>`) — this stands in for the shared view
//! Bitcoin would provide. There is no file locking: concurrent writers are
//! out of scope for the prototype.
//!
//! File format (one record per line, all digests hex):
//!
//! ```text
//! opencsv-chain-v1
//! tip 12
//! entry 6 0 <txid:64hex> <anchor-record:128hex>
//! ```

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, TruncatedDigest};
use p3_baby_bear::BabyBear;

use crate::error::{io_err, Error};
use crate::hexutil::{from_hex, to_hex};

/// First line of every chain file (format version tag).
const MAGIC: &str = "opencsv-chain-v1";

/// The write side of the anchor seam: how a new anchor record gets onto the
/// chain. [`FileAnchorChain`] appends a line to its file; a `bitcoind`
/// backend would broadcast an OP_RETURN transaction instead. Wallet
/// operations that anchor (mint/send/redeem) are generic over this trait.
pub trait AnchorWriter: AnchorChain {
    /// Publish `record`, returning a reference to its on-chain location.
    fn append(&mut self, record: AnchorRecord) -> Result<AnchorRef, Error>;
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    txid: [u8; 32],
    location: AnchorLocation,
    record: AnchorRecord,
}

/// An append-only-file [`AnchorChain`] (demo backend; see module docs).
pub struct FileAnchorChain {
    path: PathBuf,
    tip_height: u64,
    entries: Vec<Entry>,
    /// First occurrence per nullifier key (never overwritten).
    nullifier_index: HashMap<TruncatedDigest, AnchorLocation>,
}

impl FileAnchorChain {
    /// Open (or create) the chain file at `path`, replaying any existing log.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let mut chain = Self {
            path,
            tip_height: 0,
            entries: Vec::new(),
            nullifier_index: HashMap::new(),
        };
        match File::open(&chain.path) {
            Ok(file) => chain.load(file)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Start a fresh log: parent dirs + magic line.
                if let Some(parent) = chain.path.parent() {
                    std::fs::create_dir_all(parent).map_err(io_err(&chain.path))?;
                }
                let mut f = chain.open_append()?;
                writeln!(f, "{MAGIC}").map_err(io_err(&chain.path))?;
            }
            Err(e) => return Err(io_err(&chain.path)(e)),
        }
        Ok(chain)
    }

    /// The chain file this instance persists to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Advance the tip by `n` blocks (without adding anchors), persisting a
    /// `tip` marker. Simulates mining; with Bitcoin this is just time
    /// passing. `n = 0` is a no-op.
    pub fn advance_blocks(&mut self, n: u64) -> Result<(), Error> {
        if n == 0 {
            return Ok(());
        }
        self.tip_height = self.tip_height.saturating_add(n);
        let mut f = self.open_append()?;
        writeln!(f, "tip {}", self.tip_height).map_err(io_err(&self.path))
    }

    /// All anchors with their references, in canonical order — the whole
    /// chain view, for snapshot export (e.g. `opencsv-anchor-server`).
    pub fn entries(&self) -> impl Iterator<Item = (AnchorRef, AnchorRecord)> + '_ {
        self.entries.iter().map(|e| {
            (
                AnchorRef {
                    txid: e.txid,
                    location: e.location,
                },
                e.record,
            )
        })
    }

    /// Append a record to the current tip block and persist it. Semantics
    /// (position, txid derivation, first-occurrence index) match
    /// `MockAnchorChain::append`.
    pub fn append(&mut self, record: AnchorRecord) -> Result<AnchorRef, Error> {
        let position = self
            .entries
            .iter()
            .filter(|e| e.location.height == self.tip_height)
            .count() as u32;
        let location = AnchorLocation {
            height: self.tip_height,
            position,
        };
        let ordinal = self.entries.len() as u32;
        let txid =
            *opencsv_core::field::hash_felts("mock-txid", &[&[BabyBear::new(ordinal)]]).as_bytes();
        let entry = Entry {
            txid,
            location,
            record,
        };
        let mut f = self.open_append()?;
        writeln!(
            f,
            "entry {} {} {} {}",
            location.height,
            location.position,
            to_hex(&txid),
            to_hex(&record.to_bytes()),
        )
        .map_err(io_err(&self.path))?;
        for key in record.nullifier_keys() {
            self.nullifier_index.entry(key).or_insert(location);
        }
        self.entries.push(entry);
        Ok(AnchorRef { txid, location })
    }

    fn open_append(&self) -> Result<File, Error> {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(io_err(&self.path))
    }

    fn load(&mut self, file: File) -> Result<(), Error> {
        let decode = |message: String| Error::Decode {
            path: self.path.clone(),
            message,
        };
        let mut lines = BufReader::new(file).lines().enumerate();
        // First line: format tag.
        match lines.next() {
            Some((_, Ok(line))) if line.trim() == MAGIC => {}
            Some((_, Ok(line))) => return Err(decode(format!("bad magic line `{line}`"))),
            Some((_, Err(e))) => return Err(io_err(&self.path)(e)),
            None => return Err(decode("empty chain file".into())),
        }
        for (n, line) in lines {
            let line = line.map_err(io_err(&self.path))?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let bad = || decode(format!("line {}: malformed `{line}`", n + 1));
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["tip", h] => {
                    self.tip_height = h.parse().map_err(|_| bad())?;
                }
                ["entry", h, p, txid_hex, record_hex] => {
                    let location = AnchorLocation {
                        height: h.parse().map_err(|_| bad())?,
                        position: p.parse().map_err(|_| bad())?,
                    };
                    let txid: [u8; 32] = from_hex(txid_hex)?.try_into().map_err(|_| bad())?;
                    let record_bytes: [u8; 64] =
                        from_hex(record_hex)?.try_into().map_err(|_| bad())?;
                    let record = AnchorRecord::from_bytes(&record_bytes)
                        .map_err(|e| decode(format!("line {}: {e}", n + 1)))?;
                    for key in record.nullifier_keys() {
                        self.nullifier_index.entry(key).or_insert(location);
                    }
                    self.entries.push(Entry {
                        txid,
                        location,
                        record,
                    });
                }
                _ => return Err(bad()),
            }
        }
        Ok(())
    }
}

impl AnchorWriter for FileAnchorChain {
    fn append(&mut self, record: AnchorRecord) -> Result<AnchorRef, Error> {
        FileAnchorChain::append(self, record)
    }
}

impl AnchorChain for FileAnchorChain {
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
        let mut locations: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.record.nullifier_keys().contains(key))
            .map(|e| e.location)
            .collect();
        locations.sort();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        let mut anchors: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect();
        anchors.sort_by_key(|(location, _)| *location);
        anchors
    }
}
