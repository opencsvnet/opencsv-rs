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
//! - each entry carries a 32-byte transaction context `ctx` (a synthetic
//!   outpoint; in production the funding input's outpoint of the anchor
//!   transaction), and records publish only bound payloads `H("bind" ∥
//!   raw_nf ∥ ctx)` — occurrence queries take the raw nullifier and scan the
//!   log testing the binding, so only consignment holders can recognize
//!   their nullifiers (paper §4.7 rule 1, amended; see `opencsv-core`'s
//!   anchor docs);
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
//! opencsv-chain-v3
//! tip 12
//! entry 6 0 <txid:64hex> <ctx:64hex> <anchor-record:128hex>
//! ```
//!
//! Version 1 and 2 files are **not** migrated: v1 anchors predate the
//! context binding, and v2 anchors carry raw nullifier payloads with a
//! recomputable sidecar binding (the broken anti-grief model) — their
//! semantics differ from v3's bound payloads. Opening either fails with a
//! clear error — start a fresh chain file.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest};
use p3_baby_bear::BabyBear;

use crate::error::{io_err, Error};
use crate::hexutil::{from_hex, to_hex};

/// First line of every chain file (format version tag).
const MAGIC: &str = "opencsv-chain-v3";

/// The write side of the anchor seam: how a new anchor record gets onto the
/// chain. [`FileAnchorChain`] appends a line to its file; a `bitcoind`
/// backend would broadcast an OP_RETURN transaction instead. Wallet
/// operations that anchor (mint/send/redeem) are generic over this trait.
pub trait AnchorWriter: AnchorChain {
    /// Publish `record` under transaction context `ctx`, returning a
    /// reference to its on-chain location. The caller draws `ctx` *before*
    /// constructing the record (the bound payloads commit to it); see
    /// [`opencsv_core::anchor`].
    fn append(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> Result<AnchorRef, Error>;
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    txid: [u8; 32],
    location: AnchorLocation,
    record: AnchorRecord,
    ctx: [u8; 32],
}

/// An append-only-file [`AnchorChain`] (demo backend; see module docs).
pub struct FileAnchorChain {
    path: PathBuf,
    tip_height: u64,
    entries: Vec<Entry>,
}

impl FileAnchorChain {
    /// Open (or create) the chain file at `path`, replaying any existing log.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        let path = path.into();
        let mut chain = Self {
            path,
            tip_height: 0,
            entries: Vec::new(),
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

    /// All anchors with their references and transaction contexts, in
    /// canonical order — the whole chain view, for snapshot export (e.g.
    /// `opencsv-anchor-server`).
    pub fn entries(&self) -> impl Iterator<Item = (AnchorRef, AnchorRecord, [u8; 32])> + '_ {
        self.entries.iter().map(|e| {
            (
                AnchorRef {
                    txid: e.txid,
                    location: e.location,
                },
                e.record,
                e.ctx,
            )
        })
    }

    /// Append a record under transaction context `ctx` to the current tip
    /// block and persist it. Semantics (position, txid derivation) match
    /// [`opencsv_core::MockAnchorChain::append_with_ctx`].
    pub fn append(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> Result<AnchorRef, Error> {
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
            ctx,
        };
        let mut f = self.open_append()?;
        writeln!(
            f,
            "entry {} {} {} {} {}",
            location.height,
            location.position,
            to_hex(&txid),
            to_hex(&ctx),
            to_hex(&record.to_bytes()),
        )
        .map_err(io_err(&self.path))?;
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
            Some((_, Ok(line))) if line.trim().starts_with("opencsv-chain-v") => {
                return Err(decode(format!(
                    "chain log is format `{}`, which predates bound nullifier \
                     payloads and cannot be migrated — start a fresh v3 chain file",
                    line.trim()
                )));
            }
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
                ["entry", h, p, txid_hex, ctx_hex, record_hex] => {
                    let location = AnchorLocation {
                        height: h.parse().map_err(|_| bad())?,
                        position: p.parse().map_err(|_| bad())?,
                    };
                    let txid: [u8; 32] = from_hex(txid_hex)?.try_into().map_err(|_| bad())?;
                    let ctx: [u8; 32] = from_hex(ctx_hex)?.try_into().map_err(|_| bad())?;
                    let record_bytes: [u8; 64] =
                        from_hex(record_hex)?.try_into().map_err(|_| bad())?;
                    let record = AnchorRecord::from_bytes(&record_bytes);
                    self.entries.push(Entry {
                        txid,
                        location,
                        record,
                        ctx,
                    });
                }
                _ => return Err(bad()),
            }
        }
        Ok(())
    }
}

impl AnchorWriter for FileAnchorChain {
    fn append(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> Result<AnchorRef, Error> {
        FileAnchorChain::append(self, record, ctx)
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
        // Linear scan over the replayed log, same as MockAnchorChain: an
        // occurrence is an entry whose record binds `raw_nf` under the
        // entry's own ctx.
        let mut locations: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.record.well_formed(&e.ctx, raw_nf))
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
