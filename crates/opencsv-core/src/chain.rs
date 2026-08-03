//! The anchor chain abstraction and an in-memory mock (paper §4.7).
//!
//! [`AnchorChain`] is the seam over Bitcoin: the production backend will read
//! anchored payloads from `bitcoind` RPC; [`MockAnchorChain`] is an in-memory
//! append-only ordered log for tests. Ordering is `(block_height, position)`
//! — block order, then in-block order — and *first occurrence wins* for any
//! nullifier (paper §4.7 rule 1).
//!
//! ## Transaction context (`ctx`) and occurrence recognition
//!
//! Every anchor carries a 32-byte transaction context: in production the
//! funding input's outpoint of the anchor transaction; here, a synthetic
//! random outpoint per entry. On-chain records publish only **bound
//! payloads** `P = H("bind" ∥ raw_nf ∥ ctx)` — never raw nullifiers (see
//! [`crate::anchor`]). Occurrence queries therefore take the *raw*
//! nullifier: an occurrence of `raw_nf` is an entry whose record satisfies
//! [`AnchorRecord::well_formed`] under the entry's own `ctx`. Only the
//! coin's consignment holders (who know `raw_nf`) can recognize occurrences
//! — that privacy is intended: chain watchers see unlinkable bound payloads,
//! and a byte-copied record (bound to the victim's `ctx`) is an occurrence
//! under nobody's `ctx` but the victim's, so copy-griefing cannot reorder
//! the victim's spend. A genuine double-spend — two anchors, each binding
//! the same `raw_nf` under its own `ctx` — is still detected: the first
//! occurrence wins.

use rand::RngExt;
use serde::{Deserialize, Serialize};

use crate::anchor::AnchorRecord;
use crate::digest::Digest;
use crate::field::{felt, hash_felts};

/// Location of an anchor in the canonical chain order (paper §4.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnchorLocation {
    /// Block height containing the anchor transaction.
    pub height: u64,
    /// In-block position of the anchor transaction.
    pub position: u32,
}

/// A reference to a specific on-chain anchor, as carried in a consignment
/// (paper §4.8: `anchor_ref = (txid, block_height, position)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRef {
    /// ID of the Bitcoin transaction carrying the anchor.
    pub txid: [u8; 32],
    /// Claimed location of that transaction.
    pub location: AnchorLocation,
}

/// A totally ordered, append-only log of anchor records — what OpenCSV
/// requires from the base chain (paper §3.2, §4.7).
pub trait AnchorChain {
    /// Height of the chain tip.
    fn tip_height(&self) -> u64;

    /// Fetch the anchor record at the referenced location, returning `None`
    /// if no record exists there or the transaction ID does not match
    /// (paper §4.8 step 3a: "the anchor transaction exists at the claimed
    /// position").
    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord>;

    /// The 32-byte transaction context of the anchor at the referenced
    /// location (in production: the funding input's outpoint of the anchor
    /// transaction), needed to evaluate [`AnchorRecord::well_formed`].
    /// Returns `None` under the same conditions as [`AnchorChain::anchor_at`].
    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]>;

    /// Resolve an anchor reference to its canonical on-chain location.
    ///
    /// For chains where anchors land at a known position (the mock, the
    /// file demo chain), this is just the claimed location, provided the
    /// anchor exists there (paper §4.8 step 3a: "the anchor transaction
    /// exists at the claimed position"). A `bitcoind` backend broadcasts
    /// into the mempool, where the block height and in-block position are
    /// unknowable at anchor time, so its references carry a placeholder
    /// location and it overrides this to resolve by transaction ID.
    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        self.anchor_at(anchor_ref).map(|_| anchor_ref.location)
    }

    /// The first occurrence of a raw nullifier in canonical chain order, if
    /// any (paper §4.7 rule 1): an entry whose record binds `raw_nf` under
    /// the entry's `ctx` (see module docs). For compressed transfers, query
    /// the raw nullifier *commitment*.
    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation>;

    /// All occurrences of a raw nullifier in canonical chain order. More
    /// than one entry means a (failed, by rule 1) double-spend attempt is
    /// observable — but only to holders of `raw_nf` (see module docs).
    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation>;

    /// All anchors at or below `height`, in canonical order. Used by the
    /// supply audit (paper §4.9).
    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)>;

    /// Confirmation depth of an anchor at `height`: `tip − height + 1`, or 0
    /// if `height` is above the tip (paper §4.7 rule 2).
    fn confirmations_at(&self, height: u64) -> u64 {
        if height > self.tip_height() {
            0
        } else {
            self.tip_height() - height + 1
        }
    }
}

/// An in-memory append-only anchor chain for tests and prototypes.
#[derive(Clone, Debug, Default)]
pub struct MockAnchorChain {
    tip_height: u64,
    entries: Vec<Entry>,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    txid: [u8; 32],
    location: AnchorLocation,
    record: AnchorRecord,
    ctx: [u8; 32],
}

impl MockAnchorChain {
    /// An empty chain with tip at height 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the tip by `n` blocks (without adding anchors).
    pub fn advance_blocks(&mut self, n: u64) {
        self.tip_height = self.tip_height.saturating_add(n);
    }

    /// A fresh random transaction context (synthetic outpoint). The
    /// anchoring party draws this *before* constructing a nullifier-bearing
    /// record, computes the record's bound payload against it, and then
    /// anchors with [`MockAnchorChain::append_with_ctx`].
    pub fn fresh_ctx(&self) -> [u8; 32] {
        rand::rng().random()
    }

    /// Append a record to the current tip block under a fresh random
    /// transaction context, returning a reference to its location.
    ///
    /// Note: for nullifier-bearing records the context must be known
    /// *before* the record is constructed (the bound payload commits to
    /// it), so such records are anchored via [`MockAnchorChain::fresh_ctx`]
    /// and [`MockAnchorChain::append_with_ctx`]; plain `append` is for
    /// MINTs (no payload) and for deliberate copy-grief scenarios
    /// (re-anchoring an existing record under a fresh, foreign `ctx`).
    pub fn append(&mut self, record: AnchorRecord) -> AnchorRef {
        let ctx = self.fresh_ctx();
        self.append_with_ctx(record, ctx)
    }

    /// Append a record under a caller-supplied transaction context (see
    /// [`MockAnchorChain::append`]).
    pub fn append_with_ctx(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> AnchorRef {
        let position = self
            .entries
            .iter()
            .filter(|e| e.location.height == self.tip_height)
            .count() as u32;
        let location = AnchorLocation {
            height: self.tip_height,
            position,
        };
        let txid = *hash_felts("mock-txid", &[&[felt(self.entries.len() as u32)]]).as_bytes();
        self.entries.push(Entry {
            txid,
            location,
            record,
            ctx,
        });
        AnchorRef { txid, location }
    }
}

impl AnchorChain for MockAnchorChain {
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
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| opencsv_kernel::Entry {
                record: crate::kernel::record(&entry.record),
                ctx: entry.ctx,
                location: crate::kernel::location(&entry.location),
            })
            .collect();
        opencsv_kernel::first_occurrence(&entries, raw_nf.as_bytes())
            .map(|index| self.entries[index].location)
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        // Linear scan (fine for a mock): an occurrence is an entry whose
        // record binds `raw_nf` under the entry's own ctx.
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
