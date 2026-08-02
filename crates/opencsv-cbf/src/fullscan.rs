//! Zero-trust self-scan exclusion over a bounded block window (paper
//! §4.7.1, amended).
//!
//! [`CrossCheckedChain`](opencsv_core::CrossCheckedChain) covers the
//! N-of-M indexer posture for exclusion checks; [`FullScanChain`] is the
//! **escape hatch that needs no indexer at all**: for a high-value
//! receipt, download every full block in a bounded window
//! `[birth_height, spend_height]` from P2P peers — each block
//! merkle-verified against the PoW-checked header chain, so the scan is
//! as trustless as [`CbfClient::verify_anchor`] — and test every
//! 64-byte OP_RETURN candidate record against `H("bind" ∥ raw_nf ∥ ctx)`
//! locally, with `ctx` recomputed from the candidate transaction's first
//! input via the canonical `opencsv_bitcoin::funding_ctx`.
//!
//! ## Window semantics (read before use)
//!
//! The scan sees **only the window**: an occurrence before `birth` is
//! invisible, so `birth` must be at or below the nullifier's earliest
//! possible anchor height (e.g. the coin's own anchor height). And
//! [`AnchorChain::tip_height`] of a `FullScanChain` is the **window
//! end**, so `confirmations_at` measures depth *from the window end*,
//! not the live chain tip — scan up to the client's current tip when
//! consuming this through [`accept`](opencsv_core::accept) for a
//! receipt. Running `accept` against a `FullScanChain` is only
//! meaningful for anchors inside the scanned window.

use opencsv_bitcoin::funding_ctx;
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest, TruncatedDigest};

use crate::block::op_return_payload;
use crate::client::CbfClient;
use crate::error::Error;

/// Hard bound on the window size, in blocks: full blocks are heavy, and
/// the scan is meant for per-receipt windows (a coin's lifetime), not
/// chain rescan.
pub const MAX_WINDOW_BLOCKS: u64 = 2016;

/// Every anchor candidate in a block (the first 64-byte OP_RETURN
/// output per non-coinbase transaction, ctx recomputed from the first
/// input — the same rule as `opencsv-bitcoin`'s scanner). A batch
/// header at output 0 additionally expands the transaction's witness
/// envelope into one candidate per payload (see `opencsv-core`'s
/// `batch` module).
pub(crate) fn anchors_in_block(block: &crate::block::Block, height: u64) -> Vec<ScannedAnchor> {
    let mut entries = Vec::new();
    for (position, tx) in block.txs.iter().enumerate() {
        if tx.is_coinbase() {
            continue;
        }
        let Some(funding) = tx.inputs.first() else {
            continue;
        };
        let ctx = funding_ctx(&funding.prev.txid, funding.prev.vout);
        for output in &tx.outputs {
            if let Some(payload) = op_return_payload(&output.script_pubkey) {
                let record = AnchorRecord::from_bytes(&payload);
                let location = AnchorLocation {
                    height,
                    position: position as u32,
                };
                let txid = tx.txid();
                if let AnchorRecord::BatchHeader { .. } = record {
                    // The envelope is the funding input's witness minus
                    // the final witness-script item.
                    let envelope = tx
                        .witnesses
                        .first()
                        .and_then(|w| w.split_last())
                        .and_then(|(_, items)| opencsv_core::batch::envelope_decode(items));
                    match envelope {
                        Some(envelope) => {
                            for (index, _) in envelope.iter().enumerate() {
                                entries.push(ScannedAnchor {
                                    location,
                                    txid,
                                    record,
                                    ctx,
                                    batch: Some(BatchCandidate {
                                        index: index as u32,
                                        envelope: envelope.clone(),
                                    }),
                                });
                            }
                        }
                        // A batch header without a decodable envelope:
                        // index the header for presence queries only —
                        // nothing in it can bind.
                        None => entries.push(ScannedAnchor {
                            location,
                            txid,
                            record,
                            ctx,
                            batch: None,
                        }),
                    }
                } else {
                    entries.push(ScannedAnchor {
                        location,
                        txid,
                        record,
                        ctx,
                        batch: None,
                    });
                }
                break;
            }
        }
    }
    entries
}

/// A batch candidate's envelope data: this payload's envelope index
/// and the full payload envelope it was decoded from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCandidate {
    /// This candidate's index in the witness envelope.
    pub index: u32,
    /// The full decoded payload envelope of the batch.
    pub envelope: Vec<TruncatedDigest>,
}

/// One 64-byte OP_RETURN candidate found in a scanned block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedAnchor {
    /// Where the carrying transaction sits in the chain.
    pub location: AnchorLocation,
    /// The carrying transaction's id (internal order).
    pub txid: [u8; 32],
    /// The record parsed from the OP_RETURN payload (any 64-byte string
    /// parses; see `opencsv-core`'s anchor docs).
    pub record: AnchorRecord,
    /// The transaction context, recomputed from the transaction's first
    /// input.
    pub ctx: [u8; 32],
    /// Batch envelope data when `record` is a batch header.
    pub batch: Option<BatchCandidate>,
}

impl ScannedAnchor {
    /// Occurrence test: does this candidate bind `raw_nf`? Solo records
    /// use the on-chain payload slots; batch candidates use the
    /// envelope occurrence semantics (payload equality AND the
    /// envelope validating against the header's `batch_commit`).
    pub fn binds(&self, raw_nf: &Digest) -> bool {
        match &self.batch {
            None => self.record.well_formed(&self.ctx, raw_nf),
            Some(batch) => {
                opencsv_core::batch::envelope_occurrence(
                    &self.record,
                    &batch.envelope,
                    &self.ctx,
                    raw_nf,
                ) == Some(batch.index)
            }
        }
    }
}

/// The result of self-scanning a block window (module docs).
pub struct FullScanChain {
    window_start: u64,
    window_end: u64,
    entries: Vec<ScannedAnchor>,
}

impl FullScanChain {
    /// Download and scan every block in `[birth, spend]` (inclusive).
    ///
    /// Each block is fetched over P2P and its merkle root recomputed and
    /// compared against the PoW-verified header — a peer cannot smuggle
    /// or omit transactions. Errors when the window is empty, exceeds
    /// [`MAX_WINDOW_BLOCKS`], or reaches above the verified tip.
    pub fn scan(client: &mut CbfClient, birth: u64, spend: u64) -> Result<Self, Error> {
        if birth == 0 {
            return Err(Error::InvalidInput(
                "window starts at height 0 (the mempool sentinel / genesis)".into(),
            ));
        }
        if spend < birth {
            return Err(Error::InvalidInput(format!(
                "empty window [{birth}, {spend}]"
            )));
        }
        let tip = client.tip_height();
        if spend > tip {
            return Err(Error::InvalidInput(format!(
                "window end {spend} is above the verified tip {tip}"
            )));
        }
        if spend - birth + 1 > MAX_WINDOW_BLOCKS {
            return Err(Error::InvalidInput(format!(
                "window of {} blocks exceeds MAX_WINDOW_BLOCKS ({MAX_WINDOW_BLOCKS})",
                spend - birth + 1
            )));
        }
        let mut entries = Vec::new();
        for height in birth..=spend {
            let block_hash = client
                .block_hash(height)
                .ok_or_else(|| Error::Consensus(format!("no header at height {height}")))?;
            let block = client.fetch_block(&block_hash)?;
            if block.compute_merkle_root() != block.header.merkle_root {
                return Err(Error::Consensus(format!(
                    "block {} merkle root does not match its header",
                    crate::hash::hash_to_display(&block_hash)
                )));
            }
            entries.extend(anchors_in_block(&block, height));
        }
        Ok(Self {
            window_start: birth,
            window_end: spend,
            entries,
        })
    }

    /// One-shot self-scan: the earliest occurrence of `raw_nf` in
    /// `[birth, spend]`, with its transaction context; `None` when the
    /// window contains no record binding `raw_nf`.
    pub fn first_occurrence_in_window(
        client: &mut CbfClient,
        raw_nf: &Digest,
        birth: u64,
        spend: u64,
    ) -> Result<Option<(AnchorLocation, [u8; 32])>, Error> {
        let scan = Self::scan(client, birth, spend)?;
        Ok(scan
            .entries
            .iter()
            .filter(|e| e.binds(raw_nf))
            .map(|e| (e.location, e.ctx))
            .min_by_key(|(location, _)| *location))
    }

    /// The scanned window, `[start, end]` inclusive.
    pub fn window(&self) -> (u64, u64) {
        (self.window_start, self.window_end)
    }

    /// Every OP_RETURN candidate found in the window, in canonical order.
    pub fn entries(&self) -> &[ScannedAnchor] {
        &self.entries
    }
}

/// Constrained to the scanned window (module docs): occurrences outside
/// the window are invisible, and confirmation depth is measured from the
/// window end.
impl FullScanChain {
    /// Entry lookup by reference: transaction id plus location — or by
    /// transaction id alone when the reference carries the mempool
    /// placeholder location (height 0 / position 0), matching
    /// `BitcoinAnchorChain`'s resolution contract for
    /// broadcast-but-unlocated refs.
    fn find(&self, anchor_ref: &AnchorRef) -> Option<&ScannedAnchor> {
        let mempool = AnchorLocation {
            height: 0,
            position: 0,
        };
        self.entries.iter().find(|e| {
            e.txid == anchor_ref.txid
                && (e.location == anchor_ref.location || anchor_ref.location == mempool)
        })
    }
}

impl AnchorChain for FullScanChain {
    fn tip_height(&self) -> u64 {
        self.window_end
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
        self.entries
            .iter()
            .filter(|e| e.binds(raw_nf))
            .map(|e| e.location)
            .min()
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        let mut locations: Vec<_> = self
            .entries
            .iter()
            .filter(|e| e.binds(raw_nf))
            .map(|e| e.location)
            .collect();
        locations.sort();
        locations
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        self.entries
            .iter()
            .filter(|e| e.location.height <= height)
            .map(|e| (e.location, e.record))
            .collect()
    }
}
