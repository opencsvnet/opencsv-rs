//! # opencsv-cbf
//!
//! A [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)/[BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
//! compact-block-filter light client providing **trustless point
//! verification** of claimed OpenCSV anchors against plain `bitcoind`
//! P2P peers — no trusted server, no RPC, no index.
//!
//! ## What `verify_anchor` proves
//!
//! Given a claimed `(record, location, txid, required_confirmations)`:
//!
//! - **presence**: the full block at `location.height` is fetched from
//!   a peer and its merkle root recomputed and compared against the
//!   verified block header; the transaction at `location.position`
//!   must have the claimed `txid` and carry the exact 64-byte record in
//!   an OP_RETURN output;
//! - **position**: the in-block position is checked against the block's
//!   transaction list directly;
//! - **ctx**: recomputed from the anchor transaction's first input via
//!   the canonical `opencsv_bitcoin::funding_ctx`
//!   (`SHA-256(txid_internal ∥ vout_LE)`);
//! - **confirmations**: `tip − height + 1` over a header chain with
//!   full PoW validation (linkage, per-network `nBits` rules, hash
//!   below target, median-time-past), whose tip must be agreed upon by
//!   **all** connected peers.
//!
//! Absence is likewise proven by the full block: a block whose
//! transactions (all committed by the merkle root) contain no such
//! record at the claimed position.
//!
//! ## What it cannot prove: occurrence exclusion
//!
//! Compact filters cannot support OpenCSV occurrence-exclusion scans
//! ("does `raw_nf` appear anywhere else on chain?"). The filter-match
//! key would have to be derived from the on-chain payload, but the
//! payload `P = H("bind" ∥ raw_nf ∥ ctx)` is deliberately not publicly
//! derivable — that privacy is what stops copy-griefing — so occurrence
//! keys are not filter-matchable. And even for the *public* record
//! bytes: BIP158 basic filters exclude all OP_RETURN outputs, so the
//! anchor's scriptPubKey is never in the filter at all (see the
//! README). Occurrence scans remain the job of a full-chain indexer
//! (e.g. `opencsv-bitcoin`'s RPC backend).
//!
//! ## Security model (SPV)
//!
//! This is a light client: it validates proof of work and merkle
//! inclusion, **not** transaction or block validity. Its trust
//! assumptions:
//!
//! - at least one connected peer serves the real most-work header
//!   chain (an eclipse attacker controlling *all* your connections can
//!   feed a fake chain — connect to several independent peers; the
//!   client compares tips and refuses to proceed on disagreement);
//! - filter headers are not committed in blocks, so the filter-header
//!   chain is cross-checked across all connected peers (BIP157's
//!   one-honest-peer model). Filter correctness matters here only for
//!   the diagnostic [`CbfClient::filter_matches`] check, never for the
//!   anchor verdict itself.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod batch;
pub mod block;
pub mod chain;
pub mod client;
pub mod error;
pub mod fullscan;
pub mod gcs;
pub mod hash;
pub mod messages;
pub mod network;
pub mod peer;
pub mod scan;
pub mod siphash;
pub mod wire;

pub use batch::{
    BatchInputBirthHeights, CommitmentInputBirthHeights, VerifiedBatchInputs,
    VerifiedBatchOutpoint, VerifiedChainTip, VerifiedCommitmentInputs,
};
pub use client::{AnchorVerdict, CbfClient, Config, NotPresentReason, OutpointVerdict};
pub use error::Error;
pub use fullscan::{FullScanChain, ScannedAnchor, MAX_WINDOW_BLOCKS};
pub use opencsv_bitcoin::Network;
pub use opencsv_core::chain::AnchorLocation;
pub use opencsv_core::AnchorRecord;
pub use scan::{ScanCounters, ScanIndex};
