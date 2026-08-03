//! The CLI's chain-backend selection: **real Bitcoin via `bitcoind` RPC
//! (the default)** or one of the demo backends (the local file chain, the
//! shared anchor server).
//!
//! The demo backends simulate Bitcoin; every command run against one
//! prints a `DEMO CHAIN — not Bitcoin` warning on stderr. The `bitcoind`
//! backend has no fallback: if the node is unreachable, the auth fails,
//! or the network mismatches, the command fails.

use std::path::PathBuf;

use bitcoin::Transaction;
use opencsv_core::chain::{AnchorChain, AnchorLocation, AnchorRef};
use opencsv_core::{AnchorRecord, Digest, TruncatedDigest};

use crate::bitcoin::BitcoinBackend;
use crate::chain::{AnchorWriter, FileAnchorChain};
use crate::error::Error;
use crate::httpchain::HttpAnchorChain;

/// Which chain backend to open (built from the CLI flags).
#[derive(Clone)]
pub enum ChainSpec {
    /// Real Bitcoin via `bitcoind` RPC — the default.
    Bitcoin(Box<opencsv_bitcoin::Config>),
    /// Demo: an append-only local file.
    File(PathBuf),
    /// Demo: a shared `opencsv-anchor-server`.
    Http(String),
}

impl ChainSpec {
    /// `true` when anchors are simulated rather than published on Bitcoin.
    ///
    /// A `--anchor-server` may front *either* a demo file chain or a real
    /// Bitcoin backend, so it is not classified here: [`ChainBackend`]
    /// resolves it after the server reports which it is.
    pub fn is_demo(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

/// An opened chain backend.
pub enum ChainBackend {
    /// Real Bitcoin ([`BitcoinBackend`]; boxed — the backend is large).
    Bitcoin(Box<BitcoinBackend>),
    /// Append-only local file ([`FileAnchorChain`], demo).
    File(FileAnchorChain),
    /// Remote demo server ([`HttpAnchorChain`]).
    Http(HttpAnchorChain),
}

impl ChainBackend {
    /// Open the backend named by `spec`.
    pub fn open(spec: &ChainSpec) -> Result<Self, Error> {
        match spec {
            ChainSpec::Bitcoin(config) => Ok(Self::Bitcoin(Box::new(BitcoinBackend::open(config)?))),
            ChainSpec::File(path) => Ok(Self::File(FileAnchorChain::open(path)?)),
            ChainSpec::Http(url) => Ok(Self::Http(HttpAnchorChain::open(url)?)),
        }
    }

    /// Advance the tip by `n` blocks on whichever backend is active. On
    /// the `bitcoind` backend this mines via the wallet on regtest and is
    /// a hard error on real networks (blocks arrive by mining).
    pub fn advance_blocks(&mut self, n: u64) -> Result<(), Error> {
        match self {
            Self::Bitcoin(c) => c.generate_blocks(n),
            Self::File(c) => c.advance_blocks(n),
            Self::Http(c) => c.advance_blocks(n),
        }
    }

    /// The batch funding ctx for `count` payloads (bitcoind backend
    /// only — batching rides the real marker/funding construction).
    pub fn batch_ctx(&mut self, count: u8) -> Result<[u8; 32], Error> {
        match self {
            Self::Bitcoin(c) => c.marker_utxo_ctx(count),
            _ => Err(Error::Backend(
                "batch anchoring is only supported on the bitcoind backend".into(),
            )),
        }
    }

    /// Broadcast a batch anchor of pre-bound payloads (bitcoind backend
    /// only).
    pub fn anchor_batch(&mut self, payloads: &[TruncatedDigest]) -> Result<AnchorRef, Error> {
        match self {
            Self::Bitcoin(c) => c.anchor_batch(payloads),
            _ => Err(Error::Backend(
                "batch anchoring is only supported on the bitcoind backend".into(),
            )),
        }
    }

    /// Broadcast a complete batching-v2 transaction. Demo and remote
    /// anchor-server backends are intentionally rejected.
    pub fn broadcast_batch_transaction(&self, transaction: &Transaction) -> Result<String, Error> {
        match self {
            Self::Bitcoin(chain) => chain.broadcast_batch_transaction(transaction),
            _ => Err(Error::Backend(
                "batching-v2 broadcast requires the bitcoind backend".into(),
            )),
        }
    }
}

impl AnchorWriter for ChainBackend {
    fn append(&mut self, record: AnchorRecord, ctx: [u8; 32]) -> Result<AnchorRef, Error> {
        match self {
            Self::Bitcoin(c) => c.append(record, ctx),
            Self::File(c) => c.append(record, ctx),
            Self::Http(c) => c.append(record, ctx),
        }
    }

    fn append_bound(
        &mut self,
        build: impl FnMut(&[u8; 32]) -> AnchorRecord,
    ) -> Result<AnchorRef, Error> {
        match self {
            Self::Bitcoin(c) => c.append_bound(build),
            Self::File(c) => c.append_bound(build),
            Self::Http(c) => c.append_bound(build),
        }
    }
}

impl AnchorChain for ChainBackend {
    fn tip_height(&self) -> u64 {
        match self {
            Self::Bitcoin(c) => c.tip_height(),
            Self::File(c) => c.tip_height(),
            Self::Http(c) => c.tip_height(),
        }
    }

    fn anchor_at(&self, anchor_ref: &AnchorRef) -> Option<AnchorRecord> {
        match self {
            Self::Bitcoin(c) => c.anchor_at(anchor_ref),
            Self::File(c) => c.anchor_at(anchor_ref),
            Self::Http(c) => c.anchor_at(anchor_ref),
        }
    }

    fn ctx_at(&self, anchor_ref: &AnchorRef) -> Option<[u8; 32]> {
        match self {
            Self::Bitcoin(c) => c.ctx_at(anchor_ref),
            Self::File(c) => c.ctx_at(anchor_ref),
            Self::Http(c) => c.ctx_at(anchor_ref),
        }
    }

    fn locate(&self, anchor_ref: &AnchorRef) -> Option<AnchorLocation> {
        match self {
            Self::Bitcoin(c) => c.locate(anchor_ref),
            Self::File(c) => c.locate(anchor_ref),
            Self::Http(c) => c.locate(anchor_ref),
        }
    }

    fn first_nullifier_occurrence(&self, raw_nf: &Digest) -> Option<AnchorLocation> {
        match self {
            Self::Bitcoin(c) => c.first_nullifier_occurrence(raw_nf),
            Self::File(c) => c.first_nullifier_occurrence(raw_nf),
            Self::Http(c) => c.first_nullifier_occurrence(raw_nf),
        }
    }

    fn nullifier_occurrences(&self, raw_nf: &Digest) -> Vec<AnchorLocation> {
        match self {
            Self::Bitcoin(c) => c.nullifier_occurrences(raw_nf),
            Self::File(c) => c.nullifier_occurrences(raw_nf),
            Self::Http(c) => c.nullifier_occurrences(raw_nf),
        }
    }

    fn anchors_up_to(&self, height: u64) -> Vec<(AnchorLocation, AnchorRecord)> {
        match self {
            Self::Bitcoin(c) => c.anchors_up_to(height),
            Self::File(c) => c.anchors_up_to(height),
            Self::Http(c) => c.anchors_up_to(height),
        }
    }

    fn confirmations_at(&self, height: u64) -> u64 {
        match self {
            Self::Bitcoin(c) => c.confirmations_at(height),
            Self::File(c) => c.confirmations_at(height),
            Self::Http(c) => c.confirmations_at(height),
        }
    }
}
