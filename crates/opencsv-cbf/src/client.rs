//! The product surface: `CbfClient` — multi-peer header/filter-header
//! sync and trustless point verification of claimed anchors.

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use opencsv_bitcoin::{funding_ctx, Network};
use opencsv_core::chain::AnchorLocation;
use opencsv_core::AnchorRecord;

use crate::block::{anchor_script, op_return_payload, Block};
use crate::chain::{FilterHeaderChain, HeaderChain};
use crate::error::Error;
use crate::gcs::{filter_key, GcsFilter, BASIC_FILTER_M, BASIC_FILTER_P};
use crate::network::{params, Params};
use crate::peer::Peer;

/// Client configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// The Bitcoin network (magic, ports, genesis, PoW rules).
    pub network: Network,
    /// Peers to connect to (`host:port` strings; port defaults to the
    /// network's P2P port). Two or more independent peers enable the
    /// eclipse-attack cross-checks (see the crate README).
    pub peers: Vec<String>,
    /// Directory for the persistent header/filter cache (rebuildable:
    /// deleting it just forces a resync).
    pub cache_dir: PathBuf,
    /// Connect/read/write timeout per peer operation.
    pub timeout: Duration,
}

/// Why a claimed anchor is not present at its claimed location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotPresentReason {
    /// The claimed height is above the verified chain tip (the anchor
    /// cannot have been mined yet).
    AboveTip {
        /// Claimed height.
        height: u64,
        /// Verified tip height.
        tip: u64,
    },
    /// The block has fewer transactions than the claimed position.
    PositionOutOfRange {
        /// Claimed in-block position.
        position: u32,
        /// Transaction count of the block.
        tx_count: u32,
    },
    /// The transaction at the claimed position has a different txid.
    TxidMismatch {
        /// Claimed txid (internal order).
        claimed: [u8; 32],
        /// Actual txid at that position (internal order).
        actual: [u8; 32],
    },
    /// The transaction at the claimed position carries no 64-byte
    /// OP_RETURN output equal to the claimed record.
    RecordNotInTx,
}

/// The outcome of [`CbfClient::verify_anchor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// The anchor is verified: present, at the claimed position, with a
    /// recomputed ctx and enough confirmations.
    Confirmed {
        /// Hash of the block containing the anchor (internal order).
        block_hash: [u8; 32],
        /// `ctx = SHA256(txid_internal ∥ vout_LE)` recomputed from the
        /// anchor transaction's first input (canonical:
        /// `opencsv_bitcoin::funding_ctx`).
        ctx: [u8; 32],
        /// Confirmations at the current verified tip (`tip − height + 1`).
        confirmations: u64,
        /// Diagnostic: whether the block's BIP158 basic filter matched
        /// the record's OP_RETURN scriptPubKey. BIP158 basic filters
        /// exclude all OP_RETURN outputs, so this is expected to be
        /// `false` even for present anchors — presence and absence are
        /// proven by the full block under the verified header chain,
        /// not by the filter (see the crate README).
        filter_matched: bool,
    },
    /// The claimed anchor is not at its claimed location (proven by the
    /// full block contents under the verified header chain).
    NotPresent(NotPresentReason),
    /// The anchor is present but younger than required.
    InsufficientConfirmations {
        /// Current confirmations.
        have: u64,
        /// Required confirmations.
        required: u64,
    },
}

/// A BIP157/158 compact-block-filter light client for trustless point
/// verification of OpenCSV anchors.
///
/// Construct with [`CbfClient::connect`]; see the crate-level docs and
/// README for the security model (SPV — PoW-verified headers, not full
/// block validation — plus cross-peer comparison of the filter-header
/// chain).
pub struct CbfClient {
    params: Params,
    peers: Vec<Peer>,
    chain: HeaderChain,
    filter_chain: FilterHeaderChain,
    cache_dir: PathBuf,
}

impl CbfClient {
    /// Connect to all configured peers, sync the header chain on each
    /// (full PoW validation), and require agreement on the tip —
    /// disagreement means a peer is feeding us a different chain
    /// (eclipse attempt or honest reorg mid-sync) and is a hard error.
    /// Filter headers are then fetched from every peer and must agree
    /// as well (BIP157's one-honest-peer security model).
    ///
    /// At least one peer must connect and sync successfully; peers that
    /// fail to connect are skipped (recorded in the error if all fail).
    pub fn connect(config: &Config) -> Result<Self, Error> {
        let params = params(config.network);
        let cache_dir = config.cache_dir.join(config.network.name());
        let chain = HeaderChain::load(params, &cache_dir)?;
        let filter_chain = FilterHeaderChain::load(&cache_dir)?;

        let mut peers = Vec::new();
        let mut failures = Vec::new();
        for peer in &config.peers {
            let addr = match resolve(peer, params.default_port) {
                Ok(addr) => addr,
                Err(e) => {
                    failures.push(format!("{peer}: {e}"));
                    continue;
                }
            };
            let tip = chain.tip_height().unwrap_or(0);
            match Peer::connect(addr, &params, config.timeout, tip) {
                Ok(peer) => peers.push(peer),
                Err(e) => failures.push(format!("{peer}: {e}")),
            }
        }
        if peers.is_empty() {
            return Err(Error::NoPeers(failures.join("; ")));
        }

        let mut client = Self {
            params,
            peers,
            chain,
            filter_chain,
            cache_dir,
        };
        client.sync()?;
        Ok(client)
    }

    /// Resync headers (every peer, tip agreement enforced) and filter
    /// headers (every peer, chain agreement enforced).
    pub fn sync(&mut self) -> Result<(), Error> {
        // Header sync on every peer; all must agree on the tip.
        let mut tips = Vec::with_capacity(self.peers.len());
        for peer in &mut self.peers {
            self.chain.sync(peer)?;
            let tip = (
                self.chain.tip_height(),
                self.chain.tip_height().and_then(|h| self.chain.hash_at(h)),
            );
            tips.push((peer.addr(), tip));
        }
        let (_, first_tip) = tips[0];
        if tips.iter().any(|(_, tip)| *tip != first_tip) {
            let detail = tips
                .iter()
                .map(|(addr, tip)| format!("{addr} -> {tip:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::DivergentPeers(format!("header tips: {detail}")));
        }

        // Filter-header sync: fetch the range from every peer and
        // require byte-identical filter hashes (a faulty or malicious
        // peer is detectable because filters are deterministic).
        let stop = self.chain.tip_height().expect("genesis synced");
        let mut reference: Option<Vec<[u8; 32]>> = None;
        for peer in &mut self.peers {
            let fetched = self.filter_chain.fetch_range(peer, &self.chain, stop)?;
            match &reference {
                None => reference = Some(fetched),
                Some(expected) => {
                    if *expected != fetched {
                        return Err(Error::DivergentPeers(format!(
                            "filter-header chains differ below height {stop}"
                        )));
                    }
                }
            }
        }
        if let Some(new_hashes) = reference {
            self.filter_chain.extend(&new_hashes);
        }
        self.chain.persist(&self.cache_dir)?;
        self.filter_chain.persist(&self.cache_dir)?;
        Ok(())
    }

    /// Height of the verified chain tip.
    pub fn tip_height(&self) -> u64 {
        self.chain.tip_height().expect("genesis synced")
    }

    /// Internal-order hash of the block at `height`.
    pub fn block_hash(&self, height: u64) -> Option<[u8; 32]> {
        self.chain.hash_at(height)
    }

    /// The BIP157 basic-filter header at `height`, derived from the
    /// (cross-peer-verified) filter-hash chain.
    pub fn filter_header(&self, height: u64) -> Option<[u8; 32]> {
        self.filter_chain.filter_header_at(height)
    }

    /// The network's consensus parameters.
    pub fn params(&self) -> &Params {
        &self.params
    }

    /// Fetch and cache the BIP158 basic filter for the block at
    /// `height`, verified against the synced filter-header chain.
    fn filter_at(&mut self, height: u64) -> Result<Vec<u8>, Error> {
        let path = self
            .cache_dir
            .join("filters")
            .join(format!("{height:08}.filter"));
        if let Ok(bytes) = std::fs::read(&path) {
            self.filter_chain.verify_filter(height, &bytes)?;
            return Ok(bytes);
        }
        let block_hash = self
            .chain
            .hash_at(height)
            .ok_or_else(|| Error::Filter(format!("no block at height {height}")))?;
        let mut last_err = None;
        for peer in &mut self.peers {
            match peer.get_cfilter(height as u32, &block_hash) {
                Ok(cfilter) => {
                    self.filter_chain
                        .verify_filter(height, &cfilter.filter_bytes)?;
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&path, &cfilter.filter_bytes)?;
                    return Ok(cfilter.filter_bytes);
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.expect("at least one peer"))
    }

    /// Does the BIP158 basic filter of the block at `height` match
    /// `item`? The filter is verified against the filter-header chain,
    /// which is cross-checked across all connected peers.
    ///
    /// Note: basic filters contain only non-OP_RETURN output scripts
    /// and spent-prevout scripts; an OpenCSV anchor's OP_RETURN
    /// scriptPubKey is never in the filter (see the crate README).
    pub fn filter_matches(&mut self, height: u64, item: &[u8]) -> Result<bool, Error> {
        let bytes = self.filter_at(height)?;
        let block_hash = self.chain.hash_at(height).expect("checked in filter_at");
        let filter = GcsFilter::parse(&bytes)?;
        filter.matches(
            &filter_key(&block_hash),
            item,
            BASIC_FILTER_P,
            BASIC_FILTER_M,
        )
    }

    /// Fetch a full block from the first peer that has it.
    pub fn fetch_block(&mut self, block_hash: &[u8; 32]) -> Result<Block, Error> {
        let mut last_err = None;
        for peer in &mut self.peers {
            match peer.get_block(block_hash) {
                Ok(block) => return Ok(block),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.expect("at least one peer"))
    }

    /// Trustless point verification of a claimed anchor.
    ///
    /// Flow (see the crate README for the security model):
    ///
    /// 1. The claimed height must be at or below the verified tip
    ///    (header chain with full PoW validation, tip agreed by all
    ///    connected peers).
    /// 2. The record's expected OP_RETURN scriptPubKey is queried
    ///    against the block's BIP158 basic filter (diagnostic only —
    ///    basic filters exclude OP_RETURN outputs, so the filter
    ///    neither proves presence nor absence here; the result is
    ///    reported in the verdict).
    /// 3. The full block is fetched and its merkle root recomputed and
    ///    compared against the verified header — every transaction in
    ///    the block is thereby committed by the header's PoW.
    /// 4. The transaction at `location.position` must have the claimed
    ///    `txid` and carry the exact 64-byte record in an OP_RETURN
    ///    output; `ctx` is recomputed from the transaction's first
    ///    input via the canonical `opencsv_bitcoin::funding_ctx`.
    /// 5. Confirmations (`tip − height + 1`) must meet
    ///    `required_confirmations`.
    pub fn verify_anchor(
        &mut self,
        anchor: &AnchorRecord,
        location: AnchorLocation,
        txid: [u8; 32],
        required_confirmations: u64,
    ) -> Result<AnchorVerdict, Error> {
        if location.height == 0 {
            return Err(Error::InvalidInput(
                "height 0 is the mempool sentinel / genesis: anchors live in mined blocks"
                    .into(),
            ));
        }
        let tip = self.tip_height();
        if location.height > tip {
            return Ok(AnchorVerdict::NotPresent(NotPresentReason::AboveTip {
                height: location.height,
                tip,
            }));
        }
        let confirmations = tip - location.height + 1;
        let block_hash = self.chain.hash_at(location.height).expect("height <= tip");

        // Filter diagnostic (step 2): cannot prove presence or absence
        // for an OP_RETURN script, but the check exercises the verified
        // filter chain and is reported in the verdict.
        let record_bytes = anchor.to_bytes();
        let expected_script = anchor_script(&record_bytes);
        let filter_matched = self.filter_matches(location.height, &expected_script)?;

        // Step 3: full block, merkle-verified against the header.
        let block = self.fetch_block(&block_hash)?;
        if block.compute_merkle_root() != block.header.merkle_root {
            return Err(Error::Consensus(format!(
                "block {} merkle root does not match its header",
                crate::hash::hash_to_display(&block_hash)
            )));
        }

        // Step 4: position, txid, record, ctx.
        let position = location.position as usize;
        let Some(tx) = block.txs.get(position) else {
            return Ok(AnchorVerdict::NotPresent(
                NotPresentReason::PositionOutOfRange {
                    position: location.position,
                    tx_count: block.txs.len() as u32,
                },
            ));
        };
        let actual_txid = tx.txid();
        if actual_txid != txid {
            return Ok(AnchorVerdict::NotPresent(NotPresentReason::TxidMismatch {
                claimed: txid,
                actual: actual_txid,
            }));
        }
        let carries_record = tx
            .outputs
            .iter()
            .any(|o| op_return_payload(&o.script_pubkey) == Some(record_bytes));
        if !carries_record {
            return Ok(AnchorVerdict::NotPresent(NotPresentReason::RecordNotInTx));
        }
        let funding_input = tx.inputs.first().ok_or_else(|| {
            Error::Protocol("anchor transaction has no inputs".into())
        })?;
        if tx.is_coinbase() {
            return Ok(AnchorVerdict::NotPresent(NotPresentReason::RecordNotInTx));
        }
        let ctx = funding_ctx(&funding_input.prev.txid, funding_input.prev.vout);

        // Step 5: confirmations.
        if confirmations < required_confirmations {
            return Ok(AnchorVerdict::InsufficientConfirmations {
                have: confirmations,
                required: required_confirmations,
            });
        }
        Ok(AnchorVerdict::Confirmed {
            block_hash,
            ctx,
            confirmations,
            filter_matched,
        })
    }
}

/// Resolve a `host[:port]` peer string (port defaults to the network
/// P2P port).
fn resolve(peer: &str, default_port: u16) -> Result<SocketAddr, Error> {
    let with_port = if peer.contains(':') || peer.contains(']') {
        peer.to_string()
    } else {
        format!("{peer}:{default_port}")
    };
    with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| Error::Protocol(format!("cannot resolve `{peer}`")))
}
