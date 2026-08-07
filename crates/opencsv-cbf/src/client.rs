//! The product surface: `CbfClient` — multi-peer header/filter-header
//! sync and trustless point verification of claimed anchors.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

use opencsv_bitcoin::{funding_ctx, Network};
use opencsv_core::chain::AnchorLocation;
use opencsv_core::AnchorRecord;

use crate::block::{anchor_script, op_return_payload, Block, OutPoint};
use crate::chain::{FilterHeaderChain, HeaderChain};
use crate::error::Error;
use crate::gcs::{filter_key, GcsFilter, BASIC_FILTER_M, BASIC_FILTER_P};
use crate::network::{params, Params};
use crate::peer::Peer;

const FILTER_CACHE_REATTEST_BLOCKS: u64 = 144;

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

/// Independently verified state of one expected transaction output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutpointVerdict {
    /// The creating transaction/output was found and no later verified block
    /// in the checked range spends it.
    Unspent {
        /// Block containing the creating transaction.
        creation_height: u64,
        /// Verified header/filter tip through which spends were checked.
        checked_through: u64,
        /// Number of filters that matched the expected script and therefore
        /// caused a full, merkle-verified block download.
        matched_blocks: u64,
    },
    /// A later verified block spends the expected output.
    Spent {
        /// Block containing the creating transaction.
        creation_height: u64,
        /// Block containing the spending transaction.
        spend_height: u64,
        /// Transaction id of the spender, internal byte order.
        spending_txid: [u8; 32],
    },
    /// The expected creating transaction/output was not found in the checked
    /// range. This is fail-closed: the accelerator claim is not trusted.
    NotFound {
        /// First checked block.
        checked_from: u64,
        /// Last checked block.
        checked_through: u64,
    },
    /// The transaction id and output index exist, but the value or script does
    /// not match the caller-provided expected output.
    OutputMismatch {
        /// Block containing the mismatching output.
        creation_height: u64,
    },
}

enum OutpointBlockObservation {
    Continue,
    Spent {
        creation_height: u64,
        spending_txid: [u8; 32],
    },
    OutputMismatch,
    SpendBeforeCreation,
}

fn inspect_outpoint_block(
    block: &Block,
    height: u64,
    outpoint: OutPoint,
    expected_value: u64,
    expected_script: &[u8],
    creation_height: &mut Option<u64>,
) -> OutpointBlockObservation {
    for transaction in &block.txs {
        let txid = transaction.txid();
        if txid == outpoint.txid {
            let output = transaction.outputs.get(outpoint.vout as usize);
            match output {
                Some(output)
                    if output.value == expected_value
                        && output.script_pubkey == expected_script =>
                {
                    *creation_height = Some(height);
                }
                _ => return OutpointBlockObservation::OutputMismatch,
            }
        }
        if transaction
            .inputs
            .iter()
            .any(|input| input.prev == outpoint)
        {
            return match *creation_height {
                Some(creation_height) => OutpointBlockObservation::Spent {
                    creation_height,
                    spending_txid: txid,
                },
                None => OutpointBlockObservation::SpendBeforeCreation,
            };
        }
    }
    OutpointBlockObservation::Continue
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
        let mut resolved_peers = HashSet::new();
        let mut connect_tasks = Vec::new();
        for peer in &config.peers {
            let addr = match resolve(peer, params.default_port) {
                Ok(addr) => addr,
                Err(e) => {
                    failures.push(format!("{peer}: {e}"));
                    continue;
                }
            };
            if !resolved_peers.insert(addr) {
                failures.push(format!("{peer}: duplicate resolved peer {addr}"));
                continue;
            }
            let tip = chain.tip_height().unwrap_or(0);
            let timeout = config.timeout;
            connect_tasks.push((
                peer.clone(),
                std::thread::spawn(move || Peer::connect(addr, &params, timeout, tip)),
            ));
        }
        for (name, task) in connect_tasks {
            match task.join() {
                Ok(Ok(peer)) => peers.push(peer),
                Ok(Err(error)) => failures.push(format!("{name}: {error}")),
                Err(_) => failures.push(format!("{name}: connection worker panicked")),
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
        client.sync_inner(true)?;
        Ok(client)
    }

    /// Resync headers (every peer, tip agreement enforced) and filter
    /// headers (every peer, chain agreement enforced).
    pub fn sync(&mut self) -> Result<(), Error> {
        self.sync_inner(false)
    }

    fn sync_inner(&mut self, revalidate_filter_cache: bool) -> Result<(), Error> {
        // Every peer independently advances a clone of the same validated
        // base chain. Sharing one mutable chain here would let later peers
        // merely observe the first peer's result instead of attesting it.
        let base_chain = self.chain.clone();
        let mut candidates = Vec::with_capacity(self.peers.len());
        let mut header_peers = Vec::with_capacity(self.peers.len());
        let mut header_failures = Vec::new();
        let mut header_tasks = Vec::new();
        for mut peer in std::mem::take(&mut self.peers) {
            let address = peer.addr();
            let mut candidate = base_chain.clone();
            header_tasks.push((
                address,
                std::thread::spawn(move || {
                    let result = candidate.sync(&mut peer);
                    (peer, candidate, result)
                }),
            ));
        }
        for (address, task) in header_tasks {
            let (peer, candidate, result) = match task.join() {
                Ok(result) => result,
                Err(_) => {
                    header_failures.push(format!("{address}: header worker panicked"));
                    continue;
                }
            };
            if let Err(error) = result {
                header_failures.push(format!("{address}: {error}"));
                continue;
            }
            let tip = (
                candidate.tip_height(),
                candidate.tip_height().and_then(|h| candidate.hash_at(h)),
                candidate.tip_work(),
            );
            candidates.push((address, tip, candidate));
            header_peers.push(peer);
        }
        if candidates.is_empty() {
            return Err(Error::NoPeers(format!(
                "no peer completed header synchronization: {}",
                header_failures.join("; ")
            )));
        }
        let first_tip = candidates[0].1;
        if candidates.iter().any(|(_, tip, _)| *tip != first_tip) {
            let detail = candidates
                .iter()
                .map(|(addr, tip, _)| format!("{addr} -> {tip:?}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::DivergentPeers(format!("header tips: {detail}")));
        }
        let agreed_chain = candidates.remove(0).2;
        self.peers = header_peers;
        let common_prefix = self.chain.common_prefix_len(&agreed_chain);
        self.chain = agreed_chain;
        self.filter_chain.truncate(common_prefix);

        // On a new connection, each peer re-attests the cached tail and the
        // preceding filter header derived from the complete local prefix.
        // This detects any cache mutation under SHA256d second-preimage
        // resistance without replaying every historical cfheaders page.
        // Fresh installs still fetch and cross-check the complete chain.
        let stop = self.chain.tip_height().expect("genesis synced");
        let base_filters = self.filter_chain.clone();
        let mut reference: Option<Vec<[u8; 32]>> = None;
        let mut filter_peers = Vec::with_capacity(self.peers.len());
        let mut filter_failures = Vec::new();
        let mut filter_tasks = Vec::new();
        for mut peer in std::mem::take(&mut self.peers) {
            let address = peer.addr();
            let filters = base_filters.clone();
            let chain = self.chain.clone();
            filter_tasks.push((
                address,
                std::thread::spawn(move || {
                    let result = (|| {
                        if revalidate_filter_cache && !filters.is_empty() {
                            filters.reattest_tail(
                                &mut peer,
                                &chain,
                                FILTER_CACHE_REATTEST_BLOCKS,
                            )?;
                        }
                        filters.fetch_range(&mut peer, &chain, stop)
                    })();
                    (peer, result)
                }),
            ));
        }
        for (address, task) in filter_tasks {
            let (peer, result) = match task.join() {
                Ok(result) => result,
                Err(_) => {
                    filter_failures.push(format!("{address}: filter worker panicked"));
                    continue;
                }
            };
            let fetched = match result {
                Ok(fetched) => fetched,
                Err(error) => {
                    filter_failures.push(format!("{address}: {error}"));
                    continue;
                }
            };
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
            filter_peers.push(peer);
        }
        if filter_peers.is_empty() {
            return Err(Error::NoPeers(format!(
                "no peer completed filter-header synchronization: {}",
                filter_failures.join("; ")
            )));
        }
        self.peers = filter_peers;
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

    /// Total `version` handshakes performed across all peers of this
    /// client (observability for the persistent-client API: reusing a
    /// client must not re-handshake).
    pub fn handshake_count(&self) -> u64 {
        self.peers.iter().map(|p| p.versions_sent).sum()
    }

    /// Number of independently connected peers participating in agreement.
    pub fn connected_peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Addresses of peers that completed the current header and filter-header
    /// agreement pass. Peers that merely completed TCP/version negotiation but
    /// failed synchronization are not included.
    pub fn connected_peer_addresses(&self) -> Vec<SocketAddr> {
        self.peers.iter().map(Peer::addr).collect()
    }

    /// Complete P2P wire bytes sent and received by this client.
    pub fn network_bytes(&self) -> (u64, u64) {
        self.peers.iter().fold((0, 0), |(sent, received), peer| {
            (
                sent + peer.wire_bytes_sent,
                received + peer.wire_bytes_received,
            )
        })
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
        let mut last_err = None;
        match std::fs::read(&path) {
            Ok(bytes) => match self.filter_chain.verify_filter(height, &bytes) {
                Ok(()) => return Ok(bytes),
                Err(error) => {
                    // Compact filters are rebuildable public-chain cache.
                    // A truncated or dishonest cached candidate must not
                    // permanently brick synchronization at this height.
                    let _ = std::fs::remove_file(&path);
                    last_err = Some(error);
                }
            },
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                last_err = Some(error.into());
            }
            Err(_) => {}
        }
        let block_hash = self
            .chain
            .hash_at(height)
            .ok_or_else(|| Error::Filter(format!("no block at height {height}")))?;
        for peer in &mut self.peers {
            match peer.get_cfilter(height as u32, &block_hash) {
                Ok(cfilter) => match self
                    .filter_chain
                    .verify_filter(height, &cfilter.filter_bytes)
                {
                    Ok(()) => {
                        if let Some(parent) = path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::write(&path, &cfilter.filter_bytes)?;
                        return Ok(cfilter.filter_bytes);
                    }
                    // An invalid response is one bad peer, not a reason to
                    // skip the remaining independently connected peers.
                    Err(error) => last_err = Some(error),
                },
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            Error::NoPeers(format!("no peer supplied filter at height {height}"))
        }))
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

    /// Network bandwidth consumed so far, as `(filter_bytes,
    /// block_bytes)` of message payloads. Cache hits do not count; used
    /// by the scan engine's accounting.
    pub fn fetched_bytes(&self) -> (u64, u64) {
        self.peers.iter().fold((0, 0), |(f, b), peer| {
            (f + peer.filter_bytes_fetched, b + peer.block_bytes_fetched)
        })
    }

    /// Verify that an expected output exists and remains unspent through the
    /// current independently agreed tip.
    ///
    /// BIP158 basic filters contain ordinary output scripts and the scripts of
    /// spent prevouts. The method checks the expected script in every filter
    /// from `birth_height` through the verified tip, downloads every matching
    /// full block, verifies its merkle root against the PoW-checked header, and
    /// inspects exact transaction outpoints. The creating output must be found
    /// with the expected value/script and no later input may spend it.
    ///
    /// `max_blocks` bounds hostile or accidentally ancient requests. A
    /// reported creation height is only a search hint: the output is accepted
    /// only when the exact transaction/output is found in a verified block.
    pub fn verify_outpoint_unspent(
        &mut self,
        outpoint: OutPoint,
        expected_value: u64,
        expected_script: &[u8],
        birth_height: u64,
        max_blocks: u64,
    ) -> Result<OutpointVerdict, Error> {
        if birth_height == 0 {
            return Err(Error::InvalidInput(
                "outpoint birth height cannot be the mempool sentinel".into(),
            ));
        }
        let tip = self.tip_height();
        if birth_height > tip {
            return Err(Error::InvalidInput(format!(
                "outpoint birth height {birth_height} is above verified tip {tip}"
            )));
        }
        let block_count = tip - birth_height + 1;
        if max_blocks == 0 || block_count > max_blocks {
            return Err(Error::InvalidInput(format!(
                "outpoint revalidation window of {block_count} blocks exceeds limit {max_blocks}"
            )));
        }

        let mut creation_height = None;
        let mut matched_blocks = 0u64;
        for height in birth_height..=tip {
            if !self.filter_matches(height, expected_script)? {
                continue;
            }
            matched_blocks += 1;
            let block_hash = self
                .chain
                .hash_at(height)
                .expect("height is within the verified tip");
            let block = self.fetch_block(&block_hash)?;
            if block.compute_merkle_root() != block.header.merkle_root {
                return Err(Error::Consensus(format!(
                    "block {} merkle root does not match its header",
                    crate::hash::hash_to_display(&block_hash)
                )));
            }
            match inspect_outpoint_block(
                &block,
                height,
                outpoint,
                expected_value,
                expected_script,
                &mut creation_height,
            ) {
                OutpointBlockObservation::Continue => {}
                OutpointBlockObservation::OutputMismatch => {
                    return Ok(OutpointVerdict::OutputMismatch {
                        creation_height: height,
                    });
                }
                OutpointBlockObservation::SpendBeforeCreation => {
                    return Ok(OutpointVerdict::NotFound {
                        checked_from: birth_height,
                        checked_through: height,
                    });
                }
                OutpointBlockObservation::Spent {
                    creation_height,
                    spending_txid,
                } => {
                    return Ok(OutpointVerdict::Spent {
                        creation_height,
                        spend_height: height,
                        spending_txid,
                    });
                }
            }
        }

        Ok(match creation_height {
            Some(creation_height) => OutpointVerdict::Unspent {
                creation_height,
                checked_through: tip,
                matched_blocks,
            },
            None => OutpointVerdict::NotFound {
                checked_from: birth_height,
                checked_through: tip,
            },
        })
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
                "height 0 is the mempool sentinel / genesis: anchors live in mined blocks".into(),
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
        let funding_input = tx
            .inputs
            .first()
            .ok_or_else(|| Error::Protocol("anchor transaction has no inputs".into()))?;
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

#[cfg(test)]
mod tests {
    use crate::block::{BlockHeader, Transaction, TxIn, TxOut};

    use super::*;

    fn transaction(inputs: Vec<OutPoint>, outputs: Vec<(u64, Vec<u8>)>) -> Transaction {
        Transaction {
            version: 2,
            inputs: inputs
                .into_iter()
                .map(|prev| TxIn {
                    prev,
                    script_sig: Vec::new(),
                    sequence: 0xffff_fffd,
                })
                .collect(),
            outputs: outputs
                .into_iter()
                .map(|(value, script_pubkey)| TxOut {
                    value,
                    script_pubkey,
                })
                .collect(),
            lock_time: 0,
            witnesses: Vec::new(),
        }
    }

    fn block(transactions: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 1,
                prev_block: [0u8; 32],
                merkle_root: [0u8; 32],
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs: transactions,
        };
        block.header.merkle_root = block.compute_merkle_root();
        block
    }

    #[test]
    fn exact_output_then_spend_is_detected() {
        let script = vec![0x00, 0x14, 7, 7, 7];
        let creation = transaction(
            vec![OutPoint {
                txid: [1u8; 32],
                vout: 0,
            }],
            vec![(50_000, script.clone())],
        );
        let outpoint = OutPoint {
            txid: creation.txid(),
            vout: 0,
        };
        let mut creation_height = None;
        assert!(matches!(
            inspect_outpoint_block(
                &block(vec![creation]),
                100,
                outpoint,
                50_000,
                &script,
                &mut creation_height,
            ),
            OutpointBlockObservation::Continue
        ));
        assert_eq!(creation_height, Some(100));

        let spending = transaction(vec![outpoint], vec![(49_000, vec![0x51])]);
        let spending_txid = spending.txid();
        assert!(matches!(
            inspect_outpoint_block(
                &block(vec![spending]),
                101,
                outpoint,
                50_000,
                &script,
                &mut creation_height,
            ),
            OutpointBlockObservation::Spent {
                creation_height: 100,
                spending_txid: found,
            } if found == spending_txid
        ));
    }

    #[test]
    fn value_or_script_mismatch_fails_closed() {
        let creation = transaction(
            vec![OutPoint {
                txid: [2u8; 32],
                vout: 1,
            }],
            vec![(25_000, vec![0x51])],
        );
        let outpoint = OutPoint {
            txid: creation.txid(),
            vout: 0,
        };
        let mut creation_height = None;
        assert!(matches!(
            inspect_outpoint_block(
                &block(vec![creation]),
                50,
                outpoint,
                25_001,
                &[0x51],
                &mut creation_height,
            ),
            OutpointBlockObservation::OutputMismatch
        ));
        assert_eq!(creation_height, None);
    }
}
