//! End-to-end scan-engine test: the self-scan-first exclusion path —
//! BIP158 filter scan for the protocol marker, SPV block fetch for the
//! matching blocks, local occurrence checks, and `accept()` running
//! against the scan index alone (no RPC to the anchoring node, no
//! indexer).
//!
//! Skipped (silently green) when no `bitcoind` binary is available.

mod common;

use std::time::Duration;

use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_cbf::{CbfClient, Config, ScanIndex};
use opencsv_core::accept::{accept, public_input, AcceptParams, MockVerifier};
use opencsv_core::chain::AnchorChain;
use opencsv_core::consignment::{CoinOpening, Consignment};
use opencsv_core::{AnchorRecord, AssetGenesis, Digest, OwnerSecret};

const VK: &[u8] = b"scan-e2e-vk";

#[test]
fn scan_engine_finds_and_excludes() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping scan_engine_finds_and_excludes: bitcoind not found");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));
    node.create_wallet_and_mine(101);

    let btc_config = BtcConfig {
        network: Network::Regtest,
        rpc_url: node.rpc_url.clone(),
        auth: RpcAuth::Cookie(node.cookie.clone()),
        wallet: Some("test".into()),
        scan_from: Some(1),
        index_path: tmp.path().join("bitcoin-index.log"),
    };
    let mut anchor_chain = BitcoinAnchorChain::open(&btc_config).unwrap();

    // The legitimate spend of `raw_nf` (marker-carrying anchor), mined.
    let (raw_nf, ref1) = common::anchor_xfer_retry(&mut anchor_chain, 21);
    anchor_chain.generate_blocks(6).unwrap();
    let loc1 = anchor_chain.locate(&ref1).expect("anchor mined");
    let ctx1 = anchor_chain.ctx_at(&ref1).unwrap();
    let record1 = anchor_chain.anchor_at(&ref1).unwrap();
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 107);
    // The node's own scanner saw the marker.
    assert_eq!(anchor_chain.block_has_marker(loc1.height), Some(true));

    node.wait_for_filter_index();
    let config = Config {
        network: Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();

    // --- (a) the marker anchor is discovered via filters ------------------
    let scan_dir = tmp.path().join("scan");
    let mut index = ScanIndex::open(&scan_dir, Network::Regtest).unwrap();
    index.scan_sync(&mut client, 102).unwrap();
    assert_eq!(index.synced_tip(), tip);
    assert_eq!(index.occurrences().len(), 1, "only the anchor block matches");
    let found = &index.occurrences()[0];
    assert_eq!(found.location, loc1);
    assert_eq!(found.ctx, ctx1);
    assert_eq!(found.record, record1);
    assert_eq!(found.txid, ref1.txid);

    // ...and a receiver accepts against the scan index ALONE — no RPC
    // to the anchoring node, no indexer; the chain view is the scan.
    let asset_id = AssetGenesis {
        issuer_pk: [7u8; 32],
        currency_code: *b"USD",
        terms_hash: Digest::from_bytes([3u8; 32]),
        nonce: 1,
    }
    .asset_id();
    let receiver = OwnerSecret::from_bytes([8u8; 32]);
    let opening = CoinOpening {
        asset_id,
        value: 50,
        owner: receiver.owner(),
        randomness: Digest::from_bytes([9u8; 32]),
    };
    let consignment = Consignment {
        coin_openings: vec![opening],
        nullifiers: vec![raw_nf],
        proof: MockVerifier::prove(VK, &public_input(&record1, &ctx1, &[opening])),
        anchor_ref: ref1,
        aux: None,
    };
    let accepted = accept(
        &consignment,
        &index,
        &MockVerifier,
        &AcceptParams {
            vk: VK,
            required_confirmations: 6,
            recipient_secrets: &[receiver],
            known_assets: &[asset_id],
        },
    );
    assert!(accepted.is_ok(), "{accepted:?}");
    println!("scan-only accept: VERIFIED (anchor {:?}, no RPC, no indexer)", loc1);

    // --- (b) absence -------------------------------------------------------
    assert_eq!(index.scan_check(&raw_nf, 90, 101), None, "pre-anchor window");
    assert_eq!(
        index.scan_check(&Digest::from_bytes([77u8; 32]), 102, tip),
        None,
        "an unrelated nullifier has no occurrence"
    );
    // Filters skipped every non-anchor block: exactly one block was
    // fetched over the wire.
    let counters = index.counters();
    assert_eq!(counters.blocks_fetched, 1, "{counters:?}");

    // --- (c) a real double-spend: the scan finds exactly the first ---------
    let ref2 = common::anchor_xfer_same_retry(&mut anchor_chain, raw_nf);
    anchor_chain.generate_blocks(2).unwrap();
    let loc2 = anchor_chain.locate(&ref2).expect("double-spend mined");
    let tip = anchor_chain.tip_height();
    node.wait_for_filter_index();
    client.sync().unwrap();
    index.scan_sync(&mut client, 102).unwrap();
    assert_eq!(index.occurrences().len(), 2);
    assert_eq!(index.scan_check(&raw_nf, 102, tip), Some((loc1, ctx1)));
    assert_eq!(index.nullifier_occurrences(&raw_nf), vec![loc1, loc2]);
    assert_eq!(index.first_nullifier_occurrence(&raw_nf), Some(loc1));

    // A re-opened index (persistence) answers identically — locally.
    let reopened = ScanIndex::open(&scan_dir, Network::Regtest).unwrap();
    assert_eq!(reopened.synced_tip(), tip);
    assert_eq!(reopened.scan_check(&raw_nf, 102, tip), Some((loc1, ctx1)));
    assert_eq!(reopened.occurrences().len(), 2);

    // --- (d) bandwidth -----------------------------------------------------
    let counters = index.counters();
    println!(
        "scan bandwidth: {} filter bytes, {} block bytes ({} blocks) for {} filters",
        counters.filters_bytes,
        counters.blocks_bytes,
        counters.blocks_fetched,
        tip - 102 + 1,
    );
    assert!(
        counters.filters_bytes < 1_000_000 && counters.blocks_bytes < 1_000_000,
        "test window must cost well under a few MB: {counters:?}"
    );
    // The full chain (107 blocks) of filters + 2 tiny anchor blocks.
    assert_eq!(counters.blocks_fetched, 2, "{counters:?}");
}
