//! End-to-end self-scan exclusion: a genuine double-spend on regtest —
//! the same raw nullifier anchored twice (each time bound to its own
//! transaction ctx) — and `FullScanChain` over P2P-fetched,
//! merkle-verified blocks finds the first occurrence and only that one.
//!
//! Skipped (silently green) when no `bitcoind` binary is available; set
//! `OPENCSV_BITCOIND` to override the default path.

mod common;

use std::time::Duration;

use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_cbf::{CbfClient, Config, FullScanChain};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{AnchorRecord, Digest};

#[test]
fn fullscan_finds_first_occurrence_of_double_spend() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!(
            "skipping fullscan_finds_first_occurrence_of_double_spend: bitcoind not found"
        );
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

    // The legitimate spend of `raw_nf`, mined, then a double-spend of
    // the SAME raw nullifier (bound to its own ctx), mined later.
    let (raw_nf, ref1) = common::anchor_xfer_retry(&mut anchor_chain, 11);
    anchor_chain.generate_blocks(2).unwrap();
    let ref2 = common::anchor_xfer_same_retry(&mut anchor_chain, raw_nf);
    anchor_chain.generate_blocks(2).unwrap();
    let loc1 = anchor_chain.locate(&ref1).expect("first anchor mined");
    let loc2 = anchor_chain.locate(&ref2).expect("double-spend mined");
    let ctx1 = anchor_chain.ctx_at(&ref1).unwrap();
    let ctx2 = anchor_chain.ctx_at(&ref2).unwrap();
    let record2 = anchor_chain.anchor_at(&ref2).unwrap();
    assert!(loc1.height < loc2.height, "{loc1:?} before {loc2:?}");
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 105);

    node.wait_for_filter_index(); // CbfClient syncs filter headers too.
    let config = Config {
        network: Network::Regtest,
        peers: vec![format!("127.0.0.1:{}", node.p2p_port)],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();
    assert_eq!(client.tip_height(), tip);

    // The self-scan over the full window finds the FIRST occurrence —
    // and reports it with its ctx.
    let first =
        FullScanChain::first_occurrence_in_window(&mut client, &raw_nf, loc1.height, tip).unwrap();
    assert_eq!(first, Some((loc1, ctx1)));

    // A window covering only the double-spend sees only the
    // double-spend (window semantics: occurrences before `birth` are
    // invisible — callers must start at the coin's birth height).
    let only_later =
        FullScanChain::first_occurrence_in_window(&mut client, &raw_nf, loc2.height, tip).unwrap();
    assert_eq!(only_later, Some((loc2, ctx2)));

    // A window between the two spends contains no occurrence.
    let between = FullScanChain::first_occurrence_in_window(
        &mut client,
        &raw_nf,
        loc1.height + 1,
        loc2.height - 1,
    )
    .unwrap();
    assert_eq!(between, None);

    // The chain view: both occurrences in canonical order, presence
    // lookups, window-relative confirmations.
    let scan = FullScanChain::scan(&mut client, loc1.height, tip).unwrap();
    assert_eq!(scan.window(), (loc1.height, tip));
    assert_eq!(scan.nullifier_occurrences(&raw_nf), vec![loc1, loc2]);
    assert_eq!(scan.first_nullifier_occurrence(&raw_nf), Some(loc1));
    assert_eq!(scan.anchor_at(&ref2), Some(record2));
    assert_eq!(scan.ctx_at(&ref2), Some(ctx2));
    assert_eq!(scan.tip_height(), tip);
    assert_eq!(scan.confirmations_at(loc2.height), tip - loc2.height + 1);
    assert_eq!(
        scan.first_nullifier_occurrence(&Digest::from_bytes([77u8; 32])),
        None,
        "an unrelated nullifier has no occurrence"
    );
    // Every scanned entry sits inside the window.
    assert!(
        scan.entries()
            .iter()
            .all(|e| e.location.height >= loc1.height)
    );

    // Window validation. (The MAX_WINDOW_BLOCKS cap can't be reached on
    // a 105-block chain — the above-tip check fires first — and mining
    // 2017 blocks to exercise it would slow the suite for no behavioral
    // gain; the comparison is straightforward in `scan`.)
    assert!(FullScanChain::scan(&mut client, 0, tip).is_err(), "genesis window");
    assert!(FullScanChain::scan(&mut client, tip + 1, tip + 2).is_err(), "above tip");
    assert!(FullScanChain::scan(&mut client, tip, tip - 1).is_err(), "empty window");
}
