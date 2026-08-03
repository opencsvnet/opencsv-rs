//! End-to-end integration test against a real `bitcoind` in regtest
//! mode: fresh temp datadir, `blockfilterindex=1 peerblockfilters=1`,
//! a real OpenCSV anchor transaction broadcast and mined via the
//! `opencsv-bitcoin` backend, then `CbfClient::verify_anchor` over the
//! P2P compact-filter protocol — presence, absence (wrong payload),
//! wrong position, and confirmation-count verdicts, all cross-checked
//! against the node's RPC.
//!
//! Skipped (silently green) when no `bitcoind` binary is available;
//! set `OPENCSV_BITCOIND` to override the default
//! `~/bitcoin-core/bin/bitcoind` path.

mod common;

use std::time::Duration;

use common::{bitcoind_path, Node};
use opencsv_bitcoin::rpc::RpcAuth;
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_cbf::block::anchor_script;
use opencsv_cbf::hash::{hash_to_display, to_hex};
use opencsv_cbf::{AnchorVerdict, CbfClient, Config, NotPresentReason};
use opencsv_core::chain::{AnchorChain, AnchorLocation};
use opencsv_core::{AnchorRecord, Digest};
use serde_json::json;

#[test]
fn regtest_end_to_end() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping regtest_end_to_end: bitcoind not found (set OPENCSV_BITCOIND)");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));

    // Wallet + 101 spendable blocks (Node::start waits for RPC).
    node.create_wallet_and_mine(101);

    // Anchor a real record through the opencsv-bitcoin backend (real
    // two-pass OP_RETURN transaction, signed and broadcast by the node).
    let btc_config = BtcConfig {
        network: Network::Regtest,
        rpc_url: node.rpc_url.clone(),
        auth: RpcAuth::Cookie(node.cookie.clone()),
        wallet: Some("test".into()),
        scan_from: Some(1),
        index_path: tmp.path().join("bitcoin-index.log"),
    };
    let mut anchor_chain = BitcoinAnchorChain::open(&btc_config).unwrap();
    let (_raw_nf, anchor_ref) = common::anchor_xfer_retry(&mut anchor_chain, 7);
    anchor_chain.generate_blocks(6).unwrap();
    let location: AnchorLocation = anchor_chain.locate(&anchor_ref).expect("anchor mined");
    let record = anchor_chain.anchor_at(&anchor_ref).unwrap();
    let ctx_expected = anchor_chain.ctx_at(&anchor_ref).unwrap();
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 107);
    assert!(location.height > 101 && location.height <= tip);

    // Wait for the compact-filter index to catch up.
    node.wait_for_filter_index();

    // The CBF client: two peer entries (same node twice) so the
    // multi-peer tip / filter-header comparison path is exercised.
    let config = Config {
        network: Network::Regtest,
        peers: vec![
            format!("127.0.0.1:{}", node.p2p_port),
            format!("127.0.0.1:{}", node.p2p_port),
        ],
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(30),
    };
    let mut client = CbfClient::connect(&config).unwrap();
    assert_eq!(client.tip_height(), tip, "header sync must reach the node tip");

    // Cross-check the client's filter chain against the node's own
    // filter index for the anchor block.
    let block_hash_display = node
        .rpc(None)
        .call("getblockhash", json!([location.height]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let node_filter = node
        .rpc(None)
        .call("getblockfilter", json!([block_hash_display]))
        .unwrap();

    // --- presence verdict -------------------------------------------------
    let verdict = client
        .verify_anchor(&record, location, anchor_ref.txid, 6)
        .unwrap();
    let AnchorVerdict::Confirmed {
        block_hash,
        ctx,
        confirmations,
        filter_matched,
    } = verdict
    else {
        panic!("expected Confirmed, got {verdict:?}");
    };
    assert_eq!(ctx, ctx_expected, "ctx recomputed from vin[0] must match the backend's");
    assert_eq!(confirmations, 6);
    assert_eq!(hash_to_display(&block_hash), block_hash_display);
    // The anchor's OP_RETURN script is NOT in the basic filter — BIP158
    // excludes all OP_RETURN outputs. This is the documented deviation
    // from the original design doc (see the crate README).
    assert!(!filter_matched);

    // The filter itself and its header match the node's own index.
    let cached_filter = std::fs::read(
        tmp.path()
            .join("cbf/regtest/filters")
            .join(format!("{:08}.filter", location.height)),
    )
    .expect("filter cached by verify_anchor");
    assert_eq!(to_hex(&cached_filter), node_filter["filter"].as_str().unwrap());
    assert_eq!(
        hash_to_display(&client.filter_header(location.height).unwrap()),
        node_filter["header"].as_str().unwrap()
    );

    // Positive control for GCS matching against real bitcoind filters:
    // the coinbase payout script IS in the filter.
    let block = client.fetch_block(&block_hash).unwrap();
    let miner_script = block.txs[0].outputs[0].script_pubkey.clone();
    assert!(client.filter_matches(location.height, &miner_script).unwrap());
    assert!(!client.filter_matches(location.height, &anchor_script(&record.to_bytes())).unwrap());

    // Protocol-fixed anchor transaction layout: output 0 is the
    // 64-byte OP_RETURN record, output 1 is the constant marker output
    // (546 sats to OP_0 <sha256(OP_RETURN)>), which makes the block
    // discoverable by BIP158 filter scans.
    let anchor_tx = &block.txs[location.position as usize];
    assert_eq!(anchor_tx.outputs[0].script_pubkey, anchor_script(&record.to_bytes()));
    assert_eq!(
        anchor_tx.outputs[1].script_pubkey.as_slice(),
        opencsv_bitcoin::MARKER_SPK.as_slice(),
        "marker scriptPubKey at output 1"
    );
    assert_eq!(anchor_tx.outputs[1].value, opencsv_bitcoin::MARKER_DUST_SATS);
    // ...and therefore the marker spk matches this block's filter.
    assert!(
        client
            .filter_matches(location.height, &opencsv_bitcoin::MARKER_SPK)
            .unwrap(),
        "the marker output must be filter-matchable"
    );

    // --- wrong-payload absence verdict -------------------------------------
    let wrong_nf = Digest::from_bytes([9u8; 32]);
    let wrong_record = AnchorRecord::xfer(&[wrong_nf], &ctx_expected);
    let verdict = client
        .verify_anchor(&wrong_record, location, anchor_ref.txid, 6)
        .unwrap();
    assert_eq!(
        verdict,
        AnchorVerdict::NotPresent(NotPresentReason::RecordNotInTx),
        "a different record at the same location must be rejected"
    );

    // --- wrong position -----------------------------------------------------
    let coinbase_position = AnchorLocation {
        height: location.height,
        position: 0,
    };
    let verdict = client
        .verify_anchor(&record, coinbase_position, anchor_ref.txid, 6)
        .unwrap();
    assert!(
        matches!(
            verdict,
            AnchorVerdict::NotPresent(NotPresentReason::TxidMismatch { .. })
        ),
        "position 0 is the coinbase: {verdict:?}"
    );
    let out_of_range = AnchorLocation {
        height: location.height,
        position: location.position + 100,
    };
    let verdict = client
        .verify_anchor(&record, out_of_range, anchor_ref.txid, 6)
        .unwrap();
    assert!(
        matches!(
            verdict,
            AnchorVerdict::NotPresent(NotPresentReason::PositionOutOfRange { .. })
        ),
        "position beyond the block's tx count: {verdict:?}"
    );

    // --- confirmations -------------------------------------------------------
    let verdict = client
        .verify_anchor(&record, location, anchor_ref.txid, 100)
        .unwrap();
    assert_eq!(
        verdict,
        AnchorVerdict::InsufficientConfirmations {
            have: 6,
            required: 100
        }
    );

    // --- above-tip height -----------------------------------------------------
    let future = AnchorLocation {
        height: tip + 50,
        position: location.position,
    };
    let verdict = client
        .verify_anchor(&record, future, anchor_ref.txid, 6)
        .unwrap();
    assert!(matches!(
        verdict,
        AnchorVerdict::NotPresent(NotPresentReason::AboveTip { .. })
    ));

    // --- cache reuse: a second client over the same cache dir -----------------
    let mut client2 = CbfClient::connect(&config).unwrap();
    assert_eq!(client2.tip_height(), tip);
    let verdict = client2
        .verify_anchor(&record, location, anchor_ref.txid, 6)
        .unwrap();
    assert!(matches!(verdict, AnchorVerdict::Confirmed { .. }));
}
