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

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use opencsv_bitcoin::rpc::{HttpTransport, RpcAuth, RpcClient};
use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network};
use opencsv_cbf::block::anchor_script;
use opencsv_cbf::hash::{hash_to_display, to_hex};
use opencsv_cbf::{AnchorVerdict, CbfClient, Config, NotPresentReason};
use opencsv_core::chain::{AnchorChain, AnchorLocation};
use opencsv_core::{AnchorRecord, Digest};
use serde_json::json;

fn bitcoind_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("OPENCSV_BITCOIND") {
        return Some(PathBuf::from(path));
    }
    let path = PathBuf::from(std::env::var("HOME").ok()?).join("bitcoin-core/bin/bitcoind");
    path.exists().then_some(path)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running regtest node; stopped on drop.
struct Node {
    child: Child,
    rpc_url: String,
    cookie: PathBuf,
    p2p_port: u16,
    debug_log: PathBuf,
}

impl Node {
    fn start(bitcoind: &PathBuf, datadir: PathBuf) -> Self {
        std::fs::create_dir_all(&datadir).unwrap();
        let rpc_port = free_port();
        let p2p_port = free_port();
        let child = Command::new(bitcoind)
            .args([
                "-regtest",
                &format!("-datadir={}", datadir.display()),
                "-server",
                &format!("-rpcport={rpc_port}"),
                &format!("-bind=127.0.0.1:{p2p_port}"),
                "-blockfilterindex=1",
                "-peerblockfilters=1",
                "-fallbackfee=0.00001",
                "-listenonion=0",
                "-dnsseed=0",
                "-fixedseeds=0",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bitcoind");
        Self {
            child,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
            cookie: datadir.join("regtest/.cookie"),
            p2p_port,
            debug_log: datadir.join("regtest/debug.log"),
        }
    }

    fn rpc(&self, wallet: Option<&str>) -> RpcClient<HttpTransport> {
        let transport =
            HttpTransport::new(&self.rpc_url, wallet, &RpcAuth::Cookie(self.cookie.clone()))
                .unwrap();
        RpcClient::new(transport)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.cookie.exists() {
            let _ = self.rpc(None).call("stop", json!([]));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200))
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    return;
                }
            }
        }
    }
}

#[test]
fn regtest_end_to_end() {
    let Some(bitcoind) = bitcoind_path() else {
        eprintln!("skipping regtest_end_to_end: bitcoind not found (set OPENCSV_BITCOIND)");
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let node = Node::start(&bitcoind, tmp.path().join("node"));

    // Wait for the RPC interface.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if node.cookie.exists() && node.rpc(None).call("getblockcount", json!([])).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "bitcoind RPC did not come up; see {}",
            node.debug_log.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // Wallet + 101 spendable blocks.
    node.rpc(None).call("createwallet", json!(["test"])).unwrap();
    let wallet = node.rpc(Some("test"));
    let address = wallet
        .call("getnewaddress", json!([]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    wallet.call("generatetoaddress", json!([101, address])).unwrap();

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
    let raw_nf = Digest::from_bytes([7u8; 32]);
    let anchor_ref = anchor_chain
        .anchor(|ctx| AnchorRecord::xfer(&[raw_nf], ctx))
        .unwrap();
    anchor_chain.generate_blocks(6).unwrap();
    let location: AnchorLocation = anchor_chain.locate(&anchor_ref).expect("anchor mined");
    let record = anchor_chain.anchor_at(&anchor_ref).unwrap();
    let ctx_expected = anchor_chain.ctx_at(&anchor_ref).unwrap();
    let tip = anchor_chain.tip_height();
    assert_eq!(tip, 107);
    assert!(location.height > 101 && location.height <= tip);

    // Wait for the compact-filter index to catch up.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let info = node.rpc(None).call("getindexinfo", json!([])).unwrap();
        let synced = info["basic block filter index"]["synced"]
            .as_bool()
            .or_else(|| info["blockfilterindex"]["synced"].as_bool());
        if synced == Some(true) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "blockfilterindex did not sync; see {}",
            node.debug_log.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }

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
