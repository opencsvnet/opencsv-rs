//! Shared regtest harness for the integration tests: spawn a real
//! `bitcoind` (regtest, `blockfilterindex=1 peerblockfilters=1`) on a
//! fresh temp datadir, wait for RPC, and stop it on drop.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use opencsv_bitcoin::rpc::{HttpTransport, RpcAuth, RpcClient};
use serde_json::json;

/// The bitcoind binary, from `OPENCSV_BITCOIND` or the default
/// `~/bitcoin-core/bin/bitcoind`; `None` when unavailable (tests skip).
pub fn bitcoind_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("OPENCSV_BITCOIND") {
        return Some(PathBuf::from(path));
    }
    let path = PathBuf::from(std::env::var("HOME").ok()?).join("bitcoin-core/bin/bitcoind");
    path.exists().then_some(path)
}

/// A currently-free TCP port (small race with the later bind — the
/// startup retry below covers it, since several test binaries run
/// concurrently and can draw the same port).
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}


/// Anchor an XFER record binding a fresh raw nullifier, retrying with
/// successive seeds when the bound payload's first byte collides with
/// the MINT/REDEEM/BATCH tag bytes for every candidate funding ctx
/// (`Error::TagCollision` — the two-pass anchor's only redraw freedom
/// is input order, so unlucky seeds fail ~1% of the time on regtest).
pub fn anchor_xfer_retry(
    chain: &mut opencsv_bitcoin::BitcoinAnchorChain,
    seed: u8,
) -> (opencsv_core::Digest, opencsv_core::chain::AnchorRef) {
    for attempt in seed..=255 {
        let raw_nf = opencsv_core::Digest::from_bytes([attempt; 32]);
        match chain.anchor(|ctx| opencsv_core::AnchorRecord::xfer(&[raw_nf], ctx)) {
            Ok(anchor_ref) => return (raw_nf, anchor_ref),
            Err(opencsv_bitcoin::error::Error::TagCollision) => continue,
            Err(e) => panic!("anchor failed: {e}"),
        }
    }
    panic!("tag collision for all 256 seeds");
}


/// Anchor an XFER record binding `raw_nf` (a fixed nullifier, e.g. a
/// deliberate double-spend), mining a block between `TagCollision`
/// retries so `fundrawtransaction` draws different funding inputs (the
/// tag-collision redraw freedom is input order).
pub fn anchor_xfer_same_retry(
    chain: &mut opencsv_bitcoin::BitcoinAnchorChain,
    raw_nf: opencsv_core::Digest,
) -> opencsv_core::chain::AnchorRef {
    for _ in 0..8 {
        match chain.anchor(|ctx| opencsv_core::AnchorRecord::xfer(&[raw_nf], ctx)) {
            Ok(anchor_ref) => return anchor_ref,
            Err(opencsv_bitcoin::error::Error::TagCollision) => {
                chain.generate_blocks(1).expect("mine for fresh inputs")
            }
            Err(e) => panic!("anchor failed: {e}"),
        }
    }
    panic!("tag collision persists for this raw_nf");
}

/// A running regtest node; stopped on drop.
pub struct Node {
    child: Child,
    pub rpc_url: String,
    pub cookie: PathBuf,
    pub p2p_port: u16,
    pub debug_log: PathBuf,
}

impl Node {
    /// Spawn bitcoind on `datadir` and wait for its RPC interface.
    /// Port-draw races between concurrent test binaries occasionally
    /// make bitcoind exit at startup (address already in use); retry a
    /// few times with fresh ports.
    pub fn start(bitcoind: &PathBuf, datadir: PathBuf) -> Self {
        for attempt in 0..5 {
            let datadir = if attempt == 0 {
                datadir.clone()
            } else {
                datadir.with_extension(format!("retry{attempt}"))
            };
            if let Some(node) = Self::try_start(bitcoind, datadir) {
                return node;
            }
        }
        panic!("bitcoind did not come up after 5 attempts");
    }

    fn try_start(bitcoind: &PathBuf, datadir: PathBuf) -> Option<Self> {
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
        let mut node = Self {
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
            cookie: datadir.join("regtest/.cookie"),
            p2p_port,
            debug_log: datadir.join("regtest/debug.log"),
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if node.cookie.exists() && node.rpc(None).call("getblockcount", json!([])).is_ok() {
                return Some(node);
            }
            // bitcoind died at startup (e.g. the port draw lost a race)?
            if let Ok(Some(_)) = node.child.try_wait() {
                return None;
            }
            if Instant::now() >= deadline {
                let mut node = node;
                let _ = node.child.kill();
                let _ = node.child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// An RPC client (optionally scoped to a wallet).
    pub fn rpc(&self, wallet: Option<&str>) -> RpcClient<HttpTransport> {
        let transport =
            HttpTransport::new(&self.rpc_url, wallet, &RpcAuth::Cookie(self.cookie.clone()))
                .unwrap();
        RpcClient::new(transport)
    }

    /// Create the test wallet and mine `count` blocks to it.
    pub fn create_wallet_and_mine(&self, count: u64) {
        self.rpc(None).call("createwallet", json!(["test"])).unwrap();
        let wallet = self.rpc(Some("test"));
        let address = wallet
            .call("getnewaddress", json!([]))
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        wallet.call("generatetoaddress", json!([count, address])).unwrap();
    }

    /// Wait for the compact-filter index to catch up to the tip.
    pub fn wait_for_filter_index(&self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let info = self.rpc(None).call("getindexinfo", json!([])).unwrap();
            let synced = info["basic block filter index"]["synced"]
                .as_bool()
                .or_else(|| info["blockfilterindex"]["synced"].as_bool());
            if synced == Some(true) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "blockfilterindex did not sync; see {}",
                self.debug_log.display()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
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
