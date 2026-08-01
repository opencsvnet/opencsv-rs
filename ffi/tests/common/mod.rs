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

/// A currently-free TCP port (small race with the later bind; fine for
/// tests).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
    pub fn start(bitcoind: &PathBuf, datadir: PathBuf) -> Self {
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
        let node = Self {
            child,
            rpc_url: format!("http://127.0.0.1:{rpc_port}"),
            cookie: datadir.join("regtest/.cookie"),
            p2p_port,
            debug_log: datadir.join("regtest/debug.log"),
        };
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
        node
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
