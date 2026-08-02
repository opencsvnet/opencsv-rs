//! Debug helper: sync headers from a peer and report where validation
//! fails. `cargo run -p opencsv-cbf --example sync_debug -- signet 127.0.0.1:38333 2500`

use std::time::Duration;

use opencsv_cbf::{CbfClient, Config, Network};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let network = Network::parse(args.get(1).map(String::as_str).unwrap_or("signet")).unwrap();
    let peer = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:38333".into());
    let dir = std::env::temp_dir().join(format!("cbf-debug-{}", std::process::id()));
    let mut client = CbfClient::connect(&Config {
        network,
        peers: vec![peer],
        cache_dir: dir,
        timeout: Duration::from_secs(30),
    })
    .expect("connect");
    match client.sync() {
        Ok(()) => println!("sync OK to tip {}", client.tip_height()),
        Err(e) => {
            println!("sync FAILED at height {}: {e}", client.tip_height());
            std::process::exit(1);
        }
    }
}
