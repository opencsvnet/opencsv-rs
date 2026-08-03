//! Live signet regression test for the height-2016 retarget failure:
//! full header sync from genesis through (far more than) two
//! difficulty-retarget boundaries against a real synced signet node,
//! then a bounded `scan_sync` past the boundary. Skipped when no signet
//! compact-filter peers are explicitly supplied through the
//! comma-separated `OPENCSV_SIGNET_PEERS` variable. Two peers are
//! required so this test exercises independent agreement.

use std::time::{Duration, Instant};

use opencsv_cbf::{CbfClient, Config, Network, ScanIndex};

fn signet_peers() -> Option<Vec<String>> {
    let peers: Vec<String> = std::env::var("OPENCSV_SIGNET_PEERS")
        .ok()?
        .split(',')
        .map(str::trim)
        .filter(|peer| !peer.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(
        peers.len() >= 2,
        "OPENCSV_SIGNET_PEERS must name at least two peers"
    );
    Some(peers)
}

#[test]
fn signet_sync_through_retarget_boundaries() {
    let Some(peers) = signet_peers() else {
        eprintln!(
            "skipping signet_sync_through_retarget_boundaries: OPENCSV_SIGNET_PEERS is unset"
        );
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let started = Instant::now();
    // connect() performs the full PoW-validated header sync to the
    // peer's tip — this died at height 2019 before the signet
    // difficulty-rule fix.
    let mut client = CbfClient::connect(&Config {
        network: Network::Signet,
        peers,
        cache_dir: tmp.path().join("cbf"),
        timeout: Duration::from_secs(60),
    })
    .expect("signet header sync must succeed through retarget boundaries");
    let tip = client.tip_height();
    assert!(client.connected_peer_count() >= 2);
    assert!(
        tip > 2 * 2016,
        "must have passed two retarget boundaries: tip {tip}"
    );
    println!(
        "signet header sync OK: {} headers in {:?}",
        tip + 1,
        started.elapsed()
    );

    // And scan_sync proceeds past the boundary (a short window near the
    // tip keeps the filter walk small — the failure was in the header
    // phase, already exercised above).
    let mut index = ScanIndex::open(tmp.path().join("scan"), Network::Signet).unwrap();
    index.scan_sync(&mut client, tip - 10).unwrap();
    assert_eq!(index.synced_tip(), tip);
    println!(
        "scan_sync past 2016 OK: synced to {} ({} filter bytes, {} block bytes)",
        index.synced_tip(),
        index.counters().filters_bytes,
        index.counters().blocks_bytes
    );
}
