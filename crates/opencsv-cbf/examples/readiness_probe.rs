use std::path::PathBuf;
use std::time::{Duration, Instant};

use opencsv_cbf::{CbfClient, Config, Network, ScanIndex, ScanLoadStatus};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let cache_dir = PathBuf::from(args.next().ok_or(
        "usage: readiness_probe <cache-dir> <scan-dir> <scan-window> <peer> <peer> [peer...]",
    )?);
    let scan_dir = PathBuf::from(args.next().ok_or("missing scan directory")?);
    let scan_window: u64 = args.next().ok_or("missing scan window")?.parse()?;
    if scan_window == 0 {
        return Err("scan window must be nonzero".into());
    }
    let peers: Vec<String> = args.collect();
    if peers.len() < 2 {
        return Err("readiness probe requires at least two configured peers".into());
    }

    let started = Instant::now();
    let mut client = CbfClient::connect(&Config {
        network: Network::Signet,
        peers,
        cache_dir,
        timeout: Duration::from_secs(60),
    })?;
    let connection_sync_ms = elapsed_ms(started);
    if client.connected_peer_count() < 2 {
        return Err(format!(
            "only {} compact-filter peer(s) connected; readiness requires two",
            client.connected_peer_count()
        )
        .into());
    }
    let tip = client.tip_height();
    let handshakes = client.handshake_count();
    let (connection_sent, connection_received) = client.network_bytes();

    let hot_before = client.network_bytes();
    let hot_started = Instant::now();
    client.sync()?;
    let same_session_sync_ms = elapsed_ms(hot_started);
    if client.handshake_count() != handshakes {
        return Err("same-session sync unexpectedly repeated a handshake".into());
    }
    let hot_after = client.network_bytes();

    let scan_from = tip.saturating_sub(scan_window - 1).max(1);
    let mut scan = ScanIndex::open(&scan_dir, Network::Signet)?;
    let initial_scan_status = scan.load_status();
    let scan_started = Instant::now();
    scan.scan_sync(&mut client, scan_from)?;
    let scan_ms = elapsed_ms(scan_started);
    let counters = scan.counters();
    let occurrence_count = scan.occurrences().len();
    drop(scan);
    let reopened = ScanIndex::open(&scan_dir, Network::Signet)?;

    println!(
        concat!(
            "{{",
            "\"network\":\"signet\",",
            "\"tip\":{},",
            "\"connected_peers\":{},",
            "\"handshakes\":{},",
            "\"connection_sync_ms\":{},",
            "\"connection_wire_sent\":{},",
            "\"connection_wire_received\":{},",
            "\"same_session_sync_ms\":{},",
            "\"same_session_wire_sent\":{},",
            "\"same_session_wire_received\":{},",
            "\"scan_from\":{},",
            "\"scan_to\":{},",
            "\"scan_ms\":{},",
            "\"scan_filter_bytes\":{},",
            "\"scan_block_bytes\":{},",
            "\"scan_blocks_fetched\":{},",
            "\"scan_occurrences\":{},",
            "\"scan_initial_status\":\"{}\",",
            "\"scan_reopen_status\":\"{}\"",
            "}}"
        ),
        tip,
        client.connected_peer_count(),
        handshakes,
        connection_sync_ms,
        connection_sent,
        connection_received,
        same_session_sync_ms,
        hot_after.0.saturating_sub(hot_before.0),
        hot_after.1.saturating_sub(hot_before.1),
        scan_from,
        tip,
        scan_ms,
        counters.filters_bytes,
        counters.blocks_bytes,
        counters.blocks_fetched,
        occurrence_count,
        status_name(initial_scan_status),
        status_name(reopened.load_status()),
    );
    Ok(())
}

fn elapsed_ms(started: Instant) -> u128 {
    started.elapsed().as_millis()
}

fn status_name(status: ScanLoadStatus) -> &'static str {
    match status {
        ScanLoadStatus::Fresh => "fresh",
        ScanLoadStatus::Loaded => "loaded",
        ScanLoadStatus::RebuildRequired => "rebuild_required",
    }
}
