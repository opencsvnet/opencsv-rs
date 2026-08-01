//! Demo anchor server (issue: OpenCSV wallet integration, W2).
//!
//! Serves a [`FileAnchorChain`] — the CLI's demo stand-in for Bitcoin — over
//! HTTP so phone wallets can fetch the anchor-log view and publish anchors
//! without a node:
//!
//! - `GET /snapshot` → the whole chain as the snapshot JSON
//!   `opencsv-ffi` consumes (`{"tip_height":N,"entries":[...]}`), including
//!   each anchor's transaction context `ctx`;
//! - `POST /anchor` `{"record":"<128 hex>","ctx":"<64 hex>"}` → appends the
//!   64-byte anchor record under transaction context `ctx`, returns
//!   `{"txid":"<64 hex>","height":N,"position":M,"ctx":"<64 hex>"}` (the
//!   anchor ref for `opencsv_consignment_finalize`), then auto-advances the
//!   tip by `--auto-advance` blocks (default 6) so demo consignments clear
//!   the confirmation policy without a separate miner.
//!
//!   The caller draws `ctx` *before* constructing the record — the record's
//!   payloads are `H("bind" ∥ raw_nf ∥ ctx)` (see `opencsv-core`'s anchor
//!   docs), and only the caller knows the raw nullifiers, so the server
//!   cannot (re)bind anything itself. If `ctx` is omitted the server draws
//!   a fresh random one, which is only meaningful for payload-less MINT
//!   records.
//! - `POST /advance` `{"blocks":N}` → advances the tip, returns
//!   `{"tip_height":N}`.
//!
//! Point every party of a demo at the same server (`opencsv-cli` wallets use
//! `--chain` on the same file only when co-located; remote parties use this
//! server). Requests are handled on their own threads (a stalled client
//! must not wedge the server) with the chain behind a mutex, so writes stay
//! serialized — `FileAnchorChain` has no file locking of its own.

mod esplora;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use opencsv_cli::chain::FileAnchorChain;
use opencsv_cli::hexutil::{from_hex, to_hex};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{AnchorRecord, ANCHOR_SIZE};
use opencsv_ffi::snapshot::{entry_json, Snapshot};
use serde::Deserialize;
use serde_json::json;

use crate::esplora::{scan_new_blocks, AnchorWallet, EsploraClient, KnownNetwork, ScanState};

/// Demo anchor server for OpenCSV wallets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum Backend {
    /// Demo chain in a local append-only file.
    File,
    /// Real Bitcoin via an esplora API.
    Esplora,
}

#[derive(Parser)]
struct Args {
    /// Chain backend.
    #[arg(long, value_enum, default_value_t = Backend::File)]
    backend: Backend,
    /// Chain file for the file backend (created if missing).
    #[arg(long, required_if_eq("backend", "file"))]
    chain: Option<PathBuf>,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    /// Blocks to auto-advance after each anchored record (0 disables;
    /// demo default clears the receiver's 6-confirmation policy).
    #[arg(long, default_value_t = 6)]
    auto_advance: u64,
    /// Esplora backend: which network (sets the well-known endpoint).
    #[arg(long, value_enum, required_if_eq("backend", "esplora"))]
    network: Option<KnownNetwork>,
    /// Esplora backend: custom endpoint overriding the network default
    /// (e.g. your own electrs/esplora instance).
    #[arg(long)]
    esplora_url: Option<String>,
    /// Esplora backend: file holding the anchoring key (WIF). Without it
    /// the server is read-only (no anchoring).
    #[arg(long)]
    wif_file: Option<PathBuf>,
    /// Esplora backend: first block height to scan for anchors.
    #[arg(long, default_value_t = 0)]
    birth_height: u64,
    /// Esplora backend: scan cache file (default:
    /// esplora-cache-<network>.log in the working directory).
    #[arg(long)]
    cache: Option<PathBuf>,
    /// Esplora backend: seconds between scans for new blocks.
    #[arg(long, default_value_t = 20)]
    poll_secs: u64,
    /// Generate a fresh anchoring key for --network, print its WIF and
    /// address, and exit.
    #[arg(long)]
    generate_key: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.generate_key {
        let network = args.network.ok_or("--generate-key requires --network")?;
        let (wif, address) = AnchorWallet::generate(network.bitcoin_network());
        println!("network: {network:?}");
        println!("wif:     {wif}");
        println!("address: {address}");
        println!("(save the WIF to a file, pass --wif-file, and fund the address)");
        return Ok(());
    }

    match args.backend {
        Backend::File => run_file_backend(&args),
        Backend::Esplora => run_esplora_backend(&args),
    }
}

/// Serve requests on their own threads (a stalled client must not wedge
/// the server).
fn serve<F>(listen: &str, route: F) -> Result<(), Box<dyn std::error::Error>>
where
    F: Fn(&str, &str, &[u8]) -> (u16, String) + Send + Sync + 'static,
{
    let server = tiny_http::Server::http(listen).map_err(|e| format!("listen on {listen}: {e}"))?;
    let route = Arc::new(route);
    for mut request in server.incoming_requests() {
        let route = Arc::clone(&route);
        std::thread::spawn(move || {
            let mut body = Vec::new();
            if let Err(e) = request.as_reader().read_to_end(&mut body) {
                eprintln!("read body: {e}");
                return;
            }
            let method = request.method().as_str().to_owned();
            let path = request.url().to_owned();
            let (status, reply) = route(&method, &path, &body);
            eprintln!("{method} {path} -> {status}");
            let response = tiny_http::Response::from_string(reply)
                .with_status_code(status)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("static header"),
                );
            if let Err(e) = request.respond(response) {
                eprintln!("respond: {e}");
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File backend (demo chain).
// ---------------------------------------------------------------------------

fn run_file_backend(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let chain_path = args.chain.clone().expect("required for the file backend");
    let chain = FileAnchorChain::open(&chain_path)?;
    eprintln!(
        "opencsv-anchor-server[file]: serving {} on http://{} (tip {}, {} anchors, auto-advance {})",
        chain_path.display(),
        args.listen,
        chain.tip_height(),
        chain.entries().count(),
        args.auto_advance,
    );
    let chain = Arc::new(Mutex::new(chain));
    let auto_advance = args.auto_advance;
    serve(&args.listen.clone(), move |method, path, body| {
        let mut chain = match chain.lock() {
            Ok(chain) => chain,
            Err(poisoned) => poisoned.into_inner(),
        };
        handle(&mut chain, auto_advance, method, path, body)
    })
}

#[derive(Deserialize)]
struct AnchorBody {
    record: String,
    /// Transaction context the record's payloads are bound to (hex).
    /// Optional: if absent, the server draws a fresh random ctx — only
    /// meaningful for payload-less MINT records (see module docs).
    ctx: Option<String>,
}

#[derive(Deserialize)]
struct AdvanceBody {
    blocks: u64,
}

/// Route one request. Split from the HTTP loop for direct unit testing.
fn handle(
    chain: &mut FileAnchorChain,
    auto_advance: u64,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, String) {
    match (method, path) {
        ("GET", "/snapshot") => {
            let snapshot = Snapshot {
                tip_height: chain.tip_height(),
                entries: chain
                    .entries()
                    .map(|(r, record, ctx)| entry_json(r.location, &r.txid, &record, &ctx))
                    .collect(),
            };
            match serde_json::to_string(&snapshot) {
                Ok(json) => (200, json),
                Err(e) => error(500, format!("encode snapshot: {e}")),
            }
        }
        ("POST", "/anchor") => {
            let (record, ctx) = match parse_anchor(body) {
                Ok(parsed) => parsed,
                Err(e) => return error(400, e),
            };
            let anchor = match chain.append(record, ctx) {
                Ok(anchor) => anchor,
                Err(e) => return error(500, format!("append: {e}")),
            };
            if auto_advance > 0 {
                if let Err(e) = chain.advance_blocks(auto_advance) {
                    return error(500, format!("advance: {e}"));
                }
            }
            (
                200,
                json!({
                    "txid": to_hex(&anchor.txid),
                    "height": anchor.location.height,
                    "position": anchor.location.position,
                    "ctx": to_hex(&ctx),
                })
                .to_string(),
            )
        }
        ("POST", "/advance") => {
            let parsed: AdvanceBody = match serde_json::from_slice(body) {
                Ok(parsed) => parsed,
                Err(e) => return error(400, format!("body: {e}")),
            };
            if let Err(e) = chain.advance_blocks(parsed.blocks) {
                return error(500, format!("advance: {e}"));
            }
            (200, json!({ "tip_height": chain.tip_height() }).to_string())
        }
        _ => error(404, format!("no route {method} {path}")),
    }
}

// ---------------------------------------------------------------------------
// Esplora backend (real Bitcoin).
// ---------------------------------------------------------------------------

/// `ctx` on a real chain is derived from the anchor transaction's funding
/// outpoint, so any scanner recomputes it from chain data alone — no extra
/// on-chain bytes, and a snapshot server cannot lie about it. The wallet
/// must know `ctx` *before* building the record, so anchoring is a
/// handshake: `POST /anchor/context` reserves a funding UTXO and returns
/// its `ctx`; `POST /anchor` then broadcasts a transaction spending exactly
/// that UTXO.
fn run_esplora_backend(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let network = args.network.expect("required for the esplora backend");
    let esplora_url = args
        .esplora_url
        .clone()
        .unwrap_or_else(|| network.default_esplora_url().to_string());
    let cache_path = args.cache.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "esplora-cache-{}.log",
            format!("{network:?}").to_lowercase()
        ))
    });
    let wallet = match &args.wif_file {
        Some(path) => {
            let wif = std::fs::read_to_string(path)?;
            let wallet = AnchorWallet::from_wif(&wif, network.bitcoin_network())?;
            eprintln!("anchoring key funded address: {}", wallet.address);
            Some(Arc::new(wallet))
        }
        None => {
            eprintln!("no --wif-file: read-only (anchoring disabled)");
            None
        }
    };

    let client = Arc::new(EsploraClient::new(&esplora_url));
    let mut state = ScanState::load(cache_path, args.birth_height)?;
    eprintln!(
        "opencsv-anchor-server[esplora {network:?}]: {esplora_url}, scanning from height {}…",
        args.birth_height,
    );
    scan_new_blocks(&client, &mut state)?;
    eprintln!(
        "serving on http://{} (tip {}, {} anchors)",
        args.listen,
        state.tip_height,
        state.entries.len(),
    );
    let state = Arc::new(Mutex::new(state));

    {
        let client = Arc::clone(&client);
        let state = Arc::clone(&state);
        let poll_secs = args.poll_secs.max(5);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(poll_secs));
            let mut state = match state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Err(e) = scan_new_blocks(&client, &mut state) {
                eprintln!("scan: {e}");
            }
        });
    }

    serve(&args.listen.clone(), move |method, path, body| {
        esplora_handle(&client, &state, wallet.as_deref(), method, path, body)
    })
}

fn esplora_handle(
    client: &EsploraClient,
    state: &Mutex<ScanState>,
    wallet: Option<&AnchorWallet>,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, String) {
    match (method, path) {
        ("GET", "/snapshot") => {
            let state = match state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            let snapshot = Snapshot {
                tip_height: state.tip_height,
                entries: state
                    .entries
                    .iter()
                    .map(|(r, record, ctx)| entry_json(r.location, &r.txid, record, ctx))
                    .collect(),
            };
            match serde_json::to_string(&snapshot) {
                Ok(json) => (200, json),
                Err(e) => error(500, format!("encode snapshot: {e}")),
            }
        }
        ("POST", "/anchor/context") => {
            let Some(wallet) = wallet else {
                return error(400, "this server has no anchoring key (read-only)".into());
            };
            match wallet.reserve_context(client) {
                Ok(ctx) => (200, json!({ "ctx": to_hex(&ctx) }).to_string()),
                Err(e) => error(500, format!("reserve: {e}")),
            }
        }
        ("POST", "/anchor") => {
            let Some(wallet) = wallet else {
                return error(400, "this server has no anchoring key (read-only)".into());
            };
            let (record, ctx) = match parse_anchor(body) {
                Ok(parsed) => parsed,
                Err(e) => return error(400, e),
            };
            match wallet.broadcast_anchor(client, &record, &ctx) {
                Ok(txid) => (
                    200,
                    json!({ "txid": txid.to_string(), "ctx": to_hex(&ctx), "status": "pending" })
                        .to_string(),
                ),
                Err(e) => error(500, format!("broadcast: {e}")),
            }
        }
        ("GET", path) if path.starts_with("/anchor/") => {
            let txid = &path["/anchor/".len()..];
            if txid.len() != 64 || from_hex(txid).is_err() {
                return error(400, "bad txid".into());
            }
            let status = match client.tx_status(txid) {
                Ok(status) => status,
                Err(e) => return error(502, format!("esplora: {e}")),
            };
            let (Some(height), Some(block_hash), true) =
                (status.block_height, status.block_hash, status.confirmed)
            else {
                return (200, json!({ "confirmed": false, "txid": txid }).to_string());
            };
            let position = match client.block_txids(&block_hash) {
                Ok(txids) => txids.iter().position(|t| t == txid),
                Err(e) => return error(502, format!("esplora: {e}")),
            };
            let Some(position) = position else {
                return error(502, "confirmed tx missing from its block".into());
            };
            (
                200,
                json!({
                    "confirmed": true,
                    "txid": txid,
                    "height": height,
                    "position": position as u32,
                })
                .to_string(),
            )
        }
        ("POST", "/advance") => error(
            400,
            "advance is not supported on the esplora backend".into(),
        ),
        _ => error(404, format!("no route {method} {path}")),
    }
}

fn parse_anchor(body: &[u8]) -> Result<(AnchorRecord, [u8; 32]), String> {
    let parsed: AnchorBody = serde_json::from_slice(body).map_err(|e| format!("body: {e}"))?;
    let bytes: [u8; ANCHOR_SIZE] = from_hex(&parsed.record)
        .map_err(|e| format!("record: {e}"))?
        .try_into()
        .map_err(|_| format!("record: expected {ANCHOR_SIZE} bytes"))?;
    let record = AnchorRecord::from_bytes(&bytes);
    let ctx = match &parsed.ctx {
        Some(hex) => from_hex(hex)
            .map_err(|e| format!("ctx: {e}"))?
            .try_into()
            .map_err(|_| "ctx: expected 32 bytes".to_string())?,
        None => opencsv_cli::ops::random_ctx(),
    };
    Ok((record, ctx))
}

fn error(status: u16, message: String) -> (u16, String) {
    (status, json!({ "error": message }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_core::Digest;

    /// Pick a ctx whose bound payload avoids the MINT/REDEEM tag bytes (see
    /// opencsv-core's anchor docs).
    fn non_colliding_ctx(raw: &Digest) -> [u8; 32] {
        for s in 0u8..=255 {
            let ctx = [s; 32];
            let p = opencsv_core::binding(raw, &ctx).to_anchor();
            if p.as_bytes()[0] != 0x01 && p.as_bytes()[0] != 0x04 {
                return ctx;
            }
        }
        panic!("no non-colliding ctx found");
    }

    fn raw_nf() -> Digest {
        Digest::from_bytes([7u8; 32])
    }

    fn record_hex() -> String {
        let record = AnchorRecord::xfer(&[raw_nf()], &non_colliding_ctx(&raw_nf()));
        to_hex(&record.to_bytes())
    }

    fn anchor_body() -> String {
        format!(
            r#"{{"record":"{}","ctx":"{}"}}"#,
            record_hex(),
            to_hex(&non_colliding_ctx(&raw_nf()))
        )
    }

    fn chain() -> (tempfile::TempDir, FileAnchorChain) {
        let dir = tempfile::tempdir().expect("tempdir");
        let chain = FileAnchorChain::open(dir.path().join("chain.log")).expect("open chain");
        (dir, chain)
    }

    #[test]
    fn snapshot_anchor_advance_round_trip() {
        let (_dir, mut chain) = chain();

        let (status, body) = handle(&mut chain, 6, "GET", "/snapshot", b"");
        assert_eq!(status, 200);
        assert_eq!(body, r#"{"tip_height":0,"entries":[]}"#);

        let (status, body) = handle(&mut chain, 6, "POST", "/anchor", anchor_body().as_bytes());
        assert_eq!(status, 200, "{body}");
        let reply: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(reply["height"], 0);
        assert_eq!(reply["position"], 0);
        assert_eq!(reply["txid"].as_str().expect("txid").len(), 64);
        assert_eq!(
            reply["ctx"].as_str().expect("ctx"),
            to_hex(&non_colliding_ctx(&raw_nf()))
        );

        // Auto-advance moved the tip past the confirmation policy.
        let (status, body) = handle(&mut chain, 6, "GET", "/snapshot", b"");
        assert_eq!(status, 200);
        let snapshot: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(snapshot["tip_height"], 6);
        assert_eq!(
            snapshot["entries"][0]["record"].as_str(),
            Some(record_hex().as_str())
        );
        assert_eq!(
            snapshot["entries"][0]["ctx"].as_str(),
            Some(to_hex(&non_colliding_ctx(&raw_nf())).as_str())
        );

        // The snapshot parses back into the chain view opencsv-ffi uses.
        opencsv_ffi::snapshot::SnapshotChain::from_json(&body).expect("snapshot parses");

        let (status, body) = handle(&mut chain, 6, "POST", "/advance", br#"{"blocks":4}"#);
        assert_eq!(status, 200, "{body}");
        assert_eq!(chain.tip_height(), 10);

        // A restart replays the same state from the file.
        let reopened = FileAnchorChain::open(chain.path()).expect("reopen");
        assert_eq!(reopened.tip_height(), 10);
        assert_eq!(reopened.entries().count(), 1);
    }

    #[test]
    fn anchor_without_ctx_draws_one() {
        let (_dir, mut chain) = chain();
        // A MINT record carries no payload, so a server-drawn ctx is fine.
        let record = AnchorRecord::Mint {
            asset_id: Digest::from_bytes([1u8; 32]).to_anchor(),
            value: 100,
            mint_commit: Digest::from_bytes([2u8; 32]).to_anchor(),
        };
        let post = format!(r#"{{"record":"{}"}}"#, to_hex(&record.to_bytes()));
        let (status, body) = handle(&mut chain, 0, "POST", "/anchor", post.as_bytes());
        assert_eq!(status, 200, "{body}");
        let reply: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(reply["ctx"].as_str().expect("ctx").len(), 64);
    }

    #[test]
    fn rejects_bad_input() {
        let (_dir, mut chain) = chain();
        let (status, _) = handle(&mut chain, 0, "POST", "/anchor", b"not json");
        assert_eq!(status, 400);
        let (status, _) = handle(&mut chain, 0, "POST", "/anchor", br#"{"record":"zz"}"#);
        assert_eq!(status, 400);
        let (status, _) = handle(&mut chain, 0, "GET", "/nope", b"");
        assert_eq!(status, 404);
    }
}
