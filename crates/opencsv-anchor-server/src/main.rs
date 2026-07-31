//! Demo anchor server (issue: OpenCSV wallet integration, W2).
//!
//! Serves a [`FileAnchorChain`] — the CLI's demo stand-in for Bitcoin — over
//! HTTP so phone wallets can fetch the anchor-log view and publish anchors
//! without a node:
//!
//! - `GET /snapshot` → the whole chain as the snapshot JSON
//!   `opencsv-ffi` consumes (`{"tip_height":N,"entries":[...]}`);
//! - `POST /anchor` `{"record":"<128 hex>"}` → appends the 64-byte anchor
//!   record, returns `{"txid":"<64 hex>","height":N,"position":M}` (the
//!   anchor ref for `opencsv_consignment_finalize`), then auto-advances the
//!   tip by `--auto-advance` blocks (default 6) so demo consignments clear
//!   the confirmation policy without a separate miner;
//! - `POST /advance` `{"blocks":N}` → advances the tip, returns
//!   `{"tip_height":N}`.
//!
//! Point every party of a demo at the same server (`opencsv-cli` wallets use
//! `--chain` on the same file only when co-located; remote parties use this
//! server). Single-threaded on purpose: `FileAnchorChain` has no file
//! locking, and demo traffic is a handful of requests.

use std::path::PathBuf;

use clap::Parser;
use opencsv_cli::chain::FileAnchorChain;
use opencsv_cli::hexutil::{from_hex, to_hex};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{AnchorRecord, ANCHOR_SIZE};
use opencsv_ffi::snapshot::{entry_json, Snapshot};
use serde::Deserialize;
use serde_json::json;

/// Demo anchor server for OpenCSV wallets.
#[derive(Parser)]
struct Args {
    /// Chain file to serve (created if missing).
    #[arg(long)]
    chain: PathBuf,
    /// Listen address.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    /// Blocks to auto-advance after each anchored record (0 disables;
    /// demo default clears the receiver's 6-confirmation policy).
    #[arg(long, default_value_t = 6)]
    auto_advance: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut chain = FileAnchorChain::open(&args.chain)?;
    let server = tiny_http::Server::http(&args.listen)
        .map_err(|e| format!("listen on {}: {e}", args.listen))?;
    eprintln!(
        "opencsv-anchor-server: serving {} on http://{} (tip {}, {} anchors, auto-advance {})",
        args.chain.display(),
        args.listen,
        chain.tip_height(),
        chain.entries().count(),
        args.auto_advance,
    );

    for mut request in server.incoming_requests() {
        let mut body = Vec::new();
        if let Err(e) = request.as_reader().read_to_end(&mut body) {
            eprintln!("read body: {e}");
            continue;
        }
        let method = request.method().as_str().to_owned();
        let path = request.url().to_owned();
        let (status, reply) = handle(&mut chain, args.auto_advance, &method, &path, &body);
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
    }
    Ok(())
}

#[derive(Deserialize)]
struct AnchorBody {
    record: String,
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
                    .map(|(r, record)| entry_json(r.location, &r.txid, &record))
                    .collect(),
            };
            match serde_json::to_string(&snapshot) {
                Ok(json) => (200, json),
                Err(e) => error(500, format!("encode snapshot: {e}")),
            }
        }
        ("POST", "/anchor") => {
            let record = match parse_record(body) {
                Ok(record) => record,
                Err(e) => return error(400, e),
            };
            let anchor = match chain.append(record) {
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

fn parse_record(body: &[u8]) -> Result<AnchorRecord, String> {
    let parsed: AnchorBody = serde_json::from_slice(body).map_err(|e| format!("body: {e}"))?;
    let bytes: [u8; ANCHOR_SIZE] = from_hex(&parsed.record)
        .map_err(|e| format!("record: {e}"))?
        .try_into()
        .map_err(|_| format!("record: expected {ANCHOR_SIZE} bytes"))?;
    AnchorRecord::from_bytes(&bytes).map_err(|e| format!("record: {e}"))
}

fn error(status: u16, message: String) -> (u16, String) {
    (status, json!({ "error": message }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_core::TruncatedDigest;

    fn record_hex() -> String {
        let record = AnchorRecord::Xfer {
            nullifier: TruncatedDigest([7u8; 24]),
        };
        to_hex(&record.to_bytes())
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

        let post = format!(r#"{{"record":"{}"}}"#, record_hex());
        let (status, body) = handle(&mut chain, 6, "POST", "/anchor", post.as_bytes());
        assert_eq!(status, 200, "{body}");
        let reply: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(reply["height"], 0);
        assert_eq!(reply["position"], 0);
        assert_eq!(reply["txid"].as_str().expect("txid").len(), 64);

        // Auto-advance moved the tip past the confirmation policy.
        let (status, body) = handle(&mut chain, 6, "GET", "/snapshot", b"");
        assert_eq!(status, 200);
        let snapshot: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(snapshot["tip_height"], 6);
        assert_eq!(
            snapshot["entries"][0]["record"].as_str(),
            Some(record_hex().as_str())
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
