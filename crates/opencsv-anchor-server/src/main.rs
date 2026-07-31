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

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use opencsv_cli::chain::FileAnchorChain;
use opencsv_cli::hexutil::{from_hex, to_hex};
use opencsv_core::chain::AnchorChain;
use opencsv_core::{ANCHOR_SIZE, AnchorRecord};
use opencsv_ffi::snapshot::{Snapshot, entry_json};
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
    let chain = FileAnchorChain::open(&args.chain)?;
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

    let chain = Arc::new(Mutex::new(chain));
    for mut request in server.incoming_requests() {
        let chain = Arc::clone(&chain);
        let auto_advance = args.auto_advance;
        std::thread::spawn(move || {
            let mut body = Vec::new();
            if let Err(e) = request.as_reader().read_to_end(&mut body) {
                eprintln!("read body: {e}");
                return;
            }
            let method = request.method().as_str().to_owned();
            let path = request.url().to_owned();
            let (status, reply) = {
                let mut chain = match chain.lock() {
                    Ok(chain) => chain,
                    Err(poisoned) => poisoned.into_inner(),
                };
                handle(&mut chain, auto_advance, &method, &path, &body)
            };
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
