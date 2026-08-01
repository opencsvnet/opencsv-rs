//! N-of-M cross-checked accept (paper §4.7.1) behind the JSON boundary:
//! build a [`CrossCheckedChain`] from a list of backend specs and run the
//! accept driver over a received consignment against it.
//!
//! Request JSON:
//!
//! ```json
//! {
//!   "backends": [
//!     { "type": "bitcoind", "network": "signet", "rpc_url": "http://127.0.0.1:38332",
//!       "cookie": "/home/me/.bitcoin/signet/.cookie", "wallet": "opencsv",
//!       "scan_from": 120000, "index_path": "/var/mobile/.../btc-index.log" },
//!     { "type": "http", "url": "http://indexer.example.com:8080" },
//!     { "type": "snapshot", "snapshot": { "tip_height": 6, "entries": [] } }
//!   ],
//!   "consignment_base64": "...",
//!   "required_confirmations": 6
//! }
//! ```
//!
//! Backend specs: `bitcoind` (a full `opencsv-bitcoin` RPC indexer;
//! `cookie` XOR `userpass`), `http` (an `opencsv-anchor-server`, read via
//! `GET /snapshot`), and `snapshot` (an inline anchor snapshot — the
//! demo/offline spec, same JSON as [`crate::snapshot`]).
//!
//! The check is read-only: credited coins are reported, not stored (the
//! host credits via `opencsv_verify_consignment`). Members are individually
//! untrusted — occurrence queries fan out to all of them and tip
//! disagreement is a hard error (see `opencsv-core`'s `crosscheck`).

use std::io::{Read, Write};
use std::net::TcpStream;

use opencsv_bitcoin::{BitcoinAnchorChain, Config as BtcConfig, Network, RpcAuth};
use opencsv_core::accept::{accept, AcceptParams, ProofVerifier};
use opencsv_core::chain::AnchorChain;
use opencsv_core::consignment::Consignment;
use opencsv_core::crosscheck::{CrossCheckError, CrossCheckedChain};
use opencsv_core::{AssetId, OwnerSecret};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::hex::to_hex;
use crate::snapshot::SnapshotChain;
use crate::wallet::COIN_VK;

/// The JSON request (module docs).
#[derive(Deserialize)]
pub struct CrossCheckRequestJson {
    /// The member backends (at least one; all must agree on the tip).
    backends: Vec<BackendSpecJson>,
    /// The received consignment blob, base64.
    consignment_base64: String,
    /// Confirmation depth to require (paper §4.7 rule 2).
    required_confirmations: u64,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum BackendSpecJson {
    Bitcoind {
        network: String,
        rpc_url: String,
        cookie: Option<String>,
        userpass: Option<String>,
        wallet: Option<String>,
        scan_from: Option<u64>,
        index_path: String,
    },
    Http {
        url: String,
    },
    Snapshot {
        snapshot: serde_json::Value,
    },
}

/// Why a cross-check could not run (mapped to error JSON at the ABI).
#[derive(Debug)]
pub enum CrossCheckFailure {
    /// Members disagree on the tip — reported with `kind:
    /// "tip_disagreement"`, never silently resolved.
    TipDisagreement(Vec<u64>),
    /// Anything else (bad config, unreachable backend, malformed blob).
    Other(String),
}

impl std::fmt::Display for CrossCheckFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TipDisagreement(tips) => {
                write!(f, "anchor backends disagree on tip height: {tips:?}")
            }
            Self::Other(message) => f.write_str(message),
        }
    }
}

fn other(message: impl std::fmt::Display) -> CrossCheckFailure {
    CrossCheckFailure::Other(message.to_string())
}

/// Run the cross-checked accept (module docs). The verdict:
/// `{"status":"verified","coins":[...],"anchor":{...},"tip_height":N}` or
/// `{"status":"rejected","reason":"...","tip_height":N}`.
pub fn run_cross_check<V: ProofVerifier>(
    request_json: &str,
    recipient_secrets: &[OwnerSecret],
    known_assets: &[AssetId],
    verifier: &V,
) -> Result<Value, CrossCheckFailure> {
    use base64::Engine as _;
    let request: CrossCheckRequestJson = serde_json::from_str(request_json)
        .map_err(|e| other(format!("cross-check request JSON: {e}")))?;

    let mut members: Vec<Box<dyn AnchorChain>> = Vec::new();
    for spec in &request.backends {
        members.push(open_member(spec)?);
    }
    let chain = CrossCheckedChain::new(members).map_err(|e| match e {
        CrossCheckError::TipDisagreement(tips) => CrossCheckFailure::TipDisagreement(tips),
        CrossCheckError::NoMembers => other("no anchor backends configured"),
    })?;

    let blob = base64::engine::general_purpose::STANDARD
        .decode(&request.consignment_base64)
        .map_err(|e| other(format!("consignment base64: {e}")))?;
    let consignment = Consignment::from_bytes(&blob).map_err(|e| other(e))?;
    let accepted = accept(
        &consignment,
        &chain,
        verifier,
        &AcceptParams {
            vk: COIN_VK,
            required_confirmations: request.required_confirmations,
            recipient_secrets,
            known_assets,
        },
    );
    let tip = chain.agreed_tip();
    match accepted {
        Ok(accepted) => Ok(json!({
            "status": "verified",
            "coins": accepted.coins.iter().map(|coin| json!({
                "id": to_hex(coin.commitment().as_bytes()),
                "asset_id": to_hex(coin.asset_id.as_bytes()),
                "value": coin.value,
                "owner": to_hex(coin.owner.as_bytes()),
            })).collect::<Vec<_>>(),
            "anchor": { "height": accepted.anchor.height, "position": accepted.anchor.position },
            "tip_height": tip,
        })),
        Err(reason) => Ok(json!({
            "status": "rejected",
            "reason": format!("{reason:?}"),
            "tip_height": tip,
        })),
    }
}

fn open_member(spec: &BackendSpecJson) -> Result<Box<dyn AnchorChain>, CrossCheckFailure> {
    match spec {
        BackendSpecJson::Bitcoind {
            network,
            rpc_url,
            cookie,
            userpass,
            wallet,
            scan_from,
            index_path,
        } => {
            let auth = match (cookie, userpass) {
                (Some(path), None) => RpcAuth::Cookie(path.into()),
                (None, Some(up)) => RpcAuth::UserPass(up.clone()),
                _ => {
                    return Err(other(
                        "bitcoind backend needs exactly one of `cookie` / `userpass`",
                    ))
                }
            };
            let chain = BitcoinAnchorChain::open(&BtcConfig {
                network: Network::parse(network).map_err(other)?,
                rpc_url: rpc_url.clone(),
                auth,
                wallet: wallet.clone(),
                scan_from: *scan_from,
                index_path: index_path.into(),
            })
            .map_err(other)?;
            Ok(Box::new(chain))
        }
        BackendSpecJson::Http { url } => {
            let body = http_get_snapshot(url)?;
            Ok(Box::new(SnapshotChain::from_json(&body).map_err(other)?))
        }
        BackendSpecJson::Snapshot { snapshot } => Ok(Box::new(
            SnapshotChain::from_json(&snapshot.to_string()).map_err(other)?,
        )),
    }
}

/// `GET {url}/snapshot` over a bare HTTP/1.1 `TcpStream` with
/// `Connection: close` (same dependency-free pattern as the rest of the
/// project). Not a general HTTP client.
fn http_get_snapshot(url: &str) -> Result<String, CrossCheckFailure> {
    let url = url.strip_prefix("http://").unwrap_or(url);
    let authority = url.split('/').next().unwrap_or(url);
    if authority.is_empty() {
        return Err(other("http backend: empty authority"));
    }
    let mut stream = TcpStream::connect(authority)
        .map_err(|e| other(format!("http backend {authority}: {e}")))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(other)?;
    let request = format!("GET /snapshot HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(other)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).map_err(other)?;
    let text = String::from_utf8(response).map_err(|e| other(format!("http response: {e}")))?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| other("http response missing header/body split"))?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") {
        return Err(other(format!("http backend {authority}: `{status}`")));
    }
    Ok(body.to_string())
}
