//! `CbfClient` (BIP157/158 light-client anchor verification) behind the
//! JSON boundary: [`sync_json`] and [`verify_anchor_json`].
//!
//! Config JSON (both functions; `anchor` is required only by
//! [`verify_anchor_json`]):
//!
//! ```json
//! {
//!   "network": "signet",
//!   "peers": ["127.0.0.1:38333", "node.example.com"],
//!   "cache_dir": "/var/mobile/.../cbf-cache",
//!   "timeout_ms": 30000,
//!   "anchor": {
//!     "record_hex": "<128 hex>",
//!     "txid_hex": "<64 hex>",
//!     "height": 1234,
//!     "position": 1,
//!     "required_confirmations": 6
//!   }
//! }
//! ```
//!
//! `txid_hex` is the 32-byte transaction id in the same hex order the
//! rest of this crate uses (internal order, matching `opencsv-bitcoin`'s
//! `AnchorRef::txid`). The client connects to every configured peer and
//! requires tip / filter-header agreement — see `opencsv-cbf`'s README
//! for the security model.

use opencsv_cbf::{AnchorVerdict, CbfClient, Config, Network, NotPresentReason};
use opencsv_core::anchor::ANCHOR_SIZE;
use opencsv_core::chain::AnchorLocation;
use opencsv_core::AnchorRecord;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::hex::{from_hex_array, to_hex};

/// The JSON config (module docs).
#[derive(Deserialize)]
pub struct CbfConfigJson {
    /// `signet` / `mainnet` / `regtest`.
    network: String,
    /// Peer addresses (`host:port`; port defaults per network).
    peers: Vec<String>,
    /// Directory for the rebuildable header/filter cache.
    cache_dir: String,
    /// Per-operation timeout in milliseconds (default 30 s).
    timeout_ms: Option<u64>,
    /// The anchor to verify (required by [`verify_anchor_json`]).
    anchor: Option<AnchorQueryJson>,
}

#[derive(Deserialize)]
struct AnchorQueryJson {
    record_hex: String,
    txid_hex: String,
    height: u64,
    position: u32,
    required_confirmations: u64,
}

fn connect(config: &CbfConfigJson) -> Result<CbfClient, String> {
    let network = Network::parse(&config.network).map_err(|e| e.to_string())?;
    let client = CbfClient::connect(&Config {
        network,
        peers: config.peers.clone(),
        cache_dir: config.cache_dir.clone().into(),
        timeout: std::time::Duration::from_millis(config.timeout_ms.unwrap_or(30_000)),
    })
    .map_err(|e| e.to_string())?;
    Ok(client)
}

/// Sync headers + filter headers from all peers and report the verified
/// tip: `{"tip_height":N}`.
pub fn sync_json(config_json: &str) -> Result<Value, String> {
    let config: CbfConfigJson =
        serde_json::from_str(config_json).map_err(|e| format!("cbf config JSON: {e}"))?;
    let client = connect(&config)?;
    Ok(json!({ "tip_height": client.tip_height() }))
}

/// Verify a claimed anchor (module docs). Verdicts:
/// `{"status":"confirmed","ctx_hex","block_hash_hex","confirmations",
/// "filter_diagnostic","tip_height"}`,
/// `{"status":"not_present","reason":"above_tip"|"position_out_of_range"|
/// "txid_mismatch"|"record_not_in_tx",...}`,
/// `{"status":"insufficient_confirmations","have":N,"required":N,...}`.
/// NOTE: `filter_diagnostic` is a BIP158 filter-match hint ONLY — basic filters
/// exclude OP_RETURN, so it plays no part in the verdict and must never be
/// read as evidence. The verdict rests solely on the SPV/merkle path.
pub fn verify_anchor_json(config_json: &str) -> Result<Value, String> {
    let config: CbfConfigJson =
        serde_json::from_str(config_json).map_err(|e| format!("cbf config JSON: {e}"))?;
    let anchor = config
        .anchor
        .as_ref()
        .ok_or("cbf config is missing `anchor`")?;
    let record_bytes = from_hex_array::<ANCHOR_SIZE>(&anchor.record_hex, "anchor record")?;
    let record = AnchorRecord::from_bytes(&record_bytes);
    let txid = from_hex_array::<32>(&anchor.txid_hex, "anchor txid")?;
    let location = AnchorLocation {
        height: anchor.height,
        position: anchor.position,
    };

    let mut client = connect(&config)?;
    let tip = client.tip_height();
    let verdict = client
        .verify_anchor(&record, location, txid, anchor.required_confirmations)
        .map_err(|e| e.to_string())?;
    let mut out = match verdict {
        AnchorVerdict::Confirmed {
            block_hash,
            ctx,
            confirmations,
            filter_matched,
        } => json!({
            "status": "confirmed",
            "ctx_hex": to_hex(&ctx),
            "block_hash_hex": to_hex(&block_hash),
            "confirmations": confirmations,
            "filter_diagnostic": filter_matched,
        }),
        AnchorVerdict::NotPresent(reason) => {
            let (reason, detail) = match reason {
                NotPresentReason::AboveTip { height, tip } => {
                    ("above_tip", json!({ "height": height, "tip": tip }))
                }
                NotPresentReason::PositionOutOfRange { position, tx_count } => {
                    ("position_out_of_range", json!({ "position": position, "tx_count": tx_count }))
                }
                NotPresentReason::TxidMismatch { claimed, actual } => (
                    "txid_mismatch",
                    json!({ "claimed_hex": to_hex(&claimed), "actual_hex": to_hex(&actual) }),
                ),
                NotPresentReason::RecordNotInTx => ("record_not_in_tx", json!({})),
            };
            let mut value = json!({ "status": "not_present", "reason": reason });
            value
                .as_object_mut()
                .expect("object")
                .extend(detail.as_object().expect("object").clone());
            value
        }
        AnchorVerdict::InsufficientConfirmations { have, required } => json!({
            "status": "insufficient_confirmations",
            "have": have,
            "required": required,
        }),
    };
    out.as_object_mut()
        .expect("object")
        .insert("tip_height".into(), json!(tip));
    Ok(out)
}
