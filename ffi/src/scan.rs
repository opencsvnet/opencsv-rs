//! The self-scan-first scan engine (`opencsv-cbf`'s `ScanIndex`) behind
//! the JSON boundary: sync, local occurrence check, and scan-only accept.
//!
//! The flow is sync-then-verify: [`sync_json`] connects to the P2P
//! network, syncs the header/filter chains and the occurrence index into
//! `cache_dir`, and **registers** that configuration (network, cache dir,
//! required confirmations) as the handle-free default for
//! [`check_json`] and [`verify_json`], which are then fully local — no
//! network at check time.
//!
//! Sync config JSON:
//!
//! ```json
//! {
//!   "network": "signet",
//!   "peers": ["127.0.0.1:38333"],
//!   "cache_dir": "/var/mobile/.../cbf-cache",
//!   "timeout_ms": 30000,
//!   "from_height": 120000,
//!   "required_confirmations": 6
//! }
//! ```
//!
//! `from_height` is typically the wallet's birth height (the index
//! resumes from its synced tip on later calls);
//! `required_confirmations` (default 0) is the policy [`verify_json`]
//! applies — its verdict always also carries the anchor's confirmation
//! count so the host can enforce its own.

use std::sync::{LazyLock, Mutex};

use opencsv_cbf::{CbfClient, Config as CbfConfig, Network, ScanIndex};
use opencsv_core::accept::{accept, AcceptParams, ProofVerifier};
use opencsv_core::chain::AnchorChain as _;
use opencsv_core::consignment::Consignment;
use opencsv_core::{AssetId, Digest, OwnerSecret};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::hex::{from_hex, from_hex_array, to_hex};
use crate::wallet::COIN_VK;

#[derive(Clone)]
struct ScanRegistration {
    network: Network,
    cache_dir: String,
    required_confirmations: u64,
}

static LAST_SCAN: LazyLock<Mutex<Option<ScanRegistration>>> = LazyLock::new(|| Mutex::new(None));

/// The sync config (module docs).
#[derive(Deserialize)]
pub struct ScanConfigJson {
    /// `signet` / `mainnet` / `regtest`.
    network: String,
    /// Peer addresses (`host:port`; port defaults per network).
    peers: Vec<String>,
    /// Cache directory (CbfClient's chains + the scan index under
    /// `scan/`).
    cache_dir: String,
    /// Per-operation timeout in milliseconds (default 30 s).
    timeout_ms: Option<u64>,
    /// Height to start the filter scan from on a fresh index (the
    /// wallet's birth height).
    from_height: u64,
    /// Confirmation policy for [`verify_json`] (default 0).
    required_confirmations: Option<u64>,
}

/// Connect, sync, and register (module docs). Returns
/// `{"tip_height":N,"filters_bytes":N,"blocks_bytes":N,"anchors":N}`.
pub fn sync_json(config_json: &str) -> Result<Value, String> {
    let config: ScanConfigJson =
        serde_json::from_str(config_json).map_err(|e| format!("scan config JSON: {e}"))?;
    let network = Network::parse(&config.network).map_err(|e| e.to_string())?;
    let mut client = CbfClient::connect(&CbfConfig {
        network,
        peers: config.peers.clone(),
        cache_dir: config.cache_dir.clone().into(),
        timeout: std::time::Duration::from_millis(config.timeout_ms.unwrap_or(30_000)),
    })
    .map_err(|e| e.to_string())?;
    let mut index = ScanIndex::open(
        std::path::Path::new(&config.cache_dir).join("scan"),
        network,
    )
    .map_err(|e| e.to_string())?;
    index
        .scan_sync(&mut client, config.from_height)
        .map_err(|e| e.to_string())?;
    let counters = index.counters();
    let tip = index.synced_tip();
    let anchors = index.occurrences().len();
    let mut registry = match LAST_SCAN.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    *registry = Some(ScanRegistration {
        network,
        cache_dir: config.cache_dir,
        required_confirmations: config.required_confirmations.unwrap_or(0),
    });
    Ok(json!({
        "tip_height": tip,
        "filters_bytes": counters.filters_bytes,
        "blocks_bytes": counters.blocks_bytes,
        "anchors": anchors,
    }))
}

fn registered_index() -> Result<ScanIndex, String> {
    let registry = match LAST_SCAN.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    let registration = registry
        .as_ref()
        .ok_or("no scan registered; call opencsv_scan_sync first")?;
    ScanIndex::open(
        std::path::Path::new(&registration.cache_dir).join("scan"),
        registration.network,
    )
    .map_err(|e| e.to_string())
}

fn registered_required_confirmations() -> u64 {
    let registry = match LAST_SCAN.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    registry
        .as_ref()
        .map(|r| r.required_confirmations)
        .unwrap_or(0)
}

/// The occurrence-check request:
/// `{"raw_nf_hex":"<64 hex>","birth":N,"spend":N}`.
#[derive(Deserialize)]
pub struct ScanCheckRequestJson {
    raw_nf_hex: String,
    birth: u64,
    spend: u64,
}

/// Local-only earliest-occurrence check against the registered scan
/// index: `{"occurrence":{"height":N,"position":M,"ctx_hex":"<64 hex>"}}`
/// or `{"occurrence":null}`.
pub fn check_json(request_json: &str) -> Result<Value, String> {
    let request: ScanCheckRequestJson =
        serde_json::from_str(request_json).map_err(|e| format!("scan check JSON: {e}"))?;
    let raw_nf = Digest::from_bytes(from_hex_array::<32>(&request.raw_nf_hex, "raw nullifier")?);
    let index = registered_index()?;
    match index.scan_check(&raw_nf, request.birth, request.spend) {
        Some((location, ctx)) => Ok(json!({
            "occurrence": {
                "height": location.height,
                "position": location.position,
                "ctx_hex": to_hex(&ctx),
            }
        })),
        None => Ok(json!({ "occurrence": null })),
    }
}

/// Run the accept driver over a consignment against the registered scan
/// index (read-only; credit via `opencsv_verify_consignment`). Generic
/// over the proof verifier so tests can exercise the exclusion path
/// with the fast `MockVerifier`; the ABI uses the real PCD verifier.
pub fn verify_json<V: ProofVerifier>(
    consignment_hex: &str,
    recipient_secrets: &[OwnerSecret],
    known_assets: &[AssetId],
    verifier: &V,
) -> Result<Value, String> {
    let blob = from_hex(consignment_hex)?;
    let consignment = Consignment::from_bytes(&blob).map_err(|e| e.to_string())?;
    let index = registered_index()?;
    let required = registered_required_confirmations();
    let accepted = accept(
        &consignment,
        &index,
        verifier,
        &AcceptParams {
            vk: COIN_VK,
            required_confirmations: required,
            recipient_secrets,
            known_assets,
        },
    );
    let tip = index.synced_tip();
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
            "confirmations": index.confirmations_at(accepted.anchor.height),
            "tip_height": tip,
        })),
        Err(reason) => Ok(json!({
            "status": "rejected",
            "reason": format!("{reason:?}"),
            "tip_height": tip,
        })),
    }
}

