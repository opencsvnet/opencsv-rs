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
use opencsv_core::{AssetId, Digest, Owner, OwnerSecret, PublicOwnerAcceptParams};
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

/// A persistent CBF client: peers stay connected between syncs (the
/// one-shot [`sync_json`] re-dials on every call — the persistent
/// client is for hosts that sync often, e.g. on every foregrounding).
struct PersistentClient {
    client: CbfClient,
    network: Network,
    cache_dir: String,
    from_height: u64,
    required_confirmations: u64,
}

struct ClientRegistry {
    clients: std::collections::HashMap<u64, PersistentClient>,
    next_id: u64,
}

static CLIENTS: LazyLock<Mutex<ClientRegistry>> = LazyLock::new(|| {
    Mutex::new(ClientRegistry {
        clients: std::collections::HashMap::new(),
        next_id: 1,
    })
});

/// Open a persistent client (handshakes once) and register it for
/// [`sync_with_json`]. Returns
/// `{"client_id":N,"tip_height":N,"handshakes":N}`.
pub fn open_json(config_json: &str) -> Result<Value, String> {
    let config: ScanConfigJson =
        serde_json::from_str(config_json).map_err(|e| format!("scan config JSON: {e}"))?;
    let network = Network::parse(&config.network).map_err(|e| e.to_string())?;
    let client = CbfClient::connect(&CbfConfig {
        network,
        peers: config.peers.clone(),
        cache_dir: config.cache_dir.clone().into(),
        timeout: std::time::Duration::from_millis(config.timeout_ms.unwrap_or(30_000)),
    })
    .map_err(|e| e.to_string())?;
    let entry = PersistentClient {
        from_height: config.from_height,
        required_confirmations: config.required_confirmations.unwrap_or(0),
        cache_dir: config.cache_dir,
        network,
        client,
    };
    let handshakes = entry.client.handshake_count();
    let tip = entry.client.tip_height();
    let mut registry = match CLIENTS.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    let client_id = registry.next_id;
    registry.next_id += 1;
    registry.clients.insert(client_id, entry);
    Ok(json!({
        "client_id": client_id,
        "tip_height": tip,
        "handshakes": handshakes,
    }))
}

/// Drop a persistent client. Returns `{"ok":true}`.
pub fn close_json(client_id: u64) -> Value {
    let mut registry = match CLIENTS.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    match registry.clients.remove(&client_id) {
        Some(_) => json!({ "ok": true }),
        None => json!({ "error": format!("unknown client id {client_id}") }),
    }
}

/// Sync with a persistent client opened by [`open_json`]: headers on
/// the existing connections (no re-handshake — the response's
/// `handshakes` counter does not move), then the scan index. Same
/// result shape as [`sync_json`], plus `handshakes`.
pub fn sync_with_json(client_id: u64) -> Result<Value, String> {
    let mut registry = match CLIENTS.lock() {
        Ok(registry) => registry,
        Err(poisoned) => poisoned.into_inner(),
    };
    let entry = registry
        .clients
        .get_mut(&client_id)
        .ok_or_else(|| format!("unknown client id {client_id}"))?;
    entry.client.sync().map_err(|e| e.to_string())?;
    let mut index = ScanIndex::open(
        std::path::Path::new(&entry.cache_dir).join("scan"),
        entry.network,
    )
    .map_err(|e| e.to_string())?;
    index
        .scan_sync(&mut entry.client, entry.from_height)
        .map_err(|e| e.to_string())?;
    let counters = index.counters();
    let tip = index.synced_tip();
    let anchors = index.occurrences().len();
    let handshakes = entry.client.handshake_count();
    let network = entry.network;
    let cache_dir = entry.cache_dir.clone();
    let required_confirmations = entry.required_confirmations;
    drop(registry);
    let mut registration = match LAST_SCAN.lock() {
        Ok(registration) => registration,
        Err(poisoned) => poisoned.into_inner(),
    };
    *registration = Some(ScanRegistration {
        network,
        cache_dir,
        required_confirmations,
    });
    Ok(json!({
        "tip_height": tip,
        "filters_bytes": counters.filters_bytes,
        "blocks_bytes": counters.blocks_bytes,
        "anchors": anchors,
        "handshakes": handshakes,
    }))
}

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

/// Look up the first confirmed occurrence of one private raw nullifier in
/// the registered, PoW-verified compact-filter index. The caller also gets
/// the index tip so it can reject a rollback check performed against a scan
/// older than its independently verified Bitcoin funding view.
pub(crate) fn registered_nullifier_occurrence(
    raw_nf: &Digest,
) -> Result<(u64, Option<opencsv_core::chain::AnchorLocation>), String> {
    let index = registered_index()?;
    let tip = index.synced_tip();
    let occurrence = index
        .scan_check(raw_nf, 0, tip)
        .map(|(location, _)| location);
    Ok((tip, occurrence))
}

/// Confirmation evidence for one exact transaction in the registered,
/// PoW-verified compact-filter index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegisteredTxidConfirmation {
    pub location: opencsv_core::chain::AnchorLocation,
    pub confirmations: u64,
    pub required_confirmations: u64,
    pub tip_height: u64,
}

impl RegisteredTxidConfirmation {
    /// Require both the account's crediting depth and the policy registered
    /// with the canonical scan before treating this transaction as final.
    pub(crate) fn satisfies_depth(self, account_required_confirmations: u32) -> bool {
        self.confirmations
            >= u64::from(account_required_confirmations).max(self.required_confirmations)
    }
}

fn canonical_confirmations(tip_height: u64, occurrence_height: u64) -> u64 {
    tip_height
        .checked_sub(occurrence_height)
        .and_then(|depth| depth.checked_add(1))
        .unwrap_or(0)
}

/// Look up an exact transaction in the registered canonical scan view. This
/// is deliberately local-only: accelerator status can decide when a caller
/// should consult the index, but cannot manufacture this evidence.
pub(crate) fn registered_txid_confirmation(
    txid: &[u8; 32],
) -> Result<Option<RegisteredTxidConfirmation>, String> {
    let index = registered_index()?;
    let tip_height = index.synced_tip();
    let Some(location) = index
        .occurrences()
        .iter()
        .filter(|entry| &entry.txid == txid)
        .map(|entry| entry.location)
        .min()
    else {
        return Ok(None);
    };
    Ok(Some(RegisteredTxidConfirmation {
        location,
        confirmations: canonical_confirmations(tip_height, location.height),
        required_confirmations: registered_required_confirmations(),
        tip_height,
    }))
}

#[cfg(test)]
pub(crate) fn install_test_scan(
    cache_dir: &std::path::Path,
    tip_height: u64,
    required_confirmations: u64,
    occurrences: &[opencsv_cbf::ScannedAnchor],
) -> Result<(), String> {
    use sha2::Digest as _;

    let from_height = occurrences
        .iter()
        .map(|entry| entry.location.height)
        .min()
        .unwrap_or(1)
        .min(tip_height.max(1));
    let mut body = format!(
        "opencsv-cbf-scan-index-v3\nnetwork signet\nfrom {from_height}\ntip {tip_height}\n"
    );
    for height in from_height..=tip_height {
        let mut hash = sha2::Sha256::digest(height.to_le_bytes()).to_vec();
        hash.reverse();
        body.push_str(&format!("block {height} {}\n", to_hex(&hash)));
    }
    let mut occurrences = occurrences.to_vec();
    occurrences.sort_by_key(|entry| entry.location);
    for entry in occurrences {
        let mut txid = entry.txid;
        txid.reverse();
        body.push_str(&format!(
            "occurrence {} {} {} {} {}",
            entry.location.height,
            entry.location.position,
            to_hex(&txid),
            to_hex(&entry.ctx),
            to_hex(&entry.record.to_bytes()),
        ));
        if let Some(batch) = entry.batch {
            let kind = match batch.version {
                opencsv_core::BatchVersion::V1 => "batch1",
                opencsv_core::BatchVersion::V2 => "batch2",
            };
            let envelope = batch
                .envelope
                .iter()
                .flat_map(|payload| *payload.as_bytes())
                .collect::<Vec<_>>();
            body.push_str(&format!(" {kind} {} {}", batch.index, to_hex(&envelope)));
        }
        body.push('\n');
    }
    let checksum = sha2::Sha256::digest(body.as_bytes());
    let scan_dir = cache_dir.join("scan");
    std::fs::create_dir_all(&scan_dir).map_err(|error| error.to_string())?;
    std::fs::write(
        scan_dir.join("scan-index.log"),
        format!("{body}checksum {}\n", to_hex(&checksum)),
    )
    .map_err(|error| error.to_string())?;
    let mut registration = match LAST_SCAN.lock() {
        Ok(registration) => registration,
        Err(poisoned) => poisoned.into_inner(),
    };
    *registration = Some(ScanRegistration {
        network: Network::Signet,
        cache_dir: cache_dir.display().to_string(),
        required_confirmations,
    });
    Ok(())
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

/// Export the registered scan index as an **anchor-snapshot JSON** in
/// exactly the shape `opencsv_verify_consignment` consumes (see
/// [`crate::snapshot`]): `{"tip_height":N,"entries":[{height,position,
/// txid,ctx,record}]}`, `tip_height` being the scan's synced tip at call
/// time (so confirmation counting in the crediting verify agrees with
/// the scan's own view). This is the serverless crediting path: the
/// index SPV-fetched full blocks, so every entry's record, txid, ctx,
/// and location is PoW-verified already. Local-only — no network.
///
/// Batch anchors contribute one snapshot entry per *transaction*
/// (deduplicated by `(location, txid)`) plus the exact versioned witness
/// envelope read from the independently fetched full block. The account
/// verifier needs that authenticated envelope to project the selected member
/// into the single-XFER statement its proof was authored against.
pub fn export_snapshot_json() -> Result<Value, String> {
    let index = registered_index()?;
    let entries = snapshot_entries(index.occurrences());
    Ok(json!({
        "tip_height": index.synced_tip(),
        "entries": entries,
    }))
}

fn snapshot_entries(occurrences: &[opencsv_cbf::ScannedAnchor]) -> Vec<Value> {
    let mut seen = std::collections::BTreeSet::new();
    let mut entries = Vec::new();
    for e in occurrences {
        if seen.insert((e.location, e.txid)) {
            let mut entry = json!({
                "height": e.location.height,
                "position": e.location.position,
                "txid": to_hex(&e.txid),
                "ctx": to_hex(&e.ctx),
                "record": to_hex(&e.record.to_bytes()),
            });
            if let Some(batch) = &e.batch {
                let version = match batch.version {
                    opencsv_core::BatchVersion::V1 => 1,
                    opencsv_core::BatchVersion::V2 => 2,
                };
                entry["batch"] = json!({
                    "version": version,
                    "payloads": batch.envelope.iter()
                        .map(|payload| to_hex(payload.as_bytes()))
                        .collect::<Vec<_>>(),
                });
            }
            entries.push(entry);
        }
    }
    entries.sort_by_key(|e| (e["height"].as_u64(), e["position"].as_u64()));
    entries
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
    if !raw_nf.is_canonical() {
        return Err("raw nullifier is not a canonical digest encoding".to_string());
    }
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

/// Verify against public recipient identities authenticated by a durable
/// sender/issuer operation. This never credits the calling wallet and does
/// not imply possession of a recipient secret.
pub(crate) fn verify_json_for_public_owners<V: ProofVerifier>(
    consignment_hex: &str,
    recipient_owners: &[Owner],
    known_assets: &[AssetId],
    verifier: &V,
) -> Result<Value, String> {
    let blob = from_hex(consignment_hex)?;
    let consignment = Consignment::from_bytes(&blob).map_err(|e| e.to_string())?;
    let index = registered_index()?;
    let accepted = opencsv_core::accept_for_public_owners(
        &consignment,
        &index,
        verifier,
        &PublicOwnerAcceptParams {
            vk: COIN_VK,
            required_confirmations: registered_required_confirmations(),
            recipient_owners,
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
            "ownership_source": "authenticated_public_operation",
        })),
        Err(reason) => Ok(json!({
            "status": "rejected",
            "reason": format!("{reason:?}"),
            "tip_height": tip,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opencsv_cbf::fullscan::BatchCandidate;
    use opencsv_cbf::ScannedAnchor;
    use opencsv_core::chain::AnchorLocation;
    use opencsv_core::{binding, AnchorRecord, BatchVersion, Digest};

    #[test]
    fn registered_txid_depth_requires_the_stricter_policy() {
        let shallow = RegisteredTxidConfirmation {
            location: AnchorLocation {
                height: 100,
                position: 2,
            },
            confirmations: canonical_confirmations(100, 100),
            required_confirmations: 6,
            tip_height: 100,
        };
        assert_eq!(shallow.confirmations, 1);
        assert!(!shallow.satisfies_depth(1));

        let deep = RegisteredTxidConfirmation {
            confirmations: canonical_confirmations(105, 100),
            tip_height: 105,
            ..shallow
        };
        assert_eq!(deep.confirmations, 6);
        assert!(deep.satisfies_depth(1));

        let account_stricter = RegisteredTxidConfirmation {
            required_confirmations: 1,
            ..deep
        };
        assert!(!account_stricter.satisfies_depth(7));
    }

    #[test]
    fn exported_scan_snapshot_retains_one_exact_batch_envelope() {
        let ctx = [41_u8; 32];
        let payloads = vec![
            binding(&Digest::from_bytes([42_u8; 32]), &ctx).to_anchor(),
            binding(&Digest::from_bytes([43_u8; 32]), &ctx).to_anchor(),
        ];
        let record = AnchorRecord::batch_header_v2(&payloads, &ctx);
        let location = AnchorLocation {
            height: 44,
            position: 45,
        };
        let txid = [46_u8; 32];
        let occurrences = (0..2)
            .map(|index| ScannedAnchor {
                location,
                txid,
                record,
                ctx,
                batch: Some(BatchCandidate {
                    version: BatchVersion::V2,
                    index,
                    envelope: payloads.clone(),
                }),
            })
            .collect::<Vec<_>>();

        let exported = snapshot_entries(&occurrences);

        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0]["batch"]["version"], 2);
        assert_eq!(
            exported[0]["batch"]["payloads"],
            json!(payloads
                .iter()
                .map(|payload| to_hex(payload.as_bytes()))
                .collect::<Vec<_>>()),
        );
    }
}
