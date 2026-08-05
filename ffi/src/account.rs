//! Signal-native account wallet.
//!
//! This is the durable boundary that combines a BIP84 Bitcoin fee wallet,
//! the OpenCSV owner/issuer identities, and an operation journal. The host
//! supplies one random 32-byte account root for a primary device; Rust is
//! the only component that derives wallet keys from it. Linked devices open
//! with public descriptors and never receive signing material.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::bitcoin::bip32::Xpriv;
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bdk_wallet::bitcoin::hashes::{sha256, Hash as _};
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::{
    Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, Transaction, Txid,
};
use bdk_wallet::chain::{ChainPosition, Merge};
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{
    ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxOrdering, Wallet, WalletPersister,
};
use hkdf::Hkdf;
use opencsv_bitcoin::{
    funding_ctx, relay_transaction, validate_solo_anchor_replacement, Network as OpenCsvNetwork,
    MARKER_DUST_SATS, MARKER_SPK, MEMPOOL_LOCATION,
};
use opencsv_cbf::block::OutPoint as CbfOutPoint;
use opencsv_cbf::{CbfClient, Config as CbfConfig, OutpointVerdict};
use opencsv_core::chain::AnchorRef;
use opencsv_core::consignment::Consignment;
#[cfg(any(test, feature = "issuer-tools"))]
use opencsv_core::{AssetGenesis, InstrumentTermsV1, PoseidonIssuerAuthorization};
use opencsv_core::{AssetId, InstrumentManifestV1, OwnerSecret};
use rand::RngExt as _;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::wallet::MemWallet;
use crate::{
    crosscheck, scan,
    snapshot::{Snapshot, SnapshotChain, SnapshotEntry},
};

const SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_VERSION: u32 = 1;
const DEFAULT_STOP_GAP: usize = 20;
const DEFAULT_PARALLEL_REQUESTS: usize = 4;
const DEFAULT_VERIFICATION_TIMEOUT_SECS: u64 = 8;
const DEFAULT_MAX_VERIFICATION_BLOCKS: u64 = 10_000;
const MIN_FEE_RESERVE_SATS: u64 = 2_500;

/// Stable account-wallet failure crossing the JSON/FFI boundary.
#[derive(Debug)]
pub struct AccountError {
    /// Stable machine-readable reason.
    pub code: &'static str,
    /// Human-readable detail, not intended for branching.
    pub message: String,
}

impl AccountError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// JSON object returned by the C ABI.
    pub fn json(&self) -> Value {
        json!({ "error": self.message, "reason": self.code })
    }
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AccountError {}

impl From<rusqlite::Error> for AccountError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new("database_error", error.to_string())
    }
}

/// Primary devices hold derived private keys; linked devices are watch-only.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccountRole {
    /// Primary Signal phone, permitted to sign when backup policy allows it.
    Primary,
    /// Linked Signal device, public descriptors only.
    Linked,
}

fn default_role() -> AccountRole {
    AccountRole::Primary
}

fn default_confirmations() -> u32 {
    1
}

fn default_stop_gap() -> usize {
    DEFAULT_STOP_GAP
}

fn default_parallel_requests() -> usize {
    DEFAULT_PARALLEL_REQUESTS
}

fn default_verification_timeout_secs() -> u64 {
    DEFAULT_VERIFICATION_TIMEOUT_SECS
}

fn default_max_verification_blocks() -> u64 {
    DEFAULT_MAX_VERIFICATION_BLOCKS
}

/// Enforcement mode for one independently identified network check.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationMode {
    /// Do not perform or require this check.
    Off,
    /// Record evidence and failures without gating spendability.
    Observe,
    /// Fail closed unless valid, exact evidence is supplied.
    Require,
}

/// Stable kind of network observation. Cryptographic and transaction-layout
/// checks are intentionally not represented here because they are mandatory
/// protocol invariants and can never be disabled by configuration.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    /// Esplora-compatible raw transaction lookup.
    RawTransactionApi,
    /// Complete write of the persisted transaction to a Bitcoin peer.
    DirectP2pRelay,
    /// Experimental mempool-possession probe; disabled by default.
    ExperimentalP2pPossession,
    /// Multi-peer headers, PoW, BIP158, block, and Merkle verification.
    ConfirmedSpv,
}

/// One configurable observation policy row.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObservationCheck {
    /// Stable receipt identifier.
    pub id: String,
    /// Network mechanism used by this check.
    pub kind: ObservationKind,
    /// Immutable built-in API endpoint, or a custom endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Off, Observe, or Require.
    pub mode: ObservationMode,
    /// Built-in or user-defined certificate-chain pin profile.
    #[serde(default)]
    pub pin_profile: Option<String>,
    /// User-supplied SHA-256 DER certificate fingerprints for custom required
    /// observers. Built-in profiles are compiled into Signal instead.
    #[serde(default)]
    pub chain_fingerprints_sha256: Vec<String>,
    /// Maximum age of cached evidence when this check gates acceptance.
    #[serde(default = "default_observation_max_age_seconds")]
    pub max_age_seconds: u64,
}

fn default_observation_max_age_seconds() -> u64 {
    120
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ObservationResult {
    Observed,
    Submitted,
    Unavailable,
    Error,
    NotChecked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationEvidence {
    check_id: String,
    #[serde(default)]
    endpoint: Option<String>,
    result: ObservationResult,
    started_at_ms: i64,
    completed_at_ms: i64,
    cached_at_ms: i64,
    #[serde(default)]
    certificate_profile: Option<String>,
    #[serde(default)]
    certificate_chain_fingerprints_sha256: Vec<String>,
    #[serde(default)]
    raw_transaction_hex: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationEvidenceEnvelope {
    observations: Vec<ObservationEvidence>,
}

/// One exact issuer-specific USD instrument trusted by the Signal product.
/// Trust comes from the reviewed app configuration, never from the `USD`
/// display code alone.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsdIssuerPolicy {
    /// Full terms/genesis manifest whose asset id is admitted as USD.
    pub manifest: InstrumentManifestV1,
    /// Lower values are preferred when one issuer balance can cover a send.
    #[serde(default)]
    pub priority: u32,
}

/// Account configuration supplied by Signal. It contains no secret key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Schema version, currently one.
    #[serde(default = "schema_version")]
    pub version: u32,
    /// `mainnet`, `signet`, or `regtest`.
    pub network: String,
    /// Esplora endpoint used as a read accelerator and generic relay fallback.
    pub esplora_url: String,
    /// P2P peers used for direct transaction relay.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Compact-filter peers used for authoritative fee-outpoint validation.
    /// If empty, the direct-relay peer set is used.
    #[serde(default)]
    pub verification_peers: Vec<String>,
    /// Connect/read timeout for authoritative peer operations.
    #[serde(default = "default_verification_timeout_secs")]
    pub verification_timeout_secs: u64,
    /// Maximum blocks scanned while proving one selected outpoint unspent.
    #[serde(default = "default_max_verification_blocks")]
    pub max_verification_blocks: u64,
    /// Primary or linked-device role.
    #[serde(default = "default_role")]
    pub role: AccountRole,
    /// Initial Secure Backup state. Later changes use the explicit setter.
    #[serde(default)]
    pub backup_verified: bool,
    /// Public binding commitment carried beside the account root and in the
    /// Secure Backup checkpoint. It is mandatory on clean-database recovery.
    #[serde(default)]
    pub expected_device_binding_commitment: Option<String>,
    /// Required confirmations for protocol crediting.
    #[serde(default = "default_confirmations")]
    pub required_confirmations: u32,
    /// Address-discovery gap for full Esplora scans.
    #[serde(default = "default_stop_gap")]
    pub stop_gap: usize,
    /// Maximum parallel Esplora requests.
    #[serde(default = "default_parallel_requests")]
    pub parallel_requests: usize,
    /// Independently configurable network observations. An omitted list gets
    /// fail-closed signet defaults for the two built-in API observers.
    #[serde(default)]
    pub observation_checks: Vec<ObservationCheck>,
    /// Required for linked devices; public external descriptor.
    #[serde(default)]
    pub watch_external_descriptor: Option<String>,
    /// Required for linked devices; public change descriptor.
    #[serde(default)]
    pub watch_internal_descriptor: Option<String>,
    /// Public OpenCSV owner identity supplied to linked devices.
    #[serde(default)]
    pub watch_owner: Option<String>,
    /// Reviewed issuer-specific instruments grouped under Signal's one USD
    /// product. This list contains public manifests only, never issuer keys.
    #[serde(default)]
    pub usd_issuers: Vec<UsdIssuerPolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupCheckpointEnvelope {
    checkpoint: BackupCheckpointPayload,
    checkpoint_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupCheckpointPayload {
    version: u32,
    network: String,
    root_fingerprint: String,
    device_binding_commitment: Option<String>,
    owners: Vec<String>,
    assets: Vec<BackupAsset>,
    #[serde(default)]
    instrument_manifests: Vec<InstrumentManifestV1>,
    operations: Vec<BackupOperation>,
    consignments: Vec<BackupConsignment>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupAsset {
    asset_index: u32,
    currency: String,
    terms_hash: String,
    nonce: u64,
    asset_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupOperation {
    operation_id: String,
    kind: String,
    state: String,
    request: Value,
    pending_json: Option<String>,
    delivery_nonce: String,
    txid: Option<String>,
    #[serde(default)]
    receipt_json: Option<String>,
    #[serde(default)]
    rejection_reason: Option<String>,
    #[serde(default)]
    checkpoint_hash: Option<String>,
    #[serde(default)]
    backup_acked: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupConsignment {
    consignment_id: String,
    consignment_base64: String,
    spent_state: Value,
    snapshot: Option<Value>,
    #[serde(default)]
    finality: Option<String>,
    #[serde(default)]
    anchor_txid: Option<String>,
}

#[derive(Clone, Debug)]
struct FundingVerificationRequest {
    outpoint: OutPoint,
    txout: bdk_wallet::bitcoin::TxOut,
    birth_height: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct FundingVerificationReceipt {
    creation_height: u64,
    checked_through: u64,
    matched_blocks: u64,
    verified_at: i64,
    source: &'static str,
}

trait FundingVerifier: Send + Sync {
    fn verify(
        &self,
        request: &FundingVerificationRequest,
    ) -> Result<FundingVerificationReceipt, AccountError>;
}

struct CbfFundingVerifier {
    network: String,
    peers: Vec<String>,
    cache_dir: PathBuf,
    timeout: Duration,
    max_blocks: u64,
}

impl FundingVerifier for CbfFundingVerifier {
    fn verify(
        &self,
        request: &FundingVerificationRequest,
    ) -> Result<FundingVerificationReceipt, AccountError> {
        let network = parse_cbf_network(&self.network)?;
        if self.peers.is_empty() || self.timeout.is_zero() || self.max_blocks == 0 {
            return Err(AccountError::new(
                "stale_chain_state",
                "authoritative fee-outpoint verifier is not configured",
            ));
        }
        if network != OpenCsvNetwork::Regtest && self.peers.len() < 2 {
            return Err(AccountError::new(
                "stale_chain_state",
                "signet/mainnet fee validation requires at least two compact-filter peers",
            ));
        }
        let config = CbfConfig {
            network,
            peers: self.peers.clone(),
            cache_dir: self.cache_dir.clone(),
            timeout: self.timeout,
        };
        let mut client = CbfClient::connect(&config).map_err(|error| {
            AccountError::new(
                "stale_chain_state",
                format!("authoritative fee-outpoint sync: {error}"),
            )
        })?;
        let verdict = client
            .verify_outpoint_unspent(
                CbfOutPoint {
                    txid: request.outpoint.txid.to_byte_array(),
                    vout: request.outpoint.vout,
                },
                request.txout.value.to_sat(),
                request.txout.script_pubkey.as_bytes(),
                request.birth_height,
                self.max_blocks,
            )
            .map_err(|error| {
                AccountError::new(
                    "stale_chain_state",
                    format!("authoritative fee-outpoint check: {error}"),
                )
            })?;
        match verdict {
            OutpointVerdict::Unspent {
                creation_height,
                checked_through,
                matched_blocks,
            } => Ok(FundingVerificationReceipt {
                creation_height,
                checked_through,
                matched_blocks,
                verified_at: unix_time()?,
                source: "headers+bip158+verified-blocks",
            }),
            OutpointVerdict::Spent {
                spend_height,
                spending_txid,
                ..
            } => Err(AccountError::new(
                "conflicting_operation",
                format!(
                    "reserved funding outpoint was spent at height {spend_height} by {}",
                    hex_encode(&spending_txid)
                ),
            )),
            OutpointVerdict::NotFound {
                checked_from,
                checked_through,
            } => Err(AccountError::new(
                "stale_chain_state",
                format!(
                    "reserved funding outpoint was not found in verified blocks {checked_from}..={checked_through}"
                ),
            )),
            OutpointVerdict::OutputMismatch { creation_height } => Err(AccountError::new(
                "stale_chain_state",
                format!(
                    "reserved funding value/script disagrees with verified block {creation_height}"
                ),
            )),
        }
    }
}

/// Stable durable operation states.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Request journaled, no fee input selected.
    Planned,
    /// Bitcoin fee input selected and durably locked.
    FeeReserved,
    /// OpenCSV proof and pending export durably stored.
    ProofReady,
    /// Fully signed transaction persisted before any network write.
    SignedPersisted,
    /// Submitted to at least one relay but not yet observed back.
    BroadcastUnobserved,
    /// Submitted and observed through an independent read path.
    Broadcast,
    /// Present in a mempool and safe for consignment delivery.
    Mempool,
    /// Confirmed in a block.
    Confirmed,
    /// Signal attachment delivery completed.
    ConsignmentDelivered,
    /// Bitcoin transaction exists, but the OpenCSV transition lost a
    /// confirmed first-occurrence conflict and must never be resumed.
    ProtocolRejected,
    /// Cancelled before broadcast.
    Cancelled,
}

impl OperationState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::FeeReserved => "fee_reserved",
            Self::ProofReady => "proof_ready",
            Self::SignedPersisted => "signed_persisted",
            Self::BroadcastUnobserved => "broadcast_unobserved",
            Self::Broadcast => "broadcast",
            Self::Mempool => "mempool",
            Self::Confirmed => "confirmed",
            Self::ConsignmentDelivered => "consignment_delivered",
            Self::ProtocolRejected => "protocol_rejected",
            Self::Cancelled => "cancelled",
        }
    }
}

#[cfg(any(test, feature = "issuer-tools"))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuanceRequest {
    asset_id: String,
    #[serde(default)]
    to_owner: Option<String>,
    amounts: Vec<u64>,
}

#[cfg(any(test, feature = "issuer-tools"))]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstrumentCreateRequest {
    terms: InstrumentTermsV1,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransferRequest {
    asset_id: String,
    to_owner: String,
    amount: u64,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FeePolicy {
    target_sat_per_vb: u64,
    #[serde(default)]
    max_fee_sats: Option<u64>,
}

#[derive(Debug)]
struct OperationRow {
    operation_id: String,
    kind: String,
    state: String,
    request_json: String,
    funding_txid: Option<String>,
    funding_vout: Option<u32>,
    signed_tx_hex: Option<String>,
    txid: Option<String>,
    receipt_json: Option<String>,
    rejection_reason: Option<String>,
    delivery_nonce: String,
    checkpoint_hash: Option<String>,
    backup_acked: bool,
}

const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

/// SQLite-backed append-only BDK changeset store.
///
/// BDK 3.1's optional SQLite adapter depends on rusqlite 0.31, while
/// Signal's store already links rusqlite/libsqlite3-sys 0.38. Cargo cannot
/// link two SQLite `links` packages into the same app. BDK's public
/// `WalletPersister` contract and serializable `ChangeSet` make this small
/// adapter both supported and version-explicit without introducing a second
/// SQLite runtime.
pub struct SqlitePersister {
    conn: Connection,
}

impl SqlitePersister {
    fn open(path: &Path) -> Result<Self, AccountError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AccountError::new(
                    "database_error",
                    format!("create {}: {error}", parent.display()),
                )
            })?;
        }
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        let mut db = Self { conn };
        db.initialize_account_schema()?;
        Ok(db)
    }

    fn initialize_account_schema(&mut self) -> Result<(), AccountError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS opencsv_bdk_changes (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 changeset_json TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_account_meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_assets (
                 asset_index INTEGER PRIMARY KEY,
                 currency TEXT NOT NULL,
                 terms_hash TEXT NOT NULL,
                 nonce INTEGER NOT NULL,
                 asset_id TEXT NOT NULL UNIQUE
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_instrument_manifests (
                 asset_id TEXT PRIMARY KEY,
                 manifest_json TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 FOREIGN KEY(asset_id) REFERENCES opencsv_assets(asset_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_operations (
                 operation_id TEXT PRIMARY KEY,
                 kind TEXT NOT NULL,
                 state TEXT NOT NULL,
                 request_json TEXT NOT NULL,
                 funding_txid TEXT,
                 funding_vout INTEGER,
                 funding_value_sats INTEGER,
                 pending_json TEXT,
                 psbt_base64 TEXT,
                 signed_tx_hex TEXT,
                 txid TEXT,
                 receipt_json TEXT,
                 rejection_reason TEXT,
                 delivery_nonce TEXT NOT NULL,
                 checkpoint_hash TEXT,
                 backup_acked INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_consignments (
                 consignment_id TEXT PRIMARY KEY,
                 consignment_base64 TEXT NOT NULL,
                 spent_state_json TEXT NOT NULL,
                 created_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_consignment_snapshots (
                 consignment_id TEXT PRIMARY KEY,
                 snapshot_json TEXT NOT NULL,
                 FOREIGN KEY(consignment_id) REFERENCES opencsv_consignments(consignment_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_consignment_finality (
                 consignment_id TEXT PRIMARY KEY,
                 anchor_txid TEXT NOT NULL,
                 finality TEXT NOT NULL CHECK(finality IN ('unconfirmed', 'settled', 'frozen')),
                 observed_at INTEGER NOT NULL,
                 last_checked_at INTEGER NOT NULL,
                 last_error TEXT,
                 FOREIGN KEY(consignment_id) REFERENCES opencsv_consignments(consignment_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_utxo_reservations (
                 txid TEXT NOT NULL,
                 vout INTEGER NOT NULL,
                 operation_id TEXT NOT NULL UNIQUE,
                 state TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(txid, vout),
                 FOREIGN KEY(operation_id) REFERENCES opencsv_operations(operation_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_observation_receipts (
                 subject_txid TEXT NOT NULL,
                 check_id TEXT NOT NULL,
                 receipt_json TEXT NOT NULL,
                 observed_at INTEGER NOT NULL,
                 PRIMARY KEY(subject_txid, check_id)
             ) STRICT;",
        )?;
        Ok(())
    }

    fn meta(&self, key: &str) -> Result<Option<String>, AccountError> {
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM opencsv_account_meta WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn set_meta(&self, key: &str, value: &str) -> Result<(), AccountError> {
        self.conn.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    fn delete_meta(&self, key: &str) -> Result<(), AccountError> {
        self.conn
            .execute("DELETE FROM opencsv_account_meta WHERE key = ?1", [key])?;
        Ok(())
    }
}

impl WalletPersister for SqlitePersister {
    type Error = AccountError;

    fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
        persister.initialize_account_schema()?;
        let mut aggregate = ChangeSet::default();
        let mut statement = persister
            .conn
            .prepare("SELECT changeset_json FROM opencsv_bdk_changes ORDER BY sequence ASC")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        for row in rows {
            let encoded = row?;
            let changeset: ChangeSet = serde_json::from_str(&encoded).map_err(|error| {
                AccountError::new("database_corrupt", format!("BDK changeset: {error}"))
            })?;
            aggregate.merge(changeset);
        }
        Ok(aggregate)
    }

    fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
        let encoded = serde_json::to_string(changeset).map_err(|error| {
            AccountError::new("database_error", format!("encode BDK changeset: {error}"))
        })?;
        persister.conn.execute(
            "INSERT INTO opencsv_bdk_changes(changeset_json) VALUES(?1)",
            [encoded],
        )?;
        Ok(())
    }
}

/// An open Signal account wallet.
pub struct AccountWallet {
    config: AccountConfig,
    funding_verifier: Arc<dyn FundingVerifier>,
    bitcoin: PersistedWallet<SqlitePersister>,
    db: SqlitePersister,
    protocol: Option<MemWallet>,
    #[cfg(any(test, feature = "issuer-tools"))]
    issuer_root: Option<Zeroizing<[u8; 32]>>,
    root_fingerprint: String,
    #[cfg(feature = "test-wallet-recovery")]
    account_root_for_test_rebind: Option<Zeroizing<[u8; 32]>>,
    device_binding_commitment: Option<String>,
    device_binding_valid: bool,
    pending_by_operation: HashMap<String, u64>,
}

/// Result of the short, locked phase that snapshots a durable proof job.
pub(crate) enum ProofJobStart {
    /// The operation was already proof-ready.
    Ready(Value),
    /// Expensive verification/proving must run outside the account lock.
    Run(Box<AccountProofJob>),
}

/// Immutable inputs for one proof job. It owns a cloned protocol snapshot so
/// recursive proving never holds the account registry or live-wallet lock.
pub(crate) struct AccountProofJob {
    operation_id: String,
    request: TransferRequest,
    funding: ReservedFunding,
    verifier: Arc<dyn FundingVerifier>,
    protocol_snapshot: MemWallet,
    esplora_url: String,
}

pub(crate) struct CompletedProofJob {
    operation_id: String,
    request: TransferRequest,
    funding: ReservedFunding,
    verification: FundingVerificationReceipt,
    pending_json: String,
    record: [u8; 64],
    unconfirmed_dependencies: Vec<String>,
}

impl AccountProofJob {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn run(mut self) -> Result<CompletedProofJob, AccountError> {
        let verification = self.verifier.verify(&FundingVerificationRequest {
            outpoint: self.funding.outpoint,
            txout: self.funding.txout.clone(),
            birth_height: self.funding.birth_height,
        })?;
        let ctx = funding_context(self.funding.outpoint);
        let proved = self
            .protocol_snapshot
            .prove_transfer_amount(
                &self.request.asset_id,
                &self.request.to_owner,
                self.request.amount,
            )
            .map_err(|error| AccountError::new("unavailable_assets", error))?;

        if !proved.unconfirmed_dependencies.is_empty() {
            let client = esplora_client::Builder::new(&self.esplora_url).build_blocking();
            for dependency in &proved.unconfirmed_dependencies {
                let txid = dependency.parse::<Txid>().map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("invalid unconfirmed dependency {dependency}: {error}"),
                    )
                })?;
                match client.get_tx(&txid).map_err(|error| {
                    AccountError::new(
                        "unconfirmed_dependency_unavailable",
                        format!("could not re-observe parent {dependency}: {error}"),
                    )
                })? {
                    Some(transaction) if transaction.compute_txid() == txid => {}
                    _ => {
                        return Err(AccountError::new(
                            "unconfirmed_dependency_changed",
                            format!("zero-confirmation parent {dependency} disappeared or changed"),
                        ));
                    }
                }
            }
        }
        let record = self
            .protocol_snapshot
            .rebind_pending(proved.pending_id, ctx)
            .map_err(|error| AccountError::new("protocol_layout_violation", error))?;
        let pending_json = self
            .protocol_snapshot
            .export_pending(proved.pending_id)
            .map_err(|error| AccountError::new("database_error", error))?;
        Ok(CompletedProofJob {
            operation_id: self.operation_id,
            request: self.request,
            funding: self.funding,
            verification,
            pending_json,
            record,
            unconfirmed_dependencies: proved.unconfirmed_dependencies,
        })
    }
}

impl AccountWallet {
    /// Open or initialize an account database.
    pub fn open_device_bound(
        config_json: &str,
        account_key: &[u8],
        device_binding_key: &[u8],
        database_path: &str,
    ) -> Result<Self, AccountError> {
        let mut config: AccountConfig = serde_json::from_str(config_json).map_err(|error| {
            AccountError::new("invalid_config", format!("config JSON: {error}"))
        })?;
        if config.version != SCHEMA_VERSION {
            return Err(AccountError::new(
                "unsupported_version",
                format!("account config version {}", config.version),
            ));
        }
        let network = parse_network(&config.network)?;
        validate_esplora_url(&config.esplora_url)?;
        if config.observation_checks.is_empty() {
            config.observation_checks = default_observation_checks(&config.network);
        }
        validate_observation_checks(&config)?;
        validate_usd_issuer_policy(&config)?;

        #[cfg(feature = "test-wallet-recovery")]
        let account_root_for_test_rebind = match config.role {
            AccountRole::Primary => Some(Zeroizing::new(account_key.try_into().map_err(|_| {
                AccountError::new(
                    "invalid_account_key",
                    "account key must be exactly 32 bytes",
                )
            })?)),
            AccountRole::Linked => None,
        };

        let (
            external,
            internal,
            protocol,
            issuer_root,
            root_fingerprint,
            current_device_binding_commitment,
        ) = match config.role {
            AccountRole::Primary => {
                let root: Zeroizing<[u8; 32]> =
                    Zeroizing::new(account_key.try_into().map_err(|_| {
                        AccountError::new(
                            "invalid_account_key",
                            "account key must be exactly 32 bytes",
                        )
                    })?);
                let bitcoin_seed =
                    Zeroizing::new(derive::<64>(root.as_ref(), b"bitcoin-fee-wallet-v1", &[])?);
                let owner_seed =
                    Zeroizing::new(derive::<32>(root.as_ref(), b"opencsv-owner-v1", &[])?);
                let issuer_root =
                    Zeroizing::new(derive::<32>(root.as_ref(), b"opencsv-issuer-root-v1", &[])?);
                let xpriv = Xpriv::new_master(network, bitcoin_seed.as_ref()).map_err(|error| {
                    AccountError::new("key_derivation_failed", error.to_string())
                })?;
                let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
                let external = format!("wpkh({xpriv}/84h/{coin_type}h/0h/0/*)");
                let internal = format!("wpkh({xpriv}/84h/{coin_type}h/0h/1/*)");
                let fingerprint = sha256::Hash::hash(
                    &[b"OpenCSV account fingerprint v1".as_slice(), root.as_ref()].concat(),
                )
                .to_string();
                let binding_commitment = if device_binding_key.is_empty() {
                    None
                } else {
                    let device_binding: Zeroizing<[u8; 32]> =
                        Zeroizing::new(device_binding_key.try_into().map_err(|_| {
                            AccountError::new(
                                "invalid_device_binding",
                                "primary device binding must be empty or exactly 32 bytes",
                            )
                        })?);
                    Some(
                        sha256::Hash::hash(
                            &[
                                b"OpenCSV device binding v1".as_slice(),
                                root.as_ref(),
                                device_binding.as_ref(),
                            ]
                            .concat(),
                        )
                        .to_string(),
                    )
                };
                (
                    external,
                    internal,
                    Some(MemWallet::from_owner_seed(*owner_seed)),
                    Some(issuer_root),
                    fingerprint,
                    binding_commitment,
                )
            }
            AccountRole::Linked => {
                if !account_key.is_empty() {
                    return Err(AccountError::new(
                        "linked_key_forbidden",
                        "linked devices must open without an account key",
                    ));
                }
                if !device_binding_key.is_empty() {
                    return Err(AccountError::new(
                        "linked_binding_forbidden",
                        "linked devices must open without a primary device binding",
                    ));
                }
                if config.expected_device_binding_commitment.is_some() {
                    return Err(AccountError::new(
                        "invalid_config",
                        "linked devices do not accept a primary binding commitment",
                    ));
                }
                let external = config.watch_external_descriptor.clone().ok_or_else(|| {
                    AccountError::new("invalid_config", "linked device needs external descriptor")
                })?;
                let internal = config.watch_internal_descriptor.clone().ok_or_else(|| {
                    AccountError::new("invalid_config", "linked device needs internal descriptor")
                })?;
                let fingerprint =
                    sha256::Hash::hash(&[external.as_bytes(), b"\0", internal.as_bytes()].concat())
                        .to_string();
                (external, internal, None, None, fingerprint, None)
            }
        };

        let mut db = SqlitePersister::open(Path::new(database_path))?;
        match db.meta("root_fingerprint")? {
            Some(existing) if existing != root_fingerprint => {
                return Err(AccountError::new(
                    "account_key_mismatch",
                    "database belongs to another account root or watch descriptor",
                ));
            }
            None => db.set_meta("root_fingerprint", &root_fingerprint)?,
            Some(_) => {}
        }
        match db.meta("network")? {
            Some(existing) if existing != config.network => {
                return Err(AccountError::new(
                    "network_mismatch",
                    format!("database is for {existing}, not {}", config.network),
                ));
            }
            None => db.set_meta("network", &config.network)?,
            Some(_) => {}
        }
        if db.meta("backup_verified")?.is_none() {
            db.set_meta(
                "backup_verified",
                if config.backup_verified { "1" } else { "0" },
            )?;
        }

        let (device_binding_commitment, device_binding_valid) = match config.role {
            AccountRole::Linked => (None, false),
            AccountRole::Primary => {
                if let Some(expected) = config.expected_device_binding_commitment.as_deref() {
                    validate_hex_32_config(expected, "expected device binding commitment")?;
                }
                let stored = db.meta("device_binding_commitment")?;
                let missing_binding_seen =
                    db.meta("device_binding_missing_seen")?.as_deref() == Some("1");
                if let (Some(stored), Some(expected)) = (
                    stored.as_deref(),
                    config.expected_device_binding_commitment.as_deref(),
                ) {
                    if stored != expected {
                        return Err(AccountError::new(
                            "account_binding_mismatch",
                            "database and recovery checkpoint name different device bindings",
                        ));
                    }
                }
                let authoritative = stored
                    .or_else(|| config.expected_device_binding_commitment.clone())
                    .or_else(|| {
                        if missing_binding_seen {
                            None
                        } else {
                            current_device_binding_commitment.clone()
                        }
                    });
                if current_device_binding_commitment.is_none() && !missing_binding_seen {
                    db.set_meta("device_binding_missing_seen", "1")?;
                }
                if db.meta("device_binding_commitment")?.is_none() {
                    if let Some(authoritative) = authoritative.as_deref() {
                        db.set_meta("device_binding_commitment", authoritative)?;
                    }
                }
                let valid = matches!(
                    (&current_device_binding_commitment, &authoritative),
                    (Some(current), Some(authoritative)) if current == authoritative
                );
                (authoritative, valid)
            }
        };

        let loaded = Wallet::load()
            .descriptor(KeychainKind::External, Some(external.clone()))
            .descriptor(KeychainKind::Internal, Some(internal.clone()))
            .extract_keys()
            .check_network(network)
            .load_wallet(&mut db)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let bitcoin = match loaded {
            Some(wallet) => wallet,
            None => Wallet::create(external, internal)
                .network(network)
                .create_wallet(&mut db)
                .map_err(|error| AccountError::new("wallet_create_failed", error.to_string()))?,
        };

        let verification_peers = if config.verification_peers.is_empty() {
            config.peers.clone()
        } else {
            config.verification_peers.clone()
        };
        let funding_verifier: Arc<dyn FundingVerifier> = Arc::new(CbfFundingVerifier {
            network: config.network.clone(),
            peers: verification_peers,
            cache_dir: PathBuf::from(format!("{database_path}.cbf")),
            timeout: Duration::from_secs(config.verification_timeout_secs),
            max_blocks: config.max_verification_blocks,
        });
        let mut account = Self {
            config,
            funding_verifier,
            bitcoin,
            db,
            protocol,
            #[cfg(any(test, feature = "issuer-tools"))]
            issuer_root,
            root_fingerprint,
            #[cfg(feature = "test-wallet-recovery")]
            account_root_for_test_rebind,
            device_binding_commitment,
            device_binding_valid,
            pending_by_operation: HashMap::new(),
        };
        #[cfg(not(any(test, feature = "issuer-tools")))]
        drop(issuer_root);
        #[cfg(any(test, feature = "issuer-tools"))]
        account.restore_issuers()?;
        account.restore_consignment_state()?;
        account.restore_finalized_operations()?;
        account.restore_fee_reservations()?;
        account.restore_pending_operations()?;
        Ok(account)
    }

    /// Commit a DEBUG-only signet/regtest device rebind after an exact Secure
    /// Backup checkpoint has been restored into a clean database.
    ///
    /// The database update is one SQLite transaction. Repeating the same
    /// request after a crash returns the same new checkpoint; presenting a
    /// different replacement binding is a hard conflict. The rebind itself
    /// clears `backup_verified`, so Bitcoin-writing operations stay frozen
    /// until Signal stores the newly returned checkpoint in a fresh backup.
    #[cfg(feature = "test-wallet-recovery")]
    pub fn rebind_test_device(&mut self, device_binding_key: &[u8]) -> Result<Value, AccountError> {
        if self.config.role != AccountRole::Primary {
            return Err(AccountError::new(
                "primary_required",
                "linked devices cannot be rebound",
            ));
        }
        if !matches!(self.config.network.as_str(), "signet" | "regtest") {
            return Err(AccountError::new(
                "test_rebind_network_forbidden",
                "test-device rebind is restricted to signet and regtest",
            ));
        }
        let binding: Zeroizing<[u8; 32]> =
            Zeroizing::new(device_binding_key.try_into().map_err(|_| {
                AccountError::new(
                    "invalid_device_binding",
                    "test device binding must be exactly 32 bytes",
                )
            })?);
        let root = self.account_root_for_test_rebind.as_ref().ok_or_else(|| {
            AccountError::new(
                "primary_required",
                "test rebind has no primary account root",
            )
        })?;
        let new_commitment = sha256::Hash::hash(
            &[
                b"OpenCSV device binding v1".as_slice(),
                root.as_ref(),
                binding.as_ref(),
            ]
            .concat(),
        )
        .to_string();

        if let Some(existing) = self.db.meta("test_rebind_new_commitment")? {
            if existing != new_commitment {
                return Err(AccountError::new(
                    "conflicting_test_rebind",
                    "this restored wallet was already rebound to another test device",
                ));
            }
            if self.write_enabled()? {
                return Err(AccountError::new(
                    "test_rebind_already_write_enabled",
                    "an existing write-enabled wallet cannot be rebound",
                ));
            }
            self.device_binding_commitment = Some(existing);
            self.device_binding_valid = true;
            let checkpoint = self.checkpoint()?;
            return Ok(json!({
                "status": "checkpoint_ready",
                "idempotent": true,
                "backup_required": !self.backup_verified()?,
                "write_enabled": self.write_enabled()?,
                "device_binding_commitment": self.device_binding_commitment,
                "checkpoint": checkpoint,
            }));
        }

        if self.write_enabled()? {
            return Err(AccountError::new(
                "test_rebind_already_write_enabled",
                "an existing write-enabled wallet cannot be rebound",
            ));
        }
        let restored_hash = self.db.meta("restored_checkpoint_hash")?.ok_or_else(|| {
            AccountError::new(
                "test_rebind_restore_required",
                "restore and validate a Secure Backup checkpoint before rebinding",
            )
        })?;
        let current_checkpoint = self.checkpoint()?;
        let current_hash = current_checkpoint["checkpoint_hash"]
            .as_str()
            .ok_or_else(|| AccountError::new("checkpoint_failed", "checkpoint has no hash"))?;
        if current_hash != restored_hash {
            return Err(AccountError::new(
                "test_rebind_checkpoint_modified",
                "wallet state changed after the restored checkpoint was validated",
            ));
        }
        let old_commitment = self.device_binding_commitment.clone().ok_or_else(|| {
            AccountError::new(
                "test_rebind_checkpoint_invalid",
                "restored checkpoint has no prior device-binding commitment",
            )
        })?;
        if self.device_binding_valid {
            return Err(AccountError::new(
                "test_rebind_existing_binding",
                "wallet is already bound to the current test device",
            ));
        }

        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('test_rebind_old_commitment', ?1)",
            [&old_commitment],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('test_rebind_source_checkpoint_hash', ?1)",
            [&restored_hash],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('test_rebind_new_commitment', ?1)",
            [&new_commitment],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('device_binding_commitment', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&new_commitment],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('device_binding_missing_seen', '0')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('backup_verified', '0')
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value) VALUES('test_rebind_state', 'checkpoint_ready')",
            [],
        )?;
        transaction.commit()?;

        self.device_binding_commitment = Some(new_commitment.clone());
        self.device_binding_valid = true;
        let checkpoint = self.checkpoint()?;
        Ok(json!({
            "status": "checkpoint_ready",
            "idempotent": false,
            "backup_required": true,
            "write_enabled": false,
            "device_binding_commitment": new_commitment,
            "checkpoint": checkpoint,
        }))
    }

    #[cfg(test)]
    fn open(
        config_json: &str,
        account_key: &[u8],
        database_path: &str,
    ) -> Result<Self, AccountError> {
        const TEST_DEVICE_BINDING: [u8; 32] = [0xa5; 32];
        let binding = if account_key.is_empty() {
            &[][..]
        } else {
            &TEST_DEVICE_BINDING
        };
        Self::open_device_bound(config_json, account_key, binding, database_path)
    }

    /// Return balances, descriptors, fee reserve, deposit address and sync provenance.
    pub fn status(&mut self) -> Result<Value, AccountError> {
        let address = self
            .bitcoin
            .next_unused_address(KeychainKind::External)
            .address;
        self.bitcoin.persist(&mut self.db)?;
        let balance = self.bitcoin.balance();
        let utxos: Vec<Value> = self
            .bitcoin
            .list_unspent()
            .map(|utxo| {
                json!({
                    "txid": utxo.outpoint.txid.to_string(),
                    "vout": utxo.outpoint.vout,
                    "value_sats": utxo.txout.value.to_sat(),
                    "keychain": format!("{:?}", utxo.keychain).to_lowercase(),
                    "derivation_index": utxo.derivation_index,
                    "reserved": self.bitcoin.is_outpoint_locked(utxo.outpoint),
                })
            })
            .collect();
        let protocol_balances = self
            .protocol
            .as_ref()
            .map(MemWallet::balance)
            .unwrap_or_default();
        let instruments = self.instrument_records()?;
        let owners = self
            .protocol
            .as_ref()
            .map(MemWallet::owners)
            .or_else(|| self.config.watch_owner.clone().map(|owner| vec![owner]))
            .unwrap_or_default();
        Ok(json!({
            "version": SCHEMA_VERSION,
            "role": self.config.role,
            "network": self.config.network,
            "owners": owners,
            "assets": protocol_balances,
            "instruments": instruments,
            "fee_reserve": {
                "confirmed_sats": balance.confirmed.to_sat(),
                "trusted_pending_sats": balance.trusted_pending.to_sat(),
                "untrusted_pending_sats": balance.untrusted_pending.to_sat(),
                "immature_sats": balance.immature.to_sat(),
                "total_sats": balance.total().to_sat(),
                "utxos": utxos,
            },
            "deposit_address": address.to_string(),
            "watch_descriptors": {
                "external": self.bitcoin.public_descriptor(KeychainKind::External).to_string(),
                "internal": self.bitcoin.public_descriptor(KeychainKind::Internal).to_string(),
            },
            "backup_verified": self.backup_verified()?,
            "write_enabled": self.write_enabled()?,
            "issuance_enabled": false,
            "device_binding": {
                "status": match self.config.role {
                    AccountRole::Linked => "not_applicable",
                    AccountRole::Primary if self.device_binding_valid => "bound",
                    AccountRole::Primary => "mismatch_read_only",
                },
                "commitment": self.device_binding_commitment.clone(),
            },
            "sync_provenance": {
                "accelerator": self.config.esplora_url,
                "authoritative": "headers+bip158+verified-blocks",
                "verification_peer_count": if self.config.verification_peers.is_empty() {
                    self.config.peers.len()
                } else {
                    self.config.verification_peers.len()
                },
                "last_sync_at": self.db.meta("last_sync_at")?,
                "last_sync_tip": self.db.meta("last_sync_tip")?,
            },
            "observation_policy": self.config.observation_checks,
            "observation_receipts": query_json_rows(
                &self.db.conn,
                "SELECT receipt_json FROM opencsv_observation_receipts
                 ORDER BY observed_at DESC, check_id LIMIT 20",
            )?,
            "root_fingerprint": self.root_fingerprint,
        }))
    }

    /// Synchronize the BDK wallet through the configured Esplora accelerator.
    pub fn sync(&mut self) -> Result<Value, AccountError> {
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let request = self.bitcoin.start_full_scan();
        let update = client
            .full_scan(request, self.config.stop_gap, self.config.parallel_requests)
            .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
        self.bitcoin
            .apply_update(update)
            .map_err(|error| AccountError::new("stale_chain_state", error.to_string()))?;
        self.bitcoin.persist(&mut self.db)?;
        let now = unix_time()?;
        let tip = self.bitcoin.latest_checkpoint().height();
        self.db.set_meta("last_sync_at", &now.to_string())?;
        self.db.set_meta("last_sync_tip", &tip.to_string())?;
        let balance = self.bitcoin.balance();
        Ok(json!({
            "status": "synced",
            "tip_height": tip,
            "fee_reserve_sats": balance.total().to_sat(),
            "source": self.config.esplora_url,
            "authoritative_spend_check": "required_at_prepare_and_sign",
        }))
    }

    /// Credit a consignment through the account wallet's single local
    /// bookkeeping path after the chosen chain view has accepted it.
    pub fn verify_consignment(
        &mut self,
        blob: &[u8],
        snapshot_json: &str,
    ) -> Result<Value, AccountError> {
        let (canonical_blob, consignment_id) = canonical_consignment_identity(blob)?;
        let anchor_txid = consignment_anchor_txid(&canonical_blob)?;
        let chain = SnapshotChain::from_json(snapshot_json)
            .map_err(|error| AccountError::new("invalid_chain_view", error))?;
        let required_confirmations = u64::from(self.config.required_confirmations);
        let verdict = self
            .primary_protocol_mut()?
            .verify(&canonical_blob, &chain, required_confirmations)
            .map_err(|error| AccountError::new("invalid_consignment", error))?;
        match verdict {
            Ok(verified) => {
                self.db.conn.execute(
                    "INSERT INTO opencsv_consignments(
                         consignment_id, consignment_base64, spent_state_json, created_at
                     ) VALUES(?1, ?2, '{}', ?3)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         consignment_base64 = excluded.consignment_base64",
                    params![
                        consignment_id,
                        base64::engine::general_purpose::STANDARD.encode(&canonical_blob),
                        unix_time()?,
                    ],
                )?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_consignment_snapshots(consignment_id, snapshot_json)
                     VALUES(?1, ?2)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         snapshot_json = excluded.snapshot_json",
                    params![consignment_id, snapshot_json],
                )?;
                let now = unix_time()?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_consignment_finality(
                         consignment_id, anchor_txid, finality, observed_at,
                         last_checked_at, last_error
                     ) VALUES(?1, ?2, 'settled', ?3, ?3, NULL)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         anchor_txid = excluded.anchor_txid,
                         finality = 'settled',
                         last_checked_at = excluded.last_checked_at,
                         last_error = NULL",
                    params![consignment_id, anchor_txid, now],
                )?;
                Ok(json!({
                    "status": "verified",
                    "finality": "settled",
                    "spendable": true,
                    "consignment_id": consignment_id,
                    "credits": verified.credits,
                    "coins": verified.coins,
                    "anchor": {
                        "height": verified.height,
                        "position": verified.position,
                    },
                }))
            }
            Err(reason) => Ok(json!({
                "status": "rejected",
                "consignment_id": consignment_id,
                "reason": reason,
            })),
        }
    }

    /// Inspect only the canonical public identity and anchor reference of a
    /// consignment. No crediting, networking, or wallet mutation occurs.
    pub fn inspect_consignment(&self, blob: &[u8]) -> Result<Value, AccountError> {
        let (canonical, consignment_id) = canonical_consignment_identity(blob)?;
        let consignment = Consignment::from_bytes(&canonical)
            .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
        Ok(json!({
            "consignment_id": consignment_id,
            "anchor_txid": Txid::from_byte_array(consignment.anchor_ref.txid).to_string(),
            "anchor_height": consignment.anchor_ref.location.height,
            "anchor_position": consignment.anchor_ref.location.position,
        }))
    }

    /// Credit a fully proof-verified consignment whose exact anchor
    /// transaction is independently observable through the configured
    /// generic Esplora accelerator but has not met settlement depth yet.
    /// The resulting coins are selectable, with the exact parent txid
    /// carried into every child operation and rechecked before signing.
    pub fn verify_consignment_unconfirmed(
        &mut self,
        blob: &[u8],
        confirmed_snapshot_json: &str,
    ) -> Result<Value, AccountError> {
        if self
            .config
            .observation_checks
            .iter()
            .any(|check| check.mode == ObservationMode::Require)
        {
            return Err(AccountError::new(
                "observation_evidence_required",
                "required observer policy needs pinned host evidence and exact raw transaction bytes",
            ));
        }
        let (canonical_blob, consignment_id) = canonical_consignment_identity(blob)?;
        let consignment = Consignment::from_bytes(&canonical_blob)
            .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
        let anchor_txid = Txid::from_byte_array(consignment.anchor_ref.txid);
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let transaction = client
            .get_tx(&anchor_txid)
            .map_err(|error| AccountError::new("mempool_observation_failed", error.to_string()))?;
        let Some(transaction) = transaction else {
            self.freeze_unconfirmed_dependency(
                &anchor_txid.to_string(),
                "exact parent transaction is no longer observed",
            )?;
            return Err(AccountError::new(
                "unconfirmed_anchor_missing",
                format!("unconfirmed anchor {anchor_txid} is not currently observed"),
            ));
        };
        let provisional_snapshot =
            snapshot_with_unconfirmed_anchor(confirmed_snapshot_json, &consignment, &transaction)?;
        let provisional_snapshot_json = serde_json::to_string(&provisional_snapshot)
            .map_err(|error| AccountError::new("invalid_chain_view", error.to_string()))?;
        let chain = SnapshotChain::from_snapshot(&provisional_snapshot)
            .map_err(|error| AccountError::new("invalid_chain_view", error))?;
        let verdict = self
            .primary_protocol_mut()?
            .verify_unconfirmed(&canonical_blob, &chain, &anchor_txid.to_string())
            .map_err(|error| AccountError::new("invalid_consignment", error))?;
        match verdict {
            Ok(verified) => {
                let now = unix_time()?;
                let db_tx = self
                    .db
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignments(
                         consignment_id, consignment_base64, spent_state_json, created_at
                     ) VALUES(?1, ?2, '{}', ?3)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         consignment_base64 = excluded.consignment_base64",
                    params![
                        consignment_id,
                        base64::engine::general_purpose::STANDARD.encode(&canonical_blob),
                        now,
                    ],
                )?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignment_snapshots(consignment_id, snapshot_json)
                     VALUES(?1, ?2)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         snapshot_json = excluded.snapshot_json",
                    params![consignment_id, provisional_snapshot_json],
                )?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignment_finality(
                         consignment_id, anchor_txid, finality, observed_at,
                         last_checked_at, last_error
                     ) VALUES(?1, ?2, 'unconfirmed', ?3, ?3, NULL)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         anchor_txid = excluded.anchor_txid,
                         finality = CASE
                             WHEN opencsv_consignment_finality.finality = 'settled' THEN 'settled'
                             ELSE 'unconfirmed'
                         END,
                         last_checked_at = excluded.last_checked_at,
                         last_error = NULL",
                    params![consignment_id, anchor_txid.to_string(), now],
                )?;
                db_tx.commit()?;
                Ok(json!({
                    "status": "verified",
                    "finality": "unconfirmed",
                    "spendable": true,
                    "risk": "zero_confirmation_replacement_or_conflict",
                    "consignment_id": consignment_id,
                    "credits": verified.credits,
                    "coins": verified.coins,
                    "anchor": {
                        "height": verified.height,
                        "position": verified.position,
                    },
                    "anchor_txid": anchor_txid.to_string(),
                    "observed_via": self.config.esplora_url,
                }))
            }
            Err(reason) => Ok(json!({
                "status": "rejected",
                "finality": "unconfirmed",
                "spendable": false,
                "consignment_id": consignment_id,
                "reason": reason,
            })),
        }
    }

    /// Credit an unconfirmed consignment using exact raw transaction bytes and
    /// per-check evidence fetched by Signal's pinned `OWSURLSession` client.
    /// Rust treats every host field as untrusted: it recomputes the txid,
    /// validates the complete transaction layout/context, compares each
    /// provider's raw bytes, enforces the stored Off/Observe/Require policy,
    /// and durably stores normalized receipts.
    pub fn verify_consignment_unconfirmed_observed(
        &mut self,
        blob: &[u8],
        confirmed_snapshot_json: &str,
        raw_transaction: &[u8],
        observations_json: &str,
    ) -> Result<Value, AccountError> {
        let (canonical_blob, consignment_id) = canonical_consignment_identity(blob)?;
        let consignment = Consignment::from_bytes(&canonical_blob)
            .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
        let anchor_txid = Txid::from_byte_array(consignment.anchor_ref.txid);
        let transaction: Transaction = deserialize(raw_transaction).map_err(|error| {
            AccountError::new(
                "invalid_observation_transaction",
                format!("raw transaction: {error}"),
            )
        })?;
        if transaction.compute_txid() != anchor_txid {
            return Err(AccountError::new(
                "unconfirmed_anchor_mismatch",
                format!(
                    "raw transaction computes to {}, expected {anchor_txid}",
                    transaction.compute_txid()
                ),
            ));
        }
        let (receipts, policy_failure) = evaluate_observation_evidence(
            &self.config.observation_checks,
            raw_transaction,
            observations_json,
        )?;
        self.persist_observation_receipts(&anchor_txid.to_string(), &receipts)?;
        if let Some(error) = policy_failure {
            self.freeze_unconfirmed_dependency(&anchor_txid.to_string(), &error.message)?;
            return Err(error);
        }
        self.enforce_unconfirmed_non_host_policy(&anchor_txid.to_string(), false)?;

        let provisional_snapshot =
            snapshot_with_unconfirmed_anchor(confirmed_snapshot_json, &consignment, &transaction)?;
        let provisional_snapshot_json = serde_json::to_string(&provisional_snapshot)
            .map_err(|error| AccountError::new("invalid_chain_view", error.to_string()))?;
        let chain = SnapshotChain::from_snapshot(&provisional_snapshot)
            .map_err(|error| AccountError::new("invalid_chain_view", error))?;
        let verdict = self
            .primary_protocol_mut()?
            .verify_unconfirmed(&canonical_blob, &chain, &anchor_txid.to_string())
            .map_err(|error| AccountError::new("invalid_consignment", error))?;
        match verdict {
            Ok(verified) => {
                let now = unix_time()?;
                let db_tx = self
                    .db
                    .conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignments(
                         consignment_id, consignment_base64, spent_state_json, created_at
                     ) VALUES(?1, ?2, '{}', ?3)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         consignment_base64 = excluded.consignment_base64",
                    params![
                        consignment_id,
                        base64::engine::general_purpose::STANDARD.encode(&canonical_blob),
                        now,
                    ],
                )?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignment_snapshots(consignment_id, snapshot_json)
                     VALUES(?1, ?2)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         snapshot_json = excluded.snapshot_json",
                    params![consignment_id, provisional_snapshot_json],
                )?;
                db_tx.execute(
                    "INSERT INTO opencsv_consignment_finality(
                         consignment_id, anchor_txid, finality, observed_at,
                         last_checked_at, last_error
                     ) VALUES(?1, ?2, 'unconfirmed', ?3, ?3, NULL)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         anchor_txid = excluded.anchor_txid,
                         finality = CASE
                             WHEN opencsv_consignment_finality.finality = 'settled' THEN 'settled'
                             ELSE 'unconfirmed'
                         END,
                         last_checked_at = excluded.last_checked_at,
                         last_error = NULL",
                    params![consignment_id, anchor_txid.to_string(), now],
                )?;
                db_tx.commit()?;
                Ok(json!({
                    "status": "verified",
                    "finality": "unconfirmed",
                    "spendable": true,
                    "risk": "zero_confirmation_replacement_or_conflict",
                    "consignment_id": consignment_id,
                    "credits": verified.credits,
                    "coins": verified.coins,
                    "anchor": {
                        "height": verified.height,
                        "position": verified.position,
                    },
                    "anchor_txid": anchor_txid.to_string(),
                    "observations": receipts,
                }))
            }
            Err(reason) => Ok(json!({
                "status": "rejected",
                "finality": "unconfirmed",
                "spendable": false,
                "consignment_id": consignment_id,
                "reason": reason,
                "observations": receipts,
            })),
        }
    }

    /// Record independent pinned visibility for this wallet's exact signed
    /// transaction. Direct peer writes remain submission receipts only; this
    /// is the transition that may make a transaction mempool-observed and
    /// release its consignment for Signal delivery.
    pub fn observe_operation_unconfirmed(
        &mut self,
        operation_id: &str,
        raw_transaction: &[u8],
        observations_json: &str,
    ) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if !matches!(
            operation.state.as_str(),
            "signed_persisted" | "broadcast_unobserved" | "mempool"
        ) {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!("operation is {}", operation.state),
            ));
        }
        let signed_hex = operation.signed_tx_hex.as_deref().ok_or_else(|| {
            AccountError::new(
                "database_corrupt",
                "signed operation has no transaction bytes",
            )
        })?;
        let signed_bytes = hex_decode(signed_hex, "signed transaction")?;
        if signed_bytes != raw_transaction {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "observer bytes do not equal the exact persisted signed transaction",
            ));
        }
        let transaction: Transaction = deserialize(raw_transaction).map_err(|error| {
            AccountError::new(
                "invalid_observation_transaction",
                format!("raw transaction: {error}"),
            )
        })?;
        let txid = transaction.compute_txid();
        let txid_string = txid.to_string();
        if operation.txid.as_deref() != Some(txid_string.as_str()) {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "observer transaction id differs from the signed operation",
            ));
        }
        let (receipts, policy_failure) = evaluate_observation_evidence(
            &self.config.observation_checks,
            raw_transaction,
            observations_json,
        )?;
        self.persist_observation_receipts(&txid_string, &receipts)?;
        if let Some(error) = policy_failure {
            return Err(error);
        }
        self.enforce_unconfirmed_non_host_policy(&txid_string, true)?;
        let independently_visible = receipts.iter().any(|receipt| {
            receipt["kind"] == json!(ObservationKind::RawTransactionApi)
                && receipt["result"] == json!(ObservationResult::Observed)
                && receipt["raw_byte_match"] == true
        });
        if !independently_visible {
            return Err(AccountError::new(
                "mempool_observation_failed",
                "no enabled independent observer returned the exact signed transaction",
            ));
        }
        if operation.state != OperationState::Mempool.as_str() {
            self.finalize_observed_operation(operation_id, txid)?;
        }
        let mut value = operation_json(&self.operation(operation_id)?)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("observations".into(), json!(receipts));
            object.insert("confirmed".into(), json!(false));
            object.insert("observed_via".into(), json!("pinned_raw_transaction_apis"));
        }
        Ok(value)
    }

    fn enforce_unconfirmed_non_host_policy(
        &self,
        subject_txid: &str,
        locally_relayed: bool,
    ) -> Result<(), AccountError> {
        for check in self
            .config
            .observation_checks
            .iter()
            .filter(|check| check.mode == ObservationMode::Require)
        {
            match check.kind {
                ObservationKind::RawTransactionApi => {}
                ObservationKind::DirectP2pRelay if !locally_relayed => {
                    // A receiver cannot prove how the sender submitted the
                    // transaction. The receiver's independent raw-byte checks
                    // remain the acceptance gate.
                }
                ObservationKind::DirectP2pRelay => {
                    let receipt: Option<String> = self
                        .db
                        .conn
                        .query_row(
                            "SELECT receipt_json FROM opencsv_observation_receipts
                             WHERE subject_txid = ?1 AND check_id = ?2",
                            params![subject_txid, check.id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    let passed = receipt
                        .as_deref()
                        .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
                        .is_some_and(|receipt| {
                            receipt["result"] == json!(ObservationResult::Submitted)
                                && receipt["failures"].as_array().is_some_and(Vec::is_empty)
                        });
                    if !passed {
                        return Err(AccountError::new(
                            "required_observation_failed",
                            format!("required direct relay check {} did not pass", check.id),
                        ));
                    }
                }
                ObservationKind::ExperimentalP2pPossession => {
                    return Err(AccountError::new(
                        "required_observation_failed",
                        format!(
                            "required experimental check {} has no valid receipt",
                            check.id
                        ),
                    ));
                }
                ObservationKind::ConfirmedSpv => {
                    return Err(AccountError::new(
                        "confirmation_required",
                        format!("{} requires SPV confirmation before acceptance", check.id),
                    ));
                }
            }
        }
        Ok(())
    }

    fn persist_observation_receipts(
        &self,
        subject_txid: &str,
        receipts: &[Value],
    ) -> Result<(), AccountError> {
        let observed_at = unix_time()?;
        for receipt in receipts {
            let check_id = receipt["check_id"].as_str().ok_or_else(|| {
                AccountError::new("invalid_observation_evidence", "receipt has no check id")
            })?;
            self.db.conn.execute(
                "INSERT INTO opencsv_observation_receipts(
                     subject_txid, check_id, receipt_json, observed_at
                 ) VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(subject_txid, check_id) DO UPDATE SET
                     receipt_json = excluded.receipt_json,
                     observed_at = excluded.observed_at",
                params![subject_txid, check_id, receipt.to_string(), observed_at],
            )?;
        }
        Ok(())
    }

    fn submit_direct_p2p(
        &self,
        transaction: &Transaction,
    ) -> Result<(usize, Vec<Value>), AccountError> {
        let check = self
            .config
            .observation_checks
            .iter()
            .find(|check| check.kind == ObservationKind::DirectP2pRelay);
        if check.is_some_and(|check| check.mode == ObservationMode::Off) {
            return Ok((0, Vec::new()));
        }
        let relay = relay_transaction(
            self.bitcoin.network(),
            &self.config.peers,
            transaction,
            Duration::from_secs(8),
        );
        let submitted = relay.submitted_count();
        let peers: Vec<Value> = relay
            .peers
            .iter()
            .map(|peer| {
                json!({
                    "peer": peer.peer,
                    "submitted": peer.submitted,
                    "error": peer.error,
                })
            })
            .collect();
        if let Some(check) = check.filter(|check| check.mode != ObservationMode::Off) {
            let now_ms = unix_time_millis()?;
            let failures = if submitted == 0 {
                vec!["no peer completed a transaction write"]
            } else {
                Vec::new()
            };
            self.persist_observation_receipts(
                &transaction.compute_txid().to_string(),
                &[json!({
                    "check_id": check.id,
                    "kind": check.kind,
                    "mode": check.mode,
                    "endpoint": Value::Null,
                    "result": if submitted > 0 {
                        ObservationResult::Submitted
                    } else {
                        ObservationResult::Unavailable
                    },
                    "started_at_ms": now_ms,
                    "completed_at_ms": now_ms,
                    "latency_ms": 0,
                    "cached_at_ms": now_ms,
                    "cache_age_ms": 0,
                    "certificate_profile": Value::Null,
                    "certificate_chain_fingerprints_sha256": [],
                    "raw_byte_match": false,
                    "detail": format!("{} of {} peers accepted a complete socket write", submitted, peers.len()),
                    "failures": failures,
                })],
            )?;
        }
        Ok((submitted, peers))
    }

    /// Read-only self-scan verdict using this account's owner and asset set.
    pub fn scan_verify(&self, consignment_hex: &str) -> Result<Value, AccountError> {
        scan::verify_json(
            consignment_hex,
            &self.owner_secrets()?,
            &self.known_asset_ids()?,
            &opencsv_pcd::CoinProofVerifier,
        )
        .map_err(|error| AccountError::new("scan_failed", error))
    }

    /// Read-only N-of-M chain-view decision using this account's identities.
    pub fn cross_check(&self, request_json: &str) -> Result<Value, AccountError> {
        crosscheck::run_cross_check(
            request_json,
            &self.owner_secrets()?,
            &self.known_asset_ids()?,
            &opencsv_pcd::CoinProofVerifier,
        )
        .map_err(|failure| match failure {
            crosscheck::CrossCheckFailure::TipDisagreement(tips) => AccountError::new(
                "tip_disagreement",
                format!("anchor backends disagree on tip height: {tips:?}"),
            ),
            crosscheck::CrossCheckFailure::Other(message) => {
                AccountError::new("cross_check_failed", message)
            }
        })
    }

    /// Opt-in issuer-tool manifest constructor. Signal's production FFI has no
    /// asset-definition or issuance action and never enables this feature.
    #[cfg(any(test, feature = "issuer-tools"))]
    pub fn instrument_create(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let request: InstrumentCreateRequest =
            serde_json::from_str(request_json).map_err(|error| {
                AccountError::new(
                    "invalid_instrument_definition",
                    format!("instrument request: {error}"),
                )
            })?;
        request.terms.validate().map_err(|error| {
            AccountError::new("invalid_instrument_definition", error.to_string())
        })?;
        if request.terms.network != self.config.network {
            return Err(AccountError::new(
                "instrument_network_mismatch",
                format!(
                    "instrument definition is for {}, wallet is {}",
                    request.terms.network, self.config.network
                ),
            ));
        }
        let (asset_id, manifest) = self.create_instrument(request.terms)?;
        // The definition is durable, but writes stay frozen until Signal
        // Secure Backup acknowledges the checkpoint containing it.
        self.db.set_meta("backup_verified", "0")?;
        let checkpoint = self.checkpoint()?;
        Ok(json!({
            "asset_id": asset_id,
            "manifest": manifest,
            "checkpoint_hash": checkpoint["checkpoint_hash"],
            "backup_required": true,
        }))
    }

    /// Prepare issuer-authorized issuance for an existing exact asset id.
    /// Fee selection, change derivation, and the OpenCSV proof all remain
    /// inside Rust. This helper exists for account-wallet tests and the
    /// explicitly featured issuer harness, separate from Signal's FFI.
    #[cfg(any(test, feature = "issuer-tools"))]
    pub fn mint_prepare(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let request: IssuanceRequest = serde_json::from_str(request_json).map_err(|error| {
            AccountError::new("invalid_request", format!("issuance request: {error}"))
        })?;
        if request.amounts.is_empty() || request.amounts.len() > 2 {
            return Err(AccountError::new(
                "invalid_request",
                "mint requires one or two positive outputs",
            ));
        }
        if request.amounts.contains(&0) {
            return Err(AccountError::new(
                "invalid_request",
                "mint outputs must be positive",
            ));
        }
        let asset_id = request.asset_id;
        if !self.is_manifested_instrument(&asset_id)? {
            return Err(AccountError::new(
                "instrument_definition_required",
                "issuance requires an existing v1 instrument manifest; prototype assets are read-only",
            ));
        }

        let operation_id = random_id(16);
        let delivery_nonce = random_id(16);
        self.insert_planned_operation(&operation_id, "mint", request_json, &delivery_nonce)?;
        let funding = match self.reserve_fee_utxo(&operation_id) {
            Ok(funding) => funding,
            Err(error) => {
                self.reject_prebroadcast_operation(&operation_id, error.code)?;
                return Err(error);
            }
        };
        let verification = match self.verify_funding(&funding) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.reject_prebroadcast_operation(&operation_id, error.code)?;
                return Err(error);
            }
        };
        let ctx = funding_context(funding.outpoint);

        let (to_owner, proved) = {
            let protocol = match self.primary_protocol_mut() {
                Ok(protocol) => protocol,
                Err(error) => return self.fail_prebroadcast(&operation_id, error),
            };
            let to_owner = request
                .to_owner
                .unwrap_or_else(|| protocol.owners().into_iter().next().unwrap_or_default());
            let proved = match protocol.prove_mint(&asset_id, &to_owner, &request.amounts) {
                Ok(proved) => proved,
                Err(error) => {
                    return self.fail_prebroadcast(
                        &operation_id,
                        AccountError::new("invalid_proof_request", error),
                    );
                }
            };
            (to_owner, proved)
        };
        self.pending_by_operation
            .insert(operation_id.clone(), proved.pending_id);
        let record = match self.primary_protocol_mut().and_then(|protocol| {
            protocol
                .rebind_pending(proved.pending_id, ctx)
                .map_err(|error| AccountError::new("protocol_layout_violation", error))
        }) {
            Ok(record) => record,
            Err(error) => return self.fail_prebroadcast(&operation_id, error),
        };
        let pending_json = match self.primary_protocol_mut().and_then(|protocol| {
            protocol
                .export_pending(proved.pending_id)
                .map_err(|error| AccountError::new("database_error", error))
        }) {
            Ok(pending_json) => pending_json,
            Err(error) => return self.fail_prebroadcast(&operation_id, error),
        };
        let normalized_request = json!({
            "asset_id": asset_id,
            "to_owner": to_owner,
            "amounts": request.amounts,
        });
        if let Err(error) = self.mark_proof_ready(
            &operation_id,
            &normalized_request,
            &pending_json,
            &hex_encode(&record),
        ) {
            return self.fail_prebroadcast(&operation_id, error);
        }
        match self.prepared_receipt(&operation_id, funding, &verification, &record) {
            Ok(receipt) => Ok(receipt),
            Err(error) => self.fail_prebroadcast(&operation_id, error),
        }
    }

    /// Journal an exact OpenCSV transfer intent without doing expensive proof
    /// work. Signal can return to the conversation as soon as this durable
    /// `planned` receipt exists; `prove_operation` advances the same operation
    /// in a background task. There is deliberately no Bitcoin recipient or
    /// arbitrary-send field at this boundary.
    pub fn transfer_plan(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let request: TransferRequest = serde_json::from_str(request_json).map_err(|error| {
            AccountError::new("invalid_request", format!("transfer request: {error}"))
        })?;
        decode_hex_32(&request.asset_id, "asset id")?;
        decode_hex_32(&request.to_owner, "recipient owner")?;
        if request.amount == 0 {
            return Err(AccountError::new(
                "invalid_request",
                "transfer amount must be positive",
            ));
        }
        let normalized_request = serde_json::to_string(&request)
            .map_err(|error| AccountError::new("database_error", error.to_string()))?;
        let operation_id = random_id(16);
        let delivery_nonce = random_id(16);
        self.insert_planned_operation(
            &operation_id,
            "transfer",
            &normalized_request,
            &delivery_nonce,
        )?;
        operation_json(&self.operation(&operation_id)?)
    }

    /// Reserve, verify, and prove one previously planned transfer. The
    /// transition is crash-resumable from both `planned` and `fee_reserved`;
    /// a repeated call after `proof_ready` returns the exact stored receipt.
    pub fn prove_operation(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        match self.begin_proof_job(operation_id)? {
            ProofJobStart::Ready(receipt) => Ok(receipt),
            ProofJobStart::Run(job) => match job.run() {
                Ok(completed) => self.finish_proof_job(completed),
                Err(error) => self.fail_proof_job(operation_id, error),
            },
        }
    }

    /// Snapshot and durably reserve one proof job while holding the live
    /// wallet lock for only the short state-transition phase.
    pub(crate) fn begin_proof_job(
        &mut self,
        operation_id: &str,
    ) -> Result<ProofJobStart, AccountError> {
        self.require_write_enabled()?;
        let operation = self.operation(operation_id)?;
        if operation.kind != "transfer" {
            return Err(AccountError::new(
                "invalid_operation_kind",
                format!("operation is {}", operation.kind),
            ));
        }
        if operation.state == OperationState::ProofReady.as_str() {
            return Ok(ProofJobStart::Ready(
                self.prepared_operation_receipt(&operation)?,
            ));
        }
        if let Some(active) = self.db.meta("active_proof_operation")? {
            if active != operation_id {
                return Err(AccountError::new(
                    "proof_job_busy",
                    format!("another proof job is active for operation {active}"),
                ));
            }
        }
        let funding = match operation.state.as_str() {
            "planned" => match self.reserve_fee_utxo(operation_id) {
                Ok(funding) => funding,
                Err(error) => {
                    self.reject_prebroadcast_operation(operation_id, error.code)?;
                    return Err(error);
                }
            },
            "fee_reserved" => match self.reserved_funding_for_operation(&operation) {
                Ok(funding) => funding,
                Err(error) => return self.fail_prebroadcast(operation_id, error),
            },
            state => {
                return Err(AccountError::new(
                    "invalid_operation_state",
                    format!("operation is {state}"),
                ));
            }
        };
        let request: TransferRequest = match serde_json::from_str(&operation.request_json) {
            Ok(request) => request,
            Err(error) => {
                return self.fail_prebroadcast(
                    operation_id,
                    AccountError::new("database_corrupt", format!("transfer request: {error}")),
                );
            }
        };
        let protocol_snapshot = self.protocol.as_ref().cloned().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices cannot prove transfers")
        })?;
        self.db.set_meta("active_proof_operation", operation_id)?;
        Ok(ProofJobStart::Run(Box::new(AccountProofJob {
            operation_id: operation_id.to_owned(),
            request,
            funding,
            verifier: self.funding_verifier.clone(),
            protocol_snapshot,
            esplora_url: self.config.esplora_url.clone(),
        })))
    }

    /// Atomically install the proved snapshot only if the proposal, fee
    /// reservation, and live OpenCSV inputs remain current.
    pub(crate) fn finish_proof_job(
        &mut self,
        completed: CompletedProofJob,
    ) -> Result<Value, AccountError> {
        let operation = self.operation(&completed.operation_id)?;
        if operation.state == OperationState::ProofReady.as_str() {
            self.db.delete_meta("active_proof_operation")?;
            return self.prepared_operation_receipt(&operation);
        }
        if self.db.meta("active_proof_operation")?.as_deref()
            != Some(completed.operation_id.as_str())
        {
            return Err(AccountError::new(
                "stale_proof_job",
                "proof job no longer owns the active reservation",
            ));
        }
        if operation.state != OperationState::FeeReserved.as_str()
            || operation_outpoint(&operation)? != completed.funding.outpoint
        {
            return self.fail_proof_job(
                &completed.operation_id,
                AccountError::new(
                    "stale_proof_job",
                    "operation or fee reservation changed while proving",
                ),
            );
        }
        let current_request: TransferRequest = serde_json::from_str(&operation.request_json)
            .map_err(|error| {
                AccountError::new("database_corrupt", format!("transfer request: {error}"))
            })?;
        if current_request.asset_id != completed.request.asset_id
            || current_request.to_owner != completed.request.to_owner
            || current_request.amount != completed.request.amount
        {
            return self.fail_proof_job(
                &completed.operation_id,
                AccountError::new("stale_proof_job", "transfer proposal changed while proving"),
            );
        }

        let pending_id = self
            .primary_protocol_mut()?
            .import_pending(&completed.pending_json)
            .map_err(|error| AccountError::new("database_error", error))?;
        let validation = self.primary_protocol_mut().and_then(|protocol| {
            if protocol
                .pending_spend_conflicts(pending_id)
                .map_err(|error| AccountError::new("database_error", error))?
                || !protocol
                    .pending_spends_available(pending_id)
                    .map_err(|error| AccountError::new("database_error", error))?
            {
                return Err(AccountError::new(
                    "conflicting_operation",
                    "selected OpenCSV inputs changed or were reserved while proving",
                ));
            }
            let dependencies = protocol
                .pending_unconfirmed_dependencies(pending_id)
                .map_err(|error| AccountError::new("database_error", error))?;
            if dependencies != completed.unconfirmed_dependencies {
                return Err(AccountError::new(
                    "stale_proof_job",
                    "unconfirmed dependency set changed while proving",
                ));
            }
            let record = protocol
                .rebind_pending(pending_id, funding_context(completed.funding.outpoint))
                .map_err(|error| AccountError::new("protocol_layout_violation", error))?;
            if record != completed.record {
                return Err(AccountError::new(
                    "stale_proof_job",
                    "proposal-bound record changed while proving",
                ));
            }
            Ok(())
        });
        if let Err(error) = validation {
            if let Some(protocol) = self.protocol.as_mut() {
                protocol.cancel_pending(pending_id);
            }
            return self.fail_proof_job(&completed.operation_id, error);
        }
        self.pending_by_operation
            .insert(completed.operation_id.clone(), pending_id);
        for dependency in &completed.unconfirmed_dependencies {
            self.db.conn.execute(
                "UPDATE opencsv_consignment_finality
                 SET last_checked_at = ?2, last_error = NULL
                 WHERE anchor_txid = ?1 AND finality = 'unconfirmed'",
                params![dependency, unix_time()?],
            )?;
        }
        if let Err(error) = self.mark_proof_ready(
            &completed.operation_id,
            &json!({
                "asset_id": completed.request.asset_id,
                "to_owner": completed.request.to_owner,
                "amount": completed.request.amount,
            }),
            &completed.pending_json,
            &hex_encode(&completed.record),
        ) {
            return self.fail_proof_job(&completed.operation_id, error);
        }
        self.db.delete_meta("active_proof_operation")?;
        match self.prepared_receipt(
            &completed.operation_id,
            completed.funding,
            &completed.verification,
            &completed.record,
        ) {
            Ok(receipt) => Ok(receipt),
            Err(error) => self.fail_prebroadcast(&completed.operation_id, error),
        }
    }

    pub(crate) fn fail_proof_job<T>(
        &mut self,
        operation_id: &str,
        error: AccountError,
    ) -> Result<T, AccountError> {
        self.db.delete_meta("active_proof_operation")?;
        if error.code == "unconfirmed_dependency_changed" {
            if let Some(dependency) = error
                .message
                .split_whitespace()
                .nth(2)
                .map(|value| value.trim_matches(|character: char| !character.is_ascii_hexdigit()))
                .filter(|value| value.len() == 64)
            {
                self.freeze_unconfirmed_dependency(dependency, &error.message)?;
            }
        }
        self.fail_prebroadcast(operation_id, error)
    }

    /// Compatibility one-shot used by existing callers. New interactive
    /// clients should call `transfer_plan`, return to the UI, and advance the
    /// returned operation with `prove_operation` in the background.
    pub fn transfer_prepare(&mut self, request_json: &str) -> Result<Value, AccountError> {
        let planned = self.transfer_plan(request_json)?;
        let operation_id = planned["operation_id"].as_str().ok_or_else(|| {
            AccountError::new("database_error", "planned transfer has no operation id")
        })?;
        self.prove_operation(operation_id)
    }

    /// Acknowledge that Signal Secure Backup durably accepted the exact
    /// checkpoint produced after preparation. Signing refuses any stale or
    /// missing acknowledgement.
    pub fn acknowledge_operation_backup(
        &mut self,
        operation_id: &str,
        checkpoint_hash: &str,
    ) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if operation.state != OperationState::ProofReady.as_str() {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!("operation is {}", operation.state),
            ));
        }
        if operation.checkpoint_hash.as_deref() != Some(checkpoint_hash) {
            return Err(AccountError::new(
                "backup_checkpoint_mismatch",
                "Secure Backup acknowledged a stale or different checkpoint",
            ));
        }
        let current_checkpoint = self.checkpoint()?;
        let current_hash = current_checkpoint["checkpoint_hash"]
            .as_str()
            .ok_or_else(|| {
                AccountError::new("checkpoint_failed", "current checkpoint has no hash")
            })?;
        if current_hash != checkpoint_hash {
            return Err(AccountError::new(
                "backup_checkpoint_mismatch",
                "wallet state changed after the prepared checkpoint was emitted",
            ));
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations
             SET backup_acked = 1, updated_at = ?2 WHERE operation_id = ?1",
            params![operation_id, unix_time()?],
        )?;
        Ok(json!({
            "operation_id": operation_id,
            "backup_acked": true,
            "checkpoint_hash": checkpoint_hash,
        }))
    }

    /// Sign, persist, and broadcast one prepared operation. The fully signed
    /// transaction is committed to SQLite before the network call.
    pub fn sign_and_broadcast(
        &mut self,
        operation_id: &str,
        fee_policy_json: &str,
    ) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let policy: FeePolicy = serde_json::from_str(fee_policy_json)
            .map_err(|error| AccountError::new("invalid_fee_policy", error.to_string()))?;
        if policy.target_sat_per_vb == 0 {
            return Err(AccountError::new(
                "invalid_fee_policy",
                "target_sat_per_vb must be positive",
            ));
        }
        let operation = self.operation(operation_id)?;
        if operation.state != OperationState::ProofReady.as_str() {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!("operation is {}", operation.state),
            ));
        }
        if !operation.backup_acked {
            return Err(AccountError::new(
                "backup_required",
                "the prepared checkpoint has not been acknowledged by Secure Backup",
            ));
        }
        let outpoint = operation_outpoint(&operation)?;
        let funding_output = self
            .bitcoin
            .list_unspent()
            .find(|utxo| utxo.outpoint == outpoint)
            .ok_or_else(|| {
                AccountError::new(
                    "stale_chain_state",
                    "reserved funding outpoint is no longer unspent",
                )
            })?;
        if !self.bitcoin.is_outpoint_locked(outpoint) {
            return Err(AccountError::new(
                "conflicting_operation",
                "funding outpoint lost its durable reservation",
            ));
        }
        let funding = ReservedFunding::from_local(funding_output)?;
        let verification = match self.verify_funding(&funding) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.reject_operation(operation_id, error.code)?;
                return Err(error);
            }
        };
        let pending_id = *self
            .pending_by_operation
            .get(operation_id)
            .ok_or_else(|| AccountError::new("operation_not_resumable", "missing pending proof"))?;
        let unconfirmed_dependencies = self
            .primary_protocol_mut()?
            .pending_unconfirmed_dependencies(pending_id)
            .map_err(|error| AccountError::new("operation_not_resumable", error))?;
        if let Err(error) = self.reobserve_unconfirmed_dependencies(&unconfirmed_dependencies) {
            self.reject_operation(operation_id, error.code)?;
            return Err(error);
        }
        let ctx = funding_context(outpoint);
        let record = self
            .primary_protocol_mut()?
            .rebind_pending(pending_id, ctx)
            .map_err(|error| AccountError::new("protocol_layout_violation", error))?;

        let change_address = self
            .bitcoin
            .next_unused_address(KeychainKind::Internal)
            .address;
        self.bitcoin.persist(&mut self.db)?;
        let fee_rate = FeeRate::from_sat_per_vb(policy.target_sat_per_vb).ok_or_else(|| {
            AccountError::new("invalid_fee_policy", "fee rate exceeds Bitcoin limits")
        })?;
        let record_push = PushBytesBuf::try_from(record.to_vec())
            .map_err(|error| AccountError::new("protocol_layout_violation", error.to_string()))?;
        let mut builder = self.bitcoin.build_tx();
        builder
            .add_utxo(outpoint)
            .map_err(|error| AccountError::new("stale_chain_state", error.to_string()))?;
        builder.manually_selected_only();
        builder.ordering(TxOrdering::Untouched);
        builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        builder.add_recipient(ScriptBuf::new_op_return(record_push), Amount::ZERO);
        builder.add_recipient(
            ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
            Amount::from_sat(MARKER_DUST_SATS),
        );
        builder.drain_to(change_address.script_pubkey());
        builder.fee_rate(fee_rate);
        let mut psbt = builder
            .finish()
            .map_err(|error| AccountError::new("insufficient_fees", error.to_string()))?;
        let finalized = self
            .bitcoin
            .sign(&mut psbt, SignOptions::default())
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        if !finalized {
            return Err(AccountError::new(
                "signing_failed",
                "BDK did not finalize every selected fee input",
            ));
        }
        let fee = psbt.fee_amount().ok_or_else(|| {
            AccountError::new("signing_failed", "could not calculate transaction fee")
        })?;
        if policy
            .max_fee_sats
            .is_some_and(|limit| fee.to_sat() > limit)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!("{} sats exceeds configured maximum", fee.to_sat()),
            ));
        }
        let tx = psbt
            .extract_tx()
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        validate_initial_anchor(&tx, outpoint, &record)?;
        let txid = tx.compute_txid();
        let signed_hex = hex_encode(&serialize(&tx));
        let mut receipt = json!({
            "operation_id": operation_id,
            "txid": txid.to_string(),
            "fee_sats": fee.to_sat(),
            "fee_rate_sat_per_vb": policy.target_sat_per_vb,
            "funding_outpoint": outpoint.to_string(),
            "funding_verification": verification,
            "record_vout": 0,
            "marker_vout": 1,
            "change_vout": 2,
            "delivery_nonce": operation.delivery_nonce,
        });
        self.db.conn.execute(
            "UPDATE opencsv_operations
             SET state = ?2, signed_tx_hex = ?3, txid = ?4,
                 receipt_json = ?5, updated_at = ?6
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::SignedPersisted.as_str(),
                signed_hex,
                txid.to_string(),
                receipt.to_string(),
                unix_time()?,
            ],
        )?;
        let seen_at = u64::try_from(unix_time()?)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(tx.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;

        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&tx)?;
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        // A completed P2P socket write proves submission only. Core can
        // close before processing the unsolicited transaction, so never let
        // `p2p_submissions` suppress the observable generic-relay path.
        let fallback = relay_via_esplora_if_unobserved(&client, &tx);
        if let Some(object) = receipt.as_object_mut() {
            object.insert("p2p_submissions".into(), json!(p2p_submissions));
            object.insert("p2p_peers".into(), json!(relay_peers));
            object.insert(
                "generic_relay_fallback".into(),
                json!(matches!(&fallback, Ok(true))),
            );
            if let Err(error) = &fallback {
                object.insert("generic_relay_error".into(), json!(error.to_string()));
            }
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2,
             rejection_reason = 'broadcast_unobserved', receipt_json = ?3, updated_at = ?4
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::BroadcastUnobserved.as_str(),
                receipt.to_string(),
                unix_time()?
            ],
        )?;
        // Neither a socket write nor an unpinned relay response establishes
        // mempool acceptance. Signal must return exact bytes plus pinned host
        // evidence through `observe_operation_unconfirmed` before delivery.
        operation_json(&self.operation(operation_id)?)
    }

    /// Return one durable operation, refreshing mempool/confirmation state
    /// when a signed transaction exists.
    pub fn operation_status(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if operation.txid.is_some()
            && operation.state != OperationState::Cancelled.as_str()
            && operation.state != OperationState::ConsignmentDelivered.as_str()
            && operation.state != OperationState::ProtocolRejected.as_str()
        {
            return self.refresh_operation(operation_id);
        }
        operation_json(&operation)
    }

    /// Refresh settlement only through the registered multi-peer CBF scan.
    /// The scan owns peer agreement, header PoW, BIP158 discovery, full block
    /// retrieval and merkle/record verification; no host-provided Boolean can
    /// move an operation to `confirmed`.
    pub fn refresh_operation_spv(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        let check = self
            .config
            .observation_checks
            .iter()
            .find(|check| check.kind == ObservationKind::ConfirmedSpv)
            .cloned();
        if check
            .as_ref()
            .is_none_or(|check| check.mode == ObservationMode::Off)
        {
            return operation_json(&operation);
        }
        let mut receipt: Value = operation
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        let consignment_base64 = receipt["consignment_base64"].as_str().ok_or_else(|| {
            AccountError::new(
                "operation_not_observed",
                "SPV settlement requires an independently observed consignment",
            )
        })?;
        let consignment = base64::engine::general_purpose::STANDARD
            .decode(consignment_base64)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let verdict = self.scan_verify(&hex_encode(&consignment))?;
        let now_ms = unix_time_millis()?;
        let txid = operation.txid.as_deref().ok_or_else(|| {
            AccountError::new(
                "invalid_operation_state",
                "SPV operation has no transaction id",
            )
        })?;
        let verified = verdict["status"] == "verified";
        let failures = if verified {
            Vec::new()
        } else {
            vec![verdict["reason"]
                .as_str()
                .unwrap_or("multi-peer scan has not settled the transaction")]
        };
        self.persist_observation_receipts(
            txid,
            &[json!({
                "check_id": check.as_ref().map(|check| check.id.as_str()).unwrap_or("multi_peer_spv_confirmation"),
                "kind": ObservationKind::ConfirmedSpv,
                "mode": check.as_ref().map(|check| check.mode).unwrap_or(ObservationMode::Observe),
                "endpoint": Value::Null,
                "result": if verified { ObservationResult::Observed } else { ObservationResult::Unavailable },
                "started_at_ms": now_ms,
                "completed_at_ms": now_ms,
                "latency_ms": 0,
                "cached_at_ms": now_ms,
                "cache_age_ms": 0,
                "certificate_profile": Value::Null,
                "certificate_chain_fingerprints_sha256": [],
                "raw_byte_match": false,
                "detail": verdict,
                "failures": failures,
            })],
        )?;

        if verified {
            let delivered = receipt["consignment_delivered"] == true;
            let next = if delivered {
                OperationState::ConsignmentDelivered.as_str()
            } else {
                OperationState::Confirmed.as_str()
            };
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2, rejection_reason = NULL,
                 updated_at = ?3 WHERE operation_id = ?1",
                params![operation_id, next, unix_time()?],
            )?;
        } else if matches!(
            operation.state.as_str(),
            "confirmed" | "consignment_delivered"
        ) {
            // Reorgs do not erase history. They demote settlement, freeze
            // descendants through the exact parent dependency, and require a
            // refreshed backup before any new write.
            self.freeze_unconfirmed_dependency(
                txid,
                "previously settled transaction is no longer in the verified scan",
            )?;
            let delivered = receipt["consignment_delivered"] == true;
            receipt["spv_reorg_detected"] = json!(true);
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3,
                 rejection_reason = 'spv_reorg_unsettled', updated_at = ?4
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    if delivered {
                        "mempool"
                    } else {
                        "broadcast_unobserved"
                    },
                    receipt.to_string(),
                    unix_time()?,
                ],
            )?;
            self.db.set_meta("backup_verified", "0")?;
        }
        let mut value = operation_json(&self.operation(operation_id)?)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("spv".into(), verdict);
        }
        Ok(value)
    }

    /// Resume a crash-interrupted operation. Signed transactions are
    /// rebroadcast idempotently; earlier states are returned for the caller
    /// to continue with backup acknowledgement or signing.
    pub fn resume_operation(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        match operation.state.as_str() {
            "signed_persisted" | "broadcast_unobserved" => {
                let signed = operation.signed_tx_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "signed state has no transaction")
                })?;
                let tx: Transaction = deserialize(&hex_decode(signed, "signed transaction")?)
                    .map_err(|error| {
                        AccountError::new("database_corrupt", format!("signed tx: {error}"))
                    })?;
                let mut receipt: Value = operation
                    .receipt_json
                    .as_deref()
                    .and_then(|encoded| serde_json::from_str(encoded).ok())
                    .unwrap_or_else(|| json!({}));
                if let Some(value) = self.reconcile_confirmed_replacement(
                    operation_id,
                    tx.compute_txid(),
                    &mut receipt,
                )? {
                    return Ok(value);
                }
                let (p2p_submissions, _) = self.submit_direct_p2p(&tx)?;
                let client =
                    esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
                let fallback = relay_via_esplora_if_unobserved(&client, &tx);
                if let Some(object) = receipt.as_object_mut() {
                    object.insert("resume_p2p_submissions".into(), json!(p2p_submissions));
                    object.insert(
                        "resume_generic_relay_fallback".into(),
                        json!(matches!(&fallback, Ok(true))),
                    );
                    if let Err(error) = &fallback {
                        object.insert(
                            "resume_generic_relay_error".into(),
                            json!(error.to_string()),
                        );
                    }
                }
                self.db.conn.execute(
                    "UPDATE opencsv_operations SET receipt_json = ?2,
                     updated_at = ?3 WHERE operation_id = ?1",
                    params![operation_id, receipt.to_string(), unix_time()?],
                )?;
                operation_json(&self.operation(operation_id)?)
            }
            _ => self.operation_status(operation_id),
        }
    }

    fn reconcile_confirmed_replacement(
        &mut self,
        operation_id: &str,
        replacement_txid: Txid,
        receipt: &mut Value,
    ) -> Result<Option<Value>, AccountError> {
        let Some(replaced) = receipt
            .get("replaces")
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<Txid>().ok())
        else {
            return Ok(None);
        };
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let status = client
            .get_tx_status(&replaced)
            .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
        if !status.confirmed {
            return Ok(None);
        }
        let original = match self.bitcoin.get_tx(replaced) {
            Some(transaction) => transaction.tx_node.tx.as_ref().clone(),
            None => client
                .get_tx(&replaced)
                .map_err(|error| AccountError::new("sync_failed", error.to_string()))?
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "confirmed pre-replacement transaction bytes are unavailable",
                    )
                })?,
        };
        if original.compute_txid() != replaced {
            return Err(AccountError::new(
                "database_corrupt",
                "confirmed pre-replacement transaction has the wrong txid",
            ));
        }
        let original_hex = hex_encode(&serialize(&original));
        if let Some(object) = receipt.as_object_mut() {
            object.insert(
                "fee_bump_outcome".into(),
                json!("original_confirmed_before_replacement_observed"),
            );
            object.insert(
                "failed_replacement_txid".into(),
                json!(replacement_txid.to_string()),
            );
            object.insert("txid".into(), json!(replaced.to_string()));
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, signed_tx_hex = ?3,
             txid = ?4, receipt_json = ?5, rejection_reason = NULL,
             updated_at = ?6 WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::Confirmed.as_str(),
                original_hex,
                replaced.to_string(),
                receipt.to_string(),
                unix_time()?,
            ],
        )?;
        let mut value = operation_json(&self.operation(operation_id)?)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("confirmed".into(), json!(true));
            object.insert("block_height".into(), json!(status.block_height));
            object.insert("observed_via".into(), json!(self.config.esplora_url));
        }
        Ok(Some(value))
    }

    /// Cancel an operation before broadcast and release its fee UTXO.
    pub fn cancel_operation(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if matches!(
            operation.state.as_str(),
            "broadcast_unobserved"
                | "broadcast"
                | "mempool"
                | "confirmed"
                | "consignment_delivered"
                | "protocol_rejected"
        ) {
            return Err(AccountError::new(
                "cancellation_forbidden",
                "an operation cannot be cancelled after a broadcast attempt",
            ));
        }
        if operation.state == OperationState::Cancelled.as_str() {
            return operation_json(&operation);
        }
        if let Some(pending_id) = self.pending_by_operation.remove(operation_id) {
            if let Some(protocol) = self.protocol.as_mut() {
                protocol.cancel_pending(pending_id);
            }
        }
        self.release_fee_reservation(operation_id)?;
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::Cancelled.as_str(),
                unix_time()?,
            ],
        )?;
        self.operation_status(operation_id)
    }

    /// Build a protocol-safe RBF replacement. The record, marker, change
    /// destination, context-defining vin[0], and output positions are
    /// validated again before the signed replacement is persisted.
    pub fn fee_bump(
        &mut self,
        operation_id: &str,
        target_sat_per_vb: u64,
    ) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        if target_sat_per_vb == 0 {
            return Err(AccountError::new(
                "invalid_fee_policy",
                "target_sat_per_vb must be positive",
            ));
        }
        let operation = self.operation(operation_id)?;
        if !matches!(
            operation.state.as_str(),
            "broadcast_unobserved" | "broadcast" | "mempool"
        ) {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!("cannot fee-bump {}", operation.state),
            ));
        }
        let original_hex = operation.signed_tx_hex.as_deref().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation has no signed transaction")
        })?;
        let original: Transaction =
            deserialize(&hex_decode(original_hex, "signed transaction")?)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let original_txid = original.compute_txid();
        let original_last_seen = self.bitcoin.get_tx(original_txid).and_then(|transaction| {
            match transaction.chain_position {
                ChainPosition::Unconfirmed { last_seen, .. } => last_seen,
                ChainPosition::Confirmed { .. } => None,
            }
        });
        let funding_outpoint = operation_outpoint(&operation)?;
        let funding_transaction = self.bitcoin.get_tx(funding_outpoint.txid).ok_or_else(|| {
            AccountError::new(
                "stale_chain_state",
                "fee-bump funding transaction is absent from the wallet graph",
            )
        })?;
        let funding_txout = funding_transaction
            .tx_node
            .tx
            .output
            .get(funding_outpoint.vout as usize)
            .cloned()
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "fee-bump funding vout is outside its transaction",
                )
            })?;
        let funding_birth_height = match &funding_transaction.chain_position {
            ChainPosition::Confirmed {
                anchor,
                transitively: None,
            } => u64::from(anchor.block_id.height),
            _ => {
                return Err(AccountError::new(
                    "stale_chain_state",
                    "fee-bump funding output lacks an exact confirmed birth height",
                ));
            }
        };
        let funding = ReservedFunding {
            outpoint: funding_outpoint,
            txout: funding_txout,
            birth_height: funding_birth_height,
        };
        let verification = match self.verify_funding(&funding) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.reject_operation(operation_id, error.code)?;
                return Err(error);
            }
        };
        let fee_rate = FeeRate::from_sat_per_vb(target_sat_per_vb).ok_or_else(|| {
            AccountError::new("invalid_fee_policy", "fee rate exceeds Bitcoin limits")
        })?;
        let mut builder = self
            .bitcoin
            .build_fee_bump(original_txid)
            .map_err(|error| AccountError::new("fee_bump_rejected", error.to_string()))?;
        builder.ordering(TxOrdering::Untouched);
        builder.drain_to(original.output[2].script_pubkey.clone());
        // The product path bumps by reducing protected change. Adding a new
        // input would require another independently verified durable
        // reservation, so general wallet coin selection is forbidden here.
        builder.manually_selected_only();
        builder.fee_rate(fee_rate);
        let mut psbt = builder
            .finish()
            .map_err(|error| AccountError::new("insufficient_fees", error.to_string()))?;
        let finalized = self
            .bitcoin
            .sign(&mut psbt, SignOptions::default())
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        if !finalized {
            return Err(AccountError::new(
                "signing_failed",
                "fee-bump PSBT was not finalized",
            ));
        }
        let replacement = psbt
            .extract_tx()
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        let validation = validate_solo_anchor_replacement(&original, &replacement)
            .map_err(|reason| AccountError::new(reason.code(), reason.to_string()))?;
        let replacement_txid = replacement.compute_txid();
        let replacement_hex = hex_encode(&serialize(&replacement));
        let mut receipt: Value = operation
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        let receipt_object = receipt.as_object_mut().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation receipt is not an object")
        })?;
        receipt_object.insert("operation_id".into(), json!(operation_id));
        receipt_object.insert("replaces".into(), json!(original_txid.to_string()));
        receipt_object.insert("txid".into(), json!(replacement_txid.to_string()));
        receipt_object.insert("target_sat_per_vb".into(), json!(target_sat_per_vb));
        receipt_object.insert(
            "fee_increment_sats".into(),
            json!(validation.fee_increment_sats),
        );
        receipt_object.insert(
            "replacement_change_sats".into(),
            json!(validation.replacement_change_sats),
        );
        receipt_object.insert("funding_verification".into(), json!(verification));
        receipt_object.insert("record_vout".into(), json!(0));
        receipt_object.insert("marker_vout".into(), json!(1));
        receipt_object.insert("change_vout".into(), json!(2));
        self.persist_signed_replacement(
            operation_id,
            &replacement_hex,
            replacement_txid,
            &mut receipt,
        )?;
        let now = u64::try_from(unix_time()?)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        let seen_at = original_last_seen
            .and_then(|last_seen| last_seen.checked_add(1))
            .map_or(now, |next| next.max(now));
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(replacement.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&replacement)?;
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let generic_relay_fallback = relay_via_esplora_if_unobserved(&client, &replacement);
        if let Some(object) = receipt.as_object_mut() {
            object.insert("p2p_submissions".into(), json!(p2p_submissions));
            object.insert("p2p_peers".into(), json!(relay_peers));
            object.insert(
                "generic_relay_fallback".into(),
                json!(matches!(&generic_relay_fallback, Ok(true))),
            );
            if let Err(error) = &generic_relay_fallback {
                object.insert("generic_relay_error".into(), json!(error.to_string()));
            }
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3,
             updated_at = ?4
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::BroadcastUnobserved.as_str(),
                receipt.to_string(),
                unix_time()?,
            ],
        )?;
        operation_json(&self.operation(operation_id)?)
    }

    /// Mark the Signal attachment for a mempool-observed operation delivered.
    /// `delivery_nonce` makes retries idempotent and prevents attachment
    /// replay from acknowledging a different operation.
    pub fn mark_consignment_delivered(
        &mut self,
        operation_id: &str,
        delivery_nonce: &str,
    ) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if operation.delivery_nonce != delivery_nonce {
            return Err(AccountError::new(
                "delivery_nonce_mismatch",
                "delivery acknowledgement belongs to another operation",
            ));
        }
        let mut receipt: Value = operation
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        if operation.state == OperationState::ConsignmentDelivered.as_str()
            || receipt["consignment_delivered"] == true
        {
            return operation_json(&operation);
        }
        if !matches!(operation.state.as_str(), "mempool" | "confirmed") {
            return Err(AccountError::new(
                "delivery_too_early",
                "consignment delivery starts only after transaction observation",
            ));
        }
        let receipt_object = receipt.as_object_mut().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation receipt is not an object")
        })?;
        receipt_object.insert("consignment_delivered".into(), json!(true));
        receipt_object.insert("consignment_delivered_at".into(), json!(unix_time()?));
        // Delivery and chain settlement are independent. Keep a delivered
        // mempool transaction fee-bumpable; it becomes the terminal
        // consignment_delivered state only after confirmation.
        let next_state = if operation.state == OperationState::Confirmed.as_str() {
            OperationState::ConsignmentDelivered.as_str()
        } else {
            OperationState::Mempool.as_str()
        };
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3,
             updated_at = ?4
             WHERE operation_id = ?1",
            params![operation_id, next_state, receipt.to_string(), unix_time()?,],
        )?;
        operation_json(&self.operation(operation_id)?)
    }

    /// Set the current Secure Backup policy state. Disabling backup freezes
    /// all new Bitcoin-writing operations but preserves read and receive.
    pub fn set_backup_state(
        &mut self,
        verified: bool,
        checkpoint_version: u32,
    ) -> Result<Value, AccountError> {
        if verified && checkpoint_version != CHECKPOINT_VERSION {
            return Err(AccountError::new(
                "backup_version_mismatch",
                format!("expected checkpoint version {CHECKPOINT_VERSION}"),
            ));
        }
        self.db
            .set_meta("backup_verified", if verified { "1" } else { "0" })?;
        self.db
            .set_meta("backup_checkpoint_version", &checkpoint_version.to_string())?;
        Ok(json!({
            "backup_verified": verified,
            "write_enabled": self.write_enabled()?,
        }))
    }

    /// Export a compact, versioned Secure Backup checkpoint. The BDK chain
    /// graph is deliberately absent because it is rebuildable cache data.
    pub fn checkpoint(&self) -> Result<Value, AccountError> {
        let assets = query_json_rows(
            &self.db.conn,
            "SELECT json_object('asset_index', asset_index, 'currency', currency,
                                'terms_hash', terms_hash, 'nonce', nonce,
                                'asset_id', asset_id)
             FROM opencsv_assets ORDER BY asset_index",
        )?;
        let instrument_manifests = query_json_rows(
            &self.db.conn,
            "SELECT json(manifest_json)
             FROM opencsv_instrument_manifests ORDER BY created_at",
        )?;
        let mut operations = query_json_rows(
            &self.db.conn,
            "SELECT json_object('operation_id', operation_id, 'kind', kind,
                                'state', state, 'request', json(request_json),
                                'pending_json', pending_json,
                                'delivery_nonce', delivery_nonce,
                                'txid', txid, 'receipt_json', receipt_json,
                                'rejection_reason', rejection_reason,
                                'checkpoint_hash', checkpoint_hash,
                                'backup_acked', backup_acked)
             FROM opencsv_operations
             WHERE state NOT IN ('cancelled') ORDER BY created_at, rowid",
        )?;
        // Backup acknowledgement metadata cannot be part of the checkpoint it
        // acknowledges. Likewise, the receipt's copy of checkpoint_hash is a
        // presentation field, not compact recovery state. Canonicalizing those
        // self-references makes the checkpoint emitted by prepare exportable
        // byte-for-byte both before and after acknowledgement.
        for operation in &mut operations {
            let Some(object) = operation.as_object_mut() else {
                continue;
            };
            object.insert("checkpoint_hash".into(), Value::Null);
            object.insert("backup_acked".into(), json!(0));
            if let Some(Value::String(encoded)) = object.get_mut("receipt_json") {
                if let Ok(mut receipt) = serde_json::from_str::<Value>(encoded) {
                    if let Some(receipt) = receipt.as_object_mut() {
                        receipt.remove("checkpoint_hash");
                    }
                    *encoded = receipt.to_string();
                }
            }
        }
        let consignments = query_json_rows(
            &self.db.conn,
            "SELECT json_object('consignment_id', consignment_id,
                                'consignment_base64', consignment_base64,
                                'spent_state', json(spent_state_json),
                                'snapshot', CASE WHEN snapshot_json IS NULL
                                                 THEN NULL ELSE json(snapshot_json) END,
                                'finality', finality,
                                'anchor_txid', anchor_txid)
             FROM opencsv_consignments
             LEFT JOIN opencsv_consignment_snapshots USING(consignment_id)
             LEFT JOIN opencsv_consignment_finality USING(consignment_id)
             ORDER BY created_at",
        )?;
        let owners = self
            .protocol
            .as_ref()
            .map(MemWallet::owners)
            .or_else(|| self.config.watch_owner.clone().map(|owner| vec![owner]))
            .unwrap_or_default();
        let payload = json!({
            "version": CHECKPOINT_VERSION,
            "network": self.config.network,
            "root_fingerprint": self.root_fingerprint,
            "device_binding_commitment": self.device_binding_commitment,
            "owners": owners,
            "assets": assets,
            "instrument_manifests": instrument_manifests,
            "operations": operations,
            "consignments": consignments,
        });
        let canonical = serde_json::to_vec(&payload)
            .map_err(|error| AccountError::new("checkpoint_failed", error.to_string()))?;
        Ok(json!({
            "checkpoint": payload,
            "checkpoint_hash": sha256::Hash::hash(&canonical).to_string(),
        }))
    }

    /// Confirm that the exact current issuer checkpoint has been stored by an
    /// external backup system. This is available only to the opt-in headless
    /// issuer tooling; Signal uses its native Secure Backup acknowledgement.
    #[cfg(any(test, feature = "issuer-tools"))]
    pub fn acknowledge_checkpoint_backup(
        &mut self,
        checkpoint_hash: &str,
    ) -> Result<Value, AccountError> {
        let checkpoint = self.checkpoint()?;
        let current_hash = checkpoint["checkpoint_hash"].as_str().ok_or_else(|| {
            AccountError::new("checkpoint_failed", "current checkpoint has no hash")
        })?;
        if checkpoint_hash != current_hash {
            return Err(AccountError::new(
                "backup_checkpoint_mismatch",
                "external backup acknowledged a stale or different issuer checkpoint",
            ));
        }
        self.set_backup_state(true, CHECKPOINT_VERSION)?;
        Ok(json!({
            "backup_verified": true,
            "checkpoint_hash": current_hash,
            "write_enabled": self.write_enabled()?,
        }))
    }

    /// Import the exact compact state recovered by Signal Secure Backup.
    /// The account root must already have opened this clean database and the
    /// public device-binding commitment must match the checkpoint. A restored
    /// phone remains read/export-only: importing state never manufactures or
    /// replaces the non-migratable device binding.
    pub fn restore_checkpoint(&mut self, checkpoint_json: &str) -> Result<Value, AccountError> {
        if self.config.role != AccountRole::Primary {
            return Err(AccountError::new(
                "primary_required",
                "linked devices restore public watch state through provisioning",
            ));
        }
        let envelope_value: Value = serde_json::from_str(checkpoint_json)
            .map_err(|error| AccountError::new("invalid_backup_checkpoint", error.to_string()))?;
        let checkpoint_value = envelope_value.get("checkpoint").cloned().ok_or_else(|| {
            AccountError::new("invalid_backup_checkpoint", "missing checkpoint payload")
        })?;
        let envelope: BackupCheckpointEnvelope = serde_json::from_value(envelope_value)
            .map_err(|error| AccountError::new("invalid_backup_checkpoint", error.to_string()))?;
        let canonical = serde_json::to_vec(&checkpoint_value)
            .map_err(|error| AccountError::new("invalid_backup_checkpoint", error.to_string()))?;
        let actual_hash = sha256::Hash::hash(&canonical).to_string();
        if actual_hash != envelope.checkpoint_hash {
            return Err(AccountError::new(
                "backup_checkpoint_hash_mismatch",
                "Secure Backup checkpoint hash does not match its payload",
            ));
        }
        if envelope.checkpoint.version != CHECKPOINT_VERSION {
            return Err(AccountError::new(
                "backup_version_mismatch",
                format!("expected checkpoint version {CHECKPOINT_VERSION}"),
            ));
        }
        if envelope.checkpoint.network != self.config.network {
            return Err(AccountError::new(
                "backup_network_mismatch",
                "Secure Backup checkpoint belongs to another Bitcoin network",
            ));
        }
        if envelope.checkpoint.root_fingerprint != self.root_fingerprint {
            return Err(AccountError::new(
                "account_key_mismatch",
                "Secure Backup checkpoint belongs to another account root",
            ));
        }
        if envelope.checkpoint.device_binding_commitment != self.device_binding_commitment {
            return Err(AccountError::new(
                "device_binding_mismatch",
                "Secure Backup checkpoint names a different device binding",
            ));
        }
        let expected_owners = self
            .protocol
            .as_ref()
            .map(MemWallet::owners)
            .unwrap_or_default();
        if envelope.checkpoint.owners != expected_owners {
            return Err(AccountError::new(
                "account_key_mismatch",
                "Secure Backup owner identity does not derive from this account root",
            ));
        }
        if let Some(existing) = self.db.meta("restored_checkpoint_hash")? {
            if existing == actual_hash {
                return self.status();
            }
            return Err(AccountError::new(
                "conflicting_backup_checkpoint",
                "a different Secure Backup checkpoint was already imported",
            ));
        }
        let occupied: i64 = self.db.conn.query_row(
            "SELECT (SELECT COUNT(*) FROM opencsv_assets)
                  + (SELECT COUNT(*) FROM opencsv_instrument_manifests)
                  + (SELECT COUNT(*) FROM opencsv_operations)
                  + (SELECT COUNT(*) FROM opencsv_consignments)",
            [],
            |row| row.get(0),
        )?;
        if occupied != 0 {
            return Err(AccountError::new(
                "restore_requires_clean_database",
                "refusing to merge a Secure Backup checkpoint into existing wallet state",
            ));
        }

        for asset in &envelope.checkpoint.assets {
            decode_hex_32(&asset.terms_hash, "terms hash")?;
            decode_hex_32(&asset.asset_id, "asset id")?;
            i64::try_from(asset.nonce).map_err(|_| {
                AccountError::new(
                    "invalid_backup_checkpoint",
                    "asset nonce exceeds SQLite i64",
                )
            })?;
        }
        for manifest in &envelope.checkpoint.instrument_manifests {
            manifest.validate().map_err(|error| {
                AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("instrument manifest: {error}"),
                )
            })?;
            if manifest.terms.network != envelope.checkpoint.network {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "instrument manifest belongs to another network",
                ));
            }
            let asset_id = hex_encode(manifest.genesis.asset_id().as_bytes());
            let terms_hash = hex_encode(manifest.genesis.terms_hash.as_bytes());
            let matching_asset = envelope
                .checkpoint
                .assets
                .iter()
                .find(|asset| asset.asset_id == asset_id)
                .ok_or_else(|| {
                    AccountError::new(
                        "invalid_backup_checkpoint",
                        "instrument manifest has no matching asset genesis",
                    )
                })?;
            if matching_asset.currency != manifest.terms.unit_code
                || matching_asset.terms_hash != terms_hash
                || matching_asset.nonce != manifest.genesis.nonce
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "instrument manifest disagrees with its checkpoint asset",
                ));
            }
        }
        for operation in &envelope.checkpoint.operations {
            if !matches!(
                operation.state.as_str(),
                "planned"
                    | "fee_reserved"
                    | "proof_ready"
                    | "signed_persisted"
                    | "broadcast_unobserved"
                    | "broadcast"
                    | "mempool"
                    | "confirmed"
                    | "consignment_delivered"
                    | "rejected"
                    | "cancelled"
            ) {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("unknown operation state {}", operation.state),
                ));
            }
        }
        for consignment in &envelope.checkpoint.consignments {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(&consignment.consignment_base64)
                .map_err(|error| {
                    AccountError::new("invalid_backup_checkpoint", error.to_string())
                })?;
            let (_, canonical_id) = canonical_consignment_identity(&blob)?;
            if canonical_id != consignment.consignment_id {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "consignment identity does not match canonical bytes",
                ));
            }
            if let Some(snapshot) = &consignment.snapshot {
                SnapshotChain::from_json(&snapshot.to_string())
                    .map_err(|error| AccountError::new("invalid_backup_checkpoint", error))?;
            }
            if let Some(finality) = consignment.finality.as_deref() {
                if !matches!(finality, "unconfirmed" | "settled" | "frozen") {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        format!("unknown consignment finality {finality}"),
                    ));
                }
                if consignment.anchor_txid.is_none() {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        "consignment finality is missing its anchor txid",
                    ));
                }
            }
        }

        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let imported = (|| -> Result<(), AccountError> {
            let now = unix_time()?;
            for asset in &envelope.checkpoint.assets {
                self.db.conn.execute(
                    "INSERT INTO opencsv_assets(
                         asset_index, currency, terms_hash, nonce, asset_id
                     ) VALUES(?1, ?2, ?3, ?4, ?5)",
                    params![
                        asset.asset_index,
                        asset.currency,
                        asset.terms_hash,
                        i64::try_from(asset.nonce).map_err(|_| AccountError::new(
                            "invalid_backup_checkpoint",
                            "asset nonce exceeds SQLite i64",
                        ))?,
                        asset.asset_id,
                    ],
                )?;
            }
            for manifest in &envelope.checkpoint.instrument_manifests {
                let asset_id = hex_encode(manifest.genesis.asset_id().as_bytes());
                let manifest_json = serde_json::to_string(manifest).map_err(|error| {
                    AccountError::new("invalid_backup_checkpoint", error.to_string())
                })?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_instrument_manifests(
                         asset_id, manifest_json, created_at
                     ) VALUES(?1, ?2, ?3)",
                    params![asset_id, manifest_json, now],
                )?;
            }
            for operation in &envelope.checkpoint.operations {
                self.db.conn.execute(
                    "INSERT INTO opencsv_operations(
                         operation_id, kind, state, request_json, pending_json,
                         txid, receipt_json, rejection_reason, delivery_nonce,
                         checkpoint_hash, backup_acked, created_at, updated_at
                     ) VALUES(
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12
                     )",
                    params![
                        operation.operation_id,
                        operation.kind,
                        operation.state,
                        operation.request.to_string(),
                        operation.pending_json,
                        operation.txid,
                        operation.receipt_json,
                        operation.rejection_reason,
                        operation.delivery_nonce,
                        operation.checkpoint_hash,
                        operation.backup_acked,
                        now,
                    ],
                )?;
            }
            for consignment in &envelope.checkpoint.consignments {
                self.db.conn.execute(
                    "INSERT INTO opencsv_consignments(
                         consignment_id, consignment_base64, spent_state_json, created_at
                     ) VALUES(?1, ?2, ?3, ?4)",
                    params![
                        consignment.consignment_id,
                        consignment.consignment_base64,
                        consignment.spent_state.to_string(),
                        now,
                    ],
                )?;
                if let Some(snapshot) = &consignment.snapshot {
                    self.db.conn.execute(
                        "INSERT INTO opencsv_consignment_snapshots(
                             consignment_id, snapshot_json
                         ) VALUES(?1, ?2)",
                        params![consignment.consignment_id, snapshot.to_string()],
                    )?;
                }
                if let (Some(finality), Some(anchor_txid)) =
                    (&consignment.finality, &consignment.anchor_txid)
                {
                    self.db.conn.execute(
                        "INSERT INTO opencsv_consignment_finality(
                             consignment_id, anchor_txid, finality, observed_at,
                             last_checked_at, last_error
                         ) VALUES(?1, ?2, ?3, ?4, ?4, NULL)",
                        params![consignment.consignment_id, anchor_txid, finality, now],
                    )?;
                }
            }
            self.db.set_meta("backup_verified", "1")?;
            self.db
                .set_meta("backup_checkpoint_version", &CHECKPOINT_VERSION.to_string())?;
            self.db.set_meta("restored_checkpoint_hash", &actual_hash)?;
            #[cfg(any(test, feature = "issuer-tools"))]
            self.restore_issuers()?;
            self.restore_consignment_state()?;
            Ok(())
        })();
        match imported {
            Ok(()) => self.db.conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        self.status()
    }

    fn require_write_enabled(&self) -> Result<(), AccountError> {
        if self.config.role != AccountRole::Primary {
            return Err(AccountError::new(
                "primary_required",
                "linked devices are watch-only",
            ));
        }
        if !self.device_binding_valid {
            return Err(AccountError::new(
                "device_binding_mismatch",
                "this restored device is read/export-only until explicit wallet recovery",
            ));
        }
        if !self.backup_verified()? {
            return Err(AccountError::new(
                "backup_required",
                "verified Signal Secure Backup is required for Bitcoin-writing operations",
            ));
        }
        Ok(())
    }

    fn primary_protocol_mut(&mut self) -> Result<&mut MemWallet, AccountError> {
        self.protocol.as_mut().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices cannot sign or mint")
        })
    }

    fn verify_funding(
        &self,
        funding: &ReservedFunding,
    ) -> Result<FundingVerificationReceipt, AccountError> {
        self.funding_verifier.verify(&FundingVerificationRequest {
            outpoint: funding.outpoint,
            txout: funding.txout.clone(),
            birth_height: funding.birth_height,
        })
    }

    fn insert_planned_operation(
        &self,
        operation_id: &str,
        kind: &str,
        request_json: &str,
        delivery_nonce: &str,
    ) -> Result<(), AccountError> {
        let _: Value = serde_json::from_str(request_json).map_err(|error| {
            AccountError::new("invalid_request", format!("request JSON: {error}"))
        })?;
        let now = unix_time()?;
        self.db.conn.execute(
            "INSERT INTO opencsv_operations(
                 operation_id, kind, state, request_json, delivery_nonce,
                 created_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                operation_id,
                kind,
                OperationState::Planned.as_str(),
                request_json,
                delivery_nonce,
                now,
            ],
        )?;
        Ok(())
    }

    fn reserve_fee_utxo(&mut self, operation_id: &str) -> Result<ReservedFunding, AccountError> {
        let mut candidates = Vec::new();
        for output in self.bitcoin.list_unspent() {
            if self.bitcoin.is_outpoint_locked(output.outpoint)
                || output.txout.value.to_sat() < MIN_FEE_RESERVE_SATS
            {
                continue;
            }
            if let Ok(funding) = ReservedFunding::from_local(output) {
                candidates.push(funding);
            }
        }
        candidates.sort_by_key(|funding| std::cmp::Reverse(funding.value_sats()));
        if candidates.is_empty() {
            return Err(AccountError::new(
                "insufficient_fees",
                format!(
                    "no confirmed, unreserved fee UTXO of at least {MIN_FEE_RESERVE_SATS} sats"
                ),
            ));
        }

        let now = unix_time()?;
        let mut saw_conflict = false;
        for funding in candidates {
            let transaction = self
                .db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO opencsv_utxo_reservations(
                     txid, vout, operation_id, state, created_at
                 ) VALUES(?1, ?2, ?3, 'reserved', ?4)",
                params![
                    funding.outpoint.txid.to_string(),
                    funding.outpoint.vout,
                    operation_id,
                    now,
                ],
            )?;
            if inserted == 0 {
                saw_conflict = true;
                continue;
            }
            transaction.execute(
                "UPDATE opencsv_operations SET state = ?2, funding_txid = ?3,
                 funding_vout = ?4, funding_value_sats = ?5, updated_at = ?6
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::FeeReserved.as_str(),
                    funding.outpoint.txid.to_string(),
                    funding.outpoint.vout,
                    i64::try_from(funding.value_sats()).map_err(|_| {
                        AccountError::new("database_error", "funding value exceeds SQLite range")
                    })?,
                    now,
                ],
            )?;
            transaction.commit()?;
            self.bitcoin.lock_outpoint(funding.outpoint);
            self.bitcoin.persist(&mut self.db)?;
            return Ok(funding);
        }

        Err(AccountError::new(
            if saw_conflict {
                "conflicting_operation"
            } else {
                "insufficient_fees"
            },
            "every eligible fee UTXO is already reserved by another operation",
        ))
    }

    fn reserved_funding_for_operation(
        &self,
        operation: &OperationRow,
    ) -> Result<ReservedFunding, AccountError> {
        let outpoint = operation_outpoint(operation)?;
        if !self.bitcoin.is_outpoint_locked(outpoint) {
            return Err(AccountError::new(
                "conflicting_operation",
                "funding outpoint lost its durable reservation",
            ));
        }
        let output = self
            .bitcoin
            .list_unspent()
            .find(|output| output.outpoint == outpoint)
            .ok_or_else(|| {
                AccountError::new(
                    "stale_chain_state",
                    "reserved funding outpoint is no longer unspent",
                )
            })?;
        ReservedFunding::from_local(output)
    }

    fn release_fee_reservation(&mut self, operation_id: &str) -> Result<(), AccountError> {
        let operation = self.operation(operation_id)?;
        if let (Some(txid), Some(vout)) = (operation.funding_txid, operation.funding_vout) {
            let txid = Txid::from_str(&txid).map_err(|error| {
                AccountError::new("database_corrupt", format!("funding txid: {error}"))
            })?;
            self.bitcoin.unlock_outpoint(OutPoint::new(txid, vout));
            self.bitcoin.persist(&mut self.db)?;
        }
        self.db.conn.execute(
            "DELETE FROM opencsv_utxo_reservations WHERE operation_id = ?1",
            [operation_id],
        )?;
        Ok(())
    }

    #[cfg(any(test, feature = "issuer-tools"))]
    fn create_instrument(
        &mut self,
        terms: InstrumentTermsV1,
    ) -> Result<(String, InstrumentManifestV1), AccountError> {
        let terms_hash = terms.terms_hash().map_err(|error| {
            AccountError::new("invalid_instrument_definition", error.to_string())
        })?;
        let next_index: u32 = self.db.conn.query_row(
            "SELECT COALESCE(MAX(asset_index) + 1, 0) FROM opencsv_assets",
            [],
            |row| row.get(0),
        )?;
        let issuer_root = self.issuer_root.as_ref().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices cannot create assets")
        })?;
        let seed = derive::<32>(
            issuer_root.as_ref(),
            b"opencsv-asset-issuer-v1",
            &next_index.to_be_bytes(),
        )?;
        let nonce = u64::from(next_index) + 1;
        let currency = terms.unit_code.clone();
        let genesis = AssetGenesis {
            issuer_pk: PoseidonIssuerAuthorization::public_key(&seed),
            currency_code: currency.as_bytes().try_into().map_err(|_| {
                AccountError::new(
                    "invalid_instrument_definition",
                    "unit code must be three bytes",
                )
            })?,
            terms_hash,
            nonce,
        };
        let manifest = InstrumentManifestV1 { terms, genesis };
        manifest.validate().map_err(|error| {
            AccountError::new("invalid_instrument_definition", error.to_string())
        })?;
        let expected_asset_id = hex_encode(manifest.genesis.asset_id().as_bytes());
        let asset_id = self
            .primary_protocol_mut()?
            .init_issuer_from_seed(&currency, seed, nonce, *terms_hash.as_bytes())
            .map_err(|error| AccountError::new("invalid_request", error))?;
        if asset_id != expected_asset_id {
            return Err(AccountError::new(
                "database_error",
                "derived issuer genesis disagrees with instrument manifest",
            ));
        }
        let manifest_json = serde_json::to_string(&manifest).map_err(|error| {
            AccountError::new(
                "database_error",
                format!("encode instrument manifest: {error}"),
            )
        })?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO opencsv_assets(
                 asset_index, currency, terms_hash, nonce, asset_id
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                next_index,
                currency,
                hex_encode(terms_hash.as_bytes()),
                i64::try_from(nonce).map_err(|_| {
                    AccountError::new("database_error", "asset nonce exceeds SQLite range")
                })?,
                asset_id,
            ],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_instrument_manifests(asset_id, manifest_json, created_at)
             VALUES(?1, ?2, ?3)",
            params![asset_id, manifest_json, unix_time()?],
        )?;
        transaction.commit()?;
        Ok((asset_id, manifest))
    }

    #[cfg(any(test, feature = "issuer-tools"))]
    fn is_manifested_instrument(&self, asset_id: &str) -> Result<bool, AccountError> {
        Ok(self
            .db
            .conn
            .query_row(
                "SELECT 1 FROM opencsv_instrument_manifests WHERE asset_id = ?1",
                [asset_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    fn instrument_records(&self) -> Result<Vec<Value>, AccountError> {
        let mut configured = self.config.usd_issuers.iter().collect::<Vec<_>>();
        configured.sort_by_key(|issuer| {
            (
                issuer.priority,
                hex_encode(issuer.manifest.genesis.asset_id().as_bytes()),
            )
        });
        let mut configured_ids = HashSet::new();
        let mut records = Vec::new();
        for issuer in configured {
            let asset_id = hex_encode(issuer.manifest.genesis.asset_id().as_bytes());
            configured_ids.insert(asset_id.clone());
            records.push(json!({
                "asset_id": asset_id,
                "trust_state": "trusted_configuration",
                "profile": "trusted_usd_v1",
                "issuer_priority": issuer.priority,
                "manifest": issuer.manifest,
            }));
        }

        let mut statement = self.db.conn.prepare(
            "SELECT a.asset_id, m.manifest_json
             FROM opencsv_assets a
             LEFT JOIN opencsv_instrument_manifests m USING(asset_id)
             ORDER BY a.asset_index",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })?;
        for row in rows {
            let (asset_id, manifest_json) = row?;
            if configured_ids.contains(&asset_id) {
                continue;
            }
            let manifest = manifest_json
                .map(|encoded| serde_json::from_str::<InstrumentManifestV1>(&encoded))
                .transpose()
                .map_err(|error| {
                    AccountError::new("database_corrupt", format!("instrument manifest: {error}"))
                })?;
            let profile = match &manifest {
                Some(_) => "untrusted_manifest",
                None => "legacy_prototype",
            };
            records.push(json!({
                "asset_id": asset_id,
                "trust_state": if manifest.is_some() { "untrusted" } else { "prototype" },
                "profile": profile,
                "issuer_priority": null,
                "manifest": manifest,
            }));
        }
        Ok(records)
    }

    fn mark_proof_ready(
        &self,
        operation_id: &str,
        normalized_request: &Value,
        pending_json: &str,
        record_hex: &str,
    ) -> Result<(), AccountError> {
        let receipt = json!({
            "anchor_record_hex": record_hex,
            "record_vout": 0,
            "marker_vout": 1,
            "change_vout": 2,
        });
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, request_json = ?3,
             pending_json = ?4, receipt_json = ?5, updated_at = ?6
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::ProofReady.as_str(),
                normalized_request.to_string(),
                pending_json,
                receipt.to_string(),
                unix_time()?,
            ],
        )?;
        Ok(())
    }

    fn prepared_receipt(
        &self,
        operation_id: &str,
        funding: ReservedFunding,
        verification: &FundingVerificationReceipt,
        record: &[u8; 64],
    ) -> Result<Value, AccountError> {
        let normalized_request: String = self.db.conn.query_row(
            "SELECT request_json FROM opencsv_operations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )?;
        let normalized_request: Value = serde_json::from_str(&normalized_request)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let mut receipt = json!({
            "operation_id": operation_id,
            "state": OperationState::ProofReady.as_str(),
            "funding_outpoint": funding.outpoint.to_string(),
            "funding_value_sats": funding.value_sats(),
            "funding_verification": verification,
            "anchor_record_hex": hex_encode(record),
            "asset_id": normalized_request.get("asset_id"),
            "to_owner": normalized_request.get("to_owner"),
            "backup_ack_required": true,
        });
        self.db.conn.execute(
            "UPDATE opencsv_operations SET checkpoint_hash = NULL,
             backup_acked = 0, receipt_json = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![operation_id, receipt.to_string(), unix_time()?],
        )?;
        let checkpoint = self.checkpoint()?;
        let checkpoint_hash = checkpoint["checkpoint_hash"]
            .as_str()
            .ok_or_else(|| AccountError::new("checkpoint_failed", "missing checkpoint hash"))?;
        receipt["checkpoint_hash"] = json!(checkpoint_hash);
        self.db.conn.execute(
            "UPDATE opencsv_operations SET checkpoint_hash = ?2, receipt_json = ?3,
             updated_at = ?4
             WHERE operation_id = ?1",
            params![
                operation_id,
                checkpoint_hash,
                receipt.to_string(),
                unix_time()?
            ],
        )?;
        Ok(receipt)
    }

    fn prepared_operation_receipt(&self, operation: &OperationRow) -> Result<Value, AccountError> {
        operation
            .receipt_json
            .as_deref()
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "proof-ready operation has no prepared receipt",
                )
            })
            .and_then(|encoded| {
                serde_json::from_str(encoded)
                    .map_err(|error| AccountError::new("database_corrupt", error.to_string()))
            })
    }

    fn reobserve_unconfirmed_dependencies(
        &mut self,
        dependencies: &[String],
    ) -> Result<(), AccountError> {
        if dependencies.is_empty() {
            return Ok(());
        }
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        for dependency in dependencies {
            let txid = dependency.parse::<Txid>().map_err(|error| {
                AccountError::new(
                    "database_corrupt",
                    format!("invalid unconfirmed dependency {dependency}: {error}"),
                )
            })?;
            let observed = client.get_tx(&txid).map_err(|error| {
                AccountError::new(
                    "unconfirmed_dependency_unavailable",
                    format!("could not re-observe parent {dependency}: {error}"),
                )
            })?;
            let now = unix_time()?;
            if observed.is_none() {
                self.freeze_unconfirmed_dependency(
                    dependency,
                    "exact parent transaction is no longer observed",
                )?;
                return Err(AccountError::new(
                    "unconfirmed_dependency_changed",
                    format!(
                        "zero-confirmation parent {dependency} disappeared or was replaced; dependent signing is frozen"
                    ),
                ));
            }
            self.db.conn.execute(
                "UPDATE opencsv_consignment_finality
                 SET last_checked_at = ?2, last_error = NULL
                 WHERE anchor_txid = ?1 AND finality = 'unconfirmed'",
                params![dependency, now],
            )?;
        }
        Ok(())
    }

    fn freeze_unconfirmed_dependency(
        &mut self,
        dependency: &str,
        reason: &str,
    ) -> Result<(), AccountError> {
        self.db.conn.execute(
            "UPDATE opencsv_consignment_finality
             SET finality = 'frozen', last_checked_at = ?2, last_error = ?3
             WHERE anchor_txid = ?1 AND finality != 'settled'",
            params![dependency, unix_time()?, reason],
        )?;
        if let Some(protocol) = self.protocol.as_mut() {
            protocol.freeze_unconfirmed_anchor(dependency);
        }
        Ok(())
    }

    fn reject_operation(&self, operation_id: &str, reason: &str) -> Result<(), AccountError> {
        self.db.conn.execute(
            "UPDATE opencsv_operations SET rejection_reason = ?2,
             updated_at = ?3 WHERE operation_id = ?1",
            params![operation_id, reason, unix_time()?],
        )?;
        Ok(())
    }

    fn reject_prebroadcast_operation(
        &mut self,
        operation_id: &str,
        reason: &str,
    ) -> Result<(), AccountError> {
        if let Some(pending_id) = self.pending_by_operation.remove(operation_id) {
            if let Some(protocol) = self.protocol.as_mut() {
                protocol.cancel_pending(pending_id);
            }
        }
        self.release_fee_reservation(operation_id)?;
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, rejection_reason = ?3,
             updated_at = ?4 WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::Cancelled.as_str(),
                reason,
                unix_time()?,
            ],
        )?;
        Ok(())
    }

    fn fail_prebroadcast<T>(
        &mut self,
        operation_id: &str,
        error: AccountError,
    ) -> Result<T, AccountError> {
        self.reject_prebroadcast_operation(operation_id, error.code)
            .map_err(|cleanup| {
                AccountError::new(
                    "database_error",
                    format!(
                        "{}; additionally failed to release the pre-broadcast operation: {}",
                        error, cleanup
                    ),
                )
            })?;
        Err(error)
    }

    fn operation(&self, operation_id: &str) -> Result<OperationRow, AccountError> {
        self.db
            .conn
            .query_row(
                "SELECT operation_id, kind, state, request_json,
                        funding_txid, funding_vout, signed_tx_hex, txid,
                        receipt_json, rejection_reason, delivery_nonce,
                        checkpoint_hash, backup_acked
                 FROM opencsv_operations WHERE operation_id = ?1",
                [operation_id],
                |row| {
                    let vout = row.get::<_, Option<i64>>(5)?;
                    Ok(OperationRow {
                        operation_id: row.get(0)?,
                        kind: row.get(1)?,
                        state: row.get(2)?,
                        request_json: row.get(3)?,
                        funding_txid: row.get(4)?,
                        funding_vout: vout.and_then(|value| u32::try_from(value).ok()),
                        signed_tx_hex: row.get(6)?,
                        txid: row.get(7)?,
                        receipt_json: row.get(8)?,
                        rejection_reason: row.get(9)?,
                        delivery_nonce: row.get(10)?,
                        checkpoint_hash: row.get(11)?,
                        backup_acked: row.get::<_, i64>(12)? != 0,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| {
                AccountError::new(
                    "unknown_operation",
                    format!("unknown operation {operation_id}"),
                )
            })
    }

    fn refresh_operation(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if self.config.observation_checks.iter().any(|check| {
            check.kind == ObservationKind::RawTransactionApi
                && check.mode == ObservationMode::Require
        }) && !matches!(
            operation.state.as_str(),
            "confirmed" | "consignment_delivered"
        ) {
            // The generic accelerator remains useful for fee-wallet sync but
            // cannot silently replace required pinned raw-byte evidence.
            return operation_json(&operation);
        }
        let txid = operation
            .txid
            .as_deref()
            .ok_or_else(|| AccountError::new("invalid_operation_state", "operation is unsigned"))?
            .parse::<Txid>()
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let observed = client
            .get_tx(&txid)
            .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
        if observed.is_none() {
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::BroadcastUnobserved.as_str(),
                    unix_time()?,
                ],
            )?;
            return operation_json(&self.operation(operation_id)?);
        }

        let status = client
            .get_tx_status(&txid)
            .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
        if !matches!(
            operation.state.as_str(),
            "mempool" | "confirmed" | "consignment_delivered"
        ) {
            let protocol_already_finalized = operation
                .receipt_json
                .as_deref()
                .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
                .is_some_and(|receipt| receipt["delivery_ready"] == true);
            if protocol_already_finalized {
                // An operation is finalized only against the exact txid in
                // its consignment. A fee replacement clears delivery_ready
                // before reaching this path, so the replacement is finalized
                // into fresh canonical bytes below. Reaching this branch
                // means this exact transaction already owns its consignment.
                self.db.conn.execute(
                    "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
                     WHERE operation_id = ?1",
                    params![operation_id, OperationState::Mempool.as_str(), unix_time()?,],
                )?;
            } else {
                self.finalize_observed_operation(operation_id, txid)?;
            }
        }
        let spv_settlement_enabled = self.config.observation_checks.iter().any(|check| {
            check.kind == ObservationKind::ConfirmedSpv && check.mode != ObservationMode::Off
        });
        if status.confirmed
            && !spv_settlement_enabled
            && operation.state != OperationState::ConsignmentDelivered.as_str()
        {
            let delivered = operation
                .receipt_json
                .as_deref()
                .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
                .is_some_and(|receipt| receipt["consignment_delivered"] == true);
            let confirmed_state = if delivered {
                OperationState::ConsignmentDelivered.as_str()
            } else {
                OperationState::Confirmed.as_str()
            };
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
                 WHERE operation_id = ?1",
                params![operation_id, confirmed_state, unix_time()?,],
            )?;
        }
        let mut value = operation_json(&self.operation(operation_id)?)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("confirmed".into(), json!(status.confirmed));
            object.insert("block_height".into(), json!(status.block_height));
            object.insert("observed_via".into(), json!(self.config.esplora_url));
        }
        Ok(value)
    }

    fn finalize_observed_operation(
        &mut self,
        operation_id: &str,
        txid: Txid,
    ) -> Result<(), AccountError> {
        let pending_id = *self
            .pending_by_operation
            .get(operation_id)
            .ok_or_else(|| AccountError::new("operation_not_resumable", "missing pending proof"))?;
        let anchor = AnchorRef {
            txid: txid.to_byte_array(),
            location: MEMPOOL_LOCATION,
        };
        let (consignment, spends) = self
            .primary_protocol_mut()?
            .finalize(pending_id, anchor)
            .map_err(|error| AccountError::new("operation_not_resumable", error))?;
        self.pending_by_operation.remove(operation_id);
        let consignment_id = sha256::Hash::hash(&consignment).to_string();
        let consignment_base64 = base64::engine::general_purpose::STANDARD.encode(&consignment);
        let now = unix_time()?;
        let transaction = self.db.conn.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO opencsv_consignments(
                 consignment_id, consignment_base64, spent_state_json, created_at
             ) VALUES(?1, ?2, ?3, ?4)",
            params![
                consignment_id,
                consignment_base64,
                json!({ "spends": spends }).to_string(),
                now,
            ],
        )?;
        let old_receipt: String = transaction.query_row(
            "SELECT COALESCE(receipt_json, '{}') FROM opencsv_operations
             WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )?;
        let mut receipt: Value = serde_json::from_str(&old_receipt).unwrap_or_else(|_| json!({}));
        if let Some(object) = receipt.as_object_mut() {
            object.insert("consignment_id".into(), json!(consignment_id));
            object.insert("consignment_base64".into(), json!(consignment_base64));
            object.insert("delivery_ready".into(), json!(true));
            object.remove("replacement_delivery_required");
        }
        transaction.execute(
            "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3,
             updated_at = ?4 WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::Mempool.as_str(),
                receipt.to_string(),
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Persist a signed RBF replacement and invalidate any consignment that
    /// named the replaced txid. `Consignment::anchor_ref` commits to the
    /// exact Bitcoin transaction, so carrying the old bytes forward would
    /// strand the receiver at `AnchorNotFound` even though the replacement
    /// preserved every protected OpenCSV output.
    ///
    /// The durable pending export is imported before the database moves back
    /// to `signed_persisted`. A crash after the transaction commits restores
    /// the same export through `restore_pending_operations`, allowing the
    /// replacement to be finalized exactly once it is independently
    /// observed.
    fn persist_signed_replacement(
        &mut self,
        operation_id: &str,
        replacement_hex: &str,
        replacement_txid: Txid,
        receipt: &mut Value,
    ) -> Result<(), AccountError> {
        if !self.pending_by_operation.contains_key(operation_id) {
            let pending_json = self
                .db
                .conn
                .query_row(
                    "SELECT pending_json FROM opencsv_operations WHERE operation_id = ?1",
                    [operation_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten()
                .ok_or_else(|| {
                    AccountError::new(
                        "operation_not_resumable",
                        "fee replacement has no durable pending proof export",
                    )
                })?;
            let pending_id = self
                .primary_protocol_mut()?
                .import_pending(&pending_json)
                .map_err(|error| AccountError::new("operation_not_resumable", error))?;
            self.pending_by_operation
                .insert(operation_id.to_owned(), pending_id);
        }

        let receipt_object = receipt.as_object_mut().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation receipt is not an object")
        })?;
        let stale_consignment_id = receipt_object
            .remove("consignment_id")
            .and_then(|value| value.as_str().map(str::to_owned));
        receipt_object.remove("consignment_base64");
        receipt_object.remove("delivery_ready");
        receipt_object.remove("consignment_delivered");
        receipt_object.remove("consignment_delivered_at");
        receipt_object.insert("replacement_delivery_required".into(), json!(true));
        if let Some(stale_id) = &stale_consignment_id {
            let superseded = receipt_object
                .entry("superseded_consignment_ids")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "superseded consignment list is not an array",
                    )
                })?;
            if !superseded
                .iter()
                .any(|value| value.as_str() == Some(stale_id))
            {
                superseded.push(json!(stale_id));
            }
        }

        let now = unix_time()?;
        let transaction = self.db.conn.transaction()?;
        if let Some(stale_id) = stale_consignment_id {
            transaction.execute(
                "DELETE FROM opencsv_consignment_snapshots WHERE consignment_id = ?1",
                [&stale_id],
            )?;
            transaction.execute(
                "DELETE FROM opencsv_consignments WHERE consignment_id = ?1",
                [&stale_id],
            )?;
        }
        transaction.execute(
            "UPDATE opencsv_operations SET state = ?2, signed_tx_hex = ?3,
             txid = ?4, receipt_json = ?5, updated_at = ?6
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::SignedPersisted.as_str(),
                replacement_hex,
                replacement_txid.to_string(),
                receipt.to_string(),
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn backup_verified(&self) -> Result<bool, AccountError> {
        Ok(self.db.meta("backup_verified")?.as_deref() == Some("1"))
    }

    fn write_enabled(&self) -> Result<bool, AccountError> {
        Ok(self.config.role == AccountRole::Primary
            && self.device_binding_valid
            && self.backup_verified()?)
    }

    fn owner_secrets(&self) -> Result<Vec<OwnerSecret>, AccountError> {
        self.protocol
            .as_ref()
            .map(MemWallet::owner_secrets)
            .ok_or_else(|| {
                AccountError::new(
                    "primary_required",
                    "linked device has no OpenCSV owner secret",
                )
            })
    }

    fn known_asset_ids(&self) -> Result<Vec<AssetId>, AccountError> {
        let mut asset_ids = self
            .protocol
            .as_ref()
            .map(MemWallet::known_asset_ids)
            .ok_or_else(|| {
                AccountError::new(
                    "primary_required",
                    "linked device cannot credit private OpenCSV ownership",
                )
            })?;
        for issuer in &self.config.usd_issuers {
            let asset_id = issuer.manifest.genesis.asset_id();
            if !asset_ids.contains(&asset_id) {
                asset_ids.push(asset_id);
            }
        }
        Ok(asset_ids)
    }

    #[cfg(any(test, feature = "issuer-tools"))]
    fn restore_issuers(&mut self) -> Result<(), AccountError> {
        let (Some(protocol), Some(issuer_root)) =
            (self.protocol.as_mut(), self.issuer_root.as_ref())
        else {
            return Ok(());
        };
        let mut statement = self.db.conn.prepare(
            "SELECT asset_index, currency, terms_hash, nonce, asset_id
             FROM opencsv_assets ORDER BY asset_index",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (index, currency, terms_hash, nonce, expected_id) = row?;
            let nonce = u64::try_from(nonce)
                .map_err(|_| AccountError::new("database_corrupt", "negative asset nonce"))?;
            let terms = decode_hex_32(&terms_hash, "terms hash")?;
            let seed = derive::<32>(
                issuer_root.as_ref(),
                b"opencsv-asset-issuer-v1",
                &index.to_be_bytes(),
            )?;
            let actual_id = protocol
                .init_issuer_from_seed(&currency, seed, nonce, terms)
                .map_err(|error| AccountError::new("database_corrupt", error))?;
            if actual_id != expected_id {
                return Err(AccountError::new(
                    "database_corrupt",
                    format!("asset {index} does not match account root"),
                ));
            }
        }
        Ok(())
    }

    fn restore_consignment_state(&mut self) -> Result<(), AccountError> {
        let Some(protocol) = self.protocol.as_mut() else {
            return Ok(());
        };
        // Local outgoing consignments are restored from their complete
        // operation journals below. Re-verifying one here as incoming would
        // both depend on an unnecessary receive snapshot and risk applying
        // the same change output twice.
        let local_consignment_ids = {
            let mut statement = self.db.conn.prepare(
                "SELECT receipt_json FROM opencsv_operations
                 WHERE receipt_json IS NOT NULL ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            let mut ids = HashSet::new();
            for row in rows {
                let receipt: Value = serde_json::from_str(&row?).map_err(|error| {
                    AccountError::new("database_corrupt", format!("operation receipt: {error}"))
                })?;
                if let Some(id) = receipt.get("consignment_id").and_then(Value::as_str) {
                    ids.insert(id.to_owned());
                }
            }
            ids
        };
        let mut statement = self.db.conn.prepare(
            "SELECT c.consignment_id, c.consignment_base64, c.spent_state_json, s.snapshot_json,
                    COALESCE(f.finality, 'settled'), f.anchor_txid
             FROM opencsv_consignments c
             JOIN opencsv_consignment_snapshots s USING(consignment_id)
             LEFT JOIN opencsv_consignment_finality f USING(consignment_id)
             ORDER BY c.created_at, c.rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })?;
        let mut spent = Vec::new();
        for row in rows {
            let (consignment_id, encoded, spent_state, snapshot, finality, anchor_txid) = row?;
            if local_consignment_ids.contains(&consignment_id) {
                continue;
            }
            if finality == "frozen" {
                continue;
            }
            let blob = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            let chain = SnapshotChain::from_json(&snapshot)
                .map_err(|error| AccountError::new("database_corrupt", error))?;
            let verdict = if finality == "unconfirmed" {
                let anchor_txid = anchor_txid.ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "unconfirmed consignment has no anchor txid",
                    )
                })?;
                protocol.verify_unconfirmed(&blob, &chain, &anchor_txid)
            } else {
                protocol.verify(&blob, &chain, u64::from(self.config.required_confirmations))
            }
            .map_err(|error| AccountError::new("database_corrupt", error))?;
            match verdict {
                Ok(_) => {}
                Err(reason) => {
                    return Err(AccountError::new(
                        "stale_chain_state",
                        format!("stored consignment no longer verifies: {reason}"),
                    ));
                }
            }
            let state: Value = serde_json::from_str(&spent_state)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            if let Some(ids) = state.get("spends").and_then(Value::as_array) {
                spent.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }
        for coin_id in spent {
            protocol
                .mark_spent(&[coin_id])
                .map_err(|error| AccountError::new("database_corrupt", error))?;
        }
        Ok(())
    }

    /// Reapply every finalized local operation in creation order. A pending
    /// export contains the exact proof, openings, input ids, and bound record;
    /// finalizing it against the durable txid reconstructs both spent inputs
    /// and locally-owned change. The reconstructed consignment must match the
    /// receipt and consignment table byte-for-byte or account open fails
    /// closed instead of resurrecting stale coins.
    fn restore_finalized_operations(&mut self) -> Result<(), AccountError> {
        let Some(protocol) = self.protocol.as_mut() else {
            return Ok(());
        };
        let mut replayed_spends: HashMap<String, (String, String)> = HashMap::new();
        let mut quarantines = Vec::new();
        let rows = {
            let mut statement = self.db.conn.prepare(
                "SELECT operation_id, state, pending_json, txid, receipt_json
                 FROM opencsv_operations
                 WHERE state IN ('mempool', 'confirmed', 'consignment_delivered')
                 ORDER BY created_at, rowid",
            )?;
            let mapped = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        for (operation_id, state, pending_json, txid, receipt_json) in rows {
            let pending_json = pending_json.ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} has no pending export"),
                )
            })?;
            let txid = txid
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} has no txid"),
                    )
                })?
                .parse::<Txid>()
                .map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} txid: {error}"),
                    )
                })?;
            let mut receipt: Value =
                serde_json::from_str(receipt_json.as_deref().ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} has no receipt"),
                    )
                })?)
                .map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} receipt: {error}"),
                    )
                })?;
            if receipt.get("delivery_ready") != Some(&Value::Bool(true)) {
                return Err(AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} is not delivery-ready"),
                ));
            }
            let expected_id = receipt
                .get("consignment_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} has no consignment id"),
                    )
                })?
                .to_owned();
            let expected_base64 = receipt
                .get("consignment_base64")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} has no consignment bytes"),
                    )
                })?
                .to_owned();
            let stored_spent_state: String = self.db.conn.query_row(
                "SELECT spent_state_json FROM opencsv_consignments
                 WHERE consignment_id = ?1",
                [&expected_id],
                |row| row.get(0),
            )?;
            let stored_spent_state: Value =
                serde_json::from_str(&stored_spent_state).map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} spend state: {error}"),
                    )
                })?;
            let stored_spends = stored_spent_state
                .get("spends")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} has no spend list"),
                    )
                })?
                .iter()
                .map(|value| {
                    value.as_str().map(str::to_owned).ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            format!("finalized operation {operation_id} has a non-string spend"),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let pending_id = protocol.import_pending(&pending_json).map_err(|error| {
                AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} pending export: {error}"),
                )
            })?;
            let pending_spends = protocol.pending_spends(pending_id).map_err(|error| {
                AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} pending spend list: {error}"),
                )
            })?;
            if pending_spends != stored_spends {
                protocol.cancel_pending(pending_id);
                return Err(AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} spend list mismatch"),
                ));
            }
            let mut conflicts = stored_spends
                .iter()
                .filter_map(|coin_id| replayed_spends.get(coin_id))
                .cloned()
                .collect::<Vec<_>>();
            conflicts.sort();
            conflicts.dedup();
            if !conflicts.is_empty() {
                let confirmed_winners = conflicts.iter().all(|(_, winner_state)| {
                    matches!(winner_state.as_str(), "confirmed" | "consignment_delivered")
                });
                if state == OperationState::Mempool.as_str() && confirmed_winners {
                    protocol.cancel_pending(pending_id);
                    let winner_operations = conflicts
                        .iter()
                        .map(|(winner_id, _)| winner_id)
                        .collect::<Vec<_>>();
                    receipt["protocol_rejection"] = json!({
                        "code": "duplicate_protocol_spend",
                        "conflicts_with": winner_operations,
                        "detected_at": unix_time()?,
                        "bitcoin_transaction_preserved": true,
                        "backup_refresh_required": true,
                    });
                    quarantines.push((operation_id, receipt.to_string(), unix_time()?));
                    continue;
                }
                protocol.cancel_pending(pending_id);
                return Err(AccountError::new(
                    "protocol_state_conflict",
                    format!(
                        "finalized operation {operation_id} reuses coins from {:?}; no confirmed winner can be quarantined safely",
                        conflicts
                            .iter()
                            .map(|(winner_id, _)| winner_id)
                            .collect::<Vec<_>>()
                    ),
                ));
            }
            let (actual, actual_spends) = protocol
                .finalize(
                    pending_id,
                    AnchorRef {
                        txid: txid.to_byte_array(),
                        location: MEMPOOL_LOCATION,
                    },
                )
                .map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("finalized operation {operation_id} replay: {error}"),
                    )
                })?;
            let actual_id = sha256::Hash::hash(&actual).to_string();
            let actual_base64 = base64::engine::general_purpose::STANDARD.encode(&actual);
            if actual_id != expected_id || actual_base64 != expected_base64 {
                return Err(AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} does not match its receipt"),
                ));
            }
            if stored_spends != actual_spends {
                return Err(AccountError::new(
                    "database_corrupt",
                    format!("finalized operation {operation_id} spend list mismatch"),
                ));
            }
            for coin_id in actual_spends {
                replayed_spends.insert(coin_id, (operation_id.clone(), state.clone()));
            }
        }
        if !quarantines.is_empty() {
            let transaction = self
                .db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            for (operation_id, receipt_json, detected_at) in quarantines {
                transaction.execute(
                    "UPDATE opencsv_operations
                     SET state = ?2, rejection_reason = ?3, receipt_json = ?4,
                         updated_at = ?5
                     WHERE operation_id = ?1",
                    params![
                        operation_id,
                        OperationState::ProtocolRejected.as_str(),
                        "duplicate_protocol_spend",
                        receipt_json,
                        detected_at,
                    ],
                )?;
            }
            transaction.execute(
                "INSERT INTO opencsv_account_meta(key, value)
                 VALUES('backup_verified', '0')
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )?;
            transaction.commit()?;
        }
        Ok(())
    }

    fn restore_fee_reservations(&mut self) -> Result<(), AccountError> {
        let outpoints = {
            let mut statement = self.db.conn.prepare(
                "SELECT txid, vout FROM opencsv_utxo_reservations
                 WHERE state = 'reserved' ORDER BY created_at",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let mut changed = false;
        for (txid, vout) in outpoints {
            let txid = Txid::from_str(&txid).map_err(|error| {
                AccountError::new("database_corrupt", format!("reserved txid: {error}"))
            })?;
            let vout = u32::try_from(vout).map_err(|_| {
                AccountError::new("database_corrupt", "reserved vout is outside u32")
            })?;
            let outpoint = OutPoint::new(txid, vout);
            if !self.bitcoin.is_outpoint_locked(outpoint) {
                self.bitcoin.lock_outpoint(outpoint);
                changed = true;
            }
        }
        if changed {
            self.bitcoin.persist(&mut self.db)?;
        }
        Ok(())
    }

    fn restore_pending_operations(&mut self) -> Result<(), AccountError> {
        let Some(protocol) = self.protocol.as_mut() else {
            return Ok(());
        };
        let mut statement = self.db.conn.prepare(
            "SELECT operation_id, pending_json FROM opencsv_operations
             WHERE pending_json IS NOT NULL
               AND state IN ('proof_ready', 'signed_persisted',
                             'broadcast_unobserved', 'broadcast')
             ORDER BY created_at, rowid",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (operation_id, pending_json) = row?;
            let pending_id = protocol
                .import_pending(&pending_json)
                .map_err(|error| AccountError::new("database_corrupt", error))?;
            self.pending_by_operation.insert(operation_id, pending_id);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ReservedFunding {
    outpoint: OutPoint,
    txout: bdk_wallet::bitcoin::TxOut,
    birth_height: u64,
}

impl ReservedFunding {
    fn from_local(output: bdk_wallet::LocalOutput) -> Result<Self, AccountError> {
        let birth_height = match output.chain_position {
            ChainPosition::Confirmed {
                anchor,
                transitively: None,
            } => u64::from(anchor.block_id.height),
            ChainPosition::Confirmed {
                transitively: Some(_),
                ..
            } => {
                return Err(AccountError::new(
                    "stale_chain_state",
                    "fee outpoint has only a transitive confirmation height",
                ));
            }
            ChainPosition::Unconfirmed { .. } => {
                return Err(AccountError::new(
                    "stale_chain_state",
                    "fee outpoint must be confirmed before reservation",
                ));
            }
        };
        Ok(Self {
            outpoint: output.outpoint,
            txout: output.txout,
            birth_height,
        })
    }

    fn value_sats(&self) -> u64 {
        self.txout.value.to_sat()
    }
}

fn operation_outpoint(operation: &OperationRow) -> Result<OutPoint, AccountError> {
    let txid = operation
        .funding_txid
        .as_deref()
        .ok_or_else(|| AccountError::new("database_corrupt", "operation has no funding txid"))?;
    let vout = operation
        .funding_vout
        .ok_or_else(|| AccountError::new("database_corrupt", "operation has no funding vout"))?;
    Ok(OutPoint::new(
        Txid::from_str(txid)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?,
        vout,
    ))
}

fn operation_json(operation: &OperationRow) -> Result<Value, AccountError> {
    let request: Value = serde_json::from_str(&operation.request_json)
        .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
    let receipt: Option<Value> = operation
        .receipt_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
    Ok(json!({
        "operation_id": operation.operation_id,
        "kind": operation.kind,
        "state": operation.state,
        "request": request,
        "funding_txid": operation.funding_txid,
        "funding_vout": operation.funding_vout,
        "txid": operation.txid,
        "receipt": receipt,
        "rejection_reason": operation.rejection_reason,
        "delivery_nonce": operation.delivery_nonce,
        "checkpoint_hash": operation.checkpoint_hash,
        "backup_acked": operation.backup_acked,
    }))
}

fn funding_context(outpoint: OutPoint) -> [u8; 32] {
    funding_ctx(&outpoint.txid.to_byte_array(), outpoint.vout)
}

/// Ensure a signed transaction reaches the generic relay unless that relay
/// already observes it. A failed observation request is deliberately treated
/// like a cache miss: the write path can still be healthy, and its result is
/// the useful durability signal for the caller.
fn relay_via_esplora_if_unobserved(
    client: &esplora_client::BlockingClient,
    transaction: &Transaction,
) -> Result<bool, esplora_client::Error> {
    if matches!(client.get_tx(&transaction.compute_txid()), Ok(Some(_))) {
        return Ok(false);
    }
    client.broadcast(transaction)?;
    Ok(true)
}

fn validate_initial_anchor(
    transaction: &Transaction,
    funding: OutPoint,
    record: &[u8; 64],
) -> Result<(), AccountError> {
    if transaction.input.is_empty()
        || transaction.input[0].previous_output != funding
        || transaction
            .input
            .iter()
            .any(|input| input.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
    {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "funding input must be vin[0] and every input must use the canonical RBF sequence",
        ));
    }
    if transaction.output.len() != 3 {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "anchor must have record, marker, and change outputs",
        ));
    }
    let expected_record = ScriptBuf::new_op_return(
        PushBytesBuf::try_from(record.to_vec()).expect("64-byte record is pushable"),
    );
    if transaction.output[0].value != Amount::ZERO
        || transaction.output[0].script_pubkey != expected_record
        || transaction.output[1].value.to_sat() != MARKER_DUST_SATS
        || transaction.output[1].script_pubkey.as_bytes() != MARKER_SPK
        || transaction.output[2].script_pubkey.is_op_return()
        || transaction.output[2].value < transaction.output[2].script_pubkey.minimal_non_dust()
    {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "signed transaction does not preserve record/marker/change layout",
        ));
    }
    Ok(())
}

fn query_json_rows(conn: &Connection, sql: &str) -> Result<Vec<Value>, AccountError> {
    let mut statement = conn.prepare(sql)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    rows.map(|row| {
        let encoded = row?;
        serde_json::from_str(&encoded)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))
    })
    .collect()
}

fn canonical_consignment_identity(blob: &[u8]) -> Result<(Vec<u8>, String), AccountError> {
    let consignment = Consignment::from_bytes(blob)
        .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
    let canonical = consignment.to_bytes();
    let identity = sha256::Hash::hash(&canonical).to_string();
    Ok((canonical, identity))
}

fn consignment_anchor_txid(blob: &[u8]) -> Result<String, AccountError> {
    let consignment = Consignment::from_bytes(blob)
        .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
    Ok(Txid::from_byte_array(consignment.anchor_ref.txid).to_string())
}

/// Merge one exact, locally validated mempool transaction into a confirmed
/// chain snapshot. Mempool location is deliberately the `(0, 0)` sentinel:
/// SnapshotChain assigns it zero confirmations and excludes it from
/// canonical first-occurrence ordering, matching BitcoinAnchorChain.
fn snapshot_with_unconfirmed_anchor(
    confirmed_snapshot_json: &str,
    consignment: &Consignment,
    transaction: &Transaction,
) -> Result<Snapshot, AccountError> {
    if consignment.anchor_ref.location != MEMPOOL_LOCATION {
        return Err(AccountError::new(
            "invalid_consignment",
            "zero-confirmation credit requires the mempool anchor sentinel",
        ));
    }
    let expected_txid = Txid::from_byte_array(consignment.anchor_ref.txid);
    if transaction.compute_txid() != expected_txid {
        return Err(AccountError::new(
            "unconfirmed_anchor_mismatch",
            format!(
                "accelerator returned {}, expected {expected_txid}",
                transaction.compute_txid()
            ),
        ));
    }
    let funding = transaction
        .input
        .first()
        .ok_or_else(|| {
            AccountError::new(
                "protocol_layout_violation",
                "unconfirmed anchor has no funding input",
            )
        })?
        .previous_output;
    let script = transaction
        .output
        .first()
        .ok_or_else(|| {
            AccountError::new(
                "protocol_layout_violation",
                "unconfirmed anchor has no record output",
            )
        })?
        .script_pubkey
        .as_bytes();
    let record: [u8; 64] = script
        .strip_prefix(&[0x6a, 0x40])
        .and_then(|payload| payload.try_into().ok())
        .ok_or_else(|| {
            AccountError::new(
                "protocol_layout_violation",
                "unconfirmed anchor output 0 is not one canonical 64-byte OP_RETURN",
            )
        })?;
    validate_initial_anchor(transaction, funding, &record)?;

    let mut snapshot: Snapshot = serde_json::from_str(confirmed_snapshot_json)
        .map_err(|error| AccountError::new("invalid_chain_view", error.to_string()))?;
    let txid_hex = hex_encode(&consignment.anchor_ref.txid);
    // The provisional capability names one exact mempool transaction.
    // Settled scan snapshots should not contain sentinel entries at all,
    // but discard any supplied ones so occurrence lookup cannot accidentally
    // select an unrelated, non-canonically ordered mempool record.
    snapshot.entries.retain(|entry| {
        entry.height != MEMPOOL_LOCATION.height || entry.position != MEMPOOL_LOCATION.position
    });
    snapshot.entries.push(SnapshotEntry {
        height: MEMPOOL_LOCATION.height,
        position: MEMPOOL_LOCATION.position,
        txid: txid_hex,
        ctx: hex_encode(&funding_context(funding)),
        record: hex_encode(&record),
    });
    Ok(snapshot)
}

fn evaluate_observation_evidence(
    policy: &[ObservationCheck],
    exact_raw_transaction: &[u8],
    observations_json: &str,
) -> Result<(Vec<Value>, Option<AccountError>), AccountError> {
    let envelope: ObservationEvidenceEnvelope =
        serde_json::from_str(observations_json).map_err(|error| {
            AccountError::new(
                "invalid_observation_evidence",
                format!("observation evidence JSON: {error}"),
            )
        })?;
    let mut evidence_by_id = HashMap::new();
    for evidence in envelope.observations {
        if evidence_by_id
            .insert(evidence.check_id.clone(), evidence)
            .is_some()
        {
            return Err(AccountError::new(
                "invalid_observation_evidence",
                "duplicate observation evidence identifier",
            ));
        }
    }

    let now_ms = unix_time_millis()?;
    let mut receipts = Vec::new();
    let mut first_required_failure = None;
    for check in policy {
        // Raw host evidence is supplied by Signal. Direct relay submission
        // and multi-peer confirmation have separate Rust-owned receipts and
        // must not be synthesized as "missing" host checks here.
        if check.kind != ObservationKind::RawTransactionApi {
            continue;
        }
        if check.mode == ObservationMode::Off {
            continue;
        }
        let evidence = evidence_by_id.remove(&check.id);
        let mut failures = Vec::new();
        let (
            result,
            endpoint,
            started_at_ms,
            completed_at_ms,
            cached_at_ms,
            profile,
            fingerprints,
            raw_match,
            detail,
        ) = if let Some(evidence) = evidence {
            if evidence.endpoint != check.endpoint {
                failures.push("endpoint mismatch".to_owned());
            }
            if evidence.completed_at_ms < evidence.started_at_ms {
                failures.push("negative request duration".to_owned());
            }
            if evidence.cached_at_ms > now_ms + 30_000 {
                failures.push("cache timestamp is in the future".to_owned());
            }
            let cache_age_ms = now_ms.saturating_sub(evidence.cached_at_ms);
            if u64::try_from(cache_age_ms).unwrap_or(u64::MAX)
                > check.max_age_seconds.saturating_mul(1_000)
            {
                failures.push("observation cache is stale".to_owned());
            }
            if evidence.certificate_profile != check.pin_profile {
                failures.push("certificate profile mismatch".to_owned());
            }
            for fingerprint in &evidence.certificate_chain_fingerprints_sha256 {
                if validate_hex_32_config(fingerprint, "observed certificate fingerprint").is_err()
                {
                    failures.push("invalid certificate fingerprint".to_owned());
                }
            }
            if check.pin_profile.is_some()
                && evidence.certificate_chain_fingerprints_sha256.is_empty()
            {
                failures.push("pinned certificate chain is missing".to_owned());
            }
            if !check.chain_fingerprints_sha256.is_empty()
                && !evidence
                    .certificate_chain_fingerprints_sha256
                    .iter()
                    .any(|fingerprint| check.chain_fingerprints_sha256.contains(fingerprint))
            {
                failures.push("certificate chain does not match configured pins".to_owned());
            }
            let raw_match = if check.kind == ObservationKind::RawTransactionApi {
                evidence
                    .raw_transaction_hex
                    .as_deref()
                    .and_then(|encoded| hex_decode(encoded, "observed raw transaction").ok())
                    .is_some_and(|raw| raw == exact_raw_transaction)
            } else {
                false
            };
            if check.kind == ObservationKind::RawTransactionApi && !raw_match {
                failures.push("raw transaction bytes do not match".to_owned());
            }
            if check.kind == ObservationKind::RawTransactionApi
                && evidence.result != ObservationResult::Observed
            {
                failures.push("transaction was not observed".to_owned());
            }
            (
                evidence.result,
                evidence.endpoint,
                evidence.started_at_ms,
                evidence.completed_at_ms,
                evidence.cached_at_ms,
                evidence.certificate_profile,
                evidence.certificate_chain_fingerprints_sha256,
                raw_match,
                evidence.detail,
            )
        } else {
            failures.push("evidence is missing".to_owned());
            (
                ObservationResult::NotChecked,
                check.endpoint.clone(),
                now_ms,
                now_ms,
                now_ms,
                check.pin_profile.clone(),
                Vec::new(),
                false,
                None,
            )
        };
        let receipt = json!({
            "check_id": check.id,
            "kind": check.kind,
            "mode": check.mode,
            "endpoint": endpoint,
            "result": result,
            "started_at_ms": started_at_ms,
            "completed_at_ms": completed_at_ms,
            "latency_ms": completed_at_ms.saturating_sub(started_at_ms),
            "cached_at_ms": cached_at_ms,
            "cache_age_ms": now_ms.saturating_sub(cached_at_ms),
            "certificate_profile": profile,
            "certificate_chain_fingerprints_sha256": fingerprints,
            "raw_byte_match": raw_match,
            "detail": detail,
            "failures": failures,
        });
        if check.mode == ObservationMode::Require
            && !receipt["failures"]
                .as_array()
                .is_some_and(|failures| failures.is_empty())
            && first_required_failure.is_none()
        {
            first_required_failure = Some(AccountError::new(
                "required_observation_failed",
                format!(
                    "required observer {} failed: {}",
                    check.id,
                    receipt["failures"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
        receipts.push(receipt);
    }
    if !evidence_by_id.is_empty() {
        return Err(AccountError::new(
            "invalid_observation_evidence",
            format!(
                "evidence contains unconfigured checks: {}",
                evidence_by_id
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    Ok((receipts, first_required_failure))
}

fn derive<const N: usize>(
    root: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; N], AccountError> {
    let hk = Hkdf::<Sha256>::new(Some(b"OpenCSV Signal account v1"), root);
    let mut output = [0u8; N];
    let info = [label, b"\0", context].concat();
    hk.expand(&info, &mut output)
        .map_err(|_| AccountError::new("key_derivation_failed", "HKDF output length"))?;
    Ok(output)
}

fn parse_network(name: &str) -> Result<Network, AccountError> {
    match name {
        // The public account/FFI vocabulary is `mainnet`, while
        // rust-bitcoin's `FromStr` spelling is `bitcoin`.
        "mainnet" => Ok(Network::Bitcoin),
        "signet" | "regtest" => Network::from_str(name)
            .map_err(|_| AccountError::new("invalid_config", format!("unknown network `{name}`"))),
        _ => Err(AccountError::new(
            "invalid_config",
            format!("unsupported account-wallet network `{name}`"),
        )),
    }
}

fn parse_cbf_network(name: &str) -> Result<OpenCsvNetwork, AccountError> {
    match name {
        "mainnet" | "bitcoin" => Ok(OpenCsvNetwork::Mainnet),
        "signet" => Ok(OpenCsvNetwork::Signet),
        "regtest" => Ok(OpenCsvNetwork::Regtest),
        _ => Err(AccountError::new(
            "stale_chain_state",
            format!("authoritative compact-filter validation is unavailable for `{name}`"),
        )),
    }
}

fn validate_esplora_url(url: &str) -> Result<(), AccountError> {
    if url.starts_with("https://")
        || url.starts_with("http://127.0.0.1:")
        || url.starts_with("http://localhost:")
    {
        Ok(())
    } else {
        Err(AccountError::new(
            "invalid_config",
            "Esplora URL must use HTTPS (HTTP is allowed only for localhost)",
        ))
    }
}

const MEMPOOL_SPACE_SIGNET_CHAIN_PINS: [&str; 2] = [
    // Sectigo Public Server Authentication CA OV R36.
    "6542d176bed50f193c0ce297ae44ecd8a0a86bec2ede682769344059b4e78530",
    // Sectigo Public Server Authentication Root R46, USERTrust cross-certificate.
    "92f351bf3d54164dfa8dd8f9e1139d3150349786485d2b9eecd00e2971c1e6c5",
];

const BLOCKSTREAM_SIGNET_CHAIN_PINS: [&str; 4] = [
    // Let's Encrypt YR1 and YR2 intermediates.
    "13949634d99cd6fd6aa80bc034fefacceb1969feef986586713ecdbb05758d3f",
    "238b85a0099c65b970477d5724f1a1d475ce5058cffe4efa8733899bdb863c47",
    // Root YR self-signed and its ISRG Root X1 cross-certificate.
    "e57b7e6f150c419102e8d5c055729ff967b9d1a829bf00cec89ca604ebf4a86f",
    "072639d0b140d5bffae16ad9c3f6cc6086040621f51ee61a6d46a8915c07cf76",
];

fn owned_chain_pins<const N: usize>(pins: [&str; N]) -> Vec<String> {
    pins.into_iter().map(str::to_owned).collect()
}

fn default_observation_checks(network: &str) -> Vec<ObservationCheck> {
    let mut checks = Vec::new();
    if network == "signet" {
        checks.push(ObservationCheck {
            id: "mempool_space_signet".into(),
            kind: ObservationKind::RawTransactionApi,
            endpoint: Some("https://mempool.space/signet/api".into()),
            mode: ObservationMode::Require,
            pin_profile: Some("sectigo_r46".into()),
            chain_fingerprints_sha256: owned_chain_pins(MEMPOOL_SPACE_SIGNET_CHAIN_PINS),
            max_age_seconds: default_observation_max_age_seconds(),
        });
        checks.push(ObservationCheck {
            id: "blockstream_signet".into(),
            kind: ObservationKind::RawTransactionApi,
            endpoint: Some("https://blockstream.info/signet/api".into()),
            mode: ObservationMode::Require,
            pin_profile: Some("lets_encrypt_yr".into()),
            chain_fingerprints_sha256: owned_chain_pins(BLOCKSTREAM_SIGNET_CHAIN_PINS),
            max_age_seconds: default_observation_max_age_seconds(),
        });
    }
    checks.extend([
        ObservationCheck {
            id: "direct_p2p_relay".into(),
            kind: ObservationKind::DirectP2pRelay,
            endpoint: None,
            mode: ObservationMode::Observe,
            pin_profile: None,
            chain_fingerprints_sha256: Vec::new(),
            max_age_seconds: default_observation_max_age_seconds(),
        },
        ObservationCheck {
            id: "experimental_p2p_mempool_possession".into(),
            kind: ObservationKind::ExperimentalP2pPossession,
            endpoint: None,
            mode: ObservationMode::Off,
            pin_profile: None,
            chain_fingerprints_sha256: Vec::new(),
            max_age_seconds: default_observation_max_age_seconds(),
        },
        ObservationCheck {
            id: "multi_peer_spv_confirmation".into(),
            kind: ObservationKind::ConfirmedSpv,
            endpoint: None,
            mode: ObservationMode::Observe,
            pin_profile: None,
            chain_fingerprints_sha256: Vec::new(),
            max_age_seconds: default_observation_max_age_seconds(),
        },
    ]);
    checks
}

fn validate_observation_checks(config: &AccountConfig) -> Result<(), AccountError> {
    let mut ids = HashSet::new();
    for check in &config.observation_checks {
        if check.id.trim().is_empty() || !ids.insert(check.id.as_str()) {
            return Err(AccountError::new(
                "invalid_config",
                "observation check identifiers must be non-empty and unique",
            ));
        }
        if check.kind == ObservationKind::RawTransactionApi {
            let endpoint = check.endpoint.as_deref().ok_or_else(|| {
                AccountError::new(
                    "invalid_config",
                    "raw-transaction observer needs an endpoint",
                )
            })?;
            validate_esplora_url(endpoint)?;
        } else if check.endpoint.is_some() {
            return Err(AccountError::new(
                "invalid_config",
                format!(
                    "non-API observation {} cannot configure an endpoint",
                    check.id
                ),
            ));
        }
        if check.mode == ObservationMode::Require && check.max_age_seconds == 0 {
            return Err(AccountError::new(
                "invalid_config",
                format!(
                    "required observer {} must have a positive max age",
                    check.id
                ),
            ));
        }
        match check.id.as_str() {
            "mempool_space_signet" => {
                if config.network != "signet"
                    || check.kind != ObservationKind::RawTransactionApi
                    || check.endpoint.as_deref() != Some("https://mempool.space/signet/api")
                    || check.pin_profile.as_deref() != Some("sectigo_r46")
                    || check.chain_fingerprints_sha256
                        != owned_chain_pins(MEMPOOL_SPACE_SIGNET_CHAIN_PINS)
                {
                    return Err(AccountError::new(
                        "invalid_config",
                        "the built-in mempool.space signet endpoint and pin profile are immutable",
                    ));
                }
            }
            "blockstream_signet" => {
                if config.network != "signet"
                    || check.kind != ObservationKind::RawTransactionApi
                    || check.endpoint.as_deref() != Some("https://blockstream.info/signet/api")
                    || check.pin_profile.as_deref() != Some("lets_encrypt_yr")
                    || check.chain_fingerprints_sha256
                        != owned_chain_pins(BLOCKSTREAM_SIGNET_CHAIN_PINS)
                {
                    return Err(AccountError::new(
                        "invalid_config",
                        "the built-in Blockstream signet endpoint and pin profile are immutable",
                    ));
                }
            }
            _ if check.mode == ObservationMode::Require
                && check.kind == ObservationKind::RawTransactionApi =>
            {
                if check.chain_fingerprints_sha256.is_empty() {
                    return Err(AccountError::new(
                        "invalid_config",
                        format!(
                            "custom required observer {} needs a certificate-chain fingerprint",
                            check.id
                        ),
                    ));
                }
                for fingerprint in &check.chain_fingerprints_sha256 {
                    validate_hex_32_config(fingerprint, "certificate-chain fingerprint")?;
                }
            }
            _ => {
                for fingerprint in &check.chain_fingerprints_sha256 {
                    validate_hex_32_config(fingerprint, "certificate-chain fingerprint")?;
                }
            }
        }
    }
    Ok(())
}

fn validate_usd_issuer_policy(config: &AccountConfig) -> Result<(), AccountError> {
    let mut asset_ids = HashSet::new();
    for issuer in &config.usd_issuers {
        issuer.manifest.validate().map_err(|error| {
            AccountError::new("invalid_config", format!("USD issuer manifest: {error}"))
        })?;
        if issuer.manifest.terms.network != config.network {
            return Err(AccountError::new(
                "invalid_config",
                "USD issuer manifest belongs to another network",
            ));
        }
        if issuer.manifest.terms.unit_code != "USD" {
            return Err(AccountError::new(
                "invalid_config",
                "USD issuer policy accepts only manifests with unit code USD",
            ));
        }
        let asset_id = hex_encode(issuer.manifest.genesis.asset_id().as_bytes());
        if !asset_ids.insert(asset_id) {
            return Err(AccountError::new(
                "invalid_config",
                "USD issuer policy contains a duplicate asset id",
            ));
        }
    }
    Ok(())
}

fn unix_time() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AccountError::new("clock_error", error.to_string()))
        .and_then(|duration| {
            i64::try_from(duration.as_secs())
                .map_err(|_| AccountError::new("clock_error", "timestamp exceeds SQLite range"))
        })
}

fn unix_time_millis() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AccountError::new("clock_error", error.to_string()))
        .and_then(|duration| {
            i64::try_from(duration.as_millis())
                .map_err(|_| AccountError::new("clock_error", "timestamp exceeds SQLite range"))
        })
}

fn random_id(bytes: usize) -> String {
    let random: [u8; 32] = rand::rng().random();
    hex_encode(&random[..bytes.min(random.len())])
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode(value: &str, what: &str) -> Result<Vec<u8>, AccountError> {
    if !value.len().is_multiple_of(2) {
        return Err(AccountError::new(
            "database_corrupt",
            format!("{what} has odd-length hexadecimal"),
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| AccountError::new("database_corrupt", format!("invalid {what} hex")))
        })
        .collect()
}

fn validate_hex_32_config(value: &str, what: &str) -> Result<(), AccountError> {
    if value.len() != 64 || !value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AccountError::new(
            "invalid_config",
            format!("{what} must be 64 hexadecimal characters"),
        ));
    }
    Ok(())
}

fn decode_hex_32(value: &str, what: &str) -> Result<[u8; 32], AccountError> {
    if value.len() != 64 {
        return Err(AccountError::new(
            "database_corrupt",
            format!("{what} must be 64 hexadecimal characters"),
        ));
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| AccountError::new("database_corrupt", format!("invalid {what} hex")))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;

    use bdk_wallet::bitcoin::absolute;
    use bdk_wallet::bitcoin::block::{Header, Version};
    use bdk_wallet::bitcoin::hash_types::TxMerkleNode;
    use bdk_wallet::bitcoin::transaction;
    use bdk_wallet::bitcoin::{Block, CompactTarget, TxIn, TxOut, Witness};

    struct AcceptingVerifier;

    impl FundingVerifier for AcceptingVerifier {
        fn verify(
            &self,
            request: &FundingVerificationRequest,
        ) -> Result<FundingVerificationReceipt, AccountError> {
            Ok(FundingVerificationReceipt {
                creation_height: request.birth_height,
                checked_through: request.birth_height + 6,
                matched_blocks: 1,
                verified_at: 1,
                source: "test-verified-blocks",
            })
        }
    }

    fn allow_funding_verification(wallet: &mut AccountWallet) {
        wallet.funding_verifier = Arc::new(AcceptingVerifier);
    }

    #[derive(Clone, Copy)]
    enum VerificationVerdict {
        Accept,
        Reject(&'static str, &'static str),
    }

    struct ScriptedVerifier {
        verdicts: Mutex<VecDeque<VerificationVerdict>>,
        calls: AtomicUsize,
    }

    impl ScriptedVerifier {
        fn new(verdicts: impl IntoIterator<Item = VerificationVerdict>) -> Self {
            Self {
                verdicts: Mutex::new(verdicts.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl FundingVerifier for ScriptedVerifier {
        fn verify(
            &self,
            request: &FundingVerificationRequest,
        ) -> Result<FundingVerificationReceipt, AccountError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self
                .verdicts
                .lock()
                .expect("scripted verifier mutex")
                .pop_front()
                .unwrap_or(VerificationVerdict::Accept)
            {
                VerificationVerdict::Accept => Ok(FundingVerificationReceipt {
                    creation_height: request.birth_height,
                    checked_through: request.birth_height + 6,
                    matched_blocks: 1,
                    verified_at: 1,
                    source: "scripted-verified-blocks",
                }),
                VerificationVerdict::Reject(code, message) => Err(AccountError::new(code, message)),
            }
        }
    }

    fn use_scripted_verifier(
        wallet: &mut AccountWallet,
        verdicts: impl IntoIterator<Item = VerificationVerdict>,
    ) -> Arc<ScriptedVerifier> {
        let verifier = Arc::new(ScriptedVerifier::new(verdicts));
        wallet.funding_verifier = verifier.clone();
        verifier
    }

    fn config(role: AccountRole, backup_verified: bool) -> String {
        config_with_url(role, backup_verified, "https://mempool.space/signet/api")
    }

    fn config_with_url(role: AccountRole, backup_verified: bool, esplora_url: &str) -> String {
        serde_json::to_string(&json!({
            "version": 1,
            "network": "signet",
            "esplora_url": esplora_url,
            "role": role,
            "backup_verified": backup_verified,
            "observation_checks": [{
                "id": "test_accelerator",
                "kind": "raw_transaction_api",
                "endpoint": esplora_url,
                "mode": "observe",
            }],
        }))
        .unwrap()
    }

    fn test_instrument_request(unit_code: &str) -> String {
        json!({
            "terms": {
                "version": 1,
                "network": "signet",
                "display_name": format!("OpenCSV {unit_code} test claim"),
                "unit_code": unit_code,
                "decimals": 2,
                "issuer_name": "OpenCSV test issuer",
                "terms_uri": format!("https://opencsv.net/test-terms/{unit_code}"),
                "redemption_summary": "Test-only units with no monetary value.",
                "test_only": true
            }
        })
        .to_string()
    }

    fn test_usd_issuer_policy(seed_byte: u8, issuer_name: &str, priority: u32) -> Value {
        let terms = InstrumentTermsV1 {
            version: 1,
            network: "signet".into(),
            display_name: format!("{issuer_name} test USD"),
            unit_code: "USD".into(),
            decimals: 6,
            issuer_name: issuer_name.into(),
            terms_uri: format!(
                "https://opencsv.net/test-terms/usd-{}",
                issuer_name.to_ascii_lowercase().replace(' ', "-")
            ),
            redemption_summary: "Test-only issuer claim with no monetary value.".into(),
            test_only: true,
        };
        let genesis = AssetGenesis {
            issuer_pk: PoseidonIssuerAuthorization::public_key(&[seed_byte; 32]),
            currency_code: *b"USD",
            terms_hash: terms.terms_hash().unwrap(),
            nonce: u64::from(seed_byte) + 1,
        };
        json!({
            "manifest": InstrumentManifestV1 { terms, genesis },
            "priority": priority,
        })
    }

    fn config_with_usd_issuers(issuers: Vec<Value>) -> String {
        let mut value: Value = serde_json::from_str(&config(AccountRole::Primary, true)).unwrap();
        value["usd_issuers"] = Value::Array(issuers);
        value.to_string()
    }

    fn create_test_instrument(wallet: &mut AccountWallet, unit_code: &str) -> String {
        let created = wallet
            .instrument_create(&test_instrument_request(unit_code))
            .unwrap();
        assert_eq!(created["backup_required"], true);
        wallet.set_backup_state(true, CHECKPOINT_VERSION).unwrap();
        created["asset_id"].as_str().unwrap().to_owned()
    }

    fn prepare_test_issuance(
        wallet: &mut AccountWallet,
        unit_code: &str,
        amounts: &[u64],
    ) -> Result<Value, AccountError> {
        let asset_id = create_test_instrument(wallet, unit_code);
        wallet.mint_prepare(&json!({ "asset_id": asset_id, "amounts": amounts }).to_string())
    }

    fn confirmed_status_server(block_height: u32) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..length]).unwrap();
            assert!(request.starts_with("GET /tx/"));
            assert!(request.contains("/status HTTP/1.1"));
            let body = json!({
                "confirmed": true,
                "block_height": block_height,
                "block_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "block_time": 1,
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            )
            .unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}"), server)
    }

    fn unobserved_relay_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 4096];
            let length = stream.read(&mut buffer).unwrap();
            let first_request = std::str::from_utf8(&buffer[..length]).unwrap();
            assert!(first_request.starts_with("GET /tx/"));
            assert!(first_request.contains("/raw HTTP/1.1"));
            write!(
                stream,
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            stream.flush().unwrap();

            let (mut stream, _) = listener.accept().unwrap();
            let length = stream.read(&mut buffer).unwrap();
            let second_request = std::str::from_utf8(&buffer[..length]).unwrap();
            assert!(second_request.starts_with("POST /tx HTTP/1.1"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}"), server)
    }

    fn observed_raw_transaction_server(
        transaction: Transaction,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = serialize(&transaction);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let length = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..length]).unwrap();
            assert!(request.starts_with("GET /tx/"));
            assert!(request.contains("/raw HTTP/1.1"));
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len(),
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        });
        (format!("http://{address}"), server)
    }

    fn fund(wallet: &mut AccountWallet, value_sats: u64) -> OutPoint {
        let address = wallet
            .bitcoin
            .next_unused_address(KeychainKind::External)
            .address;
        let tip = wallet.bitcoin.latest_checkpoint().block_id();
        let height = tip.height.checked_add(1).unwrap();
        let mut previous_txid = [42u8; 32];
        previous_txid[..4].copy_from_slice(&height.to_be_bytes());
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(previous_txid), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value_sats),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let outpoint = OutPoint::new(transaction.compute_txid(), 0);
        let mut block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: tip.hash,
                merkle_root: TxMerkleNode::all_zeros(),
                time: height,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            },
            txdata: vec![transaction],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        wallet.bitcoin.apply_block(&block, height).unwrap();
        wallet.bitcoin.persist(&mut wallet.db).unwrap();
        assert!(wallet
            .bitcoin
            .list_unspent()
            .any(|utxo| utxo.outpoint == outpoint));
        outpoint
    }

    fn finalize_test_operation(wallet: &mut AccountWallet, operation_id: &str, txid: Txid) {
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET txid = ?2 WHERE operation_id = ?1",
                params![operation_id, txid.to_string()],
            )
            .unwrap();
        wallet
            .finalize_observed_operation(operation_id, txid)
            .unwrap();
    }

    fn install_replay_operation(
        wallet: &mut AccountWallet,
        operation_id: &str,
        outputs: &[(u64, String)],
        spent_ids: Vec<String>,
        asset_id: &str,
        tag: u8,
    ) {
        wallet
            .insert_planned_operation(
                operation_id,
                "test-replay",
                "{}",
                &format!("{operation_id}-delivery"),
            )
            .unwrap();
        let (pending_id, pending_json) = wallet
            .primary_protocol_mut()
            .unwrap()
            .install_replay_fixture(asset_id, outputs, spent_ids, tag)
            .unwrap();
        wallet
            .pending_by_operation
            .insert(operation_id.to_owned(), pending_id);
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = ?2, pending_json = ?3, receipt_json = '{}'
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::ProofReady.as_str(),
                    pending_json,
                ],
            )
            .unwrap();
    }

    #[test]
    fn descriptor_and_owner_derivation_are_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let mut first = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let first_status = first.status().unwrap();
        drop(first);

        let mut second = AccountWallet::open(
            &config(AccountRole::Primary, false),
            &key,
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let second_status = second.status().unwrap();
        assert_eq!(first_status["owners"], second_status["owners"]);
        assert_eq!(
            first_status["watch_descriptors"],
            second_status["watch_descriptors"]
        );
        // Reopening with backup_verified=false does not silently downgrade
        // already-verified durable policy state.
        assert_eq!(second_status["backup_verified"], true);
    }

    #[test]
    fn unobserved_transaction_uses_generic_relay_regardless_of_peer_receipt() {
        let (url, server) = unobserved_relay_server();
        let client = esplora_client::Builder::new(&url).build_blocking();
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        // A direct-peer submission count is intentionally not an input to
        // this decision. Only independent observation can skip the POST.
        assert!(relay_via_esplora_if_unobserved(&client, &transaction).unwrap());
        server.join().unwrap();
    }

    #[test]
    fn consignment_identity_normalizes_equivalent_wire_encodings() {
        let consignment = Consignment {
            coin_openings: Vec::new(),
            nullifiers: Vec::new(),
            proof: Vec::new(),
            anchor_ref: AnchorRef {
                txid: [0u8; 32],
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };
        let canonical = consignment.to_bytes();
        assert_eq!(canonical[0], 0, "first field is an empty opening vector");

        // Bincode accepts this overlong u16 representation of the same zero
        // length. Transport bytes differ, but verdict/render identity must not.
        let mut overlong = vec![251, 0, 0];
        overlong.extend_from_slice(&canonical[1..]);
        assert_ne!(overlong, canonical);
        assert_eq!(Consignment::from_bytes(&overlong).unwrap(), consignment);

        let (canonical_bytes, canonical_id) = canonical_consignment_identity(&canonical).unwrap();
        let (normalized_bytes, normalized_id) = canonical_consignment_identity(&overlong).unwrap();
        assert_eq!(normalized_bytes, canonical_bytes);
        assert_eq!(normalized_id, canonical_id);
    }

    #[test]
    fn provisional_snapshot_accepts_only_exact_canonical_anchor_layout() {
        let funding = OutPoint::new(Txid::from_byte_array([3u8; 32]), 1);
        let record = [7u8; 64];
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(
                        PushBytesBuf::try_from(record.to_vec()).unwrap(),
                    ),
                },
                TxOut {
                    value: Amount::from_sat(MARKER_DUST_SATS),
                    script_pubkey: ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
                },
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::from_bytes(
                        [vec![0x00, 0x14], vec![9u8; 20]].concat(),
                    ),
                },
            ],
        };
        let consignment = Consignment {
            coin_openings: Vec::new(),
            nullifiers: Vec::new(),
            proof: Vec::new(),
            anchor_ref: AnchorRef {
                txid: transaction.compute_txid().to_byte_array(),
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };
        let supplied_sentinel = SnapshotEntry {
            height: MEMPOOL_LOCATION.height,
            position: MEMPOOL_LOCATION.position,
            txid: hex_encode(&[99_u8; 32]),
            ctx: hex_encode(&[98_u8; 32]),
            record: hex_encode(&[97_u8; 64]),
        };
        let snapshot = snapshot_with_unconfirmed_anchor(
            &serde_json::to_string(&Snapshot {
                tip_height: 100,
                entries: vec![supplied_sentinel],
            })
            .unwrap(),
            &consignment,
            &transaction,
        )
        .unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(
            snapshot.entries[0].txid,
            hex_encode(&consignment.anchor_ref.txid)
        );
        let chain = SnapshotChain::from_snapshot(&snapshot).unwrap();
        assert_eq!(
            opencsv_core::chain::AnchorChain::confirmations_at(&chain, 0),
            0
        );

        let mut mutated = transaction.clone();
        mutated.output.swap(0, 1);
        let error = snapshot_with_unconfirmed_anchor(
            r#"{"tip_height":100,"entries":[]}"#,
            &consignment,
            &mutated,
        )
        .unwrap_err();
        assert!(matches!(
            error.code,
            "unconfirmed_anchor_mismatch" | "protocol_layout_violation"
        ));
    }

    #[test]
    fn wrong_account_root_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        AccountWallet::open(
            &config(AccountRole::Primary, false),
            &[1u8; 32],
            path.to_str().unwrap(),
        )
        .unwrap();
        let error = AccountWallet::open(
            &config(AccountRole::Primary, false),
            &[2u8; 32],
            path.to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "account_key_mismatch");
    }

    #[test]
    fn fresh_signet_defaults_require_both_pinned_api_observers() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = json!({
            "version": 1,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "primary",
            "backup_verified": false,
        });
        let mut wallet = AccountWallet::open_device_bound(
            &cfg.to_string(),
            &[71u8; 32],
            &[72u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = wallet.status().unwrap();
        let policy = status["observation_policy"].as_array().unwrap();
        assert_eq!(policy.len(), 5);
        assert_eq!(policy[0]["id"], "mempool_space_signet");
        assert_eq!(policy[0]["mode"], "require");
        assert_eq!(policy[0]["pin_profile"], "sectigo_r46");
        assert_eq!(
            policy[0]["chain_fingerprints_sha256"],
            json!(MEMPOOL_SPACE_SIGNET_CHAIN_PINS)
        );
        assert_eq!(policy[1]["id"], "blockstream_signet");
        assert_eq!(policy[1]["mode"], "require");
        assert_eq!(policy[1]["pin_profile"], "lets_encrypt_yr");
        assert_eq!(
            policy[1]["chain_fingerprints_sha256"],
            json!(BLOCKSTREAM_SIGNET_CHAIN_PINS)
        );
        assert_eq!(policy[2]["mode"], "observe");
        assert_eq!(policy[3]["mode"], "off");
        assert_eq!(policy[4]["mode"], "observe");
        assert_eq!(
            wallet
                .verify_consignment_unconfirmed(&[1], r#"{"tip_height":0,"entries":[]}"#)
                .unwrap_err()
                .code,
            "observation_evidence_required"
        );
    }

    #[test]
    fn observation_policy_enforces_required_raw_bytes_and_records_observe_failures() {
        let policy = default_observation_checks("signet");
        let now = unix_time_millis().unwrap();
        let evidence = json!({
            "observations": [
                {
                    "check_id": "mempool_space_signet",
                    "endpoint": "https://mempool.space/signet/api",
                    "result": "observed",
                    "started_at_ms": now - 15,
                    "completed_at_ms": now - 5,
                    "cached_at_ms": now - 5,
                    "certificate_profile": "sectigo_r46",
                    "certificate_chain_fingerprints_sha256": [MEMPOOL_SPACE_SIGNET_CHAIN_PINS[0]],
                    "raw_transaction_hex": "0102"
                },
                {
                    "check_id": "blockstream_signet",
                    "endpoint": "https://blockstream.info/signet/api",
                    "result": "observed",
                    "started_at_ms": now - 20,
                    "completed_at_ms": now - 4,
                    "cached_at_ms": now - 4,
                    "certificate_profile": "lets_encrypt_yr",
                    "certificate_chain_fingerprints_sha256": [BLOCKSTREAM_SIGNET_CHAIN_PINS[1]],
                    "raw_transaction_hex": "0102"
                }
            ]
        });
        let (receipts, failure) =
            evaluate_observation_evidence(&policy, &[1, 2], &evidence.to_string()).unwrap();
        assert!(failure.is_none());
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0]["raw_byte_match"], true);
        assert_eq!(receipts[1]["raw_byte_match"], true);

        let mut wrong_pin = evidence.clone();
        wrong_pin["observations"][0]["certificate_chain_fingerprints_sha256"] =
            json!(["11".repeat(32)]);
        let (_, failure) =
            evaluate_observation_evidence(&policy, &[1, 2], &wrong_pin.to_string()).unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");

        let mut wrong = evidence;
        wrong["observations"][1]["raw_transaction_hex"] = json!("0103");
        let (_, failure) =
            evaluate_observation_evidence(&policy, &[1, 2], &wrong.to_string()).unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");
    }

    #[test]
    fn custom_required_observer_needs_a_chain_pin() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = json!({
            "version": 1,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "primary",
            "backup_verified": false,
            "observation_checks": [{
                "id": "custom",
                "kind": "raw_transaction_api",
                "endpoint": "https://observer.example/api",
                "mode": "require"
            }]
        });
        let error = AccountWallet::open_device_bound(
            &cfg.to_string(),
            &[81u8; 32],
            &[82u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "invalid_config");
    }

    #[test]
    fn restored_primary_with_different_device_binding_is_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let restored_path = dir.path().join("restored.sqlite");
        let key = [21u8; 32];
        let original_binding = [22u8; 32];
        let restored_binding = [23u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original =
            AccountWallet::open_device_bound(&cfg, &key, &original_binding, path.to_str().unwrap())
                .unwrap();
        let original_status = original.status().unwrap();
        assert_eq!(original_status["device_binding"]["status"], "bound");
        let commitment = original_status["device_binding"]["commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            original.checkpoint().unwrap()["checkpoint"]["device_binding_commitment"],
            commitment
        );
        drop(original);

        let mut missing =
            AccountWallet::open_device_bound(&cfg, &key, &[], path.to_str().unwrap()).unwrap();
        assert_eq!(
            missing.status().unwrap()["device_binding"]["status"],
            "mismatch_read_only"
        );
        assert_eq!(
            missing
                .mint_prepare(&json!({ "currency": "USD", "amounts": [1] }).to_string())
                .unwrap_err()
                .code,
            "device_binding_mismatch"
        );
        drop(missing);

        let sticky_path = dir.path().join("missing-binding.sqlite");
        let mut missing_clean =
            AccountWallet::open_device_bound(&cfg, &key, &[], sticky_path.to_str().unwrap())
                .unwrap();
        assert_eq!(
            missing_clean.status().unwrap()["device_binding"]["status"],
            "mismatch_read_only"
        );
        drop(missing_clean);
        let mut replacement_attempt = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &restored_binding,
            sticky_path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            replacement_attempt.status().unwrap()["device_binding"]["status"],
            "mismatch_read_only"
        );
        assert_eq!(
            replacement_attempt
                .fee_bump("does-not-exist", 5)
                .unwrap_err()
                .code,
            "device_binding_mismatch"
        );
        drop(replacement_attempt);

        let mut cloned =
            AccountWallet::open_device_bound(&cfg, &key, &restored_binding, path.to_str().unwrap())
                .unwrap();
        let cloned_status = cloned.status().unwrap();
        assert_eq!(
            cloned_status["device_binding"]["status"],
            "mismatch_read_only"
        );
        assert_eq!(cloned_status["write_enabled"], false);
        assert_eq!(
            cloned
                .mint_prepare(&json!({ "currency": "USD", "amounts": [1] }).to_string())
                .unwrap_err()
                .code,
            "device_binding_mismatch"
        );
        drop(cloned);

        let mut restored_config: Value = serde_json::from_str(&cfg).unwrap();
        restored_config["expected_device_binding_commitment"] = json!(commitment);
        let mut clean_restore = AccountWallet::open_device_bound(
            &restored_config.to_string(),
            &key,
            &restored_binding,
            restored_path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            clean_restore.status().unwrap()["device_binding"]["status"],
            "mismatch_read_only"
        );
        assert_eq!(
            clean_restore
                .mint_prepare(&json!({ "currency": "USD", "amounts": [1] }).to_string())
                .unwrap_err()
                .code,
            "device_binding_mismatch"
        );
    }

    #[test]
    fn clean_restore_imports_exact_checkpoint_but_remains_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let original_path = dir.path().join("original.sqlite");
        let restored_path = dir.path().join("restored.sqlite");
        let key = [31u8; 32];
        let binding = [32u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original =
            AccountWallet::open_device_bound(&cfg, &key, &binding, original_path.to_str().unwrap())
                .unwrap();
        let asset_id = create_test_instrument(&mut original, "TCR");
        let checkpoint = original.checkpoint().unwrap();
        let commitment = checkpoint["checkpoint"]["device_binding_commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(original);

        let mut restored_config: Value = serde_json::from_str(&cfg).unwrap();
        restored_config["backup_verified"] = json!(false);
        restored_config["expected_device_binding_commitment"] = json!(commitment);
        let mut restored = AccountWallet::open_device_bound(
            &restored_config.to_string(),
            &key,
            &[],
            restored_path.to_str().unwrap(),
        )
        .unwrap();
        let status = restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        assert_eq!(status["device_binding"]["status"], "mismatch_read_only");
        assert_eq!(status["write_enabled"], false);
        assert_eq!(
            restored.checkpoint().unwrap()["checkpoint"]["assets"][0]["asset_id"],
            asset_id
        );
        // Identical replay is idempotent; a byte-tampered hash is rejected.
        restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        let mut tampered = checkpoint;
        tampered["checkpoint_hash"] = json!("00");
        assert_eq!(
            restored
                .restore_checkpoint(&tampered.to_string())
                .unwrap_err()
                .code,
            "backup_checkpoint_hash_mismatch"
        );
    }

    #[cfg(feature = "test-wallet-recovery")]
    #[test]
    fn test_rebind_is_signet_only_idempotent_and_backup_gated() {
        let dir = tempfile::tempdir().unwrap();
        let original_path = dir.path().join("original.sqlite");
        let restored_path = dir.path().join("restored.sqlite");
        let key = [41u8; 32];
        let original_binding = [42u8; 32];
        let replacement_binding = [43u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &original_binding,
            original_path.to_str().unwrap(),
        )
        .unwrap();
        create_test_instrument(&mut original, "TST");
        let checkpoint = original.checkpoint().unwrap();
        let old_commitment = checkpoint["checkpoint"]["device_binding_commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(original);

        let mut restored_config: Value = serde_json::from_str(&cfg).unwrap();
        restored_config["backup_verified"] = json!(false);
        restored_config["expected_device_binding_commitment"] = json!(old_commitment);
        let mut restored = AccountWallet::open_device_bound(
            &restored_config.to_string(),
            &key,
            &[],
            restored_path.to_str().unwrap(),
        )
        .unwrap();
        restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();

        let first = restored.rebind_test_device(&replacement_binding).unwrap();
        assert_eq!(first["status"], "checkpoint_ready");
        assert_eq!(first["idempotent"], false);
        assert_eq!(first["backup_required"], true);
        assert_eq!(first["write_enabled"], false);
        let new_commitment = first["device_binding_commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(new_commitment, old_commitment);
        assert_eq!(
            first["checkpoint"]["checkpoint"]["device_binding_commitment"],
            new_commitment
        );

        let replay = restored.rebind_test_device(&replacement_binding).unwrap();
        assert_eq!(replay["idempotent"], true);
        assert_eq!(
            restored.rebind_test_device(&[44u8; 32]).unwrap_err().code,
            "conflicting_test_rebind"
        );
        restored.set_backup_state(true, CHECKPOINT_VERSION).unwrap();
        assert_eq!(restored.status().unwrap()["write_enabled"], true);
        assert_eq!(
            restored
                .rebind_test_device(&replacement_binding)
                .unwrap_err()
                .code,
            "test_rebind_already_write_enabled"
        );
        drop(restored);

        restored_config["expected_device_binding_commitment"] = json!(new_commitment);
        let mut reopened = AccountWallet::open_device_bound(
            &restored_config.to_string(),
            &key,
            &replacement_binding,
            restored_path.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.status().unwrap()["write_enabled"], true);
    }

    #[cfg(feature = "test-wallet-recovery")]
    #[test]
    fn test_rebind_runtime_rejects_mainnet() {
        let dir = tempfile::tempdir().unwrap();
        let mut mainnet: Value =
            serde_json::from_str(&config(AccountRole::Primary, false)).unwrap();
        mainnet["network"] = json!("mainnet");
        let mut wallet = AccountWallet::open_device_bound(
            &mainnet.to_string(),
            &[51u8; 32],
            &[],
            dir.path().join("mainnet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            wallet.rebind_test_device(&[52u8; 32]).unwrap_err().code,
            "test_rebind_network_forbidden"
        );
    }

    #[test]
    fn linked_device_rejects_private_account_key() {
        let cfg = json!({
            "version": 1,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "linked",
            "watch_external_descriptor": "wpkh(tpubD6NzVbkrYhZ4Y/example/*)",
            "watch_internal_descriptor": "wpkh(tpubD6NzVbkrYhZ4Y/change/*)",
        })
        .to_string();
        let dir = tempfile::tempdir().unwrap();
        let error = AccountWallet::open(
            &cfg,
            &[9u8; 32],
            dir.path().join("linked.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "linked_key_forbidden");
    }

    #[test]
    fn disabling_backup_freezes_writes_without_erasing_status() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[3u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert!(wallet.write_enabled().unwrap());
        wallet.set_backup_state(false, CHECKPOINT_VERSION).unwrap();
        assert!(!wallet.write_enabled().unwrap());
        assert!(wallet.status().is_ok());
        assert!(wallet.checkpoint().is_ok());
    }

    #[test]
    fn action_requests_reject_caller_selected_bitcoin_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[4u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let error = wallet
            .mint_prepare(
                &json!({
                    "currency": "USD",
                    "amounts": [100],
                    "wif": "caller-secret",
                    "utxos": ["caller-selected"],
                    "change_address": "caller-selected",
                    "bitcoin_recipient": "arbitrary-send",
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");

        let error = wallet
            .transfer_plan(
                &json!({
                    "asset_id": hex_encode(&[8u8; 32]),
                    "to_owner": hex_encode(&[9u8; 32]),
                    "amount": 10,
                    "coin_ids": ["caller-selected"],
                    "amounts": [10],
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn planned_transfer_is_durable_before_background_proving() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [67u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let planned = wallet
            .transfer_plan(
                &json!({
                    "asset_id": hex_encode(&[68u8; 32]),
                    "to_owner": hex_encode(&[69u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap().to_owned();
        assert_eq!(planned["state"], OperationState::Planned.as_str());
        assert!(planned["funding_txid"].is_null());
        drop(wallet);

        let mut reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let restored = reopened.operation_status(&operation_id).unwrap();
        assert_eq!(restored["state"], OperationState::Planned.as_str());
        assert_eq!(restored["request"]["amount"], 1);
        assert_eq!(
            reopened.cancel_operation(&operation_id).unwrap()["state"],
            OperationState::Cancelled.as_str(),
        );
    }

    #[test]
    #[ignore = "slow recursive receipt; run explicitly with --release --ignored"]
    fn planned_transfer_resumes_proving_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [68u8; 32];
        let observed_parent = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([70u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let parent_txid = observed_parent.compute_txid();
        let (esplora_url, server) = observed_raw_transaction_server(observed_parent);
        let mut config_value: Value =
            serde_json::from_str(&config(AccountRole::Primary, true)).unwrap();
        config_value["esplora_url"] = json!(esplora_url);
        let cfg = config_value.to_string();
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 50_000);
        let minted = prepare_test_issuance(&mut wallet, "ASY", &[60, 40]).unwrap();
        let asset_id = minted["asset_id"].as_str().unwrap().to_owned();
        let mint_operation = minted["operation_id"].as_str().unwrap().to_owned();
        finalize_test_operation(&mut wallet, &mint_operation, parent_txid);
        fund(&mut wallet, 40_000);

        let planned = wallet
            .transfer_plan(
                &json!({
                    "asset_id": asset_id,
                    "to_owner": hex_encode(&[72u8; 32]),
                    "amount": 70,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap().to_owned();
        assert_eq!(planned["state"], OperationState::Planned.as_str());
        assert!(planned["funding_txid"].is_null());
        assert!(!wallet.pending_by_operation.contains_key(&operation_id));

        let reserved = wallet.reserve_fee_utxo(&operation_id).unwrap().outpoint;
        assert_eq!(
            wallet.operation(&operation_id).unwrap().state,
            OperationState::FeeReserved.as_str(),
        );
        drop(wallet);

        let mut reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        allow_funding_verification(&mut reopened);
        assert!(reopened.bitcoin.is_outpoint_locked(reserved));
        let prepared = reopened.prove_operation(&operation_id).unwrap();
        assert_eq!(prepared["operation_id"], operation_id);
        assert_eq!(prepared["state"], OperationState::ProofReady.as_str());
        assert!(reopened.pending_by_operation.contains_key(&operation_id));
        assert_eq!(reopened.prove_operation(&operation_id).unwrap(), prepared);
        server.join().unwrap();
    }

    #[test]
    fn ticker_only_mint_cannot_create_an_asset() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[31u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let error = wallet
            .mint_prepare(&json!({ "currency": "USD", "amounts": [100] }).to_string())
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        let asset_count: u32 = wallet
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_assets", [], |row| row.get(0))
            .unwrap();
        let operation_count: u32 = wallet
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(asset_count, 0);
        assert_eq!(operation_count, 0);
    }

    #[test]
    fn issuer_backup_acknowledges_only_the_exact_current_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[39u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        wallet
            .instrument_create(&test_instrument_request("USD"))
            .unwrap();
        assert_eq!(wallet.status().unwrap()["backup_verified"], false);
        assert_eq!(
            wallet
                .acknowledge_checkpoint_backup(&hex_encode(&[0u8; 32]))
                .unwrap_err()
                .code,
            "backup_checkpoint_mismatch"
        );

        let checkpoint = wallet.checkpoint().unwrap();
        let checkpoint_hash = checkpoint["checkpoint_hash"].as_str().unwrap();
        let receipt = wallet
            .acknowledge_checkpoint_backup(checkpoint_hash)
            .unwrap();
        assert_eq!(receipt["backup_verified"], true);
        assert_eq!(receipt["checkpoint_hash"], checkpoint_hash);
        assert_eq!(wallet.status().unwrap()["write_enabled"], true);
    }

    #[test]
    fn configured_usd_issuers_share_one_product_but_keep_exact_identities() {
        let dir = tempfile::tempdir().unwrap();
        let first = test_usd_issuer_policy(41, "OpenCSV test issuer", 20);
        let second = test_usd_issuer_policy(42, "Tether test issuer", 10);
        let first_manifest =
            serde_json::from_value::<InstrumentManifestV1>(first["manifest"].clone()).unwrap();
        let second_manifest =
            serde_json::from_value::<InstrumentManifestV1>(second["manifest"].clone()).unwrap();
        let first_id = hex_encode(first_manifest.genesis.asset_id().as_bytes());
        let second_id = hex_encode(second_manifest.genesis.asset_id().as_bytes());
        assert_ne!(first_id, second_id);

        let mut wallet = AccountWallet::open(
            &config_with_usd_issuers(vec![first, second]),
            &[32u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = wallet.status().unwrap();
        assert_eq!(status["issuance_enabled"], false);
        assert_eq!(status["assets"].as_array().unwrap().len(), 0);
        assert_eq!(status["instruments"].as_array().unwrap().len(), 2);
        assert_eq!(status["instruments"][0]["asset_id"], second_id);
        assert_eq!(status["instruments"][0]["profile"], "trusted_usd_v1");
        assert_eq!(status["instruments"][0]["issuer_priority"], 10);
        assert_eq!(status["instruments"][1]["asset_id"], first_id);
        assert_eq!(status["instruments"][1]["profile"], "trusted_usd_v1");
    }

    #[test]
    fn usd_issuer_policy_rejects_ticker_only_trust_and_duplicate_ids() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = test_usd_issuer_policy(43, "OpenCSV test issuer", 10);
        let duplicate = issuer.clone();
        let error = AccountWallet::open(
            &config_with_usd_issuers(vec![issuer, duplicate]),
            &[37u8; 32],
            dir.path().join("duplicate.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "invalid_config");

        let mut wrong_unit = test_usd_issuer_policy(44, "OpenCSV test issuer", 10);
        wrong_unit["manifest"]["terms"]["unit_code"] = json!("EUR");
        let error = AccountWallet::open(
            &config_with_usd_issuers(vec![wrong_unit]),
            &[38u8; 32],
            dir.path().join("wrong-unit.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "invalid_config");
    }

    #[test]
    fn checkpoint_restore_preserves_manifest_but_never_arms_writes() {
        let dir = tempfile::tempdir().unwrap();
        let key = [33u8; 32];
        let binding = [34u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let created = original
            .instrument_create(&test_instrument_request("TRS"))
            .unwrap();
        let checkpoint = original.checkpoint().unwrap();
        let checkpoint_json = checkpoint.to_string();
        let commitment = original.status().unwrap()["device_binding"]["commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        drop(original);

        let mut recovery_config: Value = serde_json::from_str(&cfg).unwrap();
        recovery_config["expected_device_binding_commitment"] = json!(commitment);
        let mut restored = AccountWallet::open_device_bound(
            &recovery_config.to_string(),
            &key,
            &[],
            dir.path().join("restored.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = restored.restore_checkpoint(&checkpoint_json).unwrap();
        assert_eq!(status["write_enabled"], false);
        assert_eq!(status["device_binding"]["status"], "mismatch_read_only");
        assert_eq!(status["instruments"][0]["asset_id"], created["asset_id"]);
        assert_eq!(
            status["instruments"][0]["manifest"]["terms"]["unit_code"],
            "TRS"
        );
        assert_eq!(
            restored
                .mint_prepare(
                    &json!({ "asset_id": created["asset_id"], "amounts": [1] }).to_string(),
                )
                .unwrap_err()
                .code,
            "device_binding_mismatch"
        );
    }

    #[test]
    fn checkpoint_restore_rejects_tampering_before_writing() {
        let dir = tempfile::tempdir().unwrap();
        let key = [35u8; 32];
        let binding = [36u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        original
            .instrument_create(&test_instrument_request("TRJ"))
            .unwrap();
        let mut checkpoint = original.checkpoint().unwrap();
        let commitment = original.status().unwrap()["device_binding"]["commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        checkpoint["checkpoint"]["instrument_manifests"][0]["terms"]["issuer_name"] =
            json!("dishonest replacement");
        drop(original);

        let mut recovery_config: Value = serde_json::from_str(&cfg).unwrap();
        recovery_config["expected_device_binding_commitment"] = json!(commitment);
        let mut restored = AccountWallet::open_device_bound(
            &recovery_config.to_string(),
            &key,
            &[],
            dir.path().join("restored.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            restored
                .restore_checkpoint(&checkpoint.to_string())
                .unwrap_err()
                .code,
            "backup_checkpoint_hash_mismatch"
        );
        let count: i64 = restored
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_assets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn proof_ready_operation_survives_reopen_and_can_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [5u8; 32];
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        let funding = fund(&mut wallet, 50_000);
        let prepared = prepare_test_issuance(&mut wallet, "TPR", &[100]).unwrap();
        assert_eq!(prepared["asset_id"].as_str().unwrap().len(), 64);
        assert_eq!(prepared["to_owner"].as_str().unwrap().len(), 64);
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        assert!(wallet.bitcoin.is_outpoint_locked(funding));
        drop(wallet);

        let mut reopened = AccountWallet::open(
            &config(AccountRole::Primary, false),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        assert!(reopened.pending_by_operation.contains_key(&operation_id));
        assert!(reopened.bitcoin.is_outpoint_locked(funding));
        let cancelled = reopened.cancel_operation(&operation_id).unwrap();
        assert_eq!(cancelled["state"], "cancelled");
        assert!(!reopened.bitcoin.is_outpoint_locked(funding));
    }

    #[test]
    fn prepared_checkpoint_is_exportable_and_stable_across_acknowledgement() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[40u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 50_000);

        let prepared = prepare_test_issuance(&mut wallet, "TCP", &[100]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap();
        let prepared_hash = prepared["checkpoint_hash"].as_str().unwrap();
        assert_eq!(
            wallet.checkpoint().unwrap()["checkpoint_hash"],
            prepared_hash
        );

        let acknowledged = wallet
            .acknowledge_operation_backup(operation_id, prepared_hash)
            .unwrap();
        assert_eq!(acknowledged["backup_acked"], true);
        assert_eq!(
            wallet.checkpoint().unwrap()["checkpoint_hash"],
            prepared_hash
        );
    }

    #[test]
    fn operation_backup_rejects_a_checkpoint_after_wallet_state_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[41u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 50_000);

        let prepared = prepare_test_issuance(&mut wallet, "TCS", &[100]).unwrap();
        wallet
            .insert_planned_operation("later-operation", "transfer", "{}", "later-delivery-nonce")
            .unwrap();
        assert_eq!(
            wallet
                .acknowledge_operation_backup(
                    prepared["operation_id"].as_str().unwrap(),
                    prepared["checkpoint_hash"].as_str().unwrap(),
                )
                .unwrap_err()
                .code,
            "backup_checkpoint_mismatch"
        );
    }

    #[test]
    fn signed_transaction_is_persisted_before_failed_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &[6u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        let funding = fund(&mut wallet, 50_000);
        let prepared = prepare_test_issuance(&mut wallet, "TEU", &[25]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap();
        wallet
            .acknowledge_operation_backup(
                operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        let pending = wallet
            .sign_and_broadcast(
                operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        assert_eq!(
            pending["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        assert_eq!(pending["receipt"]["generic_relay_fallback"], false);
        let operation = wallet.operation(operation_id).unwrap();
        assert_eq!(
            operation.state,
            OperationState::BroadcastUnobserved.as_str()
        );
        let signed = operation.signed_tx_hex.unwrap();
        let transaction: Transaction =
            deserialize(&hex_decode(&signed, "signed tx").unwrap()).unwrap();
        assert_eq!(transaction.input[0].previous_output, funding);
        assert_eq!(transaction.output.len(), 3);
        let mut wrong_bytes = serialize(&transaction);
        *wrong_bytes.last_mut().unwrap() ^= 1;
        assert_eq!(
            wallet
                .observe_operation_unconfirmed(operation_id, &wrong_bytes, r#"{"observations":[]}"#)
                .unwrap_err()
                .code,
            "raw_transaction_mismatch"
        );
        assert_eq!(
            wallet.operation(operation_id).unwrap().state,
            OperationState::BroadcastUnobserved.as_str()
        );
        let raw = serialize(&transaction);
        let now = unix_time_millis().unwrap();
        let evidence = json!({
            "observations": [{
                "check_id": "test_accelerator",
                "endpoint": "http://127.0.0.1:1",
                "result": "observed",
                "started_at_ms": now - 2,
                "completed_at_ms": now - 1,
                "cached_at_ms": now - 1,
                "certificate_chain_fingerprints_sha256": [],
                "raw_transaction_hex": hex_encode(&raw),
            }]
        });
        let observed = wallet
            .observe_operation_unconfirmed(operation_id, &raw, &evidence.to_string())
            .unwrap();
        assert_eq!(observed["state"], OperationState::Mempool.as_str());
        assert!(transaction.output[0].script_pubkey.is_op_return());
        assert_eq!(transaction.output[1].script_pubkey.as_bytes(), MARKER_SPK);
        assert!(!transaction.output[2].script_pubkey.is_op_return());
    }

    #[test]
    fn authoritative_rejection_blocks_dishonest_explorer_hint() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[7u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let funding = fund(&mut wallet, 50_000);
        let verifier = use_scripted_verifier(
            &mut wallet,
            [VerificationVerdict::Reject(
                "stale_chain_state",
                "verified blocks do not contain the explorer-advertised outpoint",
            )],
        );

        let asset_id = create_test_instrument(&mut wallet, "TCA");
        let error = wallet
            .mint_prepare(&json!({ "asset_id": asset_id, "amounts": [10] }).to_string())
            .unwrap_err();
        assert_eq!(error.code, "stale_chain_state");
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        assert!(!wallet.bitcoin.is_outpoint_locked(funding));
        let reservations: u32 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_utxo_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reservations, 0);
        let (state, reason): (String, Option<String>) = wallet
            .db
            .conn
            .query_row(
                "SELECT state, rejection_reason FROM opencsv_operations
                 ORDER BY created_at DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, OperationState::Cancelled.as_str());
        assert_eq!(reason.as_deref(), Some("stale_chain_state"));
    }

    #[test]
    fn recently_spent_funding_is_rejected_again_at_sign_time() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &[8u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        fund(&mut wallet, 50_000);
        let verifier = use_scripted_verifier(
            &mut wallet,
            [
                VerificationVerdict::Accept,
                VerificationVerdict::Reject(
                    "conflicting_operation",
                    "verified block spends reserved fee outpoint",
                ),
            ],
        );
        let prepared = prepare_test_issuance(&mut wallet, "TGB", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap();
        wallet
            .acknowledge_operation_backup(
                operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();

        let error = wallet
            .sign_and_broadcast(
                operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "conflicting_operation");
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 2);
        let operation = wallet.operation(operation_id).unwrap();
        assert_eq!(operation.state, OperationState::ProofReady.as_str());
        assert!(operation.signed_tx_hex.is_none());
        assert_eq!(
            operation.rejection_reason.as_deref(),
            Some("conflicting_operation")
        );
    }

    #[test]
    fn concurrent_handles_reserve_distinct_fee_outpoints() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [9u8; 32];
        let mut first = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        let larger = fund(&mut first, 60_000);
        let smaller = fund(&mut first, 50_000);
        assert_ne!(larger, smaller);
        let asset_id = create_test_instrument(&mut first, "TCN");
        let mut second = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        let second_outpoints: Vec<OutPoint> = second
            .bitcoin
            .list_unspent()
            .map(|output| output.outpoint)
            .collect();
        assert!(second_outpoints.contains(&larger));
        assert!(second_outpoints.contains(&smaller));
        allow_funding_verification(&mut first);
        allow_funding_verification(&mut second);

        let first_prepared = first
            .mint_prepare(&json!({ "asset_id": asset_id, "amounts": [10] }).to_string())
            .unwrap();
        let second_prepared = second
            .mint_prepare(&json!({ "asset_id": asset_id, "amounts": [10] }).to_string())
            .unwrap();
        assert_eq!(
            first_prepared["funding_outpoint"],
            json!(larger.to_string())
        );
        assert_eq!(
            second_prepared["funding_outpoint"],
            json!(smaller.to_string())
        );
        assert_ne!(
            first_prepared["funding_outpoint"],
            second_prepared["funding_outpoint"]
        );
        let first_operation = first_prepared["operation_id"].as_str().unwrap().to_owned();
        let second_operation = second_prepared["operation_id"].as_str().unwrap().to_owned();
        drop(first);
        drop(second);

        let reopened = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        assert!(reopened.bitcoin.is_outpoint_locked(larger));
        assert!(reopened.bitcoin.is_outpoint_locked(smaller));
        assert!(reopened.pending_by_operation.contains_key(&first_operation));
        assert!(reopened
            .pending_by_operation
            .contains_key(&second_operation));
    }

    #[test]
    fn prebroadcast_states_reopen_and_incomplete_finalized_state_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [24u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 70_000);
        fund(&mut wallet, 60_000);

        wallet
            .insert_planned_operation("planned-op", "mint", "{}", "planned-delivery")
            .unwrap();
        wallet
            .insert_planned_operation("reserved-op", "mint", "{}", "reserved-delivery")
            .unwrap();
        let reserved = wallet.reserve_fee_utxo("reserved-op").unwrap().outpoint;
        let prepared = prepare_test_issuance(&mut wallet, "TCH", &[10]).unwrap();
        let proof_operation = prepared["operation_id"].as_str().unwrap().to_owned();
        let proof_outpoint =
            operation_outpoint(&wallet.operation(&proof_operation).unwrap()).unwrap();
        drop(wallet);

        let mut reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        assert_eq!(
            reopened.operation("planned-op").unwrap().state,
            OperationState::Planned.as_str()
        );
        assert_eq!(
            reopened.operation("reserved-op").unwrap().state,
            OperationState::FeeReserved.as_str()
        );
        assert!(reopened.bitcoin.is_outpoint_locked(reserved));
        assert!(reopened.bitcoin.is_outpoint_locked(proof_outpoint));
        assert!(reopened.pending_by_operation.contains_key(&proof_operation));

        for state in [
            OperationState::ProofReady,
            OperationState::SignedPersisted,
            OperationState::BroadcastUnobserved,
            OperationState::Broadcast,
        ] {
            reopened
                .db
                .conn
                .execute(
                    "UPDATE opencsv_operations SET state = ?2 WHERE operation_id = ?1",
                    params![&proof_operation, state.as_str()],
                )
                .unwrap();
            drop(reopened);
            reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
            assert_eq!(
                reopened.operation(&proof_operation).unwrap().state,
                state.as_str()
            );
            assert!(reopened.pending_by_operation.contains_key(&proof_operation));
            assert!(reopened.bitcoin.is_outpoint_locked(proof_outpoint));
        }

        assert_eq!(
            reopened.cancel_operation("planned-op").unwrap()["state"],
            OperationState::Cancelled.as_str()
        );
        reopened
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = ?2 WHERE operation_id = ?1",
                params![&proof_operation, OperationState::Mempool.as_str()],
            )
            .unwrap();
        drop(reopened);
        let error = AccountWallet::open(&cfg, &key, path.to_str().unwrap())
            .err()
            .unwrap();
        assert_eq!(
            error.code, "database_corrupt",
            "a finalized state without an exact txid and receipt is impossible"
        );
    }

    #[test]
    fn finalized_local_operations_restore_spends_and_change_without_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [52u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let asset_id = hex_encode(&[57u8; 32]);
        let own_owner = wallet.status().unwrap()["owners"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let recipient_owner = hex_encode(&[58u8; 32]);
        let mint_operation = "fixture-mint";
        install_replay_operation(
            &mut wallet,
            mint_operation,
            &[(60, own_owner.clone()), (40, own_owner.clone())],
            Vec::new(),
            &asset_id,
            59,
        );
        finalize_test_operation(
            &mut wallet,
            mint_operation,
            Txid::from_byte_array([60u8; 32]),
        );
        assert_eq!(wallet.status().unwrap()["assets"][0]["amount"], 100);

        let spent_ids = wallet
            .primary_protocol_mut()
            .unwrap()
            .list_coins()
            .into_iter()
            .filter(|coin| coin.unspent)
            .map(|coin| coin.id)
            .collect::<Vec<_>>();
        assert_eq!(spent_ids.len(), 2);
        let transfer_operation = "fixture-transfer";
        install_replay_operation(
            &mut wallet,
            transfer_operation,
            &[(70, recipient_owner.clone()), (30, own_owner)],
            spent_ids,
            &asset_id,
            61,
        );
        finalize_test_operation(
            &mut wallet,
            transfer_operation,
            Txid::from_byte_array([62u8; 32]),
        );
        assert_eq!(wallet.status().unwrap()["assets"][0]["amount"], 30);
        drop(wallet);

        let mut reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        assert_eq!(reopened.status().unwrap()["assets"][0]["amount"], 30);
        assert!(reopened
            .primary_protocol_mut()
            .unwrap()
            .prove_transfer_amount(&asset_id, &recipient_owner, 1)
            .is_err());
        reopened
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = ?2 WHERE operation_id = ?1",
                params![
                    transfer_operation,
                    OperationState::ConsignmentDelivered.as_str(),
                ],
            )
            .unwrap();
        reopened
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_operations(
                     operation_id, kind, state, request_json, funding_txid, funding_vout,
                     funding_value_sats, pending_json, psbt_base64, signed_tx_hex, txid,
                     receipt_json, rejection_reason, delivery_nonce, checkpoint_hash,
                     backup_acked, created_at, updated_at
                 )
                 SELECT 'duplicate-finalized-op', kind, 'mempool', request_json, funding_txid,
                        funding_vout, funding_value_sats, pending_json, psbt_base64,
                        signed_tx_hex, txid, receipt_json, rejection_reason,
                        'duplicate-delivery', checkpoint_hash, backup_acked,
                        created_at + 1, updated_at + 1
                 FROM opencsv_operations WHERE operation_id = ?1",
                [transfer_operation],
            )
            .unwrap();
        drop(reopened);

        let mut repaired = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        assert_eq!(repaired.status().unwrap()["assets"][0]["amount"], 30);
        assert_eq!(repaired.status().unwrap()["backup_verified"], false);
        let rejected = repaired.operation("duplicate-finalized-op").unwrap();
        assert_eq!(rejected.state, OperationState::ProtocolRejected.as_str());
        assert_eq!(
            rejected.rejection_reason.as_deref(),
            Some("duplicate_protocol_spend")
        );

        repaired
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'mempool'
                 WHERE operation_id IN (?1, 'duplicate-finalized-op')",
                [transfer_operation],
            )
            .unwrap();
        drop(repaired);
        let error = AccountWallet::open(&cfg, &key, path.to_str().unwrap())
            .err()
            .unwrap();
        assert_eq!(error.code, "protocol_state_conflict");
        assert!(error.message.contains("no confirmed winner"));
    }

    #[test]
    fn finalized_replay_rejects_tampered_consignment_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [63u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let asset_id = hex_encode(&[64u8; 32]);
        let own_owner = wallet.status().unwrap()["owners"][0]
            .as_str()
            .unwrap()
            .to_owned();
        install_replay_operation(
            &mut wallet,
            "tampered-receipt",
            &[(100, own_owner)],
            Vec::new(),
            &asset_id,
            65,
        );
        finalize_test_operation(
            &mut wallet,
            "tampered-receipt",
            Txid::from_byte_array([66u8; 32]),
        );
        let encoded: String = wallet
            .db
            .conn
            .query_row(
                "SELECT receipt_json FROM opencsv_operations WHERE operation_id = ?1",
                ["tampered-receipt"],
                |row| row.get(0),
            )
            .unwrap();
        let mut receipt: Value = serde_json::from_str(&encoded).unwrap();
        receipt["consignment_base64"] = json!("dishonest replacement");
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET receipt_json = ?2 WHERE operation_id = ?1",
                params!["tampered-receipt", receipt.to_string()],
            )
            .unwrap();
        drop(wallet);

        let error = AccountWallet::open(&cfg, &key, path.to_str().unwrap())
            .err()
            .unwrap();
        assert_eq!(error.code, "database_corrupt");
        assert!(error.message.contains("does not match its receipt"));
    }

    #[test]
    fn delivery_acknowledgement_preserves_mempool_fee_bump_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[25_u8; 32],
            path.to_str().unwrap(),
        )
        .unwrap();

        wallet
            .insert_planned_operation("mempool-op", "mint", "{}", "mempool-nonce")
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3
                 WHERE operation_id = ?1",
                params![
                    "mempool-op",
                    OperationState::Mempool.as_str(),
                    json!({ "delivery_ready": true }).to_string(),
                ],
            )
            .unwrap();
        let acknowledged = wallet
            .mark_consignment_delivered("mempool-op", "mempool-nonce")
            .unwrap();
        assert_eq!(acknowledged["state"], OperationState::Mempool.as_str());
        assert_eq!(acknowledged["receipt"]["consignment_delivered"], true);
        assert_eq!(
            wallet
                .mark_consignment_delivered("mempool-op", "mempool-nonce")
                .unwrap()["state"],
            OperationState::Mempool.as_str(),
            "delivery acknowledgement is idempotent without closing the RBF window",
        );

        wallet
            .insert_planned_operation("confirmed-op", "mint", "{}", "confirmed-nonce")
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3
                 WHERE operation_id = ?1",
                params![
                    "confirmed-op",
                    OperationState::Confirmed.as_str(),
                    json!({ "delivery_ready": true }).to_string(),
                ],
            )
            .unwrap();
        let terminal = wallet
            .mark_consignment_delivered("confirmed-op", "confirmed-nonce")
            .unwrap();
        assert_eq!(
            terminal["state"],
            OperationState::ConsignmentDelivered.as_str(),
        );
        assert_eq!(terminal["receipt"]["consignment_delivered"], true);
    }

    #[test]
    fn fee_replacement_regenerates_exact_txid_consignment() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[49u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 100_000);
        let prepared = prepare_test_issuance(&mut wallet, "TRB", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();

        let original_txid = Txid::from_byte_array([21u8; 32]);
        wallet
            .finalize_observed_operation(&operation_id, original_txid)
            .unwrap();
        let original = wallet.operation(&operation_id).unwrap();
        let delivery_nonce = original.delivery_nonce.clone();
        let original_receipt: Value =
            serde_json::from_str(original.receipt_json.as_deref().unwrap()).unwrap();
        let original_consignment_id = original_receipt["consignment_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            Consignment::from_bytes(
                &base64::engine::general_purpose::STANDARD
                    .decode(original_receipt["consignment_base64"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap()
            .anchor_ref
            .txid,
            original_txid.to_byte_array(),
        );
        wallet
            .mark_consignment_delivered(&operation_id, &delivery_nonce)
            .unwrap();

        let replacement_txid = Txid::from_byte_array([22u8; 32]);
        let mut replacement_receipt: Value = serde_json::from_str(
            wallet
                .operation(&operation_id)
                .unwrap()
                .receipt_json
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        replacement_receipt["replaces"] = json!(original_txid.to_string());
        replacement_receipt["txid"] = json!(replacement_txid.to_string());
        wallet
            .persist_signed_replacement(
                &operation_id,
                "00",
                replacement_txid,
                &mut replacement_receipt,
            )
            .unwrap();

        let replacement_pending = wallet.operation(&operation_id).unwrap();
        assert_eq!(
            replacement_pending.state,
            OperationState::SignedPersisted.as_str(),
        );
        assert!(wallet.pending_by_operation.contains_key(&operation_id));
        let replacement_pending_receipt: Value =
            serde_json::from_str(replacement_pending.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            replacement_pending_receipt["replacement_delivery_required"],
            true,
        );
        assert!(replacement_pending_receipt.get("delivery_ready").is_none());
        assert!(replacement_pending_receipt
            .get("consignment_delivered")
            .is_none());
        assert_eq!(
            replacement_pending_receipt["superseded_consignment_ids"],
            json!([original_consignment_id]),
        );
        let old_count: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_consignments WHERE consignment_id = ?1",
                [&original_consignment_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 0);

        wallet
            .finalize_observed_operation(&operation_id, replacement_txid)
            .unwrap();
        let finalized = wallet.operation(&operation_id).unwrap();
        let finalized_receipt: Value =
            serde_json::from_str(finalized.receipt_json.as_deref().unwrap()).unwrap();
        let replacement_blob = base64::engine::general_purpose::STANDARD
            .decode(finalized_receipt["consignment_base64"].as_str().unwrap())
            .unwrap();
        let replacement_consignment = Consignment::from_bytes(&replacement_blob).unwrap();
        assert_eq!(
            replacement_consignment.anchor_ref.txid,
            replacement_txid.to_byte_array(),
        );
        assert_ne!(
            finalized_receipt["consignment_id"],
            json!(original_consignment_id),
        );
        assert_eq!(finalized_receipt["delivery_ready"], true);
        assert!(finalized_receipt
            .get("replacement_delivery_required")
            .is_none());
    }

    #[test]
    fn fee_bump_bytes_survive_failed_relay_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [10u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 100_000);
        let prepared = prepare_test_issuance(&mut wallet, "TJP", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .acknowledge_operation_backup(
                &operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        let pending = wallet
            .sign_and_broadcast(
                &operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        assert_eq!(
            pending["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        let original_hex = wallet
            .operation(&operation_id)
            .unwrap()
            .signed_tx_hex
            .unwrap();
        let bump_pending = wallet.fee_bump(&operation_id, 5).unwrap();
        assert_eq!(
            bump_pending["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        let bumped = wallet.operation(&operation_id).unwrap();
        assert_eq!(bumped.state, OperationState::BroadcastUnobserved.as_str());
        let replacement_hex = bumped.signed_tx_hex.unwrap();
        assert_ne!(replacement_hex, original_hex);
        let original: Transaction =
            deserialize(&hex_decode(&original_hex, "original tx").unwrap()).unwrap();
        let replacement: Transaction =
            deserialize(&hex_decode(&replacement_hex, "replacement tx").unwrap()).unwrap();
        validate_solo_anchor_replacement(&original, &replacement).unwrap();
        let replacement_txid = replacement.compute_txid();
        drop(wallet);

        let mut reopened = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        let restored = reopened.operation(&operation_id).unwrap();
        assert_eq!(restored.state, OperationState::BroadcastUnobserved.as_str());
        assert_eq!(
            restored.signed_tx_hex.as_deref(),
            Some(replacement_hex.as_str())
        );
        assert!(reopened.bitcoin.get_tx(replacement_txid).is_some());
        assert_eq!(
            reopened.resume_operation(&operation_id).unwrap_err().code,
            "sync_failed"
        );
        assert_eq!(
            reopened
                .operation(&operation_id)
                .unwrap()
                .signed_tx_hex
                .as_deref(),
            Some(replacement_hex.as_str())
        );
    }

    #[test]
    fn confirmed_original_wins_a_persisted_replacement_race() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let (url, server) = confirmed_status_server(123);
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, &url),
            &[13_u8; 32],
            path.to_str().unwrap(),
        )
        .unwrap();
        let original_txid = fund(&mut wallet, 50_000).txid;
        let replacement = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let replacement_txid = replacement.compute_txid();
        let operation_id = "replacement-race";
        wallet
            .insert_planned_operation(operation_id, "mint", "{}", "delivery")
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = ?2, signed_tx_hex = ?3,
                 txid = ?4, receipt_json = ?5 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::SignedPersisted.as_str(),
                    hex_encode(&serialize(&replacement)),
                    replacement_txid.to_string(),
                    json!({
                        "replaces": original_txid.to_string(),
                        "txid": replacement_txid.to_string(),
                    })
                    .to_string(),
                ],
            )
            .unwrap();

        let receipt = wallet.resume_operation(operation_id).unwrap();
        assert_eq!(receipt["state"], OperationState::Confirmed.as_str());
        assert_eq!(receipt["confirmed"], true);
        assert_eq!(receipt["block_height"], 123);
        assert_eq!(receipt["txid"], original_txid.to_string());
        assert_eq!(
            receipt["receipt"]["failed_replacement_txid"],
            replacement_txid.to_string()
        );
        assert_eq!(
            receipt["receipt"]["fee_bump_outcome"],
            "original_confirmed_before_replacement_observed"
        );
        let restored = wallet.operation(operation_id).unwrap();
        let restored_tx: Transaction = deserialize(
            &hex_decode(
                restored.signed_tx_hex.as_deref().unwrap(),
                "restored original",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(restored_tx.compute_txid(), original_txid);
        server.join().unwrap();
    }

    #[test]
    fn post_reservation_prepare_failure_releases_fee_input() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [11u8; 32];
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        let funding = fund(&mut wallet, 100_000);

        let asset_id = create_test_instrument(&mut wallet, "TPF");
        let error = wallet
            .mint_prepare(
                &json!({ "asset_id": asset_id, "to_owner": "bad", "amounts": [10] }).to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "invalid_proof_request");
        assert!(!wallet.bitcoin.is_outpoint_locked(funding));
        let reservations: u32 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_utxo_reservations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reservations, 0);
        let (state, reason): (String, Option<String>) = wallet
            .db
            .conn
            .query_row(
                "SELECT state, rejection_reason FROM opencsv_operations
                 ORDER BY created_at DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, OperationState::Cancelled.as_str());
        assert_eq!(reason.as_deref(), Some("invalid_proof_request"));
    }

    #[test]
    fn fee_bump_reverification_failure_preserves_original_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [12u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        let verifier = use_scripted_verifier(
            &mut wallet,
            [
                VerificationVerdict::Accept,
                VerificationVerdict::Accept,
                VerificationVerdict::Reject(
                    "stale_chain_state",
                    "reserved funding outpoint was recently spent",
                ),
            ],
        );
        fund(&mut wallet, 100_000);
        let prepared = prepare_test_issuance(&mut wallet, "TSE", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .acknowledge_operation_backup(
                &operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        let pending = wallet
            .sign_and_broadcast(
                &operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        assert_eq!(
            pending["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        let before = wallet.operation(&operation_id).unwrap();
        let error = wallet.fee_bump(&operation_id, 5).unwrap_err();
        assert_eq!(error.code, "stale_chain_state");
        let after = wallet.operation(&operation_id).unwrap();
        assert_eq!(after.state, before.state);
        assert_eq!(after.signed_tx_hex, before.signed_tx_hex);
        assert_eq!(after.txid, before.txid);
        assert_eq!(after.rejection_reason.as_deref(), Some("stale_chain_state"));
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn account_network_vocabulary_maps_mainnet_to_bitcoin() {
        assert_eq!(parse_network("mainnet").unwrap(), Network::Bitcoin);
        assert_eq!(parse_network("signet").unwrap(), Network::Signet);
        assert_eq!(parse_network("regtest").unwrap(), Network::Regtest);
        assert!(parse_network("bitcoin").is_err());
    }
}
