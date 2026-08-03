//! Signal-native account wallet.
//!
//! This is the durable boundary that combines a BIP84 Bitcoin fee wallet,
//! the OpenCSV owner/issuer identities, and an operation journal. The host
//! supplies one random 32-byte account root for a primary device; Rust is
//! the only component that derives wallet keys from it. Linked devices open
//! with public descriptors and never receive signing material.

use std::collections::HashMap;
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
use opencsv_core::{AssetId, OwnerSecret};
use rand::RngExt as _;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::wallet::MemWallet;
use crate::{crosscheck, scan, snapshot::SnapshotChain};

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
    /// Required for linked devices; public external descriptor.
    #[serde(default)]
    pub watch_external_descriptor: Option<String>,
    /// Required for linked devices; public change descriptor.
    #[serde(default)]
    pub watch_internal_descriptor: Option<String>,
    /// Public OpenCSV owner identity supplied to linked devices.
    #[serde(default)]
    pub watch_owner: Option<String>,
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
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintRequest {
    #[serde(default)]
    asset_id: Option<String>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    terms_hash: Option<String>,
    #[serde(default)]
    to_owner: Option<String>,
    amounts: Vec<u64>,
}

#[derive(Debug, Deserialize)]
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
             CREATE TABLE IF NOT EXISTS opencsv_utxo_reservations (
                 txid TEXT NOT NULL,
                 vout INTEGER NOT NULL,
                 operation_id TEXT NOT NULL UNIQUE,
                 state TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(txid, vout),
                 FOREIGN KEY(operation_id) REFERENCES opencsv_operations(operation_id)
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
    issuer_root: Option<Zeroizing<[u8; 32]>>,
    root_fingerprint: String,
    device_binding_commitment: Option<String>,
    device_binding_valid: bool,
    pending_by_operation: HashMap<String, u64>,
}

impl AccountWallet {
    /// Open or initialize an account database.
    pub fn open_device_bound(
        config_json: &str,
        account_key: &[u8],
        device_binding_key: &[u8],
        database_path: &str,
    ) -> Result<Self, AccountError> {
        let config: AccountConfig = serde_json::from_str(config_json).map_err(|error| {
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
            issuer_root,
            root_fingerprint,
            device_binding_commitment,
            device_binding_valid,
            pending_by_operation: HashMap::new(),
        };
        account.restore_issuers()?;
        account.restore_consignment_state()?;
        account.restore_fee_reservations()?;
        account.restore_pending_operations()?;
        Ok(account)
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
                Ok(json!({
                    "status": "verified",
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

    /// Prepare an issuer-authorized mint. Fee selection, change derivation,
    /// and the OpenCSV proof all remain inside Rust.
    pub fn mint_prepare(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let request: MintRequest = serde_json::from_str(request_json).map_err(|error| {
            AccountError::new("invalid_request", format!("mint request: {error}"))
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

        let asset_id = match request.asset_id {
            Some(asset_id) => asset_id,
            None => {
                let currency = match request.currency.as_deref() {
                    Some(currency) => currency,
                    None => {
                        return self.fail_prebroadcast(
                            &operation_id,
                            AccountError::new(
                                "invalid_request",
                                "new mint requires a 3-byte currency code",
                            ),
                        );
                    }
                };
                match self.create_asset(currency, request.terms_hash.as_deref()) {
                    Ok(asset_id) => asset_id,
                    Err(error) => return self.fail_prebroadcast(&operation_id, error),
                }
            }
        };
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

    /// Prepare an OpenCSV asset transfer. There is deliberately no Bitcoin
    /// recipient or arbitrary-send field at this boundary.
    pub fn transfer_prepare(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let request: TransferRequest = serde_json::from_str(request_json).map_err(|error| {
            AccountError::new("invalid_request", format!("transfer request: {error}"))
        })?;
        let operation_id = random_id(16);
        let delivery_nonce = random_id(16);
        self.insert_planned_operation(&operation_id, "transfer", request_json, &delivery_nonce)?;
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
        let proved = {
            let protocol = match self.primary_protocol_mut() {
                Ok(protocol) => protocol,
                Err(error) => return self.fail_prebroadcast(&operation_id, error),
            };
            match protocol.prove_transfer_amount(
                &request.asset_id,
                &request.to_owner,
                request.amount,
            ) {
                Ok(proved) => proved,
                Err(error) => {
                    return self.fail_prebroadcast(
                        &operation_id,
                        AccountError::new("unavailable_assets", error),
                    );
                }
            }
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
        if let Err(error) = self.mark_proof_ready(
            &operation_id,
            &json!({
                "asset_id": request.asset_id,
                "to_owner": request.to_owner,
                "amount": request.amount,
            }),
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

        let relay = relay_transaction(
            self.bitcoin.network(),
            &self.config.peers,
            &tx,
            Duration::from_secs(8),
        );
        let p2p_submissions = relay.submitted_count();
        let relay_peers: Vec<Value> = relay
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
        let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
        let fallback = if p2p_submissions == 0 {
            client.broadcast(&tx).map(|_| true)
        } else {
            Ok(false)
        };
        if let Some(object) = receipt.as_object_mut() {
            object.insert("p2p_submissions".into(), json!(p2p_submissions));
            object.insert("p2p_peers".into(), json!(relay_peers));
            object.insert(
                "generic_relay_fallback".into(),
                json!(matches!(&fallback, Ok(true))),
            );
        }
        if let Err(error) = fallback {
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2,
                 rejection_reason = 'broadcast_unobserved', receipt_json = ?3,
                 updated_at = ?4
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::BroadcastUnobserved.as_str(),
                    receipt.to_string(),
                    unix_time()?
                ],
            )?;
            return Err(AccountError::new(
                "broadcast_unobserved",
                format!("signed transaction preserved for resume: {error}"),
            ));
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2,
             rejection_reason = NULL, receipt_json = ?3, updated_at = ?4
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::BroadcastUnobserved.as_str(),
                receipt.to_string(),
                unix_time()?
            ],
        )?;
        self.refresh_operation(operation_id)
    }

    /// Return one durable operation, refreshing mempool/confirmation state
    /// when a signed transaction exists.
    pub fn operation_status(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if operation.txid.is_some()
            && operation.state != OperationState::Cancelled.as_str()
            && operation.state != OperationState::ConsignmentDelivered.as_str()
        {
            return self.refresh_operation(operation_id);
        }
        operation_json(&operation)
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
                let relay = relay_transaction(
                    self.bitcoin.network(),
                    &self.config.peers,
                    &tx,
                    Duration::from_secs(8),
                );
                let client =
                    esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
                let observed = client
                    .get_tx(&tx.compute_txid())
                    .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
                let fallback_used = if observed.is_none() {
                    if let Err(error) = client.broadcast(&tx) {
                        if let Some(value) = self.reconcile_confirmed_replacement(
                            operation_id,
                            tx.compute_txid(),
                            &mut receipt,
                        )? {
                            return Ok(value);
                        }
                        return Err(AccountError::new(
                            "broadcast_unobserved",
                            format!("signed transaction preserved for resume: {error}"),
                        ));
                    }
                    true
                } else {
                    false
                };
                if let Some(object) = receipt.as_object_mut() {
                    object.insert(
                        "resume_p2p_submissions".into(),
                        json!(relay.submitted_count()),
                    );
                    object.insert("resume_generic_relay_fallback".into(), json!(fallback_used));
                }
                self.db.conn.execute(
                    "UPDATE opencsv_operations SET receipt_json = ?2,
                     updated_at = ?3 WHERE operation_id = ?1",
                    params![operation_id, receipt.to_string(), unix_time()?],
                )?;
                self.refresh_operation(operation_id)
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
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, signed_tx_hex = ?3,
             txid = ?4, receipt_json = ?5, updated_at = ?6
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::SignedPersisted.as_str(),
                replacement_hex,
                replacement_txid.to_string(),
                receipt.to_string(),
                unix_time()?,
            ],
        )?;
        let now = u64::try_from(unix_time()?)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        let seen_at = original_last_seen
            .and_then(|last_seen| last_seen.checked_add(1))
            .map_or(now, |next| next.max(now));
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(replacement.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let relay = relay_transaction(
            self.bitcoin.network(),
            &self.config.peers,
            &replacement,
            Duration::from_secs(8),
        );
        let p2p_submissions = relay.submitted_count();
        let relay_peers: Vec<Value> = relay
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
        let generic_relay_fallback = if p2p_submissions == 0 {
            let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
            client.broadcast(&replacement).map_err(|error| {
                AccountError::new(
                    "broadcast_unobserved",
                    format!("replacement persisted for resume: {error}"),
                )
            })?;
            true
        } else {
            false
        };
        if let Some(object) = receipt.as_object_mut() {
            object.insert("p2p_submissions".into(), json!(p2p_submissions));
            object.insert("p2p_peers".into(), json!(relay_peers));
            object.insert(
                "generic_relay_fallback".into(),
                json!(generic_relay_fallback),
            );
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
        self.refresh_operation(operation_id)
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
        if operation.state == OperationState::ConsignmentDelivered.as_str() {
            return operation_json(&operation);
        }
        if !matches!(operation.state.as_str(), "mempool" | "confirmed") {
            return Err(AccountError::new(
                "delivery_too_early",
                "consignment delivery starts only after transaction observation",
            ));
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::ConsignmentDelivered.as_str(),
                unix_time()?,
            ],
        )?;
        self.operation_status(operation_id)
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
        let operations = query_json_rows(
            &self.db.conn,
            "SELECT json_object('operation_id', operation_id, 'kind', kind,
                                'state', state, 'request', json(request_json),
                                'pending_json', pending_json,
                                'delivery_nonce', delivery_nonce,
                                'txid', txid)
             FROM opencsv_operations
             WHERE state NOT IN ('cancelled') ORDER BY created_at",
        )?;
        let consignments = query_json_rows(
            &self.db.conn,
            "SELECT json_object('consignment_id', consignment_id,
                                'consignment_base64', consignment_base64,
                                'spent_state', json(spent_state_json))
             FROM opencsv_consignments ORDER BY created_at",
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

    fn create_asset(
        &mut self,
        currency: &str,
        terms_hash: Option<&str>,
    ) -> Result<String, AccountError> {
        if currency.len() != 3 {
            return Err(AccountError::new(
                "invalid_request",
                "currency must be exactly three UTF-8 bytes",
            ));
        }
        let terms = match terms_hash {
            Some(value) => decode_hex_32(value, "terms hash")?,
            None => [0u8; 32],
        };
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
        let asset_id = self
            .primary_protocol_mut()?
            .init_issuer_from_seed(currency, seed, nonce, terms)
            .map_err(|error| AccountError::new("invalid_request", error))?;
        self.db.conn.execute(
            "INSERT INTO opencsv_assets(
                 asset_index, currency, terms_hash, nonce, asset_id
             ) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                next_index,
                currency,
                hex_encode(&terms),
                i64::try_from(nonce).map_err(|_| {
                    AccountError::new("database_error", "asset nonce exceeds SQLite range")
                })?,
                asset_id,
            ],
        )?;
        Ok(asset_id)
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
        let checkpoint = self.checkpoint()?;
        let checkpoint_hash = checkpoint["checkpoint_hash"]
            .as_str()
            .ok_or_else(|| AccountError::new("checkpoint_failed", "missing checkpoint hash"))?;
        let receipt = json!({
            "operation_id": operation_id,
            "state": OperationState::ProofReady.as_str(),
            "funding_outpoint": funding.outpoint.to_string(),
            "funding_value_sats": funding.value_sats(),
            "funding_verification": verification,
            "anchor_record_hex": hex_encode(record),
            "checkpoint_hash": checkpoint_hash,
            "backup_ack_required": true,
        });
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
            self.finalize_observed_operation(operation_id, txid)?;
        }
        if status.confirmed && operation.state != OperationState::ConsignmentDelivered.as_str() {
            self.db.conn.execute(
                "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
                 WHERE operation_id = ?1",
                params![
                    operation_id,
                    OperationState::Confirmed.as_str(),
                    unix_time()?,
                ],
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
        self.protocol
            .as_ref()
            .map(MemWallet::known_asset_ids)
            .ok_or_else(|| {
                AccountError::new(
                    "primary_required",
                    "linked device cannot credit private OpenCSV ownership",
                )
            })
    }

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
        let mut statement = self.db.conn.prepare(
            "SELECT c.consignment_base64, c.spent_state_json, s.snapshot_json
             FROM opencsv_consignments c
             JOIN opencsv_consignment_snapshots s USING(consignment_id)
             ORDER BY c.created_at",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut spent = Vec::new();
        for row in rows {
            let (encoded, spent_state, snapshot) = row?;
            let blob = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            let chain = SnapshotChain::from_json(&snapshot)
                .map_err(|error| AccountError::new("database_corrupt", error))?;
            match protocol
                .verify(&blob, &chain, u64::from(self.config.required_confirmations))
                .map_err(|error| AccountError::new("database_corrupt", error))?
            {
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
             ORDER BY created_at",
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
        "mainnet" | "signet" | "regtest" => Network::from_str(name)
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

fn unix_time() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AccountError::new("clock_error", error.to_string()))
        .and_then(|duration| {
            i64::try_from(duration.as_secs())
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
        }))
        .unwrap()
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
            .transfer_prepare(
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "USD", "amounts": [100] }).to_string())
            .unwrap();
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "EUR", "amounts": [25] }).to_string())
            .unwrap();
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
        assert_eq!(error.code, "broadcast_unobserved");
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

        let error = wallet
            .mint_prepare(&json!({ "currency": "CAD", "amounts": [10] }).to_string())
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "GBP", "amounts": [10] }).to_string())
            .unwrap();
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
            .mint_prepare(&json!({ "currency": "USD", "amounts": [10] }).to_string())
            .unwrap();
        let second_prepared = second
            .mint_prepare(&json!({ "currency": "EUR", "amounts": [10] }).to_string())
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
    fn every_durable_operation_state_reopens_with_expected_material() {
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "CHF", "amounts": [10] }).to_string())
            .unwrap();
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

        for state in [
            OperationState::Mempool,
            OperationState::Confirmed,
            OperationState::ConsignmentDelivered,
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
            assert!(!reopened.pending_by_operation.contains_key(&proof_operation));
            assert!(reopened.bitcoin.is_outpoint_locked(proof_outpoint));
        }

        assert_eq!(
            reopened.cancel_operation("planned-op").unwrap()["state"],
            OperationState::Cancelled.as_str()
        );
        drop(reopened);
        let reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        assert_eq!(
            reopened.operation("planned-op").unwrap().state,
            OperationState::Cancelled.as_str()
        );
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "JPY", "amounts": [10] }).to_string())
            .unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .acknowledge_operation_backup(
                &operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            wallet
                .sign_and_broadcast(
                    &operation_id,
                    &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
                )
                .unwrap_err()
                .code,
            "broadcast_unobserved"
        );
        let original_hex = wallet
            .operation(&operation_id)
            .unwrap()
            .signed_tx_hex
            .unwrap();
        assert_eq!(
            wallet.fee_bump(&operation_id, 5).unwrap_err().code,
            "broadcast_unobserved"
        );
        let bumped = wallet.operation(&operation_id).unwrap();
        assert_eq!(bumped.state, OperationState::SignedPersisted.as_str());
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
        assert_eq!(restored.state, OperationState::SignedPersisted.as_str());
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

        let error = wallet
            .mint_prepare(&json!({ "currency": "US", "amounts": [10] }).to_string())
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
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
        assert_eq!(reason.as_deref(), Some("invalid_request"));
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
        let prepared = wallet
            .mint_prepare(&json!({ "currency": "SEK", "amounts": [10] }).to_string())
            .unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .acknowledge_operation_backup(
                &operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            wallet
                .sign_and_broadcast(
                    &operation_id,
                    &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
                )
                .unwrap_err()
                .code,
            "broadcast_unobserved"
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
}
