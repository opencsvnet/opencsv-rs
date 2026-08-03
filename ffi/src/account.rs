//! Signal-native account wallet.
//!
//! This is the durable boundary that combines a BIP84 Bitcoin fee wallet,
//! the OpenCSV owner/issuer identities, and an operation journal. The host
//! supplies one random 32-byte account root for a primary device; Rust is
//! the only component that derives wallet keys from it. Linked devices open
//! with public descriptors and never receive signing material.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
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
use bdk_wallet::chain::Merge;
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::{
    ChangeSet, KeychainKind, PersistedWallet, SignOptions, TxOrdering, Wallet, WalletPersister,
};
use hkdf::Hkdf;
use opencsv_bitcoin::{
    funding_ctx, relay_transaction, validate_solo_anchor_replacement, MARKER_DUST_SATS, MARKER_SPK,
    MEMPOOL_LOCATION,
};
use opencsv_core::chain::AnchorRef;
use opencsv_core::{AssetId, OwnerSecret};
use rand::RngExt as _;
use rusqlite::{params, Connection, OptionalExtension};
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

/// Account configuration supplied by Signal. It contains no secret key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Schema version, currently one.
    #[serde(default = "schema_version")]
    pub version: u32,
    /// `mainnet`, `signet`, `testnet`, `testnet4`, or `regtest`.
    pub network: String,
    /// Esplora endpoint used as a read accelerator and generic relay fallback.
    pub esplora_url: String,
    /// P2P peers used for direct transaction relay.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Primary or linked-device role.
    #[serde(default = "default_role")]
    pub role: AccountRole,
    /// Initial Secure Backup state. Later changes use the explicit setter.
    #[serde(default)]
    pub backup_verified: bool,
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
    bitcoin: PersistedWallet<SqlitePersister>,
    db: SqlitePersister,
    protocol: Option<MemWallet>,
    issuer_root: Option<Zeroizing<[u8; 32]>>,
    root_fingerprint: String,
    pending_by_operation: HashMap<String, u64>,
}

impl AccountWallet {
    /// Open or initialize an account database.
    pub fn open(
        config_json: &str,
        account_key: &[u8],
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

        let (external, internal, protocol, issuer_root, root_fingerprint) = match config.role {
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
                (
                    external,
                    internal,
                    Some(MemWallet::from_owner_seed(*owner_seed)),
                    Some(issuer_root),
                    fingerprint,
                )
            }
            AccountRole::Linked => {
                if !account_key.is_empty() {
                    return Err(AccountError::new(
                        "linked_key_forbidden",
                        "linked devices must open without an account key",
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
                (external, internal, None, None, fingerprint)
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

        let mut account = Self {
            config,
            bitcoin,
            db,
            protocol,
            issuer_root,
            root_fingerprint,
            pending_by_operation: HashMap::new(),
        };
        account.restore_issuers()?;
        account.restore_consignment_state()?;
        account.restore_pending_operations()?;
        Ok(account)
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
            "sync_provenance": {
                "accelerator": self.config.esplora_url,
                "authoritative": "headers+bip158+verified-blocks",
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
            "authoritative_spend_check": "pending_local_cbf_revalidation",
        }))
    }

    /// Credit a consignment through the account wallet's single local
    /// bookkeeping path after the chosen chain view has accepted it.
    pub fn verify_consignment(
        &mut self,
        blob: &[u8],
        snapshot_json: &str,
    ) -> Result<Value, AccountError> {
        let chain = SnapshotChain::from_json(snapshot_json)
            .map_err(|error| AccountError::new("invalid_chain_view", error))?;
        let required_confirmations = u64::from(self.config.required_confirmations);
        let verdict = self
            .primary_protocol_mut()?
            .verify(blob, &chain, required_confirmations)
            .map_err(|error| AccountError::new("invalid_consignment", error))?;
        match verdict {
            Ok(verified) => {
                let consignment_id = sha256::Hash::hash(blob).to_string();
                self.db.conn.execute(
                    "INSERT INTO opencsv_consignments(
                         consignment_id, consignment_base64, spent_state_json, created_at
                     ) VALUES(?1, ?2, '{}', ?3)
                     ON CONFLICT(consignment_id) DO UPDATE SET
                         consignment_base64 = excluded.consignment_base64",
                    params![
                        consignment_id,
                        base64::engine::general_purpose::STANDARD.encode(blob),
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
                    "credits": verified.credits,
                    "coins": verified.coins,
                    "anchor": {
                        "height": verified.height,
                        "position": verified.position,
                    },
                }))
            }
            Err(reason) => Ok(json!({ "status": "rejected", "reason": reason })),
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
        if request.amounts.iter().any(|amount| *amount == 0) {
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
                self.reject_operation(&operation_id, error.code)?;
                return Err(error);
            }
        };
        let ctx = funding_context(funding.outpoint);

        let asset_id = match request.asset_id {
            Some(asset_id) => asset_id,
            None => self.create_asset(
                request.currency.as_deref().ok_or_else(|| {
                    AccountError::new(
                        "invalid_request",
                        "new mint requires a 3-byte currency code",
                    )
                })?,
                request.terms_hash.as_deref(),
            )?,
        };
        let protocol = self.primary_protocol_mut()?;
        let to_owner = request
            .to_owner
            .unwrap_or_else(|| protocol.owners().into_iter().next().unwrap_or_default());
        let proved = match protocol.prove_mint(&asset_id, &to_owner, &request.amounts) {
            Ok(proved) => proved,
            Err(error) => {
                self.release_fee_reservation(&operation_id)?;
                self.reject_operation(&operation_id, "invalid_proof_request")?;
                return Err(AccountError::new("invalid_proof_request", error));
            }
        };
        let record = protocol
            .rebind_pending(proved.pending_id, ctx)
            .map_err(|error| AccountError::new("protocol_layout_violation", error))?;
        let pending_json = protocol
            .export_pending(proved.pending_id)
            .map_err(|error| AccountError::new("database_error", error))?;
        self.pending_by_operation
            .insert(operation_id.clone(), proved.pending_id);
        let normalized_request = json!({
            "asset_id": asset_id,
            "to_owner": to_owner,
            "amounts": request.amounts,
        });
        self.mark_proof_ready(
            &operation_id,
            &normalized_request,
            &pending_json,
            &hex_encode(&record),
        )?;
        self.prepared_receipt(&operation_id, funding, &record)
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
                self.reject_operation(&operation_id, error.code)?;
                return Err(error);
            }
        };
        let ctx = funding_context(funding.outpoint);
        let protocol = self.primary_protocol_mut()?;
        let proved = match protocol.prove_transfer_amount(
            &request.asset_id,
            &request.to_owner,
            request.amount,
        ) {
            Ok(proved) => proved,
            Err(error) => {
                self.release_fee_reservation(&operation_id)?;
                self.reject_operation(&operation_id, "unavailable_assets")?;
                return Err(AccountError::new("unavailable_assets", error));
            }
        };
        let record = protocol
            .rebind_pending(proved.pending_id, ctx)
            .map_err(|error| AccountError::new("protocol_layout_violation", error))?;
        let pending_json = protocol
            .export_pending(proved.pending_id)
            .map_err(|error| AccountError::new("database_error", error))?;
        self.pending_by_operation
            .insert(operation_id.clone(), proved.pending_id);
        self.mark_proof_ready(
            &operation_id,
            &json!({
                "asset_id": request.asset_id,
                "to_owner": request.to_owner,
                "amount": request.amount,
            }),
            &pending_json,
            &hex_encode(&record),
        )?;
        self.prepared_receipt(&operation_id, funding, &record)
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
        let _funding = self
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
                let relay = relay_transaction(
                    self.bitcoin.network(),
                    &self.config.peers,
                    &tx,
                    Duration::from_secs(8),
                );
                if relay.submitted_count() == 0 {
                    let client =
                        esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
                    let _ = client.broadcast(&tx);
                }
                self.refresh_operation(operation_id)
            }
            _ => self.operation_status(operation_id),
        }
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
        let fee_rate = FeeRate::from_sat_per_vb(target_sat_per_vb).ok_or_else(|| {
            AccountError::new("invalid_fee_policy", "fee rate exceeds Bitcoin limits")
        })?;
        let mut builder = self
            .bitcoin
            .build_fee_bump(original_txid)
            .map_err(|error| AccountError::new("fee_bump_rejected", error.to_string()))?;
        builder.ordering(TxOrdering::Untouched);
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
        let receipt = json!({
            "operation_id": operation_id,
            "replaces": original_txid.to_string(),
            "txid": replacement_txid.to_string(),
            "target_sat_per_vb": target_sat_per_vb,
            "fee_increment_sats": validation.fee_increment_sats,
            "replacement_change_sats": validation.replacement_change_sats,
            "record_vout": 0,
            "marker_vout": 1,
            "change_vout": 2,
        });
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
        let relay = relay_transaction(
            self.bitcoin.network(),
            &self.config.peers,
            &replacement,
            Duration::from_secs(8),
        );
        if relay.submitted_count() == 0 {
            let client = esplora_client::Builder::new(&self.config.esplora_url).build_blocking();
            client.broadcast(&replacement).map_err(|error| {
                AccountError::new(
                    "broadcast_unobserved",
                    format!("replacement persisted for resume: {error}"),
                )
            })?;
        }
        self.db.conn.execute(
            "UPDATE opencsv_operations SET state = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::BroadcastUnobserved.as_str(),
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
        let candidate = self
            .bitcoin
            .list_unspent()
            .filter(|utxo| !self.bitcoin.is_outpoint_locked(utxo.outpoint))
            .filter(|utxo| utxo.txout.value.to_sat() >= MIN_FEE_RESERVE_SATS)
            .max_by_key(|utxo| utxo.txout.value.to_sat())
            .ok_or_else(|| {
                AccountError::new(
                    "insufficient_fees",
                    format!("no unreserved fee UTXO of at least {MIN_FEE_RESERVE_SATS} sats"),
                )
            })?;
        let funding = ReservedFunding {
            outpoint: candidate.outpoint,
            value_sats: candidate.txout.value.to_sat(),
        };
        self.bitcoin.lock_outpoint(funding.outpoint);
        self.bitcoin.persist(&mut self.db)?;
        let now = unix_time()?;
        let transaction = self.db.conn.transaction()?;
        transaction.execute(
            "INSERT INTO opencsv_utxo_reservations(
                 txid, vout, operation_id, state, created_at
             ) VALUES(?1, ?2, ?3, 'reserved', ?4)",
            params![
                funding.outpoint.txid.to_string(),
                funding.outpoint.vout,
                operation_id,
                now,
            ],
        )?;
        transaction.execute(
            "UPDATE opencsv_operations SET state = ?2, funding_txid = ?3,
             funding_vout = ?4, funding_value_sats = ?5, updated_at = ?6
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::FeeReserved.as_str(),
                funding.outpoint.txid.to_string(),
                funding.outpoint.vout,
                i64::try_from(funding.value_sats).map_err(|_| {
                    AccountError::new("database_error", "funding value exceeds SQLite range")
                })?,
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(funding)
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
        if currency.as_bytes().len() != 3 {
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
        record: &[u8; 64],
    ) -> Result<Value, AccountError> {
        let checkpoint = self.checkpoint()?;
        let checkpoint_hash = checkpoint["checkpoint_hash"]
            .as_str()
            .ok_or_else(|| AccountError::new("checkpoint_failed", "missing checkpoint hash"))?;
        self.db.conn.execute(
            "UPDATE opencsv_operations SET checkpoint_hash = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![operation_id, checkpoint_hash, unix_time()?],
        )?;
        Ok(json!({
            "operation_id": operation_id,
            "state": OperationState::ProofReady.as_str(),
            "funding_outpoint": funding.outpoint.to_string(),
            "funding_value_sats": funding.value_sats,
            "anchor_record_hex": hex_encode(record),
            "checkpoint_hash": checkpoint_hash,
            "backup_ack_required": true,
        }))
    }

    fn reject_operation(&self, operation_id: &str, reason: &str) -> Result<(), AccountError> {
        self.db.conn.execute(
            "UPDATE opencsv_operations SET rejection_reason = ?2,
             updated_at = ?3 WHERE operation_id = ?1",
            params![operation_id, reason, unix_time()?],
        )?;
        Ok(())
    }

    fn operation(&self, operation_id: &str) -> Result<OperationRow, AccountError> {
        self.db
            .conn
            .query_row(
                "SELECT operation_id, kind, state, request_json,
                        funding_txid, funding_vout, signed_tx_hex, txid,
                        receipt_json, delivery_nonce,
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
                        delivery_nonce: row.get(9)?,
                        checkpoint_hash: row.get(10)?,
                        backup_acked: row.get::<_, i64>(11)? != 0,
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
        Ok(self.config.role == AccountRole::Primary && self.backup_verified()?)
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

#[derive(Clone, Copy, Debug)]
struct ReservedFunding {
    outpoint: OutPoint,
    value_sats: u64,
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
    Network::from_str(name)
        .map_err(|_| AccountError::new("invalid_config", format!("unknown network `{name}`")))
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
    if value.len() % 2 != 0 {
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
    use bdk_wallet::bitcoin::absolute;
    use bdk_wallet::bitcoin::transaction;
    use bdk_wallet::bitcoin::{TxIn, TxOut, Witness};

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

    fn fund(wallet: &mut AccountWallet, value_sats: u64) -> OutPoint {
        let address = wallet
            .bitcoin
            .next_unused_address(KeychainKind::External)
            .address;
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([42u8; 32]), 0),
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
        wallet
            .bitcoin
            .apply_unconfirmed_txs([(Arc::new(transaction), 1)]);
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
}
