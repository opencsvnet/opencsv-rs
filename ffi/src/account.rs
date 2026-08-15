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
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bdk_esplora::{esplora_client, EsploraExt};
use bdk_wallet::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bdk_wallet::bitcoin::constants::genesis_block;
use bdk_wallet::bitcoin::hashes::{sha256, Hash as _};
use bdk_wallet::bitcoin::script::PushBytesBuf;
use bdk_wallet::bitcoin::secp256k1::{
    ecdsa::Signature as EcdsaSignature, Message, PublicKey, Secp256k1, SecretKey,
};
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
    batch_v2::{
        stock_witness_script, Manifest as BatchManifest, ParticipantCommitment,
        Proposal as BatchProposal,
    },
    funding_ctx, relay_transaction, validate_solo_anchor_replacement, Network as OpenCsvNetwork,
    MARKER_DUST_SATS, MARKER_SPK, MEMPOOL_LOCATION,
};
use opencsv_cbf::block::OutPoint as CbfOutPoint;
use opencsv_cbf::{CbfClient, Config as CbfConfig, OutpointVerdict};
use opencsv_core::chain::AnchorRef;
use opencsv_core::consignment::Consignment;
use opencsv_core::{
    witness_envelope_decode, AnchorRecord, AssetId, BatchVersion, Digest, InstrumentManifestV1,
    OwnerSecret, TruncatedDigest,
};
#[cfg(any(test, feature = "issuer-tools"))]
use opencsv_core::{AssetGenesis, InstrumentTermsV1, PoseidonIssuerAuthorization};
use rand::RngExt as _;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use url::Url;
use zeroize::Zeroizing;

use crate::wallet::MemWallet;
use crate::{
    crosscheck, scan,
    snapshot::{Snapshot, SnapshotBatchEnvelope, SnapshotChain, SnapshotEntry},
};

const SCHEMA_VERSION: u32 = 2;
const LEGACY_CHECKPOINT_VERSION: u32 = 1;
const BATCH_CHECKPOINT_VERSION: u32 = 2;
const PRE_RESET_CHECKPOINT_VERSION: u32 = 3;
const CHECKPOINT_VERSION: u32 = 4;
const PRODUCTION_USD_REGISTRY_FORMAT_VERSION: u32 = 1;
/// Immutable deployment namespace for the fresh signet/regtest Test USD v2 wallet.
pub const TEST_USD_V2_DEPLOYMENT_ID: &str = "opencsv-test-usd-v2";
const TEST_KEY_DERIVATION_ID: &str = "opencsv-account-v2";
const MAINNET_KEY_DERIVATION_ID: &str = "opencsv-mainnet-account-v1";
const DEFAULT_STOP_GAP: usize = 20;
const DEFAULT_PARALLEL_REQUESTS: usize = 4;
const DEFAULT_ESPLORA_REQUEST_TIMEOUT_SECS: u64 = 5;
const DEFAULT_ESPLORA_MAX_RETRIES: usize = 0;
const DEFAULT_VERIFICATION_TIMEOUT_SECS: u64 = 8;
const DEFAULT_MAX_VERIFICATION_BLOCKS: u64 = 10_000;
const MIN_FEE_RESERVE_SATS: u64 = 2_500;
const SEND_BATCH_WINDOW_MILLIS: i64 = 2_000;
const MAX_LOCAL_BATCH_RECIPIENTS: usize = opencsv_core::MAX_BATCH_V2_PARTICIPANTS;
const DEPENDENCY_REOBSERVATION_CHECK_ID: &str = "dependency_esplora_reobserve";

/// Stable account-wallet failure crossing the JSON/FFI boundary.
#[derive(Debug)]
pub struct AccountError {
    /// Stable machine-readable reason.
    pub code: &'static str,
    /// Human-readable detail, not intended for branching.
    pub message: String,
    /// Whether retrying the same durable operation may succeed without any
    /// proposal, input, or policy change. This is deliberately separate from
    /// `code`: `stale_chain_state` denotes a verified contradiction, while
    /// transient peer/scan availability uses a retryable error.
    pub retryable: bool,
}

impl AccountError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
        }
    }

    fn retryable(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: true,
        }
    }

    /// JSON object returned by the C ABI.
    pub fn json(&self) -> Value {
        json!({
            "error": self.message,
            "reason": self.code,
            "retryable": self.retryable,
        })
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

fn default_esplora_request_timeout_secs() -> u64 {
    DEFAULT_ESPLORA_REQUEST_TIMEOUT_SECS
}

fn default_esplora_max_retries() -> usize {
    DEFAULT_ESPLORA_MAX_RETRIES
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

fn default_required_raw_observer_quorum() -> u32 {
    0
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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsdIssuerPolicy {
    /// Full terms/genesis manifest whose asset id is admitted as USD.
    pub manifest: InstrumentManifestV1,
    /// Lower values are preferred when one issuer balance can cover a send.
    #[serde(default)]
    pub priority: u32,
}

/// Release-authorized production stage. Candidate releases are reviewable but
/// cannot create Bitcoin writes; limited/general releases may write only
/// within the exact committed rollout caps.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProductionActivationPhase {
    /// Reviewable policy bytes; all fresh consumer Bitcoin writes are blocked.
    Candidate,
    /// Explicit limited rollout under the committed caps.
    Limited,
    /// Explicit general rollout, still constrained by the committed caps.
    General,
}

/// Exact loss/volume envelope committed by a production registry release.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionRolloutPolicy {
    /// Release-authorized activation stage.
    pub phase: ProductionActivationPhase,
    /// Maximum base units in one recipient transfer.
    pub max_transfer_base_units: u64,
    /// Maximum combined base units in one frozen multi-recipient batch.
    pub max_batch_total_base_units: u64,
    /// Maximum active/completed outgoing base units created in any rolling day.
    pub max_rolling_24h_outgoing_base_units: u64,
    /// Maximum active/completed transfer operations created in any rolling day.
    pub max_rolling_24h_operations: u32,
    /// Maximum recipients committed into one batch, including one to disable
    /// explicit multi-recipient batching while retaining solo timeout.
    pub max_batch_recipients: u8,
    /// Maximum sats allocated to protected batch stocks and fee cells by one
    /// wallet-internal reserve-maintenance transaction.
    pub max_reserve_allocation_sats: u64,
    /// Absolute miner-fee ceiling for initial transactions and replacements.
    pub max_miner_fee_sats: u64,
}

/// Exact production USD registry carried by one reviewed application release.
///
/// The registry is not fetched at spend time. Its commitment binds the
/// deployment, monotonically named release version, ordered issuer policies,
/// source revision, and public approval receipts. Application distribution
/// signing authenticates the containing release; these public fields make the
/// exact policy independently reproducible and auditable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProductionUsdRegistryRelease {
    /// Registry encoding version. Version one is the only supported format.
    pub format_version: u32,
    /// Monotonic policy version chosen by the production release process.
    pub registry_version: u64,
    /// Exact non-test account deployment this registry may activate.
    pub deployment_id: String,
    /// Ordered, exact issuer-specific manifests and selection priorities.
    pub issuers: Vec<UsdIssuerPolicy>,
    /// Candidate/limited/general stage and exact loss/volume caps.
    pub rollout: ProductionRolloutPolicy,
    /// Immutable source revision that generated the containing client build.
    pub source_revision: String,
    /// Public review/approval receipts for this exact registry release.
    pub approval_receipts: Vec<String>,
    /// SHA-256 over the canonical version-one release payload.
    pub commitment_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProductionUsdRegistryFloor {
    registry_version: u64,
    commitment_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionUsdRegistryState {
    NotApplicable,
    Unconfigured,
    Current,
    Rollback,
    Conflict,
}

impl ProductionUsdRegistryState {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Unconfigured => "unconfigured",
            Self::Current => "current",
            Self::Rollback => "rollback",
            Self::Conflict => "conflict",
        }
    }

    fn write_block_reason(self) -> Option<&'static str> {
        match self {
            Self::Rollback => Some("production_registry_rollback"),
            Self::Conflict => Some("production_registry_conflict"),
            Self::NotApplicable | Self::Unconfigured | Self::Current => None,
        }
    }
}

/// Account configuration supplied by Signal. It contains no secret key.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConfig {
    /// Account/config generation. Version two is the clean Test USD v2 reset.
    #[serde(default = "schema_version")]
    pub version: u32,
    /// Application deployment namespace. Signet and regtest are deliberately
    /// fixed to the Test USD v2 namespace so v1 databases and backups cannot
    /// be interpreted as current state.
    #[serde(default = "default_deployment_id")]
    pub deployment_id: String,
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
    /// Per-request timeout for the non-authoritative Esplora accelerator.
    /// The wallet UI must remain usable when an accelerator stalls.
    #[serde(default = "default_esplora_request_timeout_secs")]
    pub esplora_request_timeout_secs: u64,
    /// Retry budget for one accelerator request. Protocol verification and
    /// required raw observers have separate fail-closed policies.
    #[serde(default = "default_esplora_max_retries")]
    pub esplora_max_retries: usize,
    /// Independently configurable network observations. An omitted list gets
    /// fail-closed signet/mainnet defaults for two built-in API observers.
    #[serde(default)]
    pub observation_checks: Vec<ObservationCheck>,
    /// Number of `require` raw-transaction observers that must return the
    /// exact transaction bytes under their configured certificate pins. When
    /// omitted, this is derived as every raw observer marked `require`; an
    /// explicit value must match that count so `require` never means
    /// "optional member of a smaller quorum".
    #[serde(default = "default_required_raw_observer_quorum")]
    pub required_raw_observer_quorum: u32,
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
    /// Versioned, deployment-bound production registry. Mainnet refuses loose
    /// top-level `usd_issuers`; its effective issuer set comes only from this
    /// exact release input. Signet and regtest refuse this field.
    #[serde(default)]
    pub production_usd_registry: Option<ProductionUsdRegistryRelease>,
    /// Absolute miner-fee ceiling in satoshis for fee-bump replacements,
    /// which take no per-call fee policy. When omitted, bumps are uncapped.
    #[serde(default)]
    pub max_fee_sats: Option<u64>,
    /// Unit tests that exercise unrelated account transitions can opt out of
    /// the live confirmed-chain dependency. This field does not exist in
    /// normal or feature builds and therefore cannot weaken a shipped wallet.
    #[cfg(test)]
    #[serde(default)]
    pub test_skip_protocol_spend_preflight: bool,
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
    #[serde(default)]
    deployment_id: Option<String>,
    #[serde(default)]
    key_derivation_id: Option<String>,
    #[serde(default)]
    production_usd_registry_floor: Option<ProductionUsdRegistryFloor>,
    network: String,
    root_fingerprint: String,
    device_binding_commitment: Option<String>,
    owners: Vec<String>,
    assets: Vec<BackupAsset>,
    #[serde(default)]
    instrument_manifests: Vec<InstrumentManifestV1>,
    operations: Vec<BackupOperation>,
    consignments: Vec<BackupConsignment>,
    #[serde(default)]
    send_batches: Vec<BackupSendBatch>,
    #[serde(default)]
    send_batch_members: Vec<BackupSendBatchMember>,
    #[serde(default)]
    batch_stocks: Vec<BackupBatchStock>,
    #[serde(default)]
    batch_reserve_operations: Vec<BackupBatchReserveOperation>,
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
    #[serde(default)]
    funding_txid: Option<String>,
    #[serde(default)]
    funding_vout: Option<u32>,
    #[serde(default)]
    funding_value_sats: Option<u64>,
    #[serde(default)]
    signed_tx_hex: Option<String>,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupSendBatch {
    batch_local_id: String,
    state: String,
    deadline_ms: i64,
    participant_count: Option<u8>,
    proposal_wire_base64: Option<String>,
    manifest_wire_base64: Option<String>,
    signed_tx_hex: Option<String>,
    txid: Option<String>,
    receipt_json: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupSendBatchMember {
    batch_local_id: String,
    operation_id: String,
    ordinal: u8,
    added_at_ms: i64,
    change_spk_hex: Option<String>,
    commit_nonce_hex: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupBatchStock {
    participant_count: u8,
    txid: String,
    vout: u32,
    value_sats: u64,
    birth_height: u64,
    state: String,
    reserved_by_batch: Option<String>,
    created_at: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupBatchReserveOperation {
    maintenance_id: String,
    state: String,
    participant_count: u8,
    stock_count: u8,
    fee_cell_count: u16,
    signed_tx_hex: String,
    txid: String,
    receipt_json: String,
    created_at: i64,
    updated_at: i64,
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
    // One independently attested peer session is shared by the proof and
    // pre-sign phases. The first call performs the complete cross-peer
    // filter-header attestation; later calls resync only the appended range
    // before rechecking the exact outpoint. Reconnecting here would replay the
    // full public chain for every phase of one payment.
    client: Mutex<Option<CbfClient>>,
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
        let mut client_guard = self.client.lock().map_err(|_| {
            AccountError::retryable(
                "chain_verification_unavailable",
                "authoritative fee-outpoint verifier lock was poisoned",
            )
        })?;
        if let Some(client) = client_guard.as_mut() {
            if let Err(error) = client.sync() {
                // A failed live session is never reused. This call still
                // fails closed; a later operation may establish a fresh,
                // independently attested session.
                *client_guard = None;
                return Err(AccountError::retryable(
                    "chain_verification_unavailable",
                    format!("authoritative fee-outpoint resync: {error}"),
                ));
            }
            if network != OpenCsvNetwork::Regtest && client.connected_peer_count() < 2 {
                *client_guard = None;
                return Err(AccountError::retryable(
                    "chain_verification_unavailable",
                    "authoritative fee-outpoint resync retained fewer than two independent peers",
                ));
            }
        } else {
            let config = CbfConfig {
                network,
                peers: self.peers.clone(),
                cache_dir: self.cache_dir.clone(),
                timeout: self.timeout,
            };
            let client = CbfClient::connect(&config).map_err(|error| {
                AccountError::retryable(
                    "chain_verification_unavailable",
                    format!("authoritative fee-outpoint sync: {error}"),
                )
            })?;
            if network != OpenCsvNetwork::Regtest && client.connected_peer_count() < 2 {
                return Err(AccountError::retryable(
                    "chain_verification_unavailable",
                    "authoritative fee-outpoint sync retained fewer than two independent peers",
                ));
            }
            *client_guard = Some(client);
        }
        let verdict = client_guard
            .as_mut()
            .expect("client established above")
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
                AccountError::retryable(
                    "chain_verification_unavailable",
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

#[derive(Clone, Debug)]
struct SendBatchRow {
    batch_local_id: String,
    state: String,
    deadline_ms: i64,
    participant_count: Option<u8>,
    proposal_wire: Option<Vec<u8>>,
    manifest_wire: Option<Vec<u8>>,
    signed_tx_hex: Option<String>,
    txid: Option<String>,
    receipt_json: Option<String>,
    checkpoint_hash: Option<String>,
    backup_acked: bool,
}

#[derive(Clone, Debug)]
struct SendBatchMember {
    operation_id: String,
    ordinal: u8,
    added_at_ms: i64,
    change_spk_hex: Option<String>,
    commit_nonce_hex: Option<String>,
}

#[derive(Clone, Debug)]
struct BatchStock {
    participant_count: u8,
    outpoint: OutPoint,
    value_sats: u64,
    birth_height: u64,
}

const fn schema_version() -> u32 {
    SCHEMA_VERSION
}

fn default_deployment_id() -> String {
    TEST_USD_V2_DEPLOYMENT_ID.to_owned()
}

fn account_key_derivation_id(network: &str) -> &'static str {
    if network == "mainnet" {
        MAINNET_KEY_DERIVATION_ID
    } else {
        TEST_KEY_DERIVATION_ID
    }
}

fn write_block_error(reason: &'static str) -> AccountError {
    match reason {
        "primary_required" => {
            AccountError::new("primary_required", "linked devices are watch-only")
        }
        "device_binding_mismatch" => AccountError::new(
            "device_binding_mismatch",
            "this restored device is read/export-only until explicit wallet recovery",
        ),
        "backup_required" => AccountError::new(
            "backup_required",
            "verified Signal Secure Backup is required for Bitcoin-writing operations",
        ),
        "production_usd_not_configured" => AccountError::new(
            "production_usd_not_configured",
            "mainnet Bitcoin-writing operations require at least one reviewed non-test USD issuer manifest",
        ),
        "production_registry_rollback" => AccountError::new(
            "production_registry_rollback",
            "this wallet has seen a newer production USD registry release and remains read-only",
        ),
        "production_registry_conflict" => AccountError::new(
            "production_registry_conflict",
            "the production USD registry reuses a version with different committed bytes",
        ),
        "production_activation_not_authorized" => AccountError::new(
            "production_activation_not_authorized",
            "this production registry is a candidate and does not authorize consumer Bitcoin writes",
        ),
        "production_observation_policy_required" => AccountError::new(
            "production_observation_policy_required",
            "mainnet Bitcoin-writing operations require two independent pinned raw-transaction observers, direct relay, and two confirmed-chain peers",
        ),
        "production_issuance_not_authorized" => AccountError::new(
            "production_issuance_not_authorized",
            "mainnet issuance remains disabled until an independently authenticated issuer authorization and supply policy are implemented",
        ),
        _ => AccountError::new("write_disabled", "wallet writes are disabled"),
    }
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
        db.repair_observation_receipt_schema()?;
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
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_send_batches (
                 batch_local_id TEXT PRIMARY KEY,
                 state TEXT NOT NULL CHECK(state IN (
                     'collecting', 'solo', 'frozen', 'proof_ready',
                     'signed_persisted', 'broadcast_unobserved', 'mempool',
                     'confirmed', 'cancelled'
                 )),
                 deadline_ms INTEGER NOT NULL,
                 participant_count INTEGER,
                 proposal_wire BLOB,
                 manifest_wire BLOB,
                 signed_tx_hex TEXT,
                 txid TEXT,
                 receipt_json TEXT,
                 checkpoint_hash TEXT,
                 backup_acked INTEGER NOT NULL DEFAULT 0,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_send_batch_members (
                 batch_local_id TEXT NOT NULL,
                 operation_id TEXT NOT NULL UNIQUE,
                 ordinal INTEGER NOT NULL,
                 added_at_ms INTEGER NOT NULL,
                 change_spk_hex TEXT,
                 commit_nonce_hex TEXT,
                 PRIMARY KEY(batch_local_id, ordinal),
                 FOREIGN KEY(batch_local_id) REFERENCES opencsv_send_batches(batch_local_id),
                 FOREIGN KEY(operation_id) REFERENCES opencsv_operations(operation_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_batch_stocks (
                 participant_count INTEGER NOT NULL,
                 txid TEXT NOT NULL,
                 vout INTEGER NOT NULL,
                 value_sats INTEGER NOT NULL,
                 birth_height INTEGER NOT NULL,
                 state TEXT NOT NULL CHECK(state IN (
                     'pending', 'available', 'reserved', 'signature_released',
                     'confirmed', 'invalidated'
                 )),
                 reserved_by_batch TEXT UNIQUE,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY(txid, vout),
                 FOREIGN KEY(reserved_by_batch) REFERENCES opencsv_send_batches(batch_local_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS opencsv_batch_reserve_operations (
                 maintenance_id TEXT PRIMARY KEY,
                 state TEXT NOT NULL CHECK(state IN (
                     'signed_persisted', 'broadcast_unobserved', 'mempool',
                     'confirmed', 'failed'
                 )),
                 participant_count INTEGER NOT NULL,
                 stock_count INTEGER NOT NULL,
                 fee_cell_count INTEGER NOT NULL,
                 signed_tx_hex TEXT NOT NULL,
                 txid TEXT NOT NULL UNIQUE,
                 receipt_json TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             ) STRICT;",
        )?;
        Ok(())
    }

    /// One development build persisted the complete SPV verdict object in
    /// `detail`, while the stable account-status schema has always exposed an
    /// optional string there. Repair those local receipts on open so an old
    /// cached observation cannot make the whole wallet status undecodable.
    fn repair_observation_receipt_schema(&mut self) -> Result<(), AccountError> {
        let mut statement = self.conn.prepare(
            "SELECT subject_txid, check_id, receipt_json
             FROM opencsv_observation_receipts",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut repairs = Vec::new();
        for row in rows {
            let (subject_txid, check_id, encoded) = row?;
            let mut receipt: Value = serde_json::from_str(&encoded).map_err(|error| {
                AccountError::new(
                    "database_corrupt",
                    format!("observation receipt {subject_txid}/{check_id}: {error}"),
                )
            })?;
            let Some(detail) = receipt.get("detail") else {
                continue;
            };
            if detail.is_null() || detail.is_string() {
                continue;
            }
            let normalized = detail
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    (detail.get("status").and_then(Value::as_str) == Some("verified")).then(|| {
                        "verified exact transaction through the phone-owned multi-peer scan"
                            .to_owned()
                    })
                })
                .unwrap_or_else(|| "legacy observer receipt detail normalized".to_owned());
            receipt["detail"] = json!(normalized);
            repairs.push((subject_txid, check_id, receipt.to_string()));
        }
        drop(statement);
        for (subject_txid, check_id, encoded) in repairs {
            self.conn.execute(
                "UPDATE opencsv_observation_receipts SET receipt_json = ?3
                 WHERE subject_txid = ?1 AND check_id = ?2",
                params![subject_txid, check_id, encoded],
            )?;
        }
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
    production_usd_registry_state: ProductionUsdRegistryState,
    funding_verifier: Arc<dyn FundingVerifier>,
    bitcoin: PersistedWallet<SqlitePersister>,
    db: SqlitePersister,
    protocol: Option<MemWallet>,
    bitcoin_fee_seed: Option<Zeroizing<[u8; 64]>>,
    batch_stock_secret: Option<Zeroizing<[u8; 32]>>,
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
    esplora_request_timeout_secs: u64,
    esplora_max_retries: usize,
    require_protocol_spend_preflight: bool,
}

pub(crate) struct CompletedProofJob {
    operation_id: String,
    request: TransferRequest,
    funding: ReservedFunding,
    verification: FundingVerificationReceipt,
    pending_json: String,
    record: [u8; 64],
    unconfirmed_dependencies: Vec<String>,
    dependency_observed_at: Option<i64>,
    reconciled_spent_coin_ids: Vec<String>,
    phase_timings_ms: Value,
}

/// Result of the short locked phase for a frozen multi-recipient batch.
pub(crate) enum BatchProofJobStart {
    /// One-member timeout: continue through the existing solo operation path.
    Solo(String),
    /// The exact batch proof/manifest is already durable.
    Ready(Value),
    /// Verify and prove outside the live account lock.
    Run(Box<AccountBatchProofJob>),
}

struct BatchProofMemberJob {
    operation_id: String,
    request: TransferRequest,
    funding: ReservedFunding,
    fee_secret: SecretKey,
    change_spk: ScriptBuf,
    commit_nonce: [u8; 32],
}

pub(crate) struct AccountBatchProofJob {
    batch_local_id: String,
    stock: BatchStock,
    stock_secret: SecretKey,
    proposal_nonce: [u8; 32],
    chain_id: [u8; 32],
    members: Vec<BatchProofMemberJob>,
    verifier: Arc<dyn FundingVerifier>,
    protocol_snapshot: MemWallet,
    esplora_url: String,
    esplora_request_timeout_secs: u64,
    esplora_max_retries: usize,
    require_protocol_spend_preflight: bool,
}

struct CompletedBatchProofMember {
    operation_id: String,
    request: TransferRequest,
    funding: ReservedFunding,
    funding_verification: FundingVerificationReceipt,
    pending_json: String,
    payload: TruncatedDigest,
    unconfirmed_dependencies: Vec<String>,
    dependency_observed_at: Option<i64>,
}

pub(crate) struct CompletedBatchProofJob {
    batch_local_id: String,
    stock: BatchStock,
    stock_verification: FundingVerificationReceipt,
    proposal: BatchProposal,
    manifest: BatchManifest,
    members: Vec<CompletedBatchProofMember>,
    reconciled_spent_coin_ids: Vec<String>,
    phase_timings_ms: Value,
}

impl AccountProofJob {
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn run(mut self) -> Result<CompletedProofJob, AccountError> {
        let total_started = Instant::now();
        let funding_verification_started = Instant::now();
        let verification = self.verifier.verify(&FundingVerificationRequest {
            outpoint: self.funding.outpoint,
            txout: self.funding.txout.clone(),
            birth_height: self.funding.birth_height,
        })?;
        let funding_verification_ms = elapsed_millis(funding_verification_started);
        let mut reconciled_spent_coin_ids = Vec::new();
        loop {
            let selected_nullifiers = self
                .protocol_snapshot
                .selected_transfer_nullifiers(&self.request.asset_id, self.request.amount)
                .map_err(|error| {
                    if reconciled_spent_coin_ids.is_empty() {
                        AccountError::new("unavailable_assets", error)
                    } else {
                        AccountError::new(
                            "stale_chain_state",
                            format!(
                                "confirmed OpenCSV spends were removed but no alternate input covers the payment: {error}"
                            ),
                        )
                    }
                })?;
            let confirmed_spends = confirmed_protocol_input_spends(
                &selected_nullifiers,
                verification.checked_through,
                self.require_protocol_spend_preflight,
            )?;
            if confirmed_spends.is_empty() {
                break;
            }
            let confirmed_nullifiers: Vec<Digest> = confirmed_spends
                .iter()
                .map(|(nullifier, _)| *nullifier)
                .collect();
            let removed = self
                .protocol_snapshot
                .mark_confirmed_spent_nullifiers(&confirmed_nullifiers)
                .map_err(|error| AccountError::new("database_error", error))?;
            if removed.is_empty() {
                return Err(AccountError::new(
                    "stale_chain_state",
                    "confirmed OpenCSV input could not be reconciled with the wallet snapshot",
                ));
            }
            reconciled_spent_coin_ids.extend(removed);
        }
        let ctx = funding_context(self.funding.outpoint);
        let local_proving_started = Instant::now();
        let proved = self
            .protocol_snapshot
            .prove_transfer_amount(
                &self.request.asset_id,
                &self.request.to_owner,
                self.request.amount,
            )
            .map_err(|error| AccountError::new("unavailable_assets", error))?;
        let local_proving_ms = elapsed_millis(local_proving_started);

        let dependency_observation_started = Instant::now();
        let mut dependency_observed_at = None;
        if !proved.unconfirmed_dependencies.is_empty() {
            let client = build_blocking_esplora_client(
                &self.esplora_url,
                self.esplora_request_timeout_secs,
                self.esplora_max_retries,
            );
            for dependency in &proved.unconfirmed_dependencies {
                let txid = unconfirmed_dependency_txid(dependency)?;
                match client.get_tx(&txid).map_err(|error| {
                    AccountError::retryable(
                        "unconfirmed_dependency_unavailable",
                        format!("could not re-observe parent {dependency}: {error}"),
                    )
                })? {
                    Some(transaction) if transaction.compute_txid() == txid => {
                        let observed_at = unix_time()?;
                        dependency_observed_at = Some(
                            dependency_observed_at
                                .map_or(observed_at, |earliest: i64| earliest.min(observed_at)),
                        );
                    }
                    Some(transaction) => {
                        return Err(AccountError::new(
                            "unconfirmed_dependency_changed",
                            format!(
                                "zero-confirmation parent {dependency} changed to {}",
                                hex_encode(&transaction.compute_txid().to_byte_array())
                            ),
                        ));
                    }
                    None => {
                        return Err(AccountError::new(
                            "unconfirmed_dependency_changed",
                            format!("zero-confirmation parent {dependency} disappeared"),
                        ));
                    }
                }
            }
        }
        let dependency_observation_ms = elapsed_millis(dependency_observation_started);
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
            dependency_observed_at,
            reconciled_spent_coin_ids,
            phase_timings_ms: json!({
                "funding_verification": funding_verification_ms,
                "local_proving": local_proving_ms,
                "dependency_observation": dependency_observation_ms,
                "proof_total": elapsed_millis(total_started),
            }),
        })
    }
}

impl AccountBatchProofJob {
    pub(crate) fn batch_local_id(&self) -> &str {
        &self.batch_local_id
    }

    pub(crate) fn run(mut self) -> Result<CompletedBatchProofJob, AccountError> {
        let total_started = Instant::now();
        let secp = Secp256k1::new();
        let stock_pubkey = PublicKey::from_secret_key(&secp, &self.stock_secret);
        let stock_script = stock_witness_script(stock_pubkey, self.members.len()).to_p2wsh();
        let funding_verification_started = Instant::now();
        let stock_verification = self.verifier.verify(&FundingVerificationRequest {
            outpoint: self.stock.outpoint,
            txout: bdk_wallet::bitcoin::TxOut {
                value: Amount::from_sat(self.stock.value_sats),
                script_pubkey: stock_script,
            },
            birth_height: self.stock.birth_height,
        })?;
        let mut funding_verifications = Vec::with_capacity(self.members.len());
        let mut checked_through = stock_verification.checked_through;
        for member in &self.members {
            let verification = self.verifier.verify(&FundingVerificationRequest {
                outpoint: member.funding.outpoint,
                txout: member.funding.txout.clone(),
                birth_height: member.funding.birth_height,
            })?;
            checked_through = checked_through.max(verification.checked_through);
            funding_verifications.push(verification);
        }
        let funding_verification_ms = elapsed_millis(funding_verification_started);
        let observed_tip_height = u32::try_from(checked_through).map_err(|_| {
            AccountError::new("stale_chain_state", "verified tip height exceeds u32")
        })?;
        let expiry_height = observed_tip_height.checked_add(12).ok_or_else(|| {
            AccountError::new("stale_chain_state", "batch expiry height overflow")
        })?;
        let participant_count = u8::try_from(self.members.len())
            .map_err(|_| AccountError::new("batch_full", "batch participant count exceeds u8"))?;
        let proposal = BatchProposal::new(
            self.chain_id,
            self.stock.outpoint,
            self.stock.value_sats,
            stock_pubkey,
            participant_count,
            self.proposal_nonce,
            observed_tip_height,
            expiry_height,
            2,
            100,
        )
        .map_err(batch_protocol_error)?;

        let client = build_blocking_esplora_client(
            &self.esplora_url,
            self.esplora_request_timeout_secs,
            self.esplora_max_retries,
        );
        let mut completed_members = Vec::with_capacity(self.members.len());
        let mut commitments = Vec::with_capacity(self.members.len());
        let mut local_proving_ms = 0_u64;
        let mut dependency_observation_ms = 0_u64;
        let mut reconciled_spent_coin_ids = Vec::new();
        for (member, funding_verification) in self.members.into_iter().zip(funding_verifications) {
            loop {
                let selected_nullifiers = self
                    .protocol_snapshot
                    .selected_transfer_nullifiers(&member.request.asset_id, member.request.amount)
                    .map_err(|error| {
                        if reconciled_spent_coin_ids.is_empty() {
                            AccountError::new("unavailable_assets", error)
                        } else {
                            AccountError::new(
                                "stale_chain_state",
                                format!(
                                    "confirmed OpenCSV spends were removed but no alternate batch input covers the payment: {error}"
                                ),
                            )
                        }
                    })?;
                let confirmed_spends = confirmed_protocol_input_spends(
                    &selected_nullifiers,
                    funding_verification.checked_through,
                    self.require_protocol_spend_preflight,
                )?;
                if confirmed_spends.is_empty() {
                    break;
                }
                let confirmed_nullifiers: Vec<Digest> = confirmed_spends
                    .iter()
                    .map(|(nullifier, _)| *nullifier)
                    .collect();
                let removed = self
                    .protocol_snapshot
                    .mark_confirmed_spent_nullifiers(&confirmed_nullifiers)
                    .map_err(|error| AccountError::new("database_error", error))?;
                if removed.is_empty() {
                    return Err(AccountError::new(
                        "stale_chain_state",
                        "confirmed batch input could not be reconciled with the wallet snapshot",
                    ));
                }
                reconciled_spent_coin_ids.extend(removed);
            }
            let local_proving_started = Instant::now();
            let proved = self
                .protocol_snapshot
                .prove_transfer_amount(
                    &member.request.asset_id,
                    &member.request.to_owner,
                    member.request.amount,
                )
                .map_err(|error| AccountError::new("unavailable_assets", error))?;
            local_proving_ms =
                local_proving_ms.saturating_add(elapsed_millis(local_proving_started));
            let mut dependency_observed_at = None;
            for dependency in &proved.unconfirmed_dependencies {
                let txid = unconfirmed_dependency_txid(dependency)?;
                let dependency_observation_started = Instant::now();
                let observed = client.get_tx(&txid).map_err(|error| {
                    AccountError::retryable(
                        "unconfirmed_dependency_unavailable",
                        format!("could not re-observe parent {dependency}: {error}"),
                    )
                })?;
                dependency_observation_ms = dependency_observation_ms
                    .saturating_add(elapsed_millis(dependency_observation_started));
                match observed {
                    Some(transaction) if transaction.compute_txid() == txid => {
                        let observed_at = unix_time()?;
                        dependency_observed_at = Some(
                            dependency_observed_at
                                .map_or(observed_at, |earliest: i64| earliest.min(observed_at)),
                        );
                    }
                    Some(transaction) => {
                        return Err(AccountError::new(
                            "unconfirmed_dependency_changed",
                            format!(
                                "zero-confirmation parent {dependency} changed to {}",
                                hex_encode(&transaction.compute_txid().to_byte_array())
                            ),
                        ));
                    }
                    None => {
                        return Err(AccountError::new(
                            "unconfirmed_dependency_changed",
                            format!("zero-confirmation parent {dependency} disappeared"),
                        ));
                    }
                }
            }
            let payload = self
                .protocol_snapshot
                .rebind_pending_batch_payload(proved.pending_id, proposal.context())
                .map_err(|error| AccountError::new("batch_payload_incompatible", error))?;
            let pending_json = self
                .protocol_snapshot
                .export_pending(proved.pending_id)
                .map_err(|error| AccountError::new("database_error", error))?;
            let operation_id = sha256::Hash::hash(
                [
                    b"OpenCSV batch operation v1".as_slice(),
                    member.operation_id.as_bytes(),
                ]
                .concat()
                .as_slice(),
            )
            .to_byte_array();
            let fee_pubkey = PublicKey::from_secret_key(&secp, &member.fee_secret);
            let max_charge = member
                .funding
                .value_sats()
                .checked_sub(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS)
                .ok_or_else(|| {
                    AccountError::new(
                        "insufficient_fees",
                        "batch fee cell cannot preserve minimum change",
                    )
                })?;
            commitments.push(
                ParticipantCommitment::new(
                    &proposal,
                    operation_id,
                    member.commit_nonce,
                    payload,
                    member.funding.outpoint,
                    member.funding.txout.clone(),
                    fee_pubkey,
                    member.change_spk,
                    max_charge,
                )
                .map_err(batch_protocol_error)?,
            );
            completed_members.push(CompletedBatchProofMember {
                operation_id: member.operation_id,
                request: member.request,
                funding: member.funding,
                funding_verification,
                pending_json,
                payload,
                unconfirmed_dependencies: proved.unconfirmed_dependencies,
                dependency_observed_at,
            });
        }
        let manifest =
            BatchManifest::build(&proposal, commitments).map_err(batch_protocol_error)?;
        Ok(CompletedBatchProofJob {
            batch_local_id: self.batch_local_id,
            stock: self.stock,
            stock_verification,
            proposal,
            manifest,
            members: completed_members,
            reconciled_spent_coin_ids,
            phase_timings_ms: json!({
                "funding_verification": funding_verification_ms,
                "local_proving": local_proving_ms,
                "dependency_observation": dependency_observation_ms,
                "proof_total": elapsed_millis(total_started),
            }),
        })
    }
}

impl AccountWallet {
    fn esplora_client(&self) -> esplora_client::BlockingClient {
        build_blocking_esplora_client(
            &self.config.esplora_url,
            self.config.esplora_request_timeout_secs,
            self.config.esplora_max_retries,
        )
    }

    /// Open or initialize an account database.
    pub fn open_device_bound(
        config_json: &str,
        account_key: &[u8],
        device_binding_key: &[u8],
        database_path: &str,
    ) -> Result<Self, AccountError> {
        let config_value: Value = serde_json::from_str(config_json).map_err(|error| {
            AccountError::new("invalid_config", format!("config JSON: {error}"))
        })?;
        let quorum_was_explicit = config_value.get("required_raw_observer_quorum").is_some();
        let mut config: AccountConfig = serde_json::from_value(config_value).map_err(|error| {
            AccountError::new("invalid_config", format!("config JSON: {error}"))
        })?;
        if config.version != SCHEMA_VERSION {
            if config.version < SCHEMA_VERSION
                && matches!(config.network.as_str(), "signet" | "regtest")
            {
                return Err(AccountError::new(
                    "testnet_reset_required",
                    format!(
                        "account config version {} belongs to the archived Test USD v1 deployment; create a fresh Test USD v2 wallet",
                        config.version
                    ),
                ));
            }
            return Err(AccountError::new(
                "unsupported_version",
                format!("account config version {}", config.version),
            ));
        }
        let network = parse_network(&config.network)?;
        validate_deployment(&config)?;
        validate_esplora_url(&config.esplora_url)?;
        validate_esplora_client_policy(&config)?;
        if config.observation_checks.is_empty() {
            config.observation_checks = default_observation_checks(&config.network);
        }
        if !quorum_was_explicit {
            config.required_raw_observer_quorum = u32::try_from(
                config
                    .observation_checks
                    .iter()
                    .filter(|check| {
                        check.kind == ObservationKind::RawTransactionApi
                            && check.mode == ObservationMode::Require
                    })
                    .count(),
            )
            .map_err(|_| {
                AccountError::new(
                    "invalid_config",
                    "required raw observer count does not fit in u32",
                )
            })?;
        }
        validate_observation_checks(&config)?;
        prepare_production_usd_registry(&mut config)?;
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
            bitcoin_fee_seed,
            batch_stock_secret,
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
                let mainnet_context = if network == Network::Bitcoin {
                    config.deployment_id.as_bytes()
                } else {
                    &[]
                };
                let (bitcoin_label, owner_label, issuer_label, batch_label):
                    (&[u8], &[u8], &[u8], &[u8]) = if network == Network::Bitcoin {
                        (
                            b"bitcoin-fee-wallet-mainnet-v1",
                            b"opencsv-owner-mainnet-v1",
                            b"opencsv-issuer-root-mainnet-v1",
                            b"opencsv-batch-stock-mainnet-v1",
                        )
                    } else {
                        (
                            b"bitcoin-fee-wallet-v2",
                            b"opencsv-owner-v2",
                            b"opencsv-issuer-root-v2",
                            b"opencsv-batch-stock-v2",
                        )
                    };
                let bitcoin_seed = Zeroizing::new(derive::<64>(
                    root.as_ref(),
                    bitcoin_label,
                    mainnet_context,
                )?);
                let owner_seed = Zeroizing::new(derive::<32>(
                    root.as_ref(),
                    owner_label,
                    mainnet_context,
                )?);
                let issuer_root = Zeroizing::new(derive::<32>(
                    root.as_ref(),
                    issuer_label,
                    mainnet_context,
                )?);
                let batch_stock_secret = Zeroizing::new(derive::<32>(
                    root.as_ref(),
                    batch_label,
                    mainnet_context,
                )?);
                SecretKey::from_slice(batch_stock_secret.as_ref()).map_err(|_| {
                    AccountError::new(
                        "key_derivation_failed",
                        "derived batch stock key is not a valid secp256k1 scalar",
                    )
                })?;
                let xpriv = Xpriv::new_master(network, bitcoin_seed.as_ref()).map_err(|error| {
                    AccountError::new("key_derivation_failed", error.to_string())
                })?;
                let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
                let external = format!("wpkh({xpriv}/84h/{coin_type}h/0h/0/*)");
                let internal = format!("wpkh({xpriv}/84h/{coin_type}h/0h/1/*)");
                let fingerprint = if network == Network::Bitcoin {
                    sha256::Hash::hash(
                        &[
                            b"OpenCSV mainnet account fingerprint v1".as_slice(),
                            root.as_ref(),
                            b"\0",
                            mainnet_context,
                        ]
                        .concat(),
                    )
                    .to_string()
                } else {
                    sha256::Hash::hash(
                        &[b"OpenCSV account fingerprint v2".as_slice(), root.as_ref()].concat(),
                    )
                    .to_string()
                };
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
                    let binding_material = if network == Network::Bitcoin {
                        [
                            b"OpenCSV mainnet device binding v1".as_slice(),
                            root.as_ref(),
                            device_binding.as_ref(),
                            b"\0",
                            mainnet_context,
                        ]
                        .concat()
                    } else {
                        [
                            b"OpenCSV device binding v2".as_slice(),
                            root.as_ref(),
                            device_binding.as_ref(),
                        ]
                        .concat()
                    };
                    Some(sha256::Hash::hash(&binding_material).to_string())
                };
                (
                    external,
                    internal,
                    Some(MemWallet::from_owner_seed(*owner_seed)),
                    Some(bitcoin_seed),
                    Some(batch_stock_secret),
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
                (
                    external,
                    internal,
                    None,
                    None,
                    None,
                    None,
                    fingerprint,
                    None,
                )
            }
        };

        let database_path = Path::new(database_path);
        let database_preexisted = database_path.exists();
        let mut db = SqlitePersister::open(database_path)?;
        let reset_error = |message: String| deployment_reset_error(&config.network, message);
        match db.meta("deployment_id")? {
            Some(existing) if existing != config.deployment_id => {
                return Err(reset_error(format!(
                        "database deployment {existing} cannot open as {}; create a fresh Test USD v2 wallet",
                        config.deployment_id
                    )));
            }
            None if database_preexisted => {
                return Err(reset_error(
                    "pre-v2 wallet state is archived; create a fresh deployment wallet".to_owned(),
                ));
            }
            None => db.set_meta("deployment_id", &config.deployment_id)?,
            Some(_) => {}
        }
        let expected_key_derivation_id = account_key_derivation_id(&config.network);
        match db.meta("key_derivation_id")? {
            Some(existing) if existing != expected_key_derivation_id => {
                return Err(reset_error(format!(
                    "database key derivation {existing} cannot open as {expected_key_derivation_id}; create a fresh deployment wallet"
                )));
            }
            None if database_preexisted && config.network == "mainnet" => {
                return Err(AccountError::new(
                    "deployment_mismatch",
                    "pre-v1 mainnet key derivation is archived; create a fresh production wallet",
                ));
            }
            None => db.set_meta("key_derivation_id", expected_key_derivation_id)?,
            Some(_) => {}
        }
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
        let production_usd_registry_state =
            reconcile_production_usd_registry_floor(&mut db, &mut config)?;
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
            cache_dir: PathBuf::from(format!("{}.cbf", database_path.display())),
            timeout: Duration::from_secs(config.verification_timeout_secs),
            max_blocks: config.max_verification_blocks,
            client: Mutex::new(None),
        });
        let mut account = Self {
            config,
            production_usd_registry_state,
            funding_verifier,
            bitcoin,
            db,
            protocol,
            bitcoin_fee_seed,
            batch_stock_secret,
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
                b"OpenCSV device binding v2".as_slice(),
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
        let batch_stock_inventory = query_json_rows(
            &self.db.conn,
            "SELECT json_object(
                 'participant_count', participant_count,
                 'state', state,
                 'count', COUNT(*),
                 'total_sats', SUM(value_sats)
             ) FROM opencsv_batch_stocks
             GROUP BY participant_count, state
             ORDER BY participant_count, state",
        )?;
        let batch_reserve_operations = query_json_rows(
            &self.db.conn,
            "SELECT json_object(
                 'maintenance_id', maintenance_id,
                 'state', state,
                 'participant_count', participant_count,
                 'stock_count', stock_count,
                 'fee_cell_count', fee_cell_count,
                 'txid', txid,
                 'fee_rate_sat_per_vb', json_extract(receipt_json, '$.fee_rate_sat_per_vb'),
                 'updated_at', updated_at
             ) FROM opencsv_batch_reserve_operations
             ORDER BY updated_at DESC LIMIT 10",
        )?;
        Ok(json!({
            "version": SCHEMA_VERSION,
            "deployment_id": self.config.deployment_id,
            "key_derivation_id": account_key_derivation_id(&self.config.network),
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
            "write_block_reason": self.write_block_reason()?,
            "production_usd_configured": self.production_usd_configured(),
            "production_usd_registry_state": self.production_usd_registry_state.as_str(),
            "production_usd_registry_floor": read_production_usd_registry_floor(&self.db)?,
            "production_usd_registry": self.config.production_usd_registry.as_ref().map(|registry| json!({
                "format_version": registry.format_version,
                "registry_version": registry.registry_version,
                "deployment_id": registry.deployment_id,
                "source_revision": registry.source_revision,
                "approval_receipts": registry.approval_receipts,
                "commitment_sha256": registry.commitment_sha256,
                "issuer_count": registry.issuers.len(),
                "rollout": registry.rollout,
            })),
            "production_activation_write_ready": self.production_activation_write_ready(),
            "production_observation_policy_ready": self.production_observation_policy_ready(),
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
            "required_raw_observer_quorum": self.config.required_raw_observer_quorum,
            "observation_receipts": query_json_rows(
                &self.db.conn,
                "SELECT receipt_json FROM opencsv_observation_receipts
                 ORDER BY observed_at DESC, check_id LIMIT 20",
            )?,
            "batch_reserves": {
                "inventory": batch_stock_inventory,
                "maintenance_operations": batch_reserve_operations,
            },
            "root_fingerprint": self.root_fingerprint,
        }))
    }

    /// Synchronize the BDK wallet through the configured Esplora accelerator.
    pub fn sync(&mut self) -> Result<Value, AccountError> {
        let client = build_blocking_esplora_client(
            &self.config.esplora_url,
            self.config.esplora_request_timeout_secs,
            self.config.esplora_max_retries,
        );
        let request = self.bitcoin.start_full_scan();
        let update = client
            .full_scan(request, self.config.stop_gap, self.config.parallel_requests)
            .map_err(|error| AccountError::retryable("sync_failed", error.to_string()))?;
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
        let consignment = Consignment::from_bytes(&canonical_blob)
            .map_err(|error| AccountError::new("invalid_consignment", error.to_string()))?;
        let payment_id = consignment_payment_identity(&consignment)?;
        let superseded_consignment_ids =
            matching_payment_consignments(&self.db.conn, &consignment_id, &payment_id)?;
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
                    params![consignment_id, snapshot_json],
                )?;
                db_tx.execute(
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
                db_tx.commit()?;
                Ok(json!({
                    "status": "verified",
                    "finality": "settled",
                    "spendable": true,
                    "consignment_id": consignment_id,
                    "payment_id": payment_id,
                    "superseded_consignment_ids": superseded_consignment_ids,
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
                "payment_id": payment_id,
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
        let mut asset_ids = consignment
            .coin_openings
            .iter()
            .map(|opening| hex_encode(opening.asset_id.as_bytes()))
            .collect::<Vec<_>>();
        asset_ids.sort_unstable();
        asset_ids.dedup();
        let unreviewed_asset_ids = asset_ids
            .iter()
            .filter(|asset_id| !self.is_reviewed_usd_asset(asset_id))
            .cloned()
            .collect::<Vec<_>>();
        let rejection_reason = (!unreviewed_asset_ids.is_empty()).then_some("asset_not_reviewed");
        Ok(json!({
            "consignment_id": consignment_id,
            "payment_id": consignment_payment_identity(&consignment)?,
            "anchor_txid": Txid::from_byte_array(consignment.anchor_ref.txid).to_string(),
            "anchor_height": consignment.anchor_ref.location.height,
            "anchor_position": consignment.anchor_ref.location.position,
            "asset_ids": asset_ids,
            "all_assets_reviewed": unreviewed_asset_ids.is_empty(),
            "unreviewed_asset_ids": unreviewed_asset_ids,
            "rejection_reason": rejection_reason,
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
        let payment_id = consignment_payment_identity(&consignment)?;
        let superseded_consignment_ids =
            matching_payment_consignments(&self.db.conn, &consignment_id, &payment_id)?;
        let anchor_txid = Txid::from_byte_array(consignment.anchor_ref.txid);
        let client = self.esplora_client();
        let transaction = client
            .get_tx(&anchor_txid)
            .map_err(|error| AccountError::new("mempool_observation_failed", error.to_string()))?;
        let Some(transaction) = transaction else {
            self.freeze_unconfirmed_dependency(
                &unconfirmed_dependency_key(anchor_txid),
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
            .verify_unconfirmed(
                &canonical_blob,
                &chain,
                &unconfirmed_dependency_key(anchor_txid),
            )
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
                    "payment_id": payment_id,
                    "superseded_consignment_ids": superseded_consignment_ids,
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
                "payment_id": payment_id,
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
        let payment_id = consignment_payment_identity(&consignment)?;
        let superseded_consignment_ids =
            matching_payment_consignments(&self.db.conn, &consignment_id, &payment_id)?;
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
            self.config.required_raw_observer_quorum,
            raw_transaction,
            observations_json,
        )?;
        self.persist_observation_receipts(&anchor_txid.to_string(), &receipts)?;
        if let Some(error) = policy_failure {
            self.freeze_unconfirmed_dependency(
                &unconfirmed_dependency_key(anchor_txid),
                &error.message,
            )?;
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
            .verify_unconfirmed(
                &canonical_blob,
                &chain,
                &unconfirmed_dependency_key(anchor_txid),
            )
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
                    "payment_id": payment_id,
                    "superseded_consignment_ids": superseded_consignment_ids,
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
                "payment_id": payment_id,
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
        let observer_evaluation_started = Instant::now();
        let (receipts, policy_failure) = evaluate_observation_evidence(
            &self.config.observation_checks,
            self.config.required_raw_observer_quorum,
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
        let observer_evaluation_ms = elapsed_millis(observer_evaluation_started);
        let mut durable_receipt: Value = self
            .operation(operation_id)?
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        durable_receipt["phase_timings_ms"]["observer_evaluation"] = json!(observer_evaluation_ms);
        self.db.conn.execute(
            "UPDATE opencsv_operations SET receipt_json = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![operation_id, durable_receipt.to_string(), unix_time()?],
        )?;
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
            if !receipt["detail"].is_null() && !receipt["detail"].is_string() {
                return Err(AccountError::new(
                    "invalid_observation_evidence",
                    "receipt detail must be a string or null",
                ));
            }
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

    /// Create a wallet-internal reserve split for one batching-v2 participant
    /// count. The transaction has only count-specific signed stock outputs,
    /// derived P2WPKH fee cells, and wallet change; there is no arbitrary BTC
    /// recipient surface. Exact signed bytes are durable before relay.
    pub fn prepare_batch_reserves(
        &mut self,
        participant_count: u8,
        fee_policy_json: &str,
    ) -> Result<Value, AccountError> {
        self.require_product_write_enabled()?;
        if !(2..=u8::try_from(MAX_LOCAL_BATCH_RECIPIENTS).unwrap_or(u8::MAX))
            .contains(&participant_count)
        {
            return Err(AccountError::new(
                "invalid_batch_count",
                "reserve maintenance supports 2..=64 participants",
            ));
        }
        if let Some(maintenance_id) = self
            .db
            .conn
            .query_row(
                "SELECT maintenance_id FROM opencsv_batch_reserve_operations
                 WHERE participant_count = ?1
                   AND state IN ('signed_persisted', 'broadcast_unobserved', 'mempool')
                 ORDER BY created_at DESC LIMIT 1",
                [participant_count],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return self.batch_reserve_operation_json(&maintenance_id);
        }
        let policy: FeePolicy = serde_json::from_str(fee_policy_json)
            .map_err(|error| AccountError::new("invalid_fee_policy", error.to_string()))?;
        if policy.target_sat_per_vb == 0 {
            return Err(AccountError::new(
                "invalid_fee_policy",
                "target_sat_per_vb must be positive",
            ));
        }
        let stock_count = 3usize;
        let fee_cell_count = usize::from(participant_count)
            .checked_mul(3)
            .ok_or_else(|| AccountError::new("arithmetic_overflow", "fee cell count overflow"))?;
        let reserve_allocation_sats = u64::try_from(stock_count)
            .ok()
            .and_then(|count| count.checked_mul(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS))
            .and_then(|stocks| {
                u64::try_from(fee_cell_count)
                    .ok()
                    .and_then(|count| count.checked_mul(MIN_FEE_RESERVE_SATS))
                    .and_then(|fee_cells| stocks.checked_add(fee_cells))
            })
            .ok_or_else(|| {
                AccountError::new("arithmetic_overflow", "reserve allocation overflow")
            })?;
        if let Some(rollout) = self.production_rollout_policy() {
            if participant_count > rollout.max_batch_recipients {
                return Err(AccountError::new(
                    "production_batch_limit_exceeded",
                    format!(
                        "{participant_count} recipients exceeds the production batch limit of {}",
                        rollout.max_batch_recipients
                    ),
                ));
            }
            if reserve_allocation_sats > rollout.max_reserve_allocation_sats {
                return Err(AccountError::new(
                    "production_reserve_limit_exceeded",
                    format!(
                        "{reserve_allocation_sats} sats exceeds the production reserve-allocation limit of {}",
                        rollout.max_reserve_allocation_sats
                    ),
                ));
            }
        }
        let stock_secret = self.batch_stock_secret()?;
        let stock_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &stock_secret);
        let stock_script =
            stock_witness_script(stock_pubkey, usize::from(participant_count)).to_p2wsh();
        let mut fee_cell_scripts = Vec::with_capacity(fee_cell_count);
        for _ in 0..fee_cell_count {
            fee_cell_scripts.push(
                self.bitcoin
                    .reveal_next_address(KeychainKind::Internal)
                    .address
                    .script_pubkey(),
            );
        }
        let change_script = self
            .bitcoin
            .reveal_next_address(KeychainKind::Internal)
            .address
            .script_pubkey();
        self.bitcoin.persist(&mut self.db)?;
        let unspendable = self
            .bitcoin
            .list_unspent()
            .filter(|output| {
                self.bitcoin.is_outpoint_locked(output.outpoint)
                    || ReservedFunding::from_local(output.clone()).is_err()
            })
            .map(|output| output.outpoint)
            .collect::<Vec<_>>();
        let fee_rate = FeeRate::from_sat_per_vb(policy.target_sat_per_vb).ok_or_else(|| {
            AccountError::new("invalid_fee_policy", "fee rate exceeds Bitcoin limits")
        })?;
        let mut builder = self.bitcoin.build_tx();
        builder.ordering(TxOrdering::Untouched);
        builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        builder.unspendable(unspendable);
        for _ in 0..stock_count {
            builder.add_recipient(
                stock_script.clone(),
                Amount::from_sat(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS),
            );
        }
        for script in &fee_cell_scripts {
            builder.add_recipient(script.clone(), Amount::from_sat(MIN_FEE_RESERVE_SATS));
        }
        builder.drain_to(change_script);
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
                "BDK did not finalize the reserve-maintenance transaction",
            ));
        }
        let fee = psbt.fee_amount().ok_or_else(|| {
            AccountError::new("signing_failed", "could not calculate maintenance fee")
        })?;
        if self
            .effective_fee_limit(policy.max_fee_sats)
            .is_some_and(|maximum| fee.to_sat() > maximum)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!("{} sats exceeds configured maximum", fee.to_sat()),
            ));
        }
        let transaction = psbt
            .extract_tx()
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        if transaction.output.len() < stock_count + fee_cell_count
            || transaction.output[..stock_count].iter().any(|output| {
                output.value.to_sat() != opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS
                    || output.script_pubkey != stock_script
            })
            || transaction.output[stock_count..stock_count + fee_cell_count]
                .iter()
                .zip(&fee_cell_scripts)
                .any(|(output, expected_script)| {
                    output.value.to_sat() != MIN_FEE_RESERVE_SATS
                        || &output.script_pubkey != expected_script
                })
        {
            return Err(AccountError::new(
                "protocol_layout_violation",
                "reserve-maintenance outputs changed before signing",
            ));
        }
        let maintenance_id = random_id(16);
        let txid = transaction.compute_txid();
        let signed_tx_hex = hex_encode(&serialize(&transaction));
        let stock_vouts: Vec<u32> = (0..stock_count)
            .map(|index| u32::try_from(index).expect("three stock outputs"))
            .collect();
        let mut receipt = json!({
            "maintenance_id": maintenance_id,
            "txid": txid.to_string(),
            "participant_count": participant_count,
            "stock_vouts": stock_vouts,
            "stock_value_sats": opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS,
            "fee_cell_vouts": (stock_count..stock_count + fee_cell_count).collect::<Vec<_>>(),
            "fee_cell_value_sats": MIN_FEE_RESERVE_SATS,
            "fee_sats": fee.to_sat(),
            "fee_rate_sat_per_vb": policy.target_sat_per_vb,
        });
        self.stamp_production_rollout_authorization(&mut receipt, &maintenance_id)?;
        let now = unix_time()?;
        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let persisted = (|| -> Result<(), AccountError> {
            self.db.conn.execute(
                "INSERT INTO opencsv_batch_reserve_operations(
                     maintenance_id, state, participant_count, stock_count,
                     fee_cell_count, signed_tx_hex, txid, receipt_json,
                     created_at, updated_at
                 ) VALUES(?1, 'signed_persisted', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                params![
                    maintenance_id,
                    participant_count,
                    i64::try_from(stock_count).unwrap_or(i64::MAX),
                    i64::try_from(fee_cell_count).unwrap_or(i64::MAX),
                    signed_tx_hex,
                    txid.to_string(),
                    receipt.to_string(),
                    now,
                ],
            )?;
            for vout in &stock_vouts {
                self.db.conn.execute(
                    "INSERT INTO opencsv_batch_stocks(
                         participant_count, txid, vout, value_sats,
                         birth_height, state, reserved_by_batch, created_at
                     ) VALUES(?1, ?2, ?3, ?4, 0, 'pending', NULL, ?5)",
                    params![
                        participant_count,
                        txid.to_string(),
                        vout,
                        i64::try_from(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS)
                            .expect("batch stock floor fits SQLite"),
                        now,
                    ],
                )?;
            }
            Ok(())
        })();
        match persisted {
            Ok(()) => self.db.conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        let seen_at = u64::try_from(now)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(transaction.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&transaction)?;
        let client = self.esplora_client();
        let fallback = relay_via_esplora_if_unobserved(&client, &transaction);
        receipt["p2p_submissions"] = json!(p2p_submissions);
        receipt["p2p_peers"] = json!(relay_peers);
        receipt["generic_relay_fallback"] = json!(matches!(&fallback, Ok(true)));
        if let Err(error) = &fallback {
            receipt["generic_relay_error"] = json!(error.to_string());
        }
        self.db.conn.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE maintenance_id = ?1",
            params![maintenance_id, receipt.to_string(), unix_time()?],
        )?;
        self.batch_reserve_operation_json(&maintenance_id)
    }

    /// Replace one wallet-internal reserve split at a higher fee rate. The
    /// original inputs, stock outputs, fee cells, output order, version, and
    /// locktime are immutable; only the final wallet-change value may fall.
    pub fn fee_bump_batch_reserves(
        &mut self,
        maintenance_id: &str,
        target_sat_per_vb: u64,
    ) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        if target_sat_per_vb == 0 {
            return Err(AccountError::new(
                "invalid_fee_policy",
                "target_sat_per_vb must be positive",
            ));
        }
        let current = self.batch_reserve_operation_json(maintenance_id)?;
        if !matches!(
            current["state"].as_str(),
            Some("broadcast_unobserved" | "mempool")
        ) {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!(
                    "cannot fee-bump reserve maintenance in {}",
                    current["state"].as_str().unwrap_or("unknown")
                ),
            ));
        }
        let original_bytes = hex_decode(
            current["signed_tx_hex"].as_str().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance has no transaction")
            })?,
            "reserve maintenance transaction",
        )?;
        let original: Transaction = deserialize(&original_bytes)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let original_txid = original.compute_txid();
        if current["txid"].as_str() != Some(original_txid.to_string().as_str()) {
            return Err(AccountError::new(
                "database_corrupt",
                "maintenance txid differs from its persisted bytes",
            ));
        }
        let stock_count = usize::try_from(current["stock_count"].as_u64().ok_or_else(|| {
            AccountError::new("database_corrupt", "maintenance has no stock count")
        })?)
        .map_err(|_| AccountError::new("database_corrupt", "stock count exceeds usize"))?;
        let fee_cell_count =
            usize::try_from(current["fee_cell_count"].as_u64().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance has no fee-cell count")
            })?)
            .map_err(|_| AccountError::new("database_corrupt", "fee-cell count exceeds usize"))?;
        let protected_count = stock_count
            .checked_add(fee_cell_count)
            .ok_or_else(|| AccountError::new("database_corrupt", "output count overflow"))?;
        if original.output.len() != protected_count.saturating_add(1) {
            return Err(AccountError::new(
                "protocol_layout_violation",
                "reserve maintenance must end with exactly one wallet-change output",
            ));
        }
        let change = original.output.last().ok_or_else(|| {
            AccountError::new(
                "protocol_layout_violation",
                "reserve maintenance has no change",
            )
        })?;
        if self
            .bitcoin
            .derivation_of_spk(change.script_pubkey.clone())
            .is_none()
        {
            return Err(AccountError::new(
                "protocol_layout_violation",
                "reserve-maintenance change is not controlled by this wallet",
            ));
        }
        let original_last_seen = self.bitcoin.get_tx(original_txid).and_then(|transaction| {
            match transaction.chain_position {
                ChainPosition::Unconfirmed { last_seen, .. } => last_seen,
                ChainPosition::Confirmed { .. } => None,
            }
        });
        let fee_rate = FeeRate::from_sat_per_vb(target_sat_per_vb).ok_or_else(|| {
            AccountError::new("invalid_fee_policy", "fee rate exceeds Bitcoin limits")
        })?;
        let mut builder = self
            .bitcoin
            .build_fee_bump(original_txid)
            .map_err(|error| AccountError::new("fee_bump_rejected", error.to_string()))?;
        builder.ordering(TxOrdering::Untouched);
        builder.nlocktime(original.lock_time);
        builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
        builder.drain_to(change.script_pubkey.clone());
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
                "reserve-maintenance fee-bump PSBT was not finalized",
            ));
        }
        let replacement_fee_sats = psbt
            .fee_amount()
            .ok_or_else(|| {
                AccountError::new("signing_failed", "could not calculate replacement fee")
            })?
            .to_sat();
        if self
            .signed_fee_limit(&current["receipt"], maintenance_id)?
            .is_some_and(|limit| replacement_fee_sats > limit)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!("{replacement_fee_sats} sats exceeds configured maximum"),
            ));
        }
        let replacement = psbt
            .extract_tx()
            .map_err(|error| AccountError::new("signing_failed", error.to_string()))?;
        if replacement.version != original.version
            || replacement.lock_time != original.lock_time
            || replacement.input.len() != original.input.len()
            || replacement
                .input
                .iter()
                .zip(&original.input)
                .any(|(new, old)| {
                    new.previous_output != old.previous_output
                        || new.sequence != old.sequence
                        || new.script_sig != old.script_sig
                })
            || replacement.output.len() != original.output.len()
            || replacement.output[..protected_count] != original.output[..protected_count]
            || replacement.output[protected_count].script_pubkey != change.script_pubkey
            || replacement.output[protected_count].value >= change.value
            || replacement.output[protected_count].value
                < replacement.output[protected_count]
                    .script_pubkey
                    .minimal_non_dust()
        {
            return Err(AccountError::new(
                "protocol_layout_violation",
                "reserve replacement changed protected inputs, outputs, or ordering",
            ));
        }
        let mut receipt = current["receipt"].clone();
        let original_fee_sats = receipt
            .as_object()
            .ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance receipt is not an object")
            })?
            .get("fee_sats")
            .and_then(Value::as_u64)
            .ok_or_else(|| AccountError::new("database_corrupt", "maintenance fee is absent"))?;
        let fee_increment_sats = replacement_fee_sats
            .checked_sub(original_fee_sats)
            .ok_or_else(|| {
                AccountError::new("fee_bump_rejected", "replacement fee did not rise")
            })?;
        if fee_increment_sats == 0 {
            return Err(AccountError::new(
                "fee_bump_rejected",
                "replacement fee did not rise",
            ));
        }
        let replacement_txid = replacement.compute_txid();
        let replacement_hex = hex_encode(&serialize(&replacement));
        {
            let receipt_object = receipt.as_object_mut().expect("receipt checked above");
            let candidates = receipt_object
                .entry("replacement_candidates")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "reserve replacement candidates are not an array",
                    )
                })?;
            if !candidates.iter().any(|candidate| {
                candidate.get("txid").and_then(Value::as_str)
                    == Some(original_txid.to_string().as_str())
            }) {
                candidates.push(json!({
                    "txid": original_txid.to_string(),
                    "signed_tx_hex": current["signed_tx_hex"],
                    "fee_sats": original_fee_sats,
                }));
            }
            receipt_object.insert("replaces".into(), json!(original_txid.to_string()));
            receipt_object.insert("txid".into(), json!(replacement_txid.to_string()));
            receipt_object.insert("target_sat_per_vb".into(), json!(target_sat_per_vb));
            receipt_object.insert("fee_rate_sat_per_vb".into(), json!(target_sat_per_vb));
            receipt_object.insert("fee_sats".into(), json!(replacement_fee_sats));
            receipt_object.insert("fee_increment_sats".into(), json!(fee_increment_sats));
            receipt_object.insert(
                "replacement_change_sats".into(),
                json!(replacement.output[protected_count].value.to_sat()),
            );
        }
        let now = unix_time()?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'signed_persisted', signed_tx_hex = ?2, txid = ?3,
                 receipt_json = ?4, updated_at = ?5
             WHERE maintenance_id = ?1",
            params![
                maintenance_id,
                replacement_hex,
                replacement_txid.to_string(),
                receipt.to_string(),
                now,
            ],
        )?;
        transaction.execute(
            "UPDATE opencsv_batch_stocks SET txid = ?2
             WHERE txid = ?1 AND state = 'pending'",
            params![original_txid.to_string(), replacement_txid.to_string()],
        )?;
        transaction.commit()?;
        let now = u64::try_from(now)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        let seen_at = original_last_seen
            .and_then(|last_seen| last_seen.checked_add(1))
            .map_or(now, |next| next.max(now));
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(replacement.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&replacement)?;
        let client = self.esplora_client();
        let generic_relay_fallback = relay_via_esplora_if_unobserved(&client, &replacement);
        if let Some(receipt_object) = receipt.as_object_mut() {
            receipt_object.insert("p2p_submissions".into(), json!(p2p_submissions));
            receipt_object.insert("p2p_peers".into(), json!(relay_peers));
            receipt_object.insert(
                "generic_relay_fallback".into(),
                json!(matches!(&generic_relay_fallback, Ok(true))),
            );
            if let Err(error) = &generic_relay_fallback {
                receipt_object.insert("generic_relay_error".into(), json!(error.to_string()));
            }
        }
        self.db.conn.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE maintenance_id = ?1",
            params![maintenance_id, receipt.to_string(), unix_time()?],
        )?;
        self.batch_reserve_operation_json(maintenance_id)
    }

    /// If any superseded reserve-split candidate appears confirmed before the
    /// latest replacement, independently verify every exact stock outpoint
    /// before restoring that transaction. Esplora supplies only the height
    /// hint; it can never select a winning replacement by itself.
    fn reconcile_confirmed_batch_reserve_replacement(
        &mut self,
        maintenance_id: &str,
    ) -> Result<Option<(Value, u32)>, AccountError> {
        let current = self.batch_reserve_operation_json(maintenance_id)?;
        let candidates = current["receipt"]
            .get("replacement_candidates")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if candidates.is_empty() {
            return Ok(None);
        }
        let client = self.esplora_client();
        for candidate in candidates {
            let txid_text = candidate
                .get("txid")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "reserve replacement candidate has no txid",
                    )
                })?;
            let txid = txid_text
                .parse::<Txid>()
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            let status = client
                .get_tx_status(&txid)
                .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
            if !status.confirmed {
                continue;
            }
            let block_height = status.block_height.ok_or_else(|| {
                AccountError::new(
                    "sync_failed",
                    "confirmed reserve candidate has no block height",
                )
            })?;
            let signed_tx_hex = candidate
                .get("signed_tx_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "reserve replacement candidate has no signed bytes",
                    )
                })?;
            let bytes = hex_decode(signed_tx_hex, "confirmed reserve candidate")?;
            let transaction: Transaction = deserialize(&bytes)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            if transaction.compute_txid() != txid {
                return Err(AccountError::new(
                    "database_corrupt",
                    "confirmed reserve candidate txid differs from its persisted bytes",
                ));
            }
            let fee_sats = candidate
                .get("fee_sats")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "reserve replacement candidate has no fee",
                    )
                })?;
            let current_txid = current["txid"].as_str().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance has no current txid")
            })?;
            let participant_count =
                u8::try_from(current["participant_count"].as_u64().ok_or_else(|| {
                    AccountError::new("database_corrupt", "maintenance has no participant count")
                })?)
                .map_err(|_| {
                    AccountError::new("database_corrupt", "participant count exceeds u8")
                })?;
            let stock_pubkey =
                PublicKey::from_secret_key(&Secp256k1::new(), &self.batch_stock_secret()?);
            let stock_script =
                stock_witness_script(stock_pubkey, usize::from(participant_count)).to_p2wsh();
            let stocks = {
                let mut statement = self.db.conn.prepare(
                    "SELECT vout, value_sats FROM opencsv_batch_stocks
                     WHERE txid = ?1 AND state = 'pending' ORDER BY vout",
                )?;
                let rows = statement.query_map([current_txid], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            if stocks.is_empty() {
                return Err(AccountError::new(
                    "database_corrupt",
                    "reserve replacement has no pending stocks",
                ));
            }
            let mut candidate_verified = true;
            for (vout, value_sats) in &stocks {
                let vout = u32::try_from(*vout)
                    .map_err(|_| AccountError::new("database_corrupt", "stock vout exceeds u32"))?;
                let expected = bdk_wallet::bitcoin::TxOut {
                    value: Amount::from_sat(u64::try_from(*value_sats).map_err(|_| {
                        AccountError::new("database_corrupt", "stock value is negative")
                    })?),
                    script_pubkey: stock_script.clone(),
                };
                if transaction.output.get(vout as usize) != Some(&expected) {
                    return Err(AccountError::new(
                        "database_corrupt",
                        "reserve replacement stock differs from its persisted transaction",
                    ));
                }
                match self.funding_verifier.verify(&FundingVerificationRequest {
                    outpoint: OutPoint::new(txid, vout),
                    txout: expected,
                    birth_height: u64::from(block_height),
                }) {
                    Ok(_) => {}
                    Err(error)
                        if !error.retryable
                            && matches!(error.code, "stale_chain_state" | "conflicting_operation") =>
                    {
                        candidate_verified = false;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            if !candidate_verified {
                continue;
            }
            let mut receipt = current["receipt"].clone();
            let receipt_object = receipt.as_object_mut().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance receipt is not an object")
            })?;
            receipt_object.insert("txid".into(), json!(txid.to_string()));
            receipt_object.insert("fee_sats".into(), json!(fee_sats));
            receipt_object.insert(
                "fee_bump_outcome".into(),
                json!("superseded_reserve_candidate_confirmed"),
            );
            receipt_object.insert("failed_replacement_txid".into(), json!(current_txid));
            receipt_object.insert("explorer_confirmed".into(), json!(true));
            receipt_object.insert("confirmed_stock_verified".into(), json!(true));
            receipt_object.insert("requires_confirmed_stock_verification".into(), json!(false));
            receipt_object.remove("replaces");
            receipt_object.remove("replacement_candidates");

            let now = unix_time()?;
            let db_transaction = self
                .db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            db_transaction.execute(
                "UPDATE opencsv_batch_reserve_operations
                 SET state = 'broadcast_unobserved', signed_tx_hex = ?2,
                     txid = ?3, receipt_json = ?4, updated_at = ?5
                 WHERE maintenance_id = ?1",
                params![
                    maintenance_id,
                    signed_tx_hex,
                    txid.to_string(),
                    receipt.to_string(),
                    now,
                ],
            )?;
            db_transaction.execute(
                "UPDATE opencsv_batch_stocks SET txid = ?2
                 WHERE txid = ?1 AND state = 'pending'",
                params![current_txid, txid.to_string()],
            )?;
            db_transaction.commit()?;
            return Ok(Some((
                self.batch_reserve_operation_json(maintenance_id)?,
                block_height,
            )));
        }
        Ok(None)
    }

    /// Apply pinned raw-byte observation to an exact reserve-maintenance
    /// transaction. A socket submission alone never reaches `mempool`.
    pub fn observe_batch_reserve_unconfirmed(
        &mut self,
        maintenance_id: &str,
        raw_transaction: &[u8],
        observations_json: &str,
    ) -> Result<Value, AccountError> {
        let (state, signed_tx_hex, expected_txid): (String, String, String) = self
            .db
            .conn
            .query_row(
                "SELECT state, signed_tx_hex, txid
                 FROM opencsv_batch_reserve_operations WHERE maintenance_id = ?1",
                [maintenance_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?
            .ok_or_else(|| {
                AccountError::new(
                    "unknown_reserve_maintenance",
                    format!("unknown maintenance operation {maintenance_id}"),
                )
            })?;
        if !matches!(
            state.as_str(),
            "signed_persisted" | "broadcast_unobserved" | "mempool"
        ) {
            return Err(AccountError::new(
                "invalid_operation_state",
                format!("reserve maintenance is {state}"),
            ));
        }
        if hex_decode(&signed_tx_hex, "reserve maintenance transaction")? != raw_transaction {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "observer bytes differ from the persisted reserve transaction",
            ));
        }
        let transaction: Transaction = deserialize(raw_transaction).map_err(|error| {
            AccountError::new("invalid_observation_transaction", error.to_string())
        })?;
        if transaction.compute_txid().to_string() != expected_txid {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "reserve transaction id differs from persisted bytes",
            ));
        }
        let (receipts, policy_failure) = evaluate_observation_evidence(
            &self.config.observation_checks,
            self.config.required_raw_observer_quorum,
            raw_transaction,
            observations_json,
        )?;
        self.persist_observation_receipts(&expected_txid, &receipts)?;
        if let Some(error) = policy_failure {
            return Err(error);
        }
        self.enforce_unconfirmed_non_host_policy(&expected_txid, true)?;
        if !receipts.iter().any(|receipt| {
            receipt["kind"] == json!(ObservationKind::RawTransactionApi)
                && receipt["result"] == json!(ObservationResult::Observed)
                && receipt["raw_byte_match"] == true
        }) {
            return Err(AccountError::new(
                "mempool_observation_failed",
                "no pinned observer returned the exact reserve transaction",
            ));
        }
        self.db.conn.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'mempool', updated_at = ?2 WHERE maintenance_id = ?1",
            params![maintenance_id, unix_time()?],
        )?;
        let mut value = self.batch_reserve_operation_json(maintenance_id)?;
        value["observations"] = json!(receipts);
        Ok(value)
    }

    /// Reapply and rebroadcast an exact persisted reserve-maintenance
    /// transaction after a crash. No new outputs or coin selection occur.
    pub fn resume_batch_reserves(&mut self, maintenance_id: &str) -> Result<Value, AccountError> {
        let current = self.batch_reserve_operation_json(maintenance_id)?;
        if !matches!(
            current["state"].as_str(),
            Some("signed_persisted" | "broadcast_unobserved")
        ) {
            return Ok(current);
        }
        self.signed_fee_limit(&current["receipt"], maintenance_id)?;
        let reconciliation_error = match self
            .reconcile_confirmed_batch_reserve_replacement(maintenance_id)
        {
            Ok(Some((restored, _))) => return Ok(restored),
            Ok(None) => None,
            Err(error)
                if error.retryable
                    || matches!(
                        error.code,
                        "sync_failed" | "stale_chain_state" | "conflicting_operation"
                    ) =>
            {
                Some(error)
            }
            Err(error) => return Err(error),
        };
        let raw = hex_decode(
            current["signed_tx_hex"].as_str().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance has no transaction")
            })?,
            "reserve maintenance transaction",
        )?;
        let transaction: Transaction = deserialize(&raw)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let txid = transaction.compute_txid().to_string();
        if current["txid"].as_str() != Some(txid.as_str()) {
            return Err(AccountError::new(
                "database_corrupt",
                "maintenance txid differs from its persisted bytes",
            ));
        }
        let seen_at = u64::try_from(unix_time()?)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(transaction.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&transaction)?;
        let client = self.esplora_client();
        let fallback = relay_via_esplora_if_unobserved(&client, &transaction);
        let mut receipt = current["receipt"].clone();
        if let Some(error) = reconciliation_error {
            receipt["resume_candidate_reconciliation"] = json!({
                "result": "unavailable",
                "reason": error.code,
                "detail": error.message,
                "retryable": error.retryable,
            });
        }
        receipt["resume_p2p_submissions"] = json!(p2p_submissions);
        receipt["resume_p2p_peers"] = json!(relay_peers);
        receipt["resume_generic_relay_fallback"] = json!(matches!(&fallback, Ok(true)));
        if let Err(error) = fallback {
            receipt["resume_generic_relay_error"] = json!(error.to_string());
        }
        self.db.conn.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE maintenance_id = ?1",
            params![maintenance_id, receipt.to_string(), unix_time()?],
        )?;
        self.batch_reserve_operation_json(maintenance_id)
    }

    /// Promote pending stock only after the accelerator discovers a block and
    /// the CBF verifier independently proves each exact outpoint unspent.
    pub fn refresh_batch_reserves(&mut self, maintenance_id: &str) -> Result<Value, AccountError> {
        let reconciled = self.reconcile_confirmed_batch_reserve_replacement(maintenance_id)?;
        let (value, reconciled_height) = match reconciled {
            Some((value, height)) => (value, Some(height)),
            None => (self.batch_reserve_operation_json(maintenance_id)?, None),
        };
        if value["state"] == "confirmed" {
            return Ok(value);
        }
        let txid = value["txid"]
            .as_str()
            .ok_or_else(|| AccountError::new("database_corrupt", "maintenance has no txid"))?
            .parse::<Txid>()
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let block_height = match reconciled_height {
            Some(height) => height,
            None => {
                let client = self.esplora_client();
                let status = client
                    .get_tx_status(&txid)
                    .map_err(|error| AccountError::new("sync_failed", error.to_string()))?;
                let Some(block_height) = status.block_height else {
                    return Ok(value);
                };
                block_height
            }
        };
        let participant_count =
            u8::try_from(value["participant_count"].as_u64().ok_or_else(|| {
                AccountError::new("database_corrupt", "maintenance has no participant count")
            })?)
            .map_err(|_| AccountError::new("database_corrupt", "participant count exceeds u8"))?;
        let stock_pubkey =
            PublicKey::from_secret_key(&Secp256k1::new(), &self.batch_stock_secret()?);
        let stock_script =
            stock_witness_script(stock_pubkey, usize::from(participant_count)).to_p2wsh();
        let stocks = {
            let mut statement = self.db.conn.prepare(
                "SELECT vout, value_sats FROM opencsv_batch_stocks
                 WHERE txid = ?1 AND state = 'pending' ORDER BY vout",
            )?;
            let rows = statement.query_map([txid.to_string()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        if stocks.is_empty() {
            return Err(AccountError::new(
                "database_corrupt",
                "maintenance transaction has no pending stocks",
            ));
        }
        for (vout, value_sats) in &stocks {
            self.funding_verifier.verify(&FundingVerificationRequest {
                outpoint: OutPoint::new(
                    txid,
                    u32::try_from(*vout).map_err(|_| {
                        AccountError::new("database_corrupt", "stock vout exceeds u32")
                    })?,
                ),
                txout: bdk_wallet::bitcoin::TxOut {
                    value: Amount::from_sat(u64::try_from(*value_sats).map_err(|_| {
                        AccountError::new("database_corrupt", "stock value is negative")
                    })?),
                    script_pubkey: stock_script.clone(),
                },
                birth_height: u64::from(block_height),
            })?;
        }
        self.sync()?;
        let now = unix_time()?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE opencsv_batch_stocks
             SET state = 'available', birth_height = ?2
             WHERE txid = ?1 AND state = 'pending'",
            params![txid.to_string(), block_height],
        )?;
        transaction.execute(
            "UPDATE opencsv_batch_reserve_operations
             SET state = 'confirmed', updated_at = ?2 WHERE maintenance_id = ?1",
            params![maintenance_id, now],
        )?;
        transaction.commit()?;
        self.batch_reserve_operation_json(maintenance_id)
    }

    fn batch_reserve_operation_json(&self, maintenance_id: &str) -> Result<Value, AccountError> {
        let row: (String, i64, i64, i64, String, String, String) = self
            .db
            .conn
            .query_row(
                "SELECT state, participant_count, stock_count, fee_cell_count,
                        signed_tx_hex, txid, receipt_json
                 FROM opencsv_batch_reserve_operations WHERE maintenance_id = ?1",
                [maintenance_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| {
                AccountError::new(
                    "unknown_reserve_maintenance",
                    format!("unknown maintenance operation {maintenance_id}"),
                )
            })?;
        let receipt: Value = serde_json::from_str(&row.6)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        Ok(json!({
            "maintenance_id": maintenance_id,
            "state": row.0,
            "participant_count": row.1,
            "stock_count": row.2,
            "fee_cell_count": row.3,
            "signed_tx_hex": row.4,
            "txid": row.5,
            "fee_rate_sat_per_vb": receipt["fee_rate_sat_per_vb"],
            "receipt": receipt,
        }))
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

    fn scan_verify_outgoing_operation(
        &self,
        operation: &OperationRow,
        consignment_hex: &str,
    ) -> Result<Value, AccountError> {
        if operation.kind != "mint" {
            return self.scan_verify(consignment_hex);
        }
        if self.mint_recipient_is_self_owned(operation)? {
            return self.scan_verify(consignment_hex);
        }
        let owner = self.mint_recipient_owner(operation)?;
        scan::verify_json_for_public_owners(
            consignment_hex,
            &[owner],
            &self.known_asset_ids()?,
            &opencsv_pcd::CoinProofVerifier,
        )
        .map_err(|error| AccountError::new("scan_failed", error))
    }

    fn mint_recipient_owner(&self, operation: &OperationRow) -> Result<Digest, AccountError> {
        let request: Value = serde_json::from_str(&operation.request_json)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let to_owner = request["to_owner"].as_str().ok_or_else(|| {
            AccountError::new("database_corrupt", "mint operation has no recipient owner")
        })?;
        Ok(Digest::from_bytes(decode_hex_32(
            to_owner,
            "mint recipient owner",
        )?))
    }

    fn mint_recipient_is_self_owned(&self, operation: &OperationRow) -> Result<bool, AccountError> {
        let owner = self.mint_recipient_owner(operation)?;
        Ok(self
            .owner_secrets()?
            .iter()
            .any(|secret| secret.owner() == owner))
    }

    /// Read-only N-of-M chain-view decision using this account's identities.
    pub fn cross_check(&self, request_json: &str) -> Result<Value, AccountError> {
        match crosscheck::run_cross_check(
            request_json,
            &self.owner_secrets()?,
            &self.known_asset_ids()?,
            &opencsv_pcd::CoinProofVerifier,
        ) {
            Ok(value) => Ok(value),
            Err(crosscheck::CrossCheckFailure::TipDisagreement(tips)) => Ok(json!({
                "error": format!("anchor backends disagree on tip height: {tips:?}"),
                "kind": "tip_disagreement",
                "tips": tips,
            })),
            Err(crosscheck::CrossCheckFailure::Other(message)) => {
                Err(AccountError::new("cross_check_failed", message))
            }
        }
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
        let total_started = Instant::now();
        self.require_issuance_write_enabled()?;
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
        let funding_verification_started = Instant::now();
        let verification = match self.verify_funding(&funding) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.reject_prebroadcast_operation(&operation_id, error.code)?;
                return Err(error);
            }
        };
        let funding_verification_ms = elapsed_millis(funding_verification_started);
        let ctx = funding_context(funding.outpoint);

        let local_proving_started = Instant::now();
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
        let local_proving_ms = elapsed_millis(local_proving_started);
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
        let phase_timings_ms = json!({
            "funding_verification": funding_verification_ms,
            "local_proving": local_proving_ms,
            "dependency_observation": 0,
            "proof_total": elapsed_millis(total_started),
        });
        match self.prepared_receipt(
            &operation_id,
            funding,
            &verification,
            &record,
            &phase_timings_ms,
        ) {
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
        self.require_product_write_enabled()?;
        let (request, normalized_request) = normalize_transfer_request(request_json)?;
        self.require_reviewed_usd_asset(&request.asset_id)?;
        self.require_production_new_transfer_policy(&request)?;
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

    /// Durably plan the first transfer in a two-second collection window, or
    /// coalesce it into the currently open local window. No proof or Bitcoin
    /// reservation begins until the window is frozen, so a recipient added
    /// before the deadline is guaranteed membership rather than being a UI
    /// hint racing a background prover.
    pub fn transfer_batch_plan(&mut self, request_json: &str) -> Result<Value, AccountError> {
        self.plan_batched_transfer(request_json, None)
    }

    /// Add one exact recipient intent to a named, still-open collection
    /// window. This is the explicit Add Recipient boundary: the call either
    /// commits membership durably or fails without creating an operation.
    pub fn transfer_batch_add_recipient(
        &mut self,
        batch_local_id: &str,
        request_json: &str,
    ) -> Result<Value, AccountError> {
        self.plan_batched_transfer(request_json, Some(batch_local_id))
    }

    fn plan_batched_transfer(
        &mut self,
        request_json: &str,
        requested_batch: Option<&str>,
    ) -> Result<Value, AccountError> {
        self.require_product_write_enabled()?;
        let (request, normalized_request) = normalize_transfer_request(request_json)?;
        self.require_reviewed_usd_asset(&request.asset_id)?;
        self.require_production_new_transfer_policy(&request)?;
        let now_ms = unix_time_millis()?;
        let operation_created_at = unix_time()?;
        let existing = match requested_batch {
            Some(batch_local_id) => Some(self.send_batch(batch_local_id)?),
            None => self
                .db
                .meta("active_send_batch")?
                .and_then(|batch_local_id| self.send_batch(&batch_local_id).ok())
                .filter(|batch| {
                    batch.state == "collecting"
                        && batch.deadline_ms >= now_ms
                        && self
                            .send_batch_members(&batch.batch_local_id)
                            .is_ok_and(|members| members.len() < MAX_LOCAL_BATCH_RECIPIENTS)
                }),
        };

        if let Some(batch) = existing {
            if batch.state != "collecting" {
                return Err(AccountError::new(
                    "batch_window_closed",
                    format!("batch is {}", batch.state),
                ));
            }
            if now_ms > batch.deadline_ms {
                return Err(AccountError::new(
                    "batch_window_closed",
                    "the two-second Add Recipient guarantee has expired",
                ));
            }
            let members = self.send_batch_members(&batch.batch_local_id)?;
            if members.len() >= MAX_LOCAL_BATCH_RECIPIENTS {
                return Err(AccountError::new(
                    "batch_full",
                    "the local batch reached the reviewed C1 participant limit",
                ));
            }
            let mut requests = self.transfer_requests_for_batch_members(&members)?;
            requests.push(request.clone());
            self.require_production_batch_policy(&requests)?;
            let operation_id = random_id(16);
            let delivery_nonce = random_id(16);
            let ordinal = u8::try_from(members.len()).map_err(|_| {
                AccountError::new("batch_full", "batch participant ordinal exceeds u8")
            })?;
            let transaction = self
                .db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            insert_planned_operation_in_transaction(
                &transaction,
                &operation_id,
                &normalized_request,
                &delivery_nonce,
                operation_created_at,
            )?;
            transaction.execute(
                "INSERT INTO opencsv_send_batch_members(
                     batch_local_id, operation_id, ordinal, added_at_ms
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![batch.batch_local_id, operation_id, ordinal, now_ms],
            )?;
            transaction.commit()?;
            return self.send_batch_member_json(&batch.batch_local_id, &operation_id);
        }

        if requested_batch.is_some() {
            return Err(AccountError::new(
                "unknown_batch",
                "the requested Add Recipient batch does not exist",
            ));
        }
        self.require_production_batch_policy(std::slice::from_ref(&request))?;
        let batch_local_id = random_id(16);
        let operation_id = random_id(16);
        let delivery_nonce = random_id(16);
        let deadline_ms = now_ms
            .checked_add(SEND_BATCH_WINDOW_MILLIS)
            .ok_or_else(|| {
                AccountError::new("clock_error", "batch collection deadline overflow")
            })?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO opencsv_send_batches(
                 batch_local_id, state, deadline_ms, created_at, updated_at
             ) VALUES(?1, 'collecting', ?2, ?3, ?3)",
            params![batch_local_id, deadline_ms, now_ms],
        )?;
        insert_planned_operation_in_transaction(
            &transaction,
            &operation_id,
            &normalized_request,
            &delivery_nonce,
            operation_created_at,
        )?;
        transaction.execute(
            "INSERT INTO opencsv_send_batch_members(
                 batch_local_id, operation_id, ordinal, added_at_ms
             ) VALUES(?1, ?2, 0, ?3)",
            params![batch_local_id, operation_id, now_ms],
        )?;
        transaction.execute(
            "INSERT INTO opencsv_account_meta(key, value)
             VALUES('active_send_batch', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [&batch_local_id],
        )?;
        transaction.commit()?;
        self.send_batch_member_json(&batch_local_id, &operation_id)
    }

    /// Freeze membership. A one-member timeout deliberately returns to the
    /// established solo path; two or more members become an immutable C1
    /// proposal candidate. Re-entry returns the same frozen membership.
    pub fn freeze_send_batch(&mut self, batch_local_id: &str) -> Result<Value, AccountError> {
        self.require_product_write_enabled()?;
        let batch = self.send_batch(batch_local_id)?;
        let members = self.send_batch_members(batch_local_id)?;
        if members.is_empty() {
            return Err(AccountError::new(
                "database_corrupt",
                "send batch contains no operations",
            ));
        }
        let requests = self.transfer_requests_for_batch_members(&members)?;
        for request in &requests {
            self.require_reviewed_transfer(request)?;
        }
        self.require_production_batch_policy(&requests)?;
        if batch.state == "collecting" {
            let next_state = if members.len() == 1 { "solo" } else { "frozen" };
            let count = u8::try_from(members.len()).map_err(|_| {
                AccountError::new("batch_full", "batch participant count exceeds u8")
            })?;
            let now_ms = unix_time_millis()?;
            let transaction = self
                .db
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "UPDATE opencsv_send_batches
                 SET state = ?2, participant_count = ?3, updated_at = ?4
                 WHERE batch_local_id = ?1 AND state = 'collecting'",
                params![batch_local_id, next_state, count, now_ms],
            )?;
            transaction.execute(
                "DELETE FROM opencsv_account_meta
                 WHERE key = 'active_send_batch' AND value = ?1",
                [batch_local_id],
            )?;
            transaction.commit()?;
        } else if !matches!(
            batch.state.as_str(),
            "solo"
                | "frozen"
                | "proof_ready"
                | "signed_persisted"
                | "broadcast_unobserved"
                | "mempool"
                | "confirmed"
        ) {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("batch is {}", batch.state),
            ));
        }
        self.send_batch_json(batch_local_id)
    }

    /// Read one collection/frozen batch and its durably ordered members.
    pub fn send_batch_status(&self, batch_local_id: &str) -> Result<Value, AccountError> {
        self.send_batch_json(batch_local_id)
    }

    /// Cancel every member of a batch before any signature is released.
    ///
    /// This is the rollback boundary used by Signal when an explicitly
    /// assembled Add Recipient set cannot be completed. It is deliberately
    /// batch-scoped: cancelling only one member would mutate the ordered C1
    /// membership while leaving the remaining intents looking sendable.
    pub fn cancel_send_batch(&mut self, batch_local_id: &str) -> Result<Value, AccountError> {
        let batch = self.send_batch(batch_local_id)?;
        if batch.state == "cancelled" {
            return self.send_batch_json(batch_local_id);
        }
        if matches!(
            batch.state.as_str(),
            "signed_persisted" | "broadcast_unobserved" | "mempool" | "confirmed"
        ) {
            return Err(AccountError::new(
                "cancellation_forbidden",
                "a send batch cannot be cancelled after a signature was released",
            ));
        }

        // A proof job executes outside the wallet lock. Clearing this lease
        // makes its eventual commit fail as stale; the immutable job may
        // finish computation but can no longer install or sign anything.
        if self.db.meta("active_batch_proof")?.as_deref() == Some(batch_local_id) {
            self.db.delete_meta("active_batch_proof")?;
        }
        let members = self.send_batch_members(batch_local_id)?;
        for member in members {
            self.cancel_operation(&member.operation_id)?;
        }
        self.db.conn.execute(
            "UPDATE opencsv_batch_stocks
             SET state = 'available', reserved_by_batch = NULL
             WHERE reserved_by_batch = ?1 AND state = 'reserved'",
            [batch_local_id],
        )?;
        self.db.conn.execute(
            "DELETE FROM opencsv_account_meta
             WHERE key = 'active_send_batch' AND value = ?1",
            [batch_local_id],
        )?;
        self.db.conn.execute(
            "UPDATE opencsv_send_batches
             SET state = 'cancelled', updated_at = ?2
             WHERE batch_local_id = ?1",
            params![batch_local_id, unix_time()?],
        )?;
        self.send_batch_json(batch_local_id)
    }

    /// Snapshot a frozen C1 batch under the wallet lock. All authoritative
    /// chain checks and recursive proofs run from the returned immutable job,
    /// outside the global account registry and live-wallet mutex.
    pub(crate) fn begin_send_batch_proof(
        &mut self,
        batch_local_id: &str,
    ) -> Result<BatchProofJobStart, AccountError> {
        self.require_product_write_enabled()?;
        let batch = self.send_batch(batch_local_id)?;
        let members = self.send_batch_members(batch_local_id)?;
        if batch.state == "solo" {
            let operation_id = members
                .first()
                .ok_or_else(|| AccountError::new("database_corrupt", "solo batch is empty"))?
                .operation_id
                .clone();
            return Ok(BatchProofJobStart::Solo(operation_id));
        }
        if batch.state == "proof_ready" {
            return Ok(BatchProofJobStart::Ready(
                self.send_batch_json(batch_local_id)?,
            ));
        }
        if batch.state != "frozen" {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("batch is {}", batch.state),
            ));
        }
        let participant_count = u8::try_from(members.len())
            .map_err(|_| AccountError::new("batch_full", "batch participant count exceeds u8"))?;
        if participant_count < 2 {
            return Err(AccountError::new(
                "database_corrupt",
                "frozen batching-v2 path has fewer than two participants",
            ));
        }
        if batch.participant_count != Some(participant_count) {
            return Err(AccountError::new(
                "database_corrupt",
                "frozen batch participant count changed",
            ));
        }
        if let Some(active) = self.db.meta("active_batch_proof")? {
            if active != batch_local_id {
                return Err(AccountError::new(
                    "proof_job_busy",
                    format!("another batch proof job is active for {active}"),
                ));
            }
        }

        // Review every exact instrument before reserving Bitcoin or protocol
        // inputs. A registry change on reopen invalidates the complete
        // unsigned batch; it can never leave a subset looking sendable.
        let requests = self.transfer_requests_for_batch_members(&members)?;
        if let Err(error) = self.require_production_batch_policy(&requests) {
            self.cancel_send_batch(batch_local_id)?;
            return Err(error);
        }
        for member in &members {
            let operation = self.operation(&member.operation_id)?;
            let request: TransferRequest =
                serde_json::from_str(&operation.request_json).map_err(|error| {
                    AccountError::new("database_corrupt", format!("transfer request: {error}"))
                })?;
            if let Err(error) = self.require_reviewed_transfer(&request) {
                self.cancel_send_batch(batch_local_id)?;
                return Err(error);
            }
        }

        let stock = self.reserve_batch_stock(batch_local_id, participant_count)?;
        let mut jobs = Vec::with_capacity(members.len());
        for member in members {
            let operation = self.operation(&member.operation_id)?;
            let funding = match operation.state.as_str() {
                "planned" => self.reserve_fee_utxo(&member.operation_id)?,
                "fee_reserved" => self.reserved_funding_for_operation(&operation)?,
                state => {
                    return Err(AccountError::new(
                        "invalid_operation_state",
                        format!("batch member {} is {state}", member.operation_id),
                    ));
                }
            };
            let request: TransferRequest =
                serde_json::from_str(&operation.request_json).map_err(|error| {
                    AccountError::new("database_corrupt", format!("transfer request: {error}"))
                })?;
            let (change_spk, change_spk_hex) = match member.change_spk_hex {
                Some(encoded) => {
                    let script =
                        ScriptBuf::from_bytes(hex_decode(&encoded, "batch change script")?);
                    (script, encoded)
                }
                None => {
                    let address = self
                        .bitcoin
                        .reveal_next_address(KeychainKind::Internal)
                        .address;
                    let script = address.script_pubkey();
                    let encoded = hex_encode(script.as_bytes());
                    self.bitcoin.persist(&mut self.db)?;
                    (script, encoded)
                }
            };
            let (commit_nonce, commit_nonce_hex) = match member.commit_nonce_hex {
                Some(encoded) => (decode_hex_32(&encoded, "batch commit nonce")?, encoded),
                None => {
                    let encoded = random_id(32);
                    (decode_hex_32(&encoded, "batch commit nonce")?, encoded)
                }
            };
            self.db.conn.execute(
                "UPDATE opencsv_send_batch_members
                 SET change_spk_hex = ?3, commit_nonce_hex = ?4
                 WHERE batch_local_id = ?1 AND operation_id = ?2",
                params![
                    batch_local_id,
                    member.operation_id,
                    change_spk_hex,
                    commit_nonce_hex,
                ],
            )?;
            let fee_secret = self.batch_fee_secret(&funding)?;
            let fee_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &fee_secret);
            if opencsv_bitcoin::batch_v2::p2wpkh_script(fee_pubkey) != funding.txout.script_pubkey {
                return Err(AccountError::new(
                    "database_corrupt",
                    "derived batch fee key does not control its reserved output",
                ));
            }
            jobs.push(BatchProofMemberJob {
                operation_id: member.operation_id,
                request,
                funding,
                fee_secret,
                change_spk,
                commit_nonce,
            });
        }
        let network = parse_network(&self.config.network)?;
        let proposal_nonce = sha256::Hash::hash(
            [
                b"OpenCSV local batch proposal v1".as_slice(),
                batch_local_id.as_bytes(),
            ]
            .concat()
            .as_slice(),
        )
        .to_byte_array();
        self.db.set_meta("active_batch_proof", batch_local_id)?;
        Ok(BatchProofJobStart::Run(Box::new(AccountBatchProofJob {
            batch_local_id: batch_local_id.to_owned(),
            stock,
            stock_secret: self.batch_stock_secret()?,
            proposal_nonce,
            chain_id: genesis_block(network).block_hash().to_byte_array(),
            members: jobs,
            verifier: self.funding_verifier.clone(),
            protocol_snapshot: self.protocol.as_ref().cloned().ok_or_else(|| {
                AccountError::new("primary_required", "linked devices cannot prove batches")
            })?,
            esplora_url: self.config.esplora_url.clone(),
            esplora_request_timeout_secs: self.config.esplora_request_timeout_secs,
            esplora_max_retries: self.config.esplora_max_retries,
            require_protocol_spend_preflight: protocol_spend_preflight_required(&self.config),
        })))
    }

    /// Atomically install every proved member only if the frozen membership,
    /// stock, fee reservations, proposal, and OpenCSV coin inputs remain
    /// current. Every member receives the same backup checkpoint hash.
    pub(crate) fn finish_send_batch_proof(
        &mut self,
        completed: CompletedBatchProofJob,
    ) -> Result<Value, AccountError> {
        let batch = self.send_batch(&completed.batch_local_id)?;
        if batch.state == "proof_ready" {
            self.db.delete_meta("active_batch_proof")?;
            return self.send_batch_json(&completed.batch_local_id);
        }
        if batch.state != "frozen"
            || self.db.meta("active_batch_proof")?.as_deref()
                != Some(completed.batch_local_id.as_str())
        {
            return Err(AccountError::new(
                "stale_proof_job",
                "batch no longer owns the frozen proof reservation",
            ));
        }
        let current_stock = self
            .batch_stock_reserved_by(&completed.batch_local_id)?
            .ok_or_else(|| {
                AccountError::new("stale_proof_job", "batch stock reservation disappeared")
            })?;
        if current_stock.outpoint != completed.stock.outpoint
            || current_stock.participant_count != completed.stock.participant_count
        {
            return Err(AccountError::new(
                "stale_proof_job",
                "batch stock reservation changed while proving",
            ));
        }
        let members = self.send_batch_members(&completed.batch_local_id)?;
        if members.len() != completed.members.len()
            || members
                .iter()
                .map(|member| member.operation_id.as_str())
                .ne(completed
                    .members
                    .iter()
                    .map(|member| member.operation_id.as_str()))
        {
            return Err(AccountError::new(
                "stale_proof_job",
                "batch membership changed while proving",
            ));
        }

        let mut protocol_candidate = self.protocol.as_ref().cloned().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices cannot prove batches")
        })?;
        let completed_requests = completed
            .members
            .iter()
            .map(|member| member.request.clone())
            .collect::<Vec<_>>();
        if let Err(error) = self.require_production_batch_policy(&completed_requests) {
            self.cancel_send_batch(&completed.batch_local_id)?;
            return Err(error);
        }
        protocol_candidate
            .mark_spent(&completed.reconciled_spent_coin_ids)
            .map_err(|error| AccountError::new("database_error", error))?;
        let mut pending_ids = Vec::with_capacity(completed.members.len());
        for member in &completed.members {
            if let Err(error) = self.require_reviewed_transfer(&member.request) {
                self.cancel_send_batch(&completed.batch_local_id)?;
                return Err(error);
            }
            let operation = self.operation(&member.operation_id)?;
            if operation.state != "fee_reserved"
                || operation_outpoint(&operation)? != member.funding.outpoint
            {
                return Err(AccountError::new(
                    "stale_proof_job",
                    format!("fee reservation changed for {}", member.operation_id),
                ));
            }
            let pending_id = protocol_candidate
                .import_pending(&member.pending_json)
                .map_err(|error| AccountError::new("database_error", error))?;
            if protocol_candidate
                .pending_spend_conflicts(pending_id)
                .map_err(|error| AccountError::new("database_error", error))?
                || !protocol_candidate
                    .pending_spends_available(pending_id)
                    .map_err(|error| AccountError::new("database_error", error))?
            {
                return Err(AccountError::new(
                    "conflicting_operation",
                    "a batch member's OpenCSV inputs changed while proving",
                ));
            }
            if protocol_candidate
                .rebind_pending_batch_payload(pending_id, completed.proposal.context())
                .map_err(|error| AccountError::new("batch_payload_incompatible", error))?
                != member.payload
            {
                return Err(AccountError::new(
                    "stale_proof_job",
                    "proposal-bound batch payload changed while proving",
                ));
            }
            if protocol_candidate
                .pending_unconfirmed_dependencies(pending_id)
                .map_err(|error| AccountError::new("database_error", error))?
                != member.unconfirmed_dependencies
            {
                return Err(AccountError::new(
                    "stale_proof_job",
                    "a batch member's zero-confirmation dependency set changed",
                ));
            }
            pending_ids.push((member.operation_id.clone(), pending_id));
        }

        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let installed = (|| -> Result<Value, AccountError> {
            let now = unix_time()?;
            for member in &completed.members {
                self.persist_dependency_reobservations_at(
                    &member.unconfirmed_dependencies,
                    member.dependency_observed_at,
                )?;
                let envelope_position = completed
                    .manifest
                    .commitments()
                    .iter()
                    .position(|commitment| commitment.fee_outpoint() == member.funding.outpoint)
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "manifest omitted a proved batch member",
                        )
                    })?;
                let receipt = json!({
                    "batch_local_id": completed.batch_local_id,
                    "batch_id": hex_encode(&completed.proposal.batch_id()),
                    "manifest_id": hex_encode(&completed.manifest.manifest_id()),
                    "envelope_position": envelope_position,
                    "payload_hex": hex_encode(member.payload.as_bytes()),
                    "funding_outpoint": member.funding.outpoint.to_string(),
                    "funding_value_sats": member.funding.value_sats(),
                    "funding_verification": member.funding_verification,
                    "backup_ack_required": true,
                    "phase_timings_ms": completed.phase_timings_ms.clone(),
                });
                self.db.conn.execute(
                    "UPDATE opencsv_operations
                     SET state = 'proof_ready', request_json = ?2,
                         pending_json = ?3, receipt_json = ?4,
                         checkpoint_hash = NULL, backup_acked = 0,
                         updated_at = ?5 WHERE operation_id = ?1",
                    params![
                        member.operation_id,
                        serde_json::to_string(&member.request).map_err(|error| {
                            AccountError::new("database_error", error.to_string())
                        })?,
                        member.pending_json,
                        receipt.to_string(),
                        now,
                    ],
                )?;
            }
            let batch_receipt = json!({
                "batch_id": hex_encode(&completed.proposal.batch_id()),
                "manifest_id": hex_encode(&completed.manifest.manifest_id()),
                "stock_outpoint": completed.stock.outpoint.to_string(),
                "stock_value_sats": completed.stock.value_sats,
                "stock_verification": completed.stock_verification,
                "participant_count": completed.members.len(),
                "miner_fee_sats": completed.manifest.miner_fee(),
                "charges_sats": completed.manifest.charges(),
                "backup_ack_required": true,
                "phase_timings_ms": completed.phase_timings_ms.clone(),
            });
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET state = 'proof_ready', proposal_wire = ?2,
                     manifest_wire = ?3, receipt_json = ?4,
                     checkpoint_hash = NULL, backup_acked = 0,
                     updated_at = ?5 WHERE batch_local_id = ?1",
                params![
                    completed.batch_local_id,
                    completed.proposal.wire_bytes(),
                    completed.manifest.wire_bytes(),
                    batch_receipt.to_string(),
                    now,
                ],
            )?;
            self.db.delete_meta("active_batch_proof")?;
            let checkpoint = self.checkpoint()?;
            let checkpoint_hash = checkpoint["checkpoint_hash"].as_str().ok_or_else(|| {
                AccountError::new("checkpoint_failed", "batch checkpoint has no hash")
            })?;
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET checkpoint_hash = ?2 WHERE batch_local_id = ?1",
                params![completed.batch_local_id, checkpoint_hash],
            )?;
            for member in &completed.members {
                self.db.conn.execute(
                    "UPDATE opencsv_operations
                     SET checkpoint_hash = ?2 WHERE operation_id = ?1",
                    params![member.operation_id, checkpoint_hash],
                )?;
            }
            let mut response = self.send_batch_json(&completed.batch_local_id)?;
            response["checkpoint_hash"] = json!(checkpoint_hash);
            Ok(response)
        })();
        match installed {
            Ok(response) => {
                self.db.conn.execute_batch("COMMIT")?;
                self.protocol = Some(protocol_candidate);
                for (operation_id, pending_id) in pending_ids {
                    self.pending_by_operation.insert(operation_id, pending_id);
                }
                Ok(response)
            }
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub(crate) fn fail_send_batch_proof<T>(
        &mut self,
        batch_local_id: &str,
        error: AccountError,
    ) -> Result<T, AccountError> {
        self.db.delete_meta("active_batch_proof")?;
        if !error.retryable {
            if let Some(member) = self.send_batch_members(batch_local_id)?.first() {
                self.reject_prebroadcast_operation(&member.operation_id, error.code)?;
            } else {
                self.cancel_send_batch(batch_local_id)?;
            }
        }
        self.db.conn.execute(
            "UPDATE opencsv_send_batches SET receipt_json = ?2, updated_at = ?3
             WHERE batch_local_id = ?1",
            params![
                batch_local_id,
                json!({"proof_error": error.json()}).to_string(),
                unix_time()?,
            ],
        )?;
        Err(error)
    }

    /// Acknowledge the exact checkpoint that Signal staged for the complete
    /// frozen batch.
    ///
    /// The wallet can legitimately advance while Signal is exporting because
    /// an unrelated receive or finality refresh also belongs in Secure Backup.
    /// The caller supplies the hash of the payload that the completed export
    /// actually contained. Under an immediate transaction we require the
    /// batch to remain proof-ready and accept only either that batch's exact
    /// prepared checkpoint or the complete current checkpoint. An arbitrary
    /// older checkpoint can never unlock signing. Only acknowledgement
    /// metadata is rebound; the frozen proposal, manifest, and proofs are
    /// never regenerated or changed.
    pub fn acknowledge_send_batch_backup(
        &mut self,
        batch_local_id: &str,
        checkpoint_hash: &str,
    ) -> Result<Value, AccountError> {
        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let acknowledged = (|| -> Result<Value, AccountError> {
            let batch = self.send_batch(batch_local_id)?;
            if batch.state != "proof_ready" {
                return Err(AccountError::new(
                    "invalid_batch_state",
                    format!("batch is {}", batch.state),
                ));
            }
            let current = self.checkpoint()?;
            let prepared_matches = batch.checkpoint_hash.as_deref() == Some(checkpoint_hash);
            let current_matches = current["checkpoint_hash"].as_str() == Some(checkpoint_hash);
            if !prepared_matches && !current_matches {
                return Err(AccountError::new(
                    "backup_checkpoint_mismatch",
                    "Secure Backup did not acknowledge this proof-ready batch's staged or current wallet checkpoint",
                ));
            }
            let now = unix_time()?;
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET checkpoint_hash = ?2, backup_acked = 1, updated_at = ?3
                 WHERE batch_local_id = ?1",
                params![batch_local_id, checkpoint_hash, now],
            )?;
            self.db.conn.execute(
                "UPDATE opencsv_operations
                 SET checkpoint_hash = ?2, backup_acked = 1,
                     receipt_json = json_set(COALESCE(receipt_json, '{}'),
                                             '$.checkpoint_hash', ?2),
                     updated_at = ?3
                 WHERE operation_id IN (
                     SELECT operation_id FROM opencsv_send_batch_members
                     WHERE batch_local_id = ?1
                 )",
                params![batch_local_id, checkpoint_hash, now],
            )?;
            self.send_batch_json(batch_local_id)
        })();
        match acknowledged {
            Ok(response) => {
                self.db.conn.execute_batch("COMMIT")?;
                Ok(response)
            }
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Reconstruct, reverify, sign, persist, and relay one local multi-
    /// recipient C1 batch. The stock owner and every participant key remain
    /// Rust-owned; all signatures are `SIGHASH_ALL` over the exact manifest.
    pub fn sign_and_broadcast_send_batch(
        &mut self,
        batch_local_id: &str,
    ) -> Result<Value, AccountError> {
        self.require_product_write_enabled()?;
        let batch = self.send_batch(batch_local_id)?;
        if batch.state != "proof_ready" {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("batch is {}", batch.state),
            ));
        }
        if !batch.backup_acked {
            return Err(AccountError::new(
                "backup_required",
                "the complete prepared batch checkpoint is not acknowledged",
            ));
        }
        let proposal_wire = batch.proposal_wire.as_deref().ok_or_else(|| {
            AccountError::new("database_corrupt", "proof-ready batch has no proposal")
        })?;
        let manifest_wire = batch.manifest_wire.as_deref().ok_or_else(|| {
            AccountError::new("database_corrupt", "proof-ready batch has no manifest")
        })?;
        let proposal = BatchProposal::from_wire(proposal_wire).map_err(batch_protocol_error)?;
        let members = self.send_batch_members(batch_local_id)?;
        let requests = self.transfer_requests_for_batch_members(&members)?;
        if let Err(error) = self.require_production_batch_policy(&requests) {
            self.cancel_send_batch(batch_local_id)?;
            return Err(error);
        }
        for member in &members {
            let operation = self.operation(&member.operation_id)?;
            let request: TransferRequest =
                serde_json::from_str(&operation.request_json).map_err(|error| {
                    AccountError::new("database_corrupt", format!("transfer request: {error}"))
                })?;
            if let Err(error) = self.require_reviewed_transfer(&request) {
                self.cancel_send_batch(batch_local_id)?;
                return Err(error);
            }
        }
        let mut phase_timings_ms = batch
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
            .and_then(|receipt| receipt.get("phase_timings_ms").cloned())
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        let pre_sign_verification_started = Instant::now();
        let stock = self
            .batch_stock_reserved_by(batch_local_id)?
            .ok_or_else(|| AccountError::new("conflicting_operation", "batch stock is unlocked"))?;
        if stock.outpoint != proposal.stock_outpoint()
            || stock.participant_count != u8::try_from(members.len()).unwrap_or(u8::MAX)
        {
            return Err(AccountError::new(
                "conflicting_operation",
                "proposal and reserved stock differ",
            ));
        }
        let stock_script = proposal.stock_script_pubkey();
        let stock_verification = self.funding_verifier.verify(&FundingVerificationRequest {
            outpoint: stock.outpoint,
            txout: bdk_wallet::bitcoin::TxOut {
                value: Amount::from_sat(stock.value_sats),
                script_pubkey: stock_script,
            },
            birth_height: stock.birth_height,
        })?;
        let mut commitments = Vec::with_capacity(members.len());
        let mut signing_keys = HashMap::new();
        let mut member_verifications = HashMap::new();
        for member in &members {
            let operation = self.operation(&member.operation_id)?;
            if operation.state != "proof_ready" || !operation.backup_acked {
                return Err(AccountError::new(
                    "backup_required",
                    format!(
                        "batch member {} is not backup-acknowledged",
                        member.operation_id
                    ),
                ));
            }
            let funding = self.reserved_funding_for_operation(&operation)?;
            let verification = self.verify_funding(&funding)?;
            let pending_id = *self
                .pending_by_operation
                .get(&member.operation_id)
                .ok_or_else(|| {
                    AccountError::new(
                        "operation_not_resumable",
                        format!("batch member {} has no pending proof", member.operation_id),
                    )
                })?;
            let pending_nullifiers = self
                .primary_protocol_mut()?
                .pending_nullifiers(pending_id)
                .map_err(|error| AccountError::new("operation_not_resumable", error))?;
            verify_protocol_inputs_unspent(
                &pending_nullifiers,
                verification.checked_through,
                protocol_spend_preflight_required(&self.config),
            )?;
            let dependencies = self
                .primary_protocol_mut()?
                .pending_unconfirmed_dependencies(pending_id)
                .map_err(|error| AccountError::new("operation_not_resumable", error))?;
            self.reobserve_unconfirmed_dependencies(&dependencies)?;
            let payload = self
                .primary_protocol_mut()?
                .rebind_pending_batch_payload(pending_id, proposal.context())
                .map_err(|error| AccountError::new("batch_payload_incompatible", error))?;
            let change_spk = ScriptBuf::from_bytes(hex_decode(
                member.change_spk_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "batch member has no change script")
                })?,
                "batch change script",
            )?);
            let commit_nonce = decode_hex_32(
                member.commit_nonce_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "batch member has no commit nonce")
                })?,
                "batch commit nonce",
            )?;
            let fee_secret = self.batch_fee_secret(&funding)?;
            let fee_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &fee_secret);
            let max_charge = funding
                .value_sats()
                .checked_sub(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS)
                .ok_or_else(|| {
                    AccountError::new(
                        "insufficient_fees",
                        "batch fee cell cannot preserve minimum change",
                    )
                })?;
            commitments.push(
                ParticipantCommitment::new(
                    &proposal,
                    batch_operation_id(&member.operation_id),
                    commit_nonce,
                    payload,
                    funding.outpoint,
                    funding.txout.clone(),
                    fee_pubkey,
                    change_spk,
                    max_charge,
                )
                .map_err(batch_protocol_error)?,
            );
            signing_keys.insert(funding.outpoint, fee_secret);
            member_verifications.insert(member.operation_id.clone(), verification);
        }
        let current_height = member_verifications
            .values()
            .map(|receipt| receipt.checked_through)
            .chain(std::iter::once(stock_verification.checked_through))
            .max()
            .unwrap_or(stock_verification.checked_through);
        proposal
            .validate_at(
                genesis_block(parse_network(&self.config.network)?)
                    .block_hash()
                    .to_byte_array(),
                u32::try_from(current_height).map_err(|_| {
                    AccountError::new("stale_chain_state", "verified tip exceeds u32")
                })?,
            )
            .map_err(batch_protocol_error)?;
        let manifest = BatchManifest::from_wire(&proposal, commitments, manifest_wire)
            .map_err(batch_protocol_error)?;
        if self
            .config
            .max_fee_sats
            .is_some_and(|limit| manifest.miner_fee() > limit)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!("{} sats exceeds configured maximum", manifest.miner_fee()),
            ));
        }
        phase_timings_ms["pre_sign_verification"] =
            json!(elapsed_millis(pre_sign_verification_started));
        let local_signing_persistence_started = Instant::now();
        let stock_signature = manifest
            .sign_stock(&proposal, &self.batch_stock_secret()?)
            .map_err(batch_protocol_error)?;
        let participant_signatures = manifest
            .commitments()
            .iter()
            .enumerate()
            .map(|(index, commitment)| {
                let key = signing_keys
                    .get(&commitment.fee_outpoint())
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "canonical manifest contains an unknown fee input",
                        )
                    })?;
                manifest
                    .sign_participant(&proposal, index, key)
                    .map_err(batch_protocol_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let transaction = manifest
            .finalize(&proposal, &stock_signature, &participant_signatures)
            .map_err(batch_protocol_error)?;
        let txid = transaction.compute_txid();
        let signed_tx_hex = hex_encode(&serialize(&transaction));
        let now = unix_time()?;
        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let persisted = (|| -> Result<(), AccountError> {
            let mut batch_receipt: Value = batch
                .receipt_json
                .as_deref()
                .and_then(|encoded| serde_json::from_str(encoded).ok())
                .unwrap_or_else(|| json!({}));
            batch_receipt["txid"] = json!(txid.to_string());
            batch_receipt["signed_at"] = json!(now);
            batch_receipt["stock_verification"] = json!(stock_verification);
            batch_receipt["phase_timings_ms"] = phase_timings_ms.clone();
            self.stamp_production_rollout_authorization(&mut batch_receipt, batch_local_id)?;
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET state = 'signed_persisted', signed_tx_hex = ?2,
                     txid = ?3, receipt_json = ?4, updated_at = ?5
                 WHERE batch_local_id = ?1",
                params![
                    batch_local_id,
                    signed_tx_hex,
                    txid.to_string(),
                    batch_receipt.to_string(),
                    now,
                ],
            )?;
            self.db.conn.execute(
                "UPDATE opencsv_batch_stocks
                 SET state = 'signature_released'
                 WHERE reserved_by_batch = ?1",
                [batch_local_id],
            )?;
            for member in &members {
                let operation = self.operation(&member.operation_id)?;
                let mut receipt: Value = operation
                    .receipt_json
                    .as_deref()
                    .and_then(|encoded| serde_json::from_str(encoded).ok())
                    .unwrap_or_else(|| json!({}));
                receipt["txid"] = json!(txid.to_string());
                receipt["funding_verification"] = json!(member_verifications
                    .get(&member.operation_id)
                    .ok_or_else(|| AccountError::new(
                        "database_corrupt",
                        "missing member verification"
                    ))?);
                receipt["phase_timings_ms"] = phase_timings_ms.clone();
                self.stamp_production_rollout_authorization(
                    &mut receipt,
                    &member.operation_id,
                )?;
                self.db.conn.execute(
                    "UPDATE opencsv_operations
                     SET state = 'signed_persisted', signed_tx_hex = ?2,
                         txid = ?3, receipt_json = ?4, updated_at = ?5
                     WHERE operation_id = ?1",
                    params![
                        member.operation_id,
                        signed_tx_hex,
                        txid.to_string(),
                        receipt.to_string(),
                        now,
                    ],
                )?;
                self.db.conn.execute(
                    "UPDATE opencsv_utxo_reservations
                     SET state = 'signature_released' WHERE operation_id = ?1",
                    [&member.operation_id],
                )?;
            }
            self.db.conn.execute(
                "INSERT OR IGNORE INTO opencsv_batch_stocks(
                     participant_count, txid, vout, value_sats, birth_height,
                     state, reserved_by_batch, created_at
                 ) VALUES(?1, ?2, 2, ?3, 0, 'pending', NULL, ?4)",
                params![
                    u8::try_from(members.len()).unwrap_or(u8::MAX),
                    txid.to_string(),
                    i64::try_from(stock.value_sats).map_err(|_| {
                        AccountError::new("database_error", "stock value exceeds SQLite i64")
                    })?,
                    now,
                ],
            )?;
            Ok(())
        })();
        match persisted {
            Ok(()) => self.db.conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        let seen_at = u64::try_from(now)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(transaction.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        phase_timings_ms["local_signing_persistence"] =
            json!(elapsed_millis(local_signing_persistence_started));
        let phase_timings_json = phase_timings_ms.to_string();
        self.db.conn.execute(
            "UPDATE opencsv_send_batches
             SET receipt_json = json_set(receipt_json, '$.phase_timings_ms', json(?2)),
                 updated_at = ?3 WHERE batch_local_id = ?1",
            params![batch_local_id, phase_timings_json, unix_time()?],
        )?;
        self.db.conn.execute(
            "UPDATE opencsv_operations
             SET receipt_json = json_set(receipt_json, '$.phase_timings_ms', json(?2)),
                 updated_at = ?3
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![batch_local_id, phase_timings_ms.to_string(), unix_time()?],
        )?;
        let relay_submission_started = Instant::now();
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&transaction)?;
        let client = self.esplora_client();
        let fallback = relay_via_esplora_if_unobserved(&client, &transaction);
        let mut receipt: Value = self
            .send_batch(batch_local_id)?
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        receipt["p2p_submissions"] = json!(p2p_submissions);
        receipt["p2p_peers"] = json!(relay_peers);
        receipt["generic_relay_fallback"] = json!(matches!(&fallback, Ok(true)));
        if let Err(error) = &fallback {
            receipt["generic_relay_error"] = json!(error.to_string());
        }
        receipt["phase_timings_ms"]["relay_submission"] =
            json!(elapsed_millis(relay_submission_started));
        let updated = unix_time()?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE opencsv_send_batches
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE batch_local_id = ?1",
            params![batch_local_id, receipt.to_string(), updated],
        )?;
        transaction.execute(
            "UPDATE opencsv_operations SET state = 'broadcast_unobserved', updated_at = ?2
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![batch_local_id, updated],
        )?;
        transaction.execute(
            "UPDATE opencsv_operations
             SET receipt_json = json_set(
                     receipt_json,
                     '$.phase_timings_ms.relay_submission',
                     json_extract(?2, '$.phase_timings_ms.relay_submission')
                 )
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![batch_local_id, receipt.to_string()],
        )?;
        transaction.commit()?;
        self.send_batch_json(batch_local_id)
    }

    /// Require pinned exact-byte visibility for the shared transaction, then
    /// finalize one independently deliverable consignment per member.
    pub fn observe_send_batch_unconfirmed(
        &mut self,
        batch_local_id: &str,
        raw_transaction: &[u8],
        observations_json: &str,
    ) -> Result<Value, AccountError> {
        let batch = self.send_batch(batch_local_id)?;
        if !matches!(
            batch.state.as_str(),
            "signed_persisted" | "broadcast_unobserved" | "mempool"
        ) {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("batch is {}", batch.state),
            ));
        }
        if hex_decode(
            batch.signed_tx_hex.as_deref().ok_or_else(|| {
                AccountError::new("database_corrupt", "signed batch has no transaction")
            })?,
            "signed batch transaction",
        )? != raw_transaction
        {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "observer bytes differ from the exact persisted batch",
            ));
        }
        let transaction: Transaction = deserialize(raw_transaction).map_err(|error| {
            AccountError::new("invalid_observation_transaction", error.to_string())
        })?;
        let txid = transaction.compute_txid();
        let txid_string = txid.to_string();
        if batch.txid.as_deref() != Some(txid_string.as_str()) {
            return Err(AccountError::new(
                "raw_transaction_mismatch",
                "observer txid differs from the persisted batch",
            ));
        }
        let observer_evaluation_started = Instant::now();
        let (receipts, policy_failure) = evaluate_observation_evidence(
            &self.config.observation_checks,
            self.config.required_raw_observer_quorum,
            raw_transaction,
            observations_json,
        )?;
        self.persist_observation_receipts(&txid_string, &receipts)?;
        if let Some(error) = policy_failure {
            return Err(error);
        }
        self.enforce_unconfirmed_non_host_policy(&txid_string, true)?;
        if !receipts.iter().any(|receipt| {
            receipt["kind"] == json!(ObservationKind::RawTransactionApi)
                && receipt["result"] == json!(ObservationResult::Observed)
                && receipt["raw_byte_match"] == true
        }) {
            return Err(AccountError::new(
                "mempool_observation_failed",
                "no pinned observer returned the exact shared transaction",
            ));
        }
        if batch.state != "mempool" {
            for member in self.send_batch_members(batch_local_id)? {
                self.finalize_observed_operation(&member.operation_id, txid)?;
            }
            self.db.conn.execute(
                "UPDATE opencsv_send_batches SET state = 'mempool', updated_at = ?2
                 WHERE batch_local_id = ?1",
                params![batch_local_id, unix_time()?],
            )?;
        }
        let observer_evaluation_ms = elapsed_millis(observer_evaluation_started);
        let mut durable_receipt: Value = self
            .send_batch(batch_local_id)?
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        durable_receipt["phase_timings_ms"]["observer_evaluation"] = json!(observer_evaluation_ms);
        self.db.conn.execute(
            "UPDATE opencsv_send_batches SET receipt_json = ?2, updated_at = ?3
             WHERE batch_local_id = ?1",
            params![batch_local_id, durable_receipt.to_string(), unix_time()?],
        )?;
        self.db.conn.execute(
            "UPDATE opencsv_operations
             SET receipt_json = json_set(
                     receipt_json,
                     '$.phase_timings_ms.observer_evaluation',
                     ?2
                 ), updated_at = ?3
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![
                batch_local_id,
                i64::try_from(observer_evaluation_ms).unwrap_or(i64::MAX),
                unix_time()?
            ],
        )?;
        let mut value = self.send_batch_json(batch_local_id)?;
        value["observations"] = json!(receipts);
        Ok(value)
    }

    /// Resume one crash-interrupted shared transaction without changing its
    /// proposal, manifest, signatures, member ordering, or delivery IDs.
    pub fn resume_send_batch(&mut self, batch_local_id: &str) -> Result<Value, AccountError> {
        let batch = self.send_batch(batch_local_id)?;
        if !matches!(
            batch.state.as_str(),
            "signed_persisted" | "broadcast_unobserved"
        ) {
            return self.send_batch_json(batch_local_id);
        }
        let mut receipt: Value = batch
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        self.signed_fee_limit(&receipt, batch_local_id)?;
        let signed = batch.signed_tx_hex.as_deref().ok_or_else(|| {
            AccountError::new("database_corrupt", "signed batch has no transaction")
        })?;
        let transaction: Transaction = deserialize(&hex_decode(signed, "signed batch")?)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let txid = transaction.compute_txid();
        let txid_string = txid.to_string();
        if batch.txid.as_deref() != Some(txid_string.as_str()) {
            return Err(AccountError::new(
                "database_corrupt",
                "signed batch txid differs from its persisted bytes",
            ));
        }
        let seen_at = u64::try_from(unix_time()?)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(transaction.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&transaction)?;
        let client = self.esplora_client();
        let fallback = relay_via_esplora_if_unobserved(&client, &transaction);
        receipt["resume_p2p_submissions"] = json!(p2p_submissions);
        receipt["resume_p2p_peers"] = json!(relay_peers);
        receipt["resume_generic_relay_fallback"] = json!(matches!(&fallback, Ok(true)));
        if let Err(error) = fallback {
            receipt["resume_generic_relay_error"] = json!(error.to_string());
        }
        let now = unix_time()?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE opencsv_send_batches
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE batch_local_id = ?1",
            params![batch_local_id, receipt.to_string(), now],
        )?;
        transaction.execute(
            "UPDATE opencsv_operations
             SET state = 'broadcast_unobserved', updated_at = ?2
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![batch_local_id, now],
        )?;
        transaction.commit()?;
        self.send_batch_json(batch_local_id)
    }

    /// Build the next unanimous C1 replacement epoch. All inputs, payloads,
    /// protected outputs, member identities, and output positions are fixed;
    /// only participant change values may decrease to pay the higher fee.
    pub fn fee_bump_send_batch(
        &mut self,
        batch_local_id: &str,
        target_sat_per_vb: u64,
    ) -> Result<Value, AccountError> {
        self.require_write_enabled()?;
        let target_sat_per_vb = u32::try_from(target_sat_per_vb)
            .map_err(|_| AccountError::new("invalid_fee_policy", "target feerate exceeds u32"))?;
        if target_sat_per_vb == 0 {
            return Err(AccountError::new(
                "invalid_fee_policy",
                "target_sat_per_vb must be positive",
            ));
        }
        let batch = self.send_batch(batch_local_id)?;
        if !matches!(batch.state.as_str(), "broadcast_unobserved" | "mempool") {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("cannot fee-bump batch in {}", batch.state),
            ));
        }
        let proposal =
            BatchProposal::from_wire(batch.proposal_wire.as_deref().ok_or_else(|| {
                AccountError::new("database_corrupt", "signed batch has no proposal")
            })?)
            .map_err(batch_protocol_error)?;
        let manifest_wire = batch
            .manifest_wire
            .as_deref()
            .ok_or_else(|| AccountError::new("database_corrupt", "signed batch has no manifest"))?;
        let original_bytes = hex_decode(
            batch.signed_tx_hex.as_deref().ok_or_else(|| {
                AccountError::new("database_corrupt", "signed batch has no transaction")
            })?,
            "signed batch transaction",
        )?;
        let original: Transaction = deserialize(&original_bytes)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let original_txid = original.compute_txid();
        let original_txid_string = original_txid.to_string();
        if batch.txid.as_deref() != Some(original_txid_string.as_str()) {
            return Err(AccountError::new(
                "database_corrupt",
                "signed batch txid differs from its exact bytes",
            ));
        }
        let members = self.send_batch_members(batch_local_id)?;
        let stock = self
            .batch_stock_reserved_by(batch_local_id)?
            .ok_or_else(|| AccountError::new("conflicting_operation", "batch stock is unlocked"))?;
        if stock.outpoint != proposal.stock_outpoint()
            || stock.participant_count != u8::try_from(members.len()).unwrap_or(u8::MAX)
        {
            return Err(AccountError::new(
                "conflicting_operation",
                "replacement proposal and durable stock differ",
            ));
        }
        let stock_verification = self.funding_verifier.verify(&FundingVerificationRequest {
            outpoint: stock.outpoint,
            txout: bdk_wallet::bitcoin::TxOut {
                value: Amount::from_sat(stock.value_sats),
                script_pubkey: proposal.stock_script_pubkey(),
            },
            birth_height: stock.birth_height,
        })?;
        let mut protocol_candidate = self.protocol.as_ref().cloned().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices cannot bump batches")
        })?;
        let mut pending_candidate = self.pending_by_operation.clone();
        let mut commitments = Vec::with_capacity(members.len());
        let mut signing_keys = HashMap::new();
        let mut member_verifications = HashMap::new();
        let mut operations = Vec::with_capacity(members.len());
        for member in &members {
            let operation = self.operation(&member.operation_id)?;
            if !matches!(operation.state.as_str(), "broadcast_unobserved" | "mempool") {
                return Err(AccountError::new(
                    "invalid_operation_state",
                    format!(
                        "batch member {} is {}",
                        member.operation_id, operation.state
                    ),
                ));
            }
            let funding = self.historical_funding_for_operation(&operation)?;
            if !original
                .input
                .iter()
                .skip(1)
                .any(|input| input.previous_output == funding.outpoint)
            {
                return Err(AccountError::new(
                    "protocol_layout_violation",
                    "persisted batch omits a member fee input",
                ));
            }
            let verification = self.verify_funding(&funding)?;
            let pending_id = match pending_candidate.get(&member.operation_id).copied() {
                Some(pending_id) => pending_id,
                None => {
                    let pending_json = self
                        .db
                        .conn
                        .query_row(
                            "SELECT pending_json FROM opencsv_operations
                             WHERE operation_id = ?1",
                            [&member.operation_id],
                            |row| row.get::<_, Option<String>>(0),
                        )?
                        .ok_or_else(|| {
                            AccountError::new(
                                "operation_not_resumable",
                                "batch replacement has no durable pending proof",
                            )
                        })?;
                    let pending_id = protocol_candidate
                        .import_pending(&pending_json)
                        .map_err(|error| AccountError::new("operation_not_resumable", error))?;
                    pending_candidate.insert(member.operation_id.clone(), pending_id);
                    pending_id
                }
            };
            let dependencies = protocol_candidate
                .pending_unconfirmed_dependencies(pending_id)
                .map_err(|error| AccountError::new("operation_not_resumable", error))?;
            self.reobserve_unconfirmed_dependencies(&dependencies)?;
            let payload = protocol_candidate
                .rebind_pending_batch_payload(pending_id, proposal.context())
                .map_err(|error| AccountError::new("batch_payload_incompatible", error))?;
            let change_spk = ScriptBuf::from_bytes(hex_decode(
                member.change_spk_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "batch member has no change script")
                })?,
                "batch change script",
            )?);
            let commit_nonce = decode_hex_32(
                member.commit_nonce_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "batch member has no commit nonce")
                })?,
                "batch commit nonce",
            )?;
            let fee_secret = self.batch_fee_secret(&funding)?;
            let fee_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &fee_secret);
            let max_charge = funding
                .value_sats()
                .checked_sub(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS)
                .ok_or_else(|| {
                    AccountError::new(
                        "insufficient_fees",
                        "batch fee cell cannot preserve minimum change",
                    )
                })?;
            commitments.push(
                ParticipantCommitment::new(
                    &proposal,
                    batch_operation_id(&member.operation_id),
                    commit_nonce,
                    payload,
                    funding.outpoint,
                    funding.txout.clone(),
                    fee_pubkey,
                    change_spk,
                    max_charge,
                )
                .map_err(batch_protocol_error)?,
            );
            signing_keys.insert(funding.outpoint, fee_secret);
            member_verifications.insert(member.operation_id.clone(), verification);
            operations.push(operation);
        }
        let current_height = member_verifications
            .values()
            .map(|receipt| receipt.checked_through)
            .chain(std::iter::once(stock_verification.checked_through))
            .max()
            .unwrap_or(stock_verification.checked_through);
        proposal
            .validate_at(
                genesis_block(parse_network(&self.config.network)?)
                    .block_hash()
                    .to_byte_array(),
                u32::try_from(current_height).map_err(|_| {
                    AccountError::new("stale_chain_state", "verified tip exceeds u32")
                })?,
            )
            .map_err(batch_protocol_error)?;
        let manifest = BatchManifest::from_wire(&proposal, commitments, manifest_wire)
            .map_err(batch_protocol_error)?;
        let stock_secret = self.batch_stock_secret()?;
        let sign_manifest = |manifest: &BatchManifest| -> Result<Transaction, AccountError> {
            let stock_signature = manifest
                .sign_stock(&proposal, &stock_secret)
                .map_err(batch_protocol_error)?;
            let participant_signatures = manifest
                .commitments()
                .iter()
                .enumerate()
                .map(|(index, commitment)| {
                    let key = signing_keys
                        .get(&commitment.fee_outpoint())
                        .ok_or_else(|| {
                            AccountError::new(
                                "database_corrupt",
                                "manifest contains an unknown fee input",
                            )
                        })?;
                    manifest
                        .sign_participant(&proposal, index, key)
                        .map_err(batch_protocol_error)
                })
                .collect::<Result<Vec<_>, _>>()?;
            manifest
                .finalize(&proposal, &stock_signature, &participant_signatures)
                .map_err(batch_protocol_error)
        };
        if serialize(&sign_manifest(&manifest)?) != original_bytes {
            return Err(AccountError::new(
                "database_corrupt",
                "persisted batch signatures do not match the frozen manifest",
            ));
        }
        let replacement = manifest
            .replacement(&proposal, target_sat_per_vb)
            .map_err(batch_protocol_error)?;
        let mut batch_receipt: Value = batch
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        if self
            .signed_fee_limit(&batch_receipt, batch_local_id)?
            .is_some_and(|limit| replacement.miner_fee() > limit)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!(
                    "{} sats exceeds configured maximum",
                    replacement.miner_fee()
                ),
            ));
        }
        let replacement_transaction = sign_manifest(&replacement)?;
        let replacement_txid = replacement_transaction.compute_txid();
        let replacement_hex = hex_encode(&serialize(&replacement_transaction));
        let mut operation_updates = Vec::with_capacity(operations.len());
        for operation in &operations {
            let mut receipt: Value = operation
                .receipt_json
                .as_deref()
                .and_then(|encoded| serde_json::from_str(encoded).ok())
                .unwrap_or_else(|| json!({}));
            let prior_delivery = self.replacement_delivery_snapshot(operation, &receipt)?;
            let replacement_delivery_nonce = random_id(16);
            let receipt_object = receipt.as_object_mut().ok_or_else(|| {
                AccountError::new("database_corrupt", "operation receipt is not an object")
            })?;
            if let Some(prior_delivery) = prior_delivery {
                receipt_object.insert("pre_replacement_delivery".into(), prior_delivery);
            }
            receipt_object.insert(
                "delivery_nonce".into(),
                json!(replacement_delivery_nonce.clone()),
            );
            let stale_consignment_id = receipt_object
                .remove("consignment_id")
                .and_then(|value| value.as_str().map(str::to_owned));
            receipt_object.remove("consignment_base64");
            receipt_object.remove("delivery_ready");
            receipt_object.remove("consignment_delivered");
            receipt_object.remove("consignment_delivered_at");
            receipt_object.insert("replacement_delivery_required".into(), json!(true));
            receipt_object.insert("replaces".into(), json!(original_txid.to_string()));
            receipt_object.insert("txid".into(), json!(replacement_txid.to_string()));
            receipt_object.insert(
                "replacement_epoch".into(),
                json!(replacement.replacement_epoch()),
            );
            receipt_object.insert("target_sat_per_vb".into(), json!(target_sat_per_vb));
            receipt_object.insert(
                "funding_verification".into(),
                json!(member_verifications.get(&operation.operation_id)),
            );
            if let Some(stale_id) = stale_consignment_id.as_deref() {
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
            operation_updates.push((
                operation.operation_id.clone(),
                receipt.to_string(),
                stale_consignment_id,
                replacement_delivery_nonce,
            ));
        }
        let now = unix_time()?;
        batch_receipt["replaces"] = json!(original_txid.to_string());
        batch_receipt["txid"] = json!(replacement_txid.to_string());
        batch_receipt["replacement_epoch"] = json!(replacement.replacement_epoch());
        batch_receipt["target_sat_per_vb"] = json!(target_sat_per_vb);
        batch_receipt["miner_fee_sats"] = json!(replacement.miner_fee());
        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let persisted = (|| -> Result<(), AccountError> {
            for (operation_id, receipt, stale_consignment_id, delivery_nonce) in &operation_updates
            {
                if let Some(stale_id) = stale_consignment_id {
                    self.db.conn.execute(
                        "DELETE FROM opencsv_consignment_snapshots WHERE consignment_id = ?1",
                        [stale_id],
                    )?;
                    self.db.conn.execute(
                        "DELETE FROM opencsv_consignments WHERE consignment_id = ?1",
                        [stale_id],
                    )?;
                }
                self.db.conn.execute(
                    "UPDATE opencsv_operations
                     SET state = 'signed_persisted', signed_tx_hex = ?2,
                         txid = ?3, receipt_json = ?4, delivery_nonce = ?5,
                         updated_at = ?6
                     WHERE operation_id = ?1",
                    params![
                        operation_id,
                        replacement_hex,
                        replacement_txid.to_string(),
                        receipt,
                        delivery_nonce,
                        now,
                    ],
                )?;
            }
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET state = 'signed_persisted', manifest_wire = ?2,
                     signed_tx_hex = ?3, txid = ?4, receipt_json = ?5,
                     updated_at = ?6 WHERE batch_local_id = ?1",
                params![
                    batch_local_id,
                    replacement.wire_bytes(),
                    replacement_hex,
                    replacement_txid.to_string(),
                    batch_receipt.to_string(),
                    now,
                ],
            )?;
            self.db.conn.execute(
                "UPDATE opencsv_batch_stocks SET state = 'invalidated'
                 WHERE txid = ?1 AND vout = 2 AND state = 'pending'",
                [original_txid.to_string()],
            )?;
            self.db.conn.execute(
                "INSERT OR IGNORE INTO opencsv_batch_stocks(
                     participant_count, txid, vout, value_sats, birth_height,
                     state, reserved_by_batch, created_at
                 ) VALUES(?1, ?2, 2, ?3, 0, 'pending', NULL, ?4)",
                params![
                    u8::try_from(members.len()).unwrap_or(u8::MAX),
                    replacement_txid.to_string(),
                    i64::try_from(stock.value_sats).map_err(|_| {
                        AccountError::new("database_error", "stock value exceeds SQLite i64")
                    })?,
                    now,
                ],
            )?;
            Ok(())
        })();
        match persisted {
            Ok(()) => self.db.conn.execute_batch("COMMIT")?,
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        self.protocol = Some(protocol_candidate);
        self.pending_by_operation = pending_candidate;
        let seen_at = u64::try_from(now)
            .map_err(|_| AccountError::new("clock_error", "negative timestamp"))?;
        self.bitcoin
            .apply_unconfirmed_txs([(Arc::new(replacement_transaction.clone()), seen_at)]);
        self.bitcoin.persist(&mut self.db)?;
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&replacement_transaction)?;
        let client = self.esplora_client();
        let fallback = relay_via_esplora_if_unobserved(&client, &replacement_transaction);
        batch_receipt["p2p_submissions"] = json!(p2p_submissions);
        batch_receipt["p2p_peers"] = json!(relay_peers);
        batch_receipt["generic_relay_fallback"] = json!(matches!(&fallback, Ok(true)));
        if let Err(error) = fallback {
            batch_receipt["generic_relay_error"] = json!(error.to_string());
        }
        let updated = unix_time()?;
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "UPDATE opencsv_send_batches
             SET state = 'broadcast_unobserved', receipt_json = ?2, updated_at = ?3
             WHERE batch_local_id = ?1",
            params![batch_local_id, batch_receipt.to_string(), updated],
        )?;
        transaction.execute(
            "UPDATE opencsv_operations SET state = 'broadcast_unobserved', updated_at = ?2
             WHERE operation_id IN (
                 SELECT operation_id FROM opencsv_send_batch_members
                 WHERE batch_local_id = ?1
             )",
            params![batch_local_id, updated],
        )?;
        transaction.commit()?;
        self.send_batch_json(batch_local_id)
    }

    /// Refresh every member against the authoritative CBF path and mark the
    /// shared transaction confirmed only when every member reaches settlement.
    pub fn refresh_send_batch_spv(&mut self, batch_local_id: &str) -> Result<Value, AccountError> {
        let batch = self.send_batch(batch_local_id)?;
        if !matches!(batch.state.as_str(), "mempool" | "confirmed") {
            return Err(AccountError::new(
                "invalid_batch_state",
                format!("batch is {}", batch.state),
            ));
        }
        let members = self.send_batch_members(batch_local_id)?;
        let mut receipts = Vec::with_capacity(members.len());
        let mut all_confirmed = true;
        for member in members {
            let receipt = self.refresh_operation_spv(&member.operation_id)?;
            all_confirmed &= matches!(
                receipt["state"].as_str(),
                Some("confirmed" | "consignment_delivered")
            );
            receipts.push(receipt);
        }
        if all_confirmed {
            self.db.conn.execute(
                "UPDATE opencsv_send_batches SET state = 'confirmed', updated_at = ?2
                 WHERE batch_local_id = ?1",
                params![batch_local_id, unix_time()?],
            )?;
            self.db.conn.execute(
                "UPDATE opencsv_batch_stocks
                 SET state = 'confirmed'
                 WHERE txid = (SELECT txid FROM opencsv_send_batches
                               WHERE batch_local_id = ?1)
                   AND vout = 2 AND state = 'pending'",
                [batch_local_id],
            )?;
        }
        let mut result = self.send_batch_json(batch_local_id)?;
        result["member_spv"] = json!(receipts);
        Ok(result)
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
        self.require_product_write_enabled()?;
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
        let request: TransferRequest = match serde_json::from_str(&operation.request_json) {
            Ok(request) => request,
            Err(error) => {
                return self.fail_prebroadcast(
                    operation_id,
                    AccountError::new("database_corrupt", format!("transfer request: {error}")),
                );
            }
        };
        if let Err(error) = self.require_reviewed_transfer(&request) {
            return self.fail_prebroadcast(operation_id, error);
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
            esplora_request_timeout_secs: self.config.esplora_request_timeout_secs,
            esplora_max_retries: self.config.esplora_max_retries,
            require_protocol_spend_preflight: protocol_spend_preflight_required(&self.config),
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
        if let Err(error) = self.require_reviewed_transfer(&current_request) {
            return self.fail_proof_job(&completed.operation_id, error);
        }
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
        let pending_nullifiers = self
            .primary_protocol_mut()?
            .pending_nullifiers(pending_id)
            .map_err(|error| AccountError::new("database_error", error))?;
        if let Err(error) = verify_protocol_inputs_unspent(
            &pending_nullifiers,
            completed.verification.checked_through,
            protocol_spend_preflight_required(&self.config),
        ) {
            if let Some(protocol) = self.protocol.as_mut() {
                protocol.cancel_pending(pending_id);
            }
            return self.fail_proof_job(&completed.operation_id, error);
        }
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
        if !completed.reconciled_spent_coin_ids.is_empty() {
            if let Err(error) = self
                .primary_protocol_mut()?
                .mark_spent(&completed.reconciled_spent_coin_ids)
                .map_err(|error| AccountError::new("database_error", error))
            {
                if let Some(protocol) = self.protocol.as_mut() {
                    protocol.cancel_pending(pending_id);
                }
                return self.fail_proof_job(&completed.operation_id, error);
            }
        }
        self.pending_by_operation
            .insert(completed.operation_id.clone(), pending_id);
        self.persist_dependency_reobservations_at(
            &completed.unconfirmed_dependencies,
            completed.dependency_observed_at,
        )?;
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
            &completed.phase_timings_ms,
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
        if error.retryable {
            self.record_retryable_proof_error(operation_id, &error)?;
            return Err(error);
        }
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

    /// Keep an exact pre-broadcast proposal and its fee lock durable when the
    /// mandatory chain evidence is temporarily unavailable. No proof or
    /// signature is installed. Re-entering `prove_operation` retries the same
    /// operation id and reserved outpoint after the scan/peers recover.
    fn record_retryable_proof_error(
        &mut self,
        operation_id: &str,
        error: &AccountError,
    ) -> Result<(), AccountError> {
        let now = unix_time()?;
        let encoded = error.json().to_string();
        self.db.conn.execute(
            "UPDATE opencsv_operations
             SET receipt_json = json_set(COALESCE(receipt_json, '{}'),
                                         '$.retryable_proof_error', json(?2)),
                 rejection_reason = NULL, updated_at = ?3
             WHERE operation_id = ?1
               AND state IN ('planned', 'fee_reserved')",
            params![operation_id, encoded, now],
        )?;
        self.db.conn.execute(
            "UPDATE opencsv_send_batches
             SET receipt_json = json_set(COALESCE(receipt_json, '{}'),
                                         '$.retryable_proof_error', json(?2)),
                 updated_at = ?3
             WHERE batch_local_id IN (
                 SELECT batch_local_id FROM opencsv_send_batch_members
                 WHERE operation_id = ?1
             ) AND state IN ('collecting', 'solo', 'frozen')",
            params![operation_id, encoded, now],
        )?;
        Ok(())
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

    /// Acknowledge that Signal Secure Backup durably accepted the exact staged
    /// wallet checkpoint while this operation remained proof-ready.
    ///
    /// Unrelated receive/finality state may advance while Signal exports the
    /// staged payload. Accepting the operation's exact prepared checkpoint, or
    /// the complete current checkpoint, avoids an expensive proof retry while
    /// the immediate transaction ensures an arbitrary stale backup can never
    /// unlock signing.
    pub fn acknowledge_operation_backup(
        &mut self,
        operation_id: &str,
        checkpoint_hash: &str,
    ) -> Result<Value, AccountError> {
        self.db.conn.execute_batch("BEGIN IMMEDIATE")?;
        let acknowledged = (|| -> Result<Value, AccountError> {
            let operation = self.operation(operation_id)?;
            if operation.state != OperationState::ProofReady.as_str() {
                return Err(AccountError::new(
                    "invalid_operation_state",
                    format!("operation is {}", operation.state),
                ));
            }
            let current_checkpoint = self.checkpoint()?;
            let current_hash = current_checkpoint["checkpoint_hash"]
                .as_str()
                .ok_or_else(|| {
                    AccountError::new("checkpoint_failed", "current checkpoint has no hash")
                })?;
            let prepared_matches = operation.checkpoint_hash.as_deref() == Some(checkpoint_hash);
            if !prepared_matches && current_hash != checkpoint_hash {
                return Err(AccountError::new(
                    "backup_checkpoint_mismatch",
                    "Secure Backup did not acknowledge this proof-ready operation's staged or current wallet checkpoint",
                ));
            }
            self.db.conn.execute(
                "UPDATE opencsv_operations
                 SET checkpoint_hash = ?2, backup_acked = 1,
                     receipt_json = json_set(COALESCE(receipt_json, '{}'),
                                             '$.checkpoint_hash', ?2),
                     updated_at = ?3
                 WHERE operation_id = ?1",
                params![operation_id, checkpoint_hash, unix_time()?],
            )?;
            Ok(json!({
                "operation_id": operation_id,
                "backup_acked": true,
                "checkpoint_hash": checkpoint_hash,
            }))
        })();
        match acknowledged {
            Ok(response) => {
                self.db.conn.execute_batch("COMMIT")?;
                Ok(response)
            }
            Err(error) => {
                let _ = self.db.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
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
        if operation.kind == "mint" {
            self.require_issuance_write_enabled()?;
        }
        if operation.kind == "transfer" {
            self.require_product_write_enabled()?;
        }
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
        if operation.kind == "transfer" {
            let request: TransferRequest =
                serde_json::from_str(&operation.request_json).map_err(|error| {
                    AccountError::new("database_corrupt", format!("transfer request: {error}"))
                })?;
            if let Err(error) = self.require_reviewed_transfer(&request) {
                return self.fail_prebroadcast(operation_id, error);
            }
        }
        let mut phase_timings_ms = operation
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str::<Value>(encoded).ok())
            .and_then(|receipt| receipt.get("phase_timings_ms").cloned())
            .filter(Value::is_object)
            .unwrap_or_else(|| json!({}));
        let pre_sign_verification_started = Instant::now();
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
        // Mints create protocol coins but consume no OpenCSV input coin. The
        // confirmed-nullifier rollback check therefore applies only to
        // transfers; Bitcoin funding freshness remains mandatory for both
        // operation kinds above.
        if operation.kind == "transfer" {
            let pending_nullifiers = self
                .primary_protocol_mut()?
                .pending_nullifiers(pending_id)
                .map_err(|error| AccountError::new("operation_not_resumable", error))?;
            if let Err(error) = verify_protocol_inputs_unspent(
                &pending_nullifiers,
                verification.checked_through,
                protocol_spend_preflight_required(&self.config),
            ) {
                return self.fail_prebroadcast(operation_id, error);
            }
        }
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
        phase_timings_ms["pre_sign_verification"] =
            json!(elapsed_millis(pre_sign_verification_started));

        let local_signing_persistence_started = Instant::now();
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
        if self
            .effective_fee_limit(policy.max_fee_sats)
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
            "phase_timings_ms": phase_timings_ms,
        });
        self.stamp_production_rollout_authorization(&mut receipt, operation_id)?;
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
        receipt["phase_timings_ms"]["local_signing_persistence"] =
            json!(elapsed_millis(local_signing_persistence_started));
        self.db.conn.execute(
            "UPDATE opencsv_operations SET receipt_json = ?2, updated_at = ?3
             WHERE operation_id = ?1",
            params![operation_id, receipt.to_string(), unix_time()?],
        )?;

        let relay_submission_started = Instant::now();
        let (p2p_submissions, relay_peers) = self.submit_direct_p2p(&tx)?;
        let client = self.esplora_client();
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
        receipt["phase_timings_ms"]["relay_submission"] =
            json!(elapsed_millis(relay_submission_started));
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
        let txid = operation.txid.as_deref().ok_or_else(|| {
            AccountError::new(
                "invalid_operation_state",
                "SPV operation has no transaction id",
            )
        })?;
        let parsed_txid = txid.parse::<Txid>().map_err(|error| {
            AccountError::new("database_corrupt", format!("operation txid: {error}"))
        })?;
        // Required raw observers gate zero-confirmation delivery. They must
        // not strand a replacement after the phone-owned CBF path has proved
        // the exact txid in a PoW-verified block. Build the replacement
        // consignment on a clone, verify it first, and install that candidate
        // only after the scan succeeds. A missing/unavailable observer can
        // therefore never mutate protocol state by itself.
        let (consignment, mut finalized_candidate) = self.spv_consignment_candidate(
            operation_id,
            &operation,
            parsed_txid,
            &receipt,
        )?;
        let spv_started = Instant::now();
        let verdict = self.scan_verify_outgoing_operation(&operation, &hex_encode(&consignment))?;
        let spv_ms = elapsed_millis(spv_started);
        let now_ms = unix_time_millis()?;
        let spv_started_at_ms = now_ms.saturating_sub(i64::try_from(spv_ms).unwrap_or(i64::MAX));
        let verified = verdict["status"] == "verified";
        let detail = if verified {
            "verified exact transaction through the phone-owned multi-peer scan".to_owned()
        } else {
            verdict["reason"]
                .as_str()
                .unwrap_or("multi-peer scan has not settled the transaction")
                .to_owned()
        };
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
                "started_at_ms": spv_started_at_ms,
                "completed_at_ms": now_ms,
                "latency_ms": spv_ms,
                "cached_at_ms": now_ms,
                "cache_age_ms": 0,
                "certificate_profile": Value::Null,
                "certificate_chain_fingerprints_sha256": [],
                "raw_byte_match": false,
                "detail": detail,
                "failures": failures,
            })],
        )?;
        receipt["phase_timings_ms"]["spv_confirmation"] = json!(spv_ms);
        let installed_candidate = verified && finalized_candidate.is_some();
        if installed_candidate {
            let (protocol_candidate, spends) =
                finalized_candidate.take().expect("candidate checked");
            self.install_spv_finalized_candidate(
                operation_id,
                &consignment,
                spends,
                protocol_candidate,
                &mut receipt,
            )?;
        } else {
            self.db.conn.execute(
                "UPDATE opencsv_operations SET receipt_json = ?2, updated_at = ?3
                 WHERE operation_id = ?1",
                params![operation_id, receipt.to_string(), unix_time()?],
            )?;
        }

        if verified && !installed_candidate {
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
        } else if !verified && matches!(
            operation.state.as_str(),
            "confirmed" | "consignment_delivered"
        ) {
            // Reorgs do not erase history. They demote settlement, freeze
            // descendants through the exact parent dependency, and require a
            // refreshed backup before any new write.
            let dependency_txid = txid.parse::<Txid>().map_err(|error| {
                AccountError::new("database_corrupt", format!("operation txid: {error}"))
            })?;
            self.freeze_unconfirmed_dependency(
                &unconfirmed_dependency_key(dependency_txid),
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

    fn spv_consignment_candidate(
        &self,
        operation_id: &str,
        operation: &OperationRow,
        txid: Txid,
        receipt: &Value,
    ) -> Result<(Vec<u8>, Option<(MemWallet, Vec<String>)>), AccountError> {
        if let Some(consignment_base64) = receipt["consignment_base64"].as_str() {
            let consignment = base64::engine::general_purpose::STANDARD
                .decode(consignment_base64)
                .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
            return Ok((consignment, None));
        }
        if !matches!(
            operation.state.as_str(),
            "signed_persisted" | "broadcast_unobserved"
        ) {
            return Err(AccountError::new(
                "operation_not_observed",
                "SPV settlement requires a consignment or resumable signed proof",
            ));
        }
        let pending_id = *self.pending_by_operation.get(operation_id).ok_or_else(|| {
            AccountError::new(
                "operation_not_resumable",
                "confirmed operation has no durable pending proof",
            )
        })?;
        let mut protocol_candidate = self.protocol.clone().ok_or_else(|| {
            AccountError::new("account_role_violation", "linked account cannot finalize")
        })?;
        let (consignment, spends) = protocol_candidate
            .finalize(
                pending_id,
                AnchorRef {
                    txid: txid.to_byte_array(),
                    location: MEMPOOL_LOCATION,
                },
            )
            .map_err(|error| AccountError::new("operation_not_resumable", error))?;
        Ok((consignment, Some((protocol_candidate, spends))))
    }

    fn install_spv_finalized_candidate(
        &mut self,
        operation_id: &str,
        consignment: &[u8],
        spends: Vec<String>,
        protocol_candidate: MemWallet,
        receipt: &mut Value,
    ) -> Result<(), AccountError> {
        let consignment_id = sha256::Hash::hash(consignment).to_string();
        let consignment_base64 = base64::engine::general_purpose::STANDARD.encode(consignment);
        if let Some(object) = receipt.as_object_mut() {
            object.insert("consignment_id".into(), json!(consignment_id));
            object.insert("consignment_base64".into(), json!(consignment_base64));
            object.insert("delivery_ready".into(), json!(true));
            object.remove("replacement_delivery_required");
        }
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
        transaction.execute(
            "UPDATE opencsv_operations SET state = ?2, receipt_json = ?3,
             rejection_reason = NULL, updated_at = ?4 WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::Confirmed.as_str(),
                receipt.to_string(),
                now,
            ],
        )?;
        transaction.commit()?;
        self.protocol = Some(protocol_candidate);
        self.pending_by_operation.remove(operation_id);
        Ok(())
    }

    /// Resume a crash-interrupted operation. Signed transactions are
    /// rebroadcast idempotently; earlier states are returned for the caller
    /// to continue with backup acknowledgement or signing.
    pub fn resume_operation(&mut self, operation_id: &str) -> Result<Value, AccountError> {
        let operation = self.operation(operation_id)?;
        if operation.kind == "mint" {
            self.require_issuance_write_enabled()?;
        }
        match operation.state.as_str() {
            "signed_persisted" | "broadcast_unobserved" => {
                let mut receipt: Value = operation
                    .receipt_json
                    .as_deref()
                    .and_then(|encoded| serde_json::from_str(encoded).ok())
                    .unwrap_or_else(|| json!({}));
                self.signed_fee_limit(&receipt, operation_id)?;
                let signed = operation.signed_tx_hex.as_deref().ok_or_else(|| {
                    AccountError::new("database_corrupt", "signed state has no transaction")
                })?;
                let tx: Transaction = deserialize(&hex_decode(signed, "signed transaction")?)
                    .map_err(|error| {
                        AccountError::new("database_corrupt", format!("signed tx: {error}"))
                    })?;
                if let Some(value) = self.reconcile_confirmed_replacement(
                    operation_id,
                    tx.compute_txid(),
                    &mut receipt,
                )? {
                    return Ok(value);
                }
                let (p2p_submissions, _) = self.submit_direct_p2p(&tx)?;
                let client = self.esplora_client();
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
                    "UPDATE opencsv_operations SET state = ?2,
                     rejection_reason = 'broadcast_unobserved',
                     receipt_json = ?3, updated_at = ?4
                     WHERE operation_id = ?1",
                    params![
                        operation_id,
                        OperationState::BroadcastUnobserved.as_str(),
                        receipt.to_string(),
                        unix_time()?
                    ],
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
        let client = self.esplora_client();
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
        let mut restored_consignment: Option<(String, String, String)> = None;
        let mut restored_delivery_nonce = None;
        if let Some(object) = receipt.as_object_mut() {
            if let Some(prior_delivery) = object.remove("pre_replacement_delivery") {
                let prior = prior_delivery.as_object().ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "pre-replacement delivery receipt is not an object",
                    )
                })?;
                let consignment_id = prior
                    .get("consignment_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "pre-replacement delivery has no consignment id",
                        )
                    })?
                    .to_owned();
                let consignment_base64 = prior
                    .get("consignment_base64")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "pre-replacement delivery has no consignment bytes",
                        )
                    })?
                    .to_owned();
                let spent_state_json = prior
                    .get("spent_state_json")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "pre-replacement delivery has no spent-state receipt",
                        )
                    })?
                    .to_owned();
                let delivery_nonce = prior
                    .get("delivery_nonce")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        AccountError::new(
                            "database_corrupt",
                            "pre-replacement delivery has no delivery nonce",
                        )
                    })?
                    .to_owned();
                validate_consignment_identity(&consignment_id, &consignment_base64)?;
                serde_json::from_str::<Value>(&spent_state_json).map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("pre-replacement spent state: {error}"),
                    )
                })?;
                object.insert("consignment_id".into(), json!(consignment_id));
                object.insert("consignment_base64".into(), json!(consignment_base64));
                object.insert("delivery_ready".into(), json!(true));
                if prior.get("consignment_delivered") == Some(&Value::Bool(true)) {
                    object.insert("consignment_delivered".into(), json!(true));
                    if let Some(delivered_at) = prior.get("consignment_delivered_at") {
                        object.insert("consignment_delivered_at".into(), delivered_at.clone());
                    }
                } else {
                    object.remove("consignment_delivered");
                    object.remove("consignment_delivered_at");
                }
                object.insert("delivery_nonce".into(), json!(delivery_nonce));
                if let Some(superseded) = object
                    .get_mut("superseded_consignment_ids")
                    .and_then(Value::as_array_mut)
                {
                    superseded.retain(|value| value.as_str() != Some(consignment_id.as_str()));
                }
                restored_consignment = Some((consignment_id, consignment_base64, spent_state_json));
                restored_delivery_nonce = Some(delivery_nonce);
            } else {
                // Legacy replacement receipts did not preserve the original
                // attachment. Return to a resumable state and let the SPV
                // path rebuild it from the durable pending proof.
                object.remove("consignment_id");
                object.remove("consignment_base64");
                object.remove("delivery_ready");
                object.remove("consignment_delivered");
                object.remove("consignment_delivered_at");
            }
            object.insert(
                "fee_bump_outcome".into(),
                json!("original_confirmed_before_replacement_observed"),
            );
            object.insert(
                "failed_replacement_txid".into(),
                json!(replacement_txid.to_string()),
            );
            object.insert("txid".into(), json!(replaced.to_string()));
            object.insert("explorer_confirmed".into(), json!(true));
            object.insert("requires_spv_confirmation".into(), json!(true));
            object.remove("replacement_delivery_required");
            object.remove("replaces");
        }
        let now = unix_time()?;
        let transaction = self.db.conn.transaction()?;
        if let Some((consignment_id, consignment_base64, spent_state_json)) = restored_consignment {
            transaction.execute(
                "INSERT OR REPLACE INTO opencsv_consignments(
                     consignment_id, consignment_base64, spent_state_json, created_at
                 ) VALUES(?1, ?2, ?3, ?4)",
                params![consignment_id, consignment_base64, spent_state_json, now],
            )?;
        }
        transaction.execute(
            "UPDATE opencsv_operations SET state = ?2, signed_tx_hex = ?3,
             txid = ?4, receipt_json = ?5, rejection_reason = NULL,
             delivery_nonce = COALESCE(?6, delivery_nonce), updated_at = ?7
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::BroadcastUnobserved.as_str(),
                original_hex,
                replaced.to_string(),
                receipt.to_string(),
                restored_delivery_nonce,
                now,
            ],
        )?;
        transaction.commit()?;
        let mut value = operation_json(&self.operation(operation_id)?)?;
        if let Some(object) = value.as_object_mut() {
            object.insert("confirmed".into(), json!(false));
            object.insert("explorer_confirmed".into(), json!(true));
            object.insert("requires_spv_confirmation".into(), json!(true));
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
            "signed_persisted"
                | "broadcast_unobserved"
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
        // A proof job executes outside the wallet lock. Clearing this lease
        // makes its eventual commit fail as stale; the immutable job may
        // finish computation but can no longer install or sign anything.
        if self.db.meta("active_proof_operation")?.as_deref() == Some(operation_id) {
            self.db.delete_meta("active_proof_operation")?;
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
        if operation.kind == "mint" {
            self.require_issuance_write_enabled()?;
        }
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
            keychain: None,
            derivation_index: None,
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
        // BDK otherwise derives a fresh anti-fee-sniping locktime from the
        // wallet's current tip. The tip can advance between the original
        // broadcast and an RBF attempt, but OpenCSV protects the original
        // version, locktime, and input prefix as protocol context.
        builder.nlocktime(original.lock_time);
        builder.set_exact_sequence(Sequence::ENABLE_RBF_NO_LOCKTIME);
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
        let replacement_output_sats =
            replacement.output.iter().try_fold(0u64, |total, output| {
                total.checked_add(output.value.to_sat()).ok_or_else(|| {
                    AccountError::new("database_corrupt", "replacement output value overflow")
                })
            })?;
        let replacement_fee_sats = funding
            .txout
            .value
            .to_sat()
            .checked_sub(replacement_output_sats)
            .ok_or_else(|| {
                AccountError::new(
                    "protocol_layout_violation",
                    "replacement outputs exceed the protected funding input",
                )
            })?;
        let mut receipt: Value = operation
            .receipt_json
            .as_deref()
            .and_then(|encoded| serde_json::from_str(encoded).ok())
            .unwrap_or_else(|| json!({}));
        if self
            .signed_fee_limit(&receipt, operation_id)?
            .is_some_and(|limit| replacement_fee_sats > limit)
        {
            return Err(AccountError::new(
                "fee_limit_exceeded",
                format!("{replacement_fee_sats} sats exceeds configured maximum"),
            ));
        }
        let receipt_object = receipt.as_object_mut().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation receipt is not an object")
        })?;
        receipt_object.insert("operation_id".into(), json!(operation_id));
        receipt_object.insert("replaces".into(), json!(original_txid.to_string()));
        receipt_object.insert("txid".into(), json!(replacement_txid.to_string()));
        receipt_object.insert("target_sat_per_vb".into(), json!(target_sat_per_vb));
        receipt_object.insert("fee_rate_sat_per_vb".into(), json!(target_sat_per_vb));
        receipt_object.insert("fee_sats".into(), json!(replacement_fee_sats));
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
        let client = self.esplora_client();
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
                                'funding_txid', funding_txid,
                                'funding_vout', funding_vout,
                                'funding_value_sats', funding_value_sats,
                                'signed_tx_hex', signed_tx_hex,
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
        let send_batches = {
            let mut statement = self.db.conn.prepare(
                "SELECT batch_local_id, state, deadline_ms, participant_count,
                        proposal_wire, manifest_wire, signed_tx_hex, txid,
                        receipt_json
                 FROM opencsv_send_batches
                 WHERE state != 'cancelled' ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([], |row| {
                let participant_count = row
                    .get::<_, Option<i64>>(3)?
                    .and_then(|value| u8::try_from(value).ok());
                let proposal_wire = row.get::<_, Option<Vec<u8>>>(4)?;
                let manifest_wire = row.get::<_, Option<Vec<u8>>>(5)?;
                Ok(BackupSendBatch {
                    batch_local_id: row.get(0)?,
                    state: row.get(1)?,
                    deadline_ms: row.get(2)?,
                    participant_count,
                    proposal_wire_base64: proposal_wire
                        .map(|wire| base64::engine::general_purpose::STANDARD.encode(wire)),
                    manifest_wire_base64: manifest_wire
                        .map(|wire| base64::engine::general_purpose::STANDARD.encode(wire)),
                    signed_tx_hex: row.get(6)?,
                    txid: row.get(7)?,
                    receipt_json: row.get(8)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let send_batch_members = {
            let mut statement = self.db.conn.prepare(
                "SELECT m.batch_local_id, m.operation_id, m.ordinal, m.added_at_ms,
                        m.change_spk_hex, m.commit_nonce_hex
                 FROM opencsv_send_batch_members m
                 JOIN opencsv_send_batches b USING(batch_local_id)
                 WHERE b.state != 'cancelled'
                 ORDER BY b.created_at, m.ordinal",
            )?;
            let rows = statement.query_map([], |row| {
                let ordinal = row.get::<_, i64>(2)?;
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    ordinal,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?;
            rows.map(|row| {
                let (
                    batch_local_id,
                    operation_id,
                    ordinal,
                    added_at_ms,
                    change_spk_hex,
                    commit_nonce_hex,
                ) = row?;
                Ok(BackupSendBatchMember {
                    batch_local_id,
                    operation_id,
                    ordinal: u8::try_from(ordinal).map_err(|_| {
                        AccountError::new("database_corrupt", "backup batch ordinal is outside u8")
                    })?,
                    added_at_ms,
                    change_spk_hex,
                    commit_nonce_hex,
                })
            })
            .collect::<Result<Vec<_>, AccountError>>()?
        };
        let batch_stocks = {
            let mut statement = self.db.conn.prepare(
                "SELECT participant_count, txid, vout, value_sats, birth_height,
                        state, reserved_by_batch, created_at
                 FROM opencsv_batch_stocks ORDER BY created_at, txid, vout",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?;
            rows.map(|row| {
                let (
                    participant_count,
                    txid,
                    vout,
                    value_sats,
                    birth_height,
                    state,
                    reserved_by_batch,
                    created_at,
                ) = row?;
                Ok(BackupBatchStock {
                    participant_count: u8::try_from(participant_count).map_err(|_| {
                        AccountError::new(
                            "database_corrupt",
                            "batch stock participant count is outside u8",
                        )
                    })?,
                    txid,
                    vout: u32::try_from(vout).map_err(|_| {
                        AccountError::new("database_corrupt", "batch stock vout is outside u32")
                    })?,
                    value_sats: u64::try_from(value_sats).map_err(|_| {
                        AccountError::new("database_corrupt", "batch stock value is negative")
                    })?,
                    birth_height: u64::try_from(birth_height).map_err(|_| {
                        AccountError::new(
                            "database_corrupt",
                            "batch stock birth height is negative",
                        )
                    })?,
                    state,
                    reserved_by_batch,
                    created_at,
                })
            })
            .collect::<Result<Vec<_>, AccountError>>()?
        };
        let batch_reserve_operations = {
            let mut statement = self.db.conn.prepare(
                "SELECT maintenance_id, state, participant_count, stock_count,
                        fee_cell_count, signed_tx_hex, txid, receipt_json,
                        created_at, updated_at
                 FROM opencsv_batch_reserve_operations ORDER BY created_at, rowid",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })?;
            rows.map(|row| {
                let (
                    maintenance_id,
                    state,
                    participant_count,
                    stock_count,
                    fee_cell_count,
                    signed_tx_hex,
                    txid,
                    receipt_json,
                    created_at,
                    updated_at,
                ) = row?;
                Ok(BackupBatchReserveOperation {
                    maintenance_id,
                    state,
                    participant_count: u8::try_from(participant_count).map_err(|_| {
                        AccountError::new(
                            "database_corrupt",
                            "reserve participant count is outside u8",
                        )
                    })?,
                    stock_count: u8::try_from(stock_count).map_err(|_| {
                        AccountError::new("database_corrupt", "reserve stock count is outside u8")
                    })?,
                    fee_cell_count: u16::try_from(fee_cell_count).map_err(|_| {
                        AccountError::new(
                            "database_corrupt",
                            "reserve fee-cell count is outside u16",
                        )
                    })?,
                    signed_tx_hex,
                    txid,
                    receipt_json,
                    created_at,
                    updated_at,
                })
            })
            .collect::<Result<Vec<_>, AccountError>>()?
        };
        let owners = self
            .protocol
            .as_ref()
            .map(MemWallet::owners)
            .or_else(|| self.config.watch_owner.clone().map(|owner| vec![owner]))
            .unwrap_or_default();
        let payload = json!({
            "version": CHECKPOINT_VERSION,
            "deployment_id": self.config.deployment_id,
            "key_derivation_id": account_key_derivation_id(&self.config.network),
            "production_usd_registry_floor": read_production_usd_registry_floor(&self.db)?,
            "network": self.config.network,
            "root_fingerprint": self.root_fingerprint,
            "device_binding_commitment": self.device_binding_commitment,
            "owners": owners,
            "assets": assets,
            "instrument_manifests": instrument_manifests,
            "operations": operations,
            "consignments": consignments,
            "send_batches": send_batches,
            "send_batch_members": send_batch_members,
            "batch_stocks": batch_stocks,
            "batch_reserve_operations": batch_reserve_operations,
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
        if matches!(
            envelope.checkpoint.version,
            LEGACY_CHECKPOINT_VERSION | BATCH_CHECKPOINT_VERSION | PRE_RESET_CHECKPOINT_VERSION
        ) {
            return Err(deployment_reset_error(
                &self.config.network,
                "legacy Secure Backup checkpoints are archived and cannot restore into this deployment",
            ));
        }
        if envelope.checkpoint.version != CHECKPOINT_VERSION {
            return Err(AccountError::new(
                "backup_version_mismatch",
                format!("expected checkpoint version {CHECKPOINT_VERSION}"),
            ));
        }
        if envelope.checkpoint.deployment_id.as_deref() != Some(self.config.deployment_id.as_str())
        {
            return Err(deployment_reset_error(
                &self.config.network,
                "Secure Backup checkpoint belongs to another OpenCSV deployment",
            ));
        }
        if envelope.checkpoint.network != self.config.network {
            return Err(AccountError::new(
                "backup_network_mismatch",
                "Secure Backup checkpoint belongs to another Bitcoin network",
            ));
        }
        let expected_key_derivation_id = account_key_derivation_id(&self.config.network);
        match envelope.checkpoint.key_derivation_id.as_deref() {
            Some(actual) if actual != expected_key_derivation_id => {
                return Err(deployment_reset_error(
                    &self.config.network,
                    "Secure Backup checkpoint belongs to another account-key derivation namespace",
                ));
            }
            None if self.config.network == "mainnet" => {
                return Err(deployment_reset_error(
                    &self.config.network,
                    "pre-v1 mainnet key derivation is archived; create a fresh production wallet",
                ));
            }
            Some(_) | None => {}
        }
        let checkpoint_registry_floor_update = production_usd_registry_floor_from_checkpoint(
            &self.config.network,
            &self.db,
            envelope
                .checkpoint
                .production_usd_registry_floor
                .as_ref(),
        )?;
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
        if let Some(existing) = self.db.meta("restored_checkpoint_source_hash")? {
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
                  + (SELECT COUNT(*) FROM opencsv_consignments)
                  + (SELECT COUNT(*) FROM opencsv_send_batches)
                  + (SELECT COUNT(*) FROM opencsv_send_batch_members)
                  + (SELECT COUNT(*) FROM opencsv_batch_stocks)
                  + (SELECT COUNT(*) FROM opencsv_batch_reserve_operations)",
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
                    | "protocol_rejected"
                    | "rejected"
                    | "cancelled"
            ) {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("unknown operation state {}", operation.state),
                ));
            }
            let funding_fields = [
                operation.funding_txid.is_some(),
                operation.funding_vout.is_some(),
                operation.funding_value_sats.is_some(),
            ];
            if funding_fields.iter().any(|present| *present)
                && !funding_fields.iter().all(|present| *present)
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    format!(
                        "operation {} has an incomplete fee reservation",
                        operation.operation_id
                    ),
                ));
            }
            if let Some(txid) = operation.funding_txid.as_deref() {
                Txid::from_str(txid).map_err(|error| {
                    AccountError::new(
                        "invalid_backup_checkpoint",
                        format!("operation funding txid: {error}"),
                    )
                })?;
            }
            if let Some(encoded) = operation.signed_tx_hex.as_deref() {
                let transaction: Transaction =
                    deserialize(&hex_decode(encoded, "backup operation signed transaction")?)
                        .map_err(|error| {
                            AccountError::new(
                                "invalid_backup_checkpoint",
                                format!("operation signed transaction: {error}"),
                            )
                        })?;
                let computed_txid = transaction.compute_txid().to_string();
                if operation.txid.as_deref() != Some(computed_txid.as_str()) {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        format!(
                            "operation {} txid does not match its signed bytes",
                            operation.operation_id
                        ),
                    ));
                }
            }
        }
        let operation_ids: HashSet<&str> = envelope
            .checkpoint
            .operations
            .iter()
            .map(|operation| operation.operation_id.as_str())
            .collect();
        let batch_ids: HashSet<&str> = envelope
            .checkpoint
            .send_batches
            .iter()
            .map(|batch| batch.batch_local_id.as_str())
            .collect();
        if batch_ids.len() != envelope.checkpoint.send_batches.len() {
            return Err(AccountError::new(
                "invalid_backup_checkpoint",
                "send batch ids are not unique",
            ));
        }
        if envelope
            .checkpoint
            .send_batches
            .iter()
            .filter(|batch| batch.state == "collecting")
            .count()
            > 1
        {
            return Err(AccountError::new(
                "invalid_backup_checkpoint",
                "more than one send batch is collecting",
            ));
        }
        for batch in &envelope.checkpoint.send_batches {
            if !matches!(
                batch.state.as_str(),
                "collecting"
                    | "solo"
                    | "frozen"
                    | "proof_ready"
                    | "signed_persisted"
                    | "broadcast_unobserved"
                    | "mempool"
                    | "confirmed"
            ) {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("unknown send batch state {}", batch.state),
                ));
            }
            for encoded in [
                batch.proposal_wire_base64.as_deref(),
                batch.manifest_wire_base64.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|error| {
                        AccountError::new(
                            "invalid_backup_checkpoint",
                            format!("send batch wire bytes: {error}"),
                        )
                    })?;
            }
            if let Some(signed_tx_hex) = batch.signed_tx_hex.as_deref() {
                let transaction: Transaction = deserialize(&hex_decode(
                    signed_tx_hex,
                    "backup batch signed transaction",
                )?)
                .map_err(|error| {
                    AccountError::new(
                        "invalid_backup_checkpoint",
                        format!("batch signed transaction: {error}"),
                    )
                })?;
                let computed_txid = transaction.compute_txid().to_string();
                if batch.txid.as_deref() != Some(computed_txid.as_str()) {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        "batch txid does not match its signed bytes",
                    ));
                }
            }
        }
        let mut stock_outpoints = HashSet::new();
        let mut reserved_batches = HashSet::new();
        for stock in &envelope.checkpoint.batch_stocks {
            Txid::from_str(&stock.txid).map_err(|error| {
                AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("batch stock txid: {error}"),
                )
            })?;
            if stock.participant_count == 0
                || usize::from(stock.participant_count) > MAX_LOCAL_BATCH_RECIPIENTS
                || !matches!(
                    stock.state.as_str(),
                    "pending"
                        | "available"
                        | "reserved"
                        | "signature_released"
                        | "confirmed"
                        | "invalidated"
                )
                || !stock_outpoints.insert((stock.txid.as_str(), stock.vout))
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "invalid or duplicate batch stock",
                ));
            }
            if let Some(batch_id) = stock.reserved_by_batch.as_deref() {
                if !batch_ids.contains(batch_id) || !reserved_batches.insert(batch_id) {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        "batch stock names an unavailable or duplicate reservation",
                    ));
                }
                if !matches!(stock.state.as_str(), "reserved" | "signature_released") {
                    return Err(AccountError::new(
                        "invalid_backup_checkpoint",
                        "reserved batch stock has an incompatible state",
                    ));
                }
            }
        }
        let mut maintenance_ids = HashSet::new();
        let mut maintenance_txids = HashSet::new();
        for reserve in &envelope.checkpoint.batch_reserve_operations {
            if reserve.participant_count == 0
                || usize::from(reserve.participant_count) > MAX_LOCAL_BATCH_RECIPIENTS
                || reserve.stock_count == 0
                || reserve.fee_cell_count == 0
                || !matches!(
                    reserve.state.as_str(),
                    "signed_persisted"
                        | "broadcast_unobserved"
                        | "mempool"
                        | "confirmed"
                        | "failed"
                )
                || !maintenance_ids.insert(reserve.maintenance_id.as_str())
                || !maintenance_txids.insert(reserve.txid.as_str())
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "invalid or duplicate batch reserve maintenance operation",
                ));
            }
            let transaction: Transaction = deserialize(&hex_decode(
                &reserve.signed_tx_hex,
                "backup reserve transaction",
            )?)
            .map_err(|error| {
                AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("batch reserve transaction: {error}"),
                )
            })?;
            if transaction.compute_txid().to_string() != reserve.txid {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "batch reserve txid does not match its signed bytes",
                ));
            }
            serde_json::from_str::<Value>(&reserve.receipt_json).map_err(|error| {
                AccountError::new(
                    "invalid_backup_checkpoint",
                    format!("batch reserve receipt: {error}"),
                )
            })?;
        }
        let mut member_keys = HashSet::new();
        let mut member_operations = HashSet::new();
        for member in &envelope.checkpoint.send_batch_members {
            if !batch_ids.contains(member.batch_local_id.as_str())
                || !operation_ids.contains(member.operation_id.as_str())
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "send batch member names an unavailable batch or operation",
                ));
            }
            if !member_keys.insert((member.batch_local_id.as_str(), member.ordinal))
                || !member_operations.insert(member.operation_id.as_str())
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "send batch membership is duplicated",
                ));
            }
        }
        for batch in &envelope.checkpoint.send_batches {
            let count = envelope
                .checkpoint
                .send_batch_members
                .iter()
                .filter(|member| member.batch_local_id == batch.batch_local_id)
                .count();
            if count == 0
                || batch
                    .participant_count
                    .is_some_and(|expected| usize::from(expected) != count)
            {
                return Err(AccountError::new(
                    "invalid_backup_checkpoint",
                    "send batch participant count does not match its members",
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
                let funding_value_sats = operation
                    .funding_value_sats
                    .map(i64::try_from)
                    .transpose()
                    .map_err(|_| {
                        AccountError::new(
                            "invalid_backup_checkpoint",
                            "operation fee value exceeds SQLite i64",
                        )
                    })?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_operations(
                         operation_id, kind, state, request_json,
                         funding_txid, funding_vout, funding_value_sats,
                         pending_json, signed_tx_hex, txid, receipt_json,
                         rejection_reason, delivery_nonce, checkpoint_hash,
                         backup_acked, created_at, updated_at
                     ) VALUES(
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                         ?12, ?13, ?14, ?15, ?16, ?16
                     )",
                    params![
                        operation.operation_id,
                        operation.kind,
                        operation.state,
                        operation.request.to_string(),
                        operation.funding_txid,
                        operation.funding_vout,
                        funding_value_sats,
                        operation.pending_json,
                        operation.signed_tx_hex,
                        operation.txid,
                        operation.receipt_json,
                        operation.rejection_reason,
                        operation.delivery_nonce,
                        operation.checkpoint_hash,
                        operation.backup_acked,
                        now,
                    ],
                )?;
                if let (Some(txid), Some(vout)) = (&operation.funding_txid, operation.funding_vout)
                {
                    let reservation_state = if matches!(
                        operation.state.as_str(),
                        "signed_persisted"
                            | "broadcast_unobserved"
                            | "broadcast"
                            | "mempool"
                            | "confirmed"
                            | "consignment_delivered"
                    ) {
                        "signature_released"
                    } else {
                        "reserved"
                    };
                    self.db.conn.execute(
                        "INSERT INTO opencsv_utxo_reservations(
                             txid, vout, operation_id, state, created_at
                         ) VALUES(?1, ?2, ?3, ?4, ?5)",
                        params![txid, vout, operation.operation_id, reservation_state, now,],
                    )?;
                }
            }
            for batch in &envelope.checkpoint.send_batches {
                let proposal_wire = batch
                    .proposal_wire_base64
                    .as_deref()
                    .map(|encoded| {
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .map_err(|error| {
                                AccountError::new(
                                    "invalid_backup_checkpoint",
                                    format!("batch proposal bytes: {error}"),
                                )
                            })
                    })
                    .transpose()?;
                let manifest_wire = batch
                    .manifest_wire_base64
                    .as_deref()
                    .map(|encoded| {
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded)
                            .map_err(|error| {
                                AccountError::new(
                                    "invalid_backup_checkpoint",
                                    format!("batch manifest bytes: {error}"),
                                )
                            })
                    })
                    .transpose()?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_send_batches(
                         batch_local_id, state, deadline_ms, participant_count,
                         proposal_wire, manifest_wire, signed_tx_hex, txid,
                         receipt_json, checkpoint_hash, backup_acked,
                         created_at, updated_at
                     ) VALUES(
                         ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                         NULL, 0, ?10, ?10
                     )",
                    params![
                        batch.batch_local_id,
                        batch.state,
                        batch.deadline_ms,
                        batch.participant_count,
                        proposal_wire,
                        manifest_wire,
                        batch.signed_tx_hex,
                        batch.txid,
                        batch.receipt_json,
                        now,
                    ],
                )?;
            }
            for member in &envelope.checkpoint.send_batch_members {
                self.db.conn.execute(
                    "INSERT INTO opencsv_send_batch_members(
                         batch_local_id, operation_id, ordinal, added_at_ms,
                         change_spk_hex, commit_nonce_hex
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        member.batch_local_id,
                        member.operation_id,
                        member.ordinal,
                        member.added_at_ms,
                        member.change_spk_hex,
                        member.commit_nonce_hex,
                    ],
                )?;
            }
            for stock in &envelope.checkpoint.batch_stocks {
                let value_sats = i64::try_from(stock.value_sats).map_err(|_| {
                    AccountError::new(
                        "invalid_backup_checkpoint",
                        "batch stock value exceeds SQLite i64",
                    )
                })?;
                let birth_height = i64::try_from(stock.birth_height).map_err(|_| {
                    AccountError::new(
                        "invalid_backup_checkpoint",
                        "batch stock height exceeds SQLite i64",
                    )
                })?;
                self.db.conn.execute(
                    "INSERT INTO opencsv_batch_stocks(
                         participant_count, txid, vout, value_sats,
                         birth_height, state, reserved_by_batch, created_at
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        stock.participant_count,
                        stock.txid,
                        stock.vout,
                        value_sats,
                        birth_height,
                        stock.state,
                        stock.reserved_by_batch,
                        stock.created_at,
                    ],
                )?;
            }
            for reserve in &envelope.checkpoint.batch_reserve_operations {
                self.db.conn.execute(
                    "INSERT INTO opencsv_batch_reserve_operations(
                         maintenance_id, state, participant_count, stock_count,
                         fee_cell_count, signed_tx_hex, txid, receipt_json,
                         created_at, updated_at
                     ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        reserve.maintenance_id,
                        reserve.state,
                        reserve.participant_count,
                        reserve.stock_count,
                        reserve.fee_cell_count,
                        reserve.signed_tx_hex,
                        reserve.txid,
                        reserve.receipt_json,
                        reserve.created_at,
                        reserve.updated_at,
                    ],
                )?;
            }
            if let Some(collecting) = envelope
                .checkpoint
                .send_batches
                .iter()
                .find(|batch| batch.state == "collecting")
            {
                self.db.conn.execute(
                    "INSERT INTO opencsv_account_meta(key, value)
                     VALUES('active_send_batch', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [&collecting.batch_local_id],
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
            self.db
                .set_meta("restored_checkpoint_source_hash", &actual_hash)?;
            if let Some(floor) = checkpoint_registry_floor_update.as_ref() {
                write_production_usd_registry_floor(&mut self.db, floor)?;
            }
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
        self.production_usd_registry_state =
            reconcile_production_usd_registry_floor(&mut self.db, &mut self.config)?;
        // The compact checkpoint intentionally omits rebuildable BDK chain
        // history, but its durable protocol proofs and fee reservations are
        // live state. Reinstall them immediately so the first post-restore
        // process is as safe as every later reopen.
        self.restore_fee_reservations()?;
        self.restore_pending_operations()?;
        // Re-export the exact v2 deployment checkpoint before the DEBUG
        // rebind compares hashes or a new Secure Backup is required.
        let normalized = self.checkpoint()?;
        let normalized_hash = normalized["checkpoint_hash"].as_str().ok_or_else(|| {
            AccountError::new("checkpoint_failed", "normalized checkpoint has no hash")
        })?;
        self.db
            .set_meta("restored_checkpoint_hash", normalized_hash)?;
        self.status()
    }

    fn require_write_enabled(&self) -> Result<(), AccountError> {
        if let Some(reason) = self.base_write_block_reason()? {
            return Err(write_block_error(reason));
        }
        Ok(())
    }

    /// Gate creation and signing of new consumer operations. Exact persisted
    /// transactions may still be resumed, and protocol-safe fee bumps may
    /// still recover an already signed operation after an issuer is removed.
    /// A fresh mainnet Bitcoin write, however, is meaningless until the host
    /// supplies at least one fully validated production USD manifest.
    fn require_product_write_enabled(&self) -> Result<(), AccountError> {
        self.require_write_enabled()?;
        if let Some(reason) = self.production_usd_registry_state.write_block_reason() {
            return Err(write_block_error(reason));
        }
        if !self.production_usd_configured() {
            return Err(write_block_error("production_usd_not_configured"));
        }
        if !self.production_activation_write_ready() {
            return Err(write_block_error("production_activation_not_authorized"));
        }
        if !self.production_observation_policy_ready() {
            return Err(write_block_error("production_observation_policy_required"));
        }
        Ok(())
    }

    /// Issuer tooling is intentionally a separate feature and custody
    /// boundary, but a structurally valid registry file is not an
    /// independently authenticated authorization to expand production
    /// supply. Until the production issuer/key ceremony defines that
    /// authorization and its supply envelope, mainnet manifest construction
    /// remains available for review while every fresh mint fails closed.
    fn require_issuance_write_enabled(&self) -> Result<(), AccountError> {
        self.require_write_enabled()?;
        if self.config.network == "mainnet" {
            return Err(write_block_error("production_issuance_not_authorized"));
        }
        Ok(())
    }

    fn base_write_block_reason(&self) -> Result<Option<&'static str>, AccountError> {
        if self.config.role != AccountRole::Primary {
            return Ok(Some("primary_required"));
        }
        if !self.device_binding_valid {
            return Ok(Some("device_binding_mismatch"));
        }
        if !self.backup_verified()? {
            return Ok(Some("backup_required"));
        }
        Ok(None)
    }

    fn production_usd_configured(&self) -> bool {
        self.config.network != "mainnet"
            || (self.production_usd_registry_state == ProductionUsdRegistryState::Current
                && self.config.production_usd_registry.is_some()
                && !self.config.usd_issuers.is_empty())
    }

    fn production_activation_write_ready(&self) -> bool {
        self.config.network != "mainnet"
            || self
                .config
                .production_usd_registry
                .as_ref()
                .is_some_and(|registry| {
                    matches!(
                        registry.rollout.phase,
                        ProductionActivationPhase::Limited | ProductionActivationPhase::General
                    )
                })
    }

    /// Production may use the immutable built-ins or independently hosted
    /// replacements, but it must not turn a configurable observation policy
    /// into a silent safety downgrade. Two distinct pinned raw endpoints must
    /// fail closed, direct Bitcoin relay must remain visible, and confirmed
    /// chain verification must remain enabled before a fresh mainnet write.
    fn production_observation_policy_ready(&self) -> bool {
        if self.config.network != "mainnet" {
            return true;
        }
        let required_raw_hosts = self
            .config
            .observation_checks
            .iter()
            .filter(|check| {
                check.kind == ObservationKind::RawTransactionApi
                    && check.mode == ObservationMode::Require
                    && !check.chain_fingerprints_sha256.is_empty()
            })
            .filter_map(|check| {
                let endpoint = Url::parse(check.endpoint.as_deref()?).ok()?;
                endpoint.host_str().map(str::to_ascii_lowercase)
            })
            .collect::<HashSet<_>>();
        let direct_relay_enabled = self.config.observation_checks.iter().any(|check| {
            check.kind == ObservationKind::DirectP2pRelay
                && check.mode != ObservationMode::Off
        });
        let confirmed_spv_enabled = self.config.observation_checks.iter().any(|check| {
            check.kind == ObservationKind::ConfirmedSpv && check.mode != ObservationMode::Off
        });
        let verification_peers = if self.config.verification_peers.is_empty() {
            &self.config.peers
        } else {
            &self.config.verification_peers
        };
        let independent_verification_peers = verification_peers.iter().collect::<HashSet<_>>();
        required_raw_hosts.len() >= 2
            && direct_relay_enabled
            && confirmed_spv_enabled
            && independent_verification_peers.len() >= 2
    }

    fn write_block_reason(&self) -> Result<Option<&'static str>, AccountError> {
        if let Some(reason) = self.base_write_block_reason()? {
            return Ok(Some(reason));
        }
        if let Some(reason) = self.production_usd_registry_state.write_block_reason() {
            return Ok(Some(reason));
        }
        if !self.production_usd_configured() {
            return Ok(Some("production_usd_not_configured"));
        }
        if !self.production_activation_write_ready() {
            return Ok(Some("production_activation_not_authorized"));
        }
        if !self.production_observation_policy_ready() {
            return Ok(Some("production_observation_policy_required"));
        }
        Ok(None)
    }

    /// Require the exact asset identity to be present in the reviewed USD
    /// registry supplied by Signal. A ticker, received manifest, or prior
    /// balance never grants spend authority by itself.
    fn is_reviewed_usd_asset(&self, asset_id: &str) -> bool {
        let Ok(requested) = decode_hex_32(asset_id, "asset id") else {
            return false;
        };
        self.config
            .usd_issuers
            .iter()
            .any(|issuer| issuer.manifest.genesis.asset_id().as_bytes() == &requested)
    }

    fn require_reviewed_usd_asset(&self, asset_id: &str) -> Result<(), AccountError> {
        if self.is_reviewed_usd_asset(asset_id) {
            return Ok(());
        }
        Err(AccountError::new(
            "asset_not_reviewed",
            "the exact asset is not in Signal's reviewed USD issuer registry",
        ))
    }

    fn production_rollout_policy(&self) -> Option<&ProductionRolloutPolicy> {
        (self.config.network == "mainnet")
            .then(|| {
                self.config
                    .production_usd_registry
                    .as_ref()
                    .map(|registry| &registry.rollout)
            })
            .flatten()
    }

    fn effective_fee_limit(&self, per_call: Option<u64>) -> Option<u64> {
        match (per_call, self.config.max_fee_sats) {
            (Some(per_call), Some(account)) => Some(per_call.min(account)),
            (Some(per_call), None) => Some(per_call),
            (None, Some(account)) => Some(account),
            (None, None) => None,
        }
    }

    fn production_authorization_secret(&self) -> Result<SecretKey, AccountError> {
        let fee_seed = self.bitcoin_fee_seed.as_ref().ok_or_else(|| {
            AccountError::new(
                "database_corrupt",
                "production authorization needs the primary Bitcoin fee seed",
            )
        })?;
        let derived = Zeroizing::new(derive::<32>(
            fee_seed.as_ref(),
            b"production-rollout-authorization-v1",
            self.config.deployment_id.as_bytes(),
        )?);
        SecretKey::from_slice(derived.as_ref()).map_err(|_| {
            AccountError::new(
                "key_derivation_failed",
                "derived production authorization key is not a valid secp256k1 scalar",
            )
        })
    }

    fn stamp_production_rollout_authorization(
        &self,
        receipt: &mut Value,
        operation_identity: &str,
    ) -> Result<(), AccountError> {
        let Some(release) = (self.config.network == "mainnet")
            .then(|| self.config.production_usd_registry.as_ref())
            .flatten()
        else {
            return Ok(());
        };
        let digest = production_rollout_authorization_digest(
            &self.config.deployment_id,
            operation_identity,
            &release.commitment_sha256,
        )?;
        let signature = Secp256k1::new().sign_ecdsa(
            &Message::from_digest(digest),
            &self.production_authorization_secret()?,
        );
        receipt["production_rollout_authorization"] = json!({
            "release": release,
            "operation_identity": operation_identity,
            "signature_compact": hex_encode(&signature.serialize_compact()),
        });
        Ok(())
    }

    fn signed_fee_limit(
        &self,
        receipt: &Value,
        expected_operation_identity: &str,
    ) -> Result<Option<u64>, AccountError> {
        let Some(authorization) = receipt.get("production_rollout_authorization") else {
            if self.config.network == "mainnet" {
                return Err(AccountError::new(
                    "database_corrupt",
                    "signed production operation has no rollout authorization snapshot",
                ));
            }
            return Ok(self.config.max_fee_sats);
        };
        let release = serde_json::from_value::<ProductionUsdRegistryRelease>(
            authorization["release"].clone(),
        )
        .map_err(|error| {
            AccountError::new(
                "database_corrupt",
                format!("signed production rollout authorization: {error}"),
            )
        })?;
        if self.config.network != "mainnet"
            || release.format_version != PRODUCTION_USD_REGISTRY_FORMAT_VERSION
            || release.registry_version == 0
            || release.deployment_id != self.config.deployment_id
        {
            return Err(AccountError::new(
                "database_corrupt",
                "signed production rollout authorization has the wrong deployment identity",
            ));
        }
        validate_production_rollout_policy(&release.rollout)?;
        if production_usd_registry_commitment(&release)? != release.commitment_sha256 {
            return Err(AccountError::new(
                "database_corrupt",
                "signed production rollout authorization commitment does not match its release",
            ));
        }
        if authorization["operation_identity"].as_str() != Some(expected_operation_identity) {
            return Err(AccountError::new(
                "database_corrupt",
                "signed production rollout authorization belongs to another operation",
            ));
        }
        let signature_bytes = hex_decode(
            authorization["signature_compact"]
                .as_str()
                .ok_or_else(|| {
                    AccountError::new(
                        "database_corrupt",
                        "signed production rollout authorization has no signature",
                    )
                })?,
            "production rollout authorization signature",
        )?;
        let signature = EcdsaSignature::from_compact(&signature_bytes).map_err(|_| {
            AccountError::new(
                "database_corrupt",
                "signed production rollout authorization signature is malformed",
            )
        })?;
        let digest = production_rollout_authorization_digest(
            &self.config.deployment_id,
            expected_operation_identity,
            &release.commitment_sha256,
        )?;
        let secp = Secp256k1::new();
        let public_key =
            PublicKey::from_secret_key(&secp, &self.production_authorization_secret()?);
        secp.verify_ecdsa(&Message::from_digest(digest), &signature, &public_key)
            .map_err(|_| {
                AccountError::new(
                    "database_corrupt",
                    "signed production rollout authorization signature does not verify",
                )
            })?;
        Ok(Some(release.rollout.max_miner_fee_sats))
    }

    fn require_production_transfer_amount(
        &self,
        request: &TransferRequest,
    ) -> Result<(), AccountError> {
        let Some(policy) = self.production_rollout_policy() else {
            return Ok(());
        };
        if request.amount > policy.max_transfer_base_units {
            return Err(AccountError::new(
                "production_value_limit_exceeded",
                format!(
                    "{} base units exceeds the per-transfer production limit of {}",
                    request.amount, policy.max_transfer_base_units
                ),
            ));
        }
        Ok(())
    }

    fn production_rolling_transfer_usage(&self) -> Result<(u64, u64), AccountError> {
        let cutoff = unix_time()?.saturating_sub(24 * 60 * 60);
        let mut statement = self.db.conn.prepare(
            "SELECT request_json FROM opencsv_operations
             WHERE kind = 'transfer' AND created_at >= ?1
               AND state NOT IN ('cancelled', 'protocol_rejected')",
        )?;
        let rows = statement.query_map([cutoff], |row| row.get::<_, String>(0))?;
        let mut count = 0_u64;
        let mut amount = 0_u64;
        for row in rows {
            let request = serde_json::from_str::<TransferRequest>(&row?).map_err(|error| {
                AccountError::new(
                    "database_corrupt",
                    format!("rolling transfer request: {error}"),
                )
            })?;
            count = count.checked_add(1).ok_or_else(|| {
                AccountError::new("database_corrupt", "rolling operation count overflow")
            })?;
            amount = amount.checked_add(request.amount).ok_or_else(|| {
                AccountError::new("database_corrupt", "rolling transfer amount overflow")
            })?;
        }
        Ok((count, amount))
    }

    fn require_production_existing_transfer_policy(
        &self,
        request: &TransferRequest,
    ) -> Result<(), AccountError> {
        self.require_production_transfer_amount(request)?;
        let Some(policy) = self.production_rollout_policy() else {
            return Ok(());
        };
        let (count, amount) = self.production_rolling_transfer_usage()?;
        if count > u64::from(policy.max_rolling_24h_operations) {
            return Err(AccountError::new(
                "production_operation_limit_exceeded",
                "active/completed rolling-day operation count exceeds current production policy",
            ));
        }
        if amount > policy.max_rolling_24h_outgoing_base_units {
            return Err(AccountError::new(
                "production_value_limit_exceeded",
                "active/completed rolling-day outgoing amount exceeds current production policy",
            ));
        }
        Ok(())
    }

    fn require_production_new_transfer_policy(
        &self,
        request: &TransferRequest,
    ) -> Result<(), AccountError> {
        self.require_production_transfer_amount(request)?;
        let Some(policy) = self.production_rollout_policy() else {
            return Ok(());
        };
        let (count, amount) = self.production_rolling_transfer_usage()?;
        if count
            .checked_add(1)
            .is_none_or(|next| next > u64::from(policy.max_rolling_24h_operations))
        {
            return Err(AccountError::new(
                "production_operation_limit_exceeded",
                "new transfer would exceed the rolling-day production operation limit",
            ));
        }
        if amount
            .checked_add(request.amount)
            .is_none_or(|next| next > policy.max_rolling_24h_outgoing_base_units)
        {
            return Err(AccountError::new(
                "production_value_limit_exceeded",
                "new transfer would exceed the rolling-day production value limit",
            ));
        }
        Ok(())
    }

    fn require_production_batch_policy(
        &self,
        requests: &[TransferRequest],
    ) -> Result<(), AccountError> {
        let Some(policy) = self.production_rollout_policy() else {
            return Ok(());
        };
        if requests.len() > usize::from(policy.max_batch_recipients) {
            return Err(AccountError::new(
                "production_batch_limit_exceeded",
                format!(
                    "{} recipients exceeds the production batch limit of {}",
                    requests.len(),
                    policy.max_batch_recipients
                ),
            ));
        }
        let total = requests.iter().try_fold(0_u64, |sum, request| {
            sum.checked_add(request.amount).ok_or_else(|| {
                AccountError::new("production_value_limit_exceeded", "batch amount overflow")
            })
        })?;
        if total > policy.max_batch_total_base_units {
            return Err(AccountError::new(
                "production_value_limit_exceeded",
                format!(
                    "{total} base units exceeds the production batch limit of {}",
                    policy.max_batch_total_base_units
                ),
            ));
        }
        Ok(())
    }

    fn transfer_requests_for_batch_members(
        &self,
        members: &[SendBatchMember],
    ) -> Result<Vec<TransferRequest>, AccountError> {
        members
            .iter()
            .map(|member| {
                let operation = self.operation(&member.operation_id)?;
                serde_json::from_str::<TransferRequest>(&operation.request_json).map_err(|error| {
                    AccountError::new("database_corrupt", format!("transfer request: {error}"))
                })
            })
            .collect()
    }

    fn require_reviewed_transfer(&self, request: &TransferRequest) -> Result<(), AccountError> {
        self.require_reviewed_usd_asset(&request.asset_id)?;
        self.require_production_existing_transfer_policy(request)
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

    fn batch_stock_secret(&self) -> Result<SecretKey, AccountError> {
        let bytes = self.batch_stock_secret.as_ref().ok_or_else(|| {
            AccountError::new("primary_required", "linked devices have no batch stock key")
        })?;
        SecretKey::from_slice(bytes.as_ref()).map_err(|_| {
            AccountError::new("key_derivation_failed", "invalid derived batch stock key")
        })
    }

    fn batch_fee_secret(&self, funding: &ReservedFunding) -> Result<SecretKey, AccountError> {
        let seed = self.bitcoin_fee_seed.as_ref().ok_or_else(|| {
            AccountError::new(
                "primary_required",
                "linked devices have no Bitcoin fee keys",
            )
        })?;
        let keychain = funding.keychain.ok_or_else(|| {
            AccountError::new(
                "database_corrupt",
                "reserved batch fee input has no descriptor keychain",
            )
        })?;
        let index = funding.derivation_index.ok_or_else(|| {
            AccountError::new(
                "database_corrupt",
                "reserved batch fee input has no derivation index",
            )
        })?;
        let network = parse_network(&self.config.network)?;
        let coin_type = if network == Network::Bitcoin { 0 } else { 1 };
        let branch = match keychain {
            KeychainKind::External => 0,
            KeychainKind::Internal => 1,
        };
        let path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84)
                .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))?,
            ChildNumber::from_hardened_idx(coin_type)
                .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))?,
            ChildNumber::from_hardened_idx(0)
                .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))?,
            ChildNumber::from_normal_idx(branch)
                .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))?,
        ]);
        Xpriv::new_master(network, seed.as_ref())
            .and_then(|master| master.derive_priv(&Secp256k1::new(), &path))
            .map(|derived| derived.private_key)
            .map_err(|error| AccountError::new("key_derivation_failed", error.to_string()))
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

    fn reserve_batch_stock(
        &mut self,
        batch_local_id: &str,
        participant_count: u8,
    ) -> Result<BatchStock, AccountError> {
        if let Some(stock) = self.batch_stock_reserved_by(batch_local_id)? {
            if stock.participant_count != participant_count {
                return Err(AccountError::new(
                    "conflicting_operation",
                    "batch already reserves stock for another participant count",
                ));
            }
            return Ok(stock);
        }
        let transaction = self
            .db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let candidate = transaction
            .query_row(
                "SELECT txid, vout, value_sats, birth_height
                 FROM opencsv_batch_stocks
                 WHERE participant_count = ?1 AND state = 'available'
                 ORDER BY birth_height, created_at, txid, vout LIMIT 1",
                [participant_count],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((txid, vout, value_sats, birth_height)) = candidate else {
            return Err(AccountError::new(
                "batch_reserve_required",
                format!(
                    "no confirmed count-{participant_count} batching stock is available; wallet reserve maintenance must prepare one"
                ),
            ));
        };
        let updated = transaction.execute(
            "UPDATE opencsv_batch_stocks
             SET state = 'reserved', reserved_by_batch = ?3
             WHERE txid = ?1 AND vout = ?2 AND state = 'available'",
            params![txid, vout, batch_local_id],
        )?;
        if updated != 1 {
            return Err(AccountError::new(
                "conflicting_operation",
                "batch stock was concurrently reserved",
            ));
        }
        transaction.commit()?;
        decode_batch_stock(participant_count, &txid, vout, value_sats, birth_height)
    }

    fn batch_stock_reserved_by(
        &self,
        batch_local_id: &str,
    ) -> Result<Option<BatchStock>, AccountError> {
        let row = self
            .db
            .conn
            .query_row(
                "SELECT participant_count, txid, vout, value_sats, birth_height
                 FROM opencsv_batch_stocks WHERE reserved_by_batch = ?1",
                [batch_local_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(
            |(participant_count, txid, vout, value_sats, birth_height)| {
                let participant_count = u8::try_from(participant_count).map_err(|_| {
                    AccountError::new("database_corrupt", "batch stock count is outside u8")
                })?;
                decode_batch_stock(participant_count, &txid, vout, value_sats, birth_height)
            },
        )
        .transpose()
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

    fn historical_funding_for_operation(
        &self,
        operation: &OperationRow,
    ) -> Result<ReservedFunding, AccountError> {
        let outpoint = operation_outpoint(operation)?;
        let reservation_state = self
            .db
            .conn
            .query_row(
                "SELECT state FROM opencsv_utxo_reservations
                 WHERE operation_id = ?1 AND txid = ?2 AND vout = ?3",
                params![
                    operation.operation_id,
                    outpoint.txid.to_string(),
                    outpoint.vout,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if reservation_state.as_deref() != Some("signature_released") {
            return Err(AccountError::new(
                "conflicting_operation",
                "signed batch fee input lost its durable released-signature lock",
            ));
        }
        let parent = self.bitcoin.get_tx(outpoint.txid).ok_or_else(|| {
            AccountError::new(
                "stale_chain_state",
                "batch fee-input parent is absent from the wallet graph",
            )
        })?;
        let txout = parent
            .tx_node
            .tx
            .output
            .get(outpoint.vout as usize)
            .cloned()
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "batch fee-input vout is outside its parent transaction",
                )
            })?;
        let birth_height = match parent.chain_position {
            ChainPosition::Confirmed {
                anchor,
                transitively: None,
            } => u64::from(anchor.block_id.height),
            _ => {
                return Err(AccountError::new(
                    "stale_chain_state",
                    "batch fee input lacks an exact confirmed birth height",
                ));
            }
        };
        let (keychain, derivation_index) = self
            .bitcoin
            .derivation_of_spk(txout.script_pubkey.clone())
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "batch fee input is not controlled by a wallet descriptor",
                )
            })?;
        Ok(ReservedFunding {
            outpoint,
            txout,
            birth_height,
            keychain: Some(keychain),
            derivation_index: Some(derivation_index),
        })
    }

    fn release_fee_reservation(&mut self, operation_id: &str) -> Result<(), AccountError> {
        let reservation_state = self
            .db
            .conn
            .query_row(
                "SELECT state FROM opencsv_utxo_reservations WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if reservation_state.as_deref() == Some("signature_released") {
            return Err(AccountError::new(
                "cancellation_forbidden",
                "a fee input cannot be unlocked after its signature was released",
            ));
        }
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
                "profile": "trusted_test_usd_v2",
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
        phase_timings_ms: &Value,
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
            "phase_timings_ms": phase_timings_ms,
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
        let client = self.esplora_client();
        for dependency in dependencies {
            if self.dependency_reobservation_is_fresh(dependency)? {
                continue;
            }
            let txid = unconfirmed_dependency_txid(dependency)?;
            let observed = client.get_tx(&txid).map_err(|error| {
                AccountError::retryable(
                    "unconfirmed_dependency_unavailable",
                    format!("could not re-observe parent {dependency}: {error}"),
                )
            })?;
            let now = unix_time()?;
            match observed {
                Some(transaction) if transaction.compute_txid() == txid => {}
                Some(transaction) => {
                    let detail = format!("exact parent changed to {}", transaction.compute_txid());
                    self.freeze_unconfirmed_dependency(dependency, &detail)?;
                    return Err(AccountError::new(
                        "unconfirmed_dependency_changed",
                        format!(
                            "zero-confirmation parent {dependency} changed; dependent signing is frozen"
                        ),
                    ));
                }
                None => {
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
            }
            self.persist_dependency_reobservation(dependency, now)?;
        }
        Ok(())
    }

    fn dependency_reobservation_max_age_seconds(&self) -> u64 {
        self.config
            .observation_checks
            .iter()
            .filter(|check| {
                check.kind == ObservationKind::RawTransactionApi
                    && check.mode != ObservationMode::Off
            })
            .map(|check| check.max_age_seconds)
            .min()
            .unwrap_or_else(default_observation_max_age_seconds)
    }

    fn dependency_reobservation_is_fresh(&self, dependency: &str) -> Result<bool, AccountError> {
        let txid = unconfirmed_dependency_txid(dependency)?.to_string();
        let observed_at = self
            .db
            .conn
            .query_row(
                "SELECT observed_at FROM opencsv_observation_receipts
                 WHERE subject_txid = ?1 AND check_id = ?2",
                params![txid, DEPENDENCY_REOBSERVATION_CHECK_ID],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        let Some(observed_at) = observed_at else {
            return Ok(false);
        };
        let now = unix_time()?;
        let max_age =
            i64::try_from(self.dependency_reobservation_max_age_seconds()).unwrap_or(i64::MAX);
        Ok(now >= observed_at && now.saturating_sub(observed_at) <= max_age)
    }

    fn persist_dependency_reobservations_at(
        &self,
        dependencies: &[String],
        observed_at: Option<i64>,
    ) -> Result<(), AccountError> {
        if dependencies.is_empty() {
            return Ok(());
        }
        let observed_at = observed_at.ok_or_else(|| {
            AccountError::new(
                "stale_proof_job",
                "proof completed without dependency-observation time",
            )
        })?;
        for dependency in dependencies {
            self.persist_dependency_reobservation(dependency, observed_at)?;
        }
        Ok(())
    }

    fn persist_dependency_reobservation(
        &self,
        dependency: &str,
        observed_at: i64,
    ) -> Result<(), AccountError> {
        let txid = unconfirmed_dependency_txid(dependency)?.to_string();
        let observed_at_ms = observed_at.saturating_mul(1_000);
        let receipt = json!({
            "check_id": DEPENDENCY_REOBSERVATION_CHECK_ID,
            "kind": ObservationKind::RawTransactionApi,
            "mode": ObservationMode::Observe,
            "endpoint": self.config.esplora_url,
            "result": ObservationResult::Observed,
            "started_at_ms": observed_at_ms,
            "completed_at_ms": observed_at_ms,
            "latency_ms": 0,
            "cached_at_ms": observed_at_ms,
            "cache_age_ms": 0,
            "certificate_profile": Value::Null,
            "certificate_chain_fingerprints_sha256": [],
            "raw_byte_match": true,
            "detail": "exact dependency txid re-observed during proof or pre-sign",
            "failures": [],
        });
        self.db.conn.execute(
            "INSERT INTO opencsv_observation_receipts(
                 subject_txid, check_id, receipt_json, observed_at
             ) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(subject_txid, check_id) DO UPDATE SET
                 receipt_json = excluded.receipt_json,
                 observed_at = excluded.observed_at",
            params![
                txid,
                DEPENDENCY_REOBSERVATION_CHECK_ID,
                receipt.to_string(),
                observed_at
            ],
        )?;
        self.db.conn.execute(
            "UPDATE opencsv_consignment_finality
             SET last_checked_at = ?2, last_error = NULL
             WHERE anchor_txid = ?1 AND finality = 'unconfirmed'",
            params![txid, observed_at],
        )?;
        Ok(())
    }

    fn freeze_unconfirmed_dependency(
        &mut self,
        dependency: &str,
        reason: &str,
    ) -> Result<(), AccountError> {
        let txid = unconfirmed_dependency_txid(dependency)?.to_string();
        self.db.conn.execute(
            "UPDATE opencsv_consignment_finality
             SET finality = 'frozen', last_checked_at = ?2, last_error = ?3
             WHERE anchor_txid = ?1 AND finality != 'settled'",
            params![txid, unix_time()?, reason],
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
        let batch_local_id = self
            .db
            .conn
            .query_row(
                "SELECT batch_local_id FROM opencsv_send_batch_members
                 WHERE operation_id = ?1",
                [operation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(batch_local_id) = batch_local_id {
            // A solo timeout is still represented by a one-member batch, and
            // a frozen multi-recipient proposal is atomic. If any member
            // fails before signature release, close the complete batch so
            // callers never keep presenting an orphaned `solo`/`frozen`
            // container as resumable after its operation was cancelled.
            self.cancel_send_batch(&batch_local_id)?;
            let now = unix_time()?;
            self.db.conn.execute(
                "UPDATE opencsv_operations
                 SET rejection_reason = ?2, updated_at = ?3
                 WHERE operation_id IN (
                     SELECT operation_id FROM opencsv_send_batch_members
                     WHERE batch_local_id = ?1
                 )",
                params![batch_local_id, reason, now],
            )?;
            self.db.conn.execute(
                "UPDATE opencsv_send_batches
                 SET receipt_json = ?2, updated_at = ?3
                 WHERE batch_local_id = ?1",
                params![
                    batch_local_id,
                    json!({"prebroadcast_error": reason}).to_string(),
                    now,
                ],
            )?;
            return Ok(());
        }
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

    fn send_batch(&self, batch_local_id: &str) -> Result<SendBatchRow, AccountError> {
        self.db
            .conn
            .query_row(
                "SELECT batch_local_id, state, deadline_ms, participant_count,
                        proposal_wire, manifest_wire, signed_tx_hex, txid,
                        receipt_json, checkpoint_hash, backup_acked
                 FROM opencsv_send_batches WHERE batch_local_id = ?1",
                [batch_local_id],
                |row| {
                    let participant_count = row
                        .get::<_, Option<i64>>(3)?
                        .and_then(|value| u8::try_from(value).ok());
                    Ok(SendBatchRow {
                        batch_local_id: row.get(0)?,
                        state: row.get(1)?,
                        deadline_ms: row.get(2)?,
                        participant_count,
                        proposal_wire: row.get(4)?,
                        manifest_wire: row.get(5)?,
                        signed_tx_hex: row.get(6)?,
                        txid: row.get(7)?,
                        receipt_json: row.get(8)?,
                        checkpoint_hash: row.get(9)?,
                        backup_acked: row.get::<_, i64>(10)? != 0,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| {
                AccountError::new("unknown_batch", format!("unknown batch {batch_local_id}"))
            })
    }

    fn send_batch_members(
        &self,
        batch_local_id: &str,
    ) -> Result<Vec<SendBatchMember>, AccountError> {
        let mut statement = self.db.conn.prepare(
            "SELECT operation_id, ordinal, added_at_ms,
                    change_spk_hex, commit_nonce_hex
             FROM opencsv_send_batch_members
             WHERE batch_local_id = ?1 ORDER BY ordinal",
        )?;
        let rows = statement.query_map([batch_local_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (operation_id, ordinal, added_at_ms, change_spk_hex, commit_nonce_hex) = row?;
            Ok(SendBatchMember {
                operation_id,
                ordinal: u8::try_from(ordinal).map_err(|_| {
                    AccountError::new("database_corrupt", "batch ordinal is outside u8")
                })?,
                added_at_ms,
                change_spk_hex,
                commit_nonce_hex,
            })
        })
        .collect()
    }

    fn send_batch_member_json(
        &self,
        batch_local_id: &str,
        operation_id: &str,
    ) -> Result<Value, AccountError> {
        let mut operation = operation_json(&self.operation(operation_id)?)?;
        let batch = self.send_batch(batch_local_id)?;
        let members = self.send_batch_members(batch_local_id)?;
        let member = members
            .iter()
            .find(|member| member.operation_id == operation_id)
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "planned operation lost batch membership",
                )
            })?;
        operation["batch"] = json!({
            "batch_local_id": batch_local_id,
            "state": batch.state,
            "deadline_ms": batch.deadline_ms,
            "ordinal": member.ordinal,
            "added_at_ms": member.added_at_ms,
            "member_count": members.len(),
            "add_recipient_guaranteed": batch.state == "collecting"
                && unix_time_millis()? <= batch.deadline_ms,
        });
        Ok(operation)
    }

    fn send_batch_json(&self, batch_local_id: &str) -> Result<Value, AccountError> {
        let batch = self.send_batch(batch_local_id)?;
        let members = self.send_batch_members(batch_local_id)?;
        let operations = members
            .iter()
            .map(|member| operation_json(&self.operation(&member.operation_id)?))
            .collect::<Result<Vec<_>, _>>()?;
        let receipt: Option<Value> = batch
            .receipt_json
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        Ok(json!({
            "batch_local_id": batch.batch_local_id,
            "state": batch.state,
            "deadline_ms": batch.deadline_ms,
            "participant_count": batch.participant_count,
            "member_count": members.len(),
            "operations": operations,
            "proposal_wire_base64": batch.proposal_wire.map(|wire| {
                base64::engine::general_purpose::STANDARD.encode(wire)
            }),
            "manifest_wire_base64": batch.manifest_wire.map(|wire| {
                base64::engine::general_purpose::STANDARD.encode(wire)
            }),
            "signed_tx_hex": batch.signed_tx_hex,
            "txid": batch.txid,
            "receipt": receipt,
            "checkpoint_hash": batch.checkpoint_hash,
            "backup_acked": batch.backup_acked,
        }))
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
        let client = self.esplora_client();
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
             rejection_reason = NULL, updated_at = ?4 WHERE operation_id = ?1",
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

        let operation = self.operation(operation_id)?;
        let prior_delivery = self.replacement_delivery_snapshot(&operation, receipt)?;
        let receipt_object = receipt.as_object_mut().ok_or_else(|| {
            AccountError::new("database_corrupt", "operation receipt is not an object")
        })?;
        if let Some(prior_delivery) = prior_delivery {
            receipt_object.insert("pre_replacement_delivery".into(), prior_delivery);
        }
        // A replacement is a new proof-bearing attachment. Rotate the
        // transport acknowledgement nonce atomically with its exact bytes so
        // a delayed acknowledgement for the superseded consignment cannot
        // mark this replacement delivered before Signal sends it.
        let replacement_delivery_nonce = random_id(16);
        receipt_object.insert(
            "delivery_nonce".into(),
            json!(replacement_delivery_nonce.clone()),
        );
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
             txid = ?4, receipt_json = ?5, delivery_nonce = ?6, updated_at = ?7
             WHERE operation_id = ?1",
            params![
                operation_id,
                OperationState::SignedPersisted.as_str(),
                replacement_hex,
                replacement_txid.to_string(),
                receipt.to_string(),
                replacement_delivery_nonce,
                now,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn replacement_delivery_snapshot(
        &self,
        operation: &OperationRow,
        receipt: &Value,
    ) -> Result<Option<Value>, AccountError> {
        let Some(consignment_id) = receipt.get("consignment_id").and_then(Value::as_str) else {
            return Ok(None);
        };
        let consignment_base64 = receipt
            .get("consignment_base64")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "delivery-ready receipt has no consignment bytes",
                )
            })?;
        validate_consignment_identity(consignment_id, consignment_base64)?;
        let (stored_base64, spent_state_json): (String, String) = self
            .db
            .conn
            .query_row(
                "SELECT consignment_base64, spent_state_json
                 FROM opencsv_consignments WHERE consignment_id = ?1",
                [consignment_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                AccountError::new(
                    "database_corrupt",
                    "delivery-ready receipt has no persisted consignment",
                )
            })?;
        if stored_base64 != consignment_base64 {
            return Err(AccountError::new(
                "database_corrupt",
                "receipt and persisted consignment bytes disagree",
            ));
        }
        serde_json::from_str::<Value>(&spent_state_json).map_err(|error| {
            AccountError::new(
                "database_corrupt",
                format!("persisted consignment spent state: {error}"),
            )
        })?;
        Ok(Some(json!({
            "consignment_id": consignment_id,
            "consignment_base64": consignment_base64,
            "spent_state_json": spent_state_json,
            "delivery_nonce": operation.delivery_nonce,
            "consignment_delivered": receipt["consignment_delivered"] == true,
            "consignment_delivered_at": receipt.get("consignment_delivered_at"),
        })))
    }

    fn backup_verified(&self) -> Result<bool, AccountError> {
        Ok(self.db.meta("backup_verified")?.as_deref() == Some("1"))
    }

    fn write_enabled(&self) -> Result<bool, AccountError> {
        Ok(self.write_block_reason()?.is_none())
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
                let anchor_txid = anchor_txid.parse::<Txid>().map_err(|error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("unconfirmed anchor txid: {error}"),
                    )
                })?;
                protocol.verify_unconfirmed(&blob, &chain, &unconfirmed_dependency_key(anchor_txid))
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
                 WHERE state IN ('reserved', 'signature_released') ORDER BY created_at",
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
    keychain: Option<KeychainKind>,
    derivation_index: Option<u32>,
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
            keychain: Some(output.keychain),
            derivation_index: Some(output.derivation_index),
        })
    }

    fn value_sats(&self) -> u64 {
        self.txout.value.to_sat()
    }
}

fn decode_batch_stock(
    participant_count: u8,
    txid: &str,
    vout: i64,
    value_sats: i64,
    birth_height: i64,
) -> Result<BatchStock, AccountError> {
    Ok(BatchStock {
        participant_count,
        outpoint: OutPoint::new(
            Txid::from_str(txid).map_err(|error| {
                AccountError::new("database_corrupt", format!("batch stock txid: {error}"))
            })?,
            u32::try_from(vout).map_err(|_| {
                AccountError::new("database_corrupt", "batch stock vout is outside u32")
            })?,
        ),
        value_sats: u64::try_from(value_sats)
            .map_err(|_| AccountError::new("database_corrupt", "batch stock value is negative"))?,
        birth_height: u64::try_from(birth_height).map_err(|_| {
            AccountError::new("database_corrupt", "batch stock birth height is negative")
        })?,
    })
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

fn normalize_transfer_request(
    request_json: &str,
) -> Result<(TransferRequest, String), AccountError> {
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
    let normalized = serde_json::to_string(&request)
        .map_err(|error| AccountError::new("database_error", error.to_string()))?;
    Ok((request, normalized))
}

fn batch_protocol_error(error: opencsv_bitcoin::batch_v2::ProtocolError) -> AccountError {
    AccountError::new("batch_protocol_rejected", error.to_string())
}

fn batch_operation_id(operation_id: &str) -> [u8; 32] {
    sha256::Hash::hash(
        [
            b"OpenCSV batch operation v1".as_slice(),
            operation_id.as_bytes(),
        ]
        .concat()
        .as_slice(),
    )
    .to_byte_array()
}

fn insert_planned_operation_in_transaction(
    transaction: &rusqlite::Transaction<'_>,
    operation_id: &str,
    normalized_request: &str,
    delivery_nonce: &str,
    created_at: i64,
) -> Result<(), AccountError> {
    transaction.execute(
        "INSERT INTO opencsv_operations(
             operation_id, kind, state, request_json, delivery_nonce,
             created_at, updated_at
         ) VALUES(?1, 'transfer', ?2, ?3, ?4, ?5, ?5)",
        params![
            operation_id,
            OperationState::Planned.as_str(),
            normalized_request,
            delivery_nonce,
            created_at,
        ],
    )?;
    Ok(())
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

fn validate_consignment_identity(
    expected_id: &str,
    consignment_base64: &str,
) -> Result<(), AccountError> {
    let blob = base64::engine::general_purpose::STANDARD
        .decode(consignment_base64)
        .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
    let (canonical, identity) = canonical_consignment_identity(&blob).map_err(|error| {
        AccountError::new(
            "database_corrupt",
            format!("persisted consignment is invalid: {}", error.message),
        )
    })?;
    if canonical != blob || identity != expected_id {
        return Err(AccountError::new(
            "database_corrupt",
            "persisted consignment identity does not match its canonical bytes",
        ));
    }
    Ok(())
}

/// Stable logical-payment identity. An RBF replacement changes only the
/// Bitcoin anchor reference; the recipient openings, nullifiers, proof, and
/// optional genesis remain byte-for-byte identical. Hashing those protected
/// fields lets clients replace presentation without trusting Signal message
/// text or treating the new canonical consignment as a second payment.
fn consignment_payment_identity(consignment: &Consignment) -> Result<String, AccountError> {
    let mut protected = consignment.clone();
    protected.anchor_ref.txid = [0; 32];
    let mut domain_separated = b"OpenCSV/payment-presentation/v1\0".to_vec();
    domain_separated.extend_from_slice(&protected.to_bytes());
    Ok(sha256::Hash::hash(&domain_separated).to_string())
}

/// Find prior canonical consignments for the same protected payment. The
/// database contains only proof-verified consignments, so this relationship
/// is derived from protocol bytes rather than untrusted transport metadata.
fn matching_payment_consignments(
    conn: &Connection,
    current_consignment_id: &str,
    payment_id: &str,
) -> Result<Vec<String>, AccountError> {
    let mut statement = conn.prepare(
        "SELECT consignment_id, consignment_base64 FROM opencsv_consignments
         WHERE consignment_id != ?1 ORDER BY created_at, consignment_id",
    )?;
    let rows = statement.query_map([current_consignment_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut matches = Vec::new();
    for row in rows {
        let (consignment_id, encoded) = row?;
        let blob = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        let consignment = Consignment::from_bytes(&blob)
            .map_err(|error| AccountError::new("database_corrupt", error.to_string()))?;
        if consignment_payment_identity(&consignment)? == payment_id {
            matches.push(consignment_id);
        }
    }
    Ok(matches)
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
    let parsed_record = AnchorRecord::from_bytes(&record);
    let (ctx, batch) = match parsed_record {
        AnchorRecord::BatchHeader { .. } => validate_batch_anchor(transaction, &parsed_record)?,
        _ => {
            validate_initial_anchor(transaction, funding, &record)?;
            (funding_context(funding), None)
        }
    };

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
    if let Some(confirmed) = snapshot
        .entries
        .iter_mut()
        .find(|entry| entry.txid == txid_hex)
    {
        if confirmed.ctx != hex_encode(&ctx) || confirmed.record != hex_encode(&record) {
            return Err(AccountError::new(
                "unconfirmed_anchor_mismatch",
                "confirmed anchor with the expected txid does not match the exact transaction context and record",
            ));
        }
        confirmed.batch = batch;
        // The consignment still carries the mempool sentinel, but
        // SnapshotChain resolves that reference by txid to this canonical
        // confirmed location. Injecting a second sentinel entry would make
        // the transaction conflict with itself during first-occurrence
        // checks.
        return Ok(snapshot);
    }
    snapshot.entries.push(SnapshotEntry {
        height: MEMPOOL_LOCATION.height,
        position: MEMPOOL_LOCATION.position,
        txid: txid_hex,
        ctx: hex_encode(&ctx),
        record: hex_encode(&record),
        batch,
    });
    Ok(snapshot)
}

/// Validate the public, receiver-visible invariants of a signed batching-v2
/// anchor and retain its exact witness envelope for provisional occurrence
/// checks. Bitcoin peers and the two required observers establish consensus
/// validity; this check independently binds the OpenCSV header, stock script,
/// marker, participant count, and change layout to the received raw bytes.
fn validate_batch_anchor(
    transaction: &Transaction,
    record: &AnchorRecord,
) -> Result<([u8; 32], Option<SnapshotBatchEnvelope>), AccountError> {
    let AnchorRecord::BatchHeader { count, .. } = record else {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "batch validation requires a batch header",
        ));
    };
    let count = usize::from(*count);
    if count == 0
        || transaction.input.len() != count + 1
        || transaction.output.len() != count + 3
        || transaction
            .input
            .iter()
            .any(|input| input.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME)
    {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "batch input/output counts or RBF sequences are noncanonical",
        ));
    }
    let witness = transaction.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let (version, payloads) = witness_envelope_decode(&witness).ok_or_else(|| {
        AccountError::new(
            "protocol_layout_violation",
            "batch input 0 has no canonical witness envelope",
        )
    })?;
    if version != BatchVersion::V2 || payloads.len() != count {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "Signal accepts only signed batching-v2 envelopes with the committed count",
        ));
    }
    let funding = transaction.input[0].previous_output;
    let ctx = funding_context(funding);
    if AnchorRecord::batch_header_v2(&payloads, &ctx) != *record {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "batch witness envelope does not match the anchor header and input-0 context",
        ));
    }
    let expected_record = ScriptBuf::new_op_return(
        PushBytesBuf::try_from(record.to_bytes().to_vec()).expect("64-byte record is pushable"),
    );
    let stock_witness_script = ScriptBuf::from_bytes(
        witness
            .last()
            .expect("decoded batching-v2 witness has a script")
            .clone(),
    );
    let stock_output = &transaction.output[2];
    if transaction.output[0].value != Amount::ZERO
        || transaction.output[0].script_pubkey != expected_record
        || transaction.output[1].value.to_sat() != MARKER_DUST_SATS
        || transaction.output[1].script_pubkey.as_bytes() != MARKER_SPK
        || stock_output.script_pubkey != stock_witness_script.to_p2wsh()
        || stock_output.value < stock_output.script_pubkey.minimal_non_dust()
        || transaction.output[3..].iter().any(|output| {
            !output.script_pubkey.is_p2wpkh()
                || output.value < output.script_pubkey.minimal_non_dust()
        })
    {
        return Err(AccountError::new(
            "protocol_layout_violation",
            "signed transaction does not preserve batch header/marker/stock/change layout",
        ));
    }
    Ok((
        ctx,
        Some(SnapshotBatchEnvelope {
            version: 2,
            payloads: payloads
                .iter()
                .map(|payload| hex_encode(payload.as_bytes()))
                .collect(),
        }),
    ))
}

fn evaluate_observation_evidence(
    policy: &[ObservationCheck],
    required_raw_observer_quorum: u32,
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
    let required_raw_observer_count = policy
        .iter()
        .filter(|check| {
            check.kind == ObservationKind::RawTransactionApi
                && check.mode == ObservationMode::Require
        })
        .count();
    let mut successful_required_raw_observers = 0u32;
    let mut conflicting_required_raw_observers = Vec::new();
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
            let observed_raw = if check.kind == ObservationKind::RawTransactionApi {
                evidence
                    .raw_transaction_hex
                    .as_deref()
                    .and_then(|encoded| hex_decode(encoded, "observed raw transaction").ok())
            } else {
                None
            };
            let raw_match = observed_raw
                .as_deref()
                .is_some_and(|raw| raw == exact_raw_transaction);
            let reports_conflicting_transaction = check.mode == ObservationMode::Require
                && evidence.result == ObservationResult::Observed
                && observed_raw.as_deref().is_some_and(|raw| {
                    raw != exact_raw_transaction && deserialize::<Transaction>(raw).is_ok()
                });
            if reports_conflicting_transaction {
                failures.push("observer returned a different valid transaction".to_owned());
                conflicting_required_raw_observers.push(check.id.clone());
            }
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
            && receipt["failures"]
                .as_array()
                .is_some_and(|failures| failures.is_empty())
        {
            successful_required_raw_observers += 1;
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
    if !conflicting_required_raw_observers.is_empty() {
        return Ok((
            receipts,
            Some(AccountError::new(
                "observer_transaction_conflict",
                format!(
                    "required observers returned different valid transaction bytes: {}",
                    conflicting_required_raw_observers.join(", ")
                ),
            )),
        ));
    }
    let required_failure = (required_raw_observer_count > 0
        && successful_required_raw_observers < required_raw_observer_quorum)
        .then(|| {
            AccountError::new(
                "required_observation_failed",
                format!(
                    "required raw observer quorum failed: {successful_required_raw_observers} of {required_raw_observer_quorum} exact pinned observations succeeded"
                ),
            )
        });
    Ok((receipts, required_failure))
}

fn derive<const N: usize>(
    root: &[u8],
    label: &[u8],
    context: &[u8],
) -> Result<[u8; N], AccountError> {
    let hk = Hkdf::<Sha256>::new(Some(b"OpenCSV Signal account v2"), root);
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

fn validate_deployment(config: &AccountConfig) -> Result<(), AccountError> {
    validate_deployment_identity(&config.network, &config.deployment_id)
}

fn validate_deployment_identity(network: &str, deployment_id: &str) -> Result<(), AccountError> {
    if deployment_id.is_empty()
        || deployment_id.len() > 64
        || !deployment_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AccountError::new(
            "invalid_config",
            "deployment_id must be 1..=64 lowercase ASCII letters, digits, or hyphens",
        ));
    }
    match network {
        "signet" | "regtest" if deployment_id != TEST_USD_V2_DEPLOYMENT_ID => {
            return Err(AccountError::new(
                "invalid_config",
                format!("signet/regtest deployment_id must be {TEST_USD_V2_DEPLOYMENT_ID}"),
            ));
        }
        "mainnet" if deployment_id == TEST_USD_V2_DEPLOYMENT_ID => {
            return Err(AccountError::new(
                "invalid_config",
                "the Test USD v2 deployment cannot run on mainnet",
            ));
        }
        _ => {}
    }
    Ok(())
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

fn validate_esplora_client_policy(config: &AccountConfig) -> Result<(), AccountError> {
    if !(1..=60).contains(&config.esplora_request_timeout_secs) {
        return Err(AccountError::new(
            "invalid_config",
            "Esplora request timeout must be between 1 and 60 seconds",
        ));
    }
    if config.esplora_max_retries > 3 {
        return Err(AccountError::new(
            "invalid_config",
            "Esplora request retries must not exceed 3",
        ));
    }
    Ok(())
}

fn build_blocking_esplora_client(
    url: &str,
    request_timeout_secs: u64,
    max_retries: usize,
) -> esplora_client::BlockingClient {
    esplora_client::Builder::new(url)
        .timeout(request_timeout_secs)
        .max_retries(max_retries)
        .build_blocking()
}

const MEMPOOL_SPACE_CHAIN_PINS: [&str; 2] = [
    // Sectigo Public Server Authentication CA OV R36.
    "6542d176bed50f193c0ce297ae44ecd8a0a86bec2ede682769344059b4e78530",
    // Sectigo Public Server Authentication Root R46, USERTrust cross-certificate.
    "92f351bf3d54164dfa8dd8f9e1139d3150349786485d2b9eecd00e2971c1e6c5",
];

const BLOCKSTREAM_CHAIN_PINS: [&str; 4] = [
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
    if matches!(network, "signet" | "mainnet") {
        let (mempool_id, mempool_endpoint, blockstream_id, blockstream_endpoint) =
            if network == "mainnet" {
                (
                    "mempool_space_mainnet",
                    "https://mempool.space/api",
                    "blockstream_mainnet",
                    "https://blockstream.info/api",
                )
            } else {
                (
                    "mempool_space_signet",
                    "https://mempool.space/signet/api",
                    "blockstream_signet",
                    "https://blockstream.info/signet/api",
                )
            };
        checks.push(ObservationCheck {
            id: mempool_id.into(),
            kind: ObservationKind::RawTransactionApi,
            endpoint: Some(mempool_endpoint.into()),
            mode: ObservationMode::Require,
            pin_profile: Some("sectigo_r46".into()),
            chain_fingerprints_sha256: owned_chain_pins(MEMPOOL_SPACE_CHAIN_PINS),
            max_age_seconds: default_observation_max_age_seconds(),
        });
        checks.push(ObservationCheck {
            id: blockstream_id.into(),
            kind: ObservationKind::RawTransactionApi,
            endpoint: Some(blockstream_endpoint.into()),
            mode: ObservationMode::Require,
            pin_profile: Some("lets_encrypt_yr".into()),
            chain_fingerprints_sha256: owned_chain_pins(BLOCKSTREAM_CHAIN_PINS),
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
                        != owned_chain_pins(MEMPOOL_SPACE_CHAIN_PINS)
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
                        != owned_chain_pins(BLOCKSTREAM_CHAIN_PINS)
                {
                    return Err(AccountError::new(
                        "invalid_config",
                        "the built-in Blockstream signet endpoint and pin profile are immutable",
                    ));
                }
            }
            "mempool_space_mainnet" => {
                if config.network != "mainnet"
                    || check.kind != ObservationKind::RawTransactionApi
                    || check.endpoint.as_deref() != Some("https://mempool.space/api")
                    || check.pin_profile.as_deref() != Some("sectigo_r46")
                    || check.chain_fingerprints_sha256
                        != owned_chain_pins(MEMPOOL_SPACE_CHAIN_PINS)
                {
                    return Err(AccountError::new(
                        "invalid_config",
                        "the built-in mempool.space mainnet endpoint and pin profile are immutable",
                    ));
                }
            }
            "blockstream_mainnet" => {
                if config.network != "mainnet"
                    || check.kind != ObservationKind::RawTransactionApi
                    || check.endpoint.as_deref() != Some("https://blockstream.info/api")
                    || check.pin_profile.as_deref() != Some("lets_encrypt_yr")
                    || check.chain_fingerprints_sha256
                        != owned_chain_pins(BLOCKSTREAM_CHAIN_PINS)
                {
                    return Err(AccountError::new(
                        "invalid_config",
                        "the built-in Blockstream mainnet endpoint and pin profile are immutable",
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
    let required_raw_observers = config
        .observation_checks
        .iter()
        .filter(|check| {
            check.kind == ObservationKind::RawTransactionApi
                && check.mode == ObservationMode::Require
        })
        .count();
    if usize::try_from(config.required_raw_observer_quorum)
        .map_or(true, |quorum| quorum != required_raw_observers)
    {
        return Err(AccountError::new(
            "invalid_config",
            format!(
                "required raw observer quorum must equal all {required_raw_observers} raw observers marked require"
            ),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ProductionUsdRegistryCommitmentPayload<'a> {
    domain: &'static str,
    format_version: u32,
    registry_version: u64,
    deployment_id: &'a str,
    issuers: &'a [UsdIssuerPolicy],
    rollout: &'a ProductionRolloutPolicy,
    source_revision: &'a str,
    approval_receipts: &'a [String],
}

#[derive(Serialize)]
struct ProductionRolloutAuthorizationPayload<'a> {
    domain: &'static str,
    deployment_id: &'a str,
    operation_identity: &'a str,
    release_commitment_sha256: &'a str,
}

fn production_rollout_authorization_digest(
    deployment_id: &str,
    operation_identity: &str,
    release_commitment_sha256: &str,
) -> Result<[u8; 32], AccountError> {
    let canonical = serde_json::to_vec(&ProductionRolloutAuthorizationPayload {
        domain: "OpenCSV-production-rollout-authorization-v1",
        deployment_id,
        operation_identity,
        release_commitment_sha256,
    })
    .map_err(|error| {
        AccountError::new(
            "database_corrupt",
            format!("encode production rollout authorization: {error}"),
        )
    })?;
    Ok(sha256::Hash::hash(&canonical).to_byte_array())
}

fn production_usd_registry_commitment(
    release: &ProductionUsdRegistryRelease,
) -> Result<String, AccountError> {
    let canonical = serde_json::to_vec(&ProductionUsdRegistryCommitmentPayload {
        domain: "OpenCSV-production-USD-registry-v1",
        format_version: release.format_version,
        registry_version: release.registry_version,
        deployment_id: &release.deployment_id,
        issuers: &release.issuers,
        rollout: &release.rollout,
        source_revision: &release.source_revision,
        approval_receipts: &release.approval_receipts,
    })
    .map_err(|error| {
        AccountError::new(
            "invalid_config",
            format!("encode production USD registry commitment: {error}"),
        )
    })?;
    Ok(sha256::Hash::hash(&canonical).to_string())
}

fn validate_production_usd_registry_release(
    release: &ProductionUsdRegistryRelease,
    expected_deployment_id: &str,
) -> Result<(), AccountError> {
    validate_deployment_identity("mainnet", &release.deployment_id)?;
    if release.format_version != PRODUCTION_USD_REGISTRY_FORMAT_VERSION {
        return Err(AccountError::new(
            "invalid_config",
            format!(
                "unsupported production USD registry format version {}",
                release.format_version
            ),
        ));
    }
    if release.registry_version == 0 {
        return Err(AccountError::new(
            "invalid_config",
            "production USD registry version must be nonzero",
        ));
    }
    if release.deployment_id != expected_deployment_id {
        return Err(AccountError::new(
            "invalid_config",
            "production USD registry belongs to another deployment",
        ));
    }
    let revision_is_supported = matches!(release.source_revision.len(), 40 | 64)
        && release
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !revision_is_supported {
        return Err(AccountError::new(
            "invalid_config",
            "production USD registry source revision must be a 40- or 64-character lowercase hex digest",
        ));
    }
    if release.approval_receipts.is_empty() {
        return Err(AccountError::new(
            "invalid_config",
            "production USD registry needs at least one public approval receipt",
        ));
    }
    let mut receipt_urls = HashSet::new();
    for receipt in &release.approval_receipts {
        let parsed = Url::parse(receipt).map_err(|_| {
            AccountError::new(
                "invalid_config",
                "production USD registry approval receipts must be valid HTTPS URLs",
            )
        })?;
        if parsed.scheme() != "https" || parsed.host_str().is_none() {
            return Err(AccountError::new(
                "invalid_config",
                "production USD registry approval receipts must be valid HTTPS URLs",
            ));
        }
        if !receipt_urls.insert(receipt) {
            return Err(AccountError::new(
                "invalid_config",
                "production USD registry contains a duplicate approval receipt",
            ));
        }
    }
    validate_production_rollout_policy(&release.rollout)?;
    if release.rollout.phase != ProductionActivationPhase::Candidate {
        if release.issuers.is_empty() {
            return Err(AccountError::new(
                "invalid_config",
                "an activated production USD registry must contain at least one exact issuer",
            ));
        }
        if release.source_revision.bytes().all(|byte| byte == b'0') {
            return Err(AccountError::new(
                "invalid_config",
                "an activated production USD registry cannot use the placeholder source revision",
            ));
        }
    }
    validate_usd_issuer_policies(&release.issuers, "mainnet")?;
    validate_hex_32_config(
        &release.commitment_sha256,
        "production USD registry commitment",
    )?;
    let expected_commitment = production_usd_registry_commitment(release)?;
    if release.commitment_sha256 != expected_commitment {
        return Err(AccountError::new(
            "invalid_config",
            "production USD registry commitment does not match its exact release payload",
        ));
    }
    Ok(())
}

/// Build the exact canonical production-registry release used by account
/// configuration. This pure, secret-free helper is exposed only to tests and
/// the opt-in headless operator tools; Signal never enables that feature.
#[cfg(any(test, feature = "registry-tools"))]
pub fn build_production_usd_registry_release(
    draft_json: &str,
) -> Result<Value, AccountError> {
    let mut value: Value = serde_json::from_str(draft_json).map_err(|error| {
        AccountError::new(
            "invalid_config",
            format!("production registry draft JSON: {error}"),
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        AccountError::new("invalid_config", "production registry draft must be an object")
    })?;
    if object.contains_key("commitment_sha256") {
        return Err(AccountError::new(
            "invalid_config",
            "production registry build input must omit commitment_sha256",
        ));
    }
    object.insert("commitment_sha256".into(), json!("00".repeat(32)));
    let mut release = serde_json::from_value::<ProductionUsdRegistryRelease>(value).map_err(
        |error| {
            AccountError::new(
                "invalid_config",
                format!("production registry draft: {error}"),
            )
        },
    )?;
    release.commitment_sha256 = production_usd_registry_commitment(&release)?;
    validate_production_usd_registry_release(&release, &release.deployment_id)?;
    serde_json::to_value(release).map_err(|error| {
        AccountError::new(
            "json_encode_failed",
            format!("production registry release: {error}"),
        )
    })
}

/// Verify a complete release with the exact same rules used by account open.
#[cfg(any(test, feature = "registry-tools"))]
pub fn verify_production_usd_registry_release(
    release_json: &str,
    expected_deployment_id: &str,
) -> Result<Value, AccountError> {
    let release = serde_json::from_str::<ProductionUsdRegistryRelease>(release_json).map_err(
        |error| {
            AccountError::new(
                "invalid_config",
                format!("production registry release JSON: {error}"),
            )
        },
    )?;
    validate_deployment_identity("mainnet", expected_deployment_id)?;
    validate_production_usd_registry_release(&release, expected_deployment_id)?;
    Ok(json!({
        "structurally_valid": true,
        "activation_authorized": false,
        "authorization_note": "structural verification does not replace application distribution signing, independent review, or owner approval",
        "format_version": release.format_version,
        "registry_version": release.registry_version,
        "deployment_id": release.deployment_id,
        "phase": release.rollout.phase,
        "issuer_count": release.issuers.len(),
        "commitment_sha256": release.commitment_sha256,
    }))
}

fn prepare_production_usd_registry(config: &mut AccountConfig) -> Result<(), AccountError> {
    if config.network != "mainnet" {
        if config.production_usd_registry.is_some() {
            return Err(AccountError::new(
                "invalid_config",
                "production USD registry releases are mainnet-only",
            ));
        }
        return Ok(());
    }

    if !config.usd_issuers.is_empty() {
        return Err(AccountError::new(
            "invalid_config",
            "mainnet USD issuers must come from a versioned production registry release",
        ));
    }
    let Some(release) = config.production_usd_registry.as_ref() else {
        return Ok(());
    };
    validate_production_usd_registry_release(release, &config.deployment_id)?;

    config.usd_issuers.clone_from(&release.issuers);
    config.max_fee_sats = Some(
        config
            .max_fee_sats
            .map_or(release.rollout.max_miner_fee_sats, |host_limit| {
                host_limit.min(release.rollout.max_miner_fee_sats)
            }),
    );
    Ok(())
}

fn validate_production_rollout_policy(
    policy: &ProductionRolloutPolicy,
) -> Result<(), AccountError> {
    if policy.max_transfer_base_units == 0
        || policy.max_batch_total_base_units == 0
        || policy.max_rolling_24h_outgoing_base_units == 0
        || policy.max_rolling_24h_operations == 0
        || policy.max_reserve_allocation_sats == 0
        || policy.max_miner_fee_sats == 0
    {
        return Err(AccountError::new(
            "invalid_config",
            "production rollout limits must all be positive",
        ));
    }
    if policy.max_transfer_base_units > policy.max_batch_total_base_units
        || policy.max_batch_total_base_units > policy.max_rolling_24h_outgoing_base_units
    {
        return Err(AccountError::new(
            "invalid_config",
            "production transfer limit must not exceed batch or rolling-day limits",
        ));
    }
    let protocol_max = u8::try_from(MAX_LOCAL_BATCH_RECIPIENTS).unwrap_or(u8::MAX);
    if policy.max_batch_recipients == 0 || policy.max_batch_recipients > protocol_max {
        return Err(AccountError::new(
            "invalid_config",
            format!("production batch recipient limit must be 1..={protocol_max}"),
        ));
    }
    if policy.max_batch_recipients >= 2 {
        let fee_cells = u64::from(policy.max_batch_recipients)
            .checked_mul(3)
            .and_then(|count| count.checked_mul(MIN_FEE_RESERVE_SATS))
            .ok_or_else(|| {
                AccountError::new("invalid_config", "production reserve allocation overflows")
            })?;
        let stocks = 3_u64
            .checked_mul(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS)
            .ok_or_else(|| {
                AccountError::new("invalid_config", "production reserve allocation overflows")
            })?;
        let minimum = stocks.checked_add(fee_cells).ok_or_else(|| {
            AccountError::new("invalid_config", "production reserve allocation overflows")
        })?;
        if policy.max_reserve_allocation_sats < minimum {
            return Err(AccountError::new(
                "invalid_config",
                format!(
                    "production reserve allocation must cover at least {minimum} sats for the configured batch limit"
                ),
            ));
        }
    }
    Ok(())
}

fn read_production_usd_registry_floor(
    db: &SqlitePersister,
) -> Result<Option<ProductionUsdRegistryFloor>, AccountError> {
    db.meta("production_usd_registry_floor")?
        .map(|encoded| {
            let floor = serde_json::from_str::<ProductionUsdRegistryFloor>(&encoded).map_err(
                |error| {
                    AccountError::new(
                        "database_corrupt",
                        format!("production USD registry floor: {error}"),
                    )
                },
            )?;
            if floor.registry_version == 0
                || validate_hex_32_config(
                    &floor.commitment_sha256,
                    "production USD registry floor commitment",
                )
                .is_err()
            {
                return Err(AccountError::new(
                    "database_corrupt",
                    "production USD registry floor is malformed",
                ));
            }
            Ok(floor)
        })
        .transpose()
}

fn write_production_usd_registry_floor(
    db: &mut SqlitePersister,
    floor: &ProductionUsdRegistryFloor,
) -> Result<(), AccountError> {
    let encoded = serde_json::to_string(floor).map_err(|error| {
        AccountError::new(
            "database_error",
            format!("encode production USD registry floor: {error}"),
        )
    })?;
    db.set_meta("production_usd_registry_floor", &encoded)
}

fn reconcile_production_usd_registry_floor(
    db: &mut SqlitePersister,
    config: &mut AccountConfig,
) -> Result<ProductionUsdRegistryState, AccountError> {
    if config.network != "mainnet" {
        return Ok(ProductionUsdRegistryState::NotApplicable);
    }
    let stored = read_production_usd_registry_floor(db)?;
    let Some(release) = config.production_usd_registry.as_ref() else {
        config.usd_issuers.clear();
        return Ok(ProductionUsdRegistryState::Unconfigured);
    };
    let supplied = ProductionUsdRegistryFloor {
        registry_version: release.registry_version,
        commitment_sha256: release.commitment_sha256.clone(),
    };
    let Some(stored) = stored else {
        write_production_usd_registry_floor(db, &supplied)?;
        return Ok(ProductionUsdRegistryState::Current);
    };
    if supplied.registry_version < stored.registry_version {
        config.usd_issuers.clear();
        return Ok(ProductionUsdRegistryState::Rollback);
    }
    if supplied.registry_version == stored.registry_version
        && supplied.commitment_sha256 != stored.commitment_sha256
    {
        config.usd_issuers.clear();
        return Ok(ProductionUsdRegistryState::Conflict);
    }
    if supplied.registry_version > stored.registry_version {
        write_production_usd_registry_floor(db, &supplied)?;
    }
    Ok(ProductionUsdRegistryState::Current)
}

fn production_usd_registry_floor_from_checkpoint(
    network: &str,
    db: &SqlitePersister,
    checkpoint_floor: Option<&ProductionUsdRegistryFloor>,
) -> Result<Option<ProductionUsdRegistryFloor>, AccountError> {
    if network != "mainnet" {
        if checkpoint_floor.is_some() {
            return Err(AccountError::new(
                "invalid_backup_checkpoint",
                "a testnet checkpoint cannot contain a production USD registry floor",
            ));
        }
        return Ok(None);
    }
    let checkpoint_floor = checkpoint_floor.ok_or_else(|| {
        AccountError::new(
            "deployment_mismatch",
            "production Secure Backup checkpoint has no registry-version floor",
        )
    })?;
    if checkpoint_floor.registry_version == 0 {
        return Err(AccountError::new(
            "invalid_backup_checkpoint",
            "production registry checkpoint version must be nonzero",
        ));
    }
    if validate_hex_32_config(
        &checkpoint_floor.commitment_sha256,
        "production registry checkpoint commitment",
    )
    .is_err()
    {
        return Err(AccountError::new(
            "invalid_backup_checkpoint",
            "production registry checkpoint commitment is malformed",
        ));
    }
    let stored = read_production_usd_registry_floor(db)?;
    if stored.as_ref().is_some_and(|stored| {
        stored.registry_version == checkpoint_floor.registry_version
            && stored.commitment_sha256 != checkpoint_floor.commitment_sha256
    }) {
        return Err(AccountError::new(
            "production_registry_conflict",
            "Secure Backup reuses a production registry version with different committed bytes",
        ));
    }
    if stored
        .as_ref()
        .is_none_or(|stored| checkpoint_floor.registry_version > stored.registry_version)
    {
        return Ok(Some(checkpoint_floor.clone()));
    }
    Ok(None)
}

fn validate_usd_issuer_policy(config: &AccountConfig) -> Result<(), AccountError> {
    validate_usd_issuer_policies(&config.usd_issuers, &config.network)
}

fn validate_usd_issuer_policies(
    issuers: &[UsdIssuerPolicy],
    network: &str,
) -> Result<(), AccountError> {
    let mut asset_ids = HashSet::new();
    for issuer in issuers {
        issuer.manifest.validate().map_err(|error| {
            AccountError::new("invalid_config", format!("USD issuer manifest: {error}"))
        })?;
        if issuer.manifest.terms.network != network {
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

fn deployment_reset_error(network: &str, message: impl Into<String>) -> AccountError {
    if matches!(network, "signet" | "regtest") {
        AccountError::new("testnet_reset_required", message)
    } else {
        AccountError::new("deployment_mismatch", message)
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

fn unix_time_millis() -> Result<i64, AccountError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| AccountError::new("clock_error", error.to_string()))
        .and_then(|duration| {
            i64::try_from(duration.as_millis())
                .map_err(|_| AccountError::new("clock_error", "timestamp exceeds SQLite range"))
        })
}

fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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

/// Protocol anchor references preserve consensus hash bytes, while Bitcoin's
/// human-readable txid parser reverses those bytes. Reconstruct the txid from
/// the stored bytes so an exact Esplora transaction is not mistaken for its
/// byte-reversed id after checkpoint restore.
fn unconfirmed_dependency_txid(value: &str) -> Result<Txid, AccountError> {
    decode_hex_32(value, "unconfirmed dependency").map(Txid::from_byte_array)
}

fn unconfirmed_dependency_key(txid: Txid) -> String {
    hex_encode(&txid.to_byte_array())
}

fn protocol_spend_preflight_required(config: &AccountConfig) -> bool {
    // This is protocol conflict detection, not an optional observation. Do
    // not let the user-selectable Off/Observe/Require presentation policy—or
    // an empty transient relay-peer list—disable rollback protection.
    #[cfg(test)]
    if config.test_skip_protocol_spend_preflight {
        return false;
    }
    matches!(config.network.as_str(), "signet" | "mainnet")
}

/// Reject a restored checkpoint whose selected OpenCSV inputs have already
/// appeared in the independently verified confirmed-chain index. This is a
/// local privacy-preserving check: raw nullifiers never leave Rust. Requiring
/// the scan to cover the funding verifier's tip prevents a stale index from
/// blessing a rollback-created duplicate spend.
fn verify_protocol_inputs_unspent(
    nullifiers: &[Digest],
    minimum_tip: u64,
    required: bool,
) -> Result<(), AccountError> {
    let confirmed_spends = confirmed_protocol_input_spends(nullifiers, minimum_tip, required)?;
    if let Some((_, location)) = confirmed_spends.first() {
        return Err(AccountError::new(
            "stale_chain_state",
            format!(
                "selected OpenCSV input was already spent at {}:{}; the wallet checkpoint is behind the verified chain",
                location.height, location.position
            ),
        ));
    }
    Ok(())
}

fn confirmed_protocol_input_spends(
    nullifiers: &[Digest],
    minimum_tip: u64,
    required: bool,
) -> Result<Vec<(Digest, opencsv_core::chain::AnchorLocation)>, AccountError> {
    if !required {
        return Ok(Vec::new());
    }
    if nullifiers.is_empty() {
        return Err(AccountError::new(
            "stale_chain_state",
            "transfer proof contains no OpenCSV input nullifiers",
        ));
    }
    let mut confirmed_spends = Vec::new();
    for nullifier in nullifiers {
        let (scan_tip, occurrence) =
            scan::registered_nullifier_occurrence(nullifier).map_err(|error| {
                AccountError::retryable(
                    "chain_verification_unavailable",
                    format!("confirmed OpenCSV spend scan is unavailable: {error}"),
                )
            })?;
        if scan_tip < minimum_tip {
            return Err(AccountError::retryable(
                "chain_verification_unavailable",
                format!(
                    "confirmed OpenCSV spend scan tip {scan_tip} is behind verified funding tip {minimum_tip}"
                ),
            ));
        }
        if let Some(location) = occurrence {
            confirmed_spends.push((*nullifier, location));
        }
    }
    Ok(confirmed_spends)
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
        RetryableReject(&'static str, &'static str),
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
                VerificationVerdict::RetryableReject(code, message) => {
                    Err(AccountError::retryable(code, message))
                }
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
            "version": SCHEMA_VERSION,
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
            "test_skip_protocol_spend_preflight": true,
        }))
        .unwrap()
    }

    #[test]
    fn esplora_accelerator_defaults_are_bounded_and_invalid_overrides_fail_closed() {
        let parsed: AccountConfig =
            serde_json::from_str(&config(AccountRole::Primary, false)).unwrap();
        assert_eq!(
            parsed.esplora_request_timeout_secs,
            DEFAULT_ESPLORA_REQUEST_TIMEOUT_SECS
        );
        assert_eq!(parsed.esplora_max_retries, DEFAULT_ESPLORA_MAX_RETRIES);
        validate_esplora_client_policy(&parsed).unwrap();

        let mut zero_timeout = parsed.clone();
        zero_timeout.esplora_request_timeout_secs = 0;
        assert_eq!(
            validate_esplora_client_policy(&zero_timeout)
                .unwrap_err()
                .code,
            "invalid_config"
        );

        let mut excessive_retries = parsed;
        excessive_retries.esplora_max_retries = 4;
        assert_eq!(
            validate_esplora_client_policy(&excessive_retries)
                .unwrap_err()
                .code,
            "invalid_config"
        );
    }

    #[test]
    fn stalled_esplora_sync_returns_retryable_without_waiting_for_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let _server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).unwrap();
            thread::sleep(Duration::from_secs(5));
        });
        let mut config_value: Value = serde_json::from_str(&config_with_url(
            AccountRole::Primary,
            false,
            &format!("http://{address}"),
        ))
        .unwrap();
        config_value["esplora_request_timeout_secs"] = json!(1);
        config_value["esplora_max_retries"] = json!(0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bounded-sync.sqlite");
        let mut wallet = AccountWallet::open(
            &config_value.to_string(),
            &[13_u8; 32],
            path.to_str().unwrap(),
        )
        .unwrap();

        let started = Instant::now();
        let error = wallet.sync().unwrap_err();
        assert_eq!(error.code, "sync_failed");
        assert!(error.retryable);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "one stalled accelerator request exceeded its configured bound"
        );
    }

    #[test]
    fn test_usd_v2_rejects_v1_config_and_preexisting_unnamespaced_database() {
        let dir = tempfile::tempdir().unwrap();
        let mut old_config: Value =
            serde_json::from_str(&config(AccountRole::Primary, false)).unwrap();
        old_config["version"] = json!(1);
        let error = AccountWallet::open_device_bound(
            &old_config.to_string(),
            &[1u8; 32],
            &[2u8; 32],
            dir.path().join("v1-config.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "testnet_reset_required");

        let legacy_path = dir.path().join("legacy.sqlite");
        drop(SqlitePersister::open(&legacy_path).unwrap());
        let error = AccountWallet::open_device_bound(
            &config(AccountRole::Primary, false),
            &[1u8; 32],
            &[2u8; 32],
            legacy_path.to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "testnet_reset_required");

        let mut fresh = AccountWallet::open_device_bound(
            &config(AccountRole::Primary, false),
            &[1u8; 32],
            &[2u8; 32],
            dir.path().join("v2.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = fresh.status().unwrap();
        assert_eq!(status["version"], SCHEMA_VERSION);
        assert_eq!(status["deployment_id"], TEST_USD_V2_DEPLOYMENT_ID);
        assert_eq!(
            fresh.db.meta("deployment_id").unwrap().as_deref(),
            Some(TEST_USD_V2_DEPLOYMENT_ID),
        );
    }

    #[test]
    fn checkpoint_reset_reason_is_network_accurate() {
        assert_eq!(
            deployment_reset_error("signet", "archived checkpoint").code,
            "testnet_reset_required"
        );
        assert_eq!(
            deployment_reset_error("regtest", "archived checkpoint").code,
            "testnet_reset_required"
        );
        assert_eq!(
            deployment_reset_error("mainnet", "archived checkpoint").code,
            "deployment_mismatch"
        );
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

    fn mainnet_usd_issuer_policy(seed_byte: u8) -> Value {
        let terms = InstrumentTermsV1 {
            version: 1,
            network: "mainnet".into(),
            display_name: "Unit-test production USD".into(),
            unit_code: "USD".into(),
            decimals: 6,
            issuer_name: "Unit-test production issuer".into(),
            terms_uri: "https://opencsv.net/unit-test-production-terms".into(),
            redemption_summary: "Synthetic manifest used only by the Rust test suite.".into(),
            test_only: false,
        };
        let genesis = AssetGenesis {
            issuer_pk: PoseidonIssuerAuthorization::public_key(&[seed_byte; 32]),
            currency_code: *b"USD",
            terms_hash: terms.terms_hash().unwrap(),
            nonce: u64::from(seed_byte) + 10_000,
        };
        json!({
            "manifest": InstrumentManifestV1 { terms, genesis },
            "priority": 0,
        })
    }

    fn mainnet_config(issuers: Vec<Value>) -> String {
        let production_usd_registry = if issuers.is_empty() {
            Value::Null
        } else {
            let issuers = issuers
                .into_iter()
                .map(|issuer| serde_json::from_value::<UsdIssuerPolicy>(issuer).unwrap())
                .collect::<Vec<_>>();
            let mut release = ProductionUsdRegistryRelease {
                format_version: PRODUCTION_USD_REGISTRY_FORMAT_VERSION,
                registry_version: 1,
                deployment_id: "opencsv-mainnet-v1-test".into(),
                issuers,
                rollout: ProductionRolloutPolicy {
                    phase: ProductionActivationPhase::Limited,
                    max_transfer_base_units: 1_000_000,
                    max_batch_total_base_units: 10_000_000,
                    max_rolling_24h_outgoing_base_units: 100_000_000,
                    max_rolling_24h_operations: 1_000,
                    max_batch_recipients: u8::try_from(MAX_LOCAL_BATCH_RECIPIENTS)
                        .unwrap_or(u8::MAX),
                    max_reserve_allocation_sats: 1_000_000,
                    max_miner_fee_sats: 100_000,
                },
                source_revision: "ab".repeat(20),
                approval_receipts: vec![
                    "https://github.com/opencsvnet/opencsv/issues/1#unit-test-approval".into(),
                ],
                commitment_sha256: "00".repeat(32),
            };
            release.commitment_sha256 = production_usd_registry_commitment(&release).unwrap();
            serde_json::to_value(release).unwrap()
        };
        serde_json::to_string(&json!({
            "version": SCHEMA_VERSION,
            "deployment_id": "opencsv-mainnet-v1-test",
            "network": "mainnet",
            "esplora_url": "https://mempool.space/api",
            "peers": ["127.0.0.1:8333", "127.0.0.2:8333"],
            "role": AccountRole::Primary,
            "backup_verified": true,
            "production_usd_registry": production_usd_registry,
            "test_skip_protocol_spend_preflight": true,
        }))
        .unwrap()
    }

    fn rewrite_mainnet_registry(
        config: &str,
        registry_version: u64,
        source_revision_byte: u8,
    ) -> String {
        rewrite_mainnet_release(config, |release| {
            release.registry_version = registry_version;
            release.source_revision = format!("{source_revision_byte:02x}").repeat(20);
        })
    }

    fn rewrite_mainnet_release(
        config: &str,
        mutate: impl FnOnce(&mut ProductionUsdRegistryRelease),
    ) -> String {
        let mut value: Value = serde_json::from_str(config).unwrap();
        let mut release = serde_json::from_value::<ProductionUsdRegistryRelease>(
            value["production_usd_registry"].clone(),
        )
        .unwrap();
        mutate(&mut release);
        release.commitment_sha256 = production_usd_registry_commitment(&release).unwrap();
        value["production_usd_registry"] = serde_json::to_value(release).unwrap();
        value.to_string()
    }

    fn open_mainnet_config_error(config: &Value, database_name: &str) -> AccountError {
        let dir = tempfile::tempdir().unwrap();
        match AccountWallet::open(
            &config.to_string(),
            &[70_u8; 32],
            dir.path().join(database_name).to_str().unwrap(),
        ) {
            Ok(_) => panic!("mainnet config unexpectedly opened"),
            Err(error) => error,
        }
    }

    #[test]
    fn mainnet_refuses_loose_or_mutated_production_registry_inputs() {
        let issuer = mainnet_usd_issuer_policy(70);

        let mut loose: Value = serde_json::from_str(&mainnet_config(Vec::new())).unwrap();
        loose["usd_issuers"] = json!([issuer.clone()]);
        let error = open_mainnet_config_error(&loose, "loose.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("versioned production registry"));

        let valid: Value =
            serde_json::from_str(&mainnet_config(vec![issuer.clone()])).unwrap();
        let mut mutated_manifest = valid.clone();
        mutated_manifest["production_usd_registry"]["issuers"][0]["priority"] = json!(9);
        let error = open_mainnet_config_error(&mutated_manifest, "manifest.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("commitment does not match"));

        let mut wrong_deployment = valid.clone();
        wrong_deployment["production_usd_registry"]["deployment_id"] =
            json!("opencsv-mainnet-other");
        let error = open_mainnet_config_error(&wrong_deployment, "deployment.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("another deployment"));

        let mut no_approval = valid.clone();
        no_approval["production_usd_registry"]["approval_receipts"] = json!([]);
        let error = open_mainnet_config_error(&no_approval, "approval.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("approval receipt"));

        let mut signet: Value = serde_json::from_str(&config(AccountRole::Primary, true)).unwrap();
        signet["production_usd_registry"] = valid["production_usd_registry"].clone();
        let error = open_mainnet_config_error(&signet, "signet.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("mainnet-only"));
    }

    #[test]
    fn headless_registry_builder_matches_account_open_and_detects_mutation() {
        let config: Value =
            serde_json::from_str(&mainnet_config(vec![mainnet_usd_issuer_policy(70)])).unwrap();
        let expected = config["production_usd_registry"].clone();
        let mut draft = expected.clone();
        draft.as_object_mut().unwrap().remove("commitment_sha256");

        let built = build_production_usd_registry_release(&draft.to_string()).unwrap();
        assert_eq!(built, expected);
        let verified = verify_production_usd_registry_release(
            &built.to_string(),
            expected["deployment_id"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(verified["structurally_valid"], true);
        assert_eq!(verified["activation_authorized"], false);
        assert_eq!(verified["issuer_count"], 1);
        assert_eq!(verified["phase"], "limited");
        assert_eq!(
            verified["commitment_sha256"],
            expected["commitment_sha256"]
        );

        let error = build_production_usd_registry_release(&expected.to_string()).unwrap_err();
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("must omit commitment"));

        let mut mutated = built;
        mutated["issuers"][0]["priority"] = json!(99);
        let error = verify_production_usd_registry_release(
            &mutated.to_string(),
            expected["deployment_id"].as_str().unwrap(),
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("commitment does not match"));

        let error = verify_production_usd_registry_release(
            &expected.to_string(),
            "opencsv-mainnet-another-deployment",
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("another deployment"));
    }

    #[test]
    fn activated_registry_rejects_empty_issuers_and_placeholder_revision() {
        let mut candidate: Value = serde_json::from_str(include_str!(
            "../examples/production_registry_candidate_draft.json"
        ))
        .unwrap();
        candidate["rollout"]["phase"] = json!("limited");
        let error = build_production_usd_registry_release(&candidate.to_string()).unwrap_err();
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("at least one exact issuer"));

        let config: Value =
            serde_json::from_str(&mainnet_config(vec![mainnet_usd_issuer_policy(70)])).unwrap();
        let mut draft = config["production_usd_registry"].clone();
        draft.as_object_mut().unwrap().remove("commitment_sha256");
        draft["source_revision"] = json!("0".repeat(40));
        let error = build_production_usd_registry_release(&draft.to_string()).unwrap_err();
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("placeholder source revision"));
    }

    #[test]
    fn production_registry_status_exposes_the_exact_release_identity() {
        let config = mainnet_config(vec![mainnet_usd_issuer_policy(70)]);
        let config_value: Value = serde_json::from_str(&config).unwrap();
        let configured_commitment = config_value["production_usd_registry"]
            ["commitment_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[70_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        assert_eq!(status["production_usd_configured"], true);
        assert_eq!(status["production_usd_registry"]["format_version"], 1);
        assert_eq!(status["production_usd_registry"]["registry_version"], 1);
        assert_eq!(
            status["production_usd_registry"]["deployment_id"],
            "opencsv-mainnet-v1-test"
        );
        assert_eq!(status["production_usd_registry"]["issuer_count"], 1);
        assert_eq!(
            status["production_usd_registry"]["commitment_sha256"],
            configured_commitment
        );

        let release = wallet.config.production_usd_registry.as_ref().unwrap();
        assert_eq!(
            production_usd_registry_commitment(release).unwrap(),
            configured_commitment
        );
        let mut changed = release.clone();
        changed.registry_version += 1;
        assert_ne!(
            production_usd_registry_commitment(&changed).unwrap(),
            configured_commitment
        );
    }

    #[test]
    fn candidate_registry_is_reviewable_but_cannot_create_bitcoin_writes() {
        let config = rewrite_mainnet_release(
            &mainnet_config(vec![mainnet_usd_issuer_policy(84)]),
            |release| release.rollout.phase = ProductionActivationPhase::Candidate,
        );
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[84_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = wallet.status().unwrap();
        assert_eq!(status["production_usd_configured"], true);
        assert_eq!(status["production_activation_write_ready"], false);
        assert_eq!(
            status["production_usd_registry"]["rollout"]["phase"],
            "candidate"
        );
        assert_eq!(
            status["write_block_reason"],
            "production_activation_not_authorized"
        );
        let error = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "production_activation_not_authorized");
    }

    #[test]
    fn production_rollout_limits_gate_new_solo_and_batch_intents() {
        let config = rewrite_mainnet_release(
            &mainnet_config(vec![mainnet_usd_issuer_policy(85)]),
            |release| {
                release.rollout.max_transfer_base_units = 10;
                release.rollout.max_batch_total_base_units = 12;
                release.rollout.max_rolling_24h_outgoing_base_units = 100;
                release.rollout.max_rolling_24h_operations = 10;
                release.rollout.max_batch_recipients = 2;
                release.rollout.max_reserve_allocation_sats = 100_000;
                release.rollout.max_miner_fee_sats = 5_000;
            },
        );
        let mut config_value: Value = serde_json::from_str(&config).unwrap();
        config_value["max_fee_sats"] = json!(50_000);
        let config = config_value.to_string();
        let asset_id = hex_encode(
            serde_json::from_value::<ProductionUsdRegistryRelease>(
                config_value["production_usd_registry"].clone(),
            )
            .unwrap()
            .issuers[0]
                .manifest
                .genesis
                .asset_id()
                .as_bytes(),
        );
        let request = |amount: u64, owner: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[owner; 32]),
                "amount": amount,
            })
            .to_string()
        };
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[85_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(wallet.config.max_fee_sats, Some(5_000));

        let error = wallet.transfer_plan(&request(11, 1)).unwrap_err();
        assert_eq!(error.code, "production_value_limit_exceeded");

        let first = wallet.transfer_batch_plan(&request(7, 2)).unwrap();
        let batch_id = first["batch"]["batch_local_id"].as_str().unwrap();
        let error = wallet
            .transfer_batch_add_recipient(batch_id, &request(6, 3))
            .unwrap_err();
        assert_eq!(error.code, "production_value_limit_exceeded");
        wallet
            .transfer_batch_add_recipient(batch_id, &request(5, 3))
            .unwrap();
        let error = wallet
            .transfer_batch_add_recipient(batch_id, &request(1, 4))
            .unwrap_err();
        assert_eq!(error.code, "production_batch_limit_exceeded");
    }

    #[test]
    fn production_rolling_limits_count_only_live_or_released_intents() {
        let config = rewrite_mainnet_release(
            &mainnet_config(vec![mainnet_usd_issuer_policy(86)]),
            |release| {
                release.rollout.max_transfer_base_units = 10;
                release.rollout.max_batch_total_base_units = 10;
                release.rollout.max_rolling_24h_outgoing_base_units = 20;
                release.rollout.max_rolling_24h_operations = 2;
            },
        );
        let config_value: Value = serde_json::from_str(&config).unwrap();
        let release = serde_json::from_value::<ProductionUsdRegistryRelease>(
            config_value["production_usd_registry"].clone(),
        )
        .unwrap();
        let asset_id = hex_encode(release.issuers[0].manifest.genesis.asset_id().as_bytes());
        let request = |amount: u64, owner: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[owner; 32]),
                "amount": amount,
            })
            .to_string()
        };
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[86_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let first = wallet.transfer_plan(&request(10, 1)).unwrap();
        wallet.transfer_plan(&request(10, 2)).unwrap();
        let error = wallet.transfer_plan(&request(1, 3)).unwrap_err();
        assert_eq!(error.code, "production_operation_limit_exceeded");

        wallet
            .cancel_operation(first["operation_id"].as_str().unwrap())
            .unwrap();
        wallet.transfer_plan(&request(1, 3)).unwrap();
        let error = wallet.transfer_plan(&request(10, 4)).unwrap_err();
        assert_eq!(error.code, "production_operation_limit_exceeded");
    }

    #[test]
    fn production_rollout_rechecks_unsigned_operations_before_signing() {
        let config = mainnet_config(vec![mainnet_usd_issuer_policy(88)]);
        let config_value: Value = serde_json::from_str(&config).unwrap();
        let release = serde_json::from_value::<ProductionUsdRegistryRelease>(
            config_value["production_usd_registry"].clone(),
        )
        .unwrap();
        let asset_id = hex_encode(release.issuers[0].manifest.genesis.asset_id().as_bytes());
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[88_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let planned = wallet
            .transfer_plan(
                &json!({
                    "asset_id": asset_id,
                    "to_owner": hex_encode(&[89_u8; 32]),
                    "amount": 10,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'proof_ready', backup_acked = 1
                 WHERE operation_id = ?1",
                [operation_id],
            )
            .unwrap();
        wallet
            .config
            .production_usd_registry
            .as_mut()
            .unwrap()
            .rollout
            .max_transfer_base_units = 5;

        let error = wallet
            .sign_and_broadcast(operation_id, r#"{"target_sat_per_vb":1}"#)
            .unwrap_err();
        assert_eq!(error.code, "production_value_limit_exceeded");
        assert_eq!(
            wallet.operation(operation_id).unwrap().state,
            OperationState::Cancelled.as_str()
        );
    }

    #[test]
    fn signed_production_fee_authorization_survives_registry_changes() {
        let signet_dir = tempfile::tempdir().unwrap();
        let signet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[90_u8; 32],
            signet_dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            signet
                .signed_fee_limit(&json!({}), "legacy-signet-operation")
                .unwrap(),
            None
        );

        let config = rewrite_mainnet_release(
            &mainnet_config(vec![mainnet_usd_issuer_policy(89)]),
            |release| release.rollout.max_miner_fee_sats = 5_000,
        );
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config,
            &[89_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            wallet
                .signed_fee_limit(&json!({}), "operation-89")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
        let mut receipt = json!({});
        wallet
            .stamp_production_rollout_authorization(&mut receipt, "operation-89")
            .unwrap();
        assert_eq!(
            receipt["production_rollout_authorization"]["release"]["rollout"]
                ["max_miner_fee_sats"],
            5_000
        );
        assert_eq!(
            receipt["production_rollout_authorization"]["signature_compact"]
                .as_str()
                .unwrap()
                .len(),
            128
        );
        let reopened = AccountWallet::open(
            &config,
            &[89_u8; 32],
            dir.path().join("reopened.sqlite").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            reopened
                .signed_fee_limit(&receipt, "operation-89")
                .unwrap(),
            Some(5_000)
        );
        assert_eq!(
            wallet
                .signed_fee_limit(&receipt, "another-operation")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
        let mut missing_signature = receipt.clone();
        missing_signature["production_rollout_authorization"]
            .as_object_mut()
            .unwrap()
            .remove("signature_compact");
        assert_eq!(
            wallet
                .signed_fee_limit(&missing_signature, "operation-89")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
        let mut malformed_signature = receipt.clone();
        malformed_signature["production_rollout_authorization"]["signature_compact"] =
            json!("00");
        assert_eq!(
            wallet
                .signed_fee_limit(&malformed_signature, "operation-89")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
        wallet.config.max_fee_sats = Some(1_000);
        wallet
            .config
            .production_usd_registry
            .as_mut()
            .unwrap()
            .rollout
            .max_miner_fee_sats = 1_000;
        assert_eq!(
            wallet.signed_fee_limit(&receipt, "operation-89").unwrap(),
            Some(5_000)
        );
        wallet.config.max_fee_sats = Some(50_000);
        assert_eq!(
            wallet.signed_fee_limit(&receipt, "operation-89").unwrap(),
            Some(5_000)
        );
        let mut self_consistent_forgery = receipt.clone();
        let mut forged_release = serde_json::from_value::<ProductionUsdRegistryRelease>(
            self_consistent_forgery["production_rollout_authorization"]["release"].clone(),
        )
        .unwrap();
        forged_release.rollout.max_miner_fee_sats = 50_000;
        forged_release.commitment_sha256 =
            production_usd_registry_commitment(&forged_release).unwrap();
        self_consistent_forgery["production_rollout_authorization"]["release"] =
            serde_json::to_value(forged_release).unwrap();
        assert_eq!(
            wallet
                .signed_fee_limit(&self_consistent_forgery, "operation-89")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
        receipt["production_rollout_authorization"]["release"]["rollout"]
            ["max_miner_fee_sats"] = json!(50_000);
        assert_eq!(
            wallet
                .signed_fee_limit(&receipt, "operation-89")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
    }

    #[test]
    fn malformed_production_rollout_policy_is_not_an_activation_release() {
        let config = rewrite_mainnet_release(
            &mainnet_config(vec![mainnet_usd_issuer_policy(87)]),
            |release| {
                release.rollout.max_transfer_base_units = 11;
                release.rollout.max_batch_total_base_units = 10;
            },
        );
        let value: Value = serde_json::from_str(&config).unwrap();
        let error = open_mainnet_config_error(&value, "rollout.sqlite");
        assert_eq!(error.code, "invalid_config");
        assert!(error.message.contains("transfer limit"));
    }

    #[test]
    fn production_registry_version_floor_blocks_rollback_without_hiding_status() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("wallet.sqlite");
        let v1 = mainnet_config(vec![mainnet_usd_issuer_policy(81)]);
        let v2 = rewrite_mainnet_registry(&v1, 2, 0xcd);

        let mut current = AccountWallet::open(&v2, &[81_u8; 32], database.to_str().unwrap())
            .unwrap();
        let current_status = current.status().unwrap();
        assert_eq!(current_status["production_usd_registry_state"], "current");
        assert_eq!(
            current_status["production_usd_registry_floor"]["registry_version"],
            2
        );
        drop(current);

        let mut rollback = AccountWallet::open(&v1, &[81_u8; 32], database.to_str().unwrap())
            .unwrap();
        let rollback_status = rollback.status().unwrap();
        assert_eq!(
            rollback_status["production_usd_registry_state"],
            "rollback"
        );
        assert_eq!(rollback_status["production_usd_configured"], false);
        assert_eq!(rollback_status["write_enabled"], false);
        assert_eq!(
            rollback_status["write_block_reason"],
            "production_registry_rollback"
        );
        assert_eq!(
            rollback_status["production_usd_registry_floor"]["registry_version"],
            2
        );
        let error = rollback
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "production_registry_rollback");
    }

    #[test]
    fn production_registry_rejects_same_version_with_different_commitment() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("wallet.sqlite");
        let original = mainnet_config(vec![mainnet_usd_issuer_policy(82)]);
        let conflicting = rewrite_mainnet_registry(&original, 1, 0xef);

        drop(
            AccountWallet::open(&original, &[82_u8; 32], database.to_str().unwrap()).unwrap(),
        );
        let mut wallet =
            AccountWallet::open(&conflicting, &[82_u8; 32], database.to_str().unwrap()).unwrap();
        let status = wallet.status().unwrap();
        assert_eq!(status["production_usd_registry_state"], "conflict");
        assert_eq!(status["write_block_reason"], "production_registry_conflict");
        assert_eq!(status["production_usd_configured"], false);
    }

    #[test]
    fn secure_backup_carries_the_registry_floor_across_a_clean_restore() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = mainnet_config(vec![mainnet_usd_issuer_policy(83)]);
        let v2 = rewrite_mainnet_registry(&v1, 2, 0x12);
        let source = AccountWallet::open(
            &v2,
            &[83_u8; 32],
            dir.path().join("source.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let checkpoint = source.checkpoint().unwrap();
        assert_eq!(
            checkpoint["checkpoint"]["production_usd_registry_floor"]["registry_version"],
            2
        );

        let mut restored = AccountWallet::open(
            &v1,
            &[83_u8; 32],
            dir.path().join("restored.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        assert_eq!(status["production_usd_registry_state"], "rollback");
        assert_eq!(status["write_block_reason"], "production_registry_rollback");
        assert_eq!(
            status["production_usd_registry_floor"]["registry_version"],
            2
        );
    }

    #[test]
    fn mainnet_without_reviewed_product_is_read_only_and_cannot_create_reserves() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &mainnet_config(Vec::new()),
            &[71_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        assert_eq!(status["network"], "mainnet");
        assert_eq!(status["key_derivation_id"], MAINNET_KEY_DERIVATION_ID);
        assert_eq!(status["production_usd_configured"], false);
        assert_eq!(status["production_observation_policy_ready"], true);
        assert_eq!(status["write_enabled"], false);
        assert_eq!(
            status["write_block_reason"],
            "production_usd_not_configured"
        );

        let error = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "production_usd_not_configured");
        let error = wallet
            .transfer_plan(
                &json!({
                    "asset_id": hex_encode(&[0_u8; 32]),
                    "to_owner": hex_encode(&[1_u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "production_usd_not_configured");

        let created = wallet
            .instrument_create(
                &json!({
                    "terms": {
                        "version": 1,
                        "network": "mainnet",
                        "display_name": "Unit-test production USD",
                        "unit_code": "USD",
                        "decimals": 6,
                        "issuer_name": "Unit-test production issuer",
                        "terms_uri": "https://opencsv.net/unit-test-production-terms",
                        "redemption_summary": "Synthetic manifest used only by the Rust test suite.",
                        "test_only": false
                    }
                })
                .to_string(),
            )
            .unwrap();
        assert_eq!(created["backup_required"], true);
    }

    #[test]
    fn mainnet_issuer_tool_fails_closed_without_authenticated_supply_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &mainnet_config(Vec::new()),
            &[72_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let prepare_error = wallet
            .mint_prepare(
                &json!({
                    "asset_id": hex_encode(&[3_u8; 32]),
                    "amounts": [1],
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(prepare_error.code, "production_issuance_not_authorized");

        // A stale proof-ready row from an older binary must not turn the
        // signing boundary into a bypass after this gate is introduced.
        wallet
            .insert_planned_operation(
                "pre-gate-mainnet-mint",
                "mint",
                &json!({
                    "asset_id": hex_encode(&[3_u8; 32]),
                    "amounts": [1],
                })
                .to_string(),
                "pre-gate-delivery-nonce",
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'proof_ready', backup_acked = 1
                 WHERE operation_id = 'pre-gate-mainnet-mint'",
                [],
            )
            .unwrap();
        let signing_error = wallet
            .sign_and_broadcast(
                "pre-gate-mainnet-mint",
                &json!({ "target_sat_per_vb": 1 }).to_string(),
            )
            .unwrap_err();
        assert_eq!(signing_error.code, "production_issuance_not_authorized");

        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'signed_persisted', signed_tx_hex = '00'
                 WHERE operation_id = 'pre-gate-mainnet-mint'",
                [],
            )
            .unwrap();
        let resume_error = wallet
            .resume_operation("pre-gate-mainnet-mint")
            .unwrap_err();
        assert_eq!(resume_error.code, "production_issuance_not_authorized");

        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'broadcast_unobserved'
                 WHERE operation_id = 'pre-gate-mainnet-mint'",
                [],
            )
            .unwrap();
        let fee_bump_error = wallet
            .fee_bump("pre-gate-mainnet-mint", 2)
            .unwrap_err();
        assert_eq!(fee_bump_error.code, "production_issuance_not_authorized");
    }

    #[test]
    fn mainnet_resume_rejects_missing_signed_authorization_before_network_io() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &mainnet_config(vec![mainnet_usd_issuer_policy(73)]),
            &[73_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        wallet
            .insert_planned_operation(
                "pre-gate-solo",
                "transfer",
                &json!({
                    "asset_id": hex_encode(&[4_u8; 32]),
                    "to_owner": hex_encode(&[5_u8; 32]),
                    "amount": 1,
                })
                .to_string(),
                "pre-gate-solo-delivery",
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'signed_persisted', signed_tx_hex = '00',
                     receipt_json = '{}'
                 WHERE operation_id = 'pre-gate-solo'",
                [],
            )
            .unwrap();
        assert_eq!(
            wallet.resume_operation("pre-gate-solo").unwrap_err().code,
            "database_corrupt"
        );

        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_send_batches(
                     batch_local_id, state, deadline_ms, participant_count,
                     signed_tx_hex, txid, receipt_json, created_at, updated_at
                 ) VALUES(
                     'pre-gate-batch', 'signed_persisted', 0, 2,
                     '00', '00', '{}', 0, 0
                 )",
                [],
            )
            .unwrap();
        assert_eq!(
            wallet.resume_send_batch("pre-gate-batch").unwrap_err().code,
            "database_corrupt"
        );

        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_batch_reserve_operations(
                     maintenance_id, state, participant_count, stock_count,
                     fee_cell_count, signed_tx_hex, txid, receipt_json,
                     created_at, updated_at
                 ) VALUES(
                     'pre-gate-reserve', 'signed_persisted', 2, 3,
                     6, '00', '00', '{}', 0, 0
                 )",
                [],
            )
            .unwrap();
        assert_eq!(
            wallet
                .resume_batch_reserves("pre-gate-reserve")
                .unwrap_err()
                .code,
            "database_corrupt"
        );
    }

    #[test]
    fn fresh_mainnet_defaults_require_two_pinned_observers_and_chain_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &mainnet_config(Vec::new()),
            &[74_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        let policy = status["observation_policy"].as_array().unwrap();
        assert_eq!(policy.len(), 5);
        assert_eq!(policy[0]["id"], "mempool_space_mainnet");
        assert_eq!(policy[0]["endpoint"], "https://mempool.space/api");
        assert_eq!(policy[0]["mode"], "require");
        assert_eq!(policy[0]["pin_profile"], "sectigo_r46");
        assert_eq!(
            policy[0]["chain_fingerprints_sha256"],
            json!(MEMPOOL_SPACE_CHAIN_PINS)
        );
        assert_eq!(policy[1]["id"], "blockstream_mainnet");
        assert_eq!(policy[1]["endpoint"], "https://blockstream.info/api");
        assert_eq!(policy[1]["mode"], "require");
        assert_eq!(policy[1]["pin_profile"], "lets_encrypt_yr");
        assert_eq!(
            policy[1]["chain_fingerprints_sha256"],
            json!(BLOCKSTREAM_CHAIN_PINS)
        );
        assert_eq!(policy[2]["kind"], "direct_p2p_relay");
        assert_eq!(policy[2]["mode"], "observe");
        assert_eq!(policy[4]["kind"], "confirmed_spv");
        assert_eq!(policy[4]["mode"], "observe");
        assert_eq!(status["required_raw_observer_quorum"], 2);
        assert_eq!(status["production_observation_policy_ready"], true);
    }

    #[test]
    fn mainnet_product_writes_fail_closed_under_a_downgraded_observer_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: Value =
            serde_json::from_str(&mainnet_config(vec![mainnet_usd_issuer_policy(75)])).unwrap();
        config["observation_checks"] = json!([{
            "id": "mainnet_read_accelerator",
            "kind": "raw_transaction_api",
            "endpoint": "https://mempool.space/api",
            "mode": "observe"
        }]);
        let mut wallet = AccountWallet::open(
            &config.to_string(),
            &[76_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        assert_eq!(status["production_usd_configured"], true);
        assert_eq!(status["production_observation_policy_ready"], false);
        assert_eq!(status["write_enabled"], false);
        assert_eq!(
            status["write_block_reason"],
            "production_observation_policy_required"
        );
        let error = wallet
            .transfer_plan(
                &json!({
                    "asset_id": hex_encode(&[0_u8; 32]),
                    "to_owner": hex_encode(&[1_u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "production_observation_policy_required");
    }

    #[test]
    fn mainnet_observer_independence_is_keyed_by_host_not_url_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: Value =
            serde_json::from_str(&mainnet_config(vec![mainnet_usd_issuer_policy(77)])).unwrap();
        config["observation_checks"] = json!([
            {
                "id": "same_host_one",
                "kind": "raw_transaction_api",
                "endpoint": "https://observer.example/api",
                "mode": "require",
                "chain_fingerprints_sha256": ["11".repeat(32)]
            },
            {
                "id": "same_host_two",
                "kind": "raw_transaction_api",
                "endpoint": "https://observer.example/api/",
                "mode": "require",
                "chain_fingerprints_sha256": ["22".repeat(32)]
            },
            {
                "id": "direct_p2p_relay",
                "kind": "direct_p2p_relay",
                "mode": "observe"
            },
            {
                "id": "multi_peer_spv_confirmation",
                "kind": "confirmed_spv",
                "mode": "observe"
            }
        ]);
        let mut wallet = AccountWallet::open(
            &config.to_string(),
            &[78_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        assert_eq!(status["required_raw_observer_quorum"], 2);
        assert_eq!(status["production_observation_policy_ready"], false);
        assert_eq!(
            status["write_block_reason"],
            "production_observation_policy_required"
        );
    }

    #[test]
    fn mainnet_product_requires_two_distinct_confirmed_chain_peers() {
        let dir = tempfile::tempdir().unwrap();
        let mut config: Value =
            serde_json::from_str(&mainnet_config(vec![mainnet_usd_issuer_policy(79)])).unwrap();
        config["peers"] = json!(["127.0.0.1:8333", "127.0.0.1:8333"]);
        let mut wallet = AccountWallet::open(
            &config.to_string(),
            &[80_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let status = wallet.status().unwrap();
        assert_eq!(status["production_observation_policy_ready"], false);
        assert_eq!(
            status["write_block_reason"],
            "production_observation_policy_required"
        );
    }

    #[test]
    fn mainnet_product_uses_a_distinct_deployment_scoped_key_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let account_root = [72_u8; 32];
        let mut mainnet = AccountWallet::open(
            &mainnet_config(vec![mainnet_usd_issuer_policy(73)]),
            &account_root,
            dir.path().join("mainnet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let mut signet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &account_root,
            dir.path().join("signet.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let mainnet_status = mainnet.status().unwrap();
        let signet_status = signet.status().unwrap();
        assert_eq!(mainnet_status["production_usd_configured"], true);
        assert_eq!(mainnet_status["production_observation_policy_ready"], true);
        assert_eq!(mainnet_status["write_enabled"], true);
        assert_eq!(mainnet_status["write_block_reason"], Value::Null);
        let error = mainnet
            .transfer_plan(
                &json!({
                    "asset_id": hex_encode(&[0_u8; 32]),
                    "to_owner": hex_encode(&[1_u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap_err();
        assert_eq!(error.code, "asset_not_reviewed");
        assert_eq!(signet_status["key_derivation_id"], TEST_KEY_DERIVATION_ID);
        assert_ne!(
            mainnet_status["root_fingerprint"],
            signet_status["root_fingerprint"]
        );
        assert_ne!(
            mainnet_status["watch_descriptors"],
            signet_status["watch_descriptors"]
        );
        assert_eq!(
            mainnet_status["deposit_address"],
            "bc1q3k8nh9ercxsfn4d8ws9yqw97xhe7v9qag0r4wu"
        );
        assert_eq!(
            mainnet_status["owners"],
            json!(["4a7a9963d33fff574983f411bc67394f76c4a15df73fc6407251972b615f4048"])
        );
        assert_eq!(
            mainnet_status["root_fingerprint"],
            "58c5148de26407b859a24a5c89ed75186fb176028d999e198f781e75c2eba257"
        );
        assert_eq!(
            mainnet_status["device_binding"]["commitment"],
            "4858228fcc016f7e0150c70f9721d2357734475a47c8ea151239ef42a953d87b"
        );
        assert_eq!(
            mainnet_status["watch_descriptors"]["external"],
            "wpkh([45205f1f/84'/0'/0']xpub6D6NYN7PdZPEvXaGFnodfdCatyj6y6JbmeGzKAyXRDPARpKma6qNBpGW6Waky1s9WxgYYiZQnEcbVbsbf8qfcnFUnbahSL9BMxuVtWWHxqr/0/*)#ugdujupu"
        );
        assert_eq!(
            mainnet_status["watch_descriptors"]["internal"],
            "wpkh([45205f1f/84'/0'/0']xpub6D6NYN7PdZPEvXaGFnodfdCatyj6y6JbmeGzKAyXRDPARpKma6qNBpGW6Waky1s9WxgYYiZQnEcbVbsbf8qfcnFUnbahSL9BMxuVtWWHxqr/1/*)#duga0f3y"
        );
    }

    #[test]
    fn pre_v1_mainnet_database_and_checkpoint_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let config = mainnet_config(vec![mainnet_usd_issuer_policy(74)]);
        let database_path = dir.path().join("archived-mainnet.sqlite");
        let archived = AccountWallet::open(
            &config,
            &[75_u8; 32],
            database_path.to_str().unwrap(),
        )
        .unwrap();
        archived.db.delete_meta("key_derivation_id").unwrap();
        drop(archived);

        let error = AccountWallet::open(
            &config,
            &[75_u8; 32],
            database_path.to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "deployment_mismatch");

        let source = AccountWallet::open(
            &config,
            &[76_u8; 32],
            dir.path().join("checkpoint-source.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let mut envelope = source.checkpoint().unwrap();
        envelope["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("key_derivation_id");
        let canonical = serde_json::to_vec(&envelope["checkpoint"]).unwrap();
        envelope["checkpoint_hash"] = json!(sha256::Hash::hash(&canonical).to_string());
        let mut target = AccountWallet::open(
            &config,
            &[76_u8; 32],
            dir.path().join("checkpoint-target.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let error = target.restore_checkpoint(&envelope.to_string()).unwrap_err();
        assert_eq!(error.code, "deployment_mismatch");
    }

    #[test]
    fn signet_v4_checkpoint_without_derivation_id_remains_restore_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let config = config(AccountRole::Primary, true);
        let source = AccountWallet::open(
            &config,
            &[77_u8; 32],
            dir.path().join("signet-source.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let mut envelope = source.checkpoint().unwrap();
        envelope["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("key_derivation_id");
        let canonical = serde_json::to_vec(&envelope["checkpoint"]).unwrap();
        envelope["checkpoint_hash"] = json!(sha256::Hash::hash(&canonical).to_string());
        let mut target = AccountWallet::open(
            &config,
            &[77_u8; 32],
            dir.path().join("signet-target.sqlite").to_str().unwrap(),
        )
        .unwrap();

        let restored = target.restore_checkpoint(&envelope.to_string()).unwrap();
        assert_eq!(restored["network"], "signet");
    }

    #[test]
    fn signet_v2_key_derivation_matches_golden() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[78_u8; 32],
            dir.path().join("signet-golden.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let status = wallet.status().unwrap();
        assert_eq!(status["key_derivation_id"], TEST_KEY_DERIVATION_ID);
        assert_eq!(
            status["deposit_address"],
            "tb1qrtcjuqxddr3wvv70qn9azhskkl3rwkxctmpl03"
        );
        assert_eq!(
            status["owners"],
            json!(["f7cfee0897fcd470798c0a02c5a6e6732d80726b4b38ae3ed1dcf05299884463"])
        );
        assert_eq!(
            status["root_fingerprint"],
            "4c269d8eb2fb9b6eeeb1aaae15613ff30ca94ade92e5235ec522c321066c98ed"
        );
        assert_eq!(
            status["device_binding"]["commitment"],
            "59447ed49fcd993031a70e35f8c7d3b92ae725cdbb2bb271c0eac75a2b49f6df"
        );
        assert_eq!(
            status["watch_descriptors"]["external"],
            "wpkh([002621f1/84'/1'/0']tpubDD5Yb8gahcpKpgo4tLEZySBhEuLvc5ucEKfQcheSeNgwjsHEFGe1kynLdHBhAks7szaijc8757Tn8Wbi5SzcXKHGcbBdoGgDNXGnxpxRZUp/0/*)#6uhuhwww"
        );
        assert_eq!(
            status["watch_descriptors"]["internal"],
            "wpkh([002621f1/84'/1'/0']tpubDD5Yb8gahcpKpgo4tLEZySBhEuLvc5ucEKfQcheSeNgwjsHEFGe1kynLdHBhAks7szaijc8757Tn8Wbi5SzcXKHGcbBdoGgDNXGnxpxRZUp/1/*)#tgja2m7k"
        );
    }

    #[test]
    fn account_cross_check_preserves_tip_disagreement_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[49_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = json!({
            "backends": [
                {"type": "snapshot", "snapshot": {"tip_height": 50, "entries": []}},
                {"type": "snapshot", "snapshot": {"tip_height": 51, "entries": []}},
            ],
            "consignment_base64": "",
            "required_confirmations": 6,
        });

        let verdict = wallet.cross_check(&request.to_string()).unwrap();

        assert_eq!(verdict["kind"], "tip_disagreement");
        assert_eq!(verdict["tips"], json!([50, 51]));
    }

    #[test]
    fn protocol_spend_preflight_is_independent_of_observation_mode() {
        let mut value: Value = serde_json::from_str(&config(AccountRole::Primary, true)).unwrap();
        value["peers"] = json!(["127.0.0.1:38333"]);
        value["verification_peers"] = json!(["127.0.0.2:38333"]);
        value["observation_checks"] = json!([{
            "id": "multi_peer_spv_confirmation",
            "kind": "confirmed_spv",
            "mode": "off",
        }]);
        value["test_skip_protocol_spend_preflight"] = json!(false);
        let config: AccountConfig = serde_json::from_value(value).unwrap();

        assert!(protocol_spend_preflight_required(&config));
    }

    #[test]
    fn mint_pre_sign_does_not_require_transfer_nullifiers() {
        let dir = tempfile::tempdir().unwrap();
        let mut value: Value = serde_json::from_str(&config(AccountRole::Primary, true)).unwrap();
        value["test_skip_protocol_spend_preflight"] = json!(false);
        let mut wallet = AccountWallet::open(
            &value.to_string(),
            &[48_u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 50_000);
        let prepared = prepare_test_issuance(&mut wallet, "TMN", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap();
        wallet
            .acknowledge_operation_backup(
                operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();

        let broadcast = wallet
            .sign_and_broadcast(
                operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();

        assert_eq!(
            broadcast["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        assert!(wallet
            .operation(operation_id)
            .unwrap()
            .signed_tx_hex
            .is_some());
    }

    fn reviewed_test_config(seed_byte: u8) -> (String, String) {
        let policy = test_usd_issuer_policy(seed_byte, "OpenCSV reviewed test issuer", 0);
        let manifest =
            serde_json::from_value::<InstrumentManifestV1>(policy["manifest"].clone()).unwrap();
        let asset_id = hex_encode(manifest.genesis.asset_id().as_bytes());
        (config_with_usd_issuers(vec![policy]), asset_id)
    }

    fn create_test_instrument(wallet: &mut AccountWallet, unit_code: &str) -> String {
        let created = wallet
            .instrument_create(&test_instrument_request(unit_code))
            .unwrap();
        assert_eq!(created["backup_required"], true);
        if unit_code == "USD" {
            let manifest =
                serde_json::from_value::<InstrumentManifestV1>(created["manifest"].clone())
                    .unwrap();
            wallet.config.usd_issuers.push(UsdIssuerPolicy {
                manifest,
                priority: 0,
            });
        }
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

    #[test]
    fn self_mint_settlement_routes_through_the_wallet_ownership_scan() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[94u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 20_000);
        let minted = prepare_test_issuance(&mut wallet, "SLF", &[100]).unwrap();
        let operation_id = minted["operation_id"].as_str().unwrap().to_owned();
        let operation = wallet.operation(&operation_id).unwrap();
        assert!(wallet.mint_recipient_is_self_owned(&operation).unwrap());

        let external_owner = hex_encode(&[95u8; 32]);
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET request_json = ?2 WHERE operation_id = ?1",
                params![
                    operation_id,
                    json!({
                        "asset_id": minted["asset_id"],
                        "to_owner": external_owner,
                        "amounts": [100],
                    })
                    .to_string(),
                ],
            )
            .unwrap();
        let external = wallet.operation(&operation_id).unwrap();
        assert!(!wallet.mint_recipient_is_self_owned(&external).unwrap());
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

    #[test]
    fn unconfirmed_dependency_reconstructs_consensus_txid_bytes() {
        let transaction = Transaction {
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
        let expected = transaction.compute_txid();
        let dependency = hex_encode(&expected.to_byte_array());

        assert_eq!(unconfirmed_dependency_key(expected), dependency);
        assert_eq!(unconfirmed_dependency_txid(&dependency).unwrap(), expected);
        assert_ne!(dependency.parse::<Txid>().unwrap(), expected);
    }

    #[test]
    fn fresh_dependency_reobservation_skips_a_second_network_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &[71u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let dependency = unconfirmed_dependency_key(Txid::from_byte_array([72u8; 32]));

        wallet
            .persist_dependency_reobservation(&dependency, unix_time().unwrap())
            .unwrap();
        wallet
            .reobserve_unconfirmed_dependencies(std::slice::from_ref(&dependency))
            .unwrap();

        wallet
            .persist_dependency_reobservation(&dependency, unix_time().unwrap() - 121)
            .unwrap();
        assert_eq!(
            wallet
                .reobserve_unconfirmed_dependencies(&[dependency])
                .unwrap_err()
                .code,
            "unconfirmed_dependency_unavailable"
        );
    }

    #[test]
    fn freezing_consensus_dependency_updates_display_txid_finality() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[73u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let txid = Txid::from_byte_array([74u8; 32]);
        let dependency = unconfirmed_dependency_key(txid);
        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_consignments(
                     consignment_id, consignment_base64, spent_state_json, created_at
                 ) VALUES('dependency-test', '', '{}', 1)",
                [],
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_consignment_finality(
                     consignment_id, anchor_txid, finality, observed_at,
                     last_checked_at, last_error
                 ) VALUES('dependency-test', ?1, 'unconfirmed', 1, 1, NULL)",
                [txid.to_string()],
            )
            .unwrap();

        wallet
            .freeze_unconfirmed_dependency(&dependency, "parent disappeared")
            .unwrap();
        let (finality, reason): (String, Option<String>) = wallet
            .db
            .conn
            .query_row(
                "SELECT finality, last_error FROM opencsv_consignment_finality
                 WHERE consignment_id = 'dependency-test'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(finality, "frozen");
        assert_eq!(reason.as_deref(), Some("parent disappeared"));
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

    fn inspection_consignment(asset_ids: impl IntoIterator<Item = AssetId>) -> Consignment {
        Consignment {
            coin_openings: asset_ids
                .into_iter()
                .enumerate()
                .map(|(index, asset_id)| opencsv_core::consignment::CoinOpening {
                    asset_id,
                    value: u64::try_from(index + 1).unwrap(),
                    owner: Digest::from_bytes([2; 32]),
                    randomness: Digest::from_bytes([3; 32]),
                })
                .collect(),
            nullifiers: Vec::new(),
            proof: Vec::new(),
            anchor_ref: AnchorRef {
                txid: [4; 32],
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        }
    }

    #[test]
    fn consignment_inspection_admits_only_exact_reviewed_asset_ids() {
        let dir = tempfile::tempdir().unwrap();
        let (reviewed_config, reviewed_asset_id) = reviewed_test_config(19);
        let wallet = AccountWallet::open(
            &reviewed_config,
            &[20; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let reviewed_asset =
            AssetId::from_bytes(decode_hex_32(&reviewed_asset_id, "reviewed asset id").unwrap());

        let reviewed = wallet
            .inspect_consignment(&inspection_consignment([reviewed_asset]).to_bytes())
            .unwrap();
        assert_eq!(reviewed["asset_ids"], json!([reviewed_asset_id]));
        assert_eq!(reviewed["all_assets_reviewed"], true);
        assert_eq!(reviewed["unreviewed_asset_ids"], json!([]));
        assert_eq!(reviewed["rejection_reason"], Value::Null);

        let unreviewed_asset = AssetId::from_bytes([1; 32]);
        let unreviewed_asset_id = hex_encode(unreviewed_asset.as_bytes());
        let mixed = wallet
            .inspect_consignment(
                &inspection_consignment([reviewed_asset, unreviewed_asset]).to_bytes(),
            )
            .unwrap();
        let inspected_asset_ids = mixed["asset_ids"].as_array().unwrap();
        assert!(inspected_asset_ids.contains(&json!(reviewed_asset_id)));
        assert!(inspected_asset_ids.contains(&json!(unreviewed_asset_id)));
        assert_eq!(mixed["all_assets_reviewed"], false);
        assert_eq!(mixed["unreviewed_asset_ids"], json!([unreviewed_asset_id]));
        assert_eq!(mixed["rejection_reason"], "asset_not_reviewed");
    }

    #[test]
    fn payment_identity_survives_rbf_anchor_replacement_only() {
        let original = Consignment {
            coin_openings: Vec::new(),
            nullifiers: Vec::new(),
            proof: vec![1, 2, 3],
            anchor_ref: AnchorRef {
                txid: [7u8; 32],
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };
        let mut replacement = original.clone();
        replacement.anchor_ref.txid = [8u8; 32];

        assert_ne!(
            canonical_consignment_identity(&original.to_bytes())
                .unwrap()
                .1,
            canonical_consignment_identity(&replacement.to_bytes())
                .unwrap()
                .1,
        );
        assert_eq!(
            consignment_payment_identity(&original).unwrap(),
            consignment_payment_identity(&replacement).unwrap(),
        );

        replacement.proof.push(4);
        assert_ne!(
            consignment_payment_identity(&original).unwrap(),
            consignment_payment_identity(&replacement).unwrap(),
        );
    }

    #[test]
    fn matching_payment_consignments_reports_verified_rbf_predecessor() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE opencsv_consignments(
                consignment_id TEXT PRIMARY KEY,
                consignment_base64 TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );",
        )
        .unwrap();
        let original = Consignment {
            coin_openings: Vec::new(),
            nullifiers: Vec::new(),
            proof: vec![1, 2, 3],
            anchor_ref: AnchorRef {
                txid: [7u8; 32],
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };
        let original_id = canonical_consignment_identity(&original.to_bytes())
            .unwrap()
            .1;
        conn.execute(
            "INSERT INTO opencsv_consignments VALUES(?1, ?2, 1)",
            params![
                original_id,
                base64::engine::general_purpose::STANDARD.encode(original.to_bytes()),
            ],
        )
        .unwrap();

        let mut replacement = original.clone();
        replacement.anchor_ref.txid = [8u8; 32];
        let replacement_id = canonical_consignment_identity(&replacement.to_bytes())
            .unwrap()
            .1;
        assert_eq!(
            matching_payment_consignments(
                &conn,
                &replacement_id,
                &consignment_payment_identity(&replacement).unwrap(),
            )
            .unwrap(),
            vec![original_id],
        );
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
            batch: None,
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

        let confirmed_location = opencsv_core::chain::AnchorLocation {
            height: 101,
            position: 4,
        };
        let confirmed_snapshot = Snapshot {
            tip_height: 102,
            entries: vec![SnapshotEntry {
                height: confirmed_location.height,
                position: confirmed_location.position,
                txid: hex_encode(&consignment.anchor_ref.txid),
                ctx: hex_encode(&funding_context(funding)),
                record: hex_encode(&record),
                batch: None,
            }],
        };
        let settled = snapshot_with_unconfirmed_anchor(
            &serde_json::to_string(&confirmed_snapshot).unwrap(),
            &consignment,
            &transaction,
        )
        .unwrap();
        assert_eq!(
            settled.entries.len(),
            1,
            "do not duplicate a confirmed anchor"
        );
        assert_eq!(settled.entries[0].height, confirmed_location.height);
        assert_eq!(settled.entries[0].position, confirmed_location.position);
        let settled_chain = SnapshotChain::from_snapshot(&settled).unwrap();
        assert_eq!(
            opencsv_core::chain::AnchorChain::locate(&settled_chain, &consignment.anchor_ref),
            Some(confirmed_location)
        );
    }

    #[test]
    fn provisional_snapshot_accepts_exact_batch_v2_layout_and_envelope() {
        let funding = OutPoint::new(Txid::from_byte_array([41_u8; 32]), 0);
        let ctx = funding_context(funding);
        let raw_nf = Digest::from_bytes([42_u8; 32]);
        let payloads = vec![
            opencsv_core::binding(&raw_nf, &ctx).to_anchor(),
            opencsv_core::binding(&Digest::from_bytes([43_u8; 32]), &ctx).to_anchor(),
        ];
        let record = AnchorRecord::batch_header_v2(&payloads, &ctx);
        let stock_script = ScriptBuf::from_bytes(vec![0x51]);
        let mut stock_witness = vec![b"OCS2".to_vec()];
        stock_witness.extend(payloads.iter().map(|payload| payload.as_bytes().to_vec()));
        stock_witness.push(vec![1_u8]);
        stock_witness.push(stock_script.as_bytes().to_vec());
        let input = |previous_output| TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };
        let mut transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![
                input(funding),
                input(OutPoint::new(Txid::from_byte_array([44_u8; 32]), 1)),
                input(OutPoint::new(Txid::from_byte_array([45_u8; 32]), 2)),
            ],
            output: vec![
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::new_op_return(
                        PushBytesBuf::try_from(record.to_bytes().to_vec()).unwrap(),
                    ),
                },
                TxOut {
                    value: Amount::from_sat(MARKER_DUST_SATS),
                    script_pubkey: ScriptBuf::from_bytes(MARKER_SPK.to_vec()),
                },
                TxOut {
                    value: Amount::from_sat(546),
                    script_pubkey: stock_script.to_p2wsh(),
                },
                TxOut {
                    value: Amount::from_sat(2_000),
                    script_pubkey: ScriptBuf::from_bytes(
                        [vec![0x00, 0x14], vec![46_u8; 20]].concat(),
                    ),
                },
                TxOut {
                    value: Amount::from_sat(3_000),
                    script_pubkey: ScriptBuf::from_bytes(
                        [vec![0x00, 0x14], vec![47_u8; 20]].concat(),
                    ),
                },
            ],
        };
        transaction.input[0].witness = Witness::from_slice(&stock_witness);
        let consignment = Consignment {
            coin_openings: Vec::new(),
            nullifiers: vec![raw_nf],
            proof: Vec::new(),
            anchor_ref: AnchorRef {
                txid: transaction.compute_txid().to_byte_array(),
                location: MEMPOOL_LOCATION,
            },
            aux: None,
        };

        let snapshot = snapshot_with_unconfirmed_anchor(
            r#"{"tip_height":100,"entries":[]}"#,
            &consignment,
            &transaction,
        )
        .unwrap();
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(snapshot.entries[0].batch.as_ref().unwrap().version, 2);
        let chain = SnapshotChain::from_snapshot(&snapshot).unwrap();
        assert_eq!(
            opencsv_core::chain::AnchorChain::first_nullifier_occurrence(&chain, &raw_nf),
            Some(MEMPOOL_LOCATION),
        );

        transaction.output.swap(1, 2);
        let mut mutated_consignment = consignment.clone();
        mutated_consignment.anchor_ref.txid = transaction.compute_txid().to_byte_array();
        let error = snapshot_with_unconfirmed_anchor(
            r#"{"tip_height":100,"entries":[]}"#,
            &mutated_consignment,
            &transaction,
        )
        .unwrap_err();
        assert_eq!(error.code, "protocol_layout_violation");
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
            "version": SCHEMA_VERSION,
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
            json!(MEMPOOL_SPACE_CHAIN_PINS)
        );
        assert_eq!(policy[1]["id"], "blockstream_signet");
        assert_eq!(policy[1]["mode"], "require");
        assert_eq!(policy[1]["pin_profile"], "lets_encrypt_yr");
        assert_eq!(
            policy[1]["chain_fingerprints_sha256"],
            json!(BLOCKSTREAM_CHAIN_PINS)
        );
        assert_eq!(policy[2]["mode"], "observe");
        assert_eq!(policy[3]["mode"], "off");
        assert_eq!(policy[4]["mode"], "observe");
        assert_eq!(status["required_raw_observer_quorum"], 2);
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
                    "certificate_chain_fingerprints_sha256": [MEMPOOL_SPACE_CHAIN_PINS[0]],
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
                    "certificate_chain_fingerprints_sha256": [BLOCKSTREAM_CHAIN_PINS[1]],
                    "raw_transaction_hex": "0102"
                }
            ]
        });
        let (receipts, failure) =
            evaluate_observation_evidence(&policy, 2, &[1, 2], &evidence.to_string()).unwrap();
        assert!(failure.is_none());
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0]["raw_byte_match"], true);
        assert_eq!(receipts[1]["raw_byte_match"], true);

        let mut blockstream_only = evidence.clone();
        blockstream_only["observations"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let (receipts, failure) =
            evaluate_observation_evidence(&policy, 2, &[1, 2], &blockstream_only.to_string())
                .unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0]["result"], "not_checked");
        assert_eq!(receipts[1]["raw_byte_match"], true);

        let mut wrong_pin = evidence.clone();
        wrong_pin["observations"][0]["certificate_chain_fingerprints_sha256"] =
            json!(["11".repeat(32)]);
        let (_, failure) =
            evaluate_observation_evidence(&policy, 2, &[1, 2], &wrong_pin.to_string()).unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");

        let mut wrong = evidence;
        wrong["observations"][1]["raw_transaction_hex"] = json!("0103");
        let (_, failure) =
            evaluate_observation_evidence(&policy, 2, &[1, 2], &wrong.to_string()).unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");

        wrong["observations"][0]["certificate_chain_fingerprints_sha256"] =
            json!(["11".repeat(32)]);
        let (_, failure) =
            evaluate_observation_evidence(&policy, 2, &[1, 2], &wrong.to_string()).unwrap();
        assert_eq!(failure.unwrap().code, "required_observation_failed");
    }

    #[test]
    fn required_observer_conflicting_valid_transaction_is_a_distinct_failure() {
        let policy = default_observation_checks("signet");
        let now = unix_time_millis().unwrap();
        let exact = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let conflicting = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let exact_raw = serialize(&exact);
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
                    "certificate_chain_fingerprints_sha256": [MEMPOOL_SPACE_CHAIN_PINS[0]],
                    "raw_transaction_hex": hex_encode(&exact_raw)
                },
                {
                    "check_id": "blockstream_signet",
                    "endpoint": "https://blockstream.info/signet/api",
                    "result": "observed",
                    "started_at_ms": now - 20,
                    "completed_at_ms": now - 4,
                    "cached_at_ms": now - 4,
                    "certificate_profile": "lets_encrypt_yr",
                    "certificate_chain_fingerprints_sha256": [BLOCKSTREAM_CHAIN_PINS[1]],
                    "raw_transaction_hex": hex_encode(&serialize(&conflicting))
                }
            ]
        });

        let (receipts, failure) =
            evaluate_observation_evidence(&policy, 2, &exact_raw, &evidence.to_string()).unwrap();
        let failure = failure.expect("a contradictory required observer must fail closed");
        assert_eq!(failure.code, "observer_transaction_conflict");
        assert_eq!(receipts[0]["raw_byte_match"], true);
        assert_eq!(receipts[1]["raw_byte_match"], false);
        assert!(receipts[1]["failures"]
            .as_array()
            .unwrap()
            .iter()
            .any(|failure| failure == "observer returned a different valid transaction"));
    }

    #[test]
    fn raw_observer_quorum_must_match_required_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = json!({
            "version": SCHEMA_VERSION,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "primary",
            "backup_verified": false,
            "required_raw_observer_quorum": 3,
        });
        let error = AccountWallet::open_device_bound(
            &cfg.to_string(),
            &[91u8; 32],
            &[92u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "invalid_config");

        let cfg = json!({
            "version": SCHEMA_VERSION,
            "network": "signet",
            "esplora_url": "https://mempool.space/signet/api",
            "role": "primary",
            "backup_verified": false,
            "required_raw_observer_quorum": 1,
        });
        let error = AccountWallet::open_device_bound(
            &cfg.to_string(),
            &[93u8; 32],
            &[94u8; 32],
            dir.path().join("wallet-lower.sqlite").to_str().unwrap(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, "invalid_config");
    }

    #[test]
    fn custom_required_observer_needs_a_chain_pin() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = json!({
            "version": SCHEMA_VERSION,
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
        mainnet["deployment_id"] = json!("opencsv-mainnet-rebind-test");
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
            "version": SCHEMA_VERSION,
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
        let (cfg, asset_id) = reviewed_test_config(68);
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let planned = wallet
            .transfer_plan(
                &json!({
                    "asset_id": asset_id,
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
    fn two_second_batch_membership_is_durable_and_freezes_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [73u8; 32];
        let (cfg, asset_id) = reviewed_test_config(74);
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": u64::from(recipient),
            })
            .to_string()
        };
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let first = wallet.transfer_batch_plan(&request(1)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(first["batch"]["ordinal"], 0);
        assert_eq!(first["batch"]["member_count"], 1);
        assert_eq!(first["batch"]["add_recipient_guaranteed"], true);

        let second = wallet
            .transfer_batch_add_recipient(&batch_id, &request(2))
            .unwrap();
        assert_eq!(second["batch"]["batch_local_id"], batch_id);
        assert_eq!(second["batch"]["ordinal"], 1);
        assert_eq!(second["batch"]["member_count"], 2);
        let operation_ids = [
            first["operation_id"].as_str().unwrap().to_owned(),
            second["operation_id"].as_str().unwrap().to_owned(),
        ];
        drop(wallet);

        let mut reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        let frozen = reopened.freeze_send_batch(&batch_id).unwrap();
        assert_eq!(frozen["state"], "frozen");
        assert_eq!(frozen["participant_count"], 2);
        assert_eq!(frozen["member_count"], 2);
        assert_eq!(
            frozen["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|operation| operation["operation_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            operation_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let error = reopened
            .transfer_batch_add_recipient(&batch_id, &request(3))
            .unwrap_err();
        assert_eq!(error.code, "batch_window_closed");

        let next = reopened.transfer_batch_plan(&request(4)).unwrap();
        assert_ne!(next["batch"]["batch_local_id"], batch_id);
        let next_batch_id = next["batch"]["batch_local_id"].as_str().unwrap();
        assert_eq!(
            reopened.freeze_send_batch(next_batch_id).unwrap()["state"],
            "solo"
        );
    }

    #[test]
    fn batch_backup_accepts_the_exact_staged_checkpoint_after_unrelated_progress() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(79);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[78u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": 1,
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(1)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .transfer_batch_add_recipient(&batch_id, &request(2))
            .unwrap();
        wallet.freeze_send_batch(&batch_id).unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_send_batches
                 SET state = 'proof_ready', receipt_json = '{\"proof_material\":\"frozen\"}'
                 WHERE batch_local_id = ?1",
                [&batch_id],
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'proof_ready', receipt_json = '{\"proof_material\":\"frozen\"}'
                 WHERE operation_id IN (
                     SELECT operation_id FROM opencsv_send_batch_members
                     WHERE batch_local_id = ?1
                 )",
                [&batch_id],
            )
            .unwrap();
        let prepared_hash = wallet.checkpoint().unwrap()["checkpoint_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_send_batches SET checkpoint_hash = ?2
                 WHERE batch_local_id = ?1",
                params![batch_id, prepared_hash],
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET checkpoint_hash = ?2
                 WHERE operation_id IN (
                     SELECT operation_id FROM opencsv_send_batch_members
                     WHERE batch_local_id = ?1
                 )",
                params![batch_id, prepared_hash],
            )
            .unwrap();
        let before = wallet.send_batch(&batch_id).unwrap();

        wallet
            .insert_planned_operation("later-operation", "transfer", "{}", "later-delivery-nonce")
            .unwrap();
        let current_hash = wallet.checkpoint().unwrap()["checkpoint_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(current_hash, prepared_hash);
        assert_eq!(
            wallet
                .acknowledge_send_batch_backup(&batch_id, "not-a-checkpoint")
                .unwrap_err()
                .code,
            "backup_checkpoint_mismatch"
        );
        let acknowledged = wallet
            .acknowledge_send_batch_backup(&batch_id, &prepared_hash)
            .unwrap();
        assert_eq!(acknowledged["backup_acked"], true);
        assert_eq!(acknowledged["checkpoint_hash"], prepared_hash);
        let after = wallet.send_batch(&batch_id).unwrap();
        assert!(after.backup_acked);
        assert_eq!(
            after.checkpoint_hash.as_deref(),
            Some(prepared_hash.as_str())
        );
        assert_eq!(after.proposal_wire, before.proposal_wire);
        assert_eq!(after.manifest_wire, before.manifest_wire);
        for member in wallet.send_batch_members(&batch_id).unwrap() {
            let operation = wallet.operation(&member.operation_id).unwrap();
            assert!(operation.backup_acked);
            assert_eq!(
                operation.checkpoint_hash.as_deref(),
                Some(prepared_hash.as_str())
            );
            let receipt: Value =
                serde_json::from_str(operation.receipt_json.as_deref().unwrap()).unwrap();
            assert_eq!(receipt["proof_material"], "frozen");
            assert_eq!(receipt["checkpoint_hash"], prepared_hash);
        }
        assert_eq!(
            wallet.checkpoint().unwrap()["checkpoint_hash"],
            current_hash
        );
    }

    #[test]
    fn expired_add_recipient_creates_nothing_and_automatic_send_starts_next_batch() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(76);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[75u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = json!({
            "asset_id": asset_id,
            "to_owner": hex_encode(&[77u8; 32]),
            "amount": 1,
        })
        .to_string();
        let first = wallet.transfer_batch_plan(&request).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_send_batches SET deadline_ms = ?2
                 WHERE batch_local_id = ?1",
                params![batch_id, unix_time_millis().unwrap() - 1],
            )
            .unwrap();
        let operation_count_before: i64 = wallet
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            wallet
                .transfer_batch_add_recipient(&batch_id, &request)
                .unwrap_err()
                .code,
            "batch_window_closed",
        );
        let operation_count_after: i64 = wallet
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(operation_count_after, operation_count_before);

        let next = wallet.transfer_batch_plan(&request).unwrap();
        assert_ne!(next["batch"]["batch_local_id"], batch_id);
    }

    #[test]
    fn cancelling_collecting_batch_cancels_every_member_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(79);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[78u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": u64::from(recipient),
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(1)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let second = wallet
            .transfer_batch_add_recipient(&batch_id, &request(2))
            .unwrap();

        let cancelled = wallet.cancel_send_batch(&batch_id).unwrap();
        assert_eq!(cancelled["state"], "cancelled");
        assert!(cancelled["operations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|operation| operation["state"] == OperationState::Cancelled.as_str()));
        assert_eq!(wallet.cancel_send_batch(&batch_id).unwrap(), cancelled);
        assert_eq!(
            wallet
                .transfer_batch_add_recipient(&batch_id, &request(3))
                .unwrap_err()
                .code,
            "batch_window_closed",
        );
        let next = wallet.transfer_batch_plan(&request(4)).unwrap();
        assert_ne!(next["batch"]["batch_local_id"], batch_id);
        assert_ne!(next["operation_id"], first["operation_id"]);
        assert_ne!(next["operation_id"], second["operation_id"]);
    }

    #[test]
    fn cancel_operation_releases_active_proof_lease() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(96);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[95u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 50_000);
        fund(&mut wallet, 40_000);
        let request = json!({
            "asset_id": asset_id,
            "to_owner": hex_encode(&[97u8; 32]),
            "amount": 1,
        })
        .to_string();
        wallet
            .insert_planned_operation("lease-holder", "transfer", &request, "nonce-a")
            .unwrap();
        wallet
            .insert_planned_operation("waiting", "transfer", &request, "nonce-b")
            .unwrap();

        // A crashed prover leaves its durable lease behind: begin the job and
        // drop it before finish/fail can clear the reservation.
        let job = match wallet.begin_proof_job("lease-holder").unwrap() {
            ProofJobStart::Run(job) => job,
            ProofJobStart::Ready(_) => panic!("planned operation was already proved"),
        };
        drop(job);
        assert_eq!(
            wallet.db.meta("active_proof_operation").unwrap().as_deref(),
            Some("lease-holder")
        );

        wallet.cancel_operation("lease-holder").unwrap();
        assert!(wallet.db.meta("active_proof_operation").unwrap().is_none());

        match wallet.begin_proof_job("waiting").unwrap() {
            ProofJobStart::Run(job) => drop(job),
            ProofJobStart::Ready(_) => panic!("planned operation was already proved"),
        }
        assert_eq!(
            wallet.db.meta("active_proof_operation").unwrap().as_deref(),
            Some("waiting")
        );
    }

    #[test]
    fn retryable_chain_verification_preserves_solo_operation_and_fee_lock() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(101);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[102u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let verifier = use_scripted_verifier(
            &mut wallet,
            [
                VerificationVerdict::RetryableReject(
                    "chain_verification_unavailable",
                    "confirmed spend scan is still catching up",
                ),
                VerificationVerdict::Accept,
            ],
        );
        fund(&mut wallet, 50_000);
        let planned = wallet
            .transfer_batch_plan(
                &json!({
                    "asset_id": asset_id,
                    "to_owner": hex_encode(&[103u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap().to_owned();
        let batch_id = planned["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(wallet.freeze_send_batch(&batch_id).unwrap()["state"], "solo");

        let job = match wallet.begin_proof_job(&operation_id).unwrap() {
            ProofJobStart::Run(job) => job,
            ProofJobStart::Ready(_) => panic!("planned operation was already proved"),
        };
        let reserved = wallet.operation(&operation_id).unwrap();
        let reserved_outpoint = operation_outpoint(&reserved).unwrap();
        let error = match job.run() {
            Ok(_) => panic!("retryable verifier unexpectedly accepted the proof job"),
            Err(error) => error,
        };
        assert!(error.retryable);
        assert_eq!(error.code, "chain_verification_unavailable");
        assert_eq!(
            wallet
                .fail_proof_job::<Value>(&operation_id, error)
                .unwrap_err()
                .code,
            "chain_verification_unavailable",
        );

        let after = wallet.operation(&operation_id).unwrap();
        assert_eq!(after.state, OperationState::FeeReserved.as_str());
        assert_eq!(operation_outpoint(&after).unwrap(), reserved_outpoint);
        assert!(wallet.bitcoin.is_outpoint_locked(reserved_outpoint));
        assert!(after.rejection_reason.is_none());
        assert!(wallet.db.meta("active_proof_operation").unwrap().is_none());
        assert_eq!(wallet.send_batch(&batch_id).unwrap().state, "solo");
        let receipt: Value = serde_json::from_str(after.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            receipt["retryable_proof_error"]["reason"],
            "chain_verification_unavailable",
        );
        assert_eq!(receipt["retryable_proof_error"]["retryable"], true);

        // A later retry owns the same durable proposal and fee outpoint. The
        // accepting second verifier verdict is intentionally left to the job;
        // no new operation or reservation is created before proving resumes.
        let retry = match wallet.begin_proof_job(&operation_id).unwrap() {
            ProofJobStart::Run(job) => job,
            ProofJobStart::Ready(_) => panic!("retry unexpectedly skipped proof work"),
        };
        assert_eq!(
            operation_outpoint(&wallet.operation(&operation_id).unwrap()).unwrap(),
            reserved_outpoint,
        );
        assert_eq!(verifier.calls.load(Ordering::SeqCst), 1);
        drop(retry);
    }

    #[test]
    fn verified_conflict_still_cancels_solo_operation_and_batch() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(104);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[105u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        use_scripted_verifier(
            &mut wallet,
            [VerificationVerdict::Reject(
                "conflicting_operation",
                "verified block spends the reserved fee outpoint",
            )],
        );
        fund(&mut wallet, 50_000);
        let planned = wallet
            .transfer_batch_plan(
                &json!({
                    "asset_id": asset_id,
                    "to_owner": hex_encode(&[106u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap().to_owned();
        let batch_id = planned["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet.freeze_send_batch(&batch_id).unwrap();
        let job = match wallet.begin_proof_job(&operation_id).unwrap() {
            ProofJobStart::Run(job) => job,
            ProofJobStart::Ready(_) => panic!("planned operation was already proved"),
        };
        let error = match job.run() {
            Ok(_) => panic!("conflicting verifier unexpectedly accepted the proof job"),
            Err(error) => error,
        };
        assert!(!error.retryable);
        assert_eq!(
            wallet
                .fail_proof_job::<Value>(&operation_id, error)
                .unwrap_err()
                .code,
            "conflicting_operation",
        );
        let operation = wallet.operation(&operation_id).unwrap();
        assert_eq!(operation.state, OperationState::Cancelled.as_str());
        assert_eq!(
            operation.rejection_reason.as_deref(),
            Some("conflicting_operation"),
        );
        assert_eq!(wallet.send_batch(&batch_id).unwrap().state, "cancelled");
    }

    #[test]
    fn prebroadcast_member_failure_cancels_the_complete_batch() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(82);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[81u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": 1,
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(1)).unwrap();
        let operation_id = first["operation_id"].as_str().unwrap().to_owned();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let second = wallet
            .transfer_batch_add_recipient(&batch_id, &request(2))
            .unwrap();
        let second_id = second["operation_id"].as_str().unwrap().to_owned();

        let error = AccountError::new(
            "stale_chain_state",
            "selected OpenCSV input was already confirmed spent",
        );
        let result: Result<Value, AccountError> = wallet.fail_prebroadcast(&operation_id, error);
        assert_eq!(result.unwrap_err().code, "stale_chain_state");
        assert_eq!(wallet.send_batch(&batch_id).unwrap().state, "cancelled");
        for member_id in [&operation_id, &second_id] {
            let operation = wallet.operation(member_id).unwrap();
            assert_eq!(operation.state, OperationState::Cancelled.as_str());
            assert_eq!(
                operation.rejection_reason.as_deref(),
                Some("stale_chain_state")
            );
        }
    }

    #[test]
    fn batch_proof_failure_preserves_only_retryable_verification_outages() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(107);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[108u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": 1,
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(109)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .transfer_batch_add_recipient(&batch_id, &request(110))
            .unwrap();
        wallet.freeze_send_batch(&batch_id).unwrap();
        wallet.db.set_meta("active_batch_proof", &batch_id).unwrap();

        let retryable = AccountError::retryable(
            "chain_verification_unavailable",
            "compact-filter peers are temporarily unavailable",
        );
        assert_eq!(
            wallet
                .fail_send_batch_proof::<Value>(&batch_id, retryable)
                .unwrap_err()
                .code,
            "chain_verification_unavailable",
        );
        assert_eq!(wallet.send_batch(&batch_id).unwrap().state, "frozen");
        assert!(wallet
            .send_batch_members(&batch_id)
            .unwrap()
            .iter()
            .all(|member| wallet.operation(&member.operation_id).unwrap().state == "planned"));

        wallet.db.set_meta("active_batch_proof", &batch_id).unwrap();
        let conflict = AccountError::new(
            "conflicting_operation",
            "verified block spends a batch fee input",
        );
        assert_eq!(
            wallet
                .fail_send_batch_proof::<Value>(&batch_id, conflict)
                .unwrap_err()
                .code,
            "conflicting_operation",
        );
        assert_eq!(wallet.send_batch(&batch_id).unwrap().state, "cancelled");
        assert!(wallet
            .send_batch_members(&batch_id)
            .unwrap()
            .iter()
            .all(|member| wallet.operation(&member.operation_id).unwrap().state == "cancelled"));
    }

    #[test]
    fn reserve_maintenance_creates_only_stock_fee_cells_and_wallet_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &[69u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        fund(&mut wallet, 100_000);
        let prepared = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        assert_eq!(prepared["state"], "broadcast_unobserved");
        assert_eq!(
            wallet.status().unwrap()["batch_reserves"]["maintenance_operations"][0]
                ["fee_rate_sat_per_vb"],
            1
        );
        let raw = hex_decode(
            prepared["signed_tx_hex"].as_str().unwrap(),
            "reserve maintenance transaction",
        )
        .unwrap();
        let transaction: Transaction = deserialize(&raw).unwrap();
        assert_eq!(transaction.output.len(), 10);
        let stock_secret = wallet.batch_stock_secret().unwrap();
        let stock_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &stock_secret);
        let stock_script = stock_witness_script(stock_pubkey, 2).to_p2wsh();
        assert!(transaction.output[..3].iter().all(|output| {
            output.value.to_sat() == opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS
                && output.script_pubkey == stock_script
        }));
        assert!(transaction.output[3..9].iter().all(|output| {
            output.value.to_sat() == MIN_FEE_RESERVE_SATS
                && wallet
                    .bitcoin
                    .derivation_of_spk(output.script_pubkey.clone())
                    .is_some()
        }));
        assert!(wallet
            .bitcoin
            .derivation_of_spk(transaction.output[9].script_pubkey.clone())
            .is_some());
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
            .observe_batch_reserve_unconfirmed(
                prepared["maintenance_id"].as_str().unwrap(),
                &raw,
                &evidence.to_string(),
            )
            .unwrap();
        assert_eq!(observed["state"], "mempool");
        assert_eq!(
            wallet.status().unwrap()["batch_reserves"]["inventory"][0]["count"],
            3
        );
    }

    #[test]
    fn reserve_maintenance_fee_bump_only_reduces_wallet_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [68u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        fund(&mut wallet, 100_000);
        let prepared = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        let maintenance_id = prepared["maintenance_id"].as_str().unwrap();
        let original: Transaction = deserialize(
            &hex_decode(
                prepared["signed_tx_hex"].as_str().unwrap(),
                "reserve maintenance transaction",
            )
            .unwrap(),
        )
        .unwrap();
        let original_txid = original.compute_txid();
        let original_fee = prepared["receipt"]["fee_sats"].as_u64().unwrap();

        let bumped = wallet.fee_bump_batch_reserves(maintenance_id, 4).unwrap();
        assert_eq!(bumped["state"], "broadcast_unobserved");
        assert_eq!(bumped["fee_rate_sat_per_vb"], 4);
        assert_eq!(bumped["receipt"]["replaces"], original_txid.to_string());
        let replacement: Transaction = deserialize(
            &hex_decode(
                bumped["signed_tx_hex"].as_str().unwrap(),
                "reserve replacement transaction",
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(replacement.compute_txid(), original_txid);
        assert_eq!(replacement.version, original.version);
        assert_eq!(replacement.lock_time, original.lock_time);
        assert_eq!(replacement.input.len(), original.input.len());
        assert!(replacement
            .input
            .iter()
            .zip(&original.input)
            .all(|(new, old)| {
                new.previous_output == old.previous_output
                    && new.sequence == old.sequence
                    && new.script_sig == old.script_sig
            }));
        assert_eq!(replacement.output.len(), original.output.len());
        assert_eq!(
            replacement.output[..replacement.output.len() - 1],
            original.output[..original.output.len() - 1]
        );
        assert_eq!(
            replacement.output.last().unwrap().script_pubkey,
            original.output.last().unwrap().script_pubkey
        );
        assert!(replacement.output.last().unwrap().value < original.output.last().unwrap().value);
        assert!(
            replacement.output.last().unwrap().value
                >= replacement
                    .output
                    .last()
                    .unwrap()
                    .script_pubkey
                    .minimal_non_dust()
        );
        let replacement_fee = bumped["receipt"]["fee_sats"].as_u64().unwrap();
        assert!(replacement_fee > original_fee);
        assert_eq!(
            bumped["receipt"]["fee_increment_sats"],
            replacement_fee - original_fee
        );
        let old_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1",
                [original_txid.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let replacement_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1",
                [replacement.compute_txid().to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_stocks, 0);
        assert_eq!(replacement_stocks, 3);
        let first_replacement_txid = replacement.compute_txid().to_string();
        let first_replacement_hex = bumped["signed_tx_hex"].as_str().unwrap().to_owned();

        let second_bump = wallet.fee_bump_batch_reserves(maintenance_id, 7).unwrap();
        let second_replacement: Transaction = deserialize(
            &hex_decode(
                second_bump["signed_tx_hex"].as_str().unwrap(),
                "second reserve replacement transaction",
            )
            .unwrap(),
        )
        .unwrap();
        let second_replacement_fee = second_bump["receipt"]["fee_sats"].as_u64().unwrap();
        assert_eq!(second_bump["receipt"]["replaces"], first_replacement_txid);
        assert!(second_replacement_fee > replacement_fee);
        assert_eq!(
            second_bump["receipt"]["fee_increment_sats"],
            second_replacement_fee - replacement_fee
        );
        let candidates = second_bump["receipt"]["replacement_candidates"]
            .as_array()
            .unwrap();
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0]["txid"], original_txid.to_string());
        assert_eq!(
            candidates[0]["signed_tx_hex"],
            prepared["signed_tx_hex"]
        );
        assert_eq!(candidates[0]["fee_sats"], original_fee);
        assert_eq!(candidates[1]["txid"], first_replacement_txid);
        assert_eq!(candidates[1]["signed_tx_hex"], first_replacement_hex);
        assert_eq!(candidates[1]["fee_sats"], replacement_fee);
        assert_eq!(
            second_replacement.output[..second_replacement.output.len() - 1],
            original.output[..original.output.len() - 1]
        );
        assert!(
            second_replacement.output.last().unwrap().value
                < replacement.output.last().unwrap().value
        );
        assert!(
            second_replacement.output.last().unwrap().value
                >= second_replacement
                    .output
                    .last()
                    .unwrap()
                    .script_pubkey
                    .minimal_non_dust()
        );
        let first_replacement_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1",
                [&first_replacement_txid],
                |row| row.get(0),
            )
            .unwrap();
        let second_replacement_txid = second_replacement.compute_txid().to_string();
        let second_replacement_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1",
                [&second_replacement_txid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(first_replacement_stocks, 0);
        assert_eq!(second_replacement_stocks, 3);
        drop(wallet);

        let reopened = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        let recovered = reopened
            .batch_reserve_operation_json(maintenance_id)
            .unwrap();
        assert_eq!(recovered["state"], "broadcast_unobserved");
        assert_eq!(recovered["txid"], second_replacement_txid);
        assert_eq!(recovered["signed_tx_hex"], second_bump["signed_tx_hex"]);
        assert_eq!(
            recovered["receipt"]["replacement_candidates"],
            second_bump["receipt"]["replacement_candidates"]
        );
    }

    #[test]
    fn reserve_maintenance_restores_an_original_that_confirms_after_fee_bump() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [69u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 100_000);
        let prepared = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        let maintenance_id = prepared["maintenance_id"].as_str().unwrap();
        let original_txid = prepared["txid"].as_str().unwrap().to_owned();
        let original_hex = prepared["signed_tx_hex"].as_str().unwrap().to_owned();
        let bumped = wallet.fee_bump_batch_reserves(maintenance_id, 4).unwrap();
        let replacement_txid = bumped["txid"].as_str().unwrap().to_owned();
        assert_ne!(replacement_txid, original_txid);

        let (esplora_url, server) = confirmed_status_server(321_000);
        wallet.config.esplora_url = esplora_url;
        let restored = wallet.resume_batch_reserves(maintenance_id).unwrap();
        server.join().unwrap();

        assert_eq!(restored["state"], "broadcast_unobserved");
        assert_eq!(restored["txid"], original_txid);
        assert_eq!(restored["signed_tx_hex"], original_hex);
        assert_eq!(
            restored["receipt"]["fee_bump_outcome"],
            "superseded_reserve_candidate_confirmed"
        );
        assert_eq!(
            restored["receipt"]["failed_replacement_txid"],
            replacement_txid
        );
        assert!(restored["receipt"].get("replaces").is_none());
        assert!(restored["receipt"].get("replacement_candidates").is_none());
        let original_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1 AND state = 'pending'",
                [original_txid],
                |row| row.get(0),
            )
            .unwrap();
        let replacement_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1 AND state = 'pending'",
                [replacement_txid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(original_stocks, 3);
        assert_eq!(replacement_stocks, 0);
    }

    #[test]
    fn reserve_replacement_accelerator_cannot_override_verified_chain_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [70u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        fund(&mut wallet, 100_000);
        let prepared = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        let maintenance_id = prepared["maintenance_id"].as_str().unwrap();
        let original_txid = prepared["txid"].as_str().unwrap().to_owned();
        let bumped = wallet.fee_bump_batch_reserves(maintenance_id, 4).unwrap();
        let replacement_txid = bumped["txid"].as_str().unwrap().to_owned();
        use_scripted_verifier(
            &mut wallet,
            [VerificationVerdict::Reject(
                "conflicting_operation",
                "accelerator candidate is absent from the verified chain",
            )],
        );

        let (esplora_url, server) = confirmed_status_server(321_001);
        wallet.config.esplora_url = esplora_url;
        let unchanged = wallet.resume_batch_reserves(maintenance_id).unwrap();
        server.join().unwrap();

        assert_eq!(unchanged["txid"], replacement_txid);
        assert_eq!(
            unchanged["receipt"]["replacement_candidates"][0]["txid"],
            original_txid
        );
        let replacement_stocks: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_batch_stocks WHERE txid = ?1 AND state = 'pending'",
                [replacement_txid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(replacement_stocks, 3);
    }

    #[test]
    fn reserve_resume_records_unavailable_reconciliation_and_rebroadcasts_current_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let key = [71u8; 32];
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &key,
            path.to_str().unwrap(),
        )
        .unwrap();
        fund(&mut wallet, 100_000);
        let prepared = wallet
            .prepare_batch_reserves(
                2,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();
        let maintenance_id = prepared["maintenance_id"].as_str().unwrap();
        let bumped = wallet.fee_bump_batch_reserves(maintenance_id, 4).unwrap();
        let replacement_txid = bumped["txid"].as_str().unwrap().to_owned();
        let replacement_hex = bumped["signed_tx_hex"].as_str().unwrap().to_owned();
        use_scripted_verifier(
            &mut wallet,
            [VerificationVerdict::RetryableReject(
                "chain_verification_unavailable",
                "compact-filter peers are temporarily unavailable",
            )],
        );

        let (esplora_url, server) = confirmed_status_server(321_002);
        wallet.config.esplora_url = esplora_url;
        let resumed = wallet.resume_batch_reserves(maintenance_id).unwrap();
        server.join().unwrap();

        assert_eq!(resumed["state"], "broadcast_unobserved");
        assert_eq!(resumed["txid"], replacement_txid);
        assert_eq!(resumed["signed_tx_hex"], replacement_hex);
        assert_eq!(
            resumed["receipt"]["resume_candidate_reconciliation"]["reason"],
            "chain_verification_unavailable"
        );
        assert_eq!(
            resumed["receipt"]["resume_candidate_reconciliation"]["retryable"],
            true
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
        let minted = prepare_test_issuance(&mut wallet, "USD", &[60, 40]).unwrap();
        let asset_id = minted["asset_id"].as_str().unwrap().to_owned();
        let cfg = serde_json::to_string(&wallet.config).unwrap();
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
        let pending_id = reopened.pending_by_operation[&operation_id];
        let dependencies = reopened
            .primary_protocol_mut()
            .unwrap()
            .pending_unconfirmed_dependencies(pending_id)
            .unwrap();
        assert_eq!(dependencies.len(), 1);
        assert!(reopened
            .dependency_reobservation_is_fresh(&dependencies[0])
            .unwrap());
    }

    #[test]
    #[ignore = "slow recursive receipts; run explicitly with --release --ignored"]
    fn two_recipient_batch_proves_signs_and_observes_one_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config_with_url(AccountRole::Primary, true, "http://127.0.0.1:1"),
            &[91u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 60_000);
        let minted = prepare_test_issuance(&mut wallet, "USD", &[60, 40]).unwrap();
        let asset_id = minted["asset_id"].as_str().unwrap().to_owned();
        let mint_operation = minted["operation_id"].as_str().unwrap().to_owned();
        let mint_pending = wallet.pending_by_operation.remove(&mint_operation).unwrap();
        wallet
            .primary_protocol_mut()
            .unwrap()
            .finalize(
                mint_pending,
                AnchorRef {
                    txid: [92u8; 32],
                    location: opencsv_core::chain::AnchorLocation {
                        height: 1,
                        position: 0,
                    },
                },
            )
            .unwrap();
        wallet.release_fee_reservation(&mint_operation).unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'cancelled'
                 WHERE operation_id = ?1",
                [&mint_operation],
            )
            .unwrap();
        fund(&mut wallet, 20_000);
        fund(&mut wallet, 19_000);
        let stock_outpoint = OutPoint::new(Txid::from_byte_array([93u8; 32]), 0);
        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_batch_stocks(
                     participant_count, txid, vout, value_sats, birth_height,
                     state, reserved_by_batch, created_at
                 ) VALUES(2, ?1, 0, ?2, 1, 'available', NULL, 1)",
                params![
                    stock_outpoint.txid.to_string(),
                    i64::try_from(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS).unwrap(),
                ],
            )
            .unwrap();
        let request = |owner: u8, amount: u64| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[owner; 32]),
                "amount": amount,
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(94, 60)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .transfer_batch_add_recipient(&batch_id, &request(95, 40))
            .unwrap();
        wallet.freeze_send_batch(&batch_id).unwrap();
        let job = match wallet.begin_send_batch_proof(&batch_id).unwrap() {
            BatchProofJobStart::Run(job) => job,
            _ => panic!("frozen two-member batch did not produce a proof job"),
        };
        let completed = job.run().unwrap();
        let proved = wallet.finish_send_batch_proof(completed).unwrap();
        assert_eq!(proved["state"], "proof_ready");
        wallet
            .acknowledge_send_batch_backup(&batch_id, proved["checkpoint_hash"].as_str().unwrap())
            .unwrap();
        let broadcast = wallet.sign_and_broadcast_send_batch(&batch_id).unwrap();
        assert_eq!(broadcast["state"], "broadcast_unobserved");
        let resumed = wallet.resume_send_batch(&batch_id).unwrap();
        assert_eq!(resumed["signed_tx_hex"], broadcast["signed_tx_hex"]);
        assert_eq!(resumed["txid"], broadcast["txid"]);
        let raw = hex_decode(
            broadcast["signed_tx_hex"].as_str().unwrap(),
            "test batch transaction",
        )
        .unwrap();
        let transaction: Transaction = deserialize(&raw).unwrap();
        assert_eq!(transaction.input.len(), 3);
        assert_eq!(transaction.input[0].previous_output, stock_outpoint);
        assert_eq!(transaction.output.len(), 5);
        assert!(transaction.output[0].script_pubkey.is_op_return());
        assert_eq!(transaction.output[1].script_pubkey.as_bytes(), MARKER_SPK);
        assert!(transaction.input[1..]
            .iter()
            .all(|input| input.previous_output != stock_outpoint));
        assert_ne!(
            transaction.input[1].previous_output,
            transaction.input[2].previous_output
        );
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
            .observe_send_batch_unconfirmed(&batch_id, &raw, &evidence.to_string())
            .unwrap();
        assert_eq!(observed["state"], "mempool");
        let bumped = wallet.fee_bump_send_batch(&batch_id, 3).unwrap();
        assert_eq!(bumped["state"], "broadcast_unobserved");
        let replacement_raw = hex_decode(
            bumped["signed_tx_hex"].as_str().unwrap(),
            "test batch replacement",
        )
        .unwrap();
        let replacement: Transaction = deserialize(&replacement_raw).unwrap();
        assert!(replacement
            .input
            .iter()
            .zip(&transaction.input)
            .all(|(new, old)| {
                new.previous_output == old.previous_output
                    && new.sequence == old.sequence
                    && new.script_sig == old.script_sig
            }));
        assert_eq!(replacement.output[..3], transaction.output[..3]);
        assert!(replacement.output[3..]
            .iter()
            .zip(&transaction.output[3..])
            .all(|(new, old)| {
                new.script_pubkey == old.script_pubkey && new.value <= old.value
            }));
        assert!(replacement.output[3..]
            .iter()
            .zip(&transaction.output[3..])
            .any(|(new, old)| new.value < old.value));
        let replacement_now = unix_time_millis().unwrap();
        let replacement_evidence = json!({
            "observations": [{
                "check_id": "test_accelerator",
                "endpoint": "http://127.0.0.1:1",
                "result": "observed",
                "started_at_ms": replacement_now - 2,
                "completed_at_ms": replacement_now - 1,
                "cached_at_ms": replacement_now - 1,
                "certificate_chain_fingerprints_sha256": [],
                "raw_transaction_hex": hex_encode(&replacement_raw),
            }]
        });
        let replacement_observed = wallet
            .observe_send_batch_unconfirmed(
                &batch_id,
                &replacement_raw,
                &replacement_evidence.to_string(),
            )
            .unwrap();
        assert_eq!(replacement_observed["state"], "mempool");
        let members = wallet.send_batch_members(&batch_id).unwrap();
        assert_eq!(members.len(), 2);
        let expected_txid = replacement.compute_txid().to_string();
        for member in members {
            let operation = wallet.operation(&member.operation_id).unwrap();
            assert_eq!(operation.state, OperationState::Mempool.as_str());
            assert_eq!(operation.txid.as_deref(), Some(expected_txid.as_str()));
            let receipt: Value =
                serde_json::from_str(operation.receipt_json.as_deref().unwrap()).unwrap();
            assert_eq!(receipt["delivery_ready"], true);
        }
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
        assert_eq!(
            status["instruments"][0]["profile"],
            "trusted_test_usd_v2"
        );
        assert_eq!(status["instruments"][0]["issuer_priority"], 10);
        assert_eq!(status["instruments"][1]["asset_id"], first_id);
        assert_eq!(
            status["instruments"][1]["profile"],
            "trusted_test_usd_v2"
        );
    }

    #[test]
    fn transfer_intents_require_the_exact_reviewed_asset_and_recheck_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let mut unreviewed = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[45u8; 32],
            dir.path().join("unreviewed.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = json!({
            "asset_id": hex_encode(&[46u8; 32]),
            "to_owner": hex_encode(&[47u8; 32]),
            "amount": 1,
        })
        .to_string();
        let error = unreviewed.transfer_plan(&request).unwrap_err();
        assert_eq!(error.code, "asset_not_reviewed");
        let operation_count: u32 = unreviewed
            .db
            .conn
            .query_row("SELECT COUNT(*) FROM opencsv_operations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(operation_count, 0);

        let (cfg, asset_id) = reviewed_test_config(48);
        let mut reviewed = AccountWallet::open(
            &cfg,
            &[49u8; 32],
            dir.path().join("reviewed.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let planned = reviewed
            .transfer_plan(
                &json!({
                    "asset_id": asset_id,
                    "to_owner": hex_encode(&[50u8; 32]),
                    "amount": 1,
                })
                .to_string(),
            )
            .unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap();
        reviewed.config.usd_issuers.clear();
        let error = reviewed.prove_operation(operation_id).unwrap_err();
        assert_eq!(error.code, "asset_not_reviewed");
        let operation = reviewed.operation(operation_id).unwrap();
        assert_eq!(operation.state, OperationState::Cancelled.as_str());
        assert_eq!(
            operation.rejection_reason.as_deref(),
            Some("asset_not_reviewed")
        );
    }

    #[test]
    #[ignore = "slow recursive receipts; run explicitly with --release --ignored"]
    fn fee_bump_send_batch_enforces_configured_fee_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let mut config_value: Value = serde_json::from_str(&config_with_url(
            AccountRole::Primary,
            true,
            "http://127.0.0.1:1",
        ))
        .unwrap();
        config_value["max_fee_sats"] = json!(5_000);
        let mut wallet = AccountWallet::open(
            &config_value.to_string(),
            &[96u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 60_000);
        let minted = prepare_test_issuance(&mut wallet, "USD", &[60, 40]).unwrap();
        let asset_id = minted["asset_id"].as_str().unwrap().to_owned();
        let mint_operation = minted["operation_id"].as_str().unwrap().to_owned();
        let mint_pending = wallet.pending_by_operation.remove(&mint_operation).unwrap();
        wallet
            .primary_protocol_mut()
            .unwrap()
            .finalize(
                mint_pending,
                AnchorRef {
                    txid: [97u8; 32],
                    location: opencsv_core::chain::AnchorLocation {
                        height: 1,
                        position: 0,
                    },
                },
            )
            .unwrap();
        wallet.release_fee_reservation(&mint_operation).unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'cancelled'
                 WHERE operation_id = ?1",
                [&mint_operation],
            )
            .unwrap();
        fund(&mut wallet, 20_000);
        fund(&mut wallet, 19_000);
        let stock_outpoint = OutPoint::new(Txid::from_byte_array([98u8; 32]), 0);
        wallet
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_batch_stocks(
                     participant_count, txid, vout, value_sats, birth_height,
                     state, reserved_by_batch, created_at
                 ) VALUES(2, ?1, 0, ?2, 1, 'available', NULL, 1)",
                params![
                    stock_outpoint.txid.to_string(),
                    i64::try_from(opencsv_bitcoin::batch_v2::MIN_OUTPUT_SATS).unwrap(),
                ],
            )
            .unwrap();
        let request = |owner: u8, amount: u64| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[owner; 32]),
                "amount": amount,
            })
            .to_string()
        };
        let first = wallet.transfer_batch_plan(&request(99, 60)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .transfer_batch_add_recipient(&batch_id, &request(100, 40))
            .unwrap();
        wallet.freeze_send_batch(&batch_id).unwrap();
        let job = match wallet.begin_send_batch_proof(&batch_id).unwrap() {
            BatchProofJobStart::Run(job) => job,
            _ => panic!("frozen two-member batch did not produce a proof job"),
        };
        let completed = job.run().unwrap();
        let proved = wallet.finish_send_batch_proof(completed).unwrap();
        wallet
            .acknowledge_send_batch_backup(&batch_id, proved["checkpoint_hash"].as_str().unwrap())
            .unwrap();
        let broadcast = wallet.sign_and_broadcast_send_batch(&batch_id).unwrap();
        assert_eq!(broadcast["state"], "broadcast_unobserved");

        let original_nonces = wallet
            .send_batch_members(&batch_id)
            .unwrap()
            .into_iter()
            .map(|member| {
                let operation = wallet.operation(&member.operation_id).unwrap();
                (member.operation_id, operation.delivery_nonce)
            })
            .collect::<Vec<_>>();

        let below = wallet.fee_bump_send_batch(&batch_id, 3).unwrap();
        assert_eq!(below["state"], "broadcast_unobserved");
        let below_fee = below["receipt"]["miner_fee_sats"].as_u64().unwrap();
        assert!(below_fee <= 5_000);
        for (operation_id, original_nonce) in original_nonces {
            let replacement = wallet.operation(&operation_id).unwrap();
            assert_ne!(replacement.delivery_nonce, original_nonce);
            let receipt: Value =
                serde_json::from_str(replacement.receipt_json.as_deref().unwrap()).unwrap();
            assert_eq!(receipt["delivery_nonce"], replacement.delivery_nonce);
            let stale = wallet
                .mark_consignment_delivered(&operation_id, &original_nonce)
                .unwrap_err();
            assert_eq!(stale.code, "delivery_nonce_mismatch");
        }

        let error = wallet.fee_bump_send_batch(&batch_id, 40).unwrap_err();
        assert_eq!(error.code, "fee_limit_exceeded");
        assert_eq!(
            wallet.send_batch_status(&batch_id).unwrap()["state"],
            json!("broadcast_unobserved")
        );
    }

    #[test]
    fn reviewed_asset_revocation_blocks_signing_and_cancels_unsigned_batch() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, asset_id) = reviewed_test_config(51);
        let mut wallet = AccountWallet::open(
            &cfg,
            &[52u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": 1,
            })
            .to_string()
        };

        let planned = wallet.transfer_plan(&request(53)).unwrap();
        let operation_id = planned["operation_id"].as_str().unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'proof_ready', backup_acked = 1
                 WHERE operation_id = ?1",
                [operation_id],
            )
            .unwrap();
        wallet.config.usd_issuers.clear();
        let error = wallet
            .sign_and_broadcast(operation_id, r#"{"target_sat_per_vb":1}"#)
            .unwrap_err();
        assert_eq!(error.code, "asset_not_reviewed");
        let operation = wallet.operation(operation_id).unwrap();
        assert_eq!(operation.state, OperationState::Cancelled.as_str());
        assert_eq!(
            operation.rejection_reason.as_deref(),
            Some("asset_not_reviewed")
        );

        let (cfg, asset_id) = reviewed_test_config(54);
        let mut batch = AccountWallet::open(
            &cfg,
            &[55u8; 32],
            dir.path().join("batch.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": 1,
            })
            .to_string()
        };
        let first = batch.transfer_batch_plan(&request(56)).unwrap();
        let batch_id = first["batch"]["batch_local_id"].as_str().unwrap();
        batch
            .transfer_batch_add_recipient(batch_id, &request(57))
            .unwrap();
        batch.freeze_send_batch(batch_id).unwrap();
        batch.config.usd_issuers.clear();
        let error = match batch.begin_send_batch_proof(batch_id) {
            Err(error) => error,
            Ok(_) => panic!("revoked batch unexpectedly began proving"),
        };
        assert_eq!(error.code, "asset_not_reviewed");
        let status = batch.send_batch_status(batch_id).unwrap();
        assert_eq!(status["state"], "cancelled");
        for member in status["operations"].as_array().unwrap() {
            assert_eq!(member["state"], "cancelled");
        }
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
    fn checkpoint_restore_preserves_frozen_batch_membership() {
        let dir = tempfile::tempdir().unwrap();
        let key = [81u8; 32];
        let binding = [82u8; 32];
        let (cfg, asset_id) = reviewed_test_config(83);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let request = |recipient: u8| {
            json!({
                "asset_id": asset_id,
                "to_owner": hex_encode(&[recipient; 32]),
                "amount": u64::from(recipient),
            })
            .to_string()
        };
        let first = original.transfer_batch_plan(&request(1)).unwrap();
        let batch_id = first["batch"]["batch_local_id"]
            .as_str()
            .unwrap()
            .to_owned();
        original
            .transfer_batch_add_recipient(&batch_id, &request(2))
            .unwrap();
        original.freeze_send_batch(&batch_id).unwrap();
        let checkpoint = original.checkpoint().unwrap();
        assert_eq!(checkpoint["checkpoint"]["version"], CHECKPOINT_VERSION);
        assert_eq!(
            checkpoint["checkpoint"]["send_batch_members"]
                .as_array()
                .unwrap()
                .len(),
            2,
        );
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
        restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        let batch = restored.send_batch_status(&batch_id).unwrap();
        assert_eq!(batch["state"], "frozen");
        assert_eq!(batch["participant_count"], 2);
        assert_eq!(batch["member_count"], 2);
        assert_eq!(
            restored.checkpoint().unwrap()["checkpoint_hash"],
            restored
                .db
                .meta("restored_checkpoint_hash")
                .unwrap()
                .unwrap(),
        );
    }

    #[test]
    fn checkpoint_round_trips_signed_fee_locks_and_batch_reserves() {
        let dir = tempfile::tempdir().unwrap();
        let key = [86u8; 32];
        let binding = [87u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let funding = fund(&mut original, 60_000);
        let funding_transaction = original.bitcoin.get_tx(funding.txid).unwrap();
        let signed_hex = hex_encode(&serialize(funding_transaction.tx_node.tx.as_ref()));
        original
            .insert_planned_operation("signed-member", "transfer", "{}", "delivery")
            .unwrap();
        original
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'signed_persisted', funding_txid = ?2,
                     funding_vout = ?3, funding_value_sats = 60000,
                     signed_tx_hex = ?4, txid = ?2
                 WHERE operation_id = ?1",
                params![
                    "signed-member",
                    funding.txid.to_string(),
                    funding.vout,
                    signed_hex,
                ],
            )
            .unwrap();
        original
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_utxo_reservations(
                     txid, vout, operation_id, state, created_at
                 ) VALUES(?1, ?2, 'signed-member', 'signature_released', 1)",
                params![funding.txid.to_string(), funding.vout],
            )
            .unwrap();
        original.bitcoin.lock_outpoint(funding);
        original.bitcoin.persist(&mut original.db).unwrap();
        original
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_batch_stocks(
                     participant_count, txid, vout, value_sats, birth_height,
                     state, reserved_by_batch, created_at
                 ) VALUES(2, ?1, 7, 4000, 123, 'available', NULL, 1)",
                [funding.txid.to_string()],
            )
            .unwrap();
        original
            .db
            .conn
            .execute(
                "INSERT INTO opencsv_batch_reserve_operations(
                     maintenance_id, state, participant_count, stock_count,
                     fee_cell_count, signed_tx_hex, txid, receipt_json,
                     created_at, updated_at
                 ) VALUES(
                     'maintenance-1', 'mempool', 2, 3, 6, ?1, ?2, '{}', 1, 2
                 )",
                params![signed_hex, funding.txid.to_string()],
            )
            .unwrap();
        let checkpoint = original.checkpoint().unwrap();
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
        restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        assert!(restored.bitcoin.is_outpoint_locked(funding));
        assert_eq!(
            restored.cancel_operation("signed-member").unwrap_err().code,
            "cancellation_forbidden"
        );
        let restored_checkpoint = restored.checkpoint().unwrap();
        assert_eq!(
            restored_checkpoint["checkpoint"]["batch_stocks"],
            checkpoint["checkpoint"]["batch_stocks"]
        );
        assert_eq!(
            restored_checkpoint["checkpoint"]["batch_reserve_operations"],
            checkpoint["checkpoint"]["batch_reserve_operations"]
        );
        assert_eq!(
            restored_checkpoint["checkpoint_hash"],
            checkpoint["checkpoint_hash"]
        );
    }

    #[test]
    fn checkpoint_round_trips_protocol_rejected_operations() {
        let dir = tempfile::tempdir().unwrap();
        let key = [88u8; 32];
        let binding = [89u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let funding = fund(&mut original, 60_000);
        let funding_transaction = original.bitcoin.get_tx(funding.txid).unwrap();
        let signed_hex = hex_encode(&serialize(funding_transaction.tx_node.tx.as_ref()));
        original
            .insert_planned_operation("quarantined-spend", "transfer", "{}", "delivery")
            .unwrap();
        original
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations
                 SET state = 'protocol_rejected', funding_txid = ?2,
                     funding_vout = ?3, funding_value_sats = 60000,
                     signed_tx_hex = ?4, txid = ?2,
                     rejection_reason = 'duplicate_protocol_spend'
                 WHERE operation_id = ?1",
                params![
                    "quarantined-spend",
                    funding.txid.to_string(),
                    funding.vout,
                    signed_hex,
                ],
            )
            .unwrap();
        let checkpoint = original.checkpoint().unwrap();
        assert_eq!(
            checkpoint["checkpoint"]["operations"][0]["state"],
            json!(OperationState::ProtocolRejected.as_str())
        );
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
        restored
            .restore_checkpoint(&checkpoint.to_string())
            .unwrap();
        let operation = restored.operation("quarantined-spend").unwrap();
        assert_eq!(operation.state, OperationState::ProtocolRejected.as_str());
        assert_eq!(
            operation.rejection_reason.as_deref(),
            Some("duplicate_protocol_spend")
        );
        assert_eq!(
            restored
                .cancel_operation("quarantined-spend")
                .unwrap_err()
                .code,
            "cancellation_forbidden"
        );
        assert_eq!(
            restored.checkpoint().unwrap()["checkpoint_hash"],
            checkpoint["checkpoint_hash"]
        );
    }

    #[test]
    fn pre_reset_checkpoint_requires_a_fresh_test_usd_v2_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let key = [84u8; 32];
        let binding = [85u8; 32];
        let cfg = config(AccountRole::Primary, true);
        let mut original = AccountWallet::open_device_bound(
            &cfg,
            &key,
            &binding,
            dir.path().join("original.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let commitment = original.status().unwrap()["device_binding"]["commitment"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut legacy = original.checkpoint().unwrap();
        legacy["checkpoint"]["version"] = json!(LEGACY_CHECKPOINT_VERSION);
        legacy["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("send_batches");
        legacy["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("send_batch_members");
        legacy["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("batch_stocks");
        legacy["checkpoint"]
            .as_object_mut()
            .unwrap()
            .remove("batch_reserve_operations");
        let canonical = serde_json::to_vec(&legacy["checkpoint"]).unwrap();
        legacy["checkpoint_hash"] = json!(sha256::Hash::hash(&canonical).to_string());
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
                .restore_checkpoint(&legacy.to_string())
                .unwrap_err()
                .code,
            "testnet_reset_required",
        );
        assert!(restored
            .db
            .meta("restored_checkpoint_source_hash")
            .unwrap()
            .is_none());
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
        assert!(prepared["phase_timings_ms"]["funding_verification"].is_number());
        assert!(prepared["phase_timings_ms"]["local_proving"].is_number());
        assert!(prepared["phase_timings_ms"]["proof_total"].is_number());
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
    fn operation_backup_accepts_the_exact_staged_checkpoint_without_reproving() {
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
        let operation_id = prepared["operation_id"].as_str().unwrap();
        let prepared_hash = prepared["checkpoint_hash"].as_str().unwrap().to_owned();
        let before = wallet.operation(operation_id).unwrap();
        wallet
            .insert_planned_operation("later-operation", "transfer", "{}", "later-delivery-nonce")
            .unwrap();
        let current_hash = wallet.checkpoint().unwrap()["checkpoint_hash"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(current_hash, prepared_hash);
        assert_eq!(
            wallet
                .acknowledge_operation_backup(operation_id, "not-a-checkpoint")
                .unwrap_err()
                .code,
            "backup_checkpoint_mismatch"
        );
        let acknowledged = wallet
            .acknowledge_operation_backup(operation_id, &prepared_hash)
            .unwrap();
        assert_eq!(acknowledged["backup_acked"], true);
        assert_eq!(acknowledged["checkpoint_hash"], prepared_hash);
        let after = wallet.operation(operation_id).unwrap();
        assert!(after.backup_acked);
        assert_eq!(
            after.checkpoint_hash.as_deref(),
            Some(prepared_hash.as_str())
        );
        assert_eq!(after.request_json, before.request_json);
        assert_eq!(after.funding_txid, before.funding_txid);
        assert_eq!(after.funding_vout, before.funding_vout);
        let after_receipt: Value =
            serde_json::from_str(after.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(after_receipt["checkpoint_hash"], prepared_hash);
        assert_eq!(
            wallet.checkpoint().unwrap()["checkpoint_hash"],
            current_hash
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
        assert!(pending["receipt"]["phase_timings_ms"]["pre_sign_verification"].is_number());
        assert!(pending["receipt"]["phase_timings_ms"]["local_signing_persistence"].is_number());
        assert!(pending["receipt"]["phase_timings_ms"]["relay_submission"].is_number());
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
        assert!(observed["rejection_reason"].is_null());
        assert!(observed["receipt"]["phase_timings_ms"]["observer_evaluation"].is_number());
        assert!(wallet
            .operation(operation_id)
            .unwrap()
            .rejection_reason
            .is_none());
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
        let replacement_delivery_nonce = replacement_pending.delivery_nonce.clone();
        assert_eq!(
            replacement_pending.state,
            OperationState::SignedPersisted.as_str(),
        );
        assert_ne!(replacement_delivery_nonce, delivery_nonce);
        assert!(wallet.pending_by_operation.contains_key(&operation_id));
        let replacement_pending_receipt: Value =
            serde_json::from_str(replacement_pending.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(
            replacement_pending_receipt["delivery_nonce"],
            replacement_delivery_nonce,
        );
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
        let stale_ack = wallet
            .mark_consignment_delivered(&operation_id, &delivery_nonce)
            .unwrap_err();
        assert_eq!(stale_ack.code, "delivery_nonce_mismatch");
        let acknowledged = wallet
            .mark_consignment_delivered(&operation_id, &replacement_delivery_nonce)
            .unwrap();
        assert_eq!(acknowledged["receipt"]["consignment_delivered"], true);
    }

    #[test]
    fn confirmed_spv_can_finalize_replacement_without_raw_observer() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[73u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 100_000);
        let prepared = prepare_test_issuance(&mut wallet, "TSP", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .finalize_observed_operation(&operation_id, Txid::from_byte_array([74u8; 32]))
            .unwrap();

        let replacement_txid = Txid::from_byte_array([75u8; 32]);
        let mut replacement_receipt: Value = serde_json::from_str(
            wallet
                .operation(&operation_id)
                .unwrap()
                .receipt_json
                .as_deref()
                .unwrap(),
        )
        .unwrap();
        replacement_receipt["txid"] = json!(replacement_txid.to_string());
        wallet
            .persist_signed_replacement(
                &operation_id,
                "00",
                replacement_txid,
                &mut replacement_receipt,
            )
            .unwrap();
        wallet
            .db
            .conn
            .execute(
                "UPDATE opencsv_operations SET state = 'broadcast_unobserved'
                 WHERE operation_id = ?1",
                [&operation_id],
            )
            .unwrap();

        let operation = wallet.operation(&operation_id).unwrap();
        let receipt: Value =
            serde_json::from_str(operation.receipt_json.as_deref().unwrap()).unwrap();
        let (consignment, candidate) = wallet
            .spv_consignment_candidate(&operation_id, &operation, replacement_txid, &receipt)
            .unwrap();
        let consignment = Consignment::from_bytes(&consignment).unwrap();
        assert_eq!(consignment.anchor_ref.txid, replacement_txid.to_byte_array());
        assert_eq!(operation.state, OperationState::BroadcastUnobserved.as_str());
        assert!(wallet.pending_by_operation.contains_key(&operation_id));
        assert!(wallet
            .operation(&operation_id)
            .unwrap()
            .receipt_json
            .as_deref()
            .unwrap()
            .contains("replacement_delivery_required"));

        let (protocol_candidate, spends) = candidate.unwrap();
        let mut installed_receipt = receipt;
        wallet
            .install_spv_finalized_candidate(
                &operation_id,
                &consignment.to_bytes(),
                spends,
                protocol_candidate,
                &mut installed_receipt,
            )
            .unwrap();
        let settled = wallet.operation(&operation_id).unwrap();
        let settled_receipt: Value =
            serde_json::from_str(settled.receipt_json.as_deref().unwrap()).unwrap();
        assert_eq!(settled.state, OperationState::Confirmed.as_str());
        assert_eq!(settled_receipt["delivery_ready"], true);
        assert!(settled_receipt.get("replacement_delivery_required").is_none());
        assert!(!wallet.pending_by_operation.contains_key(&operation_id));
    }

    #[test]
    fn observation_receipt_detail_preserves_the_public_string_schema() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = AccountWallet::open(
            &config(AccountRole::Primary, true),
            &[76u8; 32],
            dir.path().join("wallet.sqlite").to_str().unwrap(),
        )
        .unwrap();
        let invalid = json!({
            "check_id": "multi_peer_spv_confirmation",
            "detail": { "status": "verified" },
        });
        let error = wallet
            .persist_observation_receipts("00", &[invalid])
            .unwrap_err();
        assert_eq!(error.code, "invalid_observation_evidence");

        let valid = json!({
            "check_id": "multi_peer_spv_confirmation",
            "detail": "verified exact transaction through the phone-owned multi-peer scan",
        });
        wallet
            .persist_observation_receipts("00", &[valid])
            .unwrap();
        let encoded: String = wallet
            .db
            .conn
            .query_row(
                "SELECT receipt_json FROM opencsv_observation_receipts
                 WHERE subject_txid = '00' AND check_id = 'multi_peer_spv_confirmation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let persisted: Value = serde_json::from_str(&encoded).unwrap();
        assert!(persisted["detail"].is_string());
    }

    #[test]
    fn account_open_repairs_legacy_object_observation_detail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let db = SqlitePersister::open(&path).unwrap();
        let legacy = json!({
            "check_id": "multi_peer_spv_confirmation",
            "detail": { "status": "verified", "reason": null },
        });
        db.conn
            .execute(
                "INSERT INTO opencsv_observation_receipts(
                     subject_txid, check_id, receipt_json, observed_at
                 ) VALUES('00', 'multi_peer_spv_confirmation', ?1, 1)",
                [legacy.to_string()],
            )
            .unwrap();
        drop(db);

        let repaired = SqlitePersister::open(&path).unwrap();
        let encoded: String = repaired
            .conn
            .query_row(
                "SELECT receipt_json FROM opencsv_observation_receipts
                 WHERE subject_txid = '00' AND check_id = 'multi_peer_spv_confirmation'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let receipt: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            receipt["detail"],
            "verified exact transaction through the phone-owned multi-peer scan"
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
        // Advance the wallet tip while the original remains unconfirmed.
        // Without an explicit replacement locktime, BDK would silently use
        // this newer height and violate the protected transaction context.
        fund(&mut wallet, 10_000);
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
        assert_eq!(replacement.version, original.version);
        assert_eq!(replacement.lock_time, original.lock_time);
        assert!(replacement
            .input
            .iter()
            .zip(&original.input)
            .all(|(new, old)| {
                new.previous_output == old.previous_output
                    && new.sequence == old.sequence
                    && new.script_sig == old.script_sig
            }));
        validate_solo_anchor_replacement(&original, &replacement).unwrap();
        let replacement_fee_sats = 100_000
            - replacement
                .output
                .iter()
                .map(|output| output.value.to_sat())
                .sum::<u64>();
        assert_eq!(bump_pending["receipt"]["fee_rate_sat_per_vb"], 5);
        assert_eq!(bump_pending["receipt"]["fee_sats"], replacement_fee_sats,);
        let replacement_txid = replacement.compute_txid();
        wallet
            .finalize_observed_operation(&operation_id, replacement_txid)
            .unwrap();
        let observed_replacement = wallet.operation(&operation_id).unwrap();
        wallet
            .mark_consignment_delivered(&operation_id, &observed_replacement.delivery_nonce)
            .unwrap();

        let second_bump = wallet.fee_bump(&operation_id, 8).unwrap();
        let second_replacement_hex = wallet
            .operation(&operation_id)
            .unwrap()
            .signed_tx_hex
            .unwrap();
        let second_replacement: Transaction =
            deserialize(&hex_decode(&second_replacement_hex, "second replacement tx").unwrap())
                .unwrap();
        validate_solo_anchor_replacement(&replacement, &second_replacement).unwrap();
        assert_eq!(second_bump["receipt"]["fee_rate_sat_per_vb"], 8);
        let second_replacement_txid = second_replacement.compute_txid();
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
            Some(second_replacement_hex.as_str())
        );
        assert!(reopened.bitcoin.get_tx(second_replacement_txid).is_some());
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
            Some(second_replacement_hex.as_str())
        );
    }

    #[test]
    fn fee_bump_enforces_configured_fee_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let mut config_value: Value = serde_json::from_str(&config_with_url(
            AccountRole::Primary,
            true,
            "http://127.0.0.1:1",
        ))
        .unwrap();
        config_value["max_fee_sats"] = json!(5_000);
        let mut wallet = AccountWallet::open(
            &config_value.to_string(),
            &[11u8; 32],
            path.to_str().unwrap(),
        )
        .unwrap();
        allow_funding_verification(&mut wallet);
        fund(&mut wallet, 100_000);
        let prepared = prepare_test_issuance(&mut wallet, "TFC", &[10]).unwrap();
        let operation_id = prepared["operation_id"].as_str().unwrap().to_owned();
        wallet
            .acknowledge_operation_backup(
                &operation_id,
                prepared["checkpoint_hash"].as_str().unwrap(),
            )
            .unwrap();
        wallet
            .sign_and_broadcast(
                &operation_id,
                &json!({ "target_sat_per_vb": 1, "max_fee_sats": 5_000 }).to_string(),
            )
            .unwrap();

        let below = wallet.fee_bump(&operation_id, 5).unwrap();
        assert_eq!(below["state"], OperationState::BroadcastUnobserved.as_str());
        let below_fee = below["receipt"]["fee_sats"].as_u64().unwrap();
        assert!(below_fee <= 5_000);
        let bumped_hex = wallet
            .operation(&operation_id)
            .unwrap()
            .signed_tx_hex
            .unwrap();

        let error = wallet.fee_bump(&operation_id, 50).unwrap_err();
        assert_eq!(error.code, "fee_limit_exceeded");
        // A rejected bump leaves the last persisted replacement untouched.
        let operation = wallet.operation(&operation_id).unwrap();
        assert_eq!(
            operation.state,
            OperationState::BroadcastUnobserved.as_str()
        );
        assert_eq!(
            operation.signed_tx_hex.as_deref(),
            Some(bumped_hex.as_str())
        );

        let still_bumpable = wallet.fee_bump(&operation_id, 8).unwrap();
        assert_eq!(
            still_bumpable["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        assert_ne!(
            wallet
                .operation(&operation_id)
                .unwrap()
                .signed_tx_hex
                .as_deref(),
            Some(bumped_hex.as_str())
        );
    }

    #[test]
    fn confirmed_original_wins_a_persisted_replacement_race() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet.sqlite");
        let (url, server) = confirmed_status_server(123);
        let cfg = config_with_url(AccountRole::Primary, true, &url);
        let key = [13_u8; 32];
        let mut wallet = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        allow_funding_verification(&mut wallet);
        let original_txid = fund(&mut wallet, 50_000).txid;
        let own_owner = wallet.status().unwrap()["owners"][0]
            .as_str()
            .unwrap()
            .to_owned();
        let asset_id = hex_encode(&[14u8; 32]);
        let operation_id = "replacement-race";
        install_replay_operation(
            &mut wallet,
            operation_id,
            &[(100, own_owner)],
            Vec::new(),
            &asset_id,
            15,
        );
        finalize_test_operation(&mut wallet, operation_id, original_txid);
        let original = wallet.operation(operation_id).unwrap();
        let original_delivery_nonce = original.delivery_nonce.clone();
        let original_receipt: Value =
            serde_json::from_str(original.receipt_json.as_deref().unwrap()).unwrap();
        let original_consignment_id = original_receipt["consignment_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let original_consignment_base64 = original_receipt["consignment_base64"]
            .as_str()
            .unwrap()
            .to_owned();
        wallet
            .mark_consignment_delivered(operation_id, &original_delivery_nonce)
            .unwrap();

        let replacement = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let replacement_txid = replacement.compute_txid();
        let mut replacement_receipt: Value = serde_json::from_str(
            wallet
                .operation(operation_id)
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
                operation_id,
                &hex_encode(&serialize(&replacement)),
                replacement_txid,
                &mut replacement_receipt,
            )
            .unwrap();
        let replacement_delivery_nonce = wallet.operation(operation_id).unwrap().delivery_nonce;
        assert_ne!(replacement_delivery_nonce, original_delivery_nonce);

        let receipt = wallet.resume_operation(operation_id).unwrap();
        assert_eq!(
            receipt["state"],
            OperationState::BroadcastUnobserved.as_str()
        );
        assert_eq!(receipt["confirmed"], false);
        assert_eq!(receipt["explorer_confirmed"], true);
        assert_eq!(receipt["requires_spv_confirmation"], true);
        assert_eq!(receipt["block_height"], 123);
        assert_eq!(receipt["txid"], original_txid.to_string());
        assert_eq!(receipt["delivery_nonce"], original_delivery_nonce);
        assert_eq!(receipt["receipt"]["delivery_ready"], true);
        assert_eq!(receipt["receipt"]["consignment_delivered"], true);
        assert_eq!(
            receipt["receipt"]["consignment_id"],
            original_consignment_id
        );
        assert_eq!(
            receipt["receipt"]["consignment_base64"],
            original_consignment_base64
        );
        assert!(receipt["receipt"].get("pre_replacement_delivery").is_none());
        assert!(receipt["receipt"].get("replaces").is_none());
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
        let restored_count: i64 = wallet
            .db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM opencsv_consignments WHERE consignment_id = ?1",
                [&original_consignment_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(restored_count, 1);
        assert_eq!(
            wallet
                .mark_consignment_delivered(operation_id, &replacement_delivery_nonce)
                .unwrap_err()
                .code,
            "delivery_nonce_mismatch"
        );
        server.join().unwrap();
        drop(wallet);
        let reopened = AccountWallet::open(&cfg, &key, path.to_str().unwrap()).unwrap();
        assert_eq!(
            reopened.operation(operation_id).unwrap().state,
            OperationState::BroadcastUnobserved.as_str()
        );
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
