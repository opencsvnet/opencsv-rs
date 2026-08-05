//! Headless operator interface for OpenCSV issuers.
//!
//! This binary is deliberately absent from the default `opencsv-ffi` build.
//! Build it explicitly with `--features issuer-tools`. Signal never enables
//! that feature and its C ABI exposes no issuer operation.

use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use base64::Engine;
use clap::{Args, Parser, Subcommand};
use opencsv_ffi::account::{AccountError, AccountWallet};
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "opencsv-issuer",
    version,
    about = "Headless OpenCSV issuer operator (never linked into Signal)"
)]
struct Cli {
    /// Issuer account SQLite database.
    #[arg(long, env = "OPENCSV_ISSUER_DATABASE")]
    database: PathBuf,

    /// Account-wallet configuration JSON.
    #[arg(long, env = "OPENCSV_ISSUER_CONFIG")]
    config: PathBuf,

    /// Owner-only file containing the 32-byte account root as raw bytes or hex.
    #[arg(long, env = "OPENCSV_ISSUER_ACCOUNT_ROOT_FILE")]
    account_root_file: PathBuf,

    /// Owner-only file containing the 32-byte device binding as raw bytes or hex.
    #[arg(long, env = "OPENCSV_ISSUER_DEVICE_BINDING_FILE")]
    device_binding_file: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show balances, public identities, issuer manifests, and write readiness.
    Status,
    /// Synchronize the fee wallet and OpenCSV operation journal.
    Sync,
    /// Manage issuer-controlled instrument manifests.
    #[command(subcommand)]
    Instrument(InstrumentCommand),
    /// Export and acknowledge durable issuer checkpoints.
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Prepare issuer-authorized mint operations.
    #[command(subcommand)]
    Mint(MintCommand),
    /// Inspect and advance durable mint operations.
    #[command(subcommand)]
    Operation(OperationCommand),
}

#[derive(Subcommand)]
enum InstrumentCommand {
    /// Create an exact issuer manifest from an InstrumentTermsV1 JSON file.
    Create {
        /// File containing either InstrumentTermsV1 or `{ "terms": ... }`.
        #[arg(long)]
        terms: PathBuf,
    },
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Export the complete versioned checkpoint as JSON.
    Export {
        /// Create an owner-only checkpoint file instead of printing secrets to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Confirm that the exact current checkpoint was stored durably elsewhere.
    Acknowledge {
        #[arg(long)]
        checkpoint_hash: String,
    },
}

#[derive(Subcommand)]
enum MintCommand {
    /// Reserve fees and prepare a proof for an existing issuer-controlled asset.
    Prepare {
        /// Exact asset id from the issuer manifest; ticker labels are rejected.
        #[arg(long)]
        asset_id: String,
        /// One or two positive protocol base-unit outputs.
        #[arg(long = "amount", required = true, num_args = 1..=2)]
        amounts: Vec<u64>,
        /// Exact recipient owner identity. Omit to mint to this issuer account.
        #[arg(long)]
        to_owner: Option<String>,
    },
}

#[derive(Subcommand)]
enum OperationCommand {
    /// Print one durable operation and its current state.
    Status(OperationId),
    /// Export a delivery-ready consignment as an owner-only binary attachment.
    ExportConsignment {
        #[command(flatten)]
        operation: OperationId,
        /// Create this file without overwriting an existing attachment.
        #[arg(long)]
        output: PathBuf,
    },
    /// Acknowledge the exact checkpoint emitted by mint preparation.
    AcknowledgeBackup {
        #[command(flatten)]
        operation: OperationId,
        #[arg(long)]
        checkpoint_hash: String,
    },
    /// Sign, persist, and broadcast a prepared protocol transaction.
    Broadcast {
        #[command(flatten)]
        operation: OperationId,
        #[arg(long)]
        sat_per_vb: u64,
        #[arg(long)]
        max_fee_sats: Option<u64>,
    },
    /// Resume an interrupted operation idempotently.
    Resume(OperationId),
    /// Admit exact unconfirmed bytes after independent pinned observation.
    Observe {
        #[command(flatten)]
        operation: OperationId,
        /// File containing the exact raw Bitcoin transaction bytes.
        #[arg(long)]
        raw_transaction: PathBuf,
        /// JSON file containing observation evidence from the pinned client.
        #[arg(long)]
        observations: PathBuf,
    },
    /// Cancel an operation that has not been broadcast.
    Cancel(OperationId),
    /// Replace an OpenCSV-created unconfirmed transaction without changing its protocol layout.
    FeeBump {
        #[command(flatten)]
        operation: OperationId,
        #[arg(long)]
        sat_per_vb: u64,
    },
}

#[derive(Args)]
struct OperationId {
    #[arg(long)]
    operation_id: String,
}

#[derive(Debug)]
struct CliError {
    reason: String,
    message: String,
}

impl CliError {
    fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
        }
    }

    fn json(&self) -> Value {
        json!({ "reason": self.reason, "error": self.message })
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.message)
    }
}

impl From<AccountError> for CliError {
    fn from(error: AccountError) -> Self {
        Self::new(error.code, error.message)
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(encoded) => {
                println!("{encoded}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(CliError::new("json_encode_failed", error.to_string())),
        },
        Err(error) => fail(error),
    }
}

fn fail(error: CliError) -> ExitCode {
    let encoded = serde_json::to_string(&error.json())
        .unwrap_or_else(|_| "{\"reason\":\"unknown\",\"error\":\"unknown\"}".to_owned());
    eprintln!("{encoded}");
    ExitCode::FAILURE
}

fn run(cli: Cli) -> Result<Value, CliError> {
    let config = read_text(&cli.config, "config_read_failed")?;
    let account_root = read_secret(&cli.account_root_file, "account root")?;
    let device_binding = read_secret(&cli.device_binding_file, "device binding")?;
    validate_secret_separation(&account_root, &device_binding)?;
    let database = cli.database.to_str().ok_or_else(|| {
        CliError::new("invalid_database_path", "database path is not valid UTF-8")
    })?;
    let mut wallet = AccountWallet::open_device_bound(
        &config,
        account_root.as_ref(),
        device_binding.as_ref(),
        database,
    )?;

    match cli.command {
        Command::Status => wallet.status().map_err(Into::into),
        Command::Sync => wallet.sync().map_err(Into::into),
        Command::Instrument(InstrumentCommand::Create { terms }) => {
            let value = read_json(&terms, "invalid_instrument_terms")?;
            let request = if value.get("terms").is_some() {
                value
            } else {
                json!({ "terms": value })
            };
            wallet
                .instrument_create(&request.to_string())
                .map_err(Into::into)
        }
        Command::Backup(BackupCommand::Export { output }) => {
            let checkpoint = wallet.checkpoint()?;
            match output {
                Some(path) => write_checkpoint(&path, &checkpoint),
                None => Ok(checkpoint),
            }
        }
        Command::Backup(BackupCommand::Acknowledge { checkpoint_hash }) => wallet
            .acknowledge_checkpoint_backup(&checkpoint_hash)
            .map_err(Into::into),
        Command::Mint(MintCommand::Prepare {
            asset_id,
            amounts,
            to_owner,
        }) => {
            let mut request = json!({ "asset_id": asset_id, "amounts": amounts });
            if let Some(to_owner) = to_owner {
                request["to_owner"] = Value::String(to_owner);
            }
            wallet
                .mint_prepare(&request.to_string())
                .map_err(Into::into)
        }
        Command::Operation(OperationCommand::Status(operation)) => wallet
            .operation_status(&operation.operation_id)
            .map_err(Into::into),
        Command::Operation(OperationCommand::ExportConsignment { operation, output }) => {
            let status = wallet.operation_status(&operation.operation_id)?;
            write_consignment(&output, &status)
        }
        Command::Operation(OperationCommand::AcknowledgeBackup {
            operation,
            checkpoint_hash,
        }) => wallet
            .acknowledge_operation_backup(&operation.operation_id, &checkpoint_hash)
            .map_err(Into::into),
        Command::Operation(OperationCommand::Broadcast {
            operation,
            sat_per_vb,
            max_fee_sats,
        }) => wallet
            .sign_and_broadcast(
                &operation.operation_id,
                &json!({
                    "target_sat_per_vb": sat_per_vb,
                    "max_fee_sats": max_fee_sats,
                })
                .to_string(),
            )
            .map_err(Into::into),
        Command::Operation(OperationCommand::Resume(operation)) => wallet
            .resume_operation(&operation.operation_id)
            .map_err(Into::into),
        Command::Operation(OperationCommand::Observe {
            operation,
            raw_transaction,
            observations,
        }) => {
            let raw_transaction = fs::read(&raw_transaction).map_err(|error| {
                CliError::new(
                    "raw_transaction_read_failed",
                    format!("{}: {error}", raw_transaction.display()),
                )
            })?;
            let observations = read_text(&observations, "observation_evidence_read_failed")?;
            wallet
                .observe_operation_unconfirmed(
                    &operation.operation_id,
                    &raw_transaction,
                    &observations,
                )
                .map_err(Into::into)
        }
        Command::Operation(OperationCommand::Cancel(operation)) => wallet
            .cancel_operation(&operation.operation_id)
            .map_err(Into::into),
        Command::Operation(OperationCommand::FeeBump {
            operation,
            sat_per_vb,
        }) => wallet
            .fee_bump(&operation.operation_id, sat_per_vb)
            .map_err(Into::into),
    }
}

fn read_text(path: &Path, reason: &'static str) -> Result<String, CliError> {
    fs::read_to_string(path)
        .map_err(|error| CliError::new(reason, format!("{}: {error}", path.display())))
}

fn read_json(path: &Path, reason: &'static str) -> Result<Value, CliError> {
    let text = read_text(path, reason)?;
    serde_json::from_str(&text).map_err(|error| {
        CliError::new(
            reason,
            format!("{} is not valid JSON: {error}", path.display()),
        )
    })
}

fn write_checkpoint(path: &Path, checkpoint: &Value) -> Result<Value, CliError> {
    let checkpoint_hash = checkpoint
        .get("checkpoint_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new("checkpoint_encode_failed", "checkpoint has no hash"))?;
    let mut encoded = serde_json::to_vec_pretty(checkpoint)
        .map_err(|error| CliError::new("checkpoint_encode_failed", error.to_string()))?;
    encoded.push(b'\n');

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            CliError::new(
                "checkpoint_output_exists",
                format!("refusing to overwrite {}", path.display()),
            )
        } else {
            CliError::new(
                "checkpoint_write_failed",
                format!("could not create {}: {error}", path.display()),
            )
        }
    })?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CliError::new(
            "checkpoint_write_failed",
            format!("could not durably write {}: {error}", path.display()),
        ));
    }
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                CliError::new(
                    "checkpoint_write_failed",
                    format!("could not sync {}: {error}", parent.display()),
                )
            })?;
    }
    Ok(json!({
        "checkpoint_hash": checkpoint_hash,
        "output": path.display().to_string(),
        "bytes": encoded.len(),
    }))
}

fn write_consignment(path: &Path, operation: &Value) -> Result<Value, CliError> {
    let operation_id = operation
        .get("operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new("consignment_unavailable", "operation has no id"))?;
    let receipt = operation
        .get("receipt")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            CliError::new(
                "consignment_unavailable",
                "operation has no delivery-ready receipt",
            )
        })?;
    if receipt.get("delivery_ready").and_then(Value::as_bool) != Some(true) {
        return Err(CliError::new(
            "consignment_unavailable",
            "operation receipt is not delivery-ready",
        ));
    }
    let consignment_id = receipt
        .get("consignment_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new("consignment_unavailable", "receipt has no consignment id"))?;
    let encoded = receipt
        .get("consignment_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new("consignment_unavailable", "receipt has no consignment"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| CliError::new("consignment_decode_failed", error.to_string()))?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == ErrorKind::AlreadyExists {
            CliError::new(
                "consignment_output_exists",
                format!("refusing to overwrite {}", path.display()),
            )
        } else {
            CliError::new(
                "consignment_write_failed",
                format!("could not create {}: {error}", path.display()),
            )
        }
    })?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CliError::new(
            "consignment_write_failed",
            format!("could not durably write {}: {error}", path.display()),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            CliError::new(
                "consignment_write_failed",
                format!("could not sync {}: {error}", parent.display()),
            )
        })?;
    Ok(json!({
        "operation_id": operation_id,
        "consignment_id": consignment_id,
        "output": path.display().to_string(),
        "bytes": bytes.len(),
    }))
}

fn read_secret(path: &Path, label: &'static str) -> Result<Zeroizing<[u8; 32]>, CliError> {
    #[cfg(unix)]
    {
        let permissions = fs::metadata(path)
            .map_err(|error| {
                CliError::new(
                    "secret_read_failed",
                    format!("could not inspect {label} file {}: {error}", path.display()),
                )
            })?
            .permissions()
            .mode();
        if permissions & 0o077 != 0 {
            return Err(CliError::new(
                "insecure_secret_permissions",
                format!(
                    "{label} file {} must be owner-only (mode 0600)",
                    path.display()
                ),
            ));
        }
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|error| {
        CliError::new(
            "secret_read_failed",
            format!("could not read {label} file {}: {error}", path.display()),
        )
    })?);
    decode_secret(bytes.as_slice(), label).map(Zeroizing::new)
}

fn validate_secret_separation(
    account_root: &[u8; 32],
    device_binding: &[u8; 32],
) -> Result<(), CliError> {
    if account_root == device_binding {
        return Err(CliError::new(
            "secret_separation_required",
            "account root and device binding must be independently generated",
        ));
    }
    Ok(())
}

fn decode_secret(bytes: &[u8], label: &'static str) -> Result<[u8; 32], CliError> {
    if let Ok(raw) = <[u8; 32]>::try_from(bytes) {
        return Ok(raw);
    }
    let encoded = std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| CliError::new("invalid_secret", format!("{label} is not raw or hex")))?;
    if encoded.len() != 64 {
        return Err(CliError::new(
            "invalid_secret",
            format!("{label} must contain exactly 32 raw bytes or 64 hex characters"),
        ));
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).map_err(|_| {
            CliError::new(
                "invalid_secret",
                format!("{label} is not valid hexadecimal"),
            )
        })?;
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn command_shape_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_exact_asset_mint_without_a_ticker_shortcut() {
        let cli = Cli::try_parse_from([
            "opencsv-issuer",
            "--database",
            "issuer.sqlite",
            "--config",
            "config.json",
            "--account-root-file",
            "root.secret",
            "--device-binding-file",
            "device.secret",
            "mint",
            "prepare",
            "--asset-id",
            "0123",
            "--amount",
            "1000000",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Mint(MintCommand::Prepare { asset_id, .. }) if asset_id == "0123"
        ));
    }

    #[test]
    fn decodes_raw_and_hex_secrets() {
        assert_eq!(decode_secret(&[7_u8; 32], "test").unwrap(), [7_u8; 32]);
        let encoded = format!("{}\n", "ab".repeat(32));
        assert_eq!(
            decode_secret(encoded.as_bytes(), "test").unwrap(),
            [0xab; 32]
        );
    }

    #[test]
    fn account_root_and_device_binding_must_be_distinct() {
        assert_eq!(
            validate_secret_separation(&[9_u8; 32], &[9_u8; 32])
                .unwrap_err()
                .reason,
            "secret_separation_required"
        );
        validate_secret_separation(&[9_u8; 32], &[10_u8; 32]).unwrap();
    }

    #[test]
    fn checkpoint_output_is_owner_only_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.json");
        let checkpoint = json!({ "checkpoint_hash": "exact-hash", "version": 1 });

        let receipt = write_checkpoint(&path, &checkpoint).unwrap();
        assert_eq!(receipt["checkpoint_hash"], "exact-hash");
        assert_eq!(receipt["output"], path.to_string_lossy().as_ref());
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{\n  \"checkpoint_hash\": \"exact-hash\",\n  \"version\": 1\n}\n"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        assert_eq!(
            write_checkpoint(&path, &checkpoint).unwrap_err().reason,
            "checkpoint_output_exists"
        );
    }

    #[test]
    fn consignment_output_is_owner_only_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opencsv-consignment.bin");
        let operation = json!({
            "operation_id": "mint-1",
            "receipt": {
                "delivery_ready": true,
                "consignment_id": "exact-id",
                "consignment_base64": "AQIDBA==",
            }
        });

        let receipt = write_consignment(&path, &operation).unwrap();
        assert_eq!(receipt["operation_id"], "mint-1");
        assert_eq!(receipt["consignment_id"], "exact-id");
        assert_eq!(fs::read(&path).unwrap(), [1, 2, 3, 4]);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        assert_eq!(
            write_consignment(&path, &operation).unwrap_err().reason,
            "consignment_output_exists"
        );
    }
}
