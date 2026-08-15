//! Secret-free production registry release builder and verifier.
//!
//! This binary is deliberately absent from default and Signal builds. It is
//! available only with `registry-tools` so operators can reproduce the exact
//! release commitment accepted by the Rust account wallet.

use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use opencsv_ffi::account::{
    build_production_usd_registry_release, verify_production_usd_registry_release, AccountError,
};
use opencsv_ffi::production_issuance::{
    build_production_issuance_policy_json, verify_production_issuance_policy_json,
    verify_production_mint_authorization_json, ValidationError as IssuanceValidationError,
};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(
    name = "opencsv-registry",
    version,
    about = "Build and verify exact OpenCSV production registry releases"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Compute and write a canonical commitment for a draft release.
    Build {
        /// Draft JSON with commitment_sha256 omitted.
        #[arg(long)]
        input: PathBuf,
        /// New release file. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Recompute and verify a complete release without opening a wallet.
    Verify {
        /// Complete release JSON containing commitment_sha256.
        #[arg(long)]
        input: PathBuf,
        /// Exact deployment in the containing application configuration.
        #[arg(long)]
        expected_deployment: String,
    },
    /// Build and verify a distinct threshold-signed supply policy.
    #[command(subcommand)]
    IssuancePolicy(IssuancePolicyCommand),
    /// Verify one exact threshold-signed mint envelope.
    #[command(subcommand)]
    MintAuthorization(MintAuthorizationCommand),
}

#[derive(Subcommand)]
enum IssuancePolicyCommand {
    /// Compute and write a canonical commitment for a draft issuance policy.
    Build {
        /// Draft JSON with commitment_sha256 omitted.
        #[arg(long)]
        input: PathBuf,
        /// New policy file. Existing files are never overwritten.
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a policy against exact application release inputs.
    Verify {
        /// Complete policy JSON containing commitment_sha256.
        #[arg(long)]
        input: PathBuf,
        /// Exact production deployment expected by the application.
        #[arg(long)]
        expected_deployment: String,
        /// Exact production registry release version.
        #[arg(long)]
        expected_registry_version: u64,
        /// Exact issuer asset id admitted by that registry.
        #[arg(long)]
        expected_asset_id: String,
        /// Exact issuance-policy commitment authorized by the containing release.
        #[arg(long)]
        expected_policy_commitment: String,
    },
}

#[derive(Subcommand)]
enum MintAuthorizationCommand {
    /// Verify threshold signatures and the exact supply transition.
    Verify {
        /// Complete issuance policy JSON.
        #[arg(long)]
        policy: PathBuf,
        /// Complete signed mint-authorization JSON.
        #[arg(long)]
        authorization: PathBuf,
        /// Exact production deployment expected by the application.
        #[arg(long)]
        expected_deployment: String,
        /// Exact production registry release commitment.
        #[arg(long)]
        expected_registry_commitment: String,
        /// Exact production registry release version.
        #[arg(long)]
        expected_registry_version: u64,
        /// Exact issuer asset id admitted by that registry.
        #[arg(long)]
        expected_asset_id: String,
        /// Exact issuance-policy commitment authorized by the containing release.
        #[arg(long)]
        expected_policy_commitment: String,
        /// Exact recipient owner identity.
        #[arg(long)]
        expected_to_owner: String,
        /// One or two exact output amounts.
        #[arg(long = "expected-amount", required = true, num_args = 1..=2)]
        expected_amounts: Vec<u64>,
        /// Explicit evaluation time; the verifier never hides host-clock input.
        #[arg(long)]
        at_unix_seconds: u64,
    },
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

impl From<IssuanceValidationError> for CliError {
    fn from(error: IssuanceValidationError) -> Self {
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
    match cli.command {
        Command::Build { input, output } => {
            let draft = read_text(&input)?;
            let release = build_production_usd_registry_release(&draft)?;
            write_release(&output, &release)
        }
        Command::Verify {
            input,
            expected_deployment,
        } => {
            let release = read_text(&input)?;
            verify_production_usd_registry_release(&release, &expected_deployment)
                .map_err(Into::into)
        }
        Command::IssuancePolicy(IssuancePolicyCommand::Build { input, output }) => {
            let draft = read_text(&input)?;
            let policy = build_production_issuance_policy_json(&draft)?;
            write_release(&output, &policy)
        }
        Command::IssuancePolicy(IssuancePolicyCommand::Verify {
            input,
            expected_deployment,
            expected_registry_version,
            expected_asset_id,
            expected_policy_commitment,
        }) => {
            let policy = read_text(&input)?;
            verify_production_issuance_policy_json(
                &policy,
                &expected_deployment,
                expected_registry_version,
                &expected_asset_id,
                &expected_policy_commitment,
            )
            .map_err(Into::into)
        }
        Command::MintAuthorization(MintAuthorizationCommand::Verify {
            policy,
            authorization,
            expected_deployment,
            expected_registry_commitment,
            expected_registry_version,
            expected_asset_id,
            expected_policy_commitment,
            expected_to_owner,
            expected_amounts,
            at_unix_seconds,
        }) => {
            let policy = read_text(&policy)?;
            let authorization = read_text(&authorization)?;
            verify_production_mint_authorization_json(
                &policy,
                &authorization,
                &expected_deployment,
                expected_registry_version,
                &expected_registry_commitment,
                &expected_asset_id,
                &expected_policy_commitment,
                &expected_to_owner,
                &expected_amounts,
                at_unix_seconds,
            )
            .map_err(Into::into)
        }
    }
}

fn read_text(path: &Path) -> Result<String, CliError> {
    fs::read_to_string(path).map_err(|error| {
        CliError::new(
            "registry_read_failed",
            format!("{}: {error}", path.display()),
        )
    })
}

fn write_release(path: &Path, release: &Value) -> Result<Value, CliError> {
    let commitment = release
        .get("commitment_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::new("registry_encode_failed", "release has no commitment"))?;
    let mut encoded = serde_json::to_vec_pretty(release)
        .map_err(|error| CliError::new("registry_encode_failed", error.to_string()))?;
    encoded.push(b'\n');

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == ErrorKind::AlreadyExists {
                CliError::new(
                    "registry_output_exists",
                    format!("refusing to overwrite {}", path.display()),
                )
            } else {
                CliError::new(
                    "registry_write_failed",
                    format!("could not create {}: {error}", path.display()),
                )
            }
        })?;
    if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(CliError::new(
            "registry_write_failed",
            format!("could not durably write {}: {error}", path.display()),
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    drop(file);
    if let Err(error) = fs::File::open(parent).and_then(|directory| directory.sync_all()) {
        let cleanup = fs::remove_file(path)
            .map(|()| "incomplete output removed".to_owned())
            .unwrap_or_else(|cleanup_error| format!("cleanup also failed: {cleanup_error}"));
        return Err(CliError::new(
            "registry_write_failed",
            format!("could not sync {}: {error}; {cleanup}", parent.display()),
        ));
    }
    Ok(json!({
        "commitment_sha256": commitment,
        "output": path.display().to_string(),
        "bytes": encoded.len(),
    }))
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
    fn parses_secret_free_build_and_verify_commands() {
        let build = Cli::try_parse_from([
            "opencsv-registry",
            "build",
            "--input",
            "draft.json",
            "--output",
            "release.json",
        ])
        .unwrap();
        assert!(matches!(build.command, Command::Build { .. }));

        let verify = Cli::try_parse_from([
            "opencsv-registry",
            "verify",
            "--input",
            "release.json",
            "--expected-deployment",
            "opencsv-mainnet-candidate-v1",
        ])
        .unwrap();
        assert!(matches!(verify.command, Command::Verify { .. }));

        let policy = Cli::try_parse_from([
            "opencsv-registry",
            "issuance-policy",
            "verify",
            "--input",
            "policy.json",
            "--expected-deployment",
            "opencsv-mainnet-v1",
            "--expected-registry-version",
            "1",
            "--expected-asset-id",
            &"22".repeat(32),
            "--expected-policy-commitment",
            &"33".repeat(32),
        ])
        .unwrap();
        assert!(matches!(
            policy.command,
            Command::IssuancePolicy(IssuancePolicyCommand::Verify { .. })
        ));

        let authorization = Cli::try_parse_from([
            "opencsv-registry",
            "mint-authorization",
            "verify",
            "--policy",
            "policy.json",
            "--authorization",
            "authorization.json",
            "--expected-deployment",
            "opencsv-mainnet-v1",
            "--expected-registry-commitment",
            &"11".repeat(32),
            "--expected-registry-version",
            "1",
            "--expected-asset-id",
            &"22".repeat(32),
            "--expected-policy-commitment",
            &"44".repeat(32),
            "--expected-to-owner",
            &"33".repeat(32),
            "--expected-amount",
            "10",
            "--at-unix-seconds",
            "2000",
        ])
        .unwrap();
        assert!(matches!(
            authorization.command,
            Command::MintAuthorization(MintAuthorizationCommand::Verify { .. })
        ));
    }

    #[test]
    fn release_output_is_durable_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release.json");
        let release = json!({ "commitment_sha256": "ab".repeat(32) });
        let receipt = write_release(&path, &release).unwrap();
        assert_eq!(receipt["commitment_sha256"], "ab".repeat(32));
        assert!(fs::read_to_string(&path).unwrap().ends_with('\n'));
        assert_eq!(
            write_release(&path, &release).unwrap_err().reason,
            "registry_output_exists"
        );
    }

    #[test]
    fn checked_in_candidate_has_a_stable_nonactivating_commitment() {
        let draft = include_str!("../../examples/production_registry_candidate_draft.json");
        let release = build_production_usd_registry_release(draft).unwrap();
        assert_eq!(
            release["commitment_sha256"],
            "bf808e3e0a5fad6cbc8caf23741e82adb5fbe5dd21dfb5a00840fd0801361169"
        );
        let verified = verify_production_usd_registry_release(
            &release.to_string(),
            "opencsv-mainnet-candidate-v1",
        )
        .unwrap();
        assert_eq!(verified["structurally_valid"], true);
        assert_eq!(verified["activation_authorized"], false);
        assert_eq!(verified["phase"], "candidate");
        assert_eq!(verified["issuer_count"], 0);
    }
}
