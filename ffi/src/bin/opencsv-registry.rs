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
