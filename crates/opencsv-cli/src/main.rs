//! `opencsv` — thin command-line front end over the `opencsv-cli` library.
//!
//! All wallet logic lives in the library (`src/lib.rs` and modules) so a
//! future Signal transport crate can reuse it; this binary only parses
//! arguments, prints results, and moves consignment blobs as files (or
//! base64/hex on stdout with `--print-blob`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use clap::{Parser, Subcommand};
use opencsv_cli::error::{io_err, Error};
use opencsv_cli::hexutil::{digest_from_hex, to_hex};
use opencsv_cli::httpchain::ChainBackend;
use opencsv_cli::ops::{self, Produced, ReceiveReport, DEFAULT_CONFIRMATIONS};
use opencsv_cli::store::Wallet;
use opencsv_core::{AnchorChain, Owner};

/// OpenCSV text wallet (prototype — plaintext keys, file-backed demo chain).
#[derive(Parser)]
#[command(name = "opencsv", version, about, long_about = None)]
struct Cli {
    /// Wallet directory (default: ~/.opencsv).
    #[arg(long, global = true)]
    wallet_dir: Option<PathBuf>,
    /// Anchor chain file (default: <wallet-dir>/chain.log). Point several
    /// wallets at the same file to simulate the shared L1 view.
    #[arg(long, global = true)]
    chain: Option<PathBuf>,
    /// Anchor via a shared opencsv-anchor-server (http://host:port) instead
    /// of the local chain file — required when other parties (e.g. a phone
    /// wallet) share the chain over HTTP.
    #[arg(long, global = true)]
    anchor_server: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new owner identity.
    Keygen,
    /// List owner identities.
    Keys,
    /// Issuer operations.
    #[command(subcommand)]
    Issuer(IssuerCmd),
    /// Mint new coins (issuer only), anchor, and write a consignment blob.
    Mint {
        /// Asset id (hex).
        #[arg(long)]
        asset: String,
        /// Recipient: `self` or an owner public key (hex).
        #[arg(long)]
        to: String,
        /// 1 or 2 comma-separated amounts in base units.
        #[arg(long)]
        amounts: String,
        /// Directory to write the consignment blob into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Also print the blob (base64) on stdout.
        #[arg(long)]
        print_blob: bool,
    },
    /// Spend exactly 2 coins (2-in/2-out transfer), anchor, and write a
    /// consignment blob for the recipient.
    Send {
        /// Comma-separated coin id prefixes of the 2 inputs.
        #[arg(long)]
        inputs: String,
        /// Recipient: `self` or an owner public key (hex).
        #[arg(long)]
        to: String,
        /// 1 or 2 comma-separated amounts; must sum to the input total.
        #[arg(long)]
        amounts: String,
        /// Directory to write the consignment blob into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Also print the blob (base64) on stdout.
        #[arg(long)]
        print_blob: bool,
        /// Skip the local spent check (double-spend DETECTION demo only).
        #[arg(long, hide = true)]
        force_respend: bool,
    },
    /// Verify a received consignment blob and store the coins.
    Receive {
        /// Consignment blob file.
        file: PathBuf,
        /// Required confirmation depth (paper §4.7 rule 2).
        #[arg(long, default_value_t = DEFAULT_CONFIRMATIONS)]
        confirmations: u64,
    },
    /// Burn a coin back to the issuer and write the redeem blob.
    Redeem {
        /// Coin id prefix.
        #[arg(long)]
        coin: String,
        /// Directory to write the consignment blob into.
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Also print the blob (base64) on stdout.
        #[arg(long)]
        print_blob: bool,
    },
    /// List stored coins.
    Coins,
    /// Unspent balances per asset.
    Balance {
        /// Restrict to one asset (hex).
        #[arg(long)]
        asset: Option<String>,
    },
    /// List pinned assets.
    Assets,
    /// Public supply of an asset from the anchor chain (paper §4.9).
    Audit {
        /// Asset id (hex).
        #[arg(long)]
        asset: String,
        /// Audit at this height (default: chain tip).
        #[arg(long)]
        height: Option<u64>,
    },
    /// Demo chain control.
    #[command(subcommand)]
    Chain(ChainCmd),
    /// Signal transport: link as a secondary device and move consignments
    /// as Signal attachments (feature `signal`).
    #[cfg(feature = "signal")]
    #[command(subcommand)]
    Signal(SignalCmd),
}

#[derive(Subcommand)]
enum IssuerCmd {
    /// Create an issuer key and asset genesis; prints the asset id.
    Init {
        /// ISO-4217-style 3-letter currency code (e.g. USD).
        #[arg(long)]
        currency: String,
    },
}

#[derive(Subcommand)]
enum ChainCmd {
    /// Print the chain tip height.
    Tip,
    /// Advance the tip (simulate mining).
    Advance {
        /// Number of blocks.
        #[arg(default_value_t = 1)]
        n: u64,
    },
}

/// Signal transport commands (feature `signal`).
#[cfg(feature = "signal")]
#[derive(Subcommand)]
enum SignalCmd {
    /// Link this client to your Signal account as a secondary device:
    /// prints a provisioning QR code to scan with the phone. Re-running
    /// loads the existing registration instead of re-linking.
    Link {
        /// Device name shown in the phone's Linked Devices list.
        #[arg(long, default_value = "opencsv")]
        device_name: String,
        /// Signal store directory (default: <wallet-dir>/signal).
        #[arg(long)]
        store_dir: Option<PathBuf>,
    },
    /// Send a consignment blob file as a Signal attachment.
    Send {
        /// Recipient: `self` (Note to Self), an ACI uuid, or an E.164
        /// phone number (resolved via the synced contacts).
        #[arg(long)]
        to: String,
        /// Consignment blob file (as written by mint/send/redeem).
        file: PathBuf,
        /// Signal store directory (default: <wallet-dir>/signal).
        #[arg(long)]
        store_dir: Option<PathBuf>,
    },
    /// Listen for incoming consignments and verify them into the wallet.
    /// Runs until Ctrl-C.
    Listen {
        /// Required confirmation depth (paper §4.7 rule 2).
        #[arg(long, default_value_t = DEFAULT_CONFIRMATIONS)]
        confirmations: u64,
        /// Signal store directory (default: <wallet-dir>/signal).
        #[arg(long)]
        store_dir: Option<PathBuf>,
    },
}

fn default_wallet_dir() -> PathBuf {
    let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".opencsv")
}

fn main() -> ExitCode {
    // Signal debugging: `RUST_LOG=debug opencsv signal …` surfaces presage /
    // libsignal logs (e.g. the note-to-self transcript path) on stderr.
    #[cfg(feature = "signal")]
    {
        use tracing_subscriber::EnvFilter;
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Error> {
    let wallet_dir = cli.wallet_dir.clone().unwrap_or_else(default_wallet_dir);
    let wallet = Wallet::open(&wallet_dir)?;
    let chain_path = cli
        .chain
        .clone()
        .unwrap_or_else(|| wallet_dir.join("chain.log"));
    let anchor_server = cli.anchor_server.clone();
    match cli.command {
        Commands::Keygen => {
            let mut wallet = wallet;
            let owner = ops::keygen(&mut wallet)?;
            println!(
                "key {} owner {}",
                wallet.secrets().len() - 1,
                to_hex(owner.as_bytes())
            );
        }
        Commands::Keys => {
            for (i, secret) in wallet.secrets().iter().enumerate() {
                println!("key {i} owner {}", to_hex(secret.owner().as_bytes()));
            }
        }
        Commands::Issuer(IssuerCmd::Init { currency }) => {
            let code = currency.as_bytes();
            let code: [u8; 3] = code.try_into().map_err(|_| {
                Error::Parse(format!(
                    "currency code must be 3 ASCII letters, got `{currency}`"
                ))
            })?;
            let mut wallet = wallet;
            let asset_id = ops::issuer_init(&mut wallet, code)?;
            println!("asset {}", to_hex(asset_id.as_bytes()));
        }
        Commands::Mint {
            asset,
            to,
            amounts,
            out,
            print_blob,
        } => {
            let asset = digest_from_hex(&asset)?;
            let to = parse_recipient(&wallet, &to)?;
            let amounts = parse_amounts(&amounts)?;
            eprintln!("proving mint… (~1s in release, tens of seconds in debug)");
            let mut wallet = wallet;
            let mut chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            let produced = ops::mint(&mut wallet, &mut chain, &asset, to, &amounts)?;
            report_produced(&produced, &out, print_blob)?;
        }
        Commands::Send {
            inputs,
            to,
            amounts,
            out,
            print_blob,
            force_respend,
        } => {
            let inputs: Vec<String> = inputs.split(',').map(|s| s.trim().to_string()).collect();
            let to = parse_recipient(&wallet, &to)?;
            let amounts = parse_amounts(&amounts)?;
            eprintln!("proving transfer… (this takes a few seconds in release, ~70s in debug)");
            let mut wallet = wallet;
            let mut chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            let produced = ops::send(
                &mut wallet,
                &mut chain,
                &inputs,
                to,
                &amounts,
                force_respend,
            )?;
            report_produced(&produced, &out, print_blob)?;
        }
        Commands::Receive {
            file,
            confirmations,
        } => {
            let blob = std::fs::read(&file).map_err(io_err(&file))?;
            let mut wallet = wallet;
            let chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            eprintln!("verifying proof… (~a second in release, longer in debug)");
            match ops::receive(
                &mut wallet,
                &chain,
                &opencsv_pcd::CoinProofVerifier,
                &blob,
                confirmations,
            )? {
                ReceiveReport::Verified {
                    credits,
                    coins,
                    anchor,
                } => {
                    for (asset, total) in &credits {
                        println!("VERIFIED {total} {}", to_hex(asset.as_bytes()));
                    }
                    eprintln!(
                        "stored {} coin(s), anchor at height {} position {}",
                        coins.len(),
                        anchor.height,
                        anchor.position
                    );
                }
                ReceiveReport::Rejected(reason) => {
                    println!("REJECTED {reason}");
                    return Ok(ExitCode::FAILURE);
                }
            }
        }
        Commands::Redeem {
            coin,
            out,
            print_blob,
        } => {
            eprintln!("proving redeem… (~1.5s in release, ~35s in debug)");
            let mut wallet = wallet;
            let mut chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            let produced = ops::redeem(&mut wallet, &mut chain, &coin)?;
            report_produced(&produced, &out, print_blob)?;
        }
        Commands::Coins => {
            for stored in wallet.coins() {
                println!(
                    "coin {} value {} asset {}.. {} (selector {})",
                    stored.id(),
                    stored.coin.value,
                    &to_hex(stored.coin.asset_id.as_bytes())[..16],
                    match stored.status {
                        opencsv_cli::store::CoinStatus::Unspent => "unspent",
                        opencsv_cli::store::CoinStatus::Spent => "spent",
                    },
                    stored.selector,
                );
            }
        }
        Commands::Balance { asset } => {
            let asset = asset.map(|s| digest_from_hex(&s)).transpose()?;
            let lines = ops::balance(&wallet, asset.as_ref());
            if lines.is_empty() {
                println!("0");
            }
            for (asset, total) in lines {
                println!("{total} {}", to_hex(asset.as_bytes()));
            }
        }
        Commands::Assets => {
            for genesis in wallet.assets() {
                println!(
                    "asset {} currency {} issuer {}",
                    to_hex(genesis.asset_id().as_bytes()),
                    String::from_utf8_lossy(&genesis.currency_code),
                    to_hex(&genesis.issuer_pk),
                );
            }
        }
        Commands::Audit { asset, height } => {
            let asset = digest_from_hex(&asset)?;
            let chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            let supply = ops::audit(&chain, &asset, height)?;
            println!(
                "supply {supply} asset {} height {}",
                to_hex(asset.as_bytes()),
                height.unwrap_or_else(|| chain.tip_height()),
            );
        }
        Commands::Chain(ChainCmd::Tip) => {
            let chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            println!("tip {}", chain.tip_height());
        }
        Commands::Chain(ChainCmd::Advance { n }) => {
            let mut chain = ChainBackend::open(&chain_path, anchor_server.as_deref())?;
            chain.advance_blocks(n)?;
            println!("tip {}", chain.tip_height());
        }
        #[cfg(feature = "signal")]
        Commands::Signal(cmd) => {
            run_signal(
                cmd,
                &wallet_dir,
                wallet,
                &chain_path,
                anchor_server.as_deref(),
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Signal transport commands. All Signal traffic runs on a small
/// current-thread tokio runtime; the wallet side stays synchronous.
#[cfg(feature = "signal")]
fn run_signal(
    cmd: SignalCmd,
    wallet_dir: &Path,
    wallet: Wallet,
    chain_path: &Path,
    anchor_server: Option<&str>,
) -> Result<(), Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Transport(format!("could not start the async runtime: {e}")))?;
    match cmd {
        SignalCmd::Link {
            device_name,
            store_dir,
        } => {
            let store_dir = store_dir.unwrap_or_else(|| wallet_dir.join("signal"));
            runtime.block_on(opencsv_signal::link(&store_dir, &device_name))?;
        }
        SignalCmd::Send {
            to,
            file,
            store_dir,
        } => {
            let store_dir = store_dir.unwrap_or_else(|| wallet_dir.join("signal"));
            let blob = std::fs::read(&file).map_err(io_err(&file))?;
            let recipient = opencsv_signal::parse_recipient(&to)?;
            runtime.block_on(async {
                let mut manager = opencsv_signal::open(&store_dir).await?;
                eprintln!("syncing pending Signal messages before sending…");
                opencsv_signal::sync_once(&mut manager).await?;
                opencsv_signal::send_consignment(&mut manager, &recipient, &blob).await
            })?;
            println!("sent {} ({} bytes) to {to}", file.display(), blob.len());
        }
        SignalCmd::Listen {
            confirmations,
            store_dir,
        } => {
            let store_dir = store_dir.unwrap_or_else(|| wallet_dir.join("signal"));
            let mut wallet = wallet;
            let chain_path = chain_path.to_path_buf();
            let anchor_server = anchor_server.map(str::to_owned);
            runtime.block_on(async move {
                let mut manager = opencsv_signal::open(&store_dir).await?;
                let verifier = opencsv_pcd::CoinProofVerifier;
                opencsv_signal::listen(&mut manager, move |blob| {
                    // Re-open the chain per message so anchors landed since
                    // (server appends, `chain advance`) become visible.
                    let chain = match ChainBackend::open(&chain_path, anchor_server.as_deref()) {
                        Ok(chain) => chain,
                        Err(e) => return format!("REJECTED could not open chain: {e}"),
                    };
                    match ops::receive(&mut wallet, &chain, &verifier, blob, confirmations) {
                        Ok(ReceiveReport::Verified { credits, .. }) => credits
                            .iter()
                            .map(|(asset, total)| {
                                format!("VERIFIED {total} {}", to_hex(asset.as_bytes()))
                            })
                            .collect::<Vec<_>>()
                            .join("\n"),
                        Ok(ReceiveReport::Rejected(reason)) => format!("REJECTED {reason}"),
                        Err(e) => format!("REJECTED {e}"),
                    }
                })
                .await
            })?;
        }
    }
    Ok(())
}

/// Write the consignment blob to `<out>/consignment-h<H>-p<P>.bin`, print the
/// path, and optionally print the blob base64-encoded on stdout.
fn report_produced(produced: &Produced, out: &Path, print_blob: bool) -> Result<(), Error> {
    let blob = produced.consignment.to_bytes();
    let location = produced.anchor.location;
    let name = format!(
        "consignment-h{}-p{}.bin",
        location.height, location.position
    );
    let path = out.join(name);
    std::fs::create_dir_all(out).map_err(io_err(out))?;
    std::fs::write(&path, &blob).map_err(io_err(&path))?;
    println!(
        "anchored at height {} position {}",
        location.height, location.position
    );
    println!("consignment {}", path.display());
    if print_blob {
        println!(
            "{}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        );
    }
    Ok(())
}

fn parse_recipient(wallet: &Wallet, to: &str) -> Result<Owner, Error> {
    if to == "self" {
        let secret = wallet.secrets().first().ok_or(Error::NoKeys)?;
        return Ok(secret.owner());
    }
    digest_from_hex(to)
}

fn parse_amounts(s: &str) -> Result<Vec<u64>, Error> {
    s.split(',')
        .map(|part| {
            part.trim()
                .parse::<u64>()
                .map_err(|_| Error::Parse(format!("bad amount `{part}`")))
        })
        .collect()
}
