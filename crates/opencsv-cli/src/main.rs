//! `opencsv` — thin command-line front end over the `opencsv-cli` library.
//!
//! All wallet logic lives in the library (`src/lib.rs` and modules) so a
//! future Signal transport crate can reuse it; this binary only parses
//! arguments, prints results, and moves consignment blobs as files (or
//! base64/hex on stdout with `--print-blob`).

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use bitcoin::hashes::Hash as _;
use clap::{Parser, Subcommand};
use opencsv_cli::backend::{ChainBackend, ChainSpec};
use opencsv_cli::batch_gossip::{
    relay_once, send_frame, MessageKind, ProtocolPhase, Session, SessionPolicy, SignedFrame,
};
use opencsv_cli::error::{io_err, Error};
use opencsv_cli::hexutil::{digest_from_hex, from_hex, to_hex};
use opencsv_cli::ops::{self, Produced, ReceiveReport, DEFAULT_CONFIRMATIONS};
use opencsv_cli::store::Wallet;
use opencsv_core::{AnchorChain, Owner};

/// OpenCSV text wallet (prototype — plaintext keys; anchors to real
/// Bitcoin via `bitcoind` RPC by default).
#[derive(Parser)]
#[command(name = "opencsv", version, about, long_about = None)]
struct Cli {
    /// Wallet directory (default: ~/.opencsv).
    #[arg(long, global = true)]
    wallet_dir: Option<PathBuf>,
    /// Chain backend: `bitcoin` (default — real bitcoind RPC), `demo`
    /// (simulated file chain at WALLET_DIR/chain.log), `file:<path>`
    /// (simulated file chain elsewhere), or a bare path (same, for
    /// backwards compatibility). The demo backends print a warning.
    #[arg(long, global = true)]
    chain: Option<String>,
    /// Anchor via a shared opencsv-anchor-server (http://host:port) — a
    /// DEMO backend (prints a warning), for sharing a simulated chain
    /// with other parties (e.g. a phone wallet) over HTTP.
    #[arg(long, global = true)]
    anchor_server: Option<String>,
    /// Bitcoin network for the bitcoind backend.
    #[arg(
        long,
        global = true,
        default_value = "signet",
        env = "OPENCSV_NETWORK",
        value_parser = ["signet", "mainnet", "regtest"]
    )]
    network: String,
    /// bitcoind RPC URL (default: 127.0.0.1 with the network's default port).
    #[arg(long, global = true, env = "OPENCSV_RPC_URL")]
    rpc_url: Option<String>,
    /// bitcoind RPC cookie file (default: ~/.bitcoin/NETWORK/.cookie).
    #[arg(long, global = true, env = "OPENCSV_COOKIE")]
    cookie: Option<PathBuf>,
    /// bitcoind RPC auth as `user:password` (takes precedence over
    /// --cookie).
    #[arg(long, global = true, env = "OPENCSV_RPC_AUTH")]
    rpc_auth: Option<String>,
    /// bitcoind wallet name for the multi-wallet endpoint
    /// (/wallet/NAME); default: the node's default wallet.
    #[arg(long, global = true, env = "OPENCSV_RPC_WALLET")]
    rpc_wallet: Option<String>,
    /// Height to start scanning for anchors at on first open (default:
    /// the tip at first open — a fresh wallet has no earlier anchors).
    /// Changing it rebuilds the local anchor index.
    #[arg(long, global = true, env = "OPENCSV_SCAN_FROM")]
    scan_from: Option<u64>,
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
    /// Batch anchoring: combine N transfer records in one anchor
    /// transaction (bitcoind backend only).
    #[command(subcommand)]
    Batch(BatchCmd),
    /// Chain inspection and (demo / regtest) mining.
    #[command(subcommand)]
    Chain(ChainCmd),
    /// Signal transport: link as a secondary device and move consignments
    /// as Signal attachments (feature `signal`).
    #[cfg(feature = "signal")]
    #[command(subcommand)]
    Signal(SignalCmd),
}

#[derive(Subcommand)]
enum BatchCmd {
    /// Print the batch funding ctx for a payload count (creating the
    /// funding UTXO if absent). Senders bind their payloads against it:
    /// `P = H("bind" ∥ raw_nf ∥ ctx)`.
    Ctx {
        /// Number of payloads the batch will carry.
        #[arg(long)]
        count: u8,
    },
    /// Broadcast a batch anchor carrying pre-bound payloads (comma-
    /// separated 24-byte hex strings, bound against `batch ctx`).
    Anchor {
        /// Comma-separated payload hex strings (48 hex chars each).
        #[arg(long)]
        payloads: String,
    },
    /// Serverless batching-v2 proposal/commitment/manifest/signature gossip.
    #[command(subcommand)]
    V2(BatchV2Cmd),
}

#[derive(Subcommand)]
enum BatchV2Cmd {
    /// Initialize a durable session and relay identity.
    Init {
        /// Session directory.
        #[arg(long)]
        session: PathBuf,
        /// Verified display-order genesis hash returned by Bitcoin Core.
        #[arg(long)]
        chain_id: String,
        /// Independently verified current height.
        #[arg(long)]
        height: u32,
    },
    /// Publish a round-0 canonical proposal body.
    Proposal {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
    },
    /// Publish a round-1 canonical participant commitment body.
    Commitment {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
    },
    /// Publish a round-1 source-complete canonical manifest body.
    Manifest {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
    },
    /// Publish a round-2 verified signature-share body.
    Signature {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
    },
    /// Listen for authenticated frames, persist them, then forward new ones.
    Relay {
        #[arg(long)]
        session: PathBuf,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
    },
    /// Print reconstructed durable session status.
    Status {
        #[arg(long)]
        session: PathBuf,
    },
    /// Verify all shares and persist the signed transaction before returning.
    Finalize {
        #[arg(long)]
        session: PathBuf,
    },
    /// Broadcast the already persisted transaction through bitcoind.
    Broadcast {
        #[arg(long)]
        session: PathBuf,
    },
    /// Record a post-broadcast/mempool/confirmation/delivery transition.
    Mark {
        #[arg(long)]
        session: PathBuf,
        /// `mempool`, `confirmed`, `payload_delivered`, or a terminal phase.
        #[arg(long)]
        phase: String,
        /// One-line evidence receipt (txid, height, peer receipt, etc.).
        #[arg(long)]
        evidence: String,
    },
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
    /// Advance the tip by mining: simulated on the demo chains; on the
    /// bitcoind backend, generates real blocks via the wallet on regtest
    /// (hard error on signet/mainnet — blocks arrive by mining).
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
    /// Announce this wallet's receiving key in a chat so the peer's
    /// wallet can prefill it ("OpenCSV address: <hex>").
    Announce {
        /// Recipient: `self` (Note to Self), an ACI uuid, or an E.164
        /// phone number (resolved via the synced contacts).
        #[arg(long)]
        to: String,
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

/// Resolve the `--chain`/`--anchor-server` flags into a backend spec. The
/// default is real Bitcoin; the file chain requires an explicit `demo`,
/// `file:<path>`, or bare path (backwards compatibility).
fn chain_spec(cli: &Cli, wallet_dir: &Path) -> Result<ChainSpec, Error> {
    if let Some(server) = &cli.anchor_server {
        return Ok(ChainSpec::Http(server.clone()));
    }
    match cli.chain.as_deref() {
        None | Some("bitcoin") => Ok(ChainSpec::Bitcoin(Box::new(bitcoin_config(
            cli, wallet_dir,
        )?))),
        Some("demo") => Ok(ChainSpec::File(wallet_dir.join("chain.log"))),
        Some(spec) => match spec.strip_prefix("file:") {
            Some(path) => Ok(ChainSpec::File(PathBuf::from(path))),
            None => Ok(ChainSpec::File(PathBuf::from(spec))),
        },
    }
}

/// Build the `bitcoind` backend config from the CLI flags (and their
/// `OPENCSV_*` env fallbacks, resolved by clap).
fn bitcoin_config(cli: &Cli, wallet_dir: &Path) -> Result<opencsv_bitcoin::Config, Error> {
    let network = opencsv_bitcoin::Network::parse(&cli.network)?;
    let rpc_url = cli
        .rpc_url
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{}", network.default_rpc_port()));
    let auth = match (&cli.rpc_auth, &cli.cookie) {
        (Some(user_pass), _) => opencsv_bitcoin::RpcAuth::UserPass(user_pass.clone()),
        (None, Some(path)) => opencsv_bitcoin::RpcAuth::Cookie(path.clone()),
        (None, None) => {
            let home = std::env::home_dir().unwrap_or_else(|| PathBuf::from("."));
            let dir = home.join(".bitcoin").join(network.datadir_subdir());
            opencsv_bitcoin::RpcAuth::Cookie(dir.join(".cookie"))
        }
    };
    Ok(opencsv_bitcoin::Config {
        network,
        rpc_url,
        auth,
        wallet: cli.rpc_wallet.clone(),
        scan_from: cli.scan_from,
        index_path: wallet_dir.join(format!("bitcoin-index-{}.log", network.name())),
    })
}

/// Whether the command reads or writes the anchor chain (and therefore
/// deserves the demo-chain warning when a simulated backend is selected).
fn command_uses_chain(command: &Commands) -> bool {
    match command {
        Commands::Mint { .. }
        | Commands::Send { .. }
        | Commands::Receive { .. }
        | Commands::Redeem { .. }
        | Commands::Audit { .. }
        | Commands::Batch(BatchCmd::Ctx { .. })
        | Commands::Batch(BatchCmd::Anchor { .. })
        | Commands::Batch(BatchCmd::V2(BatchV2Cmd::Broadcast { .. }))
        | Commands::Chain(_) => true,
        #[cfg(feature = "signal")]
        Commands::Signal(SignalCmd::Listen { .. }) => true,
        _ => false,
    }
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

/// Whether the selected backend simulates anchors. An `--anchor-server`
/// may front a demo file chain *or* real Bitcoin, so ask it.
fn backend_is_demo(spec: &ChainSpec) -> bool {
    match spec {
        ChainSpec::Http(url) => opencsv_cli::httpchain::HttpAnchorChain::open(url)
            .map(|chain| chain.is_demo())
            .unwrap_or(true),
        spec => spec.is_demo(),
    }
}

fn run(cli: Cli) -> Result<ExitCode, Error> {
    let wallet_dir = cli.wallet_dir.clone().unwrap_or_else(default_wallet_dir);
    let wallet = Wallet::open(&wallet_dir)?;
    let spec = chain_spec(&cli, &wallet_dir)?;
    if command_uses_chain(&cli.command) && backend_is_demo(&spec) {
        eprintln!("warning: DEMO CHAIN — not Bitcoin (anchors and confirmations are simulated)");
    }
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
            let mut chain = ChainBackend::open(&spec)?;
            let produced = ops::mint(&mut wallet, &mut chain, &asset, to, &amounts)?;
            report_produced(
                &produced,
                &out,
                print_blob,
                matches!(spec, ChainSpec::Bitcoin(_)),
            )?;
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
            let mut chain = ChainBackend::open(&spec)?;
            let produced = ops::send(
                &mut wallet,
                &mut chain,
                &inputs,
                to,
                &amounts,
                force_respend,
            )?;
            report_produced(
                &produced,
                &out,
                print_blob,
                matches!(spec, ChainSpec::Bitcoin(_)),
            )?;
        }
        Commands::Receive {
            file,
            confirmations,
        } => {
            let blob = std::fs::read(&file).map_err(io_err(&file))?;
            let mut wallet = wallet;
            let chain = ChainBackend::open(&spec)?;
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
            let mut chain = ChainBackend::open(&spec)?;
            let produced = ops::redeem(&mut wallet, &mut chain, &coin)?;
            report_produced(
                &produced,
                &out,
                print_blob,
                matches!(spec, ChainSpec::Bitcoin(_)),
            )?;
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
            let chain = ChainBackend::open(&spec)?;
            let supply = ops::audit(&chain, &asset, height)?;
            println!(
                "supply {supply} asset {} height {}",
                to_hex(asset.as_bytes()),
                height.unwrap_or_else(|| chain.tip_height()),
            );
        }
        Commands::Batch(BatchCmd::Ctx { count }) => {
            let mut chain = ChainBackend::open(&spec)?;
            let ctx = chain.batch_ctx(count)?;
            println!("ctx {} count {count}", to_hex(&ctx));
        }
        Commands::Batch(BatchCmd::Anchor { payloads }) => {
            let payloads = parse_payloads(&payloads)?;
            let mut chain = ChainBackend::open(&spec)?;
            let anchor_ref = chain.anchor_batch(&payloads)?;
            println!(
                "batch tx {} payloads {}",
                opencsv_bitcoin::display_txid(&anchor_ref.txid),
                payloads.len()
            );
            eprintln!("anchor is in the mempool; it becomes verifiable once mined");
        }
        Commands::Batch(BatchCmd::V2(command)) => {
            run_batch_v2(command, &spec)?;
        }
        Commands::Chain(ChainCmd::Tip) => {
            let chain = ChainBackend::open(&spec)?;
            println!("tip {}", chain.tip_height());
        }
        Commands::Chain(ChainCmd::Advance { n }) => {
            let mut chain = ChainBackend::open(&spec)?;
            chain.advance_blocks(n)?;
            println!("tip {}", chain.tip_height());
        }
        #[cfg(feature = "signal")]
        Commands::Signal(cmd) => {
            run_signal(cmd, &wallet_dir, wallet, &spec)?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_batch_v2(command: BatchV2Cmd, spec: &ChainSpec) -> Result<(), Error> {
    match command {
        BatchV2Cmd::Init {
            session,
            chain_id,
            height,
        } => {
            let chain_id = chain_id
                .parse::<bitcoin::BlockHash>()
                .map_err(|error| Error::Parse(format!("invalid genesis block hash: {error}")))?
                .to_byte_array();
            let session_path = session;
            let session = Session::init(
                &session_path,
                SessionPolicy {
                    chain_id,
                    current_height: height,
                },
            )?;
            println!(
                "batch-v2 session {} identity {}",
                session.identity_pubkey(),
                session_path.display()
            );
        }
        BatchV2Cmd::Proposal {
            session,
            file,
            peers,
        } => publish_batch_body(&session, &file, MessageKind::Proposal, &peers)?,
        BatchV2Cmd::Commitment {
            session,
            file,
            peers,
        } => publish_batch_body(&session, &file, MessageKind::Commitment, &peers)?,
        BatchV2Cmd::Manifest {
            session,
            file,
            peers,
        } => publish_batch_body(&session, &file, MessageKind::Manifest, &peers)?,
        BatchV2Cmd::Signature {
            session,
            file,
            peers,
        } => publish_batch_body(&session, &file, MessageKind::Signature, &peers)?,
        BatchV2Cmd::Relay {
            session,
            listen,
            peers,
        } => {
            let listener = TcpListener::bind(listen)
                .map_err(|error| Error::Transport(format!("batch v2 bind {listen}: {error}")))?;
            let mut session = Session::open(&session)?;
            println!(
                "batch-v2 relay {listen} identity {} peers {}",
                session.identity_pubkey(),
                peers.len()
            );
            loop {
                let report = relay_once(&listener, &mut session, &peers)?;
                println!(
                    "relay {:?} forwarded {} failed {}",
                    report.outcome,
                    report.forwarded,
                    report.failed_peers.len()
                );
                for failure in report.failed_peers {
                    eprintln!("relay delivery failed: {failure}");
                }
            }
        }
        BatchV2Cmd::Status { session } => {
            let session = Session::open(&session)?;
            let status = session.status()?;
            println!(
                "phase {} batch {} commitments {} manifests {} latest {} signatures {}/{} identity {}",
                status.phase.name(),
                status
                    .batch_id
                    .as_ref()
                    .map(|id| to_hex(id))
                    .unwrap_or_else(|| "-".into()),
                status.commitments,
                status.manifests,
                status
                    .latest_manifest_id
                    .as_ref()
                    .map(|id| to_hex(id))
                    .unwrap_or_else(|| "-".into()),
                status.signature_shares,
                status.required_signatures,
                session.identity_pubkey(),
            );
        }
        BatchV2Cmd::Finalize { session } => {
            let mut session = Session::open(&session)?;
            let transaction = session.finalize_latest()?;
            println!(
                "signed_persisted tx {} weight {}",
                transaction.compute_txid(),
                transaction.weight().to_wu()
            );
        }
        BatchV2Cmd::Broadcast { session } => {
            let mut session = Session::open(&session)?;
            let transaction = session.latest_signed_transaction()?;
            let status = session.status()?;
            if status.phase == ProtocolPhase::SignedPersisted {
                session.mark_phase(
                    ProtocolPhase::Broadcast,
                    &format!("attempt={}", transaction.compute_txid()),
                )?;
            } else if !matches!(
                status.phase,
                ProtocolPhase::Broadcast | ProtocolPhase::Mempool
            ) {
                return Err(Error::Transport(format!(
                    "batch v2: cannot broadcast from phase {}",
                    status.phase.name()
                )));
            }
            let chain = ChainBackend::open(spec)?;
            let txid = chain.broadcast_batch_transaction(&transaction)?;
            session.mark_phase(ProtocolPhase::Mempool, &format!("txid={txid}"))?;
            println!("mempool tx {txid}");
        }
        BatchV2Cmd::Mark {
            session,
            phase,
            evidence,
        } => {
            let mut session = Session::open(&session)?;
            let phase = ProtocolPhase::parse(&phase)?;
            session.mark_phase(phase, &evidence)?;
            println!("phase {}", phase.name());
        }
    }
    Ok(())
}

fn publish_batch_body(
    session_path: &Path,
    file: &Path,
    kind: MessageKind,
    peers: &[SocketAddr],
) -> Result<(), Error> {
    let payload = std::fs::read(file).map_err(io_err(file))?;
    let mut session = Session::open(session_path)?;
    let wire = session.publish(kind, payload)?;
    let frame = SignedFrame::from_wire(&wire)?;
    let mut failures = Vec::new();
    for peer in peers {
        if let Err(error) = send_frame(*peer, &wire) {
            failures.push(format!("{peer}: {error}"));
        }
    }
    println!(
        "published {} frame {} peers {}",
        kind.name(),
        to_hex(&frame.id()),
        peers.len() - failures.len()
    );
    if failures.is_empty() {
        Ok(())
    } else {
        Err(Error::Transport(format!(
            "batch v2 delivery failures after local persistence: {}",
            failures.join("; ")
        )))
    }
}

/// Signal transport commands. All Signal traffic runs on a small
/// current-thread tokio runtime; the wallet side stays synchronous.
#[cfg(feature = "signal")]
fn run_signal(
    cmd: SignalCmd,
    wallet_dir: &Path,
    wallet: Wallet,
    spec: &ChainSpec,
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
                let sender = wallet
                    .secrets()
                    .first()
                    .map(|k| to_hex(k.owner().as_bytes()));
                opencsv_signal::send_consignment(&mut manager, &recipient, &blob, sender.as_deref())
                    .await
            })?;
            println!("sent {} ({} bytes) to {to}", file.display(), blob.len());
        }
        SignalCmd::Announce { to, store_dir } => {
            let store_dir = store_dir.unwrap_or_else(|| wallet_dir.join("signal"));
            let owner = wallet
                .secrets()
                .first()
                .map(|k| to_hex(k.owner().as_bytes()))
                .ok_or(Error::NoKeys)?;
            let recipient = opencsv_signal::parse_recipient(&to)?;
            let body = opencsv_signal::address_announcement(&owner);
            runtime.block_on(async {
                let mut manager = opencsv_signal::open(&store_dir).await?;
                opencsv_signal::sync_once(&mut manager).await?;
                opencsv_signal::send_text(&mut manager, &recipient, &body).await
            })?;
            println!("announced {owner} to {to}");
        }
        SignalCmd::Listen {
            confirmations,
            store_dir,
        } => {
            let store_dir = store_dir.unwrap_or_else(|| wallet_dir.join("signal"));
            let mut wallet = wallet;
            let spec = spec.clone();
            runtime.block_on(async move {
                let mut manager = opencsv_signal::open(&store_dir).await?;
                let verifier = opencsv_pcd::CoinProofVerifier;
                opencsv_signal::listen(&mut manager, move |blob| {
                    // Re-open the chain per message so anchors landed since
                    // (server appends, `chain advance`) become visible.
                    let chain = match ChainBackend::open(&spec) {
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
/// path, and optionally print the blob base64-encoded on stdout. With the
/// `bitcoind` backend the anchor was just broadcast: the location is the
/// mempool placeholder and the txid is what matters.
fn report_produced(
    produced: &Produced,
    out: &Path,
    print_blob: bool,
    bitcoin: bool,
) -> Result<(), Error> {
    let blob = produced.consignment.to_bytes();
    let location = produced.anchor.location;
    let name = format!(
        "consignment-h{}-p{}.bin",
        location.height, location.position
    );
    let path = out.join(name);
    std::fs::create_dir_all(out).map_err(io_err(out))?;
    std::fs::write(&path, &blob).map_err(io_err(&path))?;
    if bitcoin {
        println!(
            "anchor broadcast (mempool; mines into a block later) tx {}",
            opencsv_bitcoin::display_txid(&produced.anchor.txid)
        );
    } else {
        println!(
            "anchored at height {} position {}",
            location.height, location.position
        );
    }
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

/// Comma-separated 24-byte payload hex strings → TruncatedDigests.
fn parse_payloads(s: &str) -> Result<Vec<opencsv_core::TruncatedDigest>, Error> {
    s.split(',')
        .map(|part| {
            let bytes = from_hex(part.trim())
                .map_err(|e| Error::Parse(format!("payload `{part}`: {e}")))?;
            let bytes: [u8; 24] = bytes
                .try_into()
                .map_err(|v: Vec<u8>| {
                    Error::Parse(format!(
                        "payload `{part}` is {} bytes, expected 24",
                        v.len()
                    ))
                })?;
            Ok(opencsv_core::TruncatedDigest(bytes))
        })
        .collect()
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
