//! The wallet error type.

use std::path::PathBuf;

use opencsv_core::audit::SupplyError;
use opencsv_core::consignment::ConsignmentError;
use opencsv_pcd::NodeError;

/// Everything that can go wrong in wallet operations and the CLI.
#[derive(Debug)]
pub enum Error {
    /// Filesystem failure on a wallet/chain path.
    Io {
        /// The path being accessed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// A stored file or the chain log is corrupt.
    Decode {
        /// The path being decoded.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },
    /// Bad hex input (asset ids, owner keys, coin ids).
    Hex(String),
    /// Bad user input (amounts, currency codes, …).
    Parse(String),
    /// The wallet holds no owner keys (run `keygen` first).
    NoKeys,
    /// No coin matches the given id prefix.
    UnknownCoin(String),
    /// More than one coin matches the given id prefix.
    AmbiguousCoin(String),
    /// A coin's owner does not correspond to any key in this wallet.
    UnknownOwner(String),
    /// The asset is not pinned in this wallet.
    UnknownAsset(String),
    /// This wallet is not the issuer of the requested asset.
    NotIssuer(String),
    /// The coin is already marked spent locally.
    CoinSpent(String),
    /// Transfers are fixed at 2 inputs by the circuit.
    WrongInputCount {
        /// What the circuit takes.
        expected: usize,
        /// What the user gave.
        got: usize,
    },
    /// Transfer outputs must sum to the inputs (conservation).
    AmountMismatch {
        /// Total value of the consumed inputs.
        inputs: u64,
        /// Total value of the requested outputs.
        outputs: u64,
    },
    /// The selected coins are not all in one asset.
    MixedAssets,
    /// Proof generation failed.
    Proving(NodeError),
    /// A consignment blob did not decode.
    Consignment(ConsignmentError),
    /// The supply audit failed.
    Supply(SupplyError),
    /// An invariant the wallet maintains was violated.
    Internal(&'static str),
    /// A transport (e.g. Signal) failed. Prototype-grade: the underlying
    /// error is stringified.
    Transport(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Decode { path, message } => {
                write!(f, "{}: corrupt data: {message}", path.display())
            }
            Self::Hex(m) => write!(f, "invalid hex: {m}"),
            Self::Parse(m) => write!(f, "{m}"),
            Self::NoKeys => write!(f, "wallet has no owner keys (run `opencsv keygen` first)"),
            Self::UnknownCoin(p) => write!(f, "no coin matches id prefix `{p}`"),
            Self::AmbiguousCoin(p) => write!(f, "coin id prefix `{p}` matches more than one coin"),
            Self::UnknownOwner(o) => write!(f, "coin owner {o} is not one of this wallet's keys"),
            Self::UnknownAsset(a) => write!(f, "asset {a} is not pinned in this wallet"),
            Self::NotIssuer(a) => write!(f, "this wallet is not the issuer of asset {a}"),
            Self::CoinSpent(c) => write!(f, "coin {c} is already spent"),
            Self::WrongInputCount { expected, got } => {
                write!(f, "transfers consume exactly {expected} coins, got {got}")
            }
            Self::AmountMismatch { inputs, outputs } => {
                write!(
                    f,
                    "outputs sum to {outputs} but inputs sum to {inputs} (conservation)"
                )
            }
            Self::MixedAssets => write!(f, "all coins in one transaction must share an asset"),
            Self::Proving(e) => write!(f, "proving failed: {e}"),
            Self::Consignment(e) => write!(f, "{e}"),
            Self::Supply(e) => write!(f, "supply audit failed: {e}"),
            Self::Internal(m) => write!(f, "internal error: {m}"),
            Self::Transport(m) => write!(f, "transport error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NodeError> for Error {
    fn from(e: NodeError) -> Self {
        Self::Proving(e)
    }
}

impl From<ConsignmentError> for Error {
    fn from(e: ConsignmentError) -> Self {
        Self::Consignment(e)
    }
}

impl From<SupplyError> for Error {
    fn from(e: SupplyError) -> Self {
        Self::Supply(e)
    }
}

#[cfg(feature = "signal")]
impl From<opencsv_signal::Error> for Error {
    fn from(e: opencsv_signal::Error) -> Self {
        Self::Transport(e.to_string())
    }
}

/// Wrap an I/O error with the path being accessed.
pub fn io_err(path: &std::path::Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.to_path_buf(),
        source,
    }
}
