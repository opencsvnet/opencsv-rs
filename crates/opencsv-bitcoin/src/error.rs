//! The backend error type.

use std::path::PathBuf;

use crate::chain::Network;

/// Everything that can go wrong talking to `bitcoind` or maintaining the
/// local anchor index.
#[derive(Debug)]
pub enum Error {
    /// Filesystem failure (cookie file, index file).
    Io {
        /// The path being accessed.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// TCP/HTTP-level failure reaching the RPC endpoint.
    Http(String),
    /// bitcoind returned a JSON-RPC error (auth failure, insufficient
    /// funds, unknown method, …). Never swallowed: there is no fallback.
    Rpc {
        /// The JSON-RPC error code.
        code: i64,
        /// The JSON-RPC error message.
        message: String,
    },
    /// The persistent index file is corrupt.
    Decode {
        /// The index path.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },
    /// An RPC response did not have the expected shape.
    Malformed(String),
    /// Bad configuration (URL, auth).
    Config(String),
    /// The node is on a different network than configured.
    WrongNetwork {
        /// What was configured.
        expected: Network,
        /// What the node reports (`getblockchaininfo.chain`).
        actual: String,
    },
    /// `signrawtransactionwithwallet` did not produce a complete
    /// transaction (wallet locked, missing keys, …).
    SigningFailed(String),
    /// `fundrawtransaction` selected no inputs (unfunded wallet).
    NoFundingInputs,
    /// Every candidate funding input produced a bound payload colliding
    /// with the MINT/REDEEM tag bytes (astronomically unlikely; retry with
    /// a fresh UTXO).
    TagCollision,
    /// `chain advance` on a real network: blocks arrive by mining, not by
    /// command (only regtest can generate on demand).
    NotRegtest,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Http(m) => write!(f, "bitcoind RPC unreachable: {m}"),
            Self::Rpc { code, message } => write!(f, "bitcoind RPC error {code}: {message}"),
            Self::Decode { path, message } => {
                write!(f, "{}: corrupt index: {message}", path.display())
            }
            Self::Malformed(m) => write!(f, "malformed bitcoind RPC response: {m}"),
            Self::Config(m) => write!(f, "{m}"),
            Self::WrongNetwork { expected, actual } => write!(
                f,
                "configured for {} but the node reports chain `{actual}`",
                expected.name()
            ),
            Self::SigningFailed(m) => write!(f, "bitcoind would not sign the anchor tx: {m}"),
            Self::NoFundingInputs => write!(
                f,
                "bitcoind wallet selected no funding inputs (no spendable UTXOs)"
            ),
            Self::TagCollision => write!(
                f,
                "every funding input's ctx yields a payload colliding with the \
                 MINT/REDEEM tag bytes — retry (needs a fresh UTXO)"
            ),
            Self::NotRegtest => write!(
                f,
                "cannot advance real Bitcoin: blocks arrive by mining \
                 (`chain advance` generates blocks on regtest only)"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Wrap an I/O error with the path being accessed.
pub(crate) fn io_err(path: &std::path::Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |source| Error::Io {
        path: path.to_path_buf(),
        source,
    }
}
