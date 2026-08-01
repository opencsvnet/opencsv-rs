//! Error type for the compact-block-filter client.

use std::fmt;

/// Everything that can go wrong in the CBF client.
#[derive(Debug)]
pub enum Error {
    /// I/O failure (socket, disk cache).
    Io(std::io::Error),
    /// A peer sent a malformed, unexpected, or missing protocol message.
    Protocol(String),
    /// A block header failed proof-of-work / consensus validation.
    Consensus(String),
    /// A compact filter or filter header failed validation.
    Filter(String),
    /// All peers failed (connect, handshake, or fetch).
    NoPeers(String),
    /// Connected peers disagree about the chain or the filter-header chain
    /// (possible eclipse / misbehaving peer — refuse to proceed).
    DivergentPeers(String),
    /// Caller supplied an invalid argument (e.g. the mempool sentinel
    /// location).
    InvalidInput(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Protocol(m) => write!(f, "p2p protocol: {m}"),
            Self::Consensus(m) => write!(f, "consensus validation: {m}"),
            Self::Filter(m) => write!(f, "compact filter: {m}"),
            Self::NoPeers(m) => write!(f, "no usable peers: {m}"),
            Self::DivergentPeers(m) => write!(f, "peers disagree: {m}"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
