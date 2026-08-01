//! # opencsv-cli
//!
//! A text wallet client for **OpenCSV** (client-side verified RWAs
//! anchored to Bitcoin L1 — see `paper/opencsv.md`). The crate is
//! deliberately **transport-agnostic**: consignments are opaque binary blobs
//! ([`opencsv_core::Consignment::to_bytes`]). This crate reads and writes them
//! as files (or hex/base64 on stdout); a future Signal transport crate should
//! reuse this library target and only move the blobs.
//!
//! ## Library layout
//!
//! - [`store`] — the [`store::Wallet`]: a local directory holding owner
//!   secrets, pinned asset geneses, received coins (with the proof that
//!   created them, needed later as the in-circuit predecessor), received
//!   consignment blobs, and issuer keys. **Prototype-grade: secrets are
//!   stored unencrypted.**
//! - [`backend`] — the chain-backend selection: **real Bitcoin via
//!   `bitcoind` RPC (default)** through the `opencsv-bitcoin` crate, or
//!   the demo backends ([`chain::FileAnchorChain`],
//!   [`httpchain::HttpAnchorChain`]).
//! - [`chain`] — [`chain::FileAnchorChain`], a persistent
//!   [`opencsv_core::AnchorChain`] backed by an append-only text file (a
//!   demo backend), plus the [`chain::AnchorWriter`] seam the wallet
//!   operations anchor through. Records are built against the backend's
//!   transaction context via [`chain::AnchorWriter::append_bound`].
//! - [`ops`] — the protocol flows: [`ops::keygen`], [`ops::issuer_init`],
//!   [`ops::mint`], [`ops::send`], [`ops::receive`], [`ops::redeem`],
//!   [`ops::balance`], [`ops::audit`]. Proving goes through `opencsv-pcd`'s
//!   real recursive provers; verification in [`ops::receive`] is generic over
//!   [`opencsv_core::ProofVerifier`] (pass
//!   [`opencsv_pcd::CoinProofVerifier`] in production).
//!
//! ## Interface for a transport crate (e.g. Signal)
//!
//! - **Produce a blob to send:** call [`ops::mint`] / [`ops::send`] /
//!   [`ops::redeem`] (they prove and anchor), then serialize the returned
//!   consignment with `opencsv_core::Consignment::to_bytes` and move the
//!   bytes however you like.
//! - **Ingest a received blob:** call [`ops::receive`] with the raw bytes
//!   and [`opencsv_pcd::CoinProofVerifier`]; it runs `opencsv-core`'s
//!   `accept()` driver, and on success stores the coins and pins the asset.
//!
//! Proving is expensive (~3 s per transfer in release, ~70 s in debug); the
//! thin CLI in `src/main.rs` prints progress notes — transports should too.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod bitcoin;
pub mod chain;
pub mod error;
pub mod hexutil;
pub mod httpchain;
pub mod ops;
pub mod store;

pub use error::Error;
pub use ops::{COIN_VK, DEFAULT_CONFIRMATIONS};
