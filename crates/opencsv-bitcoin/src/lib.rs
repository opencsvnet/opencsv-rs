//! # opencsv-bitcoin
//!
//! The **real** OpenCSV anchor backend: an [`opencsv_core::AnchorChain`]
//! plus anchor writer over `bitcoind` JSON-RPC (signet, mainnet, or
//! regtest). No mocks, no fallbacks: if the node is unreachable, the auth
//! fails, or the node is on a different network than configured, opening
//! the backend is a hard error.
//!
//! ## Write path (anchoring)
//!
//! [`BitcoinAnchorChain::anchor`] publishes a 64-byte
//! [`opencsv_core::AnchorRecord`] in an `OP_RETURN` output of a real
//! Bitcoin transaction, signed and broadcast by the node's wallet. The
//! record's bound payloads commit to the transaction context `ctx`, which
//! in production is the anchor transaction's funding-input outpoint — but
//! `fundrawtransaction` picks the inputs, so the ctx is only knowable
//! *after* funding. Anchoring is therefore a two-pass construction:
//!
//! 1. **Pass 1** — `createrawtransaction` with a dummy 64-byte data
//!    output, `fundrawtransaction`, `decoderawtransaction`: yields the
//!    selected funding inputs (and the change output, with the fee
//!    already priced in).
//! 2. The caller's record-building closure is evaluated against each
//!    candidate `ctx` (one per funding input) until the record
//!    [`opencsv_core::AnchorRecord::parses_cleanly`] — this is the
//!    tag-collision redraw of `opencsv-core`'s anchor docs, with input
//!    *order* as the redraw freedom (vin\[0\] is the ctx input).
//! 3. **Pass 2** — `createrawtransaction` with the *same* explicit
//!    inputs (chosen funding input first) and the *same* outputs, the
//!    dummy payload replaced by the real record bytes. Inputs and output
//!    amounts are identical to pass 1, so the fee and change are
//!    unchanged.
//! 4. `signrawtransactionwithwallet` (must complete), then
//!    `sendrawtransaction`. The returned [`opencsv_core::AnchorRef`]
//!    carries [`MEMPOOL_LOCATION`] — the block height and in-block
//!    position only exist once the transaction mines; the read path
//!    resolves them by txid (see `opencsv-core`'s `AnchorChain::locate`).
//!
//! The transaction context is `ctx = SHA-256(txid ∥ vout)` over the
//! 32-byte internal-order funding txid and the 4-byte little-endian vout
//! into its first 4 bytes (a 36-byte outpoint does not fit the 32-byte
//! ctx slot). The derivation is canonical across backends —
//! `SHA-256(txid_internal ∥ vout_le)`; see [`funding_ctx`].
//!
//! ## Read path (scanning)
//!
//! Blocks are fetched with `getblockhash`/`getblock` (verbosity 2) and
//! scanned for `OP_RETURN` pushes of exactly 64 bytes; each parses as an
//! [`opencsv_core::AnchorRecord`] (tagged MINT/REDEEM, untagged transfer
//! candidate otherwise — any 64-byte string parses, per the camouflage
//! design). Every hit is stored with its `ctx` (from vin\[0\]), height,
//! and in-block position in a **persistent local index** at
//! [`Config::index_path`] — a rebuildable cache, not a second source of
//! truth; deleting it just forces a rescan. Occurrence queries scan the
//! index testing `well_formed`, exactly like the file demo chain.
//!
//! **Scanning starts from [`Config::scan_from`], not genesis.** On first
//! open the default is the current tip (a fresh wallet has no anchors
//! before it exists); pass an explicit earlier height to pick up history.
//! Full-history indexing for arbitrary counterparty anchors is an indexer
//! service's job — future work, deliberately out of scope here. On a
//! pruned node the start height must be above the prune horizon.
//!
//! Reorgs: the index stores the block hash of the last scanned height; if
//! it no longer matches `getblockhash` at open, the index is truncated
//! back to the start height and rebuilt (documented limitation: no
//! incremental walk-back — deep-reorg handling is future work).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod batch;
pub mod batch_v2;
pub mod bech32;
pub mod chain;
pub mod error;
pub mod fee_model;
pub mod replacement;
pub mod rpc;

pub use batch::BATCH_FUNDING_SATS;
pub use chain::{
    display_txid, funding_ctx, is_marker_spk, marker_address, BitcoinAnchorChain, Config, Network,
    LEGACY_MARKER_SCRIPT, LEGACY_MARKER_SPK, MARKER_DUST_BTC, MARKER_DUST_SATS, MARKER_SCRIPT,
    MARKER_SPK, MEMPOOL_LOCATION,
};
pub use error::Error;
pub use replacement::{
    validate_solo_anchor_replacement, SoloReplacementReceipt, SoloReplacementRejection,
};
pub use rpc::{HttpTransport, RpcAuth, RpcClient, Transport};
