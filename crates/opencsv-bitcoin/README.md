# opencsv-bitcoin

The **real** OpenCSV anchor backend: an `opencsv_core::AnchorChain` plus
anchor writer over `bitcoind` JSON-RPC (signet / mainnet / regtest). No
mocks, no fallbacks: an unreachable node, an auth failure, or a network
mismatch is a hard error at open.

- **Write path** — two-pass anchoring: `createrawtransaction` +
  `fundrawtransaction` with a dummy 64-byte `OP_RETURN` learns the funding
  inputs; the record is built against the funding input's outpoint ctx
  (`SHA-256(txid_internal ∥ vout_le)`, canonical across backends — the tag-collision redraw picks the
  vin\[0\] input); the tx is rebuilt with identical inputs/outputs and the
  real record bytes, signed (`signrawtransactionwithwallet`), and
  broadcast (`sendrawtransaction`). The returned `AnchorRef` carries the
  mempool placeholder location; verifiers resolve the confirmed
  height/position by txid (`AnchorChain::locate`).
- **Read path** — scans blocks (`getblockhash`/`getblock` verbosity 2)
  for 64-byte `OP_RETURN` payloads into a persistent local index (a
  rebuildable cache) and answers occurrence queries by testing
  `well_formed` against it — the same semantics as the file demo chain.
  Scanning starts at `Config::scan_from` (default: tip at first open),
  not genesis: full-history indexing is an indexer service's job (future
  work). On a stale tip hash (reorg) the index is truncated to the start
  height and rebuilt.
- **Transport** — a hand-rolled blocking HTTP/1.1 JSON-RPC client over
  `TcpStream` (cookie or `user:password` auth), following the project's
  existing anchor-server client pattern. The `Transport` trait is the
  seam where unit tests script canned responses; the product path always
  uses `HttpTransport`.

Used by `opencsv-cli` (default `--chain bitcoin`). See the crate-level
rustdoc for the full design notes.
