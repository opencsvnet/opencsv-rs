# opencsv-ffi

C ABI for embedding the OpenCSV wallet in native apps (iOS-first). All
protocol logic stays in Rust over `opencsv-core` / `opencsv-pcd`. The preferred
Signal boundary is the persistent `opencsv_account_*` API documented in
`../SIGNAL_ACCOUNT_WALLET.md`: Rust owns keys, asset/Bitcoin coin selection,
reservations, proofs, signing, P2P relay, and crash recovery while Swift sends
action intent. Full ABI contract is in `src/lib.rs` and `include/opencsv.h`.
The interactive send path journals through `opencsv_transfer_plan` and returns
to Signal immediately; `opencsv_operation_prove` advances that exact id in a
resumable background pass. Only proof-ready operations may be signed, so fast
pending presentation never weakens double-spend or lineage checks.
Mandatory peer or local-scan unavailability returns
`{"reason":"chain_verification_unavailable","retryable":true,...}` and keeps
the exact planned/fee-reserved operation and Bitcoin lock durable. Verified
conflicts and stale-state contradictions return `"retryable":false` and close
the complete unsigned solo or frozen batch.

The older in-memory compatibility model is retained temporarily:
`opencsv_wallet_create` returns a small secrets
JSON the host keeps in its keystore (iOS Keychain) and passes back to
`opencsv_wallet_open`; coins are rebuilt at open by replaying verified
consignment blobs through `opencsv_verify_consignment` (milliseconds each)
and re-marking spends. Chain-dependent calls take an *anchor snapshot* JSON
(`src/snapshot.rs`) so the phone never talks to a node. Producing a
transaction is two-phase: `opencsv_prove_*` returns a 64-byte anchor record
plus the 32-byte transaction context `ctx` it is bound to (the record's
nullifier payloads are `H("bind" ∥ raw_nf ∥ ctx)`), to publish together
(e.g. to `opencsv-anchor-server`), and
`opencsv_consignment_finalize` builds the consignment blob once the host
knows where it anchored. A consignment finalized before the anchor's mined
position is known carries the mempool sentinel location `(0, 0)`: the
snapshot chain resolves such references by transaction id (the same
contract as `opencsv-bitcoin`'s backend), while explicitly claimed
locations are matched strictly. Between the two phases the pending transaction
lives only in memory; `opencsv_pending_export` / `opencsv_pending_import`
persist it (proof, openings with their fresh randomness, aux, spend list)
across the broadcast→finalize window, closing the crash-loses-consignment gap.
Its anchor-server examples are compatibility documentation, not the target
Signal send architecture.

Verification `credits` are descriptive accepted-payment totals, not an
accounting delta: replaying a consignment can return the same totals even
though Rust stores its coins idempotently. Persistent-account hosts must key
durable presentation and accounting by the returned stable `payment_id` and
must never sum `credits` across verification retries. The legacy in-memory
entry point does not expose a stable logical-payment identity and should not
be used for new host integrations.

Beyond the wallet core, three host-facing verification surfaces:

- `opencsv_cbf_sync` / `opencsv_cbf_verify_anchor` — trustless anchor
  point verification over BIP157/158 P2P (`opencsv-cbf`), config JSON in,
  verdict JSON out;
- `opencsv_cross_check` — N-of-M exclusion (paper §4.7.1): build an
  `opencsv-core` `CrossCheckedChain` from a JSON list of backend specs
  (`bitcoind` RPC indexer / `http` anchor-server / inline `snapshot`)
  and run the accept driver over a received consignment; tip
  disagreement between backends is a hard error
  (`{"kind":"tip_disagreement"}`), never a silent pick;
- `opencsv_scan_sync` / `opencsv_scan_check` / `opencsv_scan_verify` —
  the self-scan-first default: `opencsv-cbf`'s `ScanIndex` walks BIP158
  filters for the protocol marker output and SPV-fetches matching
  blocks into a persistent occurrence index; occurrence checks and
  `accept()` then run fully local (read-only);
- `opencsv_scan_export_snapshot` — exports the registered scan index as
  an anchor-snapshot JSON (the exact shape `opencsv_verify_consignment`
  consumes), so consignments are credited serverlessly: every entry was
  SPV-fetched and PoW-verified by the scan. `tip_height` is the synced
  tip at call time; with no registered scan it returns
  `{"error":"no scan registered; call opencsv_scan_sync first"}`.

## Build

```sh
cargo test -p opencsv-ffi                 # includes a C-ABI mint→verify round trip
apple/build-xcframework.sh                # OpenCsv.xcframework (device + Simulator)
```
