# opencsv-ffi

C ABI for embedding the OpenCSV wallet in native apps (iOS-first). All
protocol logic stays in Rust over `opencsv-core` / `opencsv-pcd`; the host
app supplies transport, persistence, and the anchor-log view. Full contract
in `src/lib.rs` and `include/opencsv.h`.

The model, in one paragraph: `opencsv_wallet_create` returns a small secrets
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
knows where it anchored. Between the two phases the pending transaction
lives only in memory; `opencsv_pending_export` / `opencsv_pending_import`
persist it (proof, openings with their fresh randomness, aux, spend list)
across the broadcast→finalize window, closing the crash-loses-consignment
gap.

Beyond the wallet core, three host-facing verification surfaces:

- `opencsv_cbf_sync` / `opencsv_cbf_verify_anchor` — trustless anchor
  point verification over BIP157/158 P2P (`opencsv-cbf`), config JSON in,
  verdict JSON out;
- `opencsv_cross_check` — N-of-M exclusion (paper §4.7.1): build an
  `opencsv-core` `CrossCheckedChain` from a JSON list of backend specs
  (`bitcoind` RPC indexer / `http` anchor-server / inline `snapshot`)
  and run the accept driver over a received consignment; tip
  disagreement between backends is a hard error
  (`{"kind":"tip_disagreement"}`), never a silent pick.

## Build

```sh
cargo test -p opencsv-ffi                 # includes a C-ABI mint→verify round trip
apple/build-xcframework.sh                # OpenCsv.xcframework (device + Simulator)
```
