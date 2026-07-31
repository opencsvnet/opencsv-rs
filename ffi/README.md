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
to publish (e.g. to `opencsv-anchor-server`), and
`opencsv_consignment_finalize` builds the consignment blob once the host
knows where it anchored.

## Build

```sh
cargo test -p opencsv-ffi                 # includes a C-ABI mint→verify round trip
apple/build-xcframework.sh                # OpenCsv.xcframework (device + Simulator)
```
