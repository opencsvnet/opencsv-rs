# opencsv-rs

Rust reference implementation of **OpenCSV** — client-side verified RWAs,
stables, and more, on Bitcoin. The scheme paper and explainer site live in
[opencsvnet/opencsv](https://github.com/opencsvnet/opencsv); the Lean 4
formalization in [opencsvnet/opencsv-formal](https://github.com/opencsvnet/opencsv-formal).

## Crates

```
crates/opencsv-core/    # commitments, nullifiers, anchor records, consignments, accept driver
crates/opencsv-pcd/     # AIR-native recursive proof engine (Plonky3 + Plonky3-recursion, no zkVM)
crates/opencsv-cli/     # `opencsv` text wallet: keygen/mint/send/receive/redeem/balance/audit
crates/opencsv-bitcoin/ # real bitcoind-RPC anchor backend (OP_RETURN anchors, block scanning)
crates/opencsv-signal/  # Signal transport via presage (linked device, consignments as attachments)
```

## Status

Working prototype, live-tested end to end on **real Bitcoin** (2026-08-01):
the CLI anchors to a real `bitcoind` by default (signet/mainnet/regtest) —
mint/send/redeem broadcast real `OP_RETURN` anchor transactions, and
verification scans real blocks. Validated on regtest
(`scripts/e2e-regtest.sh`): mint → REAL anchor tx → 6 blocks → VERIFIED →
send → VERIFIED → double-spend attempt → REJECTED by the first-occurrence
rule, resolved from node data → supply audit from chain data. (Earlier,
2026-07-31: the same protocol flow live-tested over the demo chain with
consignment delivery via production Signal.) Numbers:

- constant-size coin proofs (~46–56 KB) and constant verification (~3.6 ms),
  independent of history length — the PCD property, measured
- ~3 s proving per transfer hop (release, 64-core Xeon; test-grade FRI params)
- see `crates/opencsv-pcd/BENCHMARKS.md`

Known gaps are documented in `crates/opencsv-pcd/README.md` (off-circuit issuer
signature, single-asset transfers, test-grade FRI parameters, vk binding by
call-site discipline).

## Build & test

```sh
cargo build --release -p opencsv-cli   # needs protoc for the Signal feature
cargo test --workspace                 # debug; slow proving tests are #[ignore]d
```

`protoc`: `apt-get install protobuf-compiler`, or set `PROTOC=/path/to/protoc`.
The Signal feature is on by default; build without it via
`cargo build --no-default-features -p opencsv-cli` (MIT/Apache only — the
`signal` feature pulls in AGPL-licensed presage).

## License

MIT OR Apache-2.0, except where the optional `signal` feature's dependencies
(presage, AGPL-3.0) apply.
