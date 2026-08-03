# Readiness validation receipt

Date: 2026-08-03

## Passed commands

- `RUSTFLAGS='-D warnings' cargo test --workspace --locked --all-targets`
  passed with `OPENCSV_BITCOIND=/opt/homebrew/bin/bitcoind`. Enabled workspace
  tests were green, including real regtest integrations; explicitly ignored
  benchmark and multi-proof tests remained ignored. The recursive node suite
  took 801.07s and the mint-to-redeem suite took 402.06s in debug mode.
- `RUSTFLAGS='-D warnings' cargo test --locked -p opencsv-cli
  --no-default-features --all-targets` passed.
- `cargo run -p opencsv-bitcoin --example fee_model -- 5` passed and produced
  the table recorded in `SIGNET_READINESS.md`.
- Two fresh `opencsv-cbf::readiness_probe` runs passed against two distinct
  signet compact-filter peers; the exact JSON receipts are in
  `SIGNET_READINESS.md`.
- `scripts/reproducible-build.sh --verify dist/reproducible` built default and
  Signal-free release binaries twice in isolated, path-remapped target
  directories and byte-compared both pairs before the safe-marker migration.
- Post-migration focused suites passed with warnings denied:
  `opencsv-bitcoin --lib` (25 tests), `opencsv-cbf --lib` (33 tests), and
  `opencsv-anchor-server --bin opencsv-anchor-server` (7 tests).
- Live signet transactions and the failed generic fee-bump trial are recorded
  in `SIGNET_READINESS.md`; they produced security findings SR-05 and SR-06.
- A focused safe-marker batching-v2 regtest passed end to end with initial
  transaction `15959279…c4ee`, invariant-preserving replacement
  `f006744a…c94c`, 1,362-sat replacement fee, 1,808 WU, and two payloads.
- The scan regression found during validation was reproduced, traced to Core's
  briefly stale filter-index readiness flag, fixed by requiring index/tip
  height equality, and rerun successfully: 320 filter bytes, 1,140 block bytes,
  two fetched blocks over an eight-filter window.

## Superseded pre-marker binary hashes

```text
7e603c0fa6298239a5863c09f7531046ee30d174dcdc5800ff654400b5e41773  opencsv-signal
cb66002a7b1abe9d251738cf7ac23adfb31a69adaf2b30d984c28b011715e84f  opencsv-core
```

These hashes predate the unspendable-marker fix and are not release candidates.
Post-fix hashes will be recorded after the implementation commit is clean and
the reproducibility harness is rerun. The generated `dist/` directory is
intentionally ignored; release artifacts must be rebuilt from a clean reviewed
commit, and the script refuses a dirty tree unless explicitly placed in
non-release diagnostic mode.
