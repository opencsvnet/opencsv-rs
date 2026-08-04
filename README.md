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
ffi/                    # owner-only Signal C ABI; opt-in `opencsv-issuer` operator binary
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

- constant-size coin proofs and history-independent verification — the PCD
  property, measured under the frozen proof-lineage-v3 production profile
- 7.8–12.2 s proving per transfer hop on an Apple M4 (release, warm/cold),
  21–22 ms verification, 0.84–0.85 MB proofs
- a 94-bit conservative, union-adjusted proven-security floor for the
  largest current recursive shapes; proofs fail closed below that floor
- see `crates/opencsv-pcd/BENCHMARKS.md`

Known gaps are documented in `crates/opencsv-pcd/README.md` (single-asset
transfers and explicit root-circuit commitment registration).
Issuer authorization and recursive predecessor keys are bound in-circuit;
proof envelopes, FRI parameters, and accept tags are fail-closed at version 3.

The frozen co-funded batching protocol and threat model is
[`BATCHING_V2.md`](BATCHING_V2.md). C1 is implemented in
`opencsv-bitcoin::batch_v2`: signed stock, canonical participant commitments,
exact fee allocation, PSBT signer material, unanimous replacement, and
multi-party regtest evidence. The older `batch` module remains the fail-closed
v1 reader/compatibility path. C2 is implemented in
`opencsv-cli::batch_gossip`: authenticated bounded peer frames, complete-source
manifest reconstruction, all-peer signature relay, durable crash recovery,
and persistence of the verified signed transaction before any broadcast.
There is no required coordinator or OpenCSV-specific server; any peer with the
complete transcript can finalize and broadcast.

The dated signet measurements, executable fee model, security findings, and
release gates are in [`SIGNET_READINESS.md`](SIGNET_READINESS.md),
[`SECURITY_REVIEW.md`](SECURITY_REVIEW.md), and [`RELEASE.md`](RELEASE.md).
The complete command and artifact receipt is [`VALIDATION.md`](VALIDATION.md).
These are readiness receipts, not mainnet authorization.

New anchors use a BIP158-visible, unspendable P2WSH marker committing to
`OP_RETURN`. Readers retain exact compatibility with the historical
`OP_TRUE` marker, but constructors never recreate its child-pinning risk.
Solo fee replacements must pass the Rust protocol validator; generic Bitcoin
wallet fee-bump APIs are not protocol-safe.

## Build & test

```sh
cargo build --locked --release -p opencsv-cli  # needs protoc for Signal
cargo build --locked --release -p opencsv-ffi --features issuer-tools --bin opencsv-issuer
cargo test --locked --workspace               # slow proving tests are #[ignore]d
./scripts/reproducible-build.sh --verify dist/reproducible
```

`protoc`: `apt-get install protobuf-compiler`, or set `PROTOC=/path/to/protoc`.
The Signal feature is on by default; build without it via
`cargo build --locked --no-default-features -p opencsv-cli` (MIT/Apache only — the
`signal` feature pulls in AGPL-licensed presage).

## License

MIT OR Apache-2.0, except where the optional `signal` feature's dependencies
(presage, AGPL-3.0) apply.
