# OpenCSV iOS benchmark

Measures the OpenCSV recursive prover's speed on an actual iPhone/iPad:
prove time, verify time, and proof size for genesis mint, two transfer hops
(each verifying two predecessor proofs in-circuit), and redeem — the same
measurements as `crates/opencsv-pcd/tests/bench.rs`, through a C ABI shim
(`bench-ffi/`) and a minimal SwiftUI app (`OpenCsvBench/`).

## Why

Server benchmarks (Xeon Gold 6526Y) show ~3 s per recursive transfer proof,
and proving does **not** scale with core count (1 core ≈ 64 cores) — the
prover is effectively single-threaded for these circuit sizes. Single-core
speed is therefore all that matters, and modern phone cores should be
competitive or better. This app gets the real number.

## Build & run (on macOS with Xcode)

One-time Rust build (device + simulator staticlibs):

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  cargo build --release --target aarch64-apple-ios -p opencsv-bench-ffi
# output: target/aarch64-apple-ios/release/libopencsv_bench_ffi.a
```

Generate the project from the checked-in XcodeGen specification:

```sh
cd apple
xcodegen --spec project.yml
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project OpenCsvBench.xcodeproj -scheme OpenCsvBench \
  -configuration Release -destination 'platform=iOS,name=An iPhone' \
  DEVELOPMENT_TEAM="<your team id>" -allowProvisioningUpdates build
```

Install/run from Xcode, or use `xcrun devicectl device install app` and
`device process launch --console`. The app starts the benchmark on launch;
the button permits another run. It logs an `OPENCSV_BENCH_PARTIAL` JSON line
after each circuit and one `OPENCSV_BENCH_RESULT` line after the complete run,
then displays the complete data.

The app disables the iOS idle timer while a run is active and restores it on
completion so long recursive measurements are not suspended by auto-lock.

The JSON includes the frozen profile ID and, per circuit, `prove_ms`,
`verify_ms`, `proof_bytes`, raw/adjusted proven bits, and trace degree bits.

## Notes

- Debug Rust builds are ~100× slower — always `--release`.
- The benchmark bundle is `net.opencsv.bench`; it is separate from Signal and
  neither upgrades nor reads Signal data.
- First build compiles the whole Plonky3 + recursion stack for iOS; expect
  several minutes.
- If a dependency fails to build for `aarch64-apple-ios`, that's a real
  finding — file it against `opencsvnet/opencsv-rs` with the error.
