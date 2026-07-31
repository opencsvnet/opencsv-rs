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
cd apple/bench-ffi
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim   # optional, for Simulator
# outputs: target/<triple>/release/libopencsv_bench_ffi.a
```

Xcode setup (no project file is checked in — two minutes by hand):

1. File → New → Project → iOS → App. Name `OpenCsvBench`, Interface: SwiftUI,
   Language: Swift. Save anywhere (e.g. next to this `apple/` directory).
2. Delete the template's `ContentView.swift` and app entry file; drag in
   `OpenCsvBench/ContentView.swift`, `OpenCsvBench/opencsv-bench.h`, and
   `OpenCsvBench/OpenCsvBench-Bridging-Header.h` from this directory.
3. Drag `libopencsv_bench_ffi.a` into the project (check "Copy items if
   needed", add to the app target). For the Simulator, use the
   `aarch64-apple-ios-sim` build instead — or set both via an xcconfig.
4. Target → Build Settings:
   - **Objective-C Bridging Header** → path to `OpenCsvBench-Bridging-Header.h`
     (e.g. `$(SRCROOT)/OpenCsvBench/OpenCsvBench-Bridging-Header.h`)
   - **Enable Modules (C and Objective-C)** can stay default.
5. Select a physical device (release build: Product → Scheme → Edit Scheme →
   Run → Build Configuration → **Release**) and Run. Tap **Run** in the app.

The screen shows JSON: per-circuit `prove_ms`, `verify_ms`, `proof_bytes`.

## Notes

- Debug Rust builds are ~100× slower — always `--release`.
- First build compiles the whole Plonky3 + recursion stack for iOS; expect
  several minutes.
- If a dependency fails to build for `aarch64-apple-ios`, that's a real
  finding — file it against `opencsvnet/opencsv-rs` with the error.
