# opencsv-pcd benchmarks

> Historical baseline: these measurements predate the D1 setup cache and
> D3 version-2 issuer-authorization circuit. Proof sizes and timings are not
> current production claims. D2 will replace them with reproducible
> cold/warm and on-device receipts after parameters are frozen.

Prove time, verify time, and proof size for the coin-proof circuits
(stage 3–4, test-grade FRI parameters — `CoinFriParams::testing()`, **not a
security claim**). Measured with `tests/bench.rs`:

```
cargo test -p opencsv-pcd --test bench -- --ignored --nocapture           # debug
cargo test -p opencsv-pcd --release --test bench -- --ignored --nocapture # release
```

Single-shot measurements (each row costs full recursive proofs, so warm-up
effects are negligible). Proof size is the postcard-serialized
`BatchStarkProof` (the mode + statement envelope adds a constant ~200 bytes
for the consignment encoding).

## Machine

- CPU: INTEL(R) XEON(R) GOLD 6526Y, 64 cores
- RAM: 255 GB (`MemTotal: 254985704 kB`)
- rustc 1.94.0 (4a4ef493e 2026-03-02), Linux x86_64

## Results

### Debug profile (`cargo test`)

| circuit | prove | verify | proof size |
|---|---|---|---|
| genesis mint | 1.56 s | 57.60 ms | 46,431 B |
| transfer (2 mint predecessors) | 70.96 s | 45.93 ms | 56,041 B |
| 2-hop transfer (2 node predecessors) | 70.71 s | 45.97 ms | 56,041 B |
| redeem (1 node predecessor) | 35.35 s | 45.84 ms | 54,058 B |

### Release profile (`cargo test --release`)

| circuit | prove | verify | proof size |
|---|---|---|---|
| genesis mint | 63.70 ms | 3.22 ms | 46,431 B |
| transfer (2 mint predecessors) | 2.97 s | 3.56 ms | 56,041 B |
| 2-hop transfer (2 node predecessors) | 2.96 s | 3.60 ms | 56,041 B |
| redeem (1 node predecessor) | 1.47 s | 3.51 ms | 54,058 B |

## Notes

- Proof size and verify time are constant in history length (PCD): the
  2-hop transfer verifies exactly two predecessors, as does the 1-hop
  transfer; only the predecessor *shape* differs.
- Redeem is cheaper than transfer in proportion to its single in-circuit
  predecessor verification (plus fewer Poseidon2 rows: one coin opening,
  one ownership hash, one nullifier hash, no outputs, no conservation
  gadget).
- These measurements predate the D1 setup cache and D3 issuer/version
  boundary, so each row includes a cold `ProverData::from_airs_and_degrees`
  build and the old mint/statement circuit. Current code caches setup by
  complete circuit/config/predecessor-vk identity (see README "Prover setup
  cache (D1)"). The table remains an honest receipt of the old run; cold/warm
  numbers will be re-measured with the final D2 parameters rather than
  retroactively relabeling these results.

## Core scaling (2026-07-31, same machine, release)

Same bench run pinned with `taskset` to 1, 4, and 8 cores (64-core column
from the table above for comparison):

| cores | transfer prove | transfer verify | proof size |
|---|---|---|---|
| 1 | 2.98 s | 3.53 ms | 56,041 B |
| 4 | 2.97 s | 3.52 ms | 56,041 B |
| 8 | 3.71 s | 3.54 ms | 56,041 B |
| 64 | 2.97 s | 3.56 ms | 56,041 B |

**Proving does not scale with core count for these circuit sizes** — the
prover is effectively single-threaded here (small traces; per-step
parallelism doesn't pay). Consequences:

- Single-core speed is the only thing that matters for sender latency.
  A modern phone core (high clock + NEON) may well beat this 800 MHz-capped
  server Xeon; see `apple/` for the on-device benchmark harness.
- Optimizations should target single-thread time: cached prover setup,
  inner-proof FRI parameter tuning (smaller in-circuit verifier), PoW
  grinding to trade prover bits for verifier circuit size.

## On-device: iPhone (2026-07-31, release, physical devices)

Measured via `apple/` (see opencsv-rs issue #1 for full JSON and method;
best of 2 runs per device). Proof sizes byte-identical to the server runs.

| circuit | server (Xeon @ 800 MHz) | iPhone 16e (A18, iOS 26.2.1) | iPhone 17 Pro Max (A19 Pro, iOS 26.5.2) |
|---|---|---|---|
| genesis mint | 63.70 ms | **15.9 ms** | 22.4 ms |
| transfer (2 mint predecessors) | 2.97 s | **566 ms** | 674 ms |
| 2-hop transfer (2 node predecessors) | 2.96 s | **548 ms** | 668 ms |
| redeem (1 node predecessor) | 1.47 s | **268 ms** | 337 ms |
| verify (all) | 3.2–3.6 ms | 2.0–3.3 ms | 2.0–5.3 ms |

**Both phones beat the 64-core server by 3–5× on proving**, consistent with
the core-scaling finding above (proving is single-thread-bound; phone cores
have far higher clock + IPC). Recursive transfer proving at ~0.5–1 s is
viable for interactive mobile UX. Run-to-run spread was up to ~40%
(thermals/scheduling); the 16e's best edged out the Pro Max's, so treat the
flagship ranking as noise pending a controlled re-run.
