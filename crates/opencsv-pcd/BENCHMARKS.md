# opencsv-pcd production profile and benchmarks

This is the D2 receipt for proof lineage v3. It freezes the FRI profile,
states the security-accounting assumptions, and records cold/warm release
measurements without relabeling the older test-grade results.

Proof lineage v4 keeps these FRI parameters and adds the one-input recursive
shape. Its first cold debug correctness receipt was 508.26 s for mint →
one-input transfer → root verification; that number is intentionally not
mixed into the release table below. The cold/warm release receipt is recorded
in its own v4 table; a physical-device run is still required before the v4
shape is described as production-performant.
The separate migration receipt—v3 mint root verification → v4 one-input
recursive transfer → v4 root verification—completed in 507.92 s cold debug.

Reproduce the desktop table with:

```sh
RUSTFLAGS='-D warnings' cargo test -p opencsv-pcd --release \
  --test bench -- --ignored --nocapture
```

The benchmark prints profile ID, actual extended trace degrees, raw and
union-adjusted proven-security estimates, prove/verify time, and serialized
`BatchStarkProof` size.

## Frozen proof-lineage-v3 profile

Profile ID:
`opencsv-pcd-v3-babybear4-fri-b3-a4-q64-cpow16-qpow16-final4-pack1x3-horner4`.

| parameter | value |
|---|---:|
| challenge field | quartic BabyBear |
| conservative `floor(log2(|F|))` | 123 bits |
| `log_blowup` | 3 (8× LDE) |
| maximum folding arity | 4 |
| `log_final_poly_len` | 2 (4 coefficients) |
| FRI queries | 64 |
| commit grinding | 16 bits per FRI commit round |
| query grinding | 16 bits |
| Merkle cap height | 0 |
| table packing | 1 public lane, 3 ALU lanes, 4-step Horner packing |

`CoinFriParams::testing()` remains available only to the isolated recursion
feasibility spike. Public proving now emits v4 statements and envelopes under
the explicit `opencsv-pcd-coin-v4-with-v3-fri94` verifier-set tag.
Authenticated v3 proofs remain valid roots and recursive predecessors without
relabeling. A v1/v2 envelope remains parseable for migration inspection but
cannot verify or act as a recursive predecessor.

## Security accounting

The executable calculator is `src/security.rs`, using the
[Plonky3 0.6.3 proven-security implementation](https://github.com/Plonky3/Plonky3/blob/p3-uni-stark-v0.6.3/uni-stark/src/security.rs).
That implementation includes unique- and list-decoding regimes and explicitly
distinguishes the proven bound from the more optimistic random-words estimate;
the latter is informed by
[Diamond–Gruen 2025/2010](https://eprint.iacr.org/2025/2010), while the improved
proximity-gap bound is from
[Ben-Sasson et al. 2025/2055](https://eprint.iacr.org/2025/2055).

OpenCSV uses conservative inputs:

- 123 challenge-field bits rather than rounding the quartic field up to 124;
- 128-bit Poseidon2 commitment collision target;
- 1,024 total constraints and maximum degree 3; the v3 lookup-expanded
  circuits measured 699 constraints for mint and 707 for transfer/redeem,
  while v4 setup applies the same fail-closed cap;
- `max_combo = 2` for local/next openings;
- the minimum proven result across every actual batch-instance trace;
- a 2-bit union margin for the calculator's four components (ALI, DEEP, FRI
  commit, FRI query) plus `ceil(log2(batch_instances))`.

The profile is frozen only after measuring the concrete recursive shapes. The
deepest current proofs have seven instances and degree bits 17: the calculator
reports 100 raw proven bits, reduced by the 5-bit combined margin to 95
adjusted bits. The published and runtime-enforced floor is **94 bits**;
degree-18 growth remains admissible at exactly 94, while degree 19 fails
closed. Mint reports 100 adjusted bits and redeem 96. The conjectured result
is field-capped at 123 bits and is not published as the deployment claim.

Both setup and verification fail closed:

- setup rejects lookup-expanded circuit drift beyond 1,024 constraints or
  degree 3;
- verification recomputes the receipt from proof-carried trace degrees and
  rejects below 94 adjusted bits;
- the v4 envelope/statement boundary prevents a v3 proof from being
  relabeled, while authenticated v3 is accepted explicitly and v1/v2 remain
  non-verifying.

This is concrete parameter accounting, not a substitute for an independent
cryptographic review of Plonky3, Poseidon2, or the batch-composition model.

## D2 desktop results — 2026-08-02

- Apple M4, 10 cores, 16 GiB RAM
- macOS 26.5.2, arm64
- rustc 1.97.1 (8bab26f4f 2026-07-14)
- release profile with LTO; one process, sequential rows

| circuit | prove | verify | proof size | proven | adjusted | degree bits |
|---|---:|---:|---:|---:|---:|---|
| genesis mint (cold) | 119.81 ms | 14.85 ms | 535,705 B | 105 | 100 | `[6,6,10,6,6,6]` |
| genesis mint (warm) | 102.35 ms | 14.80 ms | 535,705 B | 105 | 100 | `[6,6,10,6,6,6]` |
| transfer / mint predecessors (cold) | 9.94 s | 21.73 ms | 854,105 B | 100 | 95 | `[8,10,17,15,16,6,6]` |
| transfer / mint predecessors (warm) | 7.77 s | 22.20 ms | 854,105 B | 100 | 95 | `[8,10,17,15,16,6,6]` |
| transfer / node predecessors (cold) | 12.19 s | 21.35 ms | 841,464 B | 100 | 95 | `[9,10,17,16,16,6,6]` |
| transfer / node predecessors (warm) | 9.76 s | 21.38 ms | 841,464 B | 100 | 95 | `[9,10,17,16,16,6,6]` |
| redeem (cold) | 5.86 s | 19.98 ms | 778,466 B | 101 | 96 | `[9,9,16,15,15,6,6]` |
| redeem (warm) | 4.71 s | 19.94 ms | 778,466 B | 101 | 96 | `[9,9,16,15,15,6,6]` |

The D1 setup cache saves 15–22% on the warm rows in this run. Proof size and
native verification remain history-independent, but predecessor shape changes
the root circuit enough that the two transfer rows have different sizes and
costs.

## V4 one-input desktop receipt — 2026-08-05

Same Apple M4 host and release profile. This is one cold process run of the
exact `one_input_transfer_spending_mint_output_verifies` test; it includes a
real predecessor mint, in-circuit predecessor verification, root verification,
and the runtime security check.

| circuit | prove | verify | proof size | proven | adjusted | degree bits |
|---|---:|---:|---:|---:|---:|---|
| predecessor mint | 184.10 ms | — | — | — | — | — |
| v4 one-input / mint predecessor (cold) | 5.809 s | 19.41 ms | 788,068 B | 101 | 96 | `[8,9,16,15,15,6,6]` |
| v4 one-input / mint predecessor (warm) | 4.803 s | 20.38 ms | 788,068 B | 101 | 96 | `[8,9,16,15,15,6,6]` |

The separate cold-debug v3→v4 migration test verifies a bound v3 mint root,
consumes it inside the v4 one-input circuit, and verifies the v4 root. An
outer-byte v3→v4 relabel is rejected with `StatementMismatch`.

## D2 on-device impact

Physical iPhone 16e (A18, iOS 26.2.1), release build, one cold sequential run
through the separately signed `net.opencsv.bench` harness:

| circuit | prove | verify | proof size | proven | adjusted | degree bits |
|---|---:|---:|---:|---:|---:|---|
| genesis mint | 180.8 ms | 18.46 ms | 535,705 B | 105 | 100 | `[6,6,10,6,6,6]` |
| transfer / mint predecessors | 11.253 s | 22.78 ms | 854,105 B | 100 | 95 | `[8,10,17,15,16,6,6]` |
| transfer / node predecessors | 14.469 s | 23.48 ms | 841,464 B | 100 | 95 | `[9,10,17,16,16,6,6]` |
| redeem | 7.283 s | 22.24 ms | 778,466 B | 101 | 96 | `[9,9,16,15,15,6,6]` |

The harness emits an `OPENCSV_BENCH_PARTIAL` JSON receipt after each circuit
and a final `OPENCSV_BENCH_RESULT` line. It disables the idle timer only while
running and does not replace, read, or modify Signal.

The physical run also changed the profile design. The first 16×-LDE candidate
and an 8× candidate without four-step Horner packing were both killed by the
iOS per-process memory limit: the kernel recorded a 3,376 MB hard limit and
3,457,027 KB resident at termination. The latter completed first-hop transfer
but died on the degree-18 node-predecessor transfer. Four-step Horner packing
reduced the deepest ALU trace to degree 17; the exact same two-hop sequence
then completed. Wider four-lane ALU packing and a 64-coefficient final
polynomial were also measured and rejected because recursive verifier growth
kept or expanded the degree-18 bottleneck.

## Historical test-grade baseline — 2026-07-31

The following rows used `CoinFriParams::testing()` (4× LDE, two queries, no
grinding), before D3 issuer authorization and the v3 statement/profile
boundary. They are retained only to make the D2 cost increase auditable.

### Xeon Gold 6526Y, release

| circuit | prove | verify | proof size |
|---|---:|---:|---:|
| genesis mint | 63.70 ms | 3.22 ms | 46,431 B |
| transfer / mint predecessors | 2.97 s | 3.56 ms | 56,041 B |
| transfer / node predecessors | 2.96 s | 3.60 ms | 56,041 B |
| redeem | 1.47 s | 3.51 ms | 54,058 B |

### Physical-device baseline

| circuit | iPhone 16e (A18) | iPhone 17 Pro Max (A19 Pro) |
|---|---:|---:|
| genesis mint | 15.9 ms | 22.4 ms |
| transfer / mint predecessors | 566 ms | 674 ms |
| transfer / node predecessors | 548 ms | 668 ms |
| redeem | 268 ms | 337 ms |

Those historical device numbers are not projections for v3. The measured
production-profile phone results are recorded above.
