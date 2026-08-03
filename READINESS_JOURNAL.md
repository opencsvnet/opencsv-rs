# Signet/mainnet readiness decision journal

## 2026-08-03 — independent peer attestation

The previous multi-peer header loop mutated one shared chain. That made the
recorded result order-dependent and allowed a non-attesting later peer to
inherit the first peer's tip. The client now syncs independent clones from one
base and compares height, hash, and work before adoption.

## 2026-08-03 — filter cache is acceleration only

Filter hashes are not committed in Bitcoin block headers. A complete local
cache therefore cannot establish truth after reconnect. New connections now
re-fetch and compare the full chain from every peer. This deliberately costs
20.3 MB received in the measured warm restart; the cheap path is a persistent
same-session sync, not an unverifiable disk shortcut.

## 2026-08-03 — scan index v2

Occurrence exclusion cannot tolerate a cache that claims a higher checked tip
than the occurrence rows it retained. The index moved to strict, checksummed,
atomically replaced v2 files. Any partial, corrupt, unknown, out-of-order, or
legacy file reports `RebuildRequired`. The rejected alternative was keeping a
best-effort line parser because it could silently turn crash damage into a
false exclusion result.

## 2026-08-03 — conservative fee accounting

Published fee examples use maximum signed vbytes, integer sat/vB policy, and
show marker value separately from miner fee. The stock-creation transaction is
excluded and called out rather than amortized under an unstated lifetime. The
current 4.53 sat/vB node estimate is rounded up to 5 sat/vB for the receipt.

## 2026-08-03 — agent and wallet isolation

The local `uv` signet node does not advertise compact filters, so it was used
for Core/RPC measurements. The two-peer CBF receipt used public compact-filter
peers. Claude's node was observed as available but its data directory, wallet,
and source checkout were not touched. After owner approval, 5,000 signet sats
were moved from `uvwallet` into the deliberately isolated
`opencsv-readiness-20260803` wallet; transaction `8856b269…f290` is the funding
receipt.

## 2026-08-03 — failed Mach-O UUID suppression

The first reproducibility harness applied Apple's `-Wl,-no_uuid` through
global `RUSTFLAGS`. That also removed UUID load commands from Cargo build
scripts, which macOS dyld refuses to execute. The build failed before producing
an OpenCSV artifact and its temporary directory was removed. The flag was
deleted; reproducibility is tested by comparing two ordinary pinned-toolchain
builds, including the linker's native UUID output, instead of mutating every
host build executable.

The next comparison showed different content-derived UUIDs because the two
isolated Cargo target directories were embedded as distinct build paths.
Remapping each target directory to the same virtual `/build/target` path made
both the default and Signal-free binaries byte-identical across clean builds.

## 2026-08-03 — unspendable marker migration

The inherited marker was P2WSH of `OP_TRUE`. An external signet transaction
spent it and attached a non-replaceable child to `e985c098…ead1`, pinning the
parent. New anchors now use P2WSH of `OP_RETURN`: still included in BIP158
basic filters, but impossible to satisfy. Scanners accept both exact scripts
so history remains discoverable; constructors emit only the safe script. The
rejected alternative was to rely on fee policy or timing to outrun child
pinning because neither is a protocol invariant.

## 2026-08-03 — generic Bitcoin fee bump rejected

Bitcoin Core's `bumpfee` preserved the record and safe marker but deleted the
change output when the isolated input could not cover the requested fee plus
change. The confirmed replacement `c21073b1…6b1c` is therefore a negative
receipt. OpenCSV now has a pure solo-replacement validator with stable failure
codes and requires three fixed outputs plus non-dust change. The final wallet
must construct and validate its own replacement before signing; exposing
generic `bumpfee`, raw broadcast, or arbitrary Bitcoin send was rejected.

## 2026-08-03 — explicit header polling

The client used both unsolicited `headers` announcements and synchronous
`getheaders` requests on one blocking stream. Because the wire messages carry
no request identifier, an announcement can be consumed as a response and
leave the actual response queued. The client now uses one model only: explicit
polling on the already-authenticated connection.

## 2026-08-03 — filter-index readiness race

The post-mining scan regression then exposed a separate test-harness race:
Core's filter index still reported `synced: true` briefly while its
`best_block_height` lagged the new chain tip. Core does not answer a
`getcfheaders` range it cannot yet serve, so the client correctly timed out.
The readiness helper now requires both `synced: true` and exact index/tip
height equality before starting the P2P request.
