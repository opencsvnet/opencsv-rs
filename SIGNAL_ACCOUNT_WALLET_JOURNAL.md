# Signal account-wallet implementation journal

## 2026-08-03 — isolated final-phase implementation

- Started `codex/signal-account-wallet` from pushed readiness tip `a7fe2e0` in
  `/Users/posix4e/Documents/opencsv/worktrees/opencsv-rs-signal-wallet`.
  Claude's Signal checkout, Pods, wallets, nodes, and device state are outside
  this clone and were not modified.
- Kept PR #2's receive, attachment, evidence, and persistence architecture as
  migration inputs. Superseded the remote anchor provider and Swift-owned fee
  key/UTXO/change boundary.

## Persistence decision

Enabling BDK's optional SQLite feature failed dependency resolution because it
uses `rusqlite` 0.31 / `libsqlite3-sys` 0.28 while the Signal-facing graph
already links `rusqlite` 0.38 / `libsqlite3-sys` 0.36. Cargo permits only one
crate with the `sqlite3` links key. The accepted design uses BDK's supported
`WalletPersister` interface and serializes its public `ChangeSet` into an
append-only table on `rusqlite` 0.38. This keeps one native SQLite runtime.

## Crash-ordering decision

The order is: reserve inputs and persist proof -> export exact checkpoint ->
receive Secure Backup acknowledgement -> build/sign -> persist signed bytes ->
attempt relay -> observe independently -> finalize/deliver. Tests deliberately
use an unreachable relay to prove the signed transaction and exact layout are
already durable when the network call fails.

## Relay decision

The existing compact-filter peer code was read-oriented and did not expose a
transaction submission path. A small generic Bitcoin P2P relay was added
instead of an OpenCSV service. It connects to every configured peer, completes
version/verack, submits the full transaction, and records failures per peer.
Zero successful writes may use generic Esplora broadcast; successful writes
still require separate mempool observation.

## RBF decision

The initial pure validator froze every input. Review correctly identified that
vin 0 alone fixes the OpenCSV context. The validator now permits new fee inputs
only after the immutable original input prefix and rejects duplicates,
insertion before vin 0, protocol-output mutation, reordering, change removal,
dust, and non-increasing fees.

## Asset-selection correction

The first account draft still accepted OpenCSV `coin_ids` and output `amounts`
from Swift. That was inconsistent with a Rust-owned account wallet. The stable
request now accepts only asset, recipient, and amount. Rust selects exactly two
unreserved protocol inputs, minimizes change, creates the second output, and
excludes every input named by an in-memory or restored pending proof.

## Validation receipt

- `RUSTFLAGS='-D warnings' cargo check -p opencsv-ffi --all-targets` — pass.
- `RUSTFLAGS='-D warnings' cargo test -p opencsv-ffi --all-targets` — pass:
  eight account/unit tests and every existing export, cross-check,
  persistent-client, round-trip, and scan integration test.
- `RUSTFLAGS='-D warnings' cargo test -p opencsv-bitcoin --lib` — 28 passed.

## Explicit remaining gates

- authoritative header/filter/full-block revalidation of the selected fee
  outpoint before context/proof/signing;
- dishonest-Esplora and conflicting-UTXO tests for that boundary;
- restore tests at every operation transition and concurrent-operation tests;
- end-to-end fee-bump journal/rebroadcast tests;
- Swift Secure Backup policy integration, in-place database migration, both
  build flags, and physical signet acceptance on the iPhone 16e.

These open items prevent a mainnet-readiness claim. No PR, merge, release,
mainnet broadcast, upstream submission, or destructive device action is part
of this journal entry.
