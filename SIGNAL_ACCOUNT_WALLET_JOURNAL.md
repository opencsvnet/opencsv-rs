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
vin 0 alone fixes the OpenCSV context, but the account wallet cannot safely add
an input unless it also authoritatively verifies and durably reserves that
input. The production fee-bump builder therefore uses a stricter change-only
profile: it freezes every input and output script/position, pins the original
change destination, and only reduces non-dust change. The general validator
still rejects duplicates, insertion before vin 0, protocol-output mutation,
reordering, change removal, dust, and non-increasing fees.

## Asset-selection correction

The first account draft still accepted OpenCSV `coin_ids` and output `amounts`
from Swift. That was inconsistent with a Rust-owned account wallet. The stable
request now accepts only asset, recipient, and amount. Rust selects exactly two
unreserved protocol inputs, minimizes change, creates the second output, and
excludes every input named by an in-memory or restored pending proof.

## 2026-08-03 — authoritative fee-input and recovery gates

- Added an account-owned compact-filter verifier. It connects to independently
  attested peers, locates the exact creating output in a merkle-checked full
  block, and scans through the verified tip for a later spend. The check runs
  after reservation, again immediately before initial signing, and before fee
  bump signing. Esplora remains discovery/relay acceleration only.
- Changed UTXO reservation to use an immediate SQLite transaction and a unique
  `(txid, vout)` key across handles. A second handle retries the next eligible
  output instead of reusing or silently racing the first.
- Restoring the database explicitly re-locks every durable reservation before
  pending proofs are imported.
- Added adversarial receipts for a false explorer hint, a recently spent
  outpoint between prepare and sign, two simultaneously open account handles,
  every durable operation state, and replacement persistence/reopen/resume.
- The tests found two bugs before publication. The funding fixture reused a
  dummy prevout, making two test deposits conflict. Separately, BDK selected a
  fresh change script for RBF unless the original script was explicitly
  pinned, and equal-second `last_seen` timestamps made conflict restoration
  nondeterministic. Unique test prevouts, a pinned change script, and strictly
  increasing replacement observation time fixed those failures.

## 2026-08-03 — device-clone blocker

Hardware review reported that iOS restored Keychain state onto the iPhone 16e.
An account root alone therefore cannot identify one primary device. The
accepted gate adds a second random 32-byte device binding supplied outside
JSON from a non-migratable `ThisDeviceOnly` item. Rust stores its root-bound
commitment in SQLite and in the Secure Backup checkpoint. A mismatched restored
device opens read/export-only and every new Bitcoin-writing action fails with
`device_binding_mismatch`.

A plain migratable nonce and silent root rotation were rejected. Clean-database
recovery must supply the old checkpoint commitment; explicit recovery/rekey is
required to move signing authority and existing assets. Signal receive/render
integration must also deduplicate by an identity over the canonicalized
consignment, not attachment id, delivery nonce, raw field order, or whitespace,
so byte-distinct delivery retries cannot render one payment twice. The physical
acceptance test must crash/resume the sender into two attachments and observe
exactly one verified payment bubble.

Fresh setup must create the root and binding atomically. If an OS restore
presents an existing root without its `ThisDeviceOnly` binding, Swift passes an
empty binding rather than generating a replacement. Rust opens that primary
read/export-only and returns `device_binding_mismatch` from every writing call;
the regression covers this missing-binding form as well as a mismatched clone.

## 2026-08-03 — post-reservation cleanup gate

The prepare path originally released a fee reservation when authoritative
verification or proof creation failed, but later failures in asset creation,
context rebinding, pending export, database transition, or checkpoint export
could return without cleanup. Every error after the planned operation is now
routed through one fail-closed helper that cancels any pending proof, unlocks
and deletes the durable fee reservation, and records the stable rejection.
A regression forces an invalid issuer request after reservation and proves the
operation is cancelled with no locked or persisted reservation.

Fee bump already reverified the funding output before building a replacement.
A new scripted-verifier regression now rejects that third verification and
proves the original signed bytes, txid, and state remain unchanged.

## Validation receipt

- Warnings-denied `opencsv-ffi --all-targets`: 28 passed, 0 failed.
- Warnings-denied `opencsv-bitcoin --lib`: 31 passed, 0 failed.
- `opencsv-ffi --all-targets --no-deps` Clippy with `-D warnings`: passed.
- Device-clone read-only enforcement passes.
- Cross-handle distinct fee reservation passes.
- Every durable operation-state reopen matrix passes.
- Exact replacement persistence, failed relay, reopen, and resume passes.
- Post-reservation failure cleanup and fee-bump revalidation preservation pass.

## Explicit remaining gates

- hosted wallet CI after publication;
- hosted CI and independent re-review of the completed C2 adversarial audit;
- Swift `ThisDeviceOnly` binding and checkpoint recovery integration;
- canonical-consignment verdict/render deduplication;
- in-place database migration, both build flags, and physical signet
  acceptance on the iPhone 16e.

These open items prevent a mainnet-readiness claim. No PR, merge, release,
mainnet broadcast, upstream submission, or destructive device action is part
of this journal entry.
