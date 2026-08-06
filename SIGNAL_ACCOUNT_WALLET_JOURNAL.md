# Signal account-wallet implementation journal

## 2026-08-03 — isolated final-phase implementation

- Started `codex/signal-account-wallet` from pushed readiness tip `a7fe2e0` in
  `/Users/posix4e/Documents/opencsv/worktrees/opencsv-rs-signal-wallet`.
  Claude's Signal checkout, Pods, wallets, nodes, and device state are outside
  this clone and were not modified.
- Kept PR #2's receive, attachment, evidence, and persistence architecture as
  migration inputs. Superseded the remote anchor provider and Swift-owned fee
  key/UTXO/change boundary.

## 2026-08-06 — Signal USD testnet identity is permanent

The owner confirmed that the USD instrument currently reviewed into Signal is
the permanent testnet asset and always uses the signet Bitcoin fee tree. It is
not a staging identity that can later be promoted. Production USD will be a
separate instrument and issuer review over a separately initialized mainnet
account, backup namespace, and BIP84 fee tree.

The existing implementation already enforces the important mechanics: account
databases are permanently network-bound, the preview manifest declares
`network = signet` and `test_only = true`, and Signal's reviewed mainnet issuer
set is empty. The acceptance receipts must therefore name this asset as test
USD and must never imply dollar or USDT redemption or future mainnet continuity.

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
the missing state is sticky, so supplying a new binding on a later open still
cannot arm it. The regression covers the missing binding, later replacement
attempt, and mismatched-clone forms.

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

## 2026-08-03 — canonical consignment identity

Hashing raw attachment bytes was rejected as the verdict/render identity.
Bincode accepts semantically equivalent overlong integer encodings, so one
consignment could otherwise have two byte hashes even before Signal delivery
nonces are considered. The account receive path now decode→canonically encodes
the consignment before verification, persistence, and SHA-256 identity, and
returns that identity to the host. A regression constructs two distinct valid
encodings of one consignment and proves their canonical bytes and IDs match.

## Validation receipt

- Warnings-denied `opencsv-ffi --all-targets`: 29 passed, 0 failed.
- Warnings-denied `opencsv-bitcoin --lib`: 31 passed, 0 failed.
- `opencsv-ffi --all-targets --no-deps` Clippy with `-D warnings`: passed.
- Device-clone read-only enforcement passes.
- Cross-handle distinct fee reservation passes.
- Every durable operation-state reopen matrix passes.
- Exact replacement persistence, failed relay, reopen, and resume passes.
- Post-reservation failure cleanup and fee-bump revalidation preservation pass.
- Equivalent consignment encodings normalize to one returned identity.

## 2026-08-03 — Signal integration recovery and RBF delivery correction

- Added exact Secure Backup checkpoint restore through the C ABI. Rust now
  validates hash, network, root-derived owner, and binding commitment before
  atomically importing assets, operation journal rows, consignments, spent
  state, and verification snapshots into a clean account.
- Added the normalized `asset_id` and `to_owner` to prepare receipts so Swift
  can construct mint/transfer delivery metadata without deriving protocol
  identities or inspecting pending proof JSON.
- The iOS integration exposed an operation-lifecycle bug: marking a mempool
  consignment delivered changed the sole state to `consignment_delivered`,
  closing the only state window in which `opencsv_fee_bump` was legal. Delivery
  is now an idempotent receipt fact while an unconfirmed operation remains
  `mempool`; confirmation advances a delivered operation to the terminal state.
- The same audit found that first observation of an RBF replacement tried to
  finalize the already-finalized OpenCSV pending proof again. Refresh now
  recognizes `delivery_ready`, preserves the existing consignment, and only
  updates the replacement's Bitcoin observation state.
- A regression proves mempool delivery acknowledgement is idempotent and
  remains fee-bumpable while a confirmed acknowledgement is terminal.

## Explicit remaining gates

- hosted wallet CI after publication;
- hosted CI and independent re-review of the completed C2 adversarial audit;
- Swift `ThisDeviceOnly` binding and checkpoint recovery integration;
- Signal verdict/render storage keyed by Rust's canonical consignment identity;
- in-place database migration, both build flags, and physical signet
  acceptance on the iPhone 16e.

These open items prevent a mainnet-readiness claim. No PR, merge, release,
mainnet broadcast, upstream submission, or destructive device action is part
of this journal entry.

## 2026-08-04 — issuance moved to an opt-in headless operator

Removing issuer controls from Signal did not remove protocol issuance. The
issuer-only account methods are now exposed through a dedicated
`opencsv-issuer` binary behind the non-default `issuer-tools` feature. Signal's
C ABI and CocoaPods build still contain no definition or mint action.

The operator reads the account root and device binding from files, never CLI
values, and emits JSON for automation. It creates exact manifests from terms,
prepares mints only by exact asset id, exports checkpoints, requires exact-hash
backup acknowledgements, and exposes durable broadcast/resume/cancel/fee-bump
operations. The earlier signet acceptance example's stale ticker-based mint
request was corrected to require an asset id.

This preserves the important distinction between protocol validity and wallet
trust. Anyone may run the open-source executable, but they cannot mint an
existing issuer's asset without the committed issuer seed, and Signal will not
recognize an arbitrary new `USD` ticker as reviewed USD. No Tether issuer is
claimed or configured without Tether-controlled authority and an authenticated
manifest.

## 2026-08-04 — simulator upgrade receipt and failed unsigned-install path

The first attempt to install the reviewed signet-USD build used
`CODE_SIGNING_ALLOWED=NO`. The source compiled, but the resulting simulator app
had no effective application-group entitlement. Signal failed closed during
launch, as it should. Installing that entitlement-incompatible bundle also
caused CoreSimulator to replace its simulator-only app and group containers;
the temporary Signal registration and test wallet could not be recovered.
The physical iPhone, source worktrees, issuer checkpoint, and all mainnet state
were untouched.

The accepted simulator procedure is now: build with the default local ad-hoc
signature, verify that the generated simulated entitlements contain both
Signal application groups and the expected keychain group, and only then use
`simctl install`. Never use an unsigned build for an in-place Signal acceptance
upgrade. A newly registered simulator must be upgraded only with that signed,
entitlement-compatible path. The acceptance runbook records the container
identifiers before and after installation and treats any logical app/group
state change as a failed in-place upgrade.

## 2026-08-04 — live signet issuance exposed a checkpoint self-reference

The first live headless mint preparation used the debug prover and took about
13 minutes. Its proof was valid, but its advertised checkpoint hash was not:
storing that hash and the receipt changed the very checkpoint being hashed.
The operation was cancelled before signing or broadcast and its fee outpoint
was released. The mismatching export is retained privately as forensic
evidence; it was never acknowledged as a valid backup.

The accepted fix defines the backup checkpoint over canonical operation state:
operation `checkpoint_hash` and `backup_acked` fields are normalized and the
receipt's derived checkpoint field is excluded. Mint preparation now stores
the final receipt before hashing. Acknowledgement independently recomputes the
current checkpoint and rejects the supplied hash if any wallet state changed
after export. Two regressions prove that a prepared checkpoint equals the
immediate export and remains stable across acknowledgement, and that a stale
checkpoint is rejected after a later state change.

The corrected release-prover preparation created operation
`2059c43e4bdc23fb6d180223546af2cb` for exactly 100 preview USD base units
(`100000000` at six decimals), asset
`1d58a8145eedac17efe66371293eb472a4c68554141cc14380360e6eb720b507`, and
recipient owner
`ff17c90b2e7c511f8d64734e07833502d6a82308d0c5ba0ca862f61ebd48c124`.
The exact exported and acknowledged checkpoint is
`77f94dc96d1610da4c7775a86fbbcb576ff0b72edadcf9346a04e75c06f524ef`.

After that acknowledgement, Rust signed and persisted the transaction before
submitting it to both configured signet peers. Transaction
`eb5571a6c2b5e916546dc5a099ef0047e47b8a03d1554c25845142491421c22c`
uses 455 sats at 2 sat/vB with record vout 0, marker vout 1, and change vout 2.
The generic relay also observed it. The canonical 536,508-byte consignment has
SHA-256 identity
`16d16cde8b9fda972bf5b56abda706399907d4259987251a1d1ddd09f36fdd68`.

Signal Desktop delivered that one file to the freshly registered simulator
account as a normal 537 KB attachment. The simulator downloaded it intact.
At the time of this entry the transaction is still in the signet mempool, so
the simulator correctly shows 0 USD and has not persisted a credit. This is a
transport receipt and a fail-closed pre-confirmation receipt, not yet a
completed payment acceptance receipt. The activation sweep will be rerun only
after the anchor reaches the required confirmation depth.

Focused warnings-denied validation after the checkpoint repair:

- account-wallet tests: 29 passed, 0 failed (one unrelated test filtered);
- headless issuer CLI tests: 4 passed, 0 failed;
- `rustfmt --edition 2021 --check ffi/src/account.rs`: passed;
- `git diff --check`: passed.

## 2026-08-05 — restart replay resurrected spent protocol coins

The first two-simulator Carol-to-Bob transfer found a real persistence defect,
not a transport or verifier failure. Carol's first local transfer operation
`94e778bca55ad34c46cc1506d612b9a8` anchored transaction
`0bf4bd8a07c0caa575fba0ced6ed47f70c6353b7b839c0fe788ff80804b2f5b8`,
which confirmed at signet height 316341. After restart, a second operation
`74c70871ebae832fb715ba160df00aad` anchored transaction
`90c075530160160ccf7f4259f8046f2e5611c3e2bd86868771be9ffeca8e4d0b`.
Both durable pending exports named the same two protocol coin ids and carried
the same proof and nullifiers. Bob therefore rejected the second attachment
with the earlier nullifier occurrence at height 316341. Signal attachment
delivery and Bitcoin relay worked; OpenCSV asset acceptance correctly failed.

The account reopen path had restored received consignments only. Locally
finalized outgoing consignments have no receive snapshot, so their spent inputs
and wallet-owned change were omitted. The in-memory finalize path also marked
inputs spent without crediting locally-owned outputs. Restart therefore
resurrected the original inputs and discarded valid change.

The accepted repair replays each complete local operation journal in stable
creation/row order, reconstructs its exact consignment at the durable txid,
and compares id, canonical bytes, and spend list with SQLite before accepting
the state. Finalization now credits locally-owned outputs with their exact
unconfirmed parent while preserving later spent state during deterministic
replay. Duplicate local spends fail closed. One narrow migration is allowed:
if an earlier conflicting local operation is already durably confirmed and
the later duplicate is only in mempool, the later operation becomes the
terminal `protocol_rejected` audit record. Its Bitcoin transaction and receipt
are retained, its OpenCSV outputs are never credited or redelivered, and a new
Secure Backup is required. Ambiguous mempool-vs-mempool and confirmed-vs-
confirmed conflicts still fail closed as `protocol_state_conflict`.

Regression receipts cover restored change, non-reuse of the spent inputs,
tampered consignment bytes, confirmed-winner quarantine, ambiguous-conflict
failure, and incomplete finalized journals. The complete `opencsv-ffi` test
target passes: 39 unit tests, 12 integration tests, and doc tests, with zero
failures. The failed simulator recording is retained as evidence; no return
hop, destructive wallet reset, mainnet action, or verifier bypass was used.
The complete workspace's non-ignored tests also pass. In that debug run the
recursive transfer test took 804.28 seconds and mint-to-redeem took 402.07
seconds; the repository's pre-existing explicitly ignored proof benchmarks
remained ignored. `opencsv-ffi --all-targets --no-deps` Clippy passes with
warnings denied, both changed Rust files pass `rustfmt --check`, and
`git diff --check` passes.
