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

## 2026-08-06 — reviewed-issuer spend gate and issuer binary split

Signal's `USD` presentation is now authorized by exact asset identity, not by
the three-byte unit code or by possession of a manifest. Transfer planning
checks the configured `usd_issuers` registry before creating an operation, then
checks it again before proof generation, proof commit, and signing. Removing an
issuer cancels an unsigned solo operation or the entire unsigned frozen batch
with stable rejection `asset_not_reviewed`. A signed or already-broadcast
operation remains recoverable because changing product review cannot erase a
signature that has already escaped.

Privileged issuance remains available to the opt-in `opencsv-issuer` operator,
but the default Signal static library and public header no longer contain
`opencsv_wallet_init_issuer` or `opencsv_prove_mint`. CI builds the default
archive and checks those symbols are absent, then separately compiles and tests
the `issuer-tools` feature and checks the symbols are present there. This is a
binary-boundary guarantee in addition to the absence of mint UI.

Operation receipts now report phase timings separately for funding
verification, local proving, zero-confirmation dependency observation,
pre-sign verification, local signing/persistence, relay submission, pinned
observer evaluation, and CBF/SPV confirmation. In particular,
`proof_ready -> signed_persisted` does not call the prover; any delay in that
transition can now be attributed honestly instead of being published as proof
time.

## 2026-08-07 — real Signal forwarding exposed value-carry and chain-state defects

A real simulator payment, not a mocked UI, anchored 25 Test USD in transaction
`e5ffe6076052e4bf98ba117d7122d79e21de14ed0992070c0dbe85da22dd9ee9`.
The recipient verified and credited the Signal attachment while the parent was
unconfirmed. Forwarding 10 Test USD then failed deterministically during local
proof generation. An exact reproducer loaded Bob's persisted consignment and
derived owner branch without printing either secret. It identified the
conflicting field value `2013265920` as BabyBear `-1` in the value-conservation
gadget—not a recursion or attachment defect.

Values use 24/24/16-bit limbs. The valid split `25_000_000 = 10_000_000 +
15_000_000` requires a `-1` borrow from the low limb, but the gadget had
incorrectly constrained every intermediate carry to the Boolean set `{0, 1}`.
The repair constrains each intermediate carry to `{-1, 0, 1}` with
`c(c-1)(c+1) = 0` and still pins the final carry to zero. A fast exact-split
regression passes, the full transfer target passes six tests, and the
release-mode mint -> one-input transfer -> forwarded one-input transfer proves
in 6.522 seconds and 7.226 seconds on this Mac. The persisted-consignment
reproducer also completes and verifies. These are development-host receipts,
not iPhone product performance claims.

Signet confirmed the parent before the next receive scan. That scan exposed a
second defect: the provisional snapshot helper appended a mempool-sentinel
copy even when the confirmed snapshot already contained the exact txid. The
kernel correctly reported the transaction as conflicting with itself. The
helper now resolves the consignment's sentinel reference to the single
canonical confirmed entry, validates that entry's record and funding context,
and injects a sentinel only while the exact transaction is genuinely absent
from confirmed history. The focused confirmed-parent regression passes.

The same acceptance run found one corrupt rebuildable BIP158 filter returned
by a public peer and cached at signet height 316586. Its bytes did not match the
cross-peer-committed filter hash. Invalid cached candidates are now deleted and
refetched, and an invalid response from one peer no longer prevents trying the
remaining independent peers. The complete `opencsv-cbf` suite passes: 48 tests
across unit and non-live integration targets, zero failures. No wallet secret,
asset checkpoint, transaction, or confirmed-chain commitment is rewritten by
that cache repair.

The repaired framework then resumed the same real Signal flow successfully.
Bob's durable operation `052f6e79210ca3a847cca6eded9871ca` spent 10 Test USD
from the received 25 Test USD coin and retained 15 Test USD change. It signed
and persisted signet transaction
`a3a3f4b12f71e3423801cea069e5251260aeae70fb9cfd133cd7aaefce12dc0a`,
submitted the complete bytes to two of two configured Bitcoin peers, and
delivered the 786,326-byte Signal attachment. The required pinned Blockstream
observer returned identical raw bytes in 347 ms under the
`lets_encrypt_yr` profile. The optional mempool.space observer timed out after
8.025 seconds and was recorded as unavailable; it was not silently counted as
success. Carol verified the proof, ownership, anchor binding, and exact
mempool transaction, then credited `+10 USD` as **available before
confirmation · replacement risk**. This is the first live forwarding receipt
for the negative-carry split; it remains a signet Test USD receipt with no
monetary or redemption claim. The anchor subsequently confirmed at signet
height 316620 in block
`0000000897a36fd043cb0c061f4f66b7575cfc1ac166cd0f67a6d81b24e3b5e3`.

The unmodified simulator captures are retained under
`receipts/ios/2026-08-07/real-signal-usd/`. The 38.067-second consumer cut uses
only those real Signal recordings and removes waiting time; it does not
reconstruct or fabricate application screens. Its file is
`opencsv-real-signal-test-usd-quick-demo.mp4` and its SHA-256 is
`ca859b8e130c2960b7541b92ca60fc83d29da6c2f9e5aab9fd42f931871808e0`.

## 2026-08-07 — authoritative verification reduced from minutes to seconds

The instrumented return receipt separated a 6.237-second proof and 42 ms of
signing/persistence from 77.861 seconds of funding verification and 93.163
seconds of pre-sign verification. The delay was not Bitcoin confirmation and
was not proof generation. Each phase opened a new CBF client, re-requested the
complete 316k-height filter-hash chain from every peer, and the paged linkage
loop re-folded the growing prefix on every page.

The accepted repair has three layers:

1. filter-header paging carries one rolling linkage value, making a cold full
   attestation linear rather than quadratic;
2. a new connection re-derives the filter header over the complete persisted
   prefix and asks every peer to re-attest an exact 144-block tail plus its
   preceding header, then fetches only new hashes; changing any earlier cached
   hash changes that linkage unless SHA256d second-preimage resistance fails;
3. the account wallet retains that independently attested CBF session across
   the proof and pre-sign phases, resyncs it to the current agreed header tip,
   and rechecks the exact outpoint instead of reconnecting. Failed public peers
   are pruned, but signet/mainnet signing still requires two surviving peers
   that agree. A TCP handshake or advertised service bit is not sufficient.

Using a copy of Bob's rebuildable public-chain cache and five independently
addressed public signet peers, the release readiness probe reached tip 316628
with five completed attestations in 1.837 seconds. A second same-session tip
sync took 417 ms without another handshake; scanning the newest filter took
124 ms. Parallel connection and attestation mean an unavailable peer consumes
one timeout budget rather than serially delaying every healthy peer. The
connection transferred 11,425 bytes out and 30,757 bytes in, rather than
replaying megabytes of historical filter hashes. The complete CBF target (50
unit/non-live integration tests), exact sign-time recently-spent rejection,
formatting, and warnings-denied crate Clippy pass.

This optimization does not call an unconfirmed transaction confirmed, remove
the pre-sign outpoint check, trust the disk cache, or weaken the two-peer
minimum. It removes redundant computation so a small payment can become
explicitly `available before confirmation` promptly under its separately
configured observer policy. A continuous Bob/Carol operation still has to
measure the full Signal path before this becomes a product-latency claim.

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

## 2026-08-07 — zero-confirmation parent identity and duplicate pre-sign lookup

The first post-crash Bob-to-Carol Test USD send exposed two distinct issues.
The send itself recovered without re-proving, signed in 25 ms, attempted five
ordinary Bitcoin peers with four complete submissions, and was independently
observed as transaction
`cb66620d4268add8843c802731180f15e33ed86a3010f83aab2a19d8085a920f`.
Its pre-sign phase nevertheless took 194 seconds because it repeated a blocking
Esplora lookup for an unconfirmed OpenCSV parent immediately after the proof
job had already performed the same exact-parent check.

Tracing that lookup found a more serious representation defect. Locally
created change retained the anchor's 32 consensus bytes as hexadecimal, while
received provisional coins retained Bitcoin's reversed display txid. The
dependency resolver intentionally interprets its input as consensus bytes.
An actual received-coin child could therefore request the byte-reversed parent,
and finality/freeze SQL could miss the display-txid row even when the protocol
coin was frozen in memory.

The accepted invariant is now one representation at the protocol boundary:
every provisional coin stores the anchor's consensus bytes. Receive, restore,
local-change, proof, batch, reorg, freeze, and SQLite-finality paths explicitly
convert at their boundary. A proof job records the real time at which each
exact parent was observed. Signing may reuse only that receipt and only while
it is no older than the strictest enabled raw-transaction observer's configured
maximum age (120 seconds for the signet defaults). A stale or absent receipt
performs the network lookup again and fails closed if the exact parent is no
longer available. The fee UTXO remains independently CBF-reverified at signing;
the recently-spent-funding regression still requires and observes both verifier
calls.

Regression receipts prove consensus-byte round-trip, display-txid finality
freeze, fresh-receipt reuse without a second network request, and mandatory
network re-observation after 121 seconds. The complete default FFI target passes
57 unit tests plus 2 integration tests with 2 deliberate slow-test ignores and
zero failures. The recovery-feature target passes 59 unit tests plus 2
integration tests with the same 2 deliberate ignores and zero failures.

Carol's durable attachment retry also ran twice without a restart-only gap. It
remained uncredited because the local network could not establish TCP to any
`mempool.space` address while Blockstream returned the exact 309-byte
transaction. This demonstrated that requiring every public observer made one
provider outage a global wallet liveness failure.

The owner selected an availability quorum: Signal still queries both pinned
APIs and persists every success and failure, but one fresh pinned observer must
return the exact transaction bytes. Zero matching observers still fail closed;
stale evidence, pin mismatch, wrong bytes, cryptographic proof failure,
transaction-layout failure, and protocol-context failure do not count toward
the quorum. Confirmation and settlement still require the phone-owned
headers/BIP158/full-block/Merkle path. Focused regressions prove Blockstream-only
success at quorum one, failure for the same evidence at quorum two, survival of
one provider's pin or byte failure when the other succeeds, failure when both
are invalid, and rejection of configurations whose quorum exceeds their
required candidates. Live Carol acceptance and the zero-confirmation return hop
remain acceptance gates rather than claims in this entry.

## 2026-08-07 — rollback spend preflight and terminal batch state

A read-only APFS simulator snapshot reproduced a second rollback class that
normal operation-journal replay cannot repair: the restored checkpoint itself
predated a confirmed spend. The phone-owned PoW/BIP158 scan index already
recorded the exact selected input's first occurrence at signet height 316656,
transaction position 43. The private raw nullifier is intentionally omitted
from this receipt.

Four diagnostic retries ran through an older linked framework before the
actual CocoaPods XCFramework input path was identified. They created Bitcoin
transactions
`b50e442447d8e8641bb533dbc197f2ac52a7edb155465e535dc0bc858bf8a007`,
`fd4e1b1a85c6d4cd9ce5ab3e64b89beb5c2ded373d5565100180b6ef80d0e236`,
`faf9c3e69378aa0cf2ae93abe2df8ad79e486e6c0d416a90bff49384f7ea3042`,
and
`ad451a80afcc4e99abb7b8d21aec3269611d5673cab2fae12b8b8076dd2d17f4`.
Those are failed rollback diagnostics, not valid OpenCSV payment receipts:
each reused the already-confirmed protocol nullifier and must never appear in
product performance or payment evidence.

The accepted gate derives the exact selected input nullifiers inside Rust and
compares them with the registered confirmed-chain index before recursive
proving, after proof import, and immediately before signing. It is mandatory
on signet and mainnet and is deliberately independent of the configurable
Off/Observe/Require API-observation policy. The raw nullifiers never cross FFI
or leave the device. A missing or stale scan fails closed as
`stale_chain_state` rather than blessing a rollback-created duplicate spend.

Pre-broadcast failure now cancels the complete enclosing batch, including the
one-member `solo` representation, and preserves the member's stable rejection
reason. This prevents Signal from treating a cancelled operation inside an
orphaned resumable batch as permanently pending.

The exact signed simulator build linked archive SHA-256
`16601bcfd715ff9d98a058d1847cf4403ffc67366388f23d4df0b76d5fd282b6`.
Against the restored database SHA-256
`16231b2d71003dbe64b4d0702575b846e2b963f2308995a6898735a96b5fc0eb`,
operation `a05bed708749b0559aba3a7cf27a0cf3` failed in three seconds with
`stale_chain_state`. Both operation and batch became `cancelled`; no pending
proof, signed transaction, or txid was written, and Signal emitted a terminal
failure message after the nonspendable intent.

The complete default FFI target passes 61 unit tests plus 2 integration tests,
with 2 deliberate proof benchmarks ignored and zero failures. The recovery
feature passes 63 unit tests plus the same 2 integration tests, with 2 ignored
and zero failures. The warnings-as-errors Signal simulator build also passes.

## 2026-08-07 — Secure Backup export races with unrelated wallet progress

The first live two-recipient Signal batch reached `proof_ready` with two
durable members, then remained unsigned while Signal completed its mandatory
manual Secure Backup export. The export itself succeeded, but an unrelated
receive/finality refresh advanced the wallet checkpoint while the encrypted
archive was uploading. Rust consequently rejected the hash of the checkpoint
that Signal had actually staged and uploaded because it was no longer the
wallet's newest hash. Repeating a complete remote backup until no background
state changed is not a bounded or useful signing protocol.

The accepted invariant is tied to the exported payload rather than wall-clock
recency. While the operation or complete batch remains exactly `proof_ready`,
Rust may acknowledge either its exact prepared checkpoint hash or the exact
current checkpoint hash. Any unrelated older hash still fails closed. The
acknowledgement transaction changes only backup metadata; request bytes,
funding reservation, proposal, manifest, proofs, member ordering, and
nullifiers remain frozen. This preserves the recovery boundary represented by
the completed Signal export without forcing proof regeneration or an
unbounded backup retry when later recoverable wallet state arrives.

Focused regressions cover both solo and multi-recipient operations: unrelated
wallet progress changes the current hash, an arbitrary hash is rejected, the
exact staged hash acknowledges every member, proof material and transaction
inputs remain unchanged, and the newer local checkpoint remains current. Live
Carol batch completion remains an acceptance gate rather than a claim in this
entry.

## 2026-08-07 — zero-confirmation receiver learns the exact batch envelope

Carol's first explicit two-recipient send survived deliberate crashes after
proof generation and after broadcast, then reached the mempool as one exact
transaction. Bob downloaded his consignment and both pinned observers returned
matching raw bytes, but the receive verifier rejected the anchor with `anchor
must have record, marker, and change outputs`. The failure was honest but
incorrect: the provisional snapshot builder still required the three-output
solo layout and discarded the input-0 witness envelope that makes a batch
nullifier occurrence verifiable.

The accepted boundary now distinguishes the record class before constructing a
provisional snapshot. Solo anchors retain their exact three-output validation.
A batching-v2 anchor must have the committed participant/input/output counts,
canonical RBF sequences, a canonical `OCS2` input-0 envelope, a header that
recomputes from that envelope and the input-0 context, the exact marker, a
stock output locked to the revealed stock witness script, and one non-dust
P2WPKH change output per participant. The exact envelope is retained only in
the in-memory/provisional snapshot derived from observer-matched transaction
bytes; settled CBF verification continues to read witness data from the
independently fetched full block.

Snapshot occurrence checks now validate the versioned envelope commitment
before matching a private nullifier. A forged, missing, reordered, wrong-domain,
or header-mismatched envelope fails closed. Focused tests cover valid batch
occurrence, unrelated nullifiers, mismatched envelopes, exact v2 layout, layout
mutation, and unchanged solo behavior. The complete warnings-as-errors FFI
library suite passes 64 tests with zero failures and two deliberately ignored
slow proof cases. Live recipient credit and duplicate-delivery checks remain
acceptance gates rather than claims in this entry.

## 2026-08-07 — batch acceptance projects the committed member proof

After the provisional parser learned the exact batching-v2 layout, Bob retried
Carol's real two-recipient transaction
`771aefc62e38dae80b4fdeec5ebb183c5c4c53c7902b559991aa55679103c4c3`.
The witness envelope and both pinned raw-transaction observations succeeded,
but the recipient rejected the consignment as `InvalidProof`. This exposed a
second independent receiver bug: `Accept` reconstructed the recursive proof's
public input from the on-chain batch header. The sender had correctly authored
each member proof against that member's single-XFER record, while the header
commits to the complete envelope and is not itself any member's proof
statement.

The rejected approach was to weaken proof verification or special-case
`InvalidProof`. The accepted boundary instead gives an `AnchorChain` an
explicit fail-closed member-projection operation. Snapshot and verified CBF
backends first prove that the consignment's private raw nullifier selects an
exact payload in the versioned envelope committed by the batch header. Only
then do they reconstruct the canonical single-XFER record used by the proof.
A backend that discarded or cannot authenticate the envelope returns no proof
record and the consignment is rejected as an ill-formed anchor. First-
occurrence checks now also apply to the selected batch member's raw nullifier,
preserving the solo-transfer exclusion rule.

Focused regressions cover exact member projection, receiver acceptance against
the projected statement, an unknown member failing closed, a header/envelope
mismatch, and unchanged solo behavior. The complete warnings-as-errors FFI
library suite passes 65 tests with two deliberate slow-proof cases ignored;
the DEBUG recovery-feature suite passes 67 with the same two ignored. A live
recipient retry and duplicate-delivery check remain acceptance gates rather
than claims in this entry.

## 2026-08-07 — chain views use the unified account identity

The next Bob retry passed the corrected batch-proof check and then failed at
the ownership step with `NoOwnedOutput`. The attachment did contain the owner
address Carol selected for Bob. The mismatch came from Signal's read-only
self-scan and cross-check preflight still using the retired prototype wallet's
independent owner seed, while sending and durable crediting had already moved
to the Rust-owned account wallet. A correct payment was therefore tested
against an unrelated public owner before the account wallet could see it.

The product chain-view path now calls the account-scoped scan and cross-check
FFI boundaries, which keep the account's private owner material inside Rust.
The legacy wallet overloads remain only for compatibility tests and old state;
they are not used to decide current account payments. Cross-check tip
disagreement retains its structured tips and remains a hard failure.

Confirmed batching-v2 credits also need the exact envelope after the read-only
scan accepts them. The CBF snapshot export now includes one deduplicated batch
entry with the exact version and full payload envelope recovered from the
independently fetched block. The account's snapshot verifier revalidates that
envelope against the header before projecting any member proof. It never
accepts a header-only batch record.

Stored verdict version 3 creates a bounded repair path: pre-version-2
`InvalidProof` and pre-version-3 `NoOwnedOutput` results are retried once under
the corrected verifier. Current invalid proofs and genuinely third-party
outputs remain final instead of replaying on every activation. Focused tests
cover the exact exported envelope, transaction-level deduplication, structured
tip disagreement, and version-scoped verdict retry. Live credit and duplicate
delivery remain acceptance gates rather than claims in this entry. The full
warnings-as-errors FFI library suite passes 67 tests with two deliberate slow
proof cases ignored; the DEBUG recovery-feature suite passes 69 with the same
two ignored.

## 2026-08-07 — live batch, fee replacement, and one logical payment

The Bob/Carol acceptance run completed one real two-recipient signet batch.
Carol authored Bob operation `afcaa691e4a0adb3cfd24a6f986400d0` and her
Note-to-Self operation `bc1850940e9e8f2c3af747aa60852725` under batch
`c3d0260082cea04e98a1a56d9e7713fb`. Both consignments share transaction
`771aefc62e38dae80b4fdeec5ebb183c5c4c53c7902b559991aa55679103c4c3` with
their exact envelope positions. Three Bitcoin peers recorded complete
transaction-submission writes; this is not claimed as mempool acceptance.
the two pinned raw-byte observers matched in 271 ms and 354 ms. Deliberate
relaunches after proof and broadcast resumed the same operation ids. The
transaction later settled at signet height 316687, Bob credited exactly 5 Test
USD, Carol credited her self output once, and repeated relaunches kept the
stored consignment counts stable.

A separate 1 Test USD Bob-to-Carol operation
`3d2210aeda489dfa33acbb00c92951b1` exercised fee replacement. Its 2 sat/vB
transaction `cb32fa1048b83d479fadf4aaa6160664e61170e95036ab5d4d3d57bdd0d98fd5`
was replaced at 5 sat/vB by
`4ae0f1c686977cfb270e94dc834043d4609283781b27e3bb47f222dde6cbd7f7`.
The funding input, record, marker, change destination, protocol context, and
output positions remained unchanged; the old transaction disappeared from
both public observers and the replacement remained visible. Carol's ledger
balance moved from 131 to 132, proving there was no double credit.

The first delivery implementation nevertheless exposed two transport bugs.
It reused the attachment acknowledgement nonce, so Signal suppressed the
replacement; rotating the nonce atomically with the replacement fixed exact-
once redelivery and rejects a stale acknowledgement. Once delivered, Signal
rendered both canonical consignments as two +1 bubbles even though Rust's coin
state correctly recognized one payment. Hiding one based on message text was
rejected: transport metadata is not a protocol fact. Rust now derives a
domain-separated logical payment id from the canonical proof-protected
consignment fields after zeroing only the replaceable anchor txid. A verified
replacement returns that id plus matching prior verified consignment ids.
Signal can therefore supersede the old bubble and activity row using
cryptographic bytes, while retaining both attachments as receipts. Tests show
the id survives anchor replacement, changes when protected proof bytes change,
discovers the predecessor in the verified-consignment database, and supports
repeated fee bumps after observation, delivery, and reopen.

## 2026-08-11 — addendum: raw-observer availability quorum reversed

The 2026-08-07 availability quorum (one fresh pinned observer must return the
exact transaction bytes) is reversed by same-day commit cd1e678 ("Require
every configured raw observer"). `required_raw_observer_quorum` is now derived
as every raw observer marked `require`, and an explicit value must match that
count, so `require` can never silently mean an optional member of a smaller
quorum. The signet defaults again require both pinned API observers to return
the exact transaction bytes under their configured certificate pins
(regression: `fresh_signet_defaults_require_both_pinned_api_observers`).

The reversal is fail-closed: under a one-of-N quorum a single observer's
matching bytes satisfied zero-confirmation acceptance while the other
observer's pin, byte, or availability failure was only persisted, so one
compromised or malfunctioning provider could vouch unchallenged. Requiring
every configured observer means any pin mismatch, wrong bytes, or outage
blocks zero-confirmation acceptance. The cost is the liveness coupling the
quorum was introduced to avoid: one provider outage again blocks
zero-confirmation acceptance wallet-wide until the observer recovers or the
configuration changes. Confirmation and settlement are unaffected; they still
require the phone-owned headers/BIP158/full-block/Merkle path.

## 2026-08-11 — Test USD v1 retired; canonical v2 starts clean

The canonical field-decoding audit found that historical coin randomness was
created as unrestricted 32-byte data while the current proof boundary accepts
only eight canonical BabyBear limbs. Most v1 openings therefore cannot be
decoded by the strict representation, and silently reducing them modulo the
field would make multiple byte strings denote the same value. The rejected
approaches were global permissive decoding and a best-effort in-place wallet
migration: both would preserve an ambiguous identity boundary and make
different components disagree about hashes and equality.

The accepted decision is a clean Test USD v2 application deployment on the
existing Bitcoin Signet. Config generation 2, deployment id
`opencsv-test-usd-v2`, checkpoint version 4, version-2 derivation domains, a
fresh BIP84 tree, owner, asset manifest/id, database, and backup namespace form
one fail-closed boundary. Pre-v2 configs, unnamespaced databases, and checkpoint
versions 1–3 return `testnet_reset_required`; there is no automatic migration.
V1 transactions and media remain archived receipts and are never relabeled as
v2 evidence.

The first canonical generator reduced uniform `u32` values modulo `p`. That
made every output valid but not uniform because `p` does not divide `2^32`:
some field elements had three preimages and others two. It was rejected before
the v2 launch. The accepted core generator rejection-samples each limb below
`p`; CLI and FFI share that one implementation, and a serialization regression
checks 1,024 fresh digests.

The same review found that the demo HTTP client's advertised 120-second
timeout was independently applied to DNS, every resolved address, and each
blocking I/O call. A slow resolver or byte-drip response could therefore exceed
the stated bound. DNS, all connection attempts, the request write, and the
bounded response read now spend from one monotonic deadline. A regression
server that continuously drips bytes proves the complete request still exits
at the shared deadline.

## 2026-08-11 — receiver admission precedes chain synchronization

The first live v2 install preserved Signal message history as intended, but
its startup sweep presented archived v1 consignment attachments as payments
that were still verifying. The receiver tried to locate each old anchor before
checking whether the recipient openings belonged to Signal's exact reviewed
Test USD v2 issuer registry. An absent historical anchor therefore looked like
transient chain lag and could retry indefinitely.

Treating every verification exception as terminal was rejected because pinned
observer outages, an advancing compact-filter tip, and unsettled SPV evidence
are genuinely retryable. Editing the simulator database or hiding old messages
by timestamp was also rejected: neither proves what protocol bytes the
attachment contains, and either would make the acceptance media depend on
non-reproducible local cleanup.

The existing read-only consignment inspection now reports its distinct public
asset ids, the unreviewed subset, and stable `asset_not_reviewed` admission
result using the same exact manifest-derived predicate enforced at transfer
planning and signing. Signal can make that local decision before any network
work. The attachment and its receipt remain visible and nonspendable, while no
v1 asset or balance is imported or relabeled as v2. A focused test covers both
an exact reviewed instrument and a mixed reviewed/unreviewed consignment; the
warnings-denied default FFI suite passes 76 tests and the recovery-feature
suite passes 78, with the repository's three slow recursive-proof cases still
explicitly ignored.

## 2026-08-12 — cached send raced mandatory chain verification

The first fresh Test USD v2 Carol-to-Bob acceptance attempt used merged Signal
tip `784b0122445bf9f92e0a11a5587a419500f98868` and Rust tip
`f582c118721f679b84870e55271f4723d7e1cac6`. Signal durably announced 25 Test
USD as operation `dbfeed5be1f83f94e662947bdb07137d` in solo batch
`15316e14d8aa5746adc906f220947a84`, reserved the confirmed fee outpoint, and
survived a deliberate app termination at `fee_reserved` with the same
operation id. On relaunch the proof boundary returned `stale_chain_state` and
the old failure policy cancelled both operation and batch. No proof, signed
transaction, txid, broadcast, or asset spend was written. The failed intent
remains visible as a receipt and is not acceptance footage.

Code inspection found the race that makes this outcome possible. The send
sheet correctly renders cached balances immediately and starts the phone-owned
compact-filter scan concurrently, but background proving could begin before
that scan registered or caught up. The Rust boundary then used the same
terminal code for (a) unavailable peers or a missing/behind scan and (b) a
verified contradiction such as an already-spent input. Failing closed was
correct; destroying the resumable proposal for temporary unavailability was
not.

The replacement policy distinguishes disposition without weakening any
verification. Peer, filter-scan, and unconfirmed-parent transport outages now
return stable `chain_verification_unavailable` (or the existing dependency
code) with `retryable: true`. A retryable proof failure clears only the active
proof lease, preserves the exact operation id, fee reservation, solo/frozen
batch, and unsigned state, and records the error in the durable receipt. A
later call retries the same proposal. Verified spend, output mismatch,
rollback, proof, layout, or policy failures remain terminal and cancel the
complete unsigned batch; neither class may sign without fresh mandatory
evidence. Signal separately waits for a successful compact-filter scan before
starting solo or multi-recipient proof work, while keeping the already-posted
pending chat entry visible during catch-up.

Focused tests prove that a retryable outage retains one locked outpoint and
one operation across re-entry, that a verified conflict still cancels the solo
operation and its enclosing batch, and that a frozen multi-recipient batch is
preserved only for retryable verification outages. The complete default FFI
unit suite passes 79 tests with three deliberate slow recursive-proof cases
ignored and zero failures.
The explicitly opt-in release-mode reopen-and-resume proof test also passes;
after its one-time optimized/LTO build, the test completes the resumed proof in
10.32 seconds on this Mac. That is a development-host recovery receipt, not an
iPhone product-performance claim.

## 2026-08-13 — reserve maintenance needs its own constrained RBF

Carol's count-2 batching reserve transaction
`9f13165553241f8a7af472429c97e2c41d65dfbd8cf3c93eb91158474de0f3f9`
remained unconfirmed while Signet advanced. Its 985-sat fee over 492 vbytes is
about 2 sat/vB, while Blockstream's public Signet mempool reported roughly
36 MB queued and a broad 3 sat/vB band ahead of it. Rebroadcasting the same
bytes could not change that ordering, and using a generic Bitcoin wallet bump
would violate the rule that OpenCSV alone controls fee spending and output
layout.

Reserve maintenance now has a dedicated action keyed only by its durable
maintenance id and a target feerate. Rust reconstructs the exact persisted
transaction, forbids added or reordered inputs, freezes every stock and fee-cell
output byte-for-byte, preserves version and locktime, and permits only the
final wallet-change value to decrease. It commits the signed replacement and
atomically remaps all pending stock rows to the replacement txid before any
relay. A crash after that commit resumes the same bytes; the old observation
receipts remain historical evidence and cannot certify the replacement.

The new regression proves the protected layout, increased fee, txid remap,
and reopen recovery. The complete default FFI run passes 85 unit tests plus
two integration tests, with three deliberate slow recursive-proof cases
ignored and zero failures.

## 2026-08-13 — headless issuance needs an explicit confirmed-SPV recovery command

The live `[50, 50]` Test USD issuance reached `broadcast_unobserved` with an
exact persisted transaction, three P2P submissions, and an independently
retrieved Blockstream copy. The configured mempool.space Signet endpoint was
unreachable from the development host, so the required two-observer policy
correctly refused zero-confirmation delivery. The Rust account wallet already
had a stronger recovery path: `refresh_operation_spv` verifies the exact
transaction through multi-peer header agreement, PoW, BIP158 discovery, full
block retrieval, Merkle inclusion, and OpenCSV record validation. Signal could
invoke that boundary, but the headless issuer CLI could not.

`opencsv-issuer operation refresh-spv --operation-id ID --scan-config
scan.json` now exposes that existing verifier without accepting raw
transaction bytes, a block height, or a caller-supplied success Boolean. A
first live attempt that omitted scan registration failed honestly with `no
scan registered`; the final command therefore requires an explicit scan
configuration, syncs/registers its persistent cache in the same process, and
returns that sync receipt alongside the operation receipt. Before confirmation
it returns the honest unsettled scan result. After confirmation it can finalize
the exact durable proof and make the canonical consignment delivery-ready even
when a public unconfirmed observer is unavailable. This does not downgrade the
default two-observer zero-confirmation policy; it provides the independently
verified confirmed-chain alternative already present at the Rust boundary.

The first registered live scan then rejected the confirmed mint with
`NoOwnedOutput`. That exposed a second incorrect reuse: receiver acceptance
derives its owner set from locally held secrets, but an issuer minting both
outputs to Carol correctly holds none of Carol's secrets. Core verification
now has a public-owner entry point with identical proof, anchor,
confirmation, binding, occurrence, and pure-kernel decisions. The issuer path
feeds it only the recipient owner authenticated by the durable mint request;
it neither trusts an owner supplied by the consignment nor credits the issuer
with Carol's coins. Secret-based receiver acceptance remains a wrapper over
the same decision path.

The corrected headless path was then exercised against the live Signet mint
operation `06232685d70a6cfd844927638339a9b5`. The compact-filter scan reached
height 317580 and independently finalized transaction
`79479eeda1a372dd83fed7deb1722eee1878f63ea7a508cb5e29023a62925906`,
confirmed at height 317579. The durable operation advanced to `confirmed`,
its delivery receipt became ready, and the exported 537,303-byte consignment
has id `4e916bdc96e21a7e8f0942d50779c0f186cb005bb2a86614056ce7faa29bd566`.
The receipt records 575 ms for the final SPV confirmation refresh. This is a
real confirmed-chain recovery receipt; it is not a substitute for the two
required raw observers used to unlock zero-confirmation forwarding.

## 2026-08-14 — adversarial closure keeps contradictions and replacement history explicit

The release review identified three seams where the implementation was safe
but its evidence was either ambiguous or only one epoch deep. First, a pinned
required observer returning a different, well-formed Bitcoin transaction was
reported as the generic `required_observation_failed` quorum result. That hid
the difference between an outage and direct contradictory bytes. The account
boundary now returns stable `observer_transaction_conflict` for that case,
while malformed bytes, missing evidence, stale cache data, and ordinary quorum
loss retain their existing reasons. The durable per-observer receipt still
records the exact-byte mismatch and the conflicting check identifier.

Second, reserve-maintenance RBF had a complete candidate list but its test
proved only one replacement. The focused regression now performs two fee
bumps, proves that the second increment is calculated from the current fee,
that every earlier exact signed transaction remains in order as a recovery
candidate, that protected stock outputs remain byte-identical, and that only
the latest txid owns the pending stock rows after reopen.

Third, compact-filter reorg coverage proved orphan pruning but stopped before
a replacement occurrence became the settlement-of-record. The strengthened
test now begins with an accepted anchor, rolls it off at a common ancestor,
proves that lookup, occurrence, and scan decisions forget it, installs the
same nullifier on the canonical fork at a new location, persists and reopens
the index, and checks the new confirmation depth. These are focused local
receipts; hosted CI and independent review remain separate release gates.
