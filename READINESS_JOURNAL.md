# Signet/mainnet readiness decision journal

## 2026-08-15 — signed funding makes backup rollback non-repeatable

The authorization ledger detects replay inside one current checkpoint, but an
older authentic Secure Backup can legitimately predate a later consumed row.
Restoring that backup would recreate the earlier local supply floor. Because
the first threshold envelope did not name the Bitcoin funding input, the same
already-signed next authorization could then be paired with another fee UTXO
and produce a second mint. Hashing more ledger data into the backup was
rejected: it detects mutation, not rollback to older valid bytes.

Every production mint authorization now binds one canonical confirmed funding
outpoint in its threshold-signed digest. Planning reserves exactly that outpoint
and never falls back to another wallet coin. After an old-backup restore, replay
of an already-used authorization must therefore double-spend the same Bitcoin
outpoint; at most one branch can settle. If the authorized outpoint is absent,
spent, locked, unconfirmed, or too small, the authorization remains consumed
and the operation fails. A regression keeps another eligible UTXO in the wallet
and proves it is not selected when the signed outpoint is unavailable.

The first implementation enforced this only while planning. That was
insufficient for a tampered database or a row written by an older binary.
Pre-sign now rechecks the operation funding columns against the authorization;
signed resume and RBF additionally deserialize the persisted transaction and
require its first input to be that same outpoint. Tests mutate each boundary
independently and require `database_corrupt` before signing or relay.

## 2026-08-15 — threshold keys have one canonical text identity

An adversarial exact-tip pass found that the threshold policy parsed compressed
secp256k1 keys but deduplicated their submitted hex strings. Because hex parsing
accepts both cases, one public key could appear once in uppercase and once in
lowercase, count as two policy members, and reuse one signature under both text
aliases. That would reduce a declared two-key threshold to one signer.

Policy validation now requires the submitted key to equal the lowercase hex of
its canonical compressed serialization and deduplicates the serialized key
bytes. A focused regression presents the same key through uppercase and
lowercase aliases and requires rejection before authorization verification.
Case-insensitive comparison alone was rejected because it would leave a second
canonicalization rule beside the exact commitment encoding.

## 2026-08-15 — production supply floors are atomic, backup-carried, and replay-safe

The threshold envelope is now admitted at the issuer wallet boundary. Mainnet
mint preparation first verifies the exact v2 registry, its committed policy,
the threshold signatures, recipient, amounts, time window, and supply
transition. The operation id is the authorization digest. One immediate SQLite
transaction then creates both the planned mint and its authorization-ledger
row. Per asset, the first row must be sequence one at supply zero; every later
row must be the exact next sequence and begin at the preceding supply-after
value.

Authorization consumption at proof completion was rejected. A crash, missing
fee cell, or proof failure after approval could otherwise reuse the same
authorization against a second operation. The ledger therefore consumes the
approval at durable planning and retains it even when the operation is later
cancelled. Sequence and supply are stored as canonical zero-padded decimal u64
strings, preserving numeric ordering without truncating to SQLite i64.

Secure Backup now carries the authorization, operation link, policy
commitment, sequence, and supply transition. Restore validates the full chain,
matching mint request, signatures, release identity, and exact operation before
opening one import transaction. A missing operation, duplicate id, gap, stale
floor, mutated authorization, or locally occupied database fails before any
write. Cancelled mint operations remain in the checkpoint when their consumed
authorization establishes the supply floor.

At pre-sign, the live release and policy are checked again. The signed receipt
then snapshots the exact policy and authorization alongside the existing
wallet-signed rollout release. Resume and RBF validate the historical snapshot
and durable ledger rather than requiring the live policy to remain installed;
unsigned work does fail closed after removal. Tests cover replay, skipped
sequence, stale supply, backup round-trip, tampered backup, and signed recovery
after policy rotation. The full FFI library result is 123 passed, zero failed,
and three explicitly ignored slow release tests. The subsequent canonical-key
regression raised that result to 124 passes. The funding-bound rollback
regression makes the current exact-head result 125 passed, zero failed, and
three ignored; all three pass explicitly in release mode.

## 2026-08-15 — production issuance uses a distinct threshold authority

The consumer registry and AIR issuer key answer different questions: which
instrument a wallet may spend, and whether one protocol mint is cryptographically
valid. Neither proves that responsible operators approved expansion of real
production supply. Reusing either as the supply authority was rejected.

The new secret-free verifier defines a separately committed policy for one
deployment, exact consumer-registry version, and asset. It requires a sorted set
of distinct administrative secp256k1 keys with a threshold of at least two,
per-authorization and cumulative supply ceilings, a bounded authorization
lifetime, a policy validity window, immutable source revision, and public review
receipts. Each signed mint envelope binds the exact recipient, one or two
amounts, monotonic sequence, supply-before and supply-after values, validity
window, policy commitment, and approval receipts. Signatures are unique, sorted,
authorized, low-S, and over a domain-separated canonical digest.

The verifier takes the expected deployment, registry version, asset id, and
policy commitment as external inputs from the containing release; a mint
authorization additionally binds the final registry commitment. Trusting those
fields from the policy being checked was rejected as circular
self-authorization. One-key policies were also rejected:
the AIR issuer key already supplies single-key protocol authority, so the
administrative boundary must add independent quorum rather than rename the same
failure mode.

Five focused tests cover exact-envelope binding, threshold/duplicate/wrong-key
failures, time and supply ceilings, ambiguous policies, external release
identity, and create-versus-verify commitment behavior. At this stage the
wallet still blocked all mainnet mint preparation, signing, rebroadcast, and
RBF; the later ledger entry above records the separate activation-boundary
implementation. No real production policy or key ceremony is implied.

A follow-up caught one remaining circularity: passing the expected registry and
asset to the policy verifier did not prove that the containing release approved
that policy's key set. Production registry format version two now commits a
sorted, unique `(asset_id, policy_commitment)` list, and the verifier requires
that exact policy commitment as an external input. Every reference must name an
issuer already admitted by the same release. Version-one bytes and their golden
commitment remain unchanged and cannot carry issuance authority. Mutating a
policy reference, inventing an unknown asset, duplicating a reference, or adding
one to v1 fails closed. Creating a v2 fixture with placeholder authority keys
was rejected because reviewable format support is not evidence of an actual key
ceremony or production release.

The first policy draft also committed the registry hash while registry v2
committed the policy hash. That creates a cryptographic fixed point with no
ordinary construction procedure. The policy now binds the registry version;
the registry binds the policy commitment; and each threshold-signed mint binds
both final commitments. Keeping the two-way hash reference was rejected even
though each artifact looked independently well formed.

## 2026-08-15 — crash rebroadcast revalidates production authorization

The signed-authorization snapshot was mandatory for production fee replacement,
but the three idempotent crash-resume paths still parsed and rebroadcast their
persisted solo, shared-batch, or reserve transaction without revalidating that
snapshot. A stale signed row from a pre-gate binary could therefore reach the
network even though a missing snapshot was documented as corrupt state.

Each resume path now verifies the deployment-bound, operation-bound wallet
signature before transaction parsing, chain reconciliation, or relay. Missing,
malformed, substituted, or cross-operation authorization fails as
`database_corrupt`; signet compatibility is unchanged. Deferring the check to
RBF was rejected because ordinary idempotent rebroadcast is itself a network
write and must carry the same authorization evidence.

The reachability check then found the inverse ordering problem in RBF: all three
fee-bump paths did validate the snapshot, but only after reconstructing and
signing a replacement, and the shared/solo paths could also perform live chain
checks first. Authorization now precedes transaction parsing, chain evidence,
and replacement signing in both resume and fee bump. Validating only before
persistence was rejected because an unauthorized or corrupt row should not
exercise production keys or external dependencies at all.

## 2026-08-15 — consumer activation cannot authorize production issuance

The production registry gate covered transfers, batches, reserve maintenance,
observation policy, and signed recovery, but the opt-in issuer path still used
only the generic primary-device and backup gate. A headless mainnet operator
could therefore prepare and sign a mint without passing the product registry,
activation, or observer boundary.

Mainnet manifest construction remains available because it creates reviewable
identity bytes without touching Bitcoin. Every fresh mint preparation and
pre-broadcast signature now returns the stable
`production_issuance_not_authorized` reason. Stale mint rows from an older
binary cannot bypass the decision through resume or fee bump; read-only status,
observation, and evidence remain available. Signet/regtest issuance is
unchanged.

Adding issuance numbers to the existing registry envelope was rejected. The
headless operator supplies that file, so self-consistent caps and approval URLs
would be structurally valid but would not cryptographically authenticate who
authorized new production supply. Production minting stays disabled until the
issuer/key ceremony defines a separate authenticated authorization and supply
policy.

## 2026-08-15 — signed production recovery never falls back to live policy

The first rollout-authorization snapshot pass verified a persisted mainnet
release before fee replacement, but a receipt with the complete snapshot
removed fell back to the current host fee limit. That made absence less strict
than malformed bytes and could let damaged mainnet state recover under policy
that did not authorize the original signature.

Mainnet replacement now treats a missing signed rollout snapshot as
`database_corrupt`, just like a malformed or commitment-mismatched snapshot.
Signet receipts remain backward-compatible and may use their configured fee
limit without production metadata. Falling back to the live mainnet release
was rejected because later policy may neither raise the exposure of old signed
bytes nor retroactively stand in for their missing authorization.

A second adversarial pass then replaced the complete release and recomputed its
self-hash. Commitment consistency alone cannot authenticate which release
authorized one operation. Each mainnet snapshot is now signed by a
deployment-separated key derived inside the Rust wallet, over the release
commitment and stable solo, batch, or reserve operation identity. A
self-consistent substituted release, a snapshot copied between operations, a
missing signature, and malformed signature bytes all fail as database
corruption. Reusing the release commitment as its own authenticator was
rejected because an attacker able to rewrite the receipt can recompute an
unkeyed hash.

## 2026-08-15 — production registry bytes use one Rust implementation

The wallet could verify a production registry release, but operators had no
headless command to create the exact canonical commitment. Reimplementing the
struct serialization in a shell or documentation script would create a second
consensus surface and make a release depend on JSON key-order assumptions.

The opt-in, separately featured `opencsv-registry` binary now calls the same
pure builder and verifier as account open. Build input must omit the commitment,
output is create-new and durably synced, and verification rechecks deployment, manifests,
rollout, receipts, and the exact commitment against the operator-supplied
application deployment. The public example is deliberately
issuer-empty, candidate-only, and pinned to a placeholder revision; it cannot
arm writes. Copying the commitment algorithm into an operational script was
rejected because one byte-level implementation is easier to reproduce and
audit. CI builds the registry feature in an isolated target directory, runs its
golden and durability tests, and rejects any issuer C symbol in that artifact.
Reusing the issuer-feature build directory for the symbol check was rejected
because stale archives could produce a false result. Piping `nm` directly into
a negative grep was also rejected: an incompatible or failed inspector can look
the same as an absent symbol. CI now writes the symbol inventory first, making
inspection failure fatal before testing absence.

The public candidate intentionally has no issuer and an all-zero placeholder
revision. Those fields are useful for byte-level review but must never survive
an activation-phase edit. Limited and general registry validation now requires
at least one exact issuer and a non-placeholder revision. Relying on the later
write gate was rejected because the operator verifier should reject malformed
activation bytes before they reach a wallet.

## 2026-08-15 — production issuer policy is an exact release input

The initial mainnet gate considered any nonempty, internally valid
`usd_issuers` list to be a configured production product. That protected exact
asset selection but left the activation boundary as mutable host input: it did
not identify which registry version, source revision, or approval receipts the
application release had actually reviewed.

Mainnet now refuses loose issuer lists. Its effective policies must come from
a versioned `production_usd_registry` release bound to the exact deployment.
Rust recomputes a domain-separated SHA-256 commitment over the format and
registry versions, deployment, ordered exact manifests/priorities, source
revision, and public approval receipts. Mutated manifests, cross-deployment
releases, missing approvals, and commitment mismatches fail during account
configuration. Status publishes the exact release identity for support and
independent review. Signet/regtest keep their Test USD registry and reject the
production object.

This is deliberately not a claim that a URL or application signature proves
reserves, redemption, legal authority, or brand ownership. Those remain
external evidence gates, and no real production registry exists yet. Treating
a nonempty caller-supplied vector as equivalent to a reviewed release was
rejected.

The first release-envelope pass still treated `registry_version` as metadata.
That allowed a valid older application configuration to reopen a wallet after a
newer disable/freeze policy had been observed. The database now persists the
highest version and exact commitment as one atomic floor, and production
Secure Backup checkpoints carry it across clean restore. Older policy and
same-version/different-bytes policy remain readable but return stable
`production_registry_rollback` or `production_registry_conflict` write blocks.
Higher versions advance the floor; an older checkpoint never lowers it.
Failing account open entirely was rejected because policy rollback must not
hide balances, history, or recovery evidence.

## 2026-08-15 — production observation policy cannot silently downgrade

The first production gate made an empty mainnet issuer registry read-only, but
fresh mainnet configuration still inherited no required raw-transaction
observers. A host could therefore activate a reviewed USD product while using
only a best-effort read accelerator. That was weaker than Test USD and an
unacceptable production default.

Mainnet now installs immutable pinned mempool.space and Blockstream observers,
requires both exact byte receipts, and retains visible direct relay and
confirmed-chain SPV. Independently hosted replacements remain supported, but
new mainnet writes require two distinct pinned raw endpoints, non-disabled
relay and SPV, and two distinct configured compact-filter peers. A weaker
configuration remains readable and reports the stable
`production_observation_policy_required` reason. Treating configurable
Off/Observe/Require controls as permission for a silent production downgrade
was rejected; those controls remain useful for testnets and diagnostics.

## 2026-08-15 — production USD activation and key namespace fail closed

A readable mainnet account with a non-test deployment identifier could still
enter wallet-internal Bitcoin reserve maintenance while its reviewed USD
issuer registry was empty. Transfer selection rejected unknown assets later,
but that was not a sufficient product-activation boundary: it allowed a host
configuration mistake to create a mainnet Bitcoin write before any production
USD instrument had been reviewed.

New consumer operations now require both the existing primary/device/backup
gate and a non-empty, fully validated mainnet USD manifest registry. Status
exposes the stable `production_usd_not_configured` block reason. The gate is
intentionally not applied wholesale to every mutation. Exact signed operations
remain recoverable after a registry change, protocol-safe fee bumps may rescue
those persisted bytes, and the separately featured headless issuer tooling
retains its own custody gate. Treating registry removal as permission to strand
an already-signed transaction was rejected.

Mainnet also receives a new deployment-scoped key namespace instead of
reusing the Test USD owner, issuer, batch-stock, and account-fingerprint
derivations. Signet/regtest derivation remains byte-for-byte compatible.
Databases and Secure Backup checkpoints record the derivation identifier;
pre-v1 mainnet state is archived and requires a fresh production wallet,
while an older version-4 signet checkpoint without the new label remains
restorable. Relying on the Signal host alone to keep test and production roots
separate was rejected because the Rust custody boundary can enforce it itself.

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

## 2026-08-03 — marker migration receives an explicit protocol boundary

The readiness branch initially substituted the safe marker while retaining
C1 protocol version 2. Integration review rejected that approach because it
silently changed the already-frozen manifest and signature golden vectors.
Version 2 is now preserved byte-for-byte with its exact historical marker and
is read-only. New construction uses version 3 and requires the unspendable
marker. The decoder accepts both explicit versions, never guesses from the
script, and rejects cross-version marker substitution. Both complete vector
sets are pinned in tests.

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

## 2026-08-03 — C2 adversarial relay audit

The post-remediation audit found that historical version-2 proposal bytes were
correctly preserved and replacement-blocked but could still be admitted into a
manually assembled live relay session. That would let the old spendable marker
re-enter a new workflow. Live signing, relay admission, reopening, and index
reconstruction now require the current C1 version; version 2 remains offline
and read-only.

The listener also used a fresh socket timeout for each successful partial
read. A peer could drip bytes and retain the single reference listener longer
than the advertised bound. Prefix and body reads now share one absolute
deadline. The rejected alternative was treating per-read progress as evidence
of a healthy frame because it does not bound total resource occupancy.

Finally, the CLI relay public key is recorded as a reference TCP transport
profile, not a universal protocol identity. Signal integration must bind the
stock/fee-key-authorized C1 body to Signal's authenticated sender and operation
context rather than copying the CLI identity layer.

## 2026-08-03 — backup acknowledgement kept separate in live driver

The first acceptance-driver draft acknowledged the operation checkpoint inside
`prepare-mint`. Review rejected that shortcut because a successful function
call is not evidence that Signal Secure Backup durably accepted the bytes. The
driver now emits the prepared checkpoint and requires a separate `ack-backup`
action. Its `OPENCSV_BACKUP_VERIFIED=1` setting is labeled as an operator test
attestation only; production Secure Backup evidence remains an iOS-phase gate.

## 2026-08-03 — socket write is not mempool acceptance

The live Rust-owned anchor was written successfully to two public P2P peers,
but neither write produced timely public mempool evidence. Local Core
`testmempoolaccept` accepted the exact persisted bytes. The resume path had
only used its generic Esplora fallback when every P2P socket write failed, so
an unobserved successful write could leave a valid transaction stranded. It
now checks read-side observation after the direct retry and uses the allowed
generic relay fallback only when the transaction is still absent. The receipt
records both the resume submission count and whether that fallback was used.

## 2026-08-03 — confirmation won the first replacement race

The first Rust-owned RBF candidate was valid and persisted, but its original
anchor confirmed at height 316077 while authoritative re-verification was in
progress. The relay correctly rejected the conflicting replacement. The
journal had already pointed at the replacement and had replaced rather than
extended the original consignment receipt. The corrected path now preserves
the original receipt and, on resume, restores a confirmed original with an
explicit losing-replacement receipt. A deterministic test reproduces the
recovery without relying on timing.

## 2026-08-03 — protocol-safe account RBF accepted on signet

The second run spent confirmed Rust-owned change. Initial transaction
`ae709301…2b6c` entered mempool with record, safe marker, and change at outputs
0/1/2. Replacement `0f74a2ea…0e17` kept those protected invariants, increased
the fee by 910 sats to 5 sat/vB, retained 7,542 sats of change, and confirmed
at height 316079. Separate process invocations reopened the SQLite journal at
every state boundary. Generic Bitcoin send and raw-transaction APIs were never
introduced.

## 2026-08-14 — reorg-aware scans and reserve replacement reconciliation

Adversarial review found two places where rebuildable acceleration could be
mistaken for verified chain state. The scan index recorded only a checked tip,
so a same-height fork or tip regression could leave orphaned occurrences
contributing confirmations. Scan index v3 now stores the contiguous verified
block-hash lineage, compares the common tip on every sync, walks back to the
common ancestor when necessary, and prunes orphaned occurrences before any
new scan result is used. Older indexes rebuild rather than being guessed into
the new format.

Wallet-internal batch-reserve RBF also tracked only the newest candidate. If a
superseded split confirmed, pending stock rows could remain attached to the
losing txid. Each fee bump now retains the exact signed bytes, txid, and fee of
every superseded candidate. An Esplora status is only a height hint: every
candidate stock output must match the persisted transaction and pass the
phone-owned funding verifier before the journal can restore it. A dishonest
accelerator therefore leaves the newest candidate and stock mapping unchanged.
Reserve replacement change is additionally required to remain above the exact
script dust floor; protected outputs and ordering are still immutable.

The first remediation draft also made candidate reconciliation a prerequisite
for crash-resume. That would have let an accelerator outage prevent direct P2P
rebroadcast of the already-persisted current transaction. The final path skips
definitively rejected candidate hints, records transient reconciliation
failure, and continues the exact current-byte resume. Settlement still fails
closed until the verified-chain check succeeds.

The rejected alternative was switching candidates immediately after a public
API reported `confirmed`. That would have made an accelerator authoritative
during an RBF race. Full CBF and FFI suites passed with deterministic reorg,
original-wins, dishonest-accelerator, and dust-floor regressions.

## 2026-08-15 — bounded DNS and network-accurate recovery failures

The anchor-HTTP compatibility client already enforced one absolute request
deadline, but each lookup created a new system-resolver thread. A stalled
platform resolver could therefore strand one thread per retry even though
every caller returned on time. Resolution now goes through one process-wide
worker with one queued request. Further requests fail closed at the bounded
capacity; expired queued work is skipped. The rejected alternative was a
larger thread pool because it would only raise, rather than remove, the leak
bound under an indefinitely stalled resolver.

Secure Backup rejection also reused `testnet_reset_required` for legacy or
foreign checkpoints on every network. Signet and regtest retain that stable
reset instruction, while mainnet now returns `deployment_mismatch`; no
mainnet recovery failure tells an operator to perform a testnet reset.

Finally, FFI documentation now makes the idempotency boundary explicit:
verification `credits` describe the accepted payment and are not an accounting
delta. Persistent hosts must deduplicate retries by the stable `payment_id`.
The legacy in-memory verifier remains compatibility-only and is not a new-host
integration surface.

## 2026-08-15 — production mint admission is resumable, not reusable

The first funding-bound issuance gate atomically consumed a threshold
authorization before reserving its signed Bitcoin outpoint. That was safe
against excess issuance, but a process stop in the narrow interval left a
`planned` mint that status could display but no API could advance. Replaying
the prepare call correctly failed as an authorization replay, permanently
stranding the admitted sequence.

Mint proof construction is now a reusable internal state transition. The
issuer-only resume path advances `planned` by reserving exactly the
authorization's outpoint, advances `fee_reserved` with the existing durable
lock, and commits the original operation as `proof_ready`. If the signed
outpoint is absent, the operation stays `planned` and retryable; an unrelated
larger wallet UTXO remains untouched. The rejected alternative was allowing a
second operation to reuse the authorization, because that would weaken the
atomic sequence and supply ledger rather than repair crash availability.

The release-only two-recipient success fixture also used a random proposal
nonce and could therefore land in the intentionally rejected tagged-record
ambiguity region. That made a required receipt depend on a lucky rerun. The
fixture now uses one fixed compatible proposal nonce; the production rejection
and its adversarial coverage are unchanged, and no protocol nonce-grinding
behavior was introduced.
