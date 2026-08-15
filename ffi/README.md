# opencsv-ffi

C ABI for embedding the OpenCSV wallet in native apps (iOS-first). All
protocol logic stays in Rust over `opencsv-core` / `opencsv-pcd`. The preferred
Signal boundary is the persistent `opencsv_account_*` API documented in
`../SIGNAL_ACCOUNT_WALLET.md`: Rust owns keys, asset/Bitcoin coin selection,
reservations, proofs, signing, P2P relay, and crash recovery while Swift sends
action intent. Full ABI contract is in `src/lib.rs` and `include/opencsv.h`.
The interactive send path journals through `opencsv_transfer_plan` and returns
to Signal immediately; `opencsv_operation_prove` advances that exact id in a
resumable background pass. Only proof-ready operations may be signed, so fast
pending presentation never weakens double-spend or lineage checks.
Mandatory peer or local-scan unavailability returns
`{"reason":"chain_verification_unavailable","retryable":true,...}` and keeps
the exact planned/fee-reserved operation and Bitcoin lock durable. Verified
conflicts and stale-state contradictions return `"retryable":false` and close
the complete unsigned solo or frozen batch.

## Production activation boundary

Opening and synchronizing a mainnet account does not activate a product. A
mainnet account is read-only until its configuration contains a versioned,
deployment-bound production registry release with at least one fully
validated, non-test `USD` issuer manifest. Loose top-level `usd_issuers` are
rejected on mainnet. The registry commitment covers its encoding and policy
version, deployment, exact ordered manifest set, source revision, and public
approval receipts. It also commits a `candidate`, `limited`, or `general`
activation phase plus the exact per-transfer, per-batch, rolling-day,
recipient-count, reserve-allocation, and miner-fee ceilings; status exposes
that identity and rollout envelope for independent receipts. A candidate
release is intentionally reviewable but returns
`production_activation_not_authorized` for every fresh Bitcoin write.
Limited and general releases remain bounded by the committed ceilings at
intent creation and again before proof/signing, so application configuration
cannot raise them. Cancelled or protocol-rejected intents stop consuming the
rolling-day allowance; live and completed intents continue to count.
When exact transaction bytes are signed and persisted, their receipt snapshots
the authorizing registry version, commitment, rollout, and miner-fee ceiling.
Rust signs that snapshot with a deployment-separated wallet key over the stable
solo, batch, or reserve operation identity. A missing snapshot, self-consistent
substitution, or cross-operation copy is database corruption. A later registry
change therefore cannot raise that operation's RBF exposure or strand its
protocol-safe recovery by lowering the current ceiling.
Until a valid nonempty release is present, status returns
`write_block_reason: "production_usd_not_configured"`, and every new consumer
transfer, batch, proof, signing, and wallet-internal reserve-split path fails
with that stable reason before selecting Bitcoin inputs.

The database stores the highest registry version and its exact commitment as
one atomic floor, and production Secure Backup checkpoints carry the same
floor. Reopening or restoring with an older valid release remains readable but
returns `production_registry_rollback`; reusing one version with different
committed bytes returns `production_registry_conflict`. Neither case hides
balance/history/evidence, and neither can create a new unsigned Bitcoin write.
An authenticated higher version advances the floor, including an empty
emergency-freeze release.

The opt-in, secret-free registry operator uses the same canonical serializer,
manifest checks, rollout validation, and commitment verifier as account open:

```sh
cargo run -p opencsv-ffi --features registry-tools --bin opencsv-registry -- \
  build --input ffi/examples/production_registry_candidate_draft.json \
  --output candidate-release.json
cargo run -p opencsv-ffi --features registry-tools --bin opencsv-registry -- \
  verify --input candidate-release.json \
  --expected-deployment opencsv-mainnet-candidate-v1
```

Build input must omit `commitment_sha256`; a supplied value is rejected rather
than silently replaced. Output uses create-new semantics and is never
overwritten. The checked-in draft has no issuers, a placeholder source
revision, and candidate phase, so it cannot activate a production product.
Verification requires the deployment expected by the containing application;
a structurally valid release for another deployment fails closed. Limited and
general releases additionally require at least one exact issuer and reject the
all-zero placeholder source revision.

Production accounts use the deployment-scoped
`opencsv-mainnet-account-v1` key-derivation namespace. Signet/regtest retain
the exact `opencsv-account-v2` derivation for Test USD compatibility; a
pre-v1 mainnet database or checkpoint is archived rather than guessed into
the production namespace. Removing an issuer stops unsigned consumer work,
but an exact transaction already signed and persisted can still resume and
use its protocol-safe fee-bump path. Opt-in headless issuer tooling keeps its
separate backup/device gate and remains absent from Signal's default binary.
Test USD keeps the existing signet/regtest `usd_issuers` configuration and
refuses a production registry release, so neither registry format can be
silently interpreted on the other network.

Fresh mainnet accounts also inherit the same fail-closed observation shape as
Test USD: exact transaction bytes from both immutable, pinned mempool.space
and Blockstream endpoints, direct P2P relay evidence, and confirmed-chain SPV.
Production may replace the built-ins with independently hosted pinned
observers, but two distinct required raw endpoints, non-disabled direct relay,
non-disabled SPV, and two distinct configured compact-filter peers are a
second activation gate. A downgraded policy keeps the account readable and
returns
`production_observation_policy_required` before any new Bitcoin write.

The older in-memory compatibility model is retained temporarily:
`opencsv_wallet_create` returns a small secrets
JSON the host keeps in its keystore (iOS Keychain) and passes back to
`opencsv_wallet_open`; coins are rebuilt at open by replaying verified
consignment blobs through `opencsv_verify_consignment` (milliseconds each)
and re-marking spends. Chain-dependent calls take an *anchor snapshot* JSON
(`src/snapshot.rs`) so the phone never talks to a node. Producing a
transaction is two-phase: `opencsv_prove_*` returns a 64-byte anchor record
plus the 32-byte transaction context `ctx` it is bound to (the record's
nullifier payloads are `H("bind" ∥ raw_nf ∥ ctx)`), to publish together
(e.g. to `opencsv-anchor-server`), and
`opencsv_consignment_finalize` builds the consignment blob once the host
knows where it anchored. A consignment finalized before the anchor's mined
position is known carries the mempool sentinel location `(0, 0)`: the
snapshot chain resolves such references by transaction id (the same
contract as `opencsv-bitcoin`'s backend), while explicitly claimed
locations are matched strictly. Between the two phases the pending transaction
lives only in memory; `opencsv_pending_export` / `opencsv_pending_import`
persist it (proof, openings with their fresh randomness, aux, spend list)
across the broadcast→finalize window, closing the crash-loses-consignment gap.
Its anchor-server examples are compatibility documentation, not the target
Signal send architecture.

Verification `credits` are descriptive accepted-payment totals, not an
accounting delta: replaying a consignment can return the same totals even
though Rust stores its coins idempotently. Persistent-account hosts must key
durable presentation and accounting by the returned stable `payment_id` and
must never sum `credits` across verification retries. The legacy in-memory
entry point does not expose a stable logical-payment identity and should not
be used for new host integrations.

Beyond the wallet core, three host-facing verification surfaces:

- `opencsv_cbf_sync` / `opencsv_cbf_verify_anchor` — trustless anchor
  point verification over BIP157/158 P2P (`opencsv-cbf`), config JSON in,
  verdict JSON out;
- `opencsv_cross_check` — N-of-M exclusion (paper §4.7.1): build an
  `opencsv-core` `CrossCheckedChain` from a JSON list of backend specs
  (`bitcoind` RPC indexer / `http` anchor-server / inline `snapshot`)
  and run the accept driver over a received consignment; tip
  disagreement between backends is a hard error
  (`{"kind":"tip_disagreement"}`), never a silent pick;
- `opencsv_scan_sync` / `opencsv_scan_check` / `opencsv_scan_verify` —
  the self-scan-first default: `opencsv-cbf`'s `ScanIndex` walks BIP158
  filters for the protocol marker output and SPV-fetches matching
  blocks into a persistent occurrence index; occurrence checks and
  `accept()` then run fully local (read-only);
- `opencsv_scan_export_snapshot` — exports the registered scan index as
  an anchor-snapshot JSON (the exact shape `opencsv_verify_consignment`
  consumes), so consignments are credited serverlessly: every entry was
  SPV-fetched and PoW-verified by the scan. `tip_height` is the synced
  tip at call time; with no registered scan it returns
  `{"error":"no scan registered; call opencsv_scan_sync first"}`.

## Build

```sh
cargo test -p opencsv-ffi                 # includes a C-ABI mint→verify round trip
apple/build-xcframework.sh                # OpenCsv.xcframework (device + Simulator)
```
