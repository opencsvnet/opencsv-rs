# OpenCSV security review — signet readiness gate

Date: 2026-08-03

Scope: the staged kernel/accept boundary, proof-lineage-v3 verifier and issuer
authorization, batching v2 plus gossip, Bitcoin anchoring, and the compact
filter self-scan path. This is an internal implementation review, not an
independent third-party audit and not mainnet approval.

## Findings fixed in this gate

| ID | Severity | Finding | Resolution and receipt |
|---|---|---|---|
| SR-01 | High | Header sync mutated one shared chain sequentially. A later malicious peer could return no headers and be recorded as agreeing with the chain learned from the first peer without independently serving it. | Each peer now advances a clone of the same validated base chain. Height, tip hash, and accumulated work must all agree before one candidate is adopted. The two-peer cold signet probe independently reached height 316025. |
| SR-02 | High | A complete on-disk filter-hash cache made every peer return an empty update, so reconnect compared empty vectors and never re-attested the cached chain. Filter headers are not committed by block headers. | Every new connection re-attests the cached chain against every peer: the peer must serve the exact cached 144-block filter-hash tail plus the filter header immediately preceding it, which is re-derived from the complete local prefix, so mutating any earlier cached hash breaks the rolling SHA256d linkage short of a second preimage. Fresh installs still fetch and cross-check the complete chain; only later syncs on those same connections fetch the suffix. The initial full-chain re-fetch measured 20255556 wire bytes on reconnect and then 50 bytes for a same-session sync, which motivated bounding re-attestation to the tail. |
| SR-03 | Critical | The scan index placed `tip` before occurrence rows and used a truncating write without a checksum. A crash could preserve a high tip while losing later occurrence evidence, causing exclusion checks to skip the lost range. Unknown lines were also ignored. | Scan index v2 uses a SHA-256 checksum, strict complete decoding, range/order validation, a uniquely named temporary file, file sync, atomic rename, and parent-directory sync. Corrupt, partial, and v1 files explicitly return `RebuildRequired` and start at height zero. Unit tests corrupt a persisted index and verify rebuild behavior. |
| SR-04 | Medium | Peers were accepted after handshake without checking witness and compact-filter service bits, deferring an incompatible-peer failure into synchronization. | Handshake now requires both `NODE_WITNESS` and `NODE_COMPACT_FILTERS`. The readiness command requires at least two successfully connected peers. |
| SR-05 | Critical | The historical P2WSH marker committed to `OP_TRUE`, so any observer could spend its 546 sats and attach a non-replaceable child. External signet transaction `157e3246…b1b7` did exactly that to `e985c098…ead1`; it pinned the parent and both later confirmed in block 316031. | Protocol version 3 anchors commit to `OP_RETURN` inside P2WSH (`0020189f…57b7`), retaining BIP158 visibility while making the witness program unspendable. Version 2 retains its exact historical bytes for read-only migration but cannot be newly constructed or replaced. Unit, scanner, batching, and live signet receipts cover the transition. |
| SR-06 | High | Bitcoin Core's generic `bumpfee` is not OpenCSV-aware. On signet it replaced `db85bcbb…1e60` with `c21073b1…6b1c`, preserved record/marker, but removed change output 2 and spent all 3,086 sats as fee. | `AccountWallet::fee_bump` now performs authoritative funding re-verification, builds from the journaled transaction, validates every protected invariant before signing, persists the signed replacement before relay, and preserves the original consignment receipt. Live replacement `0f74a2ea…0e17` increased the fee by 910 sats, retained 7,542 sats of change, and confirmed at height 316079. Generic wallet fee-bump APIs remain prohibited. |
| SR-07 | High | A successful Bitcoin P2P socket write was initially treated as sufficient reason not to use the allowed generic fallback, even when no independent mempool read could observe the transaction. | Direct relay remains first. On a later resumable attempt the wallet checks independent read-side observation and uses the configured generic relay only while the persisted transaction remains absent. Receipts distinguish P2P submission count from fallback use. The final replacement reached public mempool through this path. |
| SR-08 | High | The original anchor can confirm while an RBF candidate is being independently re-verified. The single-operation journal could otherwise remain pointed at a now-invalid replacement and lose the original receipt. | Replacement receipts now extend rather than replace the original receipt. Resume detects a confirmed replaced transaction, restores its exact bytes/txid, and records the losing replacement. The first live run reproduced this race at height 316077; a deterministic unit test covers recovery. |

## Reviewed invariants

- The production verifier rejects any verification-key tag other than the
  frozen proof-lineage-v3 tag before decoding or verifying a proof.
- Issuer authorization is enforced inside the AIR through a domain-separated
  Poseidon2 commitment; wrong issuer secrets and tampered mint statements are
  covered by the prover tests.
- The production FRI profile is explicitly versioned and fails closed when a
  proof's concrete trace degrees fall below the published 94-bit
  union-adjusted floor.
- Batching v2 fixes input 0 before proof generation, requires `SIGHASH_ALL`,
  fixes record/marker/stock/change positions, returns stock principal exactly,
  allocates fees deterministically, and rejects non-unanimous replacements.
- Gossip frames are bounded, canonical, signed, content-addressed, validated
  before relay, and journaled before phase advancement. The fully signed
  transaction is persisted before broadcast.
- The compact-filter client verifies PoW/header rules and block merkle roots,
  compares independent peer results, and verifies filter bytes against the
  cross-peer filter-hash chain.
- The pure solo-anchor replacement validator permits change reduction only; it
  rejects context, record, marker, output count/order, change-destination, and
  dust mutations. The action-oriented account wallet makes this validator
  mandatory before signing or broadcast.

## Residual risks and mainnet blockers

- This is SPV, not full block validation. Correctness requires at least one
  honest, independently operated peer and protection against total eclipse.
  Duplicate resolved addresses are rejected, but that does not prove operator
  independence. A release configuration must use at least two diverse peers;
  peer discovery, rotation, and operator diversity remain deployment work.
- Reconnect now re-attests only the 144-block filter-hash tail plus the
  preceding header rather than the full chain. Earlier cached hashes are
  authenticated through the rolling SHA256d linkage, so detecting a deep cache
  mutation rests on second-preimage resistance, not on re-downloading history.
  Fresh installs still fetch and cross-check the complete chain; that
  bandwidth cost is material and must not be hidden, and checkpointing it
  safely would need an authenticated/versioned design.
- Batching gossip authenticates messages but raw TCP does not provide traffic
  confidentiality or metadata privacy. There is no global admission control,
  reputation system, or Sybil resistance.
- Coordinator and participant liveness are not guaranteed. Signed fee inputs
  remain reserved until confirmation or a confirmed conflict, by design.
- `opencsv-anchor-server` remains a development/demo crate. It is not part of
  the Signal-native wallet architecture and must not become a production trust
  dependency.
- CLI wallet files and node RPC credentials need an operator-secured host.
  The future Signal wallet must keep signing material in the Rust-owned account
  wallet and platform-protected storage.
- Public fee estimates and public P2P peers reveal network metadata. The
  production client needs a privacy disclosure and configurable/self-hosted
  endpoints.
- The safe marker burns 546 sats per anchor by design. The historical marker
  remains readable, but its spendable output can be child-pinned and must not
  be recreated. Existing historical transactions cannot be retroactively
  repaired.
- Direct P2P submission is deliberately not an acknowledgement protocol. The
  wallet requires independent read-side observation and may use the configured
  generic relay fallback from its resumable, wallet-signed operation path.
- A self-mint is not credited merely because its anchor confirms. The final
  Signal flow must supply the confirmed recipient-side chain snapshot through
  the same consignment verifier used for received attachments.
- Mainnet broadcast, release publication, and iOS rollout remain blocked on an
  independent review, reproducible release receipts, owner approval, and the
  physical iPhone acceptance sequence. The owner has deferred the independent
  adversarial review; it has not been recorded as passed.
