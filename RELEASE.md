# Reproducible reference release checklist

This checklist packages evidence; it does not authorize publication or a
mainnet broadcast. Every checkbox must have a linked CI artifact, command log,
or transaction receipt. Owner approval is required where stated.

## Source and toolchain

- [ ] Release commit is reviewed, signed/tagged deliberately, and contains no
  uncommitted changes.
- [ ] `Cargo.lock` is committed and every Cargo command uses `--locked`.
- [ ] `rust-toolchain.toml` resolves Rust 1.97.1 with the recorded host target.
- [ ] `protoc --version`, host OS/architecture, source commit, and
  `SOURCE_DATE_EPOCH` are captured in provenance.
- [ ] `scripts/reproducible-build.sh --verify <output>` builds both CLI feature
  configurations twice and byte-compares each pair.
- [ ] SHA-256 sums and provenance are attached to the candidate release.

## Protocol gates

- [ ] Kernel differential/equivalence tests and the pure accept-decision suite
  pass with warnings denied.
- [ ] Proof setup cold/warm/invalidation/concurrency tests pass.
- [ ] Wrong verification key, issuer forgery/wrong-key/tampering, parameter
  mismatch, proof-version mismatch, and security-floor rejection tests pass.
- [ ] Batching v2 adversarial mutation, replay, abort, fee/output tampering,
  replacement, crash-journal, and multi-party regtest tests pass.
- [ ] New anchors use only the unspendable `sha256(OP_RETURN)` marker; scanners
  read protocol-v2's historical `sha256(OP_TRUE)` marker without recreating
  or replacing it; new batch creation emits protocol version 3.
- [x] Solo fee replacement passes `validate_solo_anchor_replacement` before
  signing and broadcast; no generic wallet `bumpfee` path is reachable.
- [ ] Both default and `--no-default-features` CLI configurations pass with
  warnings denied.
- [ ] Formal build and axiom/honesty artifacts are green at their pinned
  source revisions.

## Network and recovery gates

- [x] Two or more diverse compact-filter peers independently agree on signet
  header tip/hash/work and the complete filter-hash chain.
- [x] Cold, restart, same-session, bandwidth, scan, and cache-recovery receipts
  are attached and match `SIGNET_READINESS.md` or a newer dated run.
- [x] A dedicated signet wallet completes anchor, mempool, confirmation,
  restart recovery, and a confirmed protocol-safe RBF that preserves non-dust
  change without touching another agent's wallet.
- [x] Fee and marker tables are regenerated from the executable model at the
  release-time feerate policy.
- [ ] `SECURITY_REVIEW.md` residual risks have owners or explicit accepted-risk
  decisions.

## iOS gate — final codebase

- [ ] A fresh isolated checkout is reconciled with Claude's latest branch;
  already-landed explorer/capture/persistence work is not redone.
- [ ] Rust owns keys, fee UTXOs, change, layout, journaling, signing, and RBF;
  no anchor server or arbitrary-Bitcoin-send API is reachable.
- [ ] Secure Backup enforcement, primary/linked-device permissions, in-place
  migration, replay, and both build-flag configurations pass.
- [ ] The existing `net.ultravie.signal` installation upgrades in place on the
  iPhone 16e with messages and linkage preserved.
- [ ] Physical-device mint/send/receive, post-sign crash, post-broadcast crash,
  pre-delivery crash, confirmation, and fee bump receipts are captured.

## Explicit approvals

- [ ] Owner approves upstream pull request or merge.
- [ ] Owner approves release publication and signing identity.
- [ ] An independent reviewer approves mainnet readiness.
- [ ] Owner separately approves any mainnet transaction broadcast.
