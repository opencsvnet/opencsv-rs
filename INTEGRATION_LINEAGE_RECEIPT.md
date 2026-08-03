# Integration lineage receipt

Date: 2026-08-03

Integration branch: `codex/a4-a5-readiness-integration`

Pre-audit integration tip: `c0dceecac432bc6abc804d2e598aeb346a1e6926`

## Exact reviewed histories retained

The integration was performed as true Git merges, not by copying or replaying
the reviewed source trees. The following checks return success:

```text
git merge-base --is-ancestor \
  8d047f6534a7947f707d108795f9ac53e9c68713 c0dceec
git merge-base --is-ancestor \
  8902ac277770fa4c4fa86fb2532b3a95484f20f3 c0dceec
git merge-base --is-ancestor \
  a7fe2e0a9847a1b5db52723a9799f42d241c40ba c0dceec
```

Those commits are, respectively, the reviewed C1/C2 remediation base, the A4/A5
kernel/accept tip, and the signet/readiness tip. Their exact object IDs remain
ancestors of the integration.

The merge topology is:

```text
f9fe46eac0a70fea7841375f11e3f79d2f8d3425
  parents: 8d047f6534a7947f707d108795f9ac53e9c68713
           8902ac277770fa4c4fa86fb2532b3a95484f20f3

c0dceecac432bc6abc804d2e598aeb346a1e6926
  parents: f9fe46eac0a70fea7841375f11e3f79d2f8d3425
           a7fe2e0a9847a1b5db52723a9799f42d241c40ba
```

`git show --remerge-diff f9fe46e` is empty: Git reproduces the A4/A5 merge
without a manual resolution delta.

## Readiness conflict-resolution delta

`git show --remerge-diff c0dceec` records every resolution beyond an automatic
merge. The material decision was the explicit safe-marker version boundary:
version-2 C1 transcripts and golden vectors stay byte-identical and read-only;
version 3 creates the unspendable marker. The same diff preserves both the C2
verified-input exports and readiness scan-status exports, keeps the independent
CBF receipt path, and removes the obsolete kernel equivalence test that the A4
branch replaced with generated differential coverage.

This is the only integration-specific semantic delta before the later C2
adversarial audit. It is documented in `READINESS_JOURNAL.md`, frozen by both
legacy and current golden-vector tests, and validated in the integration CI.

## Signal wallet patch equivalence

The Rust account-wallet slice was cleanly cherry-picked from its original
isolated branch. Stable patch IDs are identical:

```text
original 82308a982f726d8fcccd1dabb3e0d60cb13eb25c
replay   bd493ec0d5046bce5c97025b2213793fba02d9ae
patch-id 5cf6917d3d29b7b3540e7dfb054aa488b83510b6
```

Subsequent wallet hardening is intentionally a new reviewed delta rather than
being described as part of that patch-equivalent replay.
