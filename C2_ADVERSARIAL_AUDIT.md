# C2 adversarial relay audit

Date: 2026-08-03

Reviewed base: `8d047f6534a7947f707d108795f9ac53e9c68713`

Integration under review: `c0dceecac432bc6abc804d2e598aeb346a1e6926`

## Scope

The audit traced the live relay path rather than relying only on the happy-path
receipt. It covered canonical frame parsing, strict ECDSA and low-S checks,
stock/fee-key origin authorization, outer relay authorization, semantic IDs,
proposal re-announcement, identity and resource quotas, persisted-index
reconstruction, event-log bounds, listener error containment, and signing and
broadcast admission.

## Findings fixed forward

### Historical proposal admitted to a live session

Version-2 C1 proposal bytes are intentionally frozen and readable. The relay
nevertheless accepted a manually constructed, correctly authorized historical
proposal into a new live session. Its later replacement path was blocked, but
admission itself could revive the historical spendable marker.

Live local signing, network-origin validation, persisted-session loading, and
index reconstruction now require the current C1 version. Historical version 2
remains offline/read-only. The regression test
`historical_v2_proposal_cannot_enter_live_relay` covers both direct relay
admission and reconstruction.

### Sliding socket timeout permitted slow partial frames

The listener applied the configured timeout to each socket read. A peer that
made periodic partial progress could therefore hold the single reference
listener beyond one advertised frame timeout.

Prefix and body reads now share one `Instant` deadline and each read receives
only the remaining duration. The regression test
`partial_frame_has_one_absolute_read_deadline` sends a valid prefix and drips
the body to prove that progress cannot reset the bound.

## Invariants confirmed

- Proposal origin authorization binds the exact C1 body hash to the stock key;
  commitment authorization does the same with the participant fee key.
- The TCP/CLI profile additionally binds the relay identity. Cross-batch replay
  is rejected because the C1 body itself commits to `batch_id`.
- Exact-body proposal re-announcement is idempotent; a different body for the
  initialized session is rejected.
- Strict DER, low-S, canonical framing, and content-derived IDs are checked
  before persistence.
- Admission quotas are keyed to authenticated identities and semantic
  resources before durable write. Startup reconstructs the same index from
  authenticated frames.
- Malformed remote input is contained and receipted; listener and durable
  storage failures remain fatal.
- Signed epochs remain recoverable, so a sign-and-disappear participant cannot
  make a prior valid conflict appear abortable.

## Transport boundary and residual risks

Stock/fee-key authorization over exact C1 bytes is transport-independent. The
separate secp256k1 relay key is the reference TCP/CLI profile only. A Signal
adapter must bind the authorized body to Signal's authenticated sender and
operation context and undergo its own replay and crash-safety review.

The reference listener bounds each frame to 4 MiB, configured identities,
configured session quotas, and one absolute read deadline. It does not claim
to prevent all public endpoint connection-rate or CPU denial of service;
deployments still need ordinary perimeter controls. One session directory is
also a one-process resource protected by the process mutex, not a shared
multi-process database.

## Reproducible receipt

The focused validation after both fixes was:

```text
RUSTFLAGS='-D warnings' cargo test --locked -p opencsv-cli \
  --no-default-features --lib batch_gossip::tests::
  4 passed

RUSTFLAGS='-D warnings' cargo test --locked -p opencsv-cli \
  --no-default-features --test batch_gossip
  6 passed
```

The complete CLI target receipt after both fixes was:

```text
RUSTFLAGS='-D warnings' cargo test --locked -p opencsv-cli \
  --no-default-features --all-targets
  19 passed; 0 failed; 1 intentionally ignored real recursive-proof test

cargo clippy --locked -p opencsv-cli --no-default-features \
  --all-targets --no-deps -- -D warnings
  passed
```

These changed-package results are not presented as a full workspace claim.
The hosted integration CI run is linked from the GitHub issue receipt after
the audit commit is pushed.
