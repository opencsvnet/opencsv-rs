# Batching v2 C1/C2 remediation receipt

Date: 2026-08-03

Branch: `codex/c1-c2-review-fixes`

Base: `54c08337a1376bb74e3d1fe410802962260f60f0`

## Decision journal

- Preserve every C1 canonical body byte and golden vector. C2 frame version 3
  adds stock/fee-key origin authorization over the exact C1 body hash and the
  selected relay identity. Amending C1 was rejected because it would create an
  unnecessary compatibility boundary.
- Replace caller-supplied `verified`/`reserved` assertions with private-field
  `VerifiedCommitmentInputs`, `VerifiedBatchInputs`, `VerifiedChainTip`, and
  `LocalReservation` capabilities. Another participant cannot prove a private
  wallet lock; every signer enforces its own durable reservation and rechecks
  every public outpoint.
- Treat commitment/epoch/byte/log limits as deployment-local relay policy.
  Admission is unique by authorized relay, fee key, outpoint, operation, and
  payload identities. Treating the default commitment cap as a new protocol
  constant was rejected.
- Persist a reservation's `signature_released` phase before gossiping the
  share. Track and finalize signed transactions by exact manifest ID across
  every replacement epoch. Latest-epoch-only recovery was rejected because a
  sign-and-disappear peer may still hold an older valid conflict.
- Continue after bounded remote parse/authentication failures. Fail the relay
  on listener or storage errors. A best-effort storage path was rejected
  because it could report progress without a durable receipt.
- Refresh the independently verified chain tip after accepting each relay
  connection, before admitting its frame, so idle listener time cannot turn a
  once-fresh receipt into an unbounded signing authority.
- Expose action-oriented originator commands that construct, verify, reserve,
  sign, and publish. Public raw-body proposal, commitment, and signature
  commands were removed; a hidden manifest import remains diagnostic only.

## Reproducible validation

All Rust commands run with `RUSTFLAGS='-D warnings'`.

```text
cargo test -p opencsv-bitcoin --lib
  18 passed; frozen transcript vector unchanged

cargo test -p opencsv-cbf --lib
  34 passed

cargo test -p opencsv-cli --no-default-features --lib batch_gossip::tests::
  2 passed

cargo test -p opencsv-cli --no-default-features --test batch_gossip
  6 passed

cargo clippy -p opencsv-bitcoin -p opencsv-cbf -p opencsv-cli \
  --no-default-features --all-targets --no-deps -- -D warnings
  changed packages clean

OPENCSV_BITCOIND=/opt/homebrew/bin/bitcoind \
  cargo test -p opencsv-cbf --test outpoint_e2e \
  --test batch_v2_e2e -- --nocapture
  2 passed; confirmed output changed to recently spent after a real block;
  the co-funded initial transaction and unanimous RBF replacement were both
  accepted by real bitcoind

OPENCSV_BITCOIND=/opt/homebrew/bin/bitcoind \
  cargo test -p opencsv-cli --no-default-features \
  --test batch_gossip_regtest -- --nocapture
  1 passed; three keyed sessions, real TCP gossip, authoritative CBF checks,
  malformed-peer survival, manifest-omission rejection, sign-and-disappear
  recovery, durable reservations, exact non-latest finalization, initial
  broadcast, unanimous RBF, BIP158 discovery, confirmation, and
  post-confirmation spent-input rejection
```

The final C2 acceptance run produced initial transaction
`84ca14a2ab294cca532dc0e4b1d1303dd8d8a4502ea306e5ad5e54447c2f168c`
and replacement
`a8ec1acbad86bd50c81f131cc84cb076740d35498ec94d2446ebf401f42f98b1`
at isolated regtest height 103. These txids are ephemeral evidence from that
run; the test itself is the reproducible receipt.

The independent C1 construction receipt produced initial transaction
`4a84ac1503136cec4f23146d7c29c35875640d1f0f63afd45fd23d6e0f0987fc`
and replacement
`30b4f9c69cf76b89b4b366ac1bef3efb4e7f70501e67800c8566068567553ba2`
with a 1,362 sat fee, 1,809 WU, and two discoverable protocol payloads.

Adversarial coverage includes recently spent prevouts, manifest omission,
cross-batch origin replay/relay substitution, same-session proposal conflict,
malformed-then-valid relay traffic, identity/outpoint/operation/payload quota
conflicts, and an earlier-epoch signature blocking a later unsigned abort.

The full workspace audit has two separately preserved environmental/base
receipts:

- `RUSTFLAGS='-D warnings' cargo test --workspace --all-targets
  --no-default-features` stops at a pre-existing unused `Entry` import in
  `opencsv-kernel/tests/kernel_equiv.rs`; the import is present at the branch
  base and is outside this repair branch.
- Without warnings-as-errors, the unskipped live-Signet test reached the
  configured `127.0.0.1:38333` peer but received EOF during header sync. A
  second workspace run with only that external test skipped passed through all
  ordinary suites and entered the documented multi-minute recursive proof
  group; it was manually stopped during the final transfer proof after the
  other long adversarial proofs passed. No claim of a complete workspace run
  is made here.
- Dependency-inclusive Clippy reaches `opencsv-pcd` and stops on five
  pre-existing lints (`type_complexity`, `needless_range_loop`, and
  `needless_question_mark`). The changed packages pass warning-clean with
  `--no-deps`; this repair branch does not alter unrelated prover code.

## Deliberate exclusions

- No C1 byte or proof-format change.
- No merge, pull request, release, mainnet broadcast, iOS edit, or device
  mutation.
- No OpenCSV-specific server and no public-explorer trust in the signing path.
