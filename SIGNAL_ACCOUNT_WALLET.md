# Signal-native OpenCSV account wallet

This document describes the Rust boundary intended for Signal-iOS. It replaces
the earlier caller-owned Bitcoin fee key and OpenCSV-specific anchor-server
shape. Signal expresses user intent; Rust owns protocol and Bitcoin custody.

## Custody boundary

A primary phone creates a random 32-byte account root and stores it in the
platform keystore and Signal Secure Backup. It also creates a distinct random
32-byte device binding in a non-migratable `ThisDeviceOnly` keystore item.
Both enter `opencsv_account_open` as byte buffers, never JSON. Rust derives
distinct branches from the account root for:

- the BIP84 Bitcoin fee wallet;
- the OpenCSV owner.

Signal is not an issuer. The production C boundary retains no issuer seed and
exports no asset-definition or mint-preparation action. Issuer keys belong to
separate privileged issuer tooling and never enter the Signal account root or
Secure Backup.

The opt-in `opencsv-issuer` binary is that headless operator boundary. It is
compiled only with the `issuer-tools` feature, reads issuer roots from files
rather than command-line values, and returns JSON suitable for automation. It
can create an exact public manifest, prepare issuer-authorized mints, export
and acknowledge checkpoints, and advance durable operations through
sign/broadcast, resume, cancellation, and protocol-safe fee bump. Possession
of this executable alone conveys no authority: mint proofs require the issuer
seed derived by the account that created the exact asset id.

Temporary root and derivation buffers are zeroized. The primary wallet keeps
the derived signing state required while the account is open. A linked device
passes no account root and opens with public descriptors and owner identity;
write calls fail with `primary_required`.

Rust commits the account root and device binding together. That public
commitment is stored in SQLite, returned with status, and included in every
Secure Backup checkpoint. A restored database or clean-database checkpoint
whose commitment does not match the current device binding opens
read/export-only: transfer, sign, and fee bump fail with
`device_binding_mismatch`. The host must carry the checkpoint commitment on a
clean restore. Fresh setup must create the root and binding atomically. If a
root already exists but its non-migratable binding is missing after an OS
restore, the host passes an empty binding and Rust opens read/export-only; it
must not generate a replacement binding or silently treat the restored root as
a new wallet. Rust persists that missing-binding state, so a later open with a
newly generated binding remains read/export-only. Re-arming another device
requires an explicit recovery/rekey flow that moves the fee reserve and assets;
replacing the root locally would strand ownership.

The action boundary contains no WIF, caller-selected Bitcoin UTXO, change
address, arbitrary Bitcoin recipient, raw-transaction broadcast, OpenCSV coin
ids, or caller-constructed asset change. A transfer request is exactly:

```json
{"asset_id":"<32-byte hex>","to_owner":"<32-byte hex>","amount":100}
```

Rust selects an unreserved two-coin protocol input set, minimizing asset
change deterministically, then independently reserves a fee UTXO and derives
Bitcoin change.

## Persistence and recovery

`bdk_wallet` 3.1.0 and `bdk_esplora` 0.22.2 are pinned. BDK's public
`WalletPersister` contract is implemented as an append-only `ChangeSet` log in
the account SQLite database. BDK's optional SQLite adapter is not enabled: it
pins an older `libsqlite3-sys` generation that cannot coexist with the SQLite
runtime used by the Signal dependency graph.

The same database stores:

- trusted public issuer manifests and legacy prototype metadata, but no issuer
  secret or account root;
- protocol consignments and verified chain snapshots;
- Bitcoin UTXO reservations;
- pending proofs and normalized action requests;
- signed transactions and delivery receipts.

A compact checkpoint exports the device-binding commitment plus asset,
consignment, spent, and operation state for Signal Secure Backup. The BDK
chain graph is rebuildable cache and is not part of the checkpoint. A prepared
operation may be signed only after Signal acknowledges the exact checkpoint
hash. Disabling backup preserves status and receive access but freezes new
writes.

On a clean restore, Signal opens the account with the recovered root, an empty
device-binding buffer, and the checkpoint's public binding commitment, then
calls `opencsv_account_restore_checkpoint`. Rust verifies the checkpoint hash,
network, root-derived owner, and binding commitment before atomically importing
asset metadata, operation identifiers, consignments, spent state, and any
available verification snapshots. Import is idempotent for the same hash and
refuses both conflicting checkpoints and non-clean databases. It never re-arms
the restored phone: the absent `ThisDeviceOnly` binding keeps every Bitcoin
write frozen until an explicit recovery/rekey flow exists.

## Operation lifecycle

The durable state machine is:

```text
planned -> fee_reserved -> proof_ready -> signed_persisted
        -> broadcast_unobserved -> broadcast/mempool -> confirmed
        -> consignment_delivered
```

Cancellation is permitted only before the first broadcast attempt. Reopening
the database restores fee and OpenCSV reservations plus pending proof state.
Every transaction is fully signed and committed before any socket or HTTP
write. `resume` rebroadcasts the exact persisted bytes and is idempotent.

Signal attachment delivery and Bitcoin settlement are recorded independently.
Acknowledging a consignment while its anchor is in the mempool sets an
idempotent receipt flag but leaves the operation in `mempool`, so the
protocol-safe RBF window remains open. Once that transaction or its valid
replacement confirms, the state advances directly to
`consignment_delivered`. A delivery acknowledged after confirmation advances
there immediately. RBF reuses the already-finalized consignment and must never
consume or recreate its pending proof a second time.

The first Bitcoin input fixes the OpenCSV context before proof generation.
Transactions use record output 0, the unspendable BIP158 marker at output 1,
and wallet change at output 2. Protocol-safe RBF is change-only. It preserves
the complete original input set, input 0, context, output scripts, output
positions, change destination, and non-dust change. Appending an input would
require a second authoritative verification and durable reservation protocol,
so the product API does not permit it.

## Network trust

Esplora is a configurable read accelerator and generic relay fallback. Direct
relay performs a Bitcoin version/verack handshake with every configured peer
and writes the complete signed transaction independently to each. A socket
write is only submission evidence. Consignment delivery waits until an
independent read path observes the transaction.

Confirmed OpenCSV consignments and selected Bitcoin fee outpoints are checked
through the header/BIP158/full-block verification path. Esplora may discover a
candidate and report its birth height, but the exact txid/vout/value/script
must be found in a merkle-verified block under the independently agreed header
chain. Every matching filter through the current tip is inspected for a later
spend. The check runs after durable reservation, immediately before initial
signing, and again before a fee bump. Missing peers, excessive history,
mismatch, or a later spend fails closed. Signet/mainnet require at least two
compact-filter peers; regtest accepts one isolated peer.

This closes the selected-outpoint trust boundary, but does not itself make the
wallet mainnet-ready. Rust now decodes and canonically re-encodes every
consignment before verification, persistence, and SHA-256 identity, and returns
that identity for Signal to key both verdicts and rendered payment cells.
Signal recovery integration and canonical verdict storage are implemented on
the isolated iOS integration branch. Hosted gates, linked-device provisioning,
canonical conversation-level duplicate suppression, and physical signet
acceptance remain mandatory. The delivery acceptance test must produce two
byte-distinct attachments through a sender crash/resume while rendering exactly
one verified payment bubble.

## Current C ABI

The action-oriented surface is:

- `opencsv_account_open/close/status/sync`
- `opencsv_account_set_backup_state/checkpoint/restore_checkpoint`
- `opencsv_account_verify_consignment/scan_verify/cross_check`
- `opencsv_transfer_prepare`
- `opencsv_operation_ack_backup`
- `opencsv_operation_sign_and_broadcast`
- `opencsv_operation_status/resume/cancel`
- `opencsv_fee_bump`
- `opencsv_operation_mark_delivered`

The account config may contain reviewed public `usd_issuers` manifests. Rust
validates each exact genesis/terms pair, network, `USD` unit code, and unique
asset id. Status groups those issuer-specific identities under the
`trusted_usd_v1` product profile with deterministic priority, while preserving
the issuer name and asset id for review and receipts. Unknown or legacy assets
remain visible but are not promoted by their ticker.

`opencsv_account_open` takes the public config, account-root bytes,
device-binding bytes, and database path. The config may include
`expected_device_binding_commitment` from a recovery checkpoint. Linked
devices pass empty root/binding buffers and remain watch-only. A primary with
a 32-byte root and empty binding is a detected missing-binding restore and is
read/export-only.

The legacy in-memory FFI remains temporarily available for compatibility while
Signal migrates. It is not the target wallet architecture.

## Headless issuer CLI

Build the operator binary explicitly; the default library and Signal CocoaPods
build do not include it:

```sh
cargo build --locked --release -p opencsv-ffi \
  --features issuer-tools --bin opencsv-issuer
```

Every invocation requires an account config, SQLite database, 32-byte account
root file, and distinct 32-byte device-binding file. Secret files may contain
raw bytes or 64 lowercase/uppercase hex characters. They are never printed or
accepted as command-line values. The same four parameters may be supplied by
the `OPENCSV_ISSUER_CONFIG`, `OPENCSV_ISSUER_DATABASE`,
`OPENCSV_ISSUER_ACCOUNT_ROOT_FILE`, and
`OPENCSV_ISSUER_DEVICE_BINDING_FILE` environment variables.

The lifecycle is intentionally two-stage:

1. `instrument create --terms terms.json` creates the exact manifest and
   freezes writes until its returned checkpoint is backed up.
2. `backup export` emits the current checkpoint; `backup acknowledge
   --checkpoint-hash HASH` accepts only its exact current hash.
3. `mint prepare --asset-id ID --amount BASE_UNITS` accepts an exact id, never
   a ticker shortcut, and returns an operation id plus checkpoint hash.
4. `operation acknowledge-backup --operation-id ID --checkpoint-hash HASH`
   gates signing on the prepared checkpoint.
5. `operation broadcast --operation-id ID --sat-per-vb RATE` signs, persists,
   and attempts direct P2P broadcast. `operation status`, `resume`, `cancel`,
   and `fee-bump` expose the durable recovery path.

Signal consumes only public manifests selected through its reviewed
`usd_issuers` policy. An unrelated operator may create another instrument, but
that does not make it a trusted Signal USD issuer. A future Tether instrument
requires Tether-controlled authority and an independently authenticated exact
manifest; its name is never inferred from the `USD` ticker.
