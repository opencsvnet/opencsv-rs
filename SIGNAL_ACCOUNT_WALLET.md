# Signal-native OpenCSV account wallet

This document describes the Rust boundary intended for Signal-iOS. It replaces
the earlier caller-owned Bitcoin fee key and OpenCSV-specific anchor-server
shape. Signal expresses user intent; Rust owns protocol and Bitcoin custody.

## Custody boundary

A primary phone creates a random 32-byte account root and stores it in the
platform keystore and Signal Secure Backup. The root enters
`opencsv_account_open` as a byte buffer, never JSON. Rust derives distinct
branches for:

- the BIP84 Bitcoin fee wallet;
- the OpenCSV owner;
- the issuer root and each account-created asset.

Temporary root and derivation buffers are zeroized. The primary wallet keeps
the derived signing state required while the account is open. A linked device
passes no account root and opens with public descriptors and owner identity;
write calls fail with `primary_required`.

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

- derived issuer metadata, but not the account root;
- protocol consignments and verified chain snapshots;
- Bitcoin UTXO reservations;
- pending proofs and normalized action requests;
- signed transactions and delivery receipts.

A compact checkpoint exports asset, consignment, spent, and operation state
for Signal Secure Backup. The BDK chain graph is rebuildable cache and is not
part of the checkpoint. A prepared operation may be signed only after Signal
acknowledges the exact checkpoint hash. Disabling backup preserves status and
receive access but freezes new writes.

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

The first Bitcoin input fixes the OpenCSV context before proof generation.
Transactions use record output 0, the unspendable BIP158 marker at output 1,
and wallet change at output 2. Protocol-safe RBF preserves the complete
original input prefix and may only append reserved fee inputs; input 0,
context, output scripts, output positions, and non-dust change remain fixed.

## Network trust

Esplora is a configurable read accelerator and generic relay fallback. Direct
relay performs a Bitcoin version/verack handshake with every configured peer
and writes the complete signed transaction independently to each. A socket
write is only submission evidence. Consignment delivery waits until an
independent read path observes the transaction.

Confirmed OpenCSV consignments are checked through the existing
header/BIP158/full-block verification path. The remaining production gate is
an equivalent authoritative revalidation of a selected Bitcoin fee outpoint
immediately before context derivation/signing. Until that lands and passes the
dishonest-Esplora tests, the account wallet is a review branch and must not be
described as mainnet-ready.

## Current C ABI

The action-oriented surface is:

- `opencsv_account_open/close/status/sync`
- `opencsv_account_set_backup_state/checkpoint`
- `opencsv_account_verify_consignment/scan_verify/cross_check`
- `opencsv_mint_prepare` and `opencsv_transfer_prepare`
- `opencsv_operation_ack_backup`
- `opencsv_operation_sign_and_broadcast`
- `opencsv_operation_status/resume/cancel`
- `opencsv_fee_bump`
- `opencsv_operation_mark_delivered`

The legacy in-memory FFI remains temporarily available for compatibility while
Signal migrates. It is not the target wallet architecture.
