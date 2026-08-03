# Signet readiness receipt

Date: 2026-08-03

This receipt includes deliberately authorized signet writes from a dedicated
Bitcoin Core wallet. It did not touch Claude's source checkout, node data, or
wallet. No mainnet transaction was created or broadcast.

## Node snapshot

The local reference node reported:

- Bitcoin Core 31.1, signet height and headers 316025, verification progress
  1.0, initial block download false, unpruned, 20822554989 bytes on disk.
- 11 peers, network active, full-RBF enabled, and 1 sat/vB relay,
  incremental-relay, and mempool floors.
- Conservative six-block estimate: 4.53 sat/vB. The readiness fee table rounds
  this up to 5 sat/vB rather than presenting a fractional policy as exact.
- The existing `uvwallet` supplied one explicit 5,000-sat signet funding
  transfer to the isolated `opencsv-readiness-20260803` wallet after owner
  approval. Funding transaction `8856b269…f290` paid a 449-sat fee, had 130
  vB, and confirmed in block 316030. No Claude-controlled wallet was used.

Reproduce the snapshot with `bitcoin-cli -signet getblockchaininfo`,
`getnetworkinfo`, `getmempoolinfo`, `estimatesmartfee 6 CONSERVATIVE`, and
wallet-scoped `getbalances`/`listunspent` against the operator's own node.

## Independent compact-filter probe

Command shape:

```sh
cargo run --release -p opencsv-cbf --example readiness_probe -- \
  <fresh-cbf-cache> <fresh-scan-cache> 144 \
  172.233.20.188:38333 15.204.114.107:38333
```

Peers are examples from the receipt, not pinned infrastructure. Operators must
select at least two independently operated peers that advertise witness and
compact-filter services.

### Cold run

```json
{"network":"signet","tip":316025,"connected_peers":2,"handshakes":2,"connection_sync_ms":156043,"connection_wire_sent":318114,"connection_wire_received":71460464,"same_session_sync_ms":351,"same_session_wire_sent":1978,"same_session_wire_received":50,"scan_from":315882,"scan_to":316025,"scan_ms":26594,"scan_filter_bytes":704742,"scan_block_bytes":76782,"scan_blocks_fetched":2,"scan_occurrences":0,"scan_initial_status":"fresh","scan_reopen_status":"loaded"}
```

### Process restart with the same caches

```json
{"network":"signet","tip":316025,"connected_peers":2,"handshakes":2,"connection_sync_ms":75193,"connection_wire_sent":21794,"connection_wire_received":20255556,"same_session_sync_ms":350,"same_session_wire_sent":1978,"same_session_wire_received":50,"scan_from":315882,"scan_to":316025,"scan_ms":25,"scan_filter_bytes":0,"scan_block_bytes":0,"scan_blocks_fetched":0,"scan_occurrences":0,"scan_initial_status":"loaded","scan_reopen_status":"loaded"}
```

Interpretation:

- Cold connection validates the full header history independently through both
  peers and re-derives the complete filter-hash chain.
- Process restart revalidates cached headers locally and re-attests all filter
  hashes over the network. It is faster but intentionally not network-free.
- Same-session sync reuses authenticated connections and downloads only new
  data, so the no-change receipt is 350–351 ms and 50 bytes received.
- The 144-block scan fetched filters individually, downloaded two
  merkle-checked blocks for marker matches, found no OpenCSV occurrences, and
  reopened the checksummed index as `loaded`.

### Degraded-peer run

One deliberately dead endpoint plus three candidates still produced two
successful, agreeing connections at height 316030. The probe failed closed on
an earlier attempt when a transient peer failure left only one connection.

```json
{"network":"signet","tip":316030,"connected_peers":2,"handshakes":2,"connection_sync_ms":119167,"connection_wire_sent":23772,"connection_wire_received":20256088,"same_session_sync_ms":319,"same_session_wire_sent":1978,"same_session_wire_received":50,"scan_from":315887,"scan_to":316030,"scan_ms":648,"scan_filter_bytes":31812,"scan_block_bytes":0,"scan_blocks_fetched":0,"scan_occurrences":0,"scan_initial_status":"loaded","scan_reopen_status":"loaded"}
```

## Fee and marker model

Run `cargo run -p opencsv-bitcoin --example fee_model -- 5`. The model uses a
constructed 911-WU/228-vB maximum solo P2WPKH anchor and batching v2's frozen
`968 + 423*N` maximum signed weight. It includes the 546-sat marker once per
transaction and excludes the reusable stock setup transaction.

| Operations | Solo total sats | Batch total sats | Savings sats | Batch charge range |
|---:|---:|---:|---:|---:|
| 1 | 1686 | 2286 | -600 | 2286 |
| 2 | 3372 | 2816 | 556 | 1408 |
| 4 | 6744 | 3871 | 2873 | 967–968 |
| 8 | 13488 | 5986 | 7502 | 748–749 |
| 16 | 26976 | 10216 | 16760 | 638–639 |
| 32 | 53952 | 18676 | 35276 | 583–584 |
| 64 | 107904 | 35596 | 72308 | 556–557 |

These are conservative size-model outputs at a caller-selected rounded
feerate, not promises about future mining fees or confirmation time.

## Live write-path and adversarial receipts

The first isolated mint exposed a critical marker defect in the inherited
implementation:

| Receipt | Result |
|---|---|
| Funding `8856b269…f290` | 5,000 sats into the isolated wallet; confirmed at height 316030. |
| Historical-marker mint `e985c098…ead1` | 240 vB, 822-sat fee, record at output 0, `sha256(OP_TRUE)` marker at output 1, 3,632-sat change at output 2. |
| Third-party child `157e3246…b1b7` | Spent the marker with witness `OP_TRUE`, burned all 546 sats to an OP_RETURN, and prevented parent RBF. Parent and child confirmed together at height 316031. |

The implementation was then changed to the unspendable
`OP_0 <sha256(OP_RETURN)>` marker and rebuilt. A second mint used transaction
`db85bcbb…1e60` (229 vB, 788-sat fee) with the same required output ordering.
No marker-spending child appeared before that transaction was replaced. This
is live evidence consistent with the new script's consensus semantics, not a
substitute for the unit and scanner tests. Historical spendable-marker
manifests remain readable but cannot start a replacement epoch.

An intentional generic-Core fee-bump trial then failed the OpenCSV invariant:
Core replaced it with confirmed transaction `c21073b1…6b1c`, raised the fee to
3,086 sats, retained the record at output 0 and safe marker at output 1, but
removed output 2 instead of preserving non-dust change. The new pure
`validate_solo_anchor_replacement` boundary rejects that exact shape as
`replacement_layout`; it also rejects funding/context, record, marker, change
destination, dust, and non-increasing-fee mutations with stable codes.

The reopened isolated CLI wallet and Bitcoin index loaded cleanly after the
transactions confirmed. The two minted consignments remain separate evidence
files; they were not falsely credited to the CLI wallet merely because their
anchors confirmed.

## Remaining write-path acceptance

Funding provenance, mint/anchor, public mempool observation, confirmation,
safe-marker migration, and restart/reopen receipts are complete. A fresh
protocol-safe replacement constructed by the Rust-owned wallet, validated
before signing, persisted before broadcast, observed in mempool, and confirmed
with its change output intact is still required. The generic Core result above
is a negative receipt, not acceptance. The isolated wallet is now empty, so a
new run also needs fresh signet sats. No mainnet broadcast is authorized by
this document.
