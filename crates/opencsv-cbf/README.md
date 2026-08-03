# opencsv-cbf

A [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)/[BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
compact-block-filter light client providing **trustless point verification**
of claimed OpenCSV anchors against plain `bitcoind` P2P peers. No trusted
server, no RPC, no txindex: the client speaks the Bitcoin wire protocol
directly (hand-rolled, `std::net::TcpStream`, `sha2` + manual encoding —
no heavy dependencies).

## What it proves

`CbfClient::verify_anchor(anchor, location, txid, required_confirmations)`
verifies a claimed anchor end-to-end, with **zero trust in any single peer**:

- **Presence** — the full block at `location.height` is fetched over P2P
  and its merkle root recomputed and compared against the verified block
  header; the transaction at `location.position` must have the claimed
  `txid` and carry the exact 64-byte record in an OP_RETURN output. The
  record's presence is thereby committed by the header's proof of work.
- **Position** — the claimed in-block position is checked directly against
  the block's transaction list (`TxidMismatch`, `PositionOutOfRange`,
  `RecordNotInTx` verdicts otherwise).
- **ctx** — recomputed from the anchor transaction's first input via the
  canonical `opencsv_bitcoin::funding_ctx`
  (`SHA-256(txid_internal ∥ vout_LE)`), so the caller can evaluate
  `AnchorRecord::well_formed` against the raw nullifier it holds.
- **Confirmations** — `tip − height + 1` over a header chain with full
  PoW validation: previous-block linkage, per-network `nBits` rules
  (mainnet retargeting, signet's testnet-style minimum difficulty,
  regtest's constant bits), hash below target, median-time-past — and
  the tip must be agreed upon by **all** connected peers.

**Absence is proven the same way**: a fetched block whose transactions
(all committed by its merkle root) contain no such record at the claimed
position proves the claim false — `AnchorVerdict::NotPresent(_)`.

`CbfClient::tip_height()` reports the verified chain tip. Headers, filter
hashes, and fetched filters are persisted in `Config::cache_dir` — a
rebuildable cache: deleting it only forces a resync, and cached data is
re-validated on load (headers). Because filter hashes are not committed in
block headers, every new connection re-fetches their complete chain from all
peers before use; later syncs on those same connections fetch only the suffix.

## The filter layer — and an honest caveat

The crate implements the full BIP157/158 machinery: `getcfheaders` /
`cfheaders` (filter-header chain, each header committing to the filter
hash and the previous header), `getcfilters` / `cfilter` (basic filters,
index 0), BIP158 GCS/Golomb-Rice encoding and matching (SipHash-**2-4**
keyed with the first 16 bytes of the block hash, P=19, M=784931), and
filter verification against the synced filter-header chain, which is
cross-checked across all connected peers. The BIP158 Appendix C test
vectors are unit tests (`tests/bip158.rs`), and the regtest integration
test cross-checks fetched filters and filter headers against bitcoind's
own `getblockfilter` index.

**Deviation from the original design doc**: the plan assumed the filter
step could prove presence/absence of the anchor's OP_RETURN scriptPubKey
("filters CAN prove absence for a fixed script"). That assumption is
wrong for the deployed basic filter: **BIP158 basic filters exclude all
OP_RETURN outputs** (deliberately, so filters can be committed to by a
future soft fork without a circular dependency). An anchor's OP_RETURN
script is therefore never in the filter — a non-match carries no
information, and a match is a 1-in-M false positive. `verify_anchor`
still runs the filter query (the verdict reports it as the
`filter_matched` diagnostic), but presence and absence are established
by the merkle-verified full block, which *is* trustless. The regtest
integration test asserts exactly this behavior: the anchor's OP_RETURN
script does not match its block's filter, while the block's coinbase
payout script does.

(Second deviation, same lesson: the design brief said "siphash-1-3".
Early BIP158 drafts did use 1-3, but the deployed spec and every
shipping implementation use SipHash-2-4; the BIP158 test vectors — and
live bitcoind filters — only decode with 2-4.)

## The scan engine (ScanIndex): trustless exclusion by default

Anchor transactions carry the protocol-constant marker output
(`opencsv_bitcoin::MARKER_SPK` = `OP_0 <sha256(OP_RETURN)>`, 546 sats) at
output index 1, so BIP158 basic filters match anchor-bearing blocks even
though they exclude the direct OP_RETURN record itself. The P2WSH marker is
unspendable, preventing third-party child pinning; scanners also recognize the
historical `sha256(OP_TRUE)` marker without creating it. `ScanIndex` builds
the default exclusion path on top of this:

- `scan_sync(client, from_height)` checks every block's verified filter
  for the marker spk from `from_height` to the tip, SPV-fetches
  (merkle-verified) the matching blocks, and stores every OP_RETURN
  candidate with its recomputed funding ctx in a persistent, rebuildable
  index dir. Bandwidth counters (`filters_bytes`, `blocks_bytes`,
  `blocks_fetched`) are exposed.
- Scan-index v2 is checksummed and atomically replaced. A partial, corrupt,
  unknown, or legacy file returns `ScanLoadStatus::RebuildRequired` and starts
  from height zero instead of trusting a possibly incomplete occurrence set.
- `scan_check(raw_nf, birth, spend)` answers occurrence queries
  **locally** — no network at check time; earliest occurrence wins.
- Batch headers expand into one indexed candidate per witness payload. `OCSV`
  selects the legacy `batch` commitment; `OCS2` skips the stock signature and
  selects `batch-v2`. The selected version is persisted, and an invalid stack
  never falls back across versions.
- The `AnchorChain` impl (tip = synced tip) lets `accept()` run against
  the scan alone: no RPC to the anchoring node, no indexer.

The regtest test measures the whole exclusion check at **320 filter
bytes + 1140 block bytes** for an 8-block window (2 anchor blocks).

### The three exclusion postures, and when each applies

| Posture | Trust needed | Cost per check | Use |
| --- | --- | --- | --- |
| **ScanIndex** (this crate) | SPV only (PoW headers + verified filters) | filters to tip + anchor blocks only | the default |
| **FullScanChain** | SPV only | full blocks for the whole window | fallback: pre-marker history, or when filter correctness itself is in doubt |
| **CrossCheckedChain** (opencsv-core) | 1-of-N honest indexers | one indexer query | when indexers are acceptable anyway (they already run them) |

Marker-copy noise (a third party putting the constant marker in their
own transaction) and BIP158 false positives both cost one
merkle-verified block download and nothing else — no record binding the
queried nullifier is found.

## FullScanChain: the zero-trust self-scan escape hatch

For high-value receipts, `FullScanChain` removes the indexer from the
exclusion check entirely: it downloads **every full block** in a bounded
window `[birth_height, spend_height]` over P2P — each merkle-verified
against the PoW-checked header chain, so the scan inherits
`verify_anchor`'s trustlessness — parses every 64-byte OP_RETURN
candidate, recomputes each candidate's `ctx` from its first input, and
tests `well_formed(ctx, raw_nf)` locally.

```text
FullScanChain::first_occurrence_in_window(client, raw_nf, birth, spend)
    -> Result<Option<(AnchorLocation, ctx)>>
```

It also implements `AnchorChain` constrained to the window, so `accept()`
can run against it directly — with two caveats that follow from the
window semantics: occurrences before `birth` are invisible (start the
window at the coin's birth height), and `tip_height()` is the window
*end*, so confirmation depth is measured from there (scan up to the
live tip for receipts). Windows are capped at `MAX_WINDOW_BLOCKS`
(2016) blocks; the regtest integration test mines a genuine double-spend
(same raw nullifier anchored twice, each under its own ctx) and checks
the scan reports the first occurrence and only that one.

## What it cannot prove: occurrence exclusion

Compact filters cannot support OpenCSV **occurrence-exclusion scans**
("does `raw_nf` appear anywhere else on the chain?"). The match key
would have to derive from the on-chain payload, but the payload
`P = H("bind" ∥ raw_nf ∥ ctx)` is deliberately *not* publicly
derivable — that privacy is precisely what stops copy-griefing — so
occurrence keys are not filter-matchable. (And per the caveat above,
even the public record bytes are not in basic filters.) Occurrence
scans remain the job of a full-chain indexer, e.g. the `opencsv-bitcoin`
RPC backend's persistent anchor index.

## Security model and eclipse resistance

This is an SPV light client: it validates proof of work and merkle
inclusion, **not** transaction or block validity. Its security rests on:

- **At least one honest, un-eclipsed peer.** An attacker controlling
  *all* your connections can feed you a fabricated lower-work chain.
  Mitigation implemented: the client syncs headers from **every**
  configured peer from the same validated base and requires identical tip
  height, hash, and accumulated work (`Error::DivergentPeers` otherwise);
  block and filter fetches fail over across peers. Peers must advertise both
  witness and compact-filter services. Connect
  to several independent peers (`Config::peers`) — on mainnet, prefer
  peers you don't all reach through one network path.
- **Filter-header chain agreement.** Filter headers are not committed
  in block headers, so a malicious peer could serve wrong filters
  (hiding filter matches). The client fetches the filter-header chain
  from every peer and requires byte-identical filter hashes before use
  (BIP157's one-honest-peer model). Note this protects only the
  *filter* layer — the anchor verdict itself never depends on a filter
  match (see the caveat above), so filter misbehavior alone cannot
  forge or hide an anchor.
- **Not validated**: block/transaction/script validity (a miner with
  majority hashpower could confirm invalid blocks — the standard SPV
  assumption), and timestamps beyond the consensus median-time-past
  rule. Confirmations count PoW depth only; for high-value decisions,
  require more confirmations, exactly as with any SPV wallet.

## Layout

- `src/siphash.rs` — SipHash-2-4 (canonical reference vectors as tests).
- `src/gcs.rs` — BIP158 GCS/Golomb-Rice encode + match (MSB-first
  bitstream, P=19, M=784931), filter hash/header chaining.
- `src/wire.rs`, `src/messages.rs` — varints, framing, and the P2P
  messages (`version`/`verack`, `getheaders`/`headers`,
  `getcfheaders`/`cfheaders`, `getcfilters`/`cfilter`, `getdata`,
  `ping`/`pong`).
- `src/block.rs` — header/transaction/block parsing (segwit-aware),
  txids, merkle roots, OP_RETURN extraction.
- `src/network.rs` — per-network consensus parameters, 256-bit target
  arithmetic, `GetNextWorkRequired`, chainwork.
- `src/peer.rs` — the `TcpStream` peer: handshake and request/response.
- `src/chain.rs` — validated header chain + filter-header chain +
  rebuildable persistent cache.
- `src/client.rs` — `CbfClient`, `verify_anchor`, `AnchorVerdict`.
- `tests/bip158.rs` — the BIP158 Appendix C vectors (fixture:
  `tests/bip158_testnet19.json`).
- `tests/regtest_e2e.rs` — end-to-end against a real `bitcoind`
  (regtest, `blockfilterindex=1 peerblockfilters=1`; real anchor via
  `opencsv-bitcoin`). Skips silently when no `bitcoind` is found;
  override the path with `OPENCSV_BITCOIND`.
- `tests/batch_v2_e2e.rs` — three independently keyed funding inputs,
  co-funded construction, output-mutation rejection, real mempool RBF,
  confirmation, and two payload occurrences recovered through the scan.

## TODO / future work

- Fetch each *filter* from two peers for equality (today only the
  filter-header chain is cross-checked; a fetched filter is verified
  against that chain, which bounds the damage to the one honest-peer
  assumption either way).
- Bandwidth: `getcfcheckpt`-based parallel filter-header sync.
- Reorg handling is follow-the-peer (truncate to fork point); no
  incremental detection of mid-session reorgs between `sync()` calls.
