# opencsv-cli

A text wallet client for **OpenCSV** — client-side verified RWAs
anchored to Bitcoin L1 with recursive PCD proofs (see `paper/opencsv.md`).
The binary is a thin shell over this crate's library: all wallet logic lives
in the lib target so a future Signal transport crate can reuse it and only
move consignment blobs.

**Prototype-grade.** Secrets are stored unencrypted. Anchoring is real:
the default chain backend talks to a real `bitcoind` over RPC and
broadcasts real `OP_RETURN` transactions (signet/mainnet/regtest). The
old simulated file chain is still available for demos, explicitly
requested, and warns on every use.

## Chain backends (honest matrix)

| Backend | How to select | What it is |
| --- | --- | --- |
| **bitcoind RPC** | *(default)* `--chain bitcoin` | **Real Bitcoin.** Anchors are real transactions broadcast to a real node; reads scan real blocks; confirmations are real. Hard error (never a fallback) if the node is unreachable, the auth fails, or the network mismatches. |
| File chain | `--chain demo`, `--chain file:<path>` | Simulated L1 in a text file; `chain advance` simulates mining. Prints `DEMO CHAIN — not Bitcoin`. |
| Anchor server | `--anchor-server http://host:port` | The file chain shared over HTTP (demo, same warning). |

bitcoind backend flags (all have `OPENCSV_*` env forms):

```text
--network signet|mainnet|regtest   (default: signet; env OPENCSV_NETWORK)
--rpc-url http://host:port         (default: 127.0.0.1 + network port; env OPENCSV_RPC_URL)
--cookie <path>                    (default: ~/.bitcoin/<network>/.cookie; env OPENCSV_COOKIE)
--rpc-auth user:password           (overrides --cookie; env OPENCSV_RPC_AUTH)
--rpc-wallet <name>                (bitcoind multi-wallet endpoint; env OPENCSV_RPC_WALLET)
--scan-from <height>               (anchor index start; env OPENCSV_SCAN_FROM)
```

How it works (see `crates/opencsv-bitcoin` for details):

- **Anchoring** is a two-pass construction: `createrawtransaction` +
  `fundrawtransaction` with a dummy 64-byte `OP_RETURN` learns the funding
  inputs; the record's bound payloads are then computed against the ctx
  (the funding input's outpoint: `txid ⊕ vout` folded to 32 bytes); the tx
  is rebuilt with the same inputs/outputs and the real record, signed with
  `signrawtransactionwithwallet`, and broadcast with `sendrawtransaction`.
  The anchor's block height/position only exist once the tx mines — the
  consignment carries a mempool placeholder that verifiers resolve by
  txid, so a consignment verifies only after the anchor confirms.
- **Reading** scans blocks (`getblock` verbosity 2) for 64-byte
  `OP_RETURN` payloads into a **persistent local index**
  (`<wallet-dir>/bitcoin-index-<network>.log`) — a rebuildable cache, not
  a second source of truth; delete it to force a rescan. Scanning starts
  at `--scan-from` (default: the tip when the index is first created),
  **not genesis**: full-history indexing for arbitrary counterparties is
  an indexer service's job (future work). A recipient whose wallet is
  newer than the anchor must pass a covering `--scan-from` (see the
  regtest walkthrough). On a pruned node the start height must be above
  the prune horizon. On a stale tip hash (reorg) the index is truncated
  back to the start height and rebuilt.

### Signet status and the one remaining manual step

Against a synced signet node the read path is fully validated (tip,
block-range scans, index, audits) and the wallet is broadcast-ready
(created, unencrypted, key-backed) — but **broadcasting on signet needs
signet coins, and public faucets require a captcha**, so the last step is
manual:

```sh
# 1. Create the wallet (once) and print a funding address.
bitcoin-cli -signet createwallet opencsv            # already done on the dev node
bitcoin-cli -signet -rpcwallet=opencsv getnewaddress
#    → e.g. tb1qpadu8m8ys2ukkx0vxhvse2up5sk7v8sy9d24q0 (the dev node's address)
# 2. Send signet coins to that address from any faucet, e.g.
#    https://signetfaucet.com or https://mempool.space/signet (web form,
#    captcha). Wait for 1+ confirmations.
# 3. Run the normal flow with --rpc-wallet opencsv, e.g.:
opencsv --rpc-wallet opencsv mint --asset <hex> --to self --amounts 100,50
```

On regtest there is no faucet problem — `chain advance` mines real blocks
via the wallet and the whole flow runs unattended (next section).

## Quickstart (regtest, real Bitcoin)

`scripts/e2e-regtest.sh` runs the full protocol against a fresh
`bitcoind -regtest` — real broadcast anchor transactions, real mining —
and is safe to rerun (it wipes `/tmp/opencsv-regtest*`):

```sh
cargo build --release -p opencsv-cli
scripts/e2e-regtest.sh
# … mint anchors (real tx), 6 blocks, VERIFIED, send, VERIFIED,
#   double-spend attempt, REJECTED (first occurrence wins), supply audit
```

Manual equivalent (the script does exactly this):

```sh
bitcoind -regtest -datadir /tmp/rt -daemon -rpcport 28443 -fallbackfee=0.00001
bitcoin-cli -regtest -datadir /tmp/rt -rpcport 28443 createwallet opencsv
bitcoin-cli -regtest -datadir /tmp/rt -rpcport 28443 -rpcwallet=opencsv \
    generatetoaddress 101 "$(bitcoin-cli -regtest -datadir /tmp/rt -rpcport 28443 -rpcwallet=opencsv getnewaddress)"

OP=target/release/opencsv
RT="--network regtest --rpc-url http://127.0.0.1:28443 --cookie /tmp/rt/regtest/.cookie --rpc-wallet opencsv"
ALICE="$OP --wallet-dir /tmp/demo/alice $RT"
BOB="$OP --wallet-dir /tmp/demo/bob $RT --scan-from 1"

$ALICE keygen && $BOB keygen
ASSET=$($ALICE issuer init --currency USD | awk '{print $2}')
$ALICE mint --asset $ASSET --to self --amounts 60,40 --out /tmp/demo   # REAL anchor tx
$ALICE chain advance 6        # mines 6 real blocks on regtest
$ALICE receive /tmp/demo/consignment-*.bin     # → VERIFIED 100 <asset>
# send / receive / audit exactly as in the demo flow below
```

(`--fallbackfee` is needed because regtest has no fee-estimation history;
on signet/mainnet `fundrawtransaction` estimates fees normally. Bob's
`--scan-from 1` makes his fresh index cover anchors mined before his
first open.)

## Quickstart (demo chain — simulated)

The commands below play the full protocol across three wallets sharing one
demo chain file (the shared file stands in for the L1 view all clients
would get from Bitcoin). Every command prints `DEMO CHAIN — not Bitcoin`.
Proving is real: budget ~1 s for a mint, ~3 s for a transfer, ~1.5 s for a
redeem **in release** (≈100× slower in debug).

```sh
cargo build --release -p opencsv-cli
OP=target/release/opencsv
CHAIN=/tmp/demo/chain.log
ALICE="--wallet-dir /tmp/demo/alice --chain $CHAIN"
BOB="--wallet-dir /tmp/demo/bob --chain $CHAIN"

# 1. Identities and the asset (issuer = alice's wallet).
$OP $ALICE keygen                          # prints key 0 owner <hex>
$OP $BOB   keygen
$OP $ALICE issuer init --currency USD      # prints asset <hex>; save it as $ASSET

# 2. Mint 60+40 to alice, advance the demo chain past 6 confirmations,
#    deliver the blob, alice receives.
$OP $ALICE mint --asset $ASSET --to self --amounts 60,40 --out /tmp/demo
$OP $ALICE chain advance 6
$OP $ALICE receive /tmp/demo/consignment-h0-p0.bin
# → VERIFIED 100 <asset>

# 3. Alice sends 70+30 to bob (2-in/2-out transfer, ~3 s proving).
BOB_OWNER=$($OP $BOB keys | head -1 | awk '{print $4}')
$OP $ALICE send --inputs <coin-id-1>,<coin-id-2> --to $BOB_OWNER --amounts 70,30 --out /tmp/demo
$OP $ALICE chain advance 6
$OP $BOB receive /tmp/demo/consignment-h12-p0.bin
# → VERIFIED 100 <asset>

# 4. Bob redeems the 70 coin back to the issuer.
$OP $BOB coins                             # find the coin id
$OP $BOB redeem --coin <id> --out /tmp/demo
$OP $BOB chain advance 6

# 5. Public supply audit (paper §4.9): mint − redeem.
$OP $ALICE audit --asset $ASSET            # → supply 30
```

Coin ids are the hex of the coin commitment; commands accept unique
prefixes. `mint`/`send`/`redeem` write the consignment blob to `--out`
(default `.`) and print its path; `--print-blob` additionally prints it
base64 on stdout.

## Command surface

```text
opencsv [--wallet-dir <dir>] [--chain <path>] <command>

keygen                              create an owner identity (prints owner pubkey)
keys                                list owner identities
issuer init --currency USD          create issuer key + asset genesis (prints asset id)
mint  --asset <hex> --to <self|owner-hex> --amounts v1[,v2] [--out dir] [--print-blob]
send  --inputs <id,id> --to <self|owner-hex> --amounts v1[,v2] [--out dir] [--print-blob]
receive <file> [--confirmations k]  verify a consignment (prints VERIFIED/REJECTED)
redeem --coin <id> [--out dir] [--print-blob]
coins                               list stored coins (id, value, asset, status)
balance [--asset <hex>]             unspent totals per asset
assets                              list pinned assets
audit --asset <hex> [--height h]    public supply from the anchor chain (§4.9)
chain tip | chain advance [n]       tip height; advance = simulated on demo chains,
                                    real mining (generatetoaddress) on regtest,
                                    hard error on signet/mainnet
batch v2 init                       create a durable peer session and relay identity
batch v2 proposal|commitment        publish a canonical C1 body to peers
batch v2 manifest|signature         publish a source-complete manifest/share to peers
batch v2 relay                      validate, persist, deduplicate, and forward frames
batch v2 status|finalize            resume state; persist the fully signed transaction
batch v2 broadcast|mark             broadcast exact persisted tx; journal chain/delivery state
signal link [--device-name n]     link to your Signal account as a secondary device (QR)
signal send --to <dest> <file>    send a consignment blob as a Signal attachment
signal listen                     verify incoming consignments into the wallet (Ctrl-C to stop)
```

### Batching v2 peer flow

`batch v2` is the serverless C2 coordination layer over the canonical C1
proposal, participant-commitment, manifest, and signature-share bodies. Start
each peer with an independently verified genesis hash and current height:

```sh
opencsv batch v2 init --session /path/to/session \
  --chain-id <display-order-genesis-hash> --height <verified-height>
opencsv batch v2 relay --session /path/to/session \
  --listen 127.0.0.1:29001 --peer 127.0.0.1:29002
```

Use the action commands `propose`, `commit`, `manifest`, `replace`, and `sign`;
run `--help` on each for the full arguments. Those commands and the long-running
`relay` require one or more `--cbf-peer` endpoints plus a rebuildable `--cache`
directory so the session's verified tip is refreshed at each action (and after
each relay accept). `propose`, `commit`, and `sign` additionally verify the exact
public inputs through the PoW/header, BIP158, full-block, and merkle-check path,
enforce a maximum-age receipt, and persist the signer-local reservation before
publishing. Secret-key files must be raw 32-byte or hex and mode 0600 (or
stricter). Repeat `--peer` for every C2 participant.

A manifest is rejected until every source commitment is present; a signature
is rejected unless it names the exact manifest, input, key, fresh verifier
capability, local reservation, and `SIGHASH_ALL` digest. Once all shares
arrive, any peer can run:

```sh
opencsv batch v2 finalize --session /path/to/session
opencsv --network signet batch v2 broadcast --session /path/to/session
opencsv batch v2 mark --session /path/to/session \
  --phase confirmed --evidence 'height=<height>,block=<hash>'
```

The session stores every signed epoch's final consensus transaction before
broadcast and makes replay/restart idempotent. Proposal and commitment relay
frames require authorization from their committed Bitcoin keys in addition to
the separate relay identity. Exact proposal re-announcement is idempotent;
another proposal body in the same session is rejected. Relay limits are local
deployment policy keyed to authorized identities, not protocol constants.
Malformed remote frames are contained while listener/storage failures remain
fatal. The raw TCP transport is not confidential; use a protected peer channel
when metadata privacy is required. No OpenCSV-specific server is involved.

Third parties may reorder or substitute non-signature witness-envelope items
without changing the legacy txid. The ordered header/envelope commitment then
fails closed (and stripping required items makes the Bitcoin script fail), so
this is a liveness/wtxid-malleability risk rather than authorization for an
invalid OpenCSV transition. Receivers validate the exact envelope.

`--chain-id` accepts the ordinary display-order hash returned by
`bitcoin-cli getblockhash 0`; the CLI converts it to the transaction-
serialization order committed by the C1 wire protocol.

The `signal` subcommands live behind the cargo feature `signal` (default
ON); build with `--no-default-features` for a lean, Signal-free binary. The
Signal store defaults to `<wallet-dir>/signal`. Recipient `<dest>` is
`self` (Note to Self), an ACI uuid, or an E.164 phone number. See
[`crates/opencsv-signal/README.md`](../opencsv-signal/README.md) for the
linking walkthrough and a two-terminal demo. Note the `signal` feature
pulls in presage (AGPL-3.0) and needs `protoc` to build.

Defaults: `--wallet-dir ~/.opencsv`, `--chain bitcoin` (real bitcoind RPC;
the demo file chain needs an explicit `--chain demo` / `--chain
file:<path>`), `--network signet`, `--confirmations 6` (paper §4.7 rule 2).

Notes on the fixed circuit shapes: mints and transfers are 2-output and
transfers are 2-input (a missing second amount pads a zero-value output to
the same recipient; transfer outputs must sum to the inputs). `send` has a
hidden `--force-respend` that skips the local spent check — it exists to
demonstrate double-spend *detection* (the second anchor loses to
first-occurrence — recognized via the raw nullifiers, whose on-chain
payloads are context-bound and unlinkable — and its consignment is rejected
with `NullifierConflict`).

## Wallet directory layout

All files are bincode (serde data model) unless noted.

```text
<wallet-dir>/
├── keys.bin                 # Vec<OwnerSecret> — owner identities (SECRET)
├── issuers.bin              # Vec<IssuerRecord> — issuer seed + AssetGenesis (SECRET)
├── assets/<asset_id>.genesis       # pinned AssetGenesis (trust-on-first-use, §4.2)
├── coins/<commitment>.coin         # StoredCoin { coin, status, proof, selector, anchor }
├── consignments/<h>-<p>-<txid>.bin # raw received consignment blobs
├── bitcoin-index-<network>.log     # bitcoind backend: scanned-anchor index (rebuildable cache)
└── chain.log                # FileAnchorChain (demo backend only)
```

Batching-v2 sessions are intentionally separate from the wallet directory.
Each session holds mode-0600 relay identity material, the independent chain
snapshot, content-addressed frames, canonical protocol bodies, an append-only
event receipt, and the finalized transaction. Only one process owns a session
directory at a time.

- `coins/*.coin` stores the **creating proof** (the `encode_coin_proof`
  envelope) and the output selector — both are needed to present the coin's
  ancestry as the in-circuit predecessor when spending
  (`opencsv_pcd::decode_coin_proof`).
- Nullifier occurrences are not indexed: they are derived state, recognized
  by scanning the anchor log/index and testing each entry's bound payload
  against the raw nullifier under the entry's `ctx`.
- `receive` is idempotent and preserves local spent state: redelivery of a
  consignment for coins you already spent does not resurrect them.

## File formats

- **Consignment blob**: `opencsv_core::Consignment::to_bytes()` (bincode):
  coin openings, the opaque proof bytes (a `postcard` envelope carrying the
  full statement + the batch-STARK proof, see `opencsv-pcd/src/accept.rs`),
  the anchor ref, and optional genesis `aux`. Treat as opaque.
- **Anchor index** (`bitcoin-index-<network>.log`): text —
  `opencsv-bitcoin-index-v1` magic, `network`/`start`/`scanned <h> <hash>`
  markers, and `entry <height> <position> <txid-hex> <ctx-hex> <record-hex>`
  anchors mined from real blocks. Rebuilt from the chain whenever missing
  or stale; txids are display-order hex.
- **Chain log** (`chain.log`, demo backend): text, one record per line —
  `opencsv-chain-v3` magic, `tip <height>` markers, and
  `entry <height> <position> <txid-hex> <ctx-hex> <record-hex>` anchors (the
  record is the 64-byte anchor of paper §4.4–4.6, hex-encoded; `ctx` is the
  32-byte transaction context the record's bound nullifier payloads commit
  to — see `opencsv-core`'s anchor docs). Append-only; corrupt lines fail to
  load. Version 1/2 logs predate the bound-payload model and are rejected
  with a clear error rather than migrated — start a fresh chain file.

## Security caveats

- **Plaintext secrets.** `keys.bin` and `issuers.bin` hold unencrypted owner
  and issuer keys. Protect the directory (`chmod 700`) yourself; real key
  management is future work.
- **bitcoind backend trust model.** The node is trusted for chain data
  (block contents, heights) — a malicious node can withhold anchors but
  cannot forge them: records verify against the consignment's proof and
  the bound-payload rules, and occurrence/confirmation checks fail closed.
  Scan coverage is bounded by `--scan-from` and the node's prune horizon —
  an anchor older than the index start is invisible until the recipient
  rescans from a lower height.
- **File-backed demo anchor.** `FileAnchorChain` is not Bitcoin. It matches
  `MockAnchorChain`'s semantics — append to the current tip block, explicit
  `chain advance`, confirmations `tip − height + 1`, a per-anchor random
  transaction context, and raw-nullifier occurrence recognition via bound
  payloads (only consignment holders can recognize their nullifiers) — but
  anyone can write the file, there is no PoW, no
  reorg model, and no file locking. Multi-wallet demos must share one chain
  file via `--chain` (a consignment's `anchor_ref` is meaningless against a
  chain that never saw the anchor). Demo confirmations are simulated:
  nothing advances the demo tip except `chain advance`.
- **Mint authorization is proof-native.** `mint` passes the issuer seed and
  genesis to the version-3 mint circuit, which proves seed control, derives
  the asset id, and binds the exact statement. No standalone signature field
  is omitted from the consignment. Stored legacy Ed25519 issuer records fail
  explicitly at new-mint proving and remain read/export-only.
- **vk binding.** `CoinProofVerifier` requires the frozen v3 lineage/profile
  tag and rejects legacy tags. Proofs still self-describe their root common
  data; see `opencsv-pcd`'s README for the remaining root-circuit commitment
  registration boundary.

## What a Signal transport plugs into

The transport moves opaque blobs; the wallet does everything else
(`src/ops.rs`):

- **Produce a blob to send** — call `ops::mint` / `ops::send` /
  `ops::redeem` (they prove and anchor), then
  `produced.consignment.to_bytes()` and ship the bytes:

  ```rust
  let produced = ops::send(&mut wallet, &mut chain, &input_ids, to, &amounts, false)?;
  let blob: Vec<u8> = produced.consignment.to_bytes();   // → Signal message
  ```

- **Ingest a received blob** — call `ops::receive` with the raw bytes and
  the real verifier; on `ReceiveReport::Verified` the coins, the asset pin,
  and the archived blob are already stored:

  ```rust
  match ops::receive(&mut wallet, &chain, &opencsv_pcd::CoinProofVerifier, &blob, 6)? {
      ReceiveReport::Verified { credits, .. } => { /* credit UI */ }
      ReceiveReport::Rejected(reason)         => { /* show rejection */ }
  }
  ```

The transport must also arrange a shared chain view (the default bitcoind
backend; one `--chain` file for demos) and surface progress during proving
(~3 s per transfer in release).

## Tests

```sh
cargo test -p opencsv-cli                 # fast: chain semantics, mock-proof
                                          # scripted flow, binary smoke
cargo test -p opencsv-bitcoin             # RPC/scan/two-pass logic vs canned
                                          # bitcoind responses (stubbed HTTP)
cargo test --release -p opencsv-cli --test e2e -- --ignored --nocapture
                                          # full flow with REAL proofs (~15 s)
scripts/e2e-regtest.sh                    # full flow against a REAL bitcoind
                                          # -regtest (broadcast anchors, mining)
```

`tests/e2e.rs` is `#[ignore]`d by default because debug proving takes
minutes; always run it in release.
