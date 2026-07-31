# opencsv-cli

A text wallet client for **OpenCSV** — client-side verified RWAs
anchored to Bitcoin L1 with recursive PCD proofs (see `paper/opencsv.md`).
The binary is a thin shell over this crate's library: all wallet logic lives
in the lib target so a future Signal transport crate can reuse it and only
move consignment blobs.

**Prototype-grade.** Secrets are stored unencrypted, the anchor chain is a
local file simulating Bitcoin, and confirmations are simulated. Do not use
with real funds.

## Quickstart

The commands below play the full protocol across three wallets sharing one
demo chain file (the shared file stands in for the L1 view all clients
would get from Bitcoin). Proving is real: budget ~1 s for a mint, ~3 s for a
transfer, ~1.5 s for a redeem **in release** (≈100× slower in debug).

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
chain tip | chain advance [n]       demo chain control (simulated mining)
signal link [--device-name n]     link to your Signal account as a secondary device (QR)
signal send --to <dest> <file>    send a consignment blob as a Signal attachment
signal listen                     verify incoming consignments into the wallet (Ctrl-C to stop)
```

The `signal` subcommands live behind the cargo feature `signal` (default
ON); build with `--no-default-features` for a lean, Signal-free binary. The
Signal store defaults to `<wallet-dir>/signal`. Recipient `<dest>` is
`self` (Note to Self), an ACI uuid, or an E.164 phone number. See
[`crates/opencsv-signal/README.md`](../opencsv-signal/README.md) for the
linking walkthrough and a two-terminal demo. Note the `signal` feature
pulls in presage (AGPL-3.0) and needs `protoc` to build.

Defaults: `--wallet-dir ~/.opencsv`, `--chain <wallet-dir>/chain.log`,
`--confirmations 6` (paper §4.7 rule 2).

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
├── issuers.bin              # Vec<IssuerRecord> — Ed25519 isk + AssetGenesis (SECRET)
├── assets/<asset_id>.genesis       # pinned AssetGenesis (trust-on-first-use, §4.2)
├── coins/<commitment>.coin         # StoredCoin { coin, status, proof, selector, anchor }
├── consignments/<h>-<p>-<txid>.bin # raw received consignment blobs
└── chain.log                # FileAnchorChain (unless --chain points elsewhere)
```

- `coins/*.coin` stores the **creating proof** (the `encode_coin_proof`
  envelope) and the output selector — both are needed to present the coin's
  ancestry as the in-circuit predecessor when spending
  (`opencsv_pcd::decode_coin_proof`).
- Nullifier occurrences are not indexed: they are derived state, recognized
  by scanning `chain.log` and testing each entry's bound payload against
  the raw nullifier under the entry's `ctx`.
- `receive` is idempotent and preserves local spent state: redelivery of a
  consignment for coins you already spent does not resurrect them.

## File formats

- **Consignment blob**: `opencsv_core::Consignment::to_bytes()` (bincode):
  coin openings, the opaque proof bytes (a `postcard` envelope carrying the
  full statement + the batch-STARK proof, see `opencsv-pcd/src/accept.rs`),
  the anchor ref, and optional genesis `aux`. Treat as opaque.
- **Chain log** (`chain.log`): text, one record per line —
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
- **File-backed demo anchor.** `FileAnchorChain` is not Bitcoin. It matches
  `MockAnchorChain`'s semantics — append to the current tip block, explicit
  `chain advance`, confirmations `tip − height + 1`, a per-anchor random
  transaction context, and raw-nullifier occurrence recognition via bound
  payloads (only consignment holders can recognize their nullifiers) — but
  anyone can write the file, there is no PoW, no
  reorg model, and no file locking. Multi-wallet demos must share one chain
  file via `--chain` (a consignment's `anchor_ref` is meaningless against a
  chain that never saw the anchor).
- **Confirmations are simulated.** Nothing advances the tip except
  `chain advance`.
- **Mint authorization signature is not propagated.** `mint` produces and
  self-checks the Ed25519 signature over `(asset_id, V, mint_nonce)` (paper
  §4.4 item 1), but `Consignment`/`accept` have no field for it, so
  recipients do not verify it yet. (The `opencsv-pcd` README says the accept
  driver checks it — that is aspirational; the check does not exist in
  `opencsv-core` today.) The production target is in-AIR verification of an
  AIR-native signature.
- **vk binding.** The `CoinProofVerifier` adapter ignores the `vk` argument
  and proofs self-describe their common data — see `opencsv-pcd`'s README
  for the current vk-binding caveats.

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

The transport must also arrange a shared chain view (here: one `--chain`
file; production: `bitcoind`) and surface progress during proving (~3 s per
transfer in release).

## Tests

```sh
cargo test -p opencsv-cli                 # fast: chain semantics, mock-proof
                                          # scripted flow, binary smoke
cargo test --release -p opencsv-cli --test e2e -- --ignored --nocapture
                                          # full flow with REAL proofs (~15 s)
```

`tests/e2e.rs` is `#[ignore]`d by default because debug proving takes
minutes; always run it in release.
