#!/usr/bin/env bash
# End-to-end validation of the OpenCSV bitcoind backend against a fresh
# regtest node. Everything here is REAL: a real bitcoind, real broadcast
# anchor transactions (OP_RETURN), real block mining, and the real CLI
# flow — no mocks, no simulated chain.
#
# Flow: start bitcoind -regtest → fund the wallet → issuer init → mint
# (real anchor tx) → mine → 2-in/2-out send to a second wallet → mine 6 →
# receive VERIFIED → double-spend attempt → receive REJECTED
# (first-occurrence, resolved from node data) → supply audit from chain
# data.
#
# Rerunnable: wipes /tmp/opencsv-regtest{,-alice,-bob,-out} each run.
#
# Usage: scripts/e2e-regtest.sh [path-to-opencsv-binary]
#   Default binary: target/release/opencsv (build with
#   `cargo build --release -p opencsv-cli`).

set -euo pipefail

BITCOIN_CORE_HOME="${BITCOIN_CORE_HOME:-$HOME/bitcoin-core}"
BITCOIND="$BITCOIN_CORE_HOME/bin/bitcoind"
BITCOIN_CLI="$BITCOIN_CORE_HOME/bin/bitcoin-cli"
OP="${1:-$(dirname "$0")/../target/release/opencsv}"
OP="$(realpath "$OP")"

DATADIR=/tmp/opencsv-regtest
ALICE=/tmp/opencsv-regtest-alice
BOB=/tmp/opencsv-regtest-bob
OUT=/tmp/opencsv-regtest-out
RPC_PORT=28443
CLI_ARGS=(--network regtest --rpc-url "http://127.0.0.1:$RPC_PORT" --cookie "$DATADIR/regtest/.cookie" --rpc-wallet opencsv)

log() { printf '\n=== %s ===\n' "$*"; }

cleanup() {
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" stop 2>/dev/null || true
}
trap cleanup EXIT

log "start bitcoind -regtest (datadir $DATADIR)"
rm -rf "$DATADIR" "$ALICE" "$BOB" "$OUT"
mkdir -p "$DATADIR" "$OUT"
"$BITCOIND" -regtest -datadir="$DATADIR" -daemon -server -rpcport="$RPC_PORT" \
    -fallbackfee=0.00001 -txindex=0 -blockfilterindex=0
for i in $(seq 1 60); do
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" getblockcount >/dev/null 2>&1 && break
    sleep 0.5
done
BTC=("$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" -rpcwallet=opencsv)

log "create wallet and mine 101 blocks (spendable funds)"
"$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" createwallet opencsv >/dev/null
ADDR=$("${BTC[@]}" getnewaddress)
"${BTC[@]}" generatetoaddress 101 "$ADDR" >/dev/null
"${BTC[@]}" getbalances | head -5

log "alice: keygen + issuer init"
$OP --wallet-dir "$ALICE" keygen
$OP --wallet-dir "$BOB" keygen
ASSET=$($OP --wallet-dir "$ALICE" issuer init --currency USD | awk '{print $2}')
echo "asset $ASSET"

log "alice mints 100+50 to self (REAL anchor tx broadcast)"
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" mint --asset "$ASSET" --to self --amounts 100,50 --out "$OUT"

log "mine 6 blocks; alice receives her own mint (6 confirmations)"
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" chain advance 6
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" receive "$OUT"/consignment-*.bin

log "alice sends 70+80 to bob (2-in/2-out, real anchor tx)"
BOB_OWNER=$($OP --wallet-dir "$BOB" keys | head -1 | awk '{print $4}')
INPUTS=$($OP --wallet-dir "$ALICE" coins | awk '{print $2}' | paste -sd, -)
echo "inputs: $INPUTS"
rm -f "$OUT"/consignment-*.bin
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" send --inputs "$INPUTS" --to "$BOB_OWNER" --amounts 70,80 --out "$OUT"

log "mine 6 blocks; bob receives (VERIFIED expected)"
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" chain advance 6
SEND_BLOB=$(ls "$OUT"/consignment-*.bin)
cp "$SEND_BLOB" "$OUT/send.bin"
# Bob's wallet is new: scan from a height covering the anchor (the local
# index starts at the tip by default — see the README's scanning notes).
$OP --wallet-dir "$BOB" "${CLI_ARGS[@]}" --scan-from 101 receive "$OUT/send.bin"

log "double-spend attempt: alice re-anchors the same inputs (--force-respend)"
rm -f "$OUT"/consignment-*.bin
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" send --inputs "$INPUTS" --to self --amounts 150 --force-respend --out "$OUT"
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" chain advance 6

log "bob receives the double-spend consignment (REJECTED expected: first occurrence wins)"
if $OP --wallet-dir "$BOB" "${CLI_ARGS[@]}" --scan-from 101 receive "$OUT"/consignment-*.bin; then
    echo "E2E FAILURE: double-spend consignment was accepted" >&2
    exit 1
fi

log "supply audit from chain data (expect 150)"
$OP --wallet-dir "$ALICE" "${CLI_ARGS[@]}" audit --asset "$ASSET"

log "anchor index contents (rebuildable cache)"
cat "$ALICE/bitcoin-index-regtest.log"

log "E2E SUCCESS"
