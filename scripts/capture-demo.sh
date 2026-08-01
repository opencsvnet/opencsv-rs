#!/usr/bin/env bash
# Capture the OpenCSV CLI demo screenshots from a REAL regtest flow:
# a fresh bitcoind -regtest, real broadcast anchor transactions, real
# mining — no demo chain, no mocks. Writes mint.png, receive.png, and
# send-double-spend-audit.png into <output-dir>.
#
# Scenes (identical to the site's "See it working" section):
#   issuer init → mint 100 to bob → 6 blocks → bob receive VERIFIED →
#   bob send 60,40 → issuer receive VERIFIED → force-respend double-spend
#   REJECTED (first occurrence) → supply audit from chain data.
#
# Requirements (clean ubuntu-latest suffices): cargo (+protoc for the
# first CLI build), tmux, python3 with PIL, bitcoind/bitcoin-cli on PATH.
#
# Idempotent: every run uses a fresh mktemp workdir and overwrites the
# three PNGs. The node and tmux session are always torn down on exit.
#
# Env overrides:
#   BITCOIND, BITCOIN_CLI   binaries (default: from PATH)
#   OPENCSV_BIN             CLI binary (default: target/release/opencsv,
#                           built with cargo if missing)
#   CAPTURE_WORKDIR         scratch dir (default: mktemp -d)
#   CAPTURE_DATADIR         bitcoind datadir (default: $WORKDIR/regtest)
#   CAPTURE_RPC_PORT        regtest RPC port (default: 28443)
#   CAPTURE_KEEP_WORKDIR=1  keep the workdir on success (debugging)

set -euo pipefail

OUT_DIR="${1:?usage: capture-demo.sh <output-dir>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RENDERER="$REPO_ROOT/scripts/render-terminal.py"

BITCOIND="${BITCOIND:-bitcoind}"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
OPENCSV_BIN="${OPENCSV_BIN:-$REPO_ROOT/target/release/opencsv}"
WORKDIR="${CAPTURE_WORKDIR:-$(mktemp -d /tmp/opencsv-capture.XXXXXX)}"
DATADIR="${CAPTURE_DATADIR:-$WORKDIR/regtest}"
RPC_PORT="${CAPTURE_RPC_PORT:-28443}"
TMUX_SESSION="opencsv-capture-$$"

log() { printf '\n=== %s ===\n' "$*"; }

cleanup() {
    local rc=$?
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" stop >/dev/null 2>&1 || true
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    if [ "$rc" -eq 0 ] && [ "${CAPTURE_KEEP_WORKDIR:-0}" != 1 ]; then
        rm -rf "$WORKDIR"
    else
        echo "workdir kept: $WORKDIR" >&2
    fi
}
trap cleanup EXIT

if [ ! -x "$OPENCSV_BIN" ]; then
    log "build the CLI (release) — missing $OPENCSV_BIN"
    (cd "$REPO_ROOT" && cargo build --release -p opencsv-cli)
fi
OPENCSV_BIN="$(realpath "$OPENCSV_BIN")"

# ---------------------------------------------------------------- node ---

log "start bitcoind -regtest (datadir $DATADIR, port $RPC_PORT)"
mkdir -p "$DATADIR" "$WORKDIR/out/mint" "$WORKDIR/out/send" "$WORKDIR/out/double" "$OUT_DIR"
"$BITCOIND" -regtest -datadir="$DATADIR" -daemon -server \
    -rpcport="$RPC_PORT" -fallbackfee=0.00001
for _ in $(seq 1 60); do
    "$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" \
        getblockcount >/dev/null 2>&1 && break
    sleep 0.5
done
"$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" getblockcount >/dev/null
"$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" createwallet opencsv >/dev/null
BCLI=("$BITCOIN_CLI" -regtest -datadir="$DATADIR" -rpcport="$RPC_PORT" -rpcwallet=opencsv)
"${BCLI[@]}" generatetoaddress 101 "$("${BCLI[@]}" getnewaddress)" >/dev/null
log "node funded: $("${BCLI[@]}" getblockcount) blocks"

# -------------------------------------------------- wallets (off-screen) ---

export OPENCSV_NETWORK=regtest
export OPENCSV_RPC_URL="http://127.0.0.1:$RPC_PORT"
export OPENCSV_COOKIE="$DATADIR/regtest/.cookie"
export OPENCSV_RPC_WALLET=opencsv

"$OPENCSV_BIN" --wallet-dir "$WORKDIR/issuer" keygen >/dev/null
"$OPENCSV_BIN" --wallet-dir "$WORKDIR/bob" keygen >/dev/null
ALICE="$("$OPENCSV_BIN" --wallet-dir "$WORKDIR/issuer" keys | awk '{print $4}')"
BOB="$("$OPENCSV_BIN" --wallet-dir "$WORKDIR/bob" keys | awk '{print $4}')"
# Bob establishes his anchor index before the mint exists (start = tip
# 101), so his later receive rescans pick the anchor up.
"$OPENCSV_BIN" --wallet-dir "$WORKDIR/bob" chain tip >/dev/null

# ------------------------------------------------------------ tmux run ---

tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
tmux new-session -d -s "$TMUX_SESSION" -x 132 -y 40

prompt_count() { tmux capture-pane -p -t "$TMUX_SESSION" | grep -cE '^[a-z]+ \$' || true; }

# Instant shell builtins (exports, cd, clear, PS1 changes, comments):
# type and give the pane a moment — no output to wait for.
fast_cmd() {
    tmux send-keys -t "$TMUX_SESSION" "$1" Enter
    sleep 0.6
}

# Type a command into the pane and wait for the prompt to return (i.e.
# for the command to finish — robust across machine speeds). Requires the
# custom PS1 to be active (fast_cmd sets it before any run_in_tmux call).
run_in_tmux() {
    local before now
    before="$(prompt_count)"
    tmux send-keys -t "$TMUX_SESSION" "$1" Enter
    for _ in $(seq 1 1200); do
        sleep 0.5
        now="$(prompt_count)"
        if [ "$now" -gt "$before" ]; then
            return 0
        fi
    done
    echo "timeout waiting for command: $1" >&2
    return 1
}

BITCOIN_CLI_DIR="$(dirname "$(command -v "$BITCOIN_CLI")")"
fast_cmd 'export PATH="'"$(dirname "$OPENCSV_BIN"):$BITCOIN_CLI_DIR"':$PATH"'
fast_cmd 'cd '"$WORKDIR"
# Owner keys as shell vars so the typed commands stay short ($BOB/$ALICE
# appear literally in the captures, as a user would write them).
fast_cmd 'BOB='"$BOB"
fast_cmd 'ALICE='"$ALICE"
fast_cmd 'export PS1='"'"'issuer $ '"'"
fast_cmd 'clear'
tmux clear-history -t "$TMUX_SESSION"
sleep 0.5

log "scene 1: issuer init + mint (real anchor tx) + confirmation"
fast_cmd 'export OPENCSV_NETWORK=regtest OPENCSV_RPC_URL=http://127.0.0.1:'"$RPC_PORT"' OPENCSV_RPC_WALLET=opencsv'
fast_cmd 'export OPENCSV_COOKIE=regtest/regtest/.cookie'
run_in_tmux 'ASSET=$(opencsv --wallet-dir issuer issuer init --currency USD | cut -d" " -f2)'
run_in_tmux 'echo "asset $ASSET"'
run_in_tmux 'opencsv --wallet-dir issuer mint --asset $ASSET --to $BOB --amounts 100 --out out/mint'
run_in_tmux 'opencsv --wallet-dir issuer chain advance 6'
run_in_tmux 'TXID=$(grep entry issuer/bitcoin-index-regtest.log | tail -1 | cut -d" " -f4)'
fast_cmd 'BTC="bitcoin-cli -regtest -datadir=regtest -rpcport='"$RPC_PORT"' -rpcwallet=opencsv"'
run_in_tmux '$BTC gettransaction $TXID | grep -E "txid|confirmations"'
tmux capture-pane -p -t "$TMUX_SESSION" > "$WORKDIR/cap-mint.txt"
grep -q '^asset [0-9a-f]\{64\}$' "$WORKDIR/cap-mint.txt"
grep -q '^anchor broadcast .* tx [0-9a-f]\{64\}$' "$WORKDIR/cap-mint.txt"
grep -q '"confirmations": 6,' "$WORKDIR/cap-mint.txt"

log "scene 2: bob receives (VERIFIED) + coins + balance"
fast_cmd 'export PS1='"'"'bob $ '"'"
fast_cmd 'clear'
tmux clear-history -t "$TMUX_SESSION"
sleep 0.5
run_in_tmux 'opencsv --wallet-dir bob keys'
run_in_tmux 'opencsv --wallet-dir bob receive out/mint/consignment-h0-p0.bin'
run_in_tmux 'opencsv --wallet-dir bob coins'
run_in_tmux 'opencsv --wallet-dir bob balance'
tmux capture-pane -p -t "$TMUX_SESSION" > "$WORKDIR/cap-receive.txt"
grep -q '^VERIFIED 100 [0-9a-f]\{64\}$' "$WORKDIR/cap-receive.txt"
grep -q '^100 [0-9a-f]\{64\}$' "$WORKDIR/cap-receive.txt"

log "scene 3: send 60,40 → VERIFIED; double-spend → REJECTED; audit"
fast_cmd 'clear'
tmux clear-history -t "$TMUX_SESSION"
sleep 0.5
run_in_tmux 'INPUTS=$(opencsv --wallet-dir bob coins | cut -d" " -f2 | paste -sd,)'
run_in_tmux 'opencsv --wallet-dir bob send --inputs $INPUTS --to $ALICE --amounts 60,40 --out out/send'
run_in_tmux 'opencsv --wallet-dir bob chain advance 6'
fast_cmd 'export PS1='"'"'issuer $ '"'"
run_in_tmux 'opencsv --wallet-dir issuer receive out/send/consignment-h0-p0.bin'
fast_cmd '# double-spend attempt: bob re-anchors the same nullifiers'
fast_cmd 'export PS1='"'"'bob $ '"'"
run_in_tmux 'opencsv --wallet-dir bob send --inputs $INPUTS --to $BOB --amounts 100 --force-respend --out out/double'
run_in_tmux 'opencsv --wallet-dir bob chain advance 6'
fast_cmd 'export PS1='"'"'issuer $ '"'"
run_in_tmux 'opencsv --wallet-dir issuer receive out/double/consignment-h0-p0.bin'
run_in_tmux 'opencsv --wallet-dir issuer audit --asset $ASSET'
tmux capture-pane -p -t "$TMUX_SESSION" > "$WORKDIR/cap-send.txt"
grep -q '^VERIFIED 100 [0-9a-f]\{64\}$' "$WORKDIR/cap-send.txt"
grep -q '^REJECTED nullifier already occurred earlier at AnchorLocation' "$WORKDIR/cap-send.txt"
grep -q '^supply 100 asset [0-9a-f]\{64\} height [0-9]\+$' "$WORKDIR/cap-send.txt"

# ------------------------------------------------------------ render ---

log "render PNGs → $OUT_DIR"
python3 "$RENDERER" --input "$WORKDIR/cap-mint.txt" --output "$OUT_DIR/mint.png"
python3 "$RENDERER" --input "$WORKDIR/cap-receive.txt" --output "$OUT_DIR/receive.png"
python3 "$RENDERER" --input "$WORKDIR/cap-send.txt" --output "$OUT_DIR/send-double-spend-audit.png"

log "CAPTURE SUCCESS"
