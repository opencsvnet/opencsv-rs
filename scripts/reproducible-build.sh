#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [--verify] [output-directory]" >&2
    exit 2
}

verify=0
if [ "${1:-}" = "--verify" ]; then
    verify=1
    shift
fi
if [ "$#" -gt 1 ]; then
    usage
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir=${1:-"$repo_root/dist/reproducible"}
case "$output_dir" in
    /*) ;;
    *) output_dir="$repo_root/$output_dir" ;;
esac

dirty=0
if ! git -C "$repo_root" diff --quiet || \
   ! git -C "$repo_root" diff --cached --quiet || \
   [ -n "$(git -C "$repo_root" ls-files --others --exclude-standard)" ]; then
    dirty=1
fi
if [ "$dirty" -eq 1 ] && [ "${OPENCSV_ALLOW_DIRTY:-0}" != "1" ]; then
    echo "refusing to package a dirty tree; commit it or set OPENCSV_ALLOW_DIRTY=1 for a non-release diagnostic" >&2
    exit 1
fi

source_date_epoch=$(git -C "$repo_root" log -1 --pretty=%ct)
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/opencsv-repro.XXXXXX")
trap 'rm -rf -- "$temporary_root"' EXIT HUP INT TERM

repro_flags="-Dwarnings --remap-path-prefix=$repo_root=/src/opencsv"

build_pair() {
    target_dir=$1
    destination=$2
    target_flags="$repro_flags --remap-path-prefix=$target_dir=/build/target"
    mkdir -p "$destination"
    (
        cd "$repo_root"
        SOURCE_DATE_EPOCH="$source_date_epoch" \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$target_dir" \
        RUSTFLAGS="$target_flags" \
        LC_ALL=C \
        TZ=UTC \
        cargo build --locked --release -p opencsv-cli --features signal
    )
    cp "$target_dir/release/opencsv" "$destination/opencsv-signal"
    (
        cd "$repo_root"
        SOURCE_DATE_EPOCH="$source_date_epoch" \
        CARGO_INCREMENTAL=0 \
        CARGO_TARGET_DIR="$target_dir" \
        RUSTFLAGS="$target_flags" \
        LC_ALL=C \
        TZ=UTC \
        cargo build --locked --release -p opencsv-cli --no-default-features
    )
    cp "$target_dir/release/opencsv" "$destination/opencsv-core"
}

first="$temporary_root/first"
build_pair "$temporary_root/target-a" "$first"

if [ "$verify" -eq 1 ]; then
    second="$temporary_root/second"
    build_pair "$temporary_root/target-b" "$second"
    cmp "$first/opencsv-signal" "$second/opencsv-signal"
    cmp "$first/opencsv-core" "$second/opencsv-core"
fi

mkdir -p "$output_dir"
cp "$first/opencsv-signal" "$output_dir/opencsv-signal"
cp "$first/opencsv-core" "$output_dir/opencsv-core"
(
    cd "$output_dir"
    shasum -a 256 opencsv-signal opencsv-core > SHA256SUMS
)
{
    echo "git_commit=$(git -C "$repo_root" rev-parse HEAD)"
    echo "source_date_epoch=$source_date_epoch"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
    echo "protoc=$(protoc --version 2>/dev/null || echo unavailable)"
    echo "verified_twice=$verify"
    echo "dirty_tree=$dirty"
} > "$output_dir/PROVENANCE.txt"

echo "reference artifacts: $output_dir"
cat "$output_dir/SHA256SUMS"
