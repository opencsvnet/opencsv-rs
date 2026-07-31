#!/bin/sh
# Build OpenCsv.xcframework from the opencsv-ffi staticlib (device + Simulator).
#
# Usage: apple/build-xcframework.sh [output-dir]   (default: apple/)
#
# Requires: rustup targets aarch64-apple-ios and aarch64-apple-ios-sim, and
# full Xcode (xcodebuild -create-xcframework). Modeled on libsignal's
# packaging: one static library per platform slice, shared C headers.
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
out_dir="${1:-$repo_root/apple}"
lib=libopencsv_ffi.a
headers="$repo_root/ffi/include"

for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    echo ">> cargo build --release --target $target -p opencsv-ffi"
    cargo build --release --target "$target" -p opencsv-ffi \
        --manifest-path "$repo_root/Cargo.toml"
done

rm -rf "$out_dir/OpenCsv.xcframework"
xcodebuild -create-xcframework \
    -library "$repo_root/target/aarch64-apple-ios/release/$lib" -headers "$headers" \
    -library "$repo_root/target/aarch64-apple-ios-sim/release/$lib" -headers "$headers" \
    -output "$out_dir/OpenCsv.xcframework"

echo ">> $out_dir/OpenCsv.xcframework"
