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
mkdir -p "$out_dir"
out_dir="$(CDPATH= cd -- "$out_dir" && pwd)"

# xcodebuild needs a full Xcode. If xcode-select points at the Command Line
# Tools (common, and what a plain `pod install` machine may have), fall back
# to an installed Xcode rather than failing with a cryptic error.
if ! xcodebuild -version >/dev/null 2>&1; then
    for candidate in /Applications/Xcode*.app; do
        if [ -d "$candidate/Contents/Developer" ]; then
            DEVELOPER_DIR="$candidate/Contents/Developer"
            export DEVELOPER_DIR
            break
        fi
    done
fi
if ! xcodebuild -version >/dev/null 2>&1; then
    echo "error: OpenCsv needs a full Xcode to build its xcframework" >&2
    echo "       (install Xcode, then: sudo xcode-select -s /Applications/Xcode.app)" >&2
    exit 1
fi
lib=libopencsv_ffi.a
headers="$repo_root/ffi/include"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
    # Adding an already-installed target is a no-op, so this is safe to
    # run unconditionally (a fresh `pod install` machine will need it).
    rustup target add "$target" >/dev/null 2>&1 || true
    echo ">> cargo build --release --target $target -p opencsv-ffi"
    cargo build --release --target "$target" -p opencsv-ffi \
        --manifest-path "$repo_root/Cargo.toml"
done

# Universal simulator slice (arm64 + x86_64), as Xcode's generic simulator
# destination builds both architectures.
sim_universal="$repo_root/target/ios-sim-universal"
mkdir -p "$sim_universal"
lipo -create \
    "$repo_root/target/aarch64-apple-ios-sim/release/$lib" \
    "$repo_root/target/x86_64-apple-ios/release/$lib" \
    -output "$sim_universal/$lib"

rm -rf "$out_dir/OpenCsv.xcframework"
xcodebuild -create-xcframework \
    -library "$repo_root/target/aarch64-apple-ios/release/$lib" -headers "$headers" \
    -library "$sim_universal/$lib" -headers "$headers" \
    -output "$out_dir/OpenCsv.xcframework"

echo ">> $out_dir/OpenCsv.xcframework"
