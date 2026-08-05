#!/bin/sh
# Build OpenCsv.xcframework from the opencsv-ffi staticlib (device + Simulator).
#
# Usage: apple/build-xcframework.sh [output-dir]   (default: apple/)
#
# Requires: rustup targets aarch64-apple-ios and aarch64-apple-ios-sim, and
# full Xcode (xcodebuild -create-xcframework). Modeled on libsignal's
# packaging: one static library per platform slice, shared C headers.
set -eu

# Rust and native dependencies must agree with the consuming Signal target.
# Without this, rustc/cc inherit the build host's current SDK version and the
# resulting archive is stamped (for example) iOS 26.5, which Xcode correctly
# rejects under warnings-as-errors when Signal links it for iOS 15.
IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"
export IPHONEOS_DEPLOYMENT_TARGET

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
    if [ "${OPENCSV_TEST_WALLET_RECOVERY:-0}" = "1" ]; then
        echo ">> cargo build --release --target $target -p opencsv-ffi --features test-wallet-recovery"
        cargo build --release --target "$target" -p opencsv-ffi \
            --features test-wallet-recovery \
            --manifest-path "$repo_root/Cargo.toml"
    else
        echo ">> cargo build --release --target $target -p opencsv-ffi"
        cargo build --release --target "$target" -p opencsv-ffi \
            --manifest-path "$repo_root/Cargo.toml"
    fi
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

if [ -n "${OPENCSV_BUILD_SOURCE_ID:-}" ]; then
    printf '%s\n' "$OPENCSV_BUILD_SOURCE_ID" > "$out_dir/OpenCsv.xcframework.build-mode"
elif [ "${OPENCSV_TEST_WALLET_RECOVERY:-0}" = "1" ]; then
    printf '%s\n' test-wallet-recovery > "$out_dir/OpenCsv.xcframework.build-mode"
else
    printf '%s\n' default > "$out_dir/OpenCsv.xcframework.build-mode"
fi

echo ">> $out_dir/OpenCsv.xcframework"
