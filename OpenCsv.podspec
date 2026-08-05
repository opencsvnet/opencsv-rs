#
# OpenCSV wallet FFI as a CocoaPods dependency.
#
# The pod is built **from source** at whatever revision the consumer pins:
# `prepare_command` runs cargo for the device and simulator targets and
# assembles OpenCsv.xcframework. There is no prebuilt binary to host and no
# checksum to rotate — the pinned git revision is the integrity guarantee.
#
#   pod 'OpenCsv', git: 'https://github.com/opencsvnet/opencsv-rs.git',
#                  commit: '<sha>'
#
# Cost of this choice, which consumers should know up front: a Rust
# toolchain is required, and the first `pod install` compiles the whole
# Plonky3 + recursion stack (several minutes). A project that would rather
# not pay that at install time should host a prebuilt xcframework and pin it
# by checksum, the way LibSignalClient does.
#
Pod::Spec.new do |s|
  s.name             = 'OpenCsv'
  s.version          = '0.1.0'
  s.summary          = 'OpenCSV wallet: client-side verified RWAs on Bitcoin (Rust core, C ABI).'
  s.homepage         = 'https://github.com/opencsvnet/opencsv-rs'
  s.license          = { type: 'MIT OR Apache-2.0', text: 'MIT OR Apache-2.0' }
  s.author           = 'OpenCSV'
  s.source           = { git: 'https://github.com/opencsvnet/opencsv-rs.git', tag: "v#{s.version}" }

  s.platform         = :ios, '15.0'
  s.swift_version    = '5'

  # Built by prepare_command below; the module is named OpenCsvFFI (see
  # ffi/include/module.modulemap).
  s.vendored_frameworks = 'OpenCsv.xcframework'
  s.preserve_paths      = 'OpenCsv.xcframework'

  # A library xcframework's module map is only found through the Swift
  # include path; CocoaPods sets HEADER_SEARCH_PATHS but not this.
  s.user_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '"$(PODS_XCFRAMEWORKS_BUILD_DIR)/OpenCsv/Headers"',
  }

  s.prepare_command = <<~CMD
    set -euo pipefail
    requested_mode=default
    if [ "${OPENCSV_TEST_WALLET_RECOVERY:-0}" = "1" ]; then
      requested_mode=test-wallet-recovery
    fi
    source_revision=$(git rev-parse HEAD 2>/dev/null || printf unknown)
    source_diff=$(git diff --no-ext-diff --binary 2>/dev/null | shasum -a 256 | awk '{print $1}')
    requested_build="$requested_mode:$source_revision:$source_diff"
    if [ -d OpenCsv.xcframework ] && [ -f OpenCsv.xcframework.build-mode ] && \
       [ "$(cat OpenCsv.xcframework.build-mode)" = "$requested_build" ]; then
      echo "OpenCsv.xcframework already present for this $requested_mode source; skipping build"
      exit 0
    fi
    command -v cargo >/dev/null 2>&1 || {
      echo "error: OpenCsv builds from source and needs a Rust toolchain (https://rustup.rs)" >&2
      exit 1
    }
    OPENCSV_BUILD_SOURCE_ID="$requested_build" sh apple/build-xcframework.sh .
  CMD
end
