#
# OpenCSV wallet FFI for iOS apps, as a CocoaPods binary pod.
#
# Consumers integrate with a local path during development, mirroring
# libsignal's local-dev flow:
#
#   pod 'OpenCsv', path: '../opencsv-rs/apple'
#
# Build the xcframework first: apple/build-xcframework.sh
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

  # Static library + C headers + module map (module name: OpenCsvFFI).
  s.vendored_frameworks = 'OpenCsv.xcframework'

  # A library xcframework's module map is only found through the Swift
  # include path; CocoaPods sets HEADER_SEARCH_PATHS but not this.
  s.user_target_xcconfig = {
    'SWIFT_INCLUDE_PATHS' => '"$(PODS_XCFRAMEWORKS_BUILD_DIR)/OpenCsv/Headers"',
  }
end
