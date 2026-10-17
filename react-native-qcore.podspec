# Copyright 2026 Quantova Inc
# SPDX-License-Identifier: Apache-2.0 OR MIT

require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "react-native-qcore"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = "https://github.com/Quantova/react-native-qcore"
  s.license      = { :type => "Apache-2.0 OR MIT" }
  s.authors      = { "Quantova Inc" => "engineering@quantova.com" }
  s.platforms    = { :ios => "13.0" }
  s.source       = { :git => "https://github.com/Quantova/react-native-qcore.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,swift}"
  s.preserve_paths = "ios/generated/quantova_qcoreFFI.modulemap"
  s.vendored_frameworks = "ios/QuantovaQcore.xcframework"
  s.frameworks = "Security"

  s.pod_target_xcconfig = {
    "SWIFT_INCLUDE_PATHS" => "\"$(PODS_TARGET_SRCROOT)/ios/generated\"",
    "OTHER_SWIFT_FLAGS" => "-Xcc -fmodule-map-file=\"$(PODS_TARGET_SRCROOT)/ios/generated/quantova_qcoreFFI.modulemap\"",
    "DEFINES_MODULE" => "YES"
  }

  s.dependency "React-Core"
end
