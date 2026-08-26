require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))

Pod::Spec.new do |s|
  s.name         = "DeRec"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.license      = "Apache-2.0"
  s.authors      = "DeRec Alliance"
  s.homepage     = "https://derec.org"
  s.platforms    = { :ios => "13.4" }
  s.source       = { :git => "https://github.com/derecalliance/lib-derec.git" }

  s.source_files = "ios/**/*.{h,mm}", "cpp/**/*.{h,cpp}"
  s.exclude_files = "cpp/tests/**/*"
  s.vendored_frameworks = "ios/DeRecFFI.xcframework"

  s.pod_target_xcconfig = {
    "CLANG_CXX_LANGUAGE_STANDARD" => "c++17",
    "HEADER_SEARCH_PATHS" => "\"$(PODS_TARGET_SRCROOT)/cpp\""
  }

  install_modules_dependencies(s)
end
