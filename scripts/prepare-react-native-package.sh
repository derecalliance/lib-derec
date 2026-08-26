#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBRARY_DIR="$ROOT_DIR/library"
WORKSPACE_TARGET_DIR="$ROOT_DIR/target"
PKG_DIR="$ROOT_DIR/packages/react-native"

IOS_DIR="$PKG_DIR/ios"
ANDROID_JNI_DIR="$PKG_DIR/android/src/main/jniLibs"
STATICLIB_NAME="libderec_library.a"
XCFRAMEWORK_NAME="DeRecFFI.xcframework"

# iOS: one device slice plus a simulator slice that itself has to carry both
# Apple-silicon and Intel simulator code, since `xcodebuild -create-xcframework`
# takes at most one library per platform+environment pair.
IOS_DEVICE_TARGET="aarch64-apple-ios"
IOS_SIM_TARGETS=("aarch64-apple-ios-sim" "x86_64-apple-ios")

# Rust target -> Android ABI (as named in android/build.gradle's `abiFilters`
# and consumed by android/CMakeLists.txt's `ANDROID_ABI`-keyed import path).
ANDROID_TARGETS=(
  "aarch64-linux-android|arm64-v8a"
  "armv7-linux-androideabi|armeabi-v7a"
  "x86_64-linux-android|x86_64"
)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[prepare-react-native-package] $*"
}

build_rust_target() {
  local rust_target="$1"
  log "Building $rust_target with cargo build"
  cargo build --release --features ffi --target "$rust_target"
}

# Android has no host toolchain that can link against its libc/sysroot, so
# the Rust target needs the NDK's linker and sysroot wired in. `cargo-ndk`
# does this per invocation instead of a hand-rolled `.cargo/config.toml`,
# which would otherwise hardcode paths specific to one NDK version.
build_android_target() {
  local rust_target="$1"
  local abi="$2"
  log "Building $rust_target ($abi) with cargo ndk"
  cargo ndk --target "$abi" --platform 24 -- build --release --features ffi --target "$rust_target"
}

staticlib_path() {
  local rust_target="$1"
  echo "$WORKSPACE_TARGET_DIR/$rust_target/release/$STATICLIB_NAME"
}

# Generates the FFI header to a scratch path and fails the build if it
# differs from the checked-in `cpp/derec_ffi.h`, rather than overwriting it.
# The whole point of checking in a cbindgen-generated header is that FFI
# signature drift between `library/src/interop/ffi/` and this SDK becomes a *compile
# error* here — a guarantee neither the Go binding (purego, resolved at
# runtime) nor the .NET binding (P/Invoke) has. Silently repairing the file
# on every packaging run would throw that guarantee away and let drift
# surface as a runtime crash in the field instead.
check_ffi_header_is_current() {
  local checked_in="$PKG_DIR/cpp/derec_ffi.h"
  local generated
  generated="$(mktemp)"

  log "Generating cbindgen output to a scratch path to check for header drift"
  cbindgen --config "$LIBRARY_DIR/cbindgen.toml" \
           --crate derec-library \
           --output "$generated" \
           "$LIBRARY_DIR"

  local header_diff
  if ! header_diff="$(diff -u "$checked_in" "$generated")"; then
    echo "$header_diff" >&2
    echo "" >&2
    echo "DeRec: packages/react-native/cpp/derec_ffi.h is stale relative to" >&2
    echo "the Rust FFI surface (library/src/interop/ffi/). Regenerate it and commit" >&2
    echo "the update:" >&2
    echo "" >&2
    echo "  cbindgen --config library/cbindgen.toml --crate derec-library \\" >&2
    echo "           --output packages/react-native/cpp/derec_ffi.h library" >&2
    rm -f "$generated"
    exit 1
  fi

  rm -f "$generated"
  log "cpp/derec_ffi.h matches the current FFI surface"
}

build_ios_xcframework() {
  log "Building iOS targets: $IOS_DEVICE_TARGET ${IOS_SIM_TARGETS[*]}"
  build_rust_target "$IOS_DEVICE_TARGET"
  for target in "${IOS_SIM_TARGETS[@]}"; do
    build_rust_target "$target"
  done

  local device_lib
  device_lib="$(staticlib_path "$IOS_DEVICE_TARGET")"

  local sim_fat_dir="$WORKSPACE_TARGET_DIR/ios-sim-fat"
  mkdir -p "$sim_fat_dir"
  local sim_fat_lib="$sim_fat_dir/$STATICLIB_NAME"

  log "Combining simulator slices with lipo"
  lipo -create \
    "$(staticlib_path "${IOS_SIM_TARGETS[0]}")" \
    "$(staticlib_path "${IOS_SIM_TARGETS[1]}")" \
    -output "$sim_fat_lib"

  # `-headers` copies the directory verbatim, so pointing it at `cpp/` would
  # publish the C++ sources and the host test harness inside the framework's
  # Headers. The framework vendors the Rust static library; the only header
  # that belongs alongside it is the C ABI one. The C++ layer is compiled from
  # `cpp/` by the podspec's `source_files`, not from here.
  local headers_dir="$WORKSPACE_TARGET_DIR/rn-ios-headers"
  rm -rf "$headers_dir"
  mkdir -p "$headers_dir"
  cp "$PKG_DIR/cpp/derec_ffi.h" "$headers_dir/"

  log "Creating $XCFRAMEWORK_NAME"
  rm -rf "$IOS_DIR/$XCFRAMEWORK_NAME"
  mkdir -p "$IOS_DIR"
  xcodebuild -create-xcframework \
    -library "$device_lib" -headers "$headers_dir" \
    -library "$sim_fat_lib" -headers "$headers_dir" \
    -output "$IOS_DIR/$XCFRAMEWORK_NAME"
}

build_android_libs() {
  log "Cleaning previous staged Android native libraries"
  rm -rf "$ANDROID_JNI_DIR"

  for entry in "${ANDROID_TARGETS[@]}"; do
    IFS="|" read -r rust_target abi <<< "$entry"
    build_android_target "$rust_target" "$abi"

    local dest_dir="$ANDROID_JNI_DIR/$abi"
    mkdir -p "$dest_dir"
    cp "$(staticlib_path "$rust_target")" "$dest_dir/"
    echo "Staged $STATICLIB_NAME -> android/src/main/jniLibs/$abi/"
  done
}

main() {
  require_cmd cargo
  require_cmd rustup
  require_cmd cbindgen
  require_cmd lipo
  require_cmd xcodebuild
  require_cmd cargo-ndk
  require_cmd node

  if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ANDROID_NDK_HOME must be set (cargo-ndk needs it to locate the NDK toolchain)." >&2
    exit 1
  fi

  cd "$LIBRARY_DIR"

  check_ffi_header_is_current
  build_ios_xcframework
  build_android_libs

  echo "── Compiling TypeScript ────────────────────────────────────"
  (cd "$PKG_DIR" && npx tsc --project tsconfig.build.json)

  # `packages/react-native/package.json` is tracked, because unlike the other
  # packages this one has its own in-tree test suite: `npm ci` and `jest` need
  # a manifest carrying `devDependencies` and `scripts`, and the lockfile is
  # resolved against it. Publishing needs the opposite — neither key belongs in
  # a published tarball. So the staged manifest is the override plus the
  # version, and the tracked development manifest is restored afterwards.
  echo "── Writing package.json ────────────────────────────────────"
  VERSION="$("$ROOT_DIR/scripts/get-version.sh")"
  node -e '
    const fs = require("fs");
    const path = process.argv[1];
    const version = process.argv[2];
    const override = JSON.parse(fs.readFileSync(path + "/package.override.json", "utf8"));
    fs.writeFileSync(
      path + "/package.json",
      JSON.stringify({ ...override, version, license: "Apache-2.0" }, null, 2) + "\n"
    );
  ' "$PKG_DIR" "$VERSION"

  cp "$ROOT_DIR/LICENSE" "$PKG_DIR/LICENSE"
  echo "Package staged at version $VERSION"
  echo ""
  echo "packages/react-native/package.json now holds the publish manifest."
  echo "After 'npm publish', restore the development manifest with:"
  echo ""
  echo "  git checkout packages/react-native/package.json"
}

# Guards direct execution so this file can also be `source`d (e.g. to run
# `check_ffi_header_is_current` alone in an environment without Xcode/NDK)
# without triggering the full build.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
