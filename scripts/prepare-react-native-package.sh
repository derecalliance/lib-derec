#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.

set -euo pipefail

# Path remapping for every shipped binary; see the file for why.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/build-env.sh"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBRARY_DIR="$ROOT_DIR/library"
WORKSPACE_TARGET_DIR="$ROOT_DIR/target"
PKG_DIR="$ROOT_DIR/packages/react-native"
# Beside pkg-nodejs and pkg-web, so every publishable package stages in one
# place. `WORKSPACE_TARGET_DIR` is the cargo workspace target at the repository
# root, which is a different directory.
STAGE_DIR="$LIBRARY_DIR/target/pkg-react-native"

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

# Remove debug sections from a static archive, keeping the symbol table.
#
# A `.a` is an archive of object files, never linked, so Cargo's
# `profile.strip` — a link-time flag — does not reach it. The archives ship
# with full DWARF: the five this package carries account for 171 MB of its
# 172 MB unpacked size, and removing it takes roughly a fifth off each one.
#
# Debug sections only. Stripping the symbol table would leave an archive the
# consuming app cannot link against.
strip_static_archive() {
  local lib="$1" kind="$2"
  local before after
  before="$(wc -c <"$lib" | tr -d ' ')"
  case "$kind" in
    apple) xcrun strip -S "$lib" ;;
    android)
      # Globbed rather than `find`ed: the NDK's toolchain directories are
      # symlinks under a Homebrew install, and `find -type f` does not follow
      # them, so it reports the tool as absent while `ls` shows it.
      local ndk_root="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
      local ndk_strip=""
      local candidate
      for candidate in "$ndk_root"/toolchains/llvm/prebuilt/*/bin/llvm-strip; do
        if [[ -x "$candidate" ]]; then
          ndk_strip="$candidate"
          break
        fi
      done
      if [[ -z "$ndk_strip" ]]; then
        log "llvm-strip not found in the NDK; leaving $lib unstripped"
        return 0
      fi
      "$ndk_strip" --strip-debug "$lib"
      ;;
  esac
  after="$(wc -c <"$lib" | tr -d ' ')"
  log "Stripped $(basename "$(dirname "$lib")")/$(basename "$lib"): $((before / 1048576))M -> $((after / 1048576))M"
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

  strip_static_archive "$device_lib" apple
  strip_static_archive "$sim_fat_lib" apple

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
    strip_static_archive "$dest_dir/$STATICLIB_NAME" android
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
  require_cmd rsync

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

  stage_package
}

# Assembles the publishable package into `library/target/pkg-react-native`,
# the way every other package is staged.
#
# The source directory is never mutated. It previously received the publish
# manifest in place, which made publishing a three-step dance — run this
# script, publish, restore the manifest — with two failure modes that both
# happened: publishing before staging ships the development manifest, and
# committing after staging strips `devDependencies` from the repository.
# Staging elsewhere removes both: the source tree keeps its development
# manifest permanently, and the directory that gets published contains only
# what ships.
stage_package() {
  local version
  version="$("$ROOT_DIR/scripts/get-version.sh")"

  echo "── Staging publishable package ─────────────────────────────"
  rm -rf "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"

  # `cpp/tests` is a host-only harness and `android/build` / `android/.cxx`
  # are Gradle output that the smoke app refills on every run; excluding them
  # here is what keeps the tarball at ~50 MB instead of ~720 MB.
  rsync -a "$PKG_DIR/lib/" "$STAGE_DIR/lib/"
  rsync -a "$PKG_DIR/src/" "$STAGE_DIR/src/"
  rsync -a --exclude 'tests/' "$PKG_DIR/cpp/" "$STAGE_DIR/cpp/"
  rsync -a "$PKG_DIR/ios/" "$STAGE_DIR/ios/"
  rsync -a --exclude 'build/' --exclude '.cxx/' "$PKG_DIR/android/" "$STAGE_DIR/android/"
  cp "$PKG_DIR/DeRec.podspec" "$PKG_DIR/react-native.config.js" "$PKG_DIR/README.md" "$STAGE_DIR/"
  cp "$ROOT_DIR/LICENSE" "$STAGE_DIR/LICENSE"

  # The schema ships with the package so consumers can generate their own code
  # from it without a lib-derec checkout.
  "$ROOT_DIR/scripts/sync-schema.sh" "$STAGE_DIR/schema"

  node -e '
    const fs = require("fs");
    const [pkgDir, stageDir, version] = process.argv.slice(1);
    const override = JSON.parse(
      fs.readFileSync(pkgDir + "/package.override.json", "utf8"),
    );
    fs.writeFileSync(
      stageDir + "/package.json",
      JSON.stringify({ ...override, version, license: "Apache-2.0" }, null, 2) + "\n",
    );
  ' "$PKG_DIR" "$STAGE_DIR" "$version"

  echo "Package staged at version $version"
  echo "  publish with: (cd $STAGE_DIR && npm publish --access public)"
}

# Guards direct execution so this file can also be `source`d (e.g. to run
# `check_ffi_header_is_current` alone in an environment without Xcode/NDK)
# without triggering the full build.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
