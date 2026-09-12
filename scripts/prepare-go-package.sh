#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.

set -euo pipefail

# Path remapping for every shipped binary; see the file for why.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/build-env.sh"

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIBRARY_DIR="$ROOT_DIR/library"
WORKSPACE_TARGET_DIR="$ROOT_DIR/target"

GO_PKG_DIR="$ROOT_DIR/packages/go"
NATIVE_LIB_DIR="$GO_PKG_DIR/internal/native/lib"

# Rust target -> Go embed dir (GOOS_GOARCH) -> expected library filename
TARGETS=(
  "aarch64-apple-darwin|darwin_arm64|libderec_library.dylib"
  "x86_64-apple-darwin|darwin_amd64|libderec_library.dylib"
  "x86_64-unknown-linux-gnu|linux_amd64|libderec_library.so"
  "aarch64-unknown-linux-gnu|linux_arm64|libderec_library.so"
)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[prepare-go-package] $*"
}

build_target() {
  local rust_target="$1"

  case "$rust_target" in
    aarch64-apple-darwin)
      log "Building $rust_target with cargo build"
      cargo build --release --features ffi --target "$rust_target"
      ;;
    x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu)
      log "Building $rust_target with cargo zigbuild"
      cargo zigbuild --release --features ffi --target "$rust_target"
      ;;
    *)
      echo "Unsupported build target in script: $rust_target" >&2
      exit 1
      ;;
  esac
}

stage_target() {
  local rust_target="$1"
  local goplat="$2"
  local libname="$3"

  # Every target is built with `--target`, so its artifact always lands in the
  # target-triple subdirectory (never the host default `target/release`).
  local source_lib="$WORKSPACE_TARGET_DIR/$rust_target/release/$libname"

  local dest_dir="$NATIVE_LIB_DIR/$goplat"

  if [[ ! -f "$source_lib" ]]; then
    echo "Expected native library not found: $source_lib" >&2
    exit 1
  fi

  mkdir -p "$dest_dir"
  cp "$source_lib" "$dest_dir/"

  echo "Staged $libname -> internal/native/lib/$goplat/"
}

main() {
  require_cmd cargo
  require_cmd rustup
  require_cmd cargo-zigbuild

  log "Cleaning previous staged native artifacts"
  rm -rf "$NATIVE_LIB_DIR/darwin_arm64" \
         "$NATIVE_LIB_DIR/darwin_amd64" \
         "$NATIVE_LIB_DIR/linux_amd64" \
         "$NATIVE_LIB_DIR/linux_arm64"

  cd "$LIBRARY_DIR"

  for entry in "${TARGETS[@]}"; do
    IFS="|" read -r rust_target goplat libname <<< "$entry"
    build_target "$rust_target"
    stage_target "$rust_target" "$goplat" "$libname"
  done

  log "Native libraries staged:"
  find "$NATIVE_LIB_DIR" -type f -name 'libderec_library.*' -print
}

main "$@"
