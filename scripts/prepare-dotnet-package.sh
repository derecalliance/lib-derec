#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
LIBRARY_DIR="$ROOT_DIR/library"
WORKSPACE_TARGET_DIR="$ROOT_DIR/target"
VERSION="$("$ROOT_DIR/scripts/get-version.sh")"

DOTNET_PKG_DIR="$ROOT_DIR/packages/dotnet/DeRec.Library"
RUNTIMES_DIR="$DOTNET_PKG_DIR/runtimes"

# Rust target -> NuGet RID -> expected library filename
TARGETS=(
  "aarch64-apple-darwin|osx-arm64|libderec_library.dylib"
  "x86_64-apple-darwin|osx-x64|libderec_library.dylib"
  "x86_64-unknown-linux-gnu|linux-x64|libderec_library.so"
  "aarch64-unknown-linux-gnu|linux-arm64|libderec_library.so"
)

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log() {
  echo "[prepare-dotnet-package] $*"
}

build_target() {
  local rust_target="$1"

  case "$rust_target" in
    aarch64-apple-darwin)
      log "Building $rust_target with cargo build"
      cargo build --release --target "$rust_target"
      ;;
    x86_64-apple-darwin|x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu)
      log "Building $rust_target with cargo zigbuild"
      cargo zigbuild --release --target "$rust_target"
      ;;
    *)
      echo "Unsupported build target in script: $rust_target" >&2
      exit 1
      ;;
  esac
}

stage_target() {
  local rust_target="$1"
  local rid="$2"
  local libname="$3"

  local source_lib

  case "$rust_target" in
    aarch64-apple-darwin)
      source_lib="$WORKSPACE_TARGET_DIR/release/$libname"
      ;;
    *)
      source_lib="$WORKSPACE_TARGET_DIR/$rust_target/release/$libname"
      ;;
  esac

  local runtime_dir="$RUNTIMES_DIR/$rid/native"

  if [[ ! -f "$source_lib" ]]; then
    echo "Expected native library not found: $source_lib" >&2
    exit 1
  fi

  mkdir -p "$runtime_dir"
  cp "$source_lib" "$runtime_dir/"

  echo "Staged $libname -> runtimes/$rid/native/"
}

main() {
  require_cmd cargo
  require_cmd rustup
  require_cmd dotnet
  require_cmd cargo-zigbuild

  log "Cleaning previous staged native artifacts"
  rm -rf "$RUNTIMES_DIR/osx-arm64" \
         "$RUNTIMES_DIR/osx-x64" \
         "$RUNTIMES_DIR/linux-x64" \
         "$RUNTIMES_DIR/linux-arm64"

  cd "$LIBRARY_DIR"

  for entry in "${TARGETS[@]}"; do
    IFS="|" read -r rust_target rid libname <<< "$entry"
    build_target "$rust_target"
    stage_target "$rust_target" "$rid" "$libname"
  done

  cd "$DOTNET_PKG_DIR"
  log "Packing NuGet package"
  dotnet pack -c Release -p:Version="$VERSION"

  log "Package ready:"
  find "$DOTNET_PKG_DIR/bin/Release" -name '*.nupkg' -print
}

main "$@"
