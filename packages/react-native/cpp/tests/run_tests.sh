#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
OUT="$ROOT/target/rn-cpp-tests"
mkdir -p "$OUT"

# `c++` picks its SDK on its own, and on a machine that carries both Xcode and
# a standalone Command Line Tools install it can pick the CLT one — whose
# clang is then older than its own `.tbd` system stubs and rejects them with
# "unknown architecture". That surfaces as a link failure against libSystem,
# which looks like a defect in this tree and is not one. Pin the SDK belonging
# to the toolchain `xcode-select` points at.
if [[ "$(uname -s)" == "Darwin" && -z "${SDKROOT:-}" ]] && command -v xcrun >/dev/null 2>&1; then
  SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
  export SDKROOT
fi

# Host build of the Rust staticlib so the C++ tests can link the real ABI.
(cd "$ROOT" && cargo build --release --features ffi)

LIB="$ROOT/target/release/libderec_library.a"

status=0
for src in "$HERE"/*Test.cpp; do
  name="$(basename "$src" .cpp)"
  echo "── $name ─────────────────────────────────────"
  c++ -std=c++17 -I"$HERE/.." "$src" "$HERE/../Convert.cpp" \
      "$HERE/../JsCallbackBridge.cpp" "$HERE/../WorkerThread.cpp" \
      "$LIB" -framework CoreFoundation -framework Security \
      -o "$OUT/$name" 2>/dev/null \
    || c++ -std=c++17 -I"$HERE/.." "$src" "$HERE/../Convert.cpp" \
           "$HERE/../JsCallbackBridge.cpp" "$HERE/../WorkerThread.cpp" \
           "$LIB" -lpthread -ldl -lm -o "$OUT/$name"
  "$OUT/$name" || status=1
done
exit $status
