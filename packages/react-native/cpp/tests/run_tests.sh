#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
OUT="$ROOT/target/rn-cpp-tests"
mkdir -p "$OUT"

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
