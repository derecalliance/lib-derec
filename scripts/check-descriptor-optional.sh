#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts the file descriptor set stays out of default builds.
#
# `derec-library` compiles to WebAssembly for the Node.js and web SDKs, and
# the descriptor is ~122 KB. If `descriptor` ever becomes a default feature of
# `derec-proto`, every one of those bundles grows by that much with nothing to
# announce it. The marker string below appears in the descriptor and in no
# generated Rust code.
#
# The build is isolated into its own target directory on purpose. The gRPC
# smoke test enables `descriptor` as a build-dependency, so the shared
# target/debug/deps can hold an rlib built *with* the feature; finding that one
# would fail this check for the wrong reason.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MARKER='google/protobuf/timestamp.proto'
TARGET_DIR="$ROOT_DIR/target/check-descriptor"

cd "$ROOT_DIR"

# Start clean so the directory holds exactly the artifacts this run produced.
# A previous run that deliberately enabled the feature leaves a descriptor-
# bearing rlib behind, and cargo gives it a different hash rather than
# replacing it, so a stale one would otherwise linger and fail later runs.
rm -rf "$TARGET_DIR"
cargo build -p derec-proto --target-dir "$TARGET_DIR"

found=0
while IFS= read -r rlib; do
  found=$((found + 1))

  # Read the artifact in its own step so a scanner failure is distinguishable
  # from a clean scan. Folding this into the `grep` pipeline below would let
  # `|| true` swallow a missing `strings`, an unreadable file, or a corrupt
  # artifact and report them all as zero hits — a guard that cannot fail.
  if ! symbols="$(strings "$rlib")"; then
    echo "FAIL: could not scan $rlib" >&2
    exit 1
  fi

  # `grep -c` rather than `grep -q`: under `set -o pipefail`, `grep -q` exits
  # on its first match, the producer then dies on the broken pipe, and the
  # pipeline reports 141 instead of grep's 0 — which silently inverts this
  # test and reports success on a failing build. `grep -c` consumes all input.
  # Its `|| true` absorbs only the exit-1-means-zero-matches case, which is
  # the genuine pass.
  hits="$(printf '%s' "$symbols" | grep -cF "$MARKER" || true)"

  if [[ "$hits" -gt 0 ]]; then
    echo "FAIL: descriptor set is present in a default build of derec-proto" >&2
    echo "      ($rlib contains $hits occurrences of '$MARKER')" >&2
    exit 1
  fi
done < <(find "$TARGET_DIR/debug/deps" -name 'libderec_proto-*.rlib')

if [[ "$found" -eq 0 ]]; then
  echo "could not locate a built derec-proto rlib" >&2
  exit 1
fi

echo "OK: descriptor set absent from default build ($found rlib(s) scanned)"
