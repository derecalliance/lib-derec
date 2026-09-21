#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts both npm packages declare and contain the schema bundle.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0
staged_checked=0

for pkg in nodejs web; do
  override="$ROOT_DIR/packages/$pkg/package.override.json"
  for entry in proto derec_descriptor.bin; do
    if ! grep -qF "\"$entry\"" "$override"; then
      echo "FAIL: $pkg package.override.json does not list '$entry'" >&2
      failures=$((failures + 1))
    fi
  done

  staged="$ROOT_DIR/library/target/pkg-$pkg"
  if [[ -d "$staged" ]]; then
    staged_checked=$((staged_checked + 1))

    if [[ ! -f "$staged/derec_descriptor.bin" ]]; then
      echo "FAIL: staged $pkg package is missing derec_descriptor.bin" >&2
      failures=$((failures + 1))
    fi

    # Guard the directory's existence rather than letting `find` fail into the
    # assignment: under `errexit` with `pipefail`, a missing directory makes
    # `find` exit 1, which aborts the script before this package's diagnostic
    # prints and before the next package is examined at all.
    count=0
    if [[ -d "$staged/proto" ]]; then
      count="$(find "$staged/proto" -name '*.proto' | wc -l | tr -d ' ')"
    fi
    if [[ "$count" != "18" ]]; then
      echo "FAIL: staged $pkg package has $count protos, expected 18" >&2
      failures=$((failures + 1))
    fi
  else
    echo "note: $staged not built; checked manifest only"
  fi
done

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

# Say what was actually verified. Reporting that the packages carry the bundle
# when no staged package existed to inspect would be a pass that proves nothing.
if [[ "$staged_checked" -eq 0 ]]; then
  echo "OK: manifests declare the schema bundle (no staged package built; staging not verified)"
else
  echo "OK: npm packages carry the schema bundle ($staged_checked staged package(s) verified)"
fi
