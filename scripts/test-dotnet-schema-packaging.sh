#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts the .NET package declares and contains the schema bundle.
#
# `dotnet pack` gives no warning and no build failure if the csproj's proto
# glob resolves to zero items — the .nupkg simply ships without a schema.
# This checks the csproj declares the pack items, and, when a .nupkg has
# been built, that it actually contains them.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CSPROJ="$ROOT_DIR/packages/dotnet/DeRec.Library/DeRec.Library.csproj"
NUPKG_DIR="$ROOT_DIR/packages/dotnet/DeRec.Library/bin/Release"
failures=0
staged_checked=0

check_pack_item() {
  local include_value="$1"
  local block

  # `grep -A3` directly on the file, not piped from another command: a
  # no-match is a plain exit 1 here, not a SIGPIPE from an upstream process,
  # so it is safe to catch with `if !` rather than needing `|| true`.
  if ! block="$(grep -A3 -F "Include=\"$include_value\"" "$CSPROJ")"; then
    echo "FAIL: csproj does not declare a pack item for '$include_value'" >&2
    failures=$((failures + 1))
    return
  fi

  if [[ "$block" != *'Pack="true"'* ]]; then
    echo "FAIL: csproj pack item for '$include_value' is missing Pack=\"true\"" >&2
    failures=$((failures + 1))
  fi
}

check_pack_item 'schema/proto/**/*.proto'
check_pack_item 'schema/derec_descriptor.bin'

# A glob, not `find | head -n1`: closing a pipe early after the first match
# can SIGPIPE the producer under `pipefail`, the same failure shape as a
# `grep -q` consumer. Unmatched, the pattern expands to its own literal
# string (no nullglob), so `-e` on it correctly evaluates false.
nupkgs=("$NUPKG_DIR"/*.nupkg)
nupkg=""
if [[ -e "${nupkgs[0]}" ]]; then
  nupkg="${nupkgs[0]}"
fi

if [[ -n "$nupkg" ]]; then
  staged_checked=$((staged_checked + 1))

  # Capture the listing first so a genuine `unzip` failure (corrupt archive,
  # unreadable file) is reported as such, rather than being folded into the
  # "zero matches" case below by a blanket `|| true` on the whole pipeline.
  if ! listing="$(unzip -l "$nupkg" 2>&1)"; then
    echo "FAIL: unzip -l failed to read $nupkg" >&2
    echo "$listing" >&2
    failures=$((failures + 1))
  else
    # `grep -c` reads to EOF to produce a count, so it does not early-exit
    # and cannot trigger a SIGPIPE on the herestring's producer. The `|| true`
    # here only absorbs grep's exit 1 for zero matches, a legitimate count.
    proto_count="$(grep -c 'schema/proto/.*\.proto$' <<<"$listing" || true)"
    descriptor_count="$(grep -c 'schema/derec_descriptor\.bin$' <<<"$listing" || true)"

    if [[ "$proto_count" != "18" ]]; then
      echo "FAIL: $nupkg has $proto_count schema/proto/*.proto entries, expected 18" >&2
      failures=$((failures + 1))
    fi
    if [[ "$descriptor_count" != "1" ]]; then
      echo "FAIL: $nupkg has $descriptor_count schema/derec_descriptor.bin entries, expected 1" >&2
      failures=$((failures + 1))
    fi
  fi
else
  echo "note: no .nupkg under $NUPKG_DIR; checked csproj only"
fi

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

# Say what was actually verified. Reporting that the package carries the
# bundle when no .nupkg existed to inspect would be a pass that proves
# nothing.
if [[ "$staged_checked" -eq 0 ]]; then
  echo "OK: csproj declares the schema bundle (no .nupkg built; packaging not verified)"
else
  echo "OK: .nupkg carries the schema bundle ($staged_checked package(s) verified)"
fi
