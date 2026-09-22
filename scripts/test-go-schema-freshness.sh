#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts the Go module's committed schema still matches the source of truth.
#
# Go ships source, so its bundle is committed rather than staged at package
# time. That makes it the one channel whose schema can fall behind: the npm,
# NuGet and react-native bundles are regenerated on every package build, while
# this one only changes when someone runs `go generate`. Without this check, a
# `.proto` edit followed by a release would publish a module whose embedded
# schema predates its own version tag.
#
# Regeneration is deterministic, so any difference here means the committed
# copy is stale, not that the generator is noisy.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMITTED="$ROOT_DIR/packages/go/derecpb/schema"
EXPECTED="$(mktemp -d)"
trap 'rm -rf "$EXPECTED"' EXIT

if [[ ! -d "$COMMITTED/proto" ]]; then
  echo "FAIL: $COMMITTED/proto does not exist" >&2
  exit 1
fi

"$ROOT_DIR/scripts/sync-schema.sh" "$EXPECTED" >/dev/null

if ! diff -r "$EXPECTED/proto" "$COMMITTED/proto" >/dev/null; then
  echo "FAIL: the Go module's committed .proto files are stale" >&2
  diff -r "$EXPECTED/proto" "$COMMITTED/proto" >&2 || true
  echo "      regenerate with: bash packages/go/derecpb/generate.sh" >&2
  exit 1
fi

if ! cmp -s "$EXPECTED/derec_descriptor.bin" "$COMMITTED/derec_descriptor.bin"; then
  echo "FAIL: the Go module's committed descriptor is stale" >&2
  echo "      expected $(wc -c <"$EXPECTED/derec_descriptor.bin" | tr -d ' ') bytes," \
       "found $(wc -c <"$COMMITTED/derec_descriptor.bin" | tr -d ' ')" >&2
  echo "      regenerate with: bash packages/go/derecpb/generate.sh" >&2
  exit 1
fi

count="$(find "$COMMITTED/proto" -name '*.proto' | wc -l | tr -d ' ')"
echo "OK: the Go module's committed schema is current ($count protos, descriptor matches)"
