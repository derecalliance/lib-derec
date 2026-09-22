#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts the generated bundle is complete and self-contained.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE="$(mktemp -d)"
trap 'rm -rf "$BUNDLE"' EXIT

"$ROOT_DIR/scripts/sync-schema.sh" "$BUNDLE" >/dev/null

repo_count="$(find "$ROOT_DIR/protobufs/protobufs" "$ROOT_DIR/protobufs/grpc" -name '*.proto' | wc -l | tr -d ' ')"
bundle_count="$(find "$BUNDLE/proto" -name '*.proto' | wc -l | tr -d ' ')"

if [[ "$repo_count" != "$bundle_count" ]]; then
  echo "FAIL: repo has $repo_count protos, bundle has $bundle_count" >&2
  exit 1
fi

if [[ "$bundle_count" != "18" ]]; then
  echo "FAIL: expected 18 schema files, found $bundle_count" >&2
  exit 1
fi

# The point of the flat layout: one include root resolves everything.
protoc --proto_path="$BUNDLE/proto" -o /dev/null "$BUNDLE/proto"/*.proto

if [[ ! -s "$BUNDLE/derec_descriptor.bin" ]]; then
  echo "FAIL: descriptor set missing or empty" >&2
  exit 1
fi

echo "OK: bundle has $bundle_count protos and compiles with a single include root"
