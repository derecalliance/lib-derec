#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Builds the distributable schema bundle.
#
# The repo keeps the message vocabulary in protobufs/protobufs and the
# transport contracts in protobufs/grpc, which means a consumer compiling
# derectransport.proto needs two include paths. Every import in the schema is
# a bare filename, so collapsing both roots into one directory resolves the
# whole closure with a single -I. The bundle is generated rather than
# maintained so the two layouts cannot drift.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_MESSAGES="$ROOT_DIR/protobufs/protobufs"
SRC_TRANSPORT="$ROOT_DIR/protobufs/grpc"
OUT_DIR="${1:-$ROOT_DIR/target/schema-bundle}"

if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required to build the schema bundle" >&2
  exit 1
fi

# Clear only what this script owns. The Go SDK keeps its embed shim and its
# test in the same directory it regenerates the bundle into, so wiping
# OUT_DIR wholesale would delete hand-written source.
rm -rf "$OUT_DIR/proto" "$OUT_DIR/derec_descriptor.bin"
mkdir -p "$OUT_DIR/proto"

cp "$SRC_MESSAGES"/*.proto "$SRC_TRANSPORT"/*.proto "$OUT_DIR/proto/"

# --include_source_info embeds comment locations in the descriptor, so code
# generated from this bundle (Go, C#, TypeScript, ...) carries the protobuf
# doc comments instead of shipping undocumented.
protoc \
  --proto_path="$OUT_DIR/proto" \
  --include_imports \
  --include_source_info \
  --descriptor_set_out="$OUT_DIR/derec_descriptor.bin" \
  "$OUT_DIR/proto"/*.proto

echo "Schema bundle written to $OUT_DIR"
