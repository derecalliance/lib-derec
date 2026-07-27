# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Regenerates the derecpb package from the shared protobuf definitions in
# protobufs/protobufs/*.proto. Invoked via `go generate ./derecpb/...` from
# packages/go (see the //go:generate directive in gen.go).
#
# Requires `protoc` and `protoc-gen-go` on PATH:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-${0}}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
proto_dir="${repo_root}/protobufs/protobufs"
out_dir="${script_dir}"

go_opts=(--go_opt=paths=source_relative)
for f in "${proto_dir}"/*.proto; do
  go_opts+=("--go_opt=M$(basename "${f}")=github.com/derecalliance/lib-derec/packages/go/derecpb")
done

protoc \
  --proto_path="${proto_dir}" \
  --go_out="${out_dir}" \
  "${go_opts[@]}" \
  "${proto_dir}"/*.proto
