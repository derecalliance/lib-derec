#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts every publishable artifact reports the version `get-version.sh`
# resolves from library/Cargo.toml.
#
# Six packages take their version from one place, but they take it by six
# different routes: three crates read it directly, nodejs and web have it
# merged into a generated manifest, .NET receives it as a `dotnet pack`
# argument, react-native has it written into a staged manifest, and Go carries
# it only as a git tag. A bump that misses one of those is invisible until
# something is published at the wrong version — which is not recoverable on
# crates.io, and awkward everywhere else.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED="$("$ROOT_DIR/scripts/get-version.sh")"

failures=0

check() {
  local name="$1" actual="$2"
  if [[ "$actual" == "$EXPECTED" ]]; then
    printf '  %-26s %s\n' "$name" "$actual"
  else
    printf '  %-26s %s   EXPECTED %s\n' "$name" "${actual:-<missing>}" "$EXPECTED" >&2
    failures=$((failures + 1))
  fi
}

crate_version() {
  awk -F'"' '$1 ~ /^version = / { print $2; exit }' "$ROOT_DIR/$1/Cargo.toml"
}

json_version() {
  [[ -f "$1" ]] || return 0
  node -e 'process.stdout.write(require(process.argv[1]).version || "")' "$1"
}

echo "expected version: $EXPECTED"

check "crate: derec-proto"        "$(crate_version protobufs)"
check "crate: derec-cryptography" "$(crate_version cryptography)"
check "crate: derec-library"      "$(crate_version library)"

check "npm: nodejs"       "$(json_version "$ROOT_DIR/library/target/pkg-nodejs/package.json")"
check "npm: web"          "$(json_version "$ROOT_DIR/library/target/pkg-web/package.json")"
check "npm: react-native" "$(json_version "$ROOT_DIR/library/target/pkg-react-native/package.json")"

# The tracked development manifest is the only one carrying a literal version
# in git, so it is the only one that can silently fall behind a bump.
check "npm: react-native (src)" \
  "$(json_version "$ROOT_DIR/packages/react-native/package.json")"

nupkg="$(ls "$ROOT_DIR/packages/dotnet/DeRec.Library/bin/Release/DeRec.Library.$EXPECTED.nupkg" 2>/dev/null || true)"
check "nuget: DeRec.Library" \
  "$([[ -n "$nupkg" ]] && basename "$nupkg" | sed 's/^DeRec\.Library\.//;s/\.nupkg$//' || true)"

# The staged react-native manifest must be the publish one. Shipping the
# development manifest puts `devDependencies` and `scripts` into the registry
# metadata, which is what happened to 0.0.1.
staged="$ROOT_DIR/library/target/pkg-react-native/package.json"
if [[ -f "$staged" ]] && node -e '
    const m = require(process.argv[1]);
    process.exit("devDependencies" in m || "scripts" in m ? 1 : 0);
  ' "$staged"; then
  printf '  %-26s %s\n' "npm: react-native manifest" "publish (no devDependencies)"
else
  printf '  %-26s %s\n' "npm: react-native manifest" "DEVELOPMENT MANIFEST STAGED" >&2
  failures=$((failures + 1))
fi

if (( failures > 0 )); then
  echo "" >&2
  echo "$failures artifact(s) disagree with library/Cargo.toml." >&2
  exit 1
fi

echo "all artifacts agree at $EXPECTED"
