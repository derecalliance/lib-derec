#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts the react-native package declares and contains the schema bundle.
#
# `packages/react-native/` holds both `package.json` and
# `package.override.json`. `stage_package()` in
# scripts/prepare-react-native-package.sh never copies `package.json` into
# the staging directory — it generates the staged manifest from
# `package.override.json` alone (spread with `version` and `license`), and
# `npm publish` runs from that staging directory. A check against
# `package.json` would pass while proving nothing about what actually
# publishes, so this checks the *generated* manifest instead.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="$ROOT_DIR/packages/react-native"
STAGE_DIR="$ROOT_DIR/library/target/pkg-react-native"
failures=0
staged_checked=0

if ! node -e '
  const fs = require("fs");
  const o = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  const staged = { ...o, version: "0.0.0", license: "Apache-2.0" };
  process.exit(Array.isArray(staged.files) && staged.files.includes("schema") ? 0 : 1);
' "$PKG_DIR/package.override.json"; then
  echo "FAIL: generated react-native manifest (from package.override.json) does not list 'schema' in files" >&2
  failures=$((failures + 1))
fi

if [[ -d "$STAGE_DIR" ]]; then
  staged_checked=$((staged_checked + 1))

  if [[ ! -s "$STAGE_DIR/schema/derec_descriptor.bin" ]]; then
    echo "FAIL: staged react-native package is missing a non-empty schema/derec_descriptor.bin" >&2
    failures=$((failures + 1))
  fi

  # Guard the directory's existence rather than letting `find` fail into the
  # assignment: under `errexit` with `pipefail`, a missing directory makes
  # `find` exit 1, which aborts the script before the diagnostic prints.
  count=0
  if [[ -d "$STAGE_DIR/schema/proto" ]]; then
    count="$(find "$STAGE_DIR/schema/proto" -name '*.proto' | wc -l | tr -d ' ')"
  fi
  if [[ "$count" != "18" ]]; then
    echo "FAIL: staged react-native package has $count schema protos, expected 18" >&2
    failures=$((failures + 1))
  fi
else
  echo "note: $STAGE_DIR not built; checked manifest only"
fi

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

# Say what was actually verified. Reporting that the package carries the
# bundle when no staged package existed to inspect would be a pass that
# proves nothing.
if [[ "$staged_checked" -eq 0 ]]; then
  echo "OK: generated manifest declares the schema bundle (no staged package built; staging not verified)"
else
  echo "OK: react-native package carries the schema bundle ($staged_checked staged package(s) verified)"
fi
