#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CARGO_TOML="$ROOT_DIR/library/Cargo.toml"

awk -F'"' '
  $1 ~ /^version = / {
    print $2
    exit
  }
' "$CARGO_TOML"
