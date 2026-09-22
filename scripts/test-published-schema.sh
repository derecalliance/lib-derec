#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Asserts a *published* `derec-proto` carries a schema a consumer can build
# gRPC stubs from.
#
# Every other schema check in this repository runs against the working tree,
# where `derec-proto` is a path dependency. That resolves the descriptor
# through the crate directory, which is exactly the resolution a consumer
# never gets: they get an extracted `.crate` tarball under `CARGO_HOME`, or a
# vendored copy, or a mirror. Those paths are the ones the descriptor design
# exists to survive, and no path-dependency test can exercise them.
#
# So this runs after publishing, against crates.io, from a scratch crate that
# sits outside any `lib-derec` checkout and contains no `.proto` files of its
# own. It builds a `DeRecTransport` client and server three ways:
#
#   1. `--offline` against a warm cache   — no network at build time
#   2. `cargo vendor` + source replacement — no registry at all
#   3. a relocated `CARGO_HOME`            — no default-path assumption
#
# Each scenario gets its own copy of the crate: `cargo vendor` writes a
# `.cargo/config.toml` that would otherwise leak into the runs after it.
#
# Usage: scripts/test-published-schema.sh [version]
#        defaults to the version `scripts/get-version.sh` resolves.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${1:-$("$ROOT_DIR/scripts/get-version.sh")}"

# Mirrors the versions `smoke-tests/grpc` builds against, so a failure here is
# about the published schema rather than about a tonic release this repository
# has never compiled with.
TONIC_VERSION="0.14.6"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The property under test is that a consumer outside this repository can
# build. A scratch crate created *inside* the checkout would sit in the
# workspace and could resolve `derec-proto` by path, which is the one
# resolution this script must not use.
case "$WORK/" in
  "$ROOT_DIR"/*)
    echo "FAIL: scratch directory $WORK is inside the checkout at $ROOT_DIR" >&2
    echo "      set TMPDIR somewhere outside it" >&2
    exit 1
    ;;
esac

scaffold() {
  local dir="$1"
  mkdir -p "$dir/src"

  # `=` rather than `^`: this checks the version being released, not whatever
  # newer one happens to satisfy a caret range by the time it runs.
  cat >"$dir/Cargo.toml" <<EOF
[package]
name = "derec-published-schema-check"
version = "0.0.0"
edition = "2024"
publish = false

# Stops the crate being adopted by a workspace that happens to sit above
# whatever \`mktemp\` returned.
[workspace]

[dependencies]
derec-proto = "=$VERSION"
prost = "0.14"
tonic = "$TONIC_VERSION"
tonic-prost = "$TONIC_VERSION"

[build-dependencies]
derec-proto = { version = "=$VERSION", features = ["descriptor"] }
tonic-prost-build = "$TONIC_VERSION"
EOF

  cat >"$dir/build.rs" <<'EOF'
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .extern_path(".org.derecalliance.derec.protobuf", "::derec_proto")
        .compile_fds(derec_proto::descriptor::transport_descriptor())?;
    Ok(())
}
EOF

  # Naming the generated client's request type as `derec_proto::DeRecMessage`
  # is the type-identity assertion: it compiles only if `extern_path` bound the
  # service to the crate's own messages instead of emitting a second,
  # structurally identical set that does not unify with them.
  cat >"$dir/src/lib.rs" <<'EOF'
pub mod pb {
    tonic::include_proto!("org.derecalliance.derec.protobuf");
}

use pb::de_rec_transport_client::DeRecTransportClient;

pub async fn send(
    client: &mut DeRecTransportClient<tonic::transport::Channel>,
    message: derec_proto::DeRecMessage,
) -> Result<(), tonic::Status> {
    client.send(message).await?;
    Ok(())
}

// The server half is generated from the same descriptor; naming both types
// fails the build if only the client side came out.
pub use pb::de_rec_transport_server::{DeRecTransport, DeRecTransportServer};
EOF
}

step=0
run() {
  local label="$1" dir="$2"
  shift 2
  step=$((step + 1))
  local log="$WORK/step-$step.log"
  if (cd "$dir" && "$@") >"$log" 2>&1; then
    echo "  ok: $label"
  else
    echo "FAIL: $label" >&2
    tail -40 "$log" >&2
    exit 1
  fi
}

echo "checking published derec-proto $VERSION from $WORK"

# ---------------------------------------------------------------- scenario 1
scaffold "$WORK/offline"
# Warms the default cache. This is the one step that must reach the network,
# and resolution alone already decides two of the acceptance criteria: the
# version has to exist on crates.io, and the published manifest has to declare
# the `descriptor` feature. A crate published without it fails here, with
# cargo naming the missing feature, before any build is attempted.
if ! (cd "$WORK/offline" && cargo fetch >"$WORK/fetch.log" 2>&1); then
  echo "FAIL: could not resolve derec-proto $VERSION with the descriptor feature" >&2
  echo "      either the version is not published, or it shipped without the feature" >&2
  tail -20 "$WORK/fetch.log" >&2
  exit 1
fi
run "offline build against a warm cache" "$WORK/offline" \
  cargo build --offline

# ---------------------------------------------------------------- scenario 2
scaffold "$WORK/vendored"
run "cargo vendor" "$WORK/vendored" \
  cargo vendor --versioned-dirs vendor
mkdir -p "$WORK/vendored/.cargo"
cat >"$WORK/vendored/.cargo/config.toml" <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
EOF
run "build from vendored sources" "$WORK/vendored" \
  cargo build --offline

# ---------------------------------------------------------------- scenario 3
scaffold "$WORK/relocated"
mkdir -p "$WORK/cargo-home"
run "build with a relocated CARGO_HOME" "$WORK/relocated" \
  env "CARGO_HOME=$WORK/cargo-home" cargo build

echo "OK: published derec-proto $VERSION builds a DeRecTransport client and server"
echo "    offline, vendored, and under a relocated CARGO_HOME"
