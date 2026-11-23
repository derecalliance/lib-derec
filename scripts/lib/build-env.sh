#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 DeRec Alliance. All rights reserved.
#
# Build flags shared by every script that produces a *shipped* binary.
#
# Source it, do not execute it:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/build-env.sh"
#
# Sourced by each `prepare-*-package.sh` rather than set once in
# `library/Makefile`, so a script run directly — as several sections of
# RELEASE.md do — still produces the same artifact the Makefile would.
#
# ## Why
#
# `panic!`, `unwrap()` and `expect()` embed their source location through
# `core::panic::Location`, and those paths are compiled into the binary as
# ordinary read-only data. For dependency and standard-library code that path
# is absolute and machine-specific:
#
#   /Users/<someone>/.cargo/registry/src/index.crates.io-*/serde_json-1.0.151/src/de.rs
#   /Users/<someone>/.rustup/toolchains/stable-*/lib/rustlib/src/rust/library/alloc/src/string.rs
#
# Every published artifact carried them — 63 in each wasm bundle, 70 in the Go
# shared libraries, over a thousand in the React Native static archives. That
# is an information leak about the release machine, and it is why two machines
# building the same commit cannot produce identical output.
#
# They are **not** debug info, so stripping does not remove them: after
# `strip -S` a React Native archive still held 211. Only rewriting them at
# compile time works, which is what `--remap-path-prefix` does.
#
# Cargo's `profile.trim-paths` expresses exactly this and would be the right
# home for it, but it is still nightly-only as of Cargo 1.96.
#
# ## Sourcing it by hand
#
# It can also be sourced from an interactive bash or zsh, to build by hand
# what a script would. It sets no shell options, since those would stay set
# in the caller's shell (an `errexit` there closes the terminal on the next
# failing command); the scripts that source it set their own.

# `$HOME` covers `.cargo/registry` and `.rustup/toolchains`, which is where
# nearly all of these paths come from. The repository root is mapped too, for
# a checkout that does not live under `$HOME`; it is listed last because when
# several prefixes match, rustc applies the last one given.
derec_build_flags="--remap-path-prefix=${HOME}=/derec-build"

# This file's own path: bash records it in `BASH_SOURCE`, and zsh sets `$0` to
# the file being sourced.
derec_env_file="${BASH_SOURCE[0]:-$0}"
if derec_repo_root="$(git -C "$(dirname "${derec_env_file}")" rev-parse --show-toplevel 2>/dev/null)"; then
  derec_build_flags+=" --remap-path-prefix=${derec_repo_root}=/derec"
fi

# Appended, so a caller that set RUSTFLAGS for its own reasons keeps it.
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }${derec_build_flags}"

unset derec_build_flags derec_env_file derec_repo_root
