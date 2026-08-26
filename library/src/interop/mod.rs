// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The language-binding layer: everything that exists so a host language can
//! reach the protocol, and nothing that is part of the protocol itself.
//!
//! [`ffi`] and [`wasm`] are compiled under mutually exclusive `cfg`s — the
//! first requires `not(target_arch = "wasm32")`, the second requires it — so
//! neither can own something the other also needs. [`dto`] holds what both
//! depend on, as a sibling of the two rather than inside either. That is the
//! whole reason this module exists as a layer instead of two unrelated
//! top-level modules.
//!
//! Everything above this module — [`crate::primitives`], [`crate::protocol`],
//! [`crate::transport`] — is binding-agnostic and must stay that way. A
//! binding concern that leaks upward is a bug, not a shortcut.

#[cfg(any(feature = "serde", target_arch = "wasm32"))]
pub mod dto;

// Private: the C ABI is exported by the linker from the `#[unsafe(no_mangle)]
// extern "C"` items inside, not by Rust visibility, so nothing is gained by
// making the module path public and it would invite Rust callers onto a
// surface shaped for C.
#[cfg(all(not(target_arch = "wasm32"), feature = "ffi"))]
mod ffi;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
