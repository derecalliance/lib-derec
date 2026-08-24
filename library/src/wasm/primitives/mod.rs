// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! JavaScript bindings for the primitives layer.
//!
//! One submodule per flow, mirroring [`crate::primitives`] one-to-one. These
//! are the stateless message builders and parsers — no store, no transport, no
//! orchestration. An application that wants the flows driven for it should use
//! the `DeRecProtocol` bindings in [`crate::wasm::protocol`] instead.
//!
//! Every function takes and returns plain JS values: `Uint8Array` for wire
//! bytes, and objects whose shape is documented on each binding. `u64`
//! identifiers cross as decimal strings, never as JS numbers, so values above
//! `Number.MAX_SAFE_INTEGER` survive the boundary intact.

mod helpers;
pub mod types;

pub mod discovery;
pub mod pairing;
pub mod recovery;
pub mod sharing;
pub mod unpairing;
pub mod verification;
