// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Re-exports of the shared primitives DTOs under the paths the WASM binding
//! code already imports them from. The definitions live in
//! [`crate::interop::dto`] so the C FFI and the WASM bindings — compiled
//! under mutually exclusive `cfg`s — cannot drift apart in field names,
//! optionality or serde attributes.

pub use crate::interop::dto::{DeRecResult, Timestamp};
