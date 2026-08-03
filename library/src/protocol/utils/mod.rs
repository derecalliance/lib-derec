// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Protocol helper modules: the reserved `derec.*` communication-info keys
//! and the pending-action wire codec.

#[cfg(any(feature = "ffi", target_arch = "wasm32"))]
pub(crate) mod pending_action_wire;
pub mod reserved_keys;
