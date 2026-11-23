// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! WASM bindings for the channel key chain. Mirrors the FFI shape in
//! `crate::interop::ffi::channel_key`.

use crate::interop::wasm::{
    primitives::helpers::parse_shared_key, ts_bindings_utils::js_error_from_lib,
};
use wasm_bindgen::prelude::*;

/// The channel key at `to_epoch`, derived forward from `key`, the key at
/// `epoch`. See [`crate::types::ChannelKey::derive`]: `to_epoch` below
/// `epoch`, or more than [`crate::types::ChannelKey::MAX_DERIVE_STEPS`] above
/// it, is refused as invalid input.
#[wasm_bindgen(js_name = "channel_key_derive")]
pub fn derive(key: &[u8], epoch: u32, to_epoch: u32) -> Result<Vec<u8>, JsValue> {
    let key = parse_shared_key(key)?;
    let derived = crate::types::ChannelKey::new(epoch, key)
        .derive(to_epoch)
        .map_err(js_error_from_lib)?;
    Ok(derived.key().as_bytes().to_vec())
}
