// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! C FFI for the channel key chain.
//!
//! A channel key moves forward one epoch at a time; see
//! [`crate::types::ChannelKey`]. Callers using primitives directly derive the
//! key for an epoch here, then pass it with that epoch to a `produce_*` call,
//! or pass the key alone to an `extract_*` call.

use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error,
    success,
};

#[repr(C)]
pub struct DeriveChannelKeyResult {
    pub error: DeRecError,
    /// The 32-byte key at `to_epoch`. Empty on error.
    pub key_bytes: DeRecBuffer,
}

/// The channel key at `to_epoch`, derived forward from `key`, the key at
/// `epoch`.
///
/// Mirrors [`crate::types::ChannelKey::derive`]: `to_epoch` below `epoch`, or
/// more than [`crate::types::ChannelKey::MAX_DERIVE_STEPS`] above it, is
/// refused as invalid input.
///
/// # Safety
///
/// `key_ptr` must point to a readable byte range of length `key_len`.
#[unsafe(no_mangle)]
pub extern "C" fn derive_channel_key(
    key_ptr: *const u8,
    key_len: usize,
    epoch: u32,
    to_epoch: u32,
) -> DeriveChannelKeyResult {
    let with_err = |error| DeriveChannelKeyResult {
        error,
        key_bytes: empty_buffer(),
    };

    if key_ptr.is_null() && key_len > 0 {
        return with_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "key_ptr is null"));
    }
    let bytes = if key_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(key_ptr, key_len) }
    };
    let Ok(key) = crate::types::SharedKey::try_from(bytes) else {
        return with_err(ffi_error(
            DEREC_CODE_FFI_BAD_SHARED_KEY,
            "shared_key must be exactly 32 bytes",
        ));
    };

    match crate::types::ChannelKey::new(epoch, key).derive(to_epoch) {
        Ok(derived) => DeriveChannelKeyResult {
            error: success(),
            key_bytes: vec_into_buffer(derived.key().as_bytes().to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::ffi::common::derec_free_buffer;
    use crate::interop::ffi::error::{DEREC_CODE_INVALID_INPUT, derec_free_error};

    /// Copies a returned buffer out and releases it, matching the ABI
    /// contract foreign callers follow.
    fn take_buffer(buffer: DeRecBuffer) -> Vec<u8> {
        if buffer.ptr.is_null() {
            return Vec::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec();
        derec_free_buffer(buffer.ptr, buffer.len);
        bytes
    }

    fn release(mut error: DeRecError) -> i32 {
        let code = error.code;
        unsafe { derec_free_error(&mut error) };
        code
    }

    fn derive(key: &[u8], epoch: u32, to_epoch: u32) -> Result<Vec<u8>, i32> {
        let result = derive_channel_key(key.as_ptr(), key.len(), epoch, to_epoch);
        let code = release(result.error);
        let bytes = take_buffer(result.key_bytes);
        if code == 0 { Ok(bytes) } else { Err(code) }
    }

    const K0: [u8; 32] = [5u8; 32];

    #[test]
    fn derives_the_key_the_core_derives() {
        let expected = crate::types::ChannelKey::new(0, crate::types::SharedKey::new(K0))
            .derive(3)
            .expect("forward");
        assert_eq!(derive(&K0, 0, 3).unwrap(), expected.key().as_bytes());
    }

    #[test]
    fn refuses_a_backward_or_too_long_derivation_as_invalid_input() {
        assert_eq!(derive(&K0, 3, 2), Err(DEREC_CODE_INVALID_INPUT));
        assert_eq!(
            derive(&K0, 0, crate::types::ChannelKey::MAX_DERIVE_STEPS + 1),
            Err(DEREC_CODE_INVALID_INPUT)
        );
    }

    #[test]
    fn refuses_a_key_that_is_not_32_bytes() {
        assert_eq!(derive(&K0[..31], 0, 1), Err(DEREC_CODE_FFI_BAD_SHARED_KEY));
    }
}
