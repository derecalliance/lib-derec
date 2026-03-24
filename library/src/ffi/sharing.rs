//! C FFI exports for the DeRec *sharing* flow.
//!
//! This module exposes secret sharing through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Provide a secret ID and secret data
//! 2. Specify the helper channel set together with their 32-byte shared keys
//! 3. Specify the recovery threshold
//! 4. Optionally provide a keep-list and description
//! 5. Receive one serialized outer `DeRecMessage` envelope per helper
//!
//! The sharing flow is exposed as a single FFI entry point:
//!
//! - [`protect_secret`]
//!
//! The exported function follows the common FFI pattern used across the SDK:
//!
//! - inputs are passed as primitive C values, raw byte buffers, or `#[repr(C)]` arrays
//! - optional values are represented using nullable pointers
//! - results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - `secret_id` and `secret_data` are passed as `(*const u8, usize)` byte buffers
//! - `channels` is passed as a pointer to an array of [`ChannelSharedKeyInput`]
//! - `keep_list` is optional and passed as a nullable pointer to `i32` values plus a length
//! - `description` is optional and passed as a nullable UTF-8 byte buffer
//! - returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - on error, output buffers are returned empty and details are reported in
//!   the returned [`DeRecStatus`]
//!
//! # Serialized Share Map Format
//!
//! The sharing result is returned as a single serialized FFI container rather than a native map.
//! That container has the following layout:
//!
//! 1. A 32-bit little-endian count
//! 2. For each share entry, sorted by channel ID:
//!    - the channel ID as a 64-bit little-endian integer
//!    - a length-prefixed serialized outer `DeRecMessage` envelope
//!
//! This byte format is specific to the FFI layer and should be treated as an
//! opaque transport container by foreign callers unless they explicitly choose
//! to deserialize it.
//!
//! # Notes
//!
//! - This module does not expose Rust `HashMap` or collection types directly over FFI
//! - the output of this module is not a recovered secret or a helper response;
//!   it is the set of encrypted share-storage request envelopes that should be
//!   delivered to helpers
//! - each helper entry must include the 32-byte symmetric key previously derived
//!   during pairing for that channel

use crate::{
    ffi::common::{
        DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
        write_len_prefixed, write_u32_le, write_u64_le,
    },
    types::ChannelId,
};
use std::collections::HashMap;

/// One helper channel and its previously established 32-byte shared key.
///
/// This structure is consumed by [`protect_secret`] over the C FFI boundary.
///
/// The `shared_key` value must be the symmetric channel key previously derived
/// during the pairing flow for this helper.
#[repr(C)]
pub struct ChannelSharedKeyInput {
    /// Helper channel identifier.
    pub channel_id: u64,

    /// 32-byte symmetric key established during pairing.
    pub shared_key: [u8; 32],
}

/// FFI result returned by [`protect_secret`].
///
/// On success:
///
/// - `status` indicates success
/// - `shares` contains a serialized FFI share map, where each entry associates
///   a channel ID with serialized outer `DeRecMessage` bytes carrying an encrypted
///   inner `StoreShareRequestMessage`
///
/// On failure:
///
/// - `status` contains an error
/// - `shares` is returned empty
#[repr(C)]
pub struct ProtectSecretResult {
    pub status: DeRecStatus,
    pub shares: DeRecBuffer,
}

/// Splits a secret into helper shares and returns one serialized outer
/// `DeRecMessage` envelope per helper channel.
///
/// This is the C FFI entry point for the DeRec sharing flow.
///
/// The caller provides:
///
/// - `secret_id` as raw secret identifier bytes
/// - `secret_data` as raw secret bytes to protect
/// - `channels` as an array of [`ChannelSharedKeyInput`] values
/// - `threshold` as the recovery threshold
/// - `version` as the share-distribution version
/// - optionally, a keep-list and a UTF-8 description
///
/// On success, this function returns a serialized FFI container representing
/// a map from channel ID to serialized outer `DeRecMessage` bytes.
///
/// Each returned envelope contains an encrypted inner `StoreShareRequestMessage`.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `secret_data_ptr` - Pointer to secret data bytes.
/// * `secret_data_len` - Length of the secret data buffer.
/// * `channels_ptr` - Pointer to an array of [`ChannelSharedKeyInput`].
/// * `channels_len` - Number of helper channel entries.
/// * `threshold` - Recovery threshold to use when generating shares.
/// * `version` - Share-distribution version number.
/// * `keep_list_ptr` - Optional pointer to an array of `i32` values representing
///   the keep-list.
/// * `keep_list_len` - Number of keep-list entries.
/// * `description_ptr` - Optional pointer to a UTF-8 description string.
/// * `description_len` - Length of the description buffer in bytes.
///
/// # Returns
///
/// Returns [`ProtectSecretResult`].
///
/// On success, the `shares` buffer contains:
///
/// 1. a 32-bit little-endian entry count
/// 2. for each share entry:
///    - channel ID as little-endian `u64`
///    - a length-prefixed serialized outer `DeRecMessage` envelope
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `secret_data_ptr` is null while `secret_data_len > 0`
/// - `channels_ptr` is null while `channels_len > 0`
/// - `keep_list_ptr` is null while `keep_list_len > 0`
/// - `description_ptr` is null while `description_len > 0`
/// - `description_ptr` is provided but the bytes are not valid UTF-8
/// - the underlying Rust sharing API returns an error
///
/// # Safety
///
/// Each non-null pointer must point to the corresponding readable range:
///
/// - `secret_id_ptr` → `secret_id_len` bytes
/// - `secret_data_ptr` → `secret_data_len` bytes
/// - `channels_ptr` → `channels_len` [`ChannelSharedKeyInput`] values
/// - `keep_list_ptr` → `keep_list_len` `i32` values when provided
/// - `description_ptr` → `description_len` UTF-8 bytes when provided
///
/// Nullable pointer handling follows these rules:
///
/// - `keep_list_ptr == null` means no keep-list was supplied
/// - `description_ptr == null` means no description was supplied
/// - zero-length buffers are allowed and interpreted as empty slices where applicable
#[unsafe(no_mangle)]
pub extern "C" fn protect_secret(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    secret_data_ptr: *const u8,
    secret_data_len: usize,
    channels_ptr: *const ChannelSharedKeyInput,
    channels_len: usize,
    threshold: usize,
    version: i32,
    keep_list_ptr: *const i32,
    keep_list_len: usize,
    description_ptr: *const u8,
    description_len: usize,
) -> ProtectSecretResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return ProtectSecretResult {
            status: err_status("secret_id_ptr is null"),
            shares: empty_buffer(),
        };
    }

    if secret_data_ptr.is_null() && secret_data_len > 0 {
        return ProtectSecretResult {
            status: err_status("secret_data_ptr is null"),
            shares: empty_buffer(),
        };
    }

    if channels_ptr.is_null() && channels_len > 0 {
        return ProtectSecretResult {
            status: err_status("channels_ptr is null"),
            shares: empty_buffer(),
        };
    }

    if keep_list_ptr.is_null() && keep_list_len > 0 {
        return ProtectSecretResult {
            status: err_status("keep_list_ptr is null"),
            shares: empty_buffer(),
        };
    }

    if description_ptr.is_null() && description_len > 0 {
        return ProtectSecretResult {
            status: err_status("description_ptr is null"),
            shares: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let secret_data: &[u8] = if secret_data_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_data_ptr, secret_data_len) }
    };

    let channels: &[ChannelSharedKeyInput] = if channels_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(channels_ptr, channels_len) }
    };

    let keep_list: Option<&[i32]> = if keep_list_ptr.is_null() {
        None
    } else if keep_list_len == 0 {
        Some(&[])
    } else {
        Some(unsafe { std::slice::from_raw_parts(keep_list_ptr, keep_list_len) })
    };

    let description: Option<&str> = if description_ptr.is_null() {
        None
    } else {
        let description_bytes: &[u8] = if description_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(description_ptr, description_len) }
        };

        match std::str::from_utf8(description_bytes) {
            Ok(value) => Some(value),
            Err(_) => {
                return ProtectSecretResult {
                    status: err_status("description is not valid UTF-8"),
                    shares: empty_buffer(),
                };
            }
        }
    };

    let mut channel_map: HashMap<ChannelId, [u8; 32]> = HashMap::with_capacity(channels.len());

    for entry in channels {
        channel_map.insert(ChannelId(entry.channel_id), entry.shared_key);
    }

    let result = match crate::sharing::protect_secret(
        secret_id,
        secret_data,
        channel_map,
        threshold,
        version,
        keep_list,
        description,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProtectSecretResult {
                status: err_status(err.to_string()),
                shares: empty_buffer(),
            };
        }
    };

    let shares_bytes = serialize_share_envelopes(&result.shares);

    ProtectSecretResult {
        status: ok_status(),
        shares: vec_into_buffer(shares_bytes),
    }
}

fn serialize_share_envelopes(shares: &HashMap<crate::types::ChannelId, Vec<u8>>) -> Vec<u8> {
    let mut entries: Vec<_> = shares.iter().collect();
    entries
        .sort_by_key(|(channel_id, _)| <u64 as From<crate::types::ChannelId>>::from(**channel_id));

    let mut out = Vec::new();

    let count = u32::try_from(entries.len()).expect("too many share entries");
    write_u32_le(&mut out, count);

    for (channel_id, wire_bytes) in entries {
        write_u64_le(
            &mut out,
            <u64 as From<crate::types::ChannelId>>::from(*channel_id),
        );
        write_len_prefixed(&mut out, wire_bytes);
    }

    out
}
