//! C FFI exports for the DeRec *sharing* flow.
//!
//! This module exposes secret sharing through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Provide a secret ID and secret data
//! 2. Specify the helper channel set as a list of channel IDs
//! 3. Specify the recovery threshold
//! 4. Receive one serialized [`CommittedDeRecShare`] per helper channel
//!
//! The sharing flow is exposed as a single FFI entry point:
//!
//! - [`protect_secret`]
//!
//! The exported function follows the common FFI pattern used across the SDK:
//!
//! - inputs are passed as primitive C values or raw byte buffers
//! - results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - `secret_id` and `secret_data` are passed as `(*const u8, usize)` byte buffers
//! - `channels` is passed as a pointer to an array of `u64` channel IDs
//! - returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - on error, output buffers are returned empty and details are reported in
//!   the returned [`DeRecStatus`]
//!
//! # Serialized Share Map Format
//!
//! The sharing result is returned as a single serialized FFI container.
//! That container has the following layout:
//!
//! 1. A 32-bit little-endian count
//! 2. For each share entry, sorted by channel ID:
//!    - the channel ID as a 64-bit little-endian integer
//!    - a length-prefixed serialized [`CommittedDeRecShare`] protobuf
//!
//! This byte format is specific to the FFI layer and should be treated as an
//! opaque transport container by foreign callers unless they explicitly choose
//! to deserialize it.
//!
//! # Notes
//!
//! - This module does not expose Rust `HashMap` or collection types directly over FFI
//! - the output of this module is the raw set of committed shares for each helper;
//!   wrap each share into a delivery envelope using `produce_store_share_request_message`
//!   before sending it to its helper

use crate::{
    ffi::common::{
        DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
        write_len_prefixed, write_u32_le, write_u64_le,
    },
    types::ChannelId,
};
use derec_proto::CommittedDeRecShare;
use prost::Message;
use std::collections::HashMap;
use std::str;

/// FFI result returned by [`protect_secret`].
///
/// On success:
///
/// - `status` indicates success
/// - `shares_wire_bytes` contains a serialized FFI share map, where each entry
///   associates a channel ID with serialized [`CommittedDeRecShare`] protobuf bytes
///
/// On failure:
///
/// - `status` contains an error
/// - `shares_wire_bytes` is returned empty
#[repr(C)]
pub struct ProtectSecretResult {
    pub status: DeRecStatus,
    pub shares_wire_bytes: DeRecBuffer,
}

/// Splits a secret into committed helper shares.
///
/// This is the C FFI entry point for the DeRec sharing flow.
///
/// The caller provides:
///
/// - `secret_id` as raw secret identifier bytes
/// - `secret_data` as raw secret bytes to protect
/// - `channels` as an array of `u64` channel IDs
/// - `threshold` as the recovery threshold
/// - `version` as the share-distribution version
///
/// On success, this function returns a serialized FFI container representing
/// a map from channel ID to serialized [`CommittedDeRecShare`] bytes.
///
/// Each returned share must be wrapped into a delivery envelope by calling
/// `produce_store_share_request_message` before being sent to the helper.
///
/// # Arguments
///
/// * `secret_id_ptr` - Pointer to secret ID bytes.
/// * `secret_id_len` - Length of the secret ID buffer.
/// * `secret_data_ptr` - Pointer to secret data bytes.
/// * `secret_data_len` - Length of the secret data buffer.
/// * `channels_ptr` - Pointer to an array of `u64` channel IDs.
/// * `channels_len` - Number of channel IDs.
/// * `threshold` - Recovery threshold.
/// * `version` - Share-distribution version number.
///
/// # Returns
///
/// Returns [`ProtectSecretResult`].
///
/// On success, the `shares_wire_bytes` buffer contains:
///
/// 1. a 32-bit little-endian entry count
/// 2. for each share entry:
///    - channel ID as little-endian `u64`
///    - a length-prefixed serialized [`CommittedDeRecShare`] protobuf
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `secret_id_ptr` is null while `secret_id_len > 0`
/// - `secret_data_ptr` is null while `secret_data_len > 0`
/// - `channels_ptr` is null while `channels_len > 0`
/// - the underlying Rust sharing API returns an error
///
/// # Safety
///
/// Each non-null pointer must point to the corresponding readable range:
///
/// - `secret_id_ptr` → `secret_id_len` bytes
/// - `secret_data_ptr` → `secret_data_len` bytes
/// - `channels_ptr` → `channels_len` `u64` values
///
/// Zero-length buffers are allowed and interpreted as empty slices.
#[unsafe(no_mangle)]
pub extern "C" fn protect_secret(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    secret_data_ptr: *const u8,
    secret_data_len: usize,
    channels_ptr: *const u64,
    channels_len: usize,
    threshold: usize,
    version: i32,
) -> ProtectSecretResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return ProtectSecretResult {
            status: err_status("secret_id_ptr is null"),
            shares_wire_bytes: empty_buffer(),
        };
    }

    if secret_data_ptr.is_null() && secret_data_len > 0 {
        return ProtectSecretResult {
            status: err_status("secret_data_ptr is null"),
            shares_wire_bytes: empty_buffer(),
        };
    }

    if channels_ptr.is_null() && channels_len > 0 {
        return ProtectSecretResult {
            status: err_status("channels_ptr is null"),
            shares_wire_bytes: empty_buffer(),
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

    let channel_ids: Vec<ChannelId> = if channels_len == 0 {
        vec![]
    } else {
        let raw = unsafe { std::slice::from_raw_parts(channels_ptr, channels_len) };
        raw.iter().map(|&id| ChannelId(id)).collect()
    };

    let result = match crate::sharing::protect_secret(
        secret_id,
        secret_data,
        &channel_ids,
        threshold,
        version,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProtectSecretResult {
                status: err_status(err.to_string()),
                shares_wire_bytes: empty_buffer(),
            };
        }
    };

    let shares_bytes = serialize_committed_shares(&result.shares);

    ProtectSecretResult {
        status: ok_status(),
        shares_wire_bytes: vec_into_buffer(shares_bytes),
    }
}

/// FFI result returned by [`produce_store_share_request_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `wire_bytes` contains a serialized [`derec_proto::DeRecMessage`] envelope
///   carrying an encrypted [`derec_proto::StoreShareRequestMessage`]
///
/// On failure:
///
/// - `status` contains an error
/// - `wire_bytes` is returned empty
#[repr(C)]
pub struct ProduceStoreShareRequestMessageResult {
    pub status: DeRecStatus,
    pub wire_bytes: DeRecBuffer,
}

/// Wraps a committed helper share into an encrypted delivery envelope.
///
/// This is the C FFI entry point for step 2 of the DeRec sharing flow.
///
/// The caller provides a serialized [`CommittedDeRecShare`] (as returned by
/// the FFI container produced by [`protect_secret`]), the helper's channel ID,
/// the share-distribution version, optional retention hints (`keep_list`), an
/// optional description, and the symmetric shared key established during pairing.
///
/// On success, this function returns a serialized [`derec_proto::DeRecMessage`]
/// envelope whose inner payload is an encrypted [`derec_proto::StoreShareRequestMessage`].
/// The caller should send these bytes to the helper over the channel transport.
///
/// # Arguments
///
/// * `channel_id` - Channel ID of the target helper.
/// * `version` - Share-distribution version number.
/// * `committed_share_ptr` - Pointer to serialized [`CommittedDeRecShare`] protobuf bytes.
/// * `committed_share_len` - Length of the committed share buffer.
/// * `keep_list_ptr` - Pointer to an array of `i32` version numbers to retain. May be null
///   when `keep_list_len` is `0`.
/// * `keep_list_len` - Number of entries in `keep_list`.
/// * `description_ptr` - Pointer to a UTF-8 description string (not null-terminated). May
///   be null when `description_len` is `0`.
/// * `description_len` - Byte length of the description.
/// * `shared_key_ptr` - Pointer to the 32-byte symmetric shared key.
/// * `shared_key_len` - Must be exactly `32`.
///
/// # Returns
///
/// Returns [`ProduceStoreShareRequestMessageResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - any non-null pointer constraint is violated
/// - `shared_key_len != 32`
/// - `committed_share` cannot be decoded as a valid [`CommittedDeRecShare`] protobuf
/// - the underlying Rust API returns an error
///
/// # Safety
///
/// Each non-null pointer must point to the corresponding readable range.
#[unsafe(no_mangle)]
pub extern "C" fn produce_store_share_request_message(
    channel_id: u64,
    version: i32,
    committed_share_ptr: *const u8,
    committed_share_len: usize,
    keep_list_ptr: *const i32,
    keep_list_len: usize,
    description_ptr: *const u8,
    description_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProduceStoreShareRequestMessageResult {
    macro_rules! bail {
        ($msg:expr) => {
            return ProduceStoreShareRequestMessageResult {
                status: err_status($msg),
                wire_bytes: empty_buffer(),
            }
        };
    }

    if committed_share_ptr.is_null() && committed_share_len > 0 {
        bail!("committed_share_ptr is null");
    }
    if keep_list_ptr.is_null() && keep_list_len > 0 {
        bail!("keep_list_ptr is null");
    }
    if description_ptr.is_null() && description_len > 0 {
        bail!("description_ptr is null");
    }
    if shared_key_ptr.is_null() {
        bail!("shared_key_ptr is null");
    }
    if shared_key_len != 32 {
        bail!("shared_key_len must be exactly 32");
    }

    let committed_share_bytes: &[u8] = if committed_share_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(committed_share_ptr, committed_share_len) }
    };

    let keep_list: &[i32] = if keep_list_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(keep_list_ptr, keep_list_len) }
    };

    let description: &str = if description_len == 0 {
        ""
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(description_ptr, description_len) };
        match str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => bail!("description is not valid UTF-8"),
        }
    };

    let shared_key_bytes = unsafe { std::slice::from_raw_parts(shared_key_ptr, 32) };
    let shared_key: &[u8; 32] = shared_key_bytes
        .try_into()
        .expect("shared_key_len validated to be 32");

    let committed_share =
        match CommittedDeRecShare::decode(committed_share_bytes) {
            Ok(s) => s,
            Err(e) => bail!(format!("failed to decode CommittedDeRecShare: {e}")),
        };

    let result = match crate::sharing::produce_store_share_request_message(
        ChannelId(channel_id),
        version,
        &committed_share,
        keep_list,
        description,
        shared_key,
    ) {
        Ok(r) => r,
        Err(e) => bail!(e.to_string()),
    };

    ProduceStoreShareRequestMessageResult {
        status: ok_status(),
        wire_bytes: vec_into_buffer(result.wire_bytes),
    }
}

/// FFI result returned by [`produce_store_share_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `wire_bytes` contains a serialized [`derec_proto::DeRecMessage`] envelope
///   carrying an encrypted [`derec_proto::StoreShareResponseMessage`] to send back to the Owner
/// - `committed_share_bytes` contains the serialized [`CommittedDeRecShare`] protobuf,
///   extracted from the request, for the Helper to store locally
///
/// On failure:
///
/// - `status` contains an error
/// - both `wire_bytes` and `committed_share_bytes` are returned empty
#[repr(C)]
pub struct ProduceStoreShareResponseMessageResult {
    pub status: DeRecStatus,
    pub wire_bytes: DeRecBuffer,
    pub committed_share_bytes: DeRecBuffer,
}

/// Processes an incoming sharing request on behalf of a Helper.
///
/// This is the C FFI entry point for processing a [`derec_proto::StoreShareRequestMessage`].
///
/// The caller provides:
///
/// - `channel_id`: the channel this request arrived on
/// - `shared_key`: the 32-byte symmetric key shared with the Owner
/// - `request_bytes`: the serialized outer [`derec_proto::DeRecMessage`] envelope received
///   from the Owner, as produced by `produce_store_share_request_message`
///
/// On success, this function returns:
///
/// - an encrypted [`derec_proto::StoreShareResponseMessage`] envelope (send to the Owner)
/// - the serialized [`CommittedDeRecShare`] protobuf (store locally)
///
/// # Arguments
///
/// * `channel_id` - Channel ID of the originating Owner channel.
/// * `shared_key_ptr` - Pointer to the 32-byte symmetric shared key.
/// * `shared_key_len` - Must be exactly `32`.
/// * `request_bytes_ptr` - Pointer to the serialized request envelope bytes.
/// * `request_bytes_len` - Length of the request envelope buffer.
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `shared_key_ptr` is null or `shared_key_len != 32`
/// - `request_bytes_ptr` is null while `request_bytes_len > 0`
/// - the underlying Rust API returns an error (decryption, decode, validation)
///
/// # Safety
///
/// Each non-null pointer must point to the corresponding readable range.
#[unsafe(no_mangle)]
pub extern "C" fn produce_store_share_response_message(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    request_bytes_ptr: *const u8,
    request_bytes_len: usize,
) -> ProduceStoreShareResponseMessageResult {
    macro_rules! bail {
        ($msg:expr) => {
            return ProduceStoreShareResponseMessageResult {
                status: err_status($msg),
                wire_bytes: empty_buffer(),
                committed_share_bytes: empty_buffer(),
            }
        };
    }

    if shared_key_ptr.is_null() {
        bail!("shared_key_ptr is null");
    }
    if shared_key_len != 32 {
        bail!("shared_key_len must be exactly 32");
    }
    if request_bytes_ptr.is_null() && request_bytes_len > 0 {
        bail!("request_bytes_ptr is null");
    }

    let shared_key_bytes = unsafe { std::slice::from_raw_parts(shared_key_ptr, 32) };
    let shared_key: &[u8; 32] = shared_key_bytes
        .try_into()
        .expect("shared_key_len validated to be 32");

    let request_bytes: &[u8] = if request_bytes_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_bytes_ptr, request_bytes_len) }
    };

    let result = match crate::sharing::produce_store_share_response_message(
        ChannelId(channel_id),
        shared_key,
        request_bytes,
    ) {
        Ok(r) => r,
        Err(e) => bail!(e.to_string()),
    };

    let committed_share_bytes = result.committed_share.encode_to_vec();

    ProduceStoreShareResponseMessageResult {
        status: ok_status(),
        wire_bytes: vec_into_buffer(result.wire_bytes),
        committed_share_bytes: vec_into_buffer(committed_share_bytes),
    }
}

/// FFI result returned by [`process_store_share_response_message`].
///
/// On success:
///
/// - `status` indicates success
///
/// On failure (including the Helper explicitly rejecting the share):
///
/// - `status` contains an error describing the cause, including the Helper's
///   status code and memo when the rejection originates from the Helper
#[repr(C)]
pub struct ProcessStoreShareResponseMessageResult {
    pub status: DeRecStatus,
}

/// Validates a sharing response received from a Helper.
///
/// This is the C FFI entry point for the Owner-side validation of a
/// [`derec_proto::StoreShareResponseMessage`].
///
/// The caller provides:
///
/// - `version`: the version number sent in the original request
/// - `shared_key`: the 32-byte symmetric key shared with the Helper
/// - `response_bytes`: the serialized outer [`derec_proto::DeRecMessage`] envelope
///   received from the Helper, as produced by `produce_store_share_response_message`
///
/// On success the returned `status` indicates success. If the Helper's response
/// status is not `Ok`, the call fails and the Helper's status code and memo are
/// embedded in the returned error message.
///
/// # Arguments
///
/// * `version` - Version number from the original request.
/// * `shared_key_ptr` - Pointer to the 32-byte symmetric shared key.
/// * `shared_key_len` - Must be exactly `32`.
/// * `response_bytes_ptr` - Pointer to the serialized response envelope bytes.
/// * `response_bytes_len` - Length of the response envelope buffer.
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `shared_key_ptr` is null or `shared_key_len != 32`
/// - `response_bytes_ptr` is null while `response_bytes_len > 0`
/// - the underlying Rust API returns an error (decryption, decode, invariant violation)
///
/// # Safety
///
/// Each non-null pointer must point to the corresponding readable range.
#[unsafe(no_mangle)]
pub extern "C" fn process_store_share_response_message(
    version: i32,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    response_bytes_ptr: *const u8,
    response_bytes_len: usize,
) -> ProcessStoreShareResponseMessageResult {
    macro_rules! bail {
        ($msg:expr) => {
            return ProcessStoreShareResponseMessageResult {
                status: err_status($msg),
            }
        };
    }

    if shared_key_ptr.is_null() {
        bail!("shared_key_ptr is null");
    }
    if shared_key_len != 32 {
        bail!("shared_key_len must be exactly 32");
    }
    if response_bytes_ptr.is_null() && response_bytes_len > 0 {
        bail!("response_bytes_ptr is null");
    }

    let shared_key_bytes = unsafe { std::slice::from_raw_parts(shared_key_ptr, 32) };
    let shared_key: &[u8; 32] = shared_key_bytes
        .try_into()
        .expect("shared_key_len validated to be 32");

    let response_bytes: &[u8] = if response_bytes_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(response_bytes_ptr, response_bytes_len) }
    };

    if let Err(e) = crate::sharing::process_store_share_response_message(
        version,
        shared_key,
        response_bytes,
    ) {
        bail!(e.to_string());
    }

    ProcessStoreShareResponseMessageResult {
        status: ok_status(),
    }
}

fn serialize_committed_shares(
    shares: &HashMap<ChannelId, CommittedDeRecShare>,
) -> Vec<u8> {
    let mut entries: Vec<_> = shares.iter().collect();
    entries
        .sort_by_key(|(channel_id, _)| <u64 as From<ChannelId>>::from(**channel_id));

    let mut out = Vec::new();

    let count = u32::try_from(entries.len()).expect("too many share entries");
    write_u32_le(&mut out, count);

    for (channel_id, share) in entries {
        write_u64_le(
            &mut out,
            <u64 as From<ChannelId>>::from(*channel_id),
        );
        write_len_prefixed(&mut out, &share.encode_to_vec());
    }

    out
}
