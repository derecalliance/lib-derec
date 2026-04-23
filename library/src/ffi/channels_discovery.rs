// SPDX-License-Identifier: Apache-2.0

//! C FFI exports for the DeRec *channels discovery* flow.

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
    read_u32_le, read_len_prefixed_vec, write_u32_le, write_len_prefixed,
};
use crate::primitives::channels_discovery::response::ChannelEntry;
use crate::types::ChannelId;

/// FFI result returned by [`produce_channels_discovery_request`].
#[repr(C)]
pub struct ProduceChannelsDiscoveryRequestResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`extract_channels_discovery_request`].
#[repr(C)]
pub struct ExtractChannelsDiscoveryRequestResult {
    pub status: DeRecStatus,
    pub last_batch_index: i32,
}

/// FFI result returned by [`produce_channels_discovery_response`].
#[repr(C)]
pub struct ProduceChannelsDiscoveryResponseResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`process_channels_discovery_response`].
///
/// `entries_wire_bytes` contains a serialized array of channel entries:
/// `count(u32le) + for-each: channel_id(u64le) + shared_key(len_prefixed)`.
#[repr(C)]
pub struct ProcessChannelsDiscoveryResponseResult {
    pub status: DeRecStatus,
    pub total_batches: i32,
    pub current_batch: i32,
    pub entries_wire_bytes: DeRecBuffer,
}

/// Produces a channels discovery request envelope (Replica side).
///
/// # Safety
///
/// `shared_key_ptr` must point to exactly `shared_key_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn produce_channels_discovery_request(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    last_batch_index: i32,
) -> ProduceChannelsDiscoveryRequestResult {
    let err = |msg: &str| ProduceChannelsDiscoveryRequestResult {
        status: err_status(msg),
        request_wire_bytes: empty_buffer(),
    };

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    match crate::primitives::channels_discovery::request::produce(
        channel_id.into(),
        &shared_key,
        last_batch_index,
    ) {
        Ok(r) => ProduceChannelsDiscoveryRequestResult {
            status: ok_status(),
            request_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes and decrypts a channels discovery request envelope (Owner side).
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_channels_discovery_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractChannelsDiscoveryRequestResult {
    let err = |msg: &str| ExtractChannelsDiscoveryRequestResult {
        status: err_status(msg),
        last_batch_index: 0,
    };

    if request_ptr.is_null() && request_len > 0 {
        return err("request_ptr is null");
    }
    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    match crate::primitives::channels_discovery::request::extract(request_bytes, &shared_key) {
        Ok(r) => ExtractChannelsDiscoveryRequestResult {
            status: ok_status(),
            last_batch_index: r.request.last_batch_index,
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Produces a channels discovery response envelope (Owner side).
///
/// `entries_ptr`/`entries_len` must point to a serialized entries buffer:
/// `count(u32le) + for-each: channel_id(u64le) + shared_key(len_prefixed)`.
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_channels_discovery_response(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    entries_ptr: *const u8,
    entries_len: usize,
    total_batches: i32,
    current_batch: i32,
) -> ProduceChannelsDiscoveryResponseResult {
    let err = |msg: &str| ProduceChannelsDiscoveryResponseResult {
        status: err_status(msg),
        response_wire_bytes: empty_buffer(),
    };

    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    let entries_bytes: &[u8] = if entries_len == 0 || entries_ptr.is_null() {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(entries_ptr, entries_len) }
    };

    let entries = match decode_channel_entries(entries_bytes) {
        Ok(v) => v,
        Err(msg) => return err(&msg),
    };

    match crate::primitives::channels_discovery::response::produce(
        channel_id.into(),
        &shared_key,
        &entries,
        total_batches,
        current_batch,
    ) {
        Ok(r) => ProduceChannelsDiscoveryResponseResult {
            status: ok_status(),
            response_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes, decrypts, and processes a channels discovery response (Replica side).
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_channels_discovery_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProcessChannelsDiscoveryResponseResult {
    let err = |msg: &str| ProcessChannelsDiscoveryResponseResult {
        status: err_status(msg),
        total_batches: 0,
        current_batch: 0,
        entries_wire_bytes: empty_buffer(),
    };

    if response_ptr.is_null() && response_len > 0 {
        return err("response_ptr is null");
    }
    if shared_key_ptr.is_null() && shared_key_len > 0 {
        return err("shared_key_ptr is null");
    }

    let response_bytes: &[u8] = if response_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(response_ptr, response_len) }
    };

    let shared_key_bytes: &[u8] = if shared_key_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(shared_key_ptr, shared_key_len) }
    };

    let shared_key: [u8; 32] = match shared_key_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return err("shared_key must be exactly 32 bytes"),
    };

    let extract_result = match crate::primitives::channels_discovery::response::extract(
        response_bytes,
        &shared_key,
    ) {
        Ok(r) => r,
        Err(e) => return err(&e.to_string()),
    };

    match crate::primitives::channels_discovery::response::process(&extract_result.response) {
        Ok(r) => {
            let encoded = encode_channel_entries(&r.entries);
            ProcessChannelsDiscoveryResponseResult {
                status: ok_status(),
                total_batches: r.total_batches,
                current_batch: r.current_batch,
                entries_wire_bytes: vec_into_buffer(encoded),
            }
        }
        Err(e) => err(&e.to_string()),
    }
}

fn encode_channel_entries(entries: &[ChannelEntry]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_u32_le(&mut buf, entries.len() as u32);
    for entry in entries {
        buf.extend_from_slice(&entry.channel_id.0.to_le_bytes());
        write_len_prefixed(&mut buf, &entry.shared_key);
    }
    buf
}

fn decode_channel_entries(mut data: &[u8]) -> Result<Vec<ChannelEntry>, String> {
    if data.is_empty() {
        return Ok(Vec::new());
    }

    let count = read_u32_le(&mut data).map_err(|e| format!("entries: {e}"))? as usize;
    let mut entries = Vec::with_capacity(count);

    for i in 0..count {
        if data.len() < 8 {
            return Err(format!("entry {i}: not enough bytes for channel_id"));
        }
        let channel_id = u64::from_le_bytes(data[..8].try_into().unwrap());
        data = &data[8..];

        let key_bytes = read_len_prefixed_vec(&mut data)
            .map_err(|e| format!("entry {i}: {e}"))?;
        let shared_key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| format!("entry {i}: shared_key must be 32 bytes"))?;

        entries.push(ChannelEntry {
            channel_id: ChannelId(channel_id),
            shared_key,
        });
    }

    Ok(entries)
}
