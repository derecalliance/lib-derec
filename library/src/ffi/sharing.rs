use crate::{
    ffi::common::{
        DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
        write_len_prefixed, write_u32_le, write_u64_le,
    },
    types::ChannelId,
};
use derec_proto::StoreShareRequestMessage;
use prost::Message;

#[repr(C)]
pub struct ProtectSecretResult {
    pub status: DeRecStatus,
    pub shares: DeRecBuffer,
}

fn serialize_store_share_requests(
    shares: &std::collections::HashMap<crate::types::ChannelId, StoreShareRequestMessage>,
) -> Vec<u8> {
    let mut entries: Vec<_> = shares.iter().collect();
    entries.sort_by_key(|(channel_id, _)| **channel_id);

    let mut out = Vec::new();

    let count = u32::try_from(entries.len()).expect("too many share entries");
    write_u32_le(&mut out, count);

    for (channel_id, message) in entries {
        let encoded = message.encode_to_vec();
        write_u64_le(&mut out, (*channel_id).into());
        write_len_prefixed(&mut out, &encoded);
    }

    out
}

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

    let channels: &[u64] = if channels_len == 0 {
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

    let channels_vec: Vec<ChannelId> = channels.iter().map(|c| ChannelId(*c)).collect();

    let result = match crate::sharing::protect_secret(
        secret_id,
        secret_data,
        &channels_vec,
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

    let shares_bytes = serialize_store_share_requests(&result.shares);

    ProtectSecretResult {
        status: ok_status(),
        shares: vec_into_buffer(shares_bytes),
    }
}
