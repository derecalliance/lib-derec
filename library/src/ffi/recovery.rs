use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_u32_le, vec_into_buffer,
};
use derec_proto::{GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage};
use prost::Message;

#[repr(C)]
pub struct GenerateShareRequestResult {
    pub status: DeRecStatus,
    pub get_share_request_message: DeRecBuffer,
}

#[repr(C)]
pub struct GenerateShareResponseResult {
    pub status: DeRecStatus,
    pub get_share_response_message: DeRecBuffer,
}

#[repr(C)]
pub struct RecoverFromShareResponsesResult {
    pub status: DeRecStatus,
    pub secret_data: DeRecBuffer,
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_share_request(
    channel_id: u64,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> GenerateShareRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareRequestResult {
            status: err_status("secret_id_ptr is null"),
            get_share_request_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request =
        match crate::recovery::generate_share_request(channel_id.into(), secret_id, version) {
            Ok(value) => value,
            Err(err) => {
                return GenerateShareRequestResult {
                    status: err_status(err.to_string()),
                    get_share_request_message: empty_buffer(),
                };
            }
        };

    let request_bytes = request.encode_to_vec();

    GenerateShareRequestResult {
        status: ok_status(),
        get_share_request_message: vec_into_buffer(request_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_share_response(
    channel_id: u64,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    request_ptr: *const u8,
    request_len: usize,
    share_content_ptr: *const u8,
    share_content_len: usize,
) -> GenerateShareResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("secret_id_ptr is null"),
            get_share_response_message: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("request_ptr is null"),
            get_share_response_message: empty_buffer(),
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return GenerateShareResponseResult {
            status: err_status("share_content_ptr is null"),
            get_share_response_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let share_content_bytes: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let request = match GetShareRequestMessage::decode(request_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(format!("invalid GetShareRequestMessage protobuf: {err}")),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let share_content = match StoreShareRequestMessage::decode(share_content_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(format!("invalid StoreShareRequestMessage protobuf: {err}")),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let response = match crate::recovery::generate_share_response(
        channel_id.into(),
        secret_id,
        &request,
        &share_content,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateShareResponseResult {
                status: err_status(err.to_string()),
                get_share_response_message: empty_buffer(),
            };
        }
    };

    let response_bytes = response.encode_to_vec();

    GenerateShareResponseResult {
        status: ok_status(),
        get_share_response_message: vec_into_buffer(response_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn recover_from_share_responses(
    responses_ptr: *const u8,
    responses_len: usize,
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> RecoverFromShareResponsesResult {
    if responses_ptr.is_null() && responses_len > 0 {
        return RecoverFromShareResponsesResult {
            status: err_status("responses_ptr is null"),
            secret_data: empty_buffer(),
        };
    }

    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return RecoverFromShareResponsesResult {
            status: err_status("secret_id_ptr is null"),
            secret_data: empty_buffer(),
        };
    }

    let responses_bytes: &[u8] = if responses_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(responses_ptr, responses_len) }
    };

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let responses = match deserialize_share_responses(responses_bytes) {
        Ok(value) => value,
        Err(err) => {
            return RecoverFromShareResponsesResult {
                status: err_status(err),
                secret_data: empty_buffer(),
            };
        }
    };

    let recovered_secret =
        match crate::recovery::recover_from_share_responses(&responses, secret_id, version) {
            Ok(value) => value,
            Err(err) => {
                return RecoverFromShareResponsesResult {
                    status: err_status(err.to_string()),
                    secret_data: empty_buffer(),
                };
            }
        };

    RecoverFromShareResponsesResult {
        status: ok_status(),
        secret_data: vec_into_buffer(recovered_secret),
    }
}

fn deserialize_share_responses(bytes: &[u8]) -> Result<Vec<GetShareResponseMessage>, String> {
    let mut input = bytes;

    let count = read_u32_le(&mut input)? as usize;
    let mut responses = Vec::with_capacity(count);

    for _ in 0..count {
        let encoded = read_len_prefixed_vec(&mut input)?;
        let response = GetShareResponseMessage::decode(encoded.as_slice())
            .map_err(|err| format!("invalid GetShareResponseMessage protobuf: {err}"))?;
        responses.push(response);
    }

    if !input.is_empty() {
        return Err("unexpected trailing bytes in serialized share responses".to_string());
    }

    Ok(responses)
}
