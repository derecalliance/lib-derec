use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};
use derec_proto::{VerifyShareRequestMessage, VerifyShareResponseMessage};
use prost::Message;

#[repr(C)]
pub struct GenerateVerificationRequestResult {
    pub status: DeRecStatus,
    pub verify_share_request_message: DeRecBuffer,
}

#[repr(C)]
pub struct GenerateVerificationResponseResult {
    pub status: DeRecStatus,
    pub verify_share_response_message: DeRecBuffer,
}

#[repr(C)]
pub struct VerifyShareResponseResult {
    pub status: DeRecStatus,
    pub is_valid: bool,
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_verification_request(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    version: i32,
) -> GenerateVerificationRequestResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationRequestResult {
            status: err_status("secret_id_ptr is null"),
            verify_share_request_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let request = match crate::verification::generate_verification_request(secret_id, version) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationRequestResult {
                status: err_status(err.to_string()),
                verify_share_request_message: empty_buffer(),
            };
        }
    };

    let request_bytes = request.encode_to_vec();

    GenerateVerificationRequestResult {
        status: ok_status(),
        verify_share_request_message: vec_into_buffer(request_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn generate_verification_response(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    channel_id: u64,
    share_content_ptr: *const u8,
    share_content_len: usize,
    request_ptr: *const u8,
    request_len: usize,
) -> GenerateVerificationResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("secret_id_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("share_content_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    if request_ptr.is_null() && request_len > 0 {
        return GenerateVerificationResponseResult {
            status: err_status("request_ptr is null"),
            verify_share_response_message: empty_buffer(),
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let request_bytes: &[u8] = if request_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(request_ptr, request_len) }
    };

    let request = match VerifyShareRequestMessage::decode(request_bytes) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationResponseResult {
                status: err_status(format!("invalid VerifyShareRequestMessage protobuf: {err}")),
                verify_share_response_message: empty_buffer(),
            };
        }
    };

    let response = match crate::verification::generate_verification_response(
        secret_id,
        channel_id.into(),
        share_content,
        &request,
    ) {
        Ok(value) => value,
        Err(err) => {
            return GenerateVerificationResponseResult {
                status: err_status(err.to_string()),
                verify_share_response_message: empty_buffer(),
            };
        }
    };

    let response_bytes = response.encode_to_vec();

    GenerateVerificationResponseResult {
        status: ok_status(),
        verify_share_response_message: vec_into_buffer(response_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn verify_share_response(
    secret_id_ptr: *const u8,
    secret_id_len: usize,
    channel_id: u64,
    share_content_ptr: *const u8,
    share_content_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> VerifyShareResponseResult {
    if secret_id_ptr.is_null() && secret_id_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("secret_id_ptr is null"),
            is_valid: false,
        };
    }

    if share_content_ptr.is_null() && share_content_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("share_content_ptr is null"),
            is_valid: false,
        };
    }

    if response_ptr.is_null() && response_len > 0 {
        return VerifyShareResponseResult {
            status: err_status("response_ptr is null"),
            is_valid: false,
        };
    }

    let secret_id: &[u8] = if secret_id_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }
    };

    let share_content: &[u8] = if share_content_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(share_content_ptr, share_content_len) }
    };

    let response_bytes: &[u8] = if response_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(response_ptr, response_len) }
    };

    let response = match VerifyShareResponseMessage::decode(response_bytes) {
        Ok(value) => value,
        Err(err) => {
            return VerifyShareResponseResult {
                status: err_status(format!(
                    "invalid VerifyShareResponseMessage protobuf: {err}"
                )),
                is_valid: false,
            };
        }
    };

    let is_valid = match crate::verification::verify_share_response(
        secret_id,
        channel_id.into(),
        share_content,
        &response,
    ) {
        Ok(value) => value,
        Err(err) => {
            return VerifyShareResponseResult {
                status: err_status(err.to_string()),
                is_valid: false,
            };
        }
    };

    VerifyShareResponseResult {
        status: ok_status(),
        is_valid,
    }
}
