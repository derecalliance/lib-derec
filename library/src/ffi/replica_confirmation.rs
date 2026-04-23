// SPDX-License-Identifier: Apache-2.0

//! C FFI exports for the DeRec *replica confirmation* flow.

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
};

/// FFI result returned by [`produce_replica_confirmation_request`].
#[repr(C)]
pub struct ProduceReplicaConfirmationRequestResult {
    pub status: DeRecStatus,
    pub request_wire_bytes: DeRecBuffer,
    pub fingerprint: DeRecBuffer,
}

/// FFI result returned by [`extract_replica_confirmation_request`].
#[repr(C)]
pub struct ExtractReplicaConfirmationRequestResult {
    pub status: DeRecStatus,
    pub replica_id: i32,
    pub fingerprint: DeRecBuffer,
}

/// FFI result returned by [`produce_replica_confirmation_response`].
#[repr(C)]
pub struct ProduceReplicaConfirmationResponseResult {
    pub status: DeRecStatus,
    pub response_wire_bytes: DeRecBuffer,
}

/// FFI result returned by [`process_replica_confirmation_response`].
#[repr(C)]
pub struct ProcessReplicaConfirmationResponseResult {
    pub status: DeRecStatus,
    pub replica_id: i32,
}

/// Produces a replica confirmation request envelope.
///
/// # Safety
///
/// `shared_key_ptr` must point to exactly `shared_key_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn produce_replica_confirmation_request(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    replica_id: i32,
) -> ProduceReplicaConfirmationRequestResult {
    let err = |msg: &str| ProduceReplicaConfirmationRequestResult {
        status: err_status(msg),
        request_wire_bytes: empty_buffer(),
        fingerprint: empty_buffer(),
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

    match crate::primitives::replica_confirmation::request::produce(
        channel_id.into(),
        &shared_key,
        replica_id,
    ) {
        Ok(r) => ProduceReplicaConfirmationRequestResult {
            status: ok_status(),
            request_wire_bytes: vec_into_buffer(r.envelope),
            fingerprint: vec_into_buffer(r.fingerprint.to_vec()),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes and decrypts a replica confirmation request, verifies the fingerprint,
/// and returns the peer's replica_id and the locally computed fingerprint.
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_replica_confirmation_request(
    request_ptr: *const u8,
    request_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ExtractReplicaConfirmationRequestResult {
    let err = |msg: &str| ExtractReplicaConfirmationRequestResult {
        status: err_status(msg),
        replica_id: 0,
        fingerprint: empty_buffer(),
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

    let extract_result = match crate::primitives::replica_confirmation::request::extract(
        request_bytes,
        &shared_key,
    ) {
        Ok(r) => r,
        Err(e) => return err(&e.to_string()),
    };

    if let Err(e) = crate::primitives::replica_confirmation::request::verify_fingerprint(
        &extract_result.request,
        &shared_key,
    ) {
        return err(&e.to_string());
    }

    let fingerprint = derec_cryptography::replica::fingerprint(&shared_key);

    ExtractReplicaConfirmationRequestResult {
        status: ok_status(),
        replica_id: extract_result.request.replica_id,
        fingerprint: vec_into_buffer(fingerprint.to_vec()),
    }
}

/// Produces a replica confirmation response envelope.
///
/// # Safety
///
/// `shared_key_ptr` must point to exactly `shared_key_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn produce_replica_confirmation_response(
    channel_id: u64,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
    replica_id: i32,
) -> ProduceReplicaConfirmationResponseResult {
    let err = |msg: &str| ProduceReplicaConfirmationResponseResult {
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

    match crate::primitives::replica_confirmation::response::produce(
        channel_id.into(),
        &shared_key,
        replica_id,
    ) {
        Ok(r) => ProduceReplicaConfirmationResponseResult {
            status: ok_status(),
            response_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => err(&e.to_string()),
    }
}

/// Decodes, decrypts, and validates a replica confirmation response.
/// Returns the peer's replica_id.
///
/// # Safety
///
/// All non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_replica_confirmation_response(
    response_ptr: *const u8,
    response_len: usize,
    shared_key_ptr: *const u8,
    shared_key_len: usize,
) -> ProcessReplicaConfirmationResponseResult {
    let err = |msg: &str| ProcessReplicaConfirmationResponseResult {
        status: err_status(msg),
        replica_id: 0,
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

    let extract_result = match crate::primitives::replica_confirmation::response::extract(
        response_bytes,
        &shared_key,
    ) {
        Ok(r) => r,
        Err(e) => return err(&e.to_string()),
    };

    match crate::primitives::replica_confirmation::response::process(&extract_result.response) {
        Ok(r) => ProcessReplicaConfirmationResponseResult {
            status: ok_status(),
            replica_id: r.replica_id,
        },
        Err(e) => err(&e.to_string()),
    }
}
