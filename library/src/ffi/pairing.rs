//! C FFI exports for the DeRec *pairing* flow.
//!
//! This module exposes the pairing flow through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create an out-of-band [`ContactMessage`]
//! 2. Produce a [`PairRequestMessage`]
//! 3. Produce a [`PairResponseMessage`]
//! 4. Process a [`PairResponseMessage`] and derive the final shared key
//!
//! All exported functions follow the same general pattern:
//!
//! - Inputs are passed as primitive C values or raw byte buffers
//! - Protobuf messages are passed as serialized protobuf bytes
//! - Opaque key material is passed as serialized byte buffers defined by this FFI layer
//! - Results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - String inputs are passed as `(*const u8, usize)` and must be valid UTF-8
//! - Protobuf inputs are passed as raw serialized bytes
//! - Returned protobuf outputs are also serialized bytes
//! - Returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - On error, output buffers are returned empty and details are reported in
//!   the returned [`DeRecStatus`]
//!
//! # Pairing Secret Material
//!
//! This module serializes the Rust pairing secret key material into an FFI-specific
//! binary format so that callers can persist and later pass it back into the
//! appropriate pairing functions. That format is an implementation detail of this
//! FFI layer and should be treated as opaque by foreign callers.
//!
//! # Notes
//!
//! - `ContactMessage` is the only DeRec protocol message exchanged out-of-band
//!   and is therefore passed directly as serialized protobuf bytes
//! - `SenderKind` is supplied over FFI as its raw `i32` protobuf enum value
//! - All protobuf decoding and validation happens inside this module before the
//!   core Rust SDK pairing functions are invoked

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_optional_len_prefixed_vec, vec_into_buffer, write_len_prefixed,
    write_optional_len_prefixed,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, SenderKind};
use prost::Message;

/// FFI result returned by [`create_contact_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `contact_message` contains the serialized [`ContactMessage`] protobuf bytes
/// - `secret_key_material` contains opaque serialized pairing secret key material
///   that must be stored by the caller and later supplied to
///   [`produce_pairing_response_message`]
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct CreateContactMessageResult {
    pub status: DeRecStatus,
    pub contact_message: DeRecBuffer,
    pub secret_key_material: DeRecBuffer,
}

/// FFI result returned by [`produce_pairing_request_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `pair_request_message` contains serialized [`derec_proto::PairRequestMessage`] bytes
/// - `secret_key_material` contains opaque serialized pairing secret key material
///   that must be stored by the caller and later supplied to
///   [`process_pairing_response_message`]
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct ProducePairingRequestMessageResult {
    pub status: DeRecStatus,
    pub pair_request_message: DeRecBuffer,
    pub secret_key_material: DeRecBuffer,
}

/// FFI result returned by [`produce_pairing_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `pair_response_message` contains serialized [`derec_proto::PairResponseMessage`] bytes
/// - `shared_key` contains the derived pairing shared key bytes
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct ProducePairingResponseMessageResult {
    pub status: DeRecStatus,
    pub pair_response_message: DeRecBuffer,
    pub shared_key: DeRecBuffer,
}

/// FFI result returned by [`process_pairing_response_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `shared_key` contains the derived pairing shared key bytes
///
/// On failure:
///
/// - `status` contains an error
/// - output buffers are empty
#[repr(C)]
pub struct ProcessPairingResponseMessageResult {
    pub status: DeRecStatus,
    pub shared_key: DeRecBuffer,
}

/// Creates a serialized [`ContactMessage`] and its associated pairing secret key material.
///
/// This is the C FFI entry point for the first step of the DeRec pairing flow.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `transport_uri_ptr` / `transport_uri_len` as a UTF-8 string buffer
///
/// On success, this function returns:
///
/// - a serialized [`ContactMessage`] protobuf
/// - opaque secret key material that must be retained by the caller and passed
///   back into [`produce_pairing_response_message`]
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used by the pairing flow.
/// * `transport_uri_ptr` - Pointer to UTF-8 transport URI bytes.
/// * `transport_uri_len` - Length of the transport URI buffer.
///
/// # Returns
///
/// Returns [`CreateContactMessageResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `transport_uri_ptr` is null
/// - the transport URI is not valid UTF-8
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// `transport_uri_ptr` must either be null (in which case an error is returned)
/// or point to `transport_uri_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn create_contact_message(
    channel_id: u64,
    transport_uri_ptr: *const u8,
    transport_uri_len: usize,
) -> CreateContactMessageResult {
    if transport_uri_ptr.is_null() {
        return CreateContactMessageResult {
            status: err_status("transport_uri_ptr is null"),
            contact_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    let transport_uri_bytes =
        unsafe { std::slice::from_raw_parts(transport_uri_ptr, transport_uri_len) };

    let transport_uri = match std::str::from_utf8(transport_uri_bytes) {
        Ok(value) => value,
        Err(_) => {
            return CreateContactMessageResult {
                status: err_status("transport_uri is not valid UTF-8"),
                contact_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let result = match crate::pairing::create_contact_message(channel_id.into(), transport_uri) {
        Ok(value) => value,
        Err(err) => {
            return CreateContactMessageResult {
                status: err_status(err.to_string()),
                contact_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let contact_message_bytes = result.contact_message.encode_to_vec();
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    CreateContactMessageResult {
        status: ok_status(),
        contact_message: vec_into_buffer(contact_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

/// Produces a serialized [`derec_proto::PairRequestMessage`] from a serialized [`ContactMessage`].
///
/// This is the C FFI entry point for the second step of the DeRec pairing flow.
///
/// The caller provides:
///
/// - `channel_id` as a raw `u64`
/// - `peer_status` as the raw `i32` protobuf enum value of [`SenderKind`]
/// - a serialized [`ContactMessage`] protobuf buffer
///
/// On success, this function returns:
///
/// - a serialized [`derec_proto::PairRequestMessage`] protobuf
/// - opaque secret key material that must be retained by the caller and later
///   supplied to [`process_pairing_response_message`]
///
/// # Arguments
///
/// * `channel_id` - Channel identifier used by the pairing flow.
/// * `peer_status` - Raw protobuf enum value of [`SenderKind`].
/// * `contact_message_ptr` - Pointer to serialized [`ContactMessage`] protobuf bytes.
/// * `contact_message_len` - Length of the serialized contact message buffer.
///
/// # Returns
///
/// Returns [`ProducePairingRequestMessageResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `contact_message_ptr` is null
/// - `peer_status` is not a valid [`SenderKind`]
/// - the contact message bytes are not a valid serialized [`ContactMessage`]
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// `contact_message_ptr` must either be null (in which case an error is returned)
/// or point to `contact_message_len` readable bytes.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_request_message(
    channel_id: u64,
    peer_status: i32,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> ProducePairingRequestMessageResult {
    if contact_message_ptr.is_null() {
        return ProducePairingRequestMessageResult {
            status: err_status("contact_message_ptr is null"),
            pair_request_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    let contact_message_bytes =
        unsafe { std::slice::from_raw_parts(contact_message_ptr, contact_message_len) };

    let contact_message = match ContactMessage::decode(contact_message_bytes) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingRequestMessageResult {
                status: err_status(format!("invalid ContactMessage protobuf: {err}")),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let sender_kind = match SenderKind::try_from(peer_status) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingRequestMessageResult {
                status: err_status(format!("invalid SenderKind value: {peer_status}")),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let result = match crate::pairing::produce_pairing_request_message(
        channel_id.into(),
        sender_kind,
        &contact_message,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingRequestMessageResult {
                status: err_status(err.to_string()),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let pair_request_message_bytes = result.pair_request_message.encode_to_vec();
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    ProducePairingRequestMessageResult {
        status: ok_status(),
        pair_request_message: vec_into_buffer(pair_request_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

/// Produces a serialized [`derec_proto::PairResponseMessage`] and the final shared key.
///
/// This is the C FFI entry point for the responder-side finalization step of the
/// pairing flow.
///
/// The caller provides:
///
/// - `peer_status` as the raw `i32` protobuf enum value of [`SenderKind`]
/// - a serialized [`derec_proto::PairRequestMessage`] protobuf
/// - opaque pairing secret key material previously returned by
///   [`create_contact_message`]
///
/// On success, this function returns:
///
/// - a serialized [`derec_proto::PairResponseMessage`] protobuf
/// - the derived pairing shared key bytes
///
/// # Arguments
///
/// * `peer_status` - Raw protobuf enum value of [`SenderKind`].
/// * `pair_request_message_ptr` - Pointer to serialized pair request bytes.
/// * `pair_request_message_len` - Length of the serialized pair request buffer.
/// * `secret_key_material_ptr` - Pointer to opaque serialized pairing secret key material.
/// * `secret_key_material_len` - Length of the secret key material buffer.
///
/// # Returns
///
/// Returns [`ProducePairingResponseMessageResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - `pair_request_message_ptr` is null
/// - `secret_key_material_ptr` is null
/// - `peer_status` is not a valid [`SenderKind`]
/// - the pair request bytes are not a valid serialized [`derec_proto::PairRequestMessage`]
/// - the secret key material bytes are not valid for this FFI format
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// The input pointers must either be null (in which case an error is returned)
/// or point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_response_message(
    peer_status: i32,
    pair_request_message_ptr: *const u8,
    pair_request_message_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProducePairingResponseMessageResult {
    if pair_request_message_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("pair_request_message_ptr is null"),
            pair_response_message: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    if secret_key_material_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("secret_key_material_ptr is null"),
            pair_response_message: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    let sender_kind = match SenderKind::try_from(peer_status) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingResponseMessageResult {
                status: err_status(format!("invalid SenderKind value: {peer_status}")),
                pair_response_message: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_request_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_request_message_ptr, pair_request_message_len) };

    let pair_request_message =
        match derec_proto::PairRequestMessage::decode(pair_request_message_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProducePairingResponseMessageResult {
                    status: err_status(format!("invalid PairRequestMessage protobuf: {err}")),
                    pair_response_message: empty_buffer(),
                    shared_key: empty_buffer(),
                };
            }
        };

    let secret_key_material_bytes =
        unsafe { std::slice::from_raw_parts(secret_key_material_ptr, secret_key_material_len) };

    let pairing_secret_key_material =
        match deserialize_pairing_secret_key_material(secret_key_material_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProducePairingResponseMessageResult {
                    status: err_status(format!("invalid secret key material: {err}")),
                    pair_response_message: empty_buffer(),
                    shared_key: empty_buffer(),
                };
            }
        };

    let result = match crate::pairing::produce_pairing_response_message(
        sender_kind,
        &pair_request_message,
        &pairing_secret_key_material,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingResponseMessageResult {
                status: err_status(err.to_string()),
                pair_response_message: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_response_message_bytes = result.pair_response_message.encode_to_vec();
    let shared_key_bytes = serialize_pairing_shared_key(&result.shared_key);

    ProducePairingResponseMessageResult {
        status: ok_status(),
        pair_response_message: vec_into_buffer(pair_response_message_bytes),
        shared_key: vec_into_buffer(shared_key_bytes),
    }
}

/// Processes a serialized [`derec_proto::PairResponseMessage`] and derives the final shared key.
///
/// This is the C FFI entry point for the requestor-side completion step of the
/// pairing flow.
///
/// The caller provides:
///
/// - a serialized [`ContactMessage`] protobuf
/// - a serialized [`derec_proto::PairResponseMessage`] protobuf
/// - opaque pairing secret key material previously returned by
///   [`produce_pairing_request_message`]
///
/// On success, this function returns:
///
/// - the derived pairing shared key bytes
///
/// # Arguments
///
/// * `contact_message_ptr` - Pointer to serialized [`ContactMessage`] bytes.
/// * `contact_message_len` - Length of the serialized contact message buffer.
/// * `pair_response_message_ptr` - Pointer to serialized pair response bytes.
/// * `pair_response_message_len` - Length of the serialized pair response buffer.
/// * `secret_key_material_ptr` - Pointer to opaque serialized pairing secret key material.
/// * `secret_key_material_len` - Length of the secret key material buffer.
///
/// # Returns
///
/// Returns [`ProcessPairingResponseMessageResult`].
///
/// # Errors
///
/// The returned `status` indicates failure if:
///
/// - any required pointer is null
/// - the contact message bytes are not a valid serialized [`ContactMessage`]
/// - the pair response bytes are not a valid serialized [`derec_proto::PairResponseMessage`]
/// - the secret key material bytes are not valid for this FFI format
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// The input pointers must either be null (in which case an error is returned)
/// or point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_pairing_response_message(
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    pair_response_message_ptr: *const u8,
    pair_response_message_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProcessPairingResponseMessageResult {
    if contact_message_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("contact_message_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    if pair_response_message_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("pair_response_message_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    if secret_key_material_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("secret_key_material_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    let contact_message_bytes =
        unsafe { std::slice::from_raw_parts(contact_message_ptr, contact_message_len) };

    let contact_message = match derec_proto::ContactMessage::decode(contact_message_bytes) {
        Ok(value) => value,
        Err(err) => {
            return ProcessPairingResponseMessageResult {
                status: err_status(format!("invalid ContactMessage protobuf: {err}")),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_response_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_response_message_ptr, pair_response_message_len) };

    let pair_response_message =
        match derec_proto::PairResponseMessage::decode(pair_response_message_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProcessPairingResponseMessageResult {
                    status: err_status(format!("invalid PairResponseMessage protobuf: {err}")),
                    shared_key: empty_buffer(),
                };
            }
        };

    let secret_key_material_bytes =
        unsafe { std::slice::from_raw_parts(secret_key_material_ptr, secret_key_material_len) };

    let pairing_secret_key_material =
        match deserialize_pairing_secret_key_material(secret_key_material_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProcessPairingResponseMessageResult {
                    status: err_status(format!("invalid secret key material: {err}")),
                    shared_key: empty_buffer(),
                };
            }
        };

    let result = match crate::pairing::process_pairing_response_message(
        &contact_message,
        &pair_response_message,
        &pairing_secret_key_material,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProcessPairingResponseMessageResult {
                status: err_status(err.to_string()),
                shared_key: empty_buffer(),
            };
        }
    };

    let shared_key_bytes = serialize_pairing_shared_key(&result.shared_key);

    ProcessPairingResponseMessageResult {
        status: ok_status(),
        shared_key: vec_into_buffer(shared_key_bytes),
    }
}
fn serialize_pairing_secret_key_material(sk: &PairingSecretKeyMaterial) -> Vec<u8> {
    let mut out = Vec::new();

    write_optional_len_prefixed(&mut out, sk.mlkem_decapsulation_key.as_deref());

    write_optional_len_prefixed(
        &mut out,
        sk.mlkem_shared_secret.as_ref().map(|x| x.as_slice()),
    );

    write_len_prefixed(&mut out, &sk.ecies_secret_key);

    out
}

fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, String> {
    let mut input = bytes;

    let mlkem_decapsulation_key = read_optional_len_prefixed_vec(&mut input)?;

    let mlkem_shared_secret = match read_optional_len_prefixed_vec(&mut input)? {
        Some(vec) => {
            let array: [u8; 32] = vec
                .try_into()
                .map_err(|_| "mlkem_shared_secret must be exactly 32 bytes".to_string())?;
            Some(array)
        }
        None => None,
    };

    let ecies_secret_key = read_len_prefixed_vec(&mut input)?;

    if !input.is_empty() {
        return Err("unexpected trailing bytes in secret key material".to_string());
    }

    Ok(PairingSecretKeyMaterial {
        mlkem_decapsulation_key,
        mlkem_shared_secret,
        ecies_secret_key,
    })
}

fn serialize_pairing_shared_key(
    shared_key: &derec_cryptography::pairing::PairingSharedKey,
) -> Vec<u8> {
    shared_key.to_vec()
}
