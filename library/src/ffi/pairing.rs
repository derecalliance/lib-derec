//! C FFI exports for the DeRec *pairing* flow.
//!
//! This module exposes the pairing flow through a C-compatible ABI so that
//! non-Rust consumers can:
//!
//! 1. Create an out-of-band `ContactMessage` payload
//! 2. Produce a pairing request envelope
//! 3. Produce a pairing response envelope and derive the initiator-side shared key
//! 4. Process a pairing response envelope and derive the responder-side shared key
//!
//! All exported functions follow the same general pattern:
//!
//! - inputs are passed as primitive C values or raw byte buffers
//! - protocol messages are passed as serialized wire bytes
//! - opaque key material is passed as serialized byte buffers defined by this FFI layer
//! - results are returned as `#[repr(C)]` structs containing:
//!   - a [`DeRecStatus`] indicating success or failure
//!   - one or more [`DeRecBuffer`] values containing output bytes
//!
//! # FFI Conventions
//!
//! - string inputs are passed as `(*const u8, usize)` and must be valid UTF-8
//! - protocol message inputs are passed as raw serialized bytes
//! - returned protocol outputs are also serialized bytes
//! - returned buffers must be released by the caller using the common FFI
//!   buffer-freeing helper exposed elsewhere in the FFI surface
//! - on error, output buffers are returned empty and details are reported in
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
//! - `ContactMessage` is the only DeRec protocol payload exchanged out-of-band;
//!   it is returned here as plain serialized protobuf bytes
//! - pairing request and response outputs are serialized outer `DeRecMessage`
//!   envelopes whose inner messages are encrypted
//! - `SenderKind` is supplied over FFI as its raw `i32` protobuf enum value
//! - protobuf decoding and protocol validation are delegated to the core Rust SDK

use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_optional_len_prefixed_vec, vec_into_buffer, write_len_prefixed,
    write_optional_len_prefixed,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{SenderKind, TransportProtocol};
use prost::Message;

/// FFI result returned by [`create_contact_message`].
///
/// On success:
///
/// - `status` indicates success
/// - `contact_message` contains plain serialized `ContactMessage` protobuf bytes
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
/// - `pair_request_message` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `PairRequestMessage`
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
/// - `pair_response_message` contains serialized outer `DeRecMessage` bytes
///   carrying an encrypted inner `PairResponseMessage`
/// - `transport_protocol` contains serialized `TransportProtocol` protobuf bytes
///   extracted from the validated pairing request
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
    pub transport_protocol: DeRecBuffer,
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

/// Creates a serialized `ContactMessage` and its associated pairing secret key material.
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
/// - plain serialized `ContactMessage` protobuf bytes
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

    let contact_message_bytes = result.wire_bytes;
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    CreateContactMessageResult {
        status: ok_status(),
        contact_message: vec_into_buffer(contact_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

/// Produces a serialized pairing request envelope from a serialized `ContactMessage`.
///
/// This is the C FFI entry point for the second step of the DeRec pairing flow.
///
/// The caller provides:
///
/// - `sender_kind` as the raw `i32` protobuf enum value of [`SenderKind`]
/// - `transport_uri_ptr` / `transport_uri_len` as the responder transport URI
/// - a plain serialized `ContactMessage` protobuf buffer
///
/// On success, this function returns:
///
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `PairRequestMessage`
/// - opaque secret key material that must be retained by the caller and later
///   supplied to [`process_pairing_response_message`]
///
/// # Arguments
///
/// * `sender_kind` - Raw protobuf enum value of [`SenderKind`].
/// * `transport_uri_ptr` - Pointer to UTF-8 transport URI bytes.
/// * `transport_uri_len` - Length of the transport URI buffer.
/// * `contact_message_ptr` - Pointer to plain serialized `ContactMessage` protobuf bytes.
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
/// - `transport_uri_ptr` is null
/// - `contact_message_ptr` is null
/// - `transport_uri` is not valid UTF-8
/// - `sender_kind` is not a valid [`SenderKind`]
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// The input pointers must either be null (in which case an error is returned)
/// or point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_request_message(
    sender_kind: i32,
    transport_uri_ptr: *const u8,
    transport_uri_len: usize,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> ProducePairingRequestMessageResult {
    if transport_uri_ptr.is_null() {
        return ProducePairingRequestMessageResult {
            status: err_status("transport_uri_ptr is null"),
            pair_request_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    if contact_message_ptr.is_null() {
        return ProducePairingRequestMessageResult {
            status: err_status("contact_message_ptr is null"),
            pair_request_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    let sender_kind = match SenderKind::try_from(sender_kind) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingRequestMessageResult {
                status: err_status(format!("invalid SenderKind value: {sender_kind}")),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let transport_uri_bytes =
        unsafe { std::slice::from_raw_parts(transport_uri_ptr, transport_uri_len) };

    let transport_uri = match std::str::from_utf8(transport_uri_bytes) {
        Ok(value) => value,
        Err(_) => {
            return ProducePairingRequestMessageResult {
                status: err_status("transport_uri is not valid UTF-8"),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let contact_message_bytes =
        unsafe { std::slice::from_raw_parts(contact_message_ptr, contact_message_len) };

    let result = match crate::pairing::produce_pairing_request_message(
        sender_kind,
        transport_uri,
        contact_message_bytes,
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

    let pair_request_message_bytes = result.wire_bytes;
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    ProducePairingRequestMessageResult {
        status: ok_status(),
        pair_request_message: vec_into_buffer(pair_request_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

/// Produces a serialized pairing response envelope and the final shared key.
///
/// This is the C FFI entry point for the initiator-side finalization step of the
/// pairing flow.
///
/// The caller provides:
///
/// - `sender_kind` as the raw `i32` protobuf enum value of [`SenderKind`]
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `PairRequestMessage`
/// - opaque pairing secret key material previously returned by
///   [`create_contact_message`]
///
/// On success, this function returns:
///
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `PairResponseMessage`
/// - serialized `TransportProtocol` protobuf bytes extracted from the request
/// - the derived pairing shared key bytes
///
/// # Arguments
///
/// * `sender_kind` - Raw protobuf enum value of [`SenderKind`].
/// * `pair_request_message_ptr` - Pointer to serialized outer request envelope bytes.
/// * `pair_request_message_len` - Length of the serialized outer request buffer.
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
/// - `sender_kind` is not a valid [`SenderKind`]
/// - the secret key material bytes are not valid for this FFI format
/// - the underlying Rust pairing API returns an error
///
/// # Safety
///
/// The input pointers must either be null (in which case an error is returned)
/// or point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_response_message(
    sender_kind: i32,
    pair_request_message_ptr: *const u8,
    pair_request_message_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProducePairingResponseMessageResult {
    if pair_request_message_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("pair_request_message_ptr is null"),
            pair_response_message: empty_buffer(),
            transport_protocol: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    if secret_key_material_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("secret_key_material_ptr is null"),
            pair_response_message: empty_buffer(),
            transport_protocol: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    let sender_kind = match SenderKind::try_from(sender_kind) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingResponseMessageResult {
                status: err_status(format!("invalid SenderKind value: {sender_kind}")),
                pair_response_message: empty_buffer(),
                transport_protocol: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_request_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_request_message_ptr, pair_request_message_len) };

    let secret_key_material_bytes =
        unsafe { std::slice::from_raw_parts(secret_key_material_ptr, secret_key_material_len) };

    let pairing_secret_key_material =
        match deserialize_pairing_secret_key_material(secret_key_material_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProducePairingResponseMessageResult {
                    status: err_status(format!("invalid secret key material: {err}")),
                    pair_response_message: empty_buffer(),
                    transport_protocol: empty_buffer(),
                    shared_key: empty_buffer(),
                };
            }
        };

    let result = match crate::pairing::produce_pairing_response_message(
        sender_kind,
        pair_request_message_bytes,
        &pairing_secret_key_material,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingResponseMessageResult {
                status: err_status(err.to_string()),
                pair_response_message: empty_buffer(),
                transport_protocol: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_response_message_bytes = result.wire_bytes;
    let transport_protocol_bytes = serialize_transport_protocol(&result.transport_protocol);
    let shared_key_bytes = serialize_pairing_shared_key(&result.shared_key);

    ProducePairingResponseMessageResult {
        status: ok_status(),
        pair_response_message: vec_into_buffer(pair_response_message_bytes),
        transport_protocol: vec_into_buffer(transport_protocol_bytes),
        shared_key: vec_into_buffer(shared_key_bytes),
    }
}

/// Processes a serialized pairing response envelope and derives the final shared key.
///
/// This is the C FFI entry point for the responder-side completion step of the
/// pairing flow.
///
/// The caller provides:
///
/// - a plain serialized `ContactMessage` protobuf
/// - serialized outer `DeRecMessage` bytes carrying an encrypted inner
///   `PairResponseMessage`
/// - opaque pairing secret key material previously returned by
///   [`produce_pairing_request_message`]
///
/// On success, this function returns:
///
/// - the derived pairing shared key bytes
///
/// # Arguments
///
/// * `contact_message_ptr` - Pointer to plain serialized `ContactMessage` bytes.
/// * `contact_message_len` - Length of the serialized contact message buffer.
/// * `pair_response_message_ptr` - Pointer to serialized outer response envelope bytes.
/// * `pair_response_message_len` - Length of the serialized outer response buffer.
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

    let pair_response_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_response_message_ptr, pair_response_message_len) };

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
        contact_message_bytes,
        pair_response_message_bytes,
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

fn serialize_transport_protocol(tp: &TransportProtocol) -> Vec<u8> {
    tp.encode_to_vec()
}
