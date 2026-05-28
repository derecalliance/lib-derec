// SPDX-License-Identifier: Apache-2.0

//! C FFI for the DeRec pairing flow.
//!
//! Protocol semantics live in `library/src/primitives/pairing/`. Items below
//! describe only the FFI surface.
//!
//! # Pairing secret material
//!
//! [`PairingSecretKeyMaterial`] is serialized into an opaque FFI-specific
//! blob. Persist it and feed it back into [`extract_pair_request`] /
//! [`accept_pair_request_message`] / [`reject_pair_request_message`] (on the
//! contact-initiator side) or [`extract_pair_response`] /
//! [`process_pair_response_message`] (on the contact-responder side).

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_BAD_UTF8,
    DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error,
    success,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    CommunicationInfo, ContactMessage, DeRecMessage, PairRequestMessage, PairResponseMessage,
    SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message as _;

#[repr(C)]
pub struct CreateContactMessageResult {
    pub error: DeRecError,
    pub contact_wire_bytes: DeRecBuffer,
    /// Opaque pairing secret key material. See module docs.
    pub secret_key_material: DeRecBuffer,
}

#[repr(C)]
pub struct ProducePairRequestMessageResult {
    pub error: DeRecError,
    pub request_wire_bytes: DeRecBuffer,
    pub initiator_contact_message_wire_bytes: DeRecBuffer,
    /// Opaque pairing secret key material. See module docs.
    pub secret_key_material: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractPairRequestResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `PairRequestMessage` proto bytes for chaining into
    /// [`accept_pair_request_message`] or [`reject_pair_request_message`].
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct AcceptPairRequestMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
    pub peer_transport_protocol: DeRecBuffer,
    pub shared_key: DeRecBuffer,
}

#[repr(C)]
pub struct RejectPairRequestMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
    pub peer_transport_protocol: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractPairResponseResult {
    pub error: DeRecError,
    pub channel_id: u64,
    /// Inner `PairResponseMessage` proto bytes for chaining into
    /// [`process_pair_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

/// `shared_key` is populated only on success; empty on peer rejection (see
/// [`crate::ffi::error`]).
#[repr(C)]
pub struct ProcessPairResponseMessageResult {
    pub error: DeRecError,
    pub shared_key: DeRecBuffer,
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn create_contact_message(
    channel_id: u64,
    transport_protocol_ptr: *const u8,
    transport_protocol_len: usize,
) -> CreateContactMessageResult {
    let with_err = |error| CreateContactMessageResult {
        error,
        contact_wire_bytes: empty_buffer(),
        secret_key_material: empty_buffer(),
    };

    let transport_protocol =
        match decode_transport_protocol(transport_protocol_ptr, transport_protocol_len) {
            Ok(t) => t,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::request::create_contact(channel_id.into(), transport_protocol)
    {
        Ok(r) => CreateContactMessageResult {
            error: success(),
            contact_wire_bytes: vec_into_buffer(r.contact_message.encode_to_vec()),
            secret_key_material: vec_into_buffer(serialize_pairing_secret_key_material(
                &r.secret_key,
            )),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `communication_info_ptr` may be null / zero-length to indicate no
/// communication info; otherwise it must be serialized [`CommunicationInfo`]
/// proto bytes.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pair_request_message(
    sender_kind: i32,
    transport_protocol_ptr: *const u8,
    transport_protocol_len: usize,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
) -> ProducePairRequestMessageResult {
    let with_err = |error| ProducePairRequestMessageResult {
        error,
        request_wire_bytes: empty_buffer(),
        initiator_contact_message_wire_bytes: empty_buffer(),
        secret_key_material: empty_buffer(),
    };

    let sender_kind = match SenderKind::try_from(sender_kind) {
        Ok(v) => v,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid SenderKind value: {sender_kind}"),
            ));
        }
    };
    let transport_protocol =
        match decode_transport_protocol(transport_protocol_ptr, transport_protocol_len) {
            Ok(t) => t,
            Err(e) => return with_err(e),
        };
    let contact_message_bytes =
        match parse_buffer(contact_message_ptr, contact_message_len, "contact_message_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let contact_message = match ContactMessage::decode(contact_message_bytes) {
        Ok(c) => c,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "contact_message_bytes is not a valid ContactMessage",
            ));
        }
    };
    let communication_info =
        match decode_optional_communication_info(communication_info_ptr, communication_info_len) {
            Ok(c) => c,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::request::produce(
        sender_kind,
        transport_protocol,
        &contact_message,
        communication_info,
    ) {
        Ok(r) => ProducePairRequestMessageResult {
            error: success(),
            request_wire_bytes: vec_into_buffer(r.envelope),
            initiator_contact_message_wire_bytes: vec_into_buffer(
                r.initiator_contact_message.encode_to_vec(),
            ),
            secret_key_material: vec_into_buffer(serialize_pairing_secret_key_material(
                &r.secret_key,
            )),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_pair_request(
    request_ptr: *const u8,
    request_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ExtractPairRequestResult {
    let with_err = |error| ExtractPairRequestResult {
        error,
        channel_id: 0,
        request_proto_bytes: empty_buffer(),
    };

    let request_bytes = match parse_buffer(request_ptr, request_len, "request_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let pairing_secret_key_material =
        match decode_secret_key_material(secret_key_material_ptr, secret_key_material_len) {
            Ok(m) => m,
            Err(e) => return with_err(e),
        };

    let channel_id = match DeRecMessage::decode(request_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::pairing::request::extract(
        request_bytes,
        pairing_secret_key_material.ecies_secret_key(),
    ) {
        Ok(r) => ExtractPairRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_pair_request`]. `communication_info_ptr` may be null /
/// zero-length to indicate no communication info.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn accept_pair_request_message(
    sender_kind: i32,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
) -> AcceptPairRequestMessageResult {
    let with_err = |error| AcceptPairRequestMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
        peer_transport_protocol: empty_buffer(),
        shared_key: empty_buffer(),
    };

    let sender_kind = match SenderKind::try_from(sender_kind) {
        Ok(v) => v,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid SenderKind value: {sender_kind}"),
            ));
        }
    };
    let request_bytes =
        match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let request = match PairRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };
    let pairing_secret_key_material =
        match decode_secret_key_material(secret_key_material_ptr, secret_key_material_len) {
            Ok(m) => m,
            Err(e) => return with_err(e),
        };
    let communication_info =
        match decode_optional_communication_info(communication_info_ptr, communication_info_len) {
            Ok(c) => c,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::response::accept(
        sender_kind,
        &request,
        &pairing_secret_key_material,
        communication_info,
    ) {
        Ok(r) => AcceptPairRequestMessageResult {
            error: success(),
            response_wire_bytes: vec_into_buffer(r.envelope),
            peer_transport_protocol: vec_into_buffer(r.peer_transport_protocol.encode_to_vec()),
            shared_key: vec_into_buffer(r.shared_key.to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_pair_request`]. `status_enum` is the raw `i32` value
/// of [`StatusEnum`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn reject_pair_request_message(
    sender_kind: i32,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    status_enum: i32,
    memo_ptr: *const u8,
    memo_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
) -> RejectPairRequestMessageResult {
    let with_err = |error| RejectPairRequestMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
        peer_transport_protocol: empty_buffer(),
    };

    let sender_kind = match SenderKind::try_from(sender_kind) {
        Ok(v) => v,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid SenderKind value: {sender_kind}"),
            ));
        }
    };
    let status_enum_value = match StatusEnum::try_from(status_enum) {
        Ok(v) => v,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid StatusEnum value: {status_enum}"),
            ));
        }
    };
    let request_bytes =
        match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let request = match PairRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode request: {e}"),
            ));
        }
    };
    let memo_bytes = match parse_buffer(memo_ptr, memo_len, "memo_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let memo = match std::str::from_utf8(memo_bytes) {
        Ok(s) => s,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_UTF8,
                "memo is not valid UTF-8",
            ));
        }
    };
    let communication_info =
        match decode_optional_communication_info(communication_info_ptr, communication_info_len) {
            Ok(c) => c,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::response::reject(
        sender_kind,
        &request,
        status_enum_value,
        memo,
        communication_info,
    ) {
        Ok(r) => RejectPairRequestMessageResult {
            error: success(),
            response_wire_bytes: vec_into_buffer(r.envelope),
            peer_transport_protocol: vec_into_buffer(r.peer_transport_protocol.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_pair_response(
    response_ptr: *const u8,
    response_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ExtractPairResponseResult {
    let with_err = |error| ExtractPairResponseResult {
        error,
        channel_id: 0,
        response_proto_bytes: empty_buffer(),
    };

    let response_bytes = match parse_buffer(response_ptr, response_len, "response_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let pairing_secret_key_material =
        match decode_secret_key_material(secret_key_material_ptr, secret_key_material_len) {
            Ok(m) => m,
            Err(e) => return with_err(e),
        };

    let channel_id = match DeRecMessage::decode(response_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::pairing::response::extract(
        response_bytes,
        pairing_secret_key_material.ecies_secret_key(),
    ) {
        Ok(r) => ExtractPairResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by [`extract_pair_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_pair_response_message(
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    response_proto_ptr: *const u8,
    response_proto_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProcessPairResponseMessageResult {
    let with_err = |error| ProcessPairResponseMessageResult {
        error,
        shared_key: empty_buffer(),
    };

    let contact_message_bytes =
        match parse_buffer(contact_message_ptr, contact_message_len, "contact_message_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let contact_message = match ContactMessage::decode(contact_message_bytes) {
        Ok(c) => c,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "contact_message_bytes is not a valid ContactMessage",
            ));
        }
    };
    let response_bytes =
        match parse_buffer(response_proto_ptr, response_proto_len, "response_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let response = match PairResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode response: {e}"),
            ));
        }
    };
    let pairing_secret_key_material =
        match decode_secret_key_material(secret_key_material_ptr, secret_key_material_len) {
            Ok(m) => m,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::response::process(
        &contact_message,
        &response,
        &pairing_secret_key_material,
    ) {
        Ok(r) => ProcessPairResponseMessageResult {
            error: success(),
            shared_key: vec_into_buffer(r.shared_key.to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

fn parse_buffer<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], DeRecError> {
    if ptr.is_null() && len > 0 {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            format!("{name} is null"),
        ));
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

fn decode_transport_protocol(ptr: *const u8, len: usize) -> Result<TransportProtocol, DeRecError> {
    let bytes = parse_buffer(ptr, len, "transport_protocol_ptr")?;
    TransportProtocol::decode(bytes).map_err(|_| {
        ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "transport_protocol_bytes is not a valid TransportProtocol",
        )
    })
}

fn decode_optional_communication_info(
    ptr: *const u8,
    len: usize,
) -> Result<Option<CommunicationInfo>, DeRecError> {
    if ptr.is_null() || len == 0 {
        return Ok(None);
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    CommunicationInfo::decode(bytes).map(Some).map_err(|_| {
        ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info_bytes is not a valid CommunicationInfo",
        )
    })
}

fn decode_secret_key_material(
    ptr: *const u8,
    len: usize,
) -> Result<PairingSecretKeyMaterial, DeRecError> {
    let bytes = parse_buffer(ptr, len, "secret_key_material_ptr")?;
    PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..]).map_err(|e| {
        ffi_error(
            DEREC_CODE_FFI_BAD_SHARED_KEY,
            format!("invalid secret key material: {e}"),
        )
    })
}

fn serialize_pairing_secret_key_material(sk: &PairingSecretKeyMaterial) -> Vec<u8> {
    let mut out = Vec::new();
    sk.serialize_uncompressed(&mut out)
        .expect("PairingSecretKeyMaterial serialization is infallible");
    out
}
