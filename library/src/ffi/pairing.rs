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
//! [`produce_pair_response_message`] (on the contact-initiator side) or
//! [`extract_pair_response`] / [`process_pair_response_message`] (on the
//! contact-responder side).

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_SHARED_KEY, DEREC_CODE_FFI_INVALID_ENUM,
    DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error, success,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    CommunicationInfo, ContactMessage, ContactMode, DeRecMessage, PairRequestMessage,
    PairResponseMessage, PrePairRequestMessage, PrePairResponseMessage, SenderKind,
    TransportProtocol,
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
    /// [`produce_pair_response_message`].
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProducePairResponseMessageResult {
    pub error: DeRecError,
    pub response_wire_bytes: DeRecBuffer,
    pub peer_transport_protocol: DeRecBuffer,
    pub shared_key: DeRecBuffer,
    /// Post-handshake rekey channel id the responder is committing to.
    /// Callers MUST atomically rename their local channel record from the
    /// pre-rekey id (the one passed to `produce_pair_response_message`) to
    /// this value as part of accepting the response. Zero on error.
    pub channel_id: u64,
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
    /// Post-handshake rekey channel id — already validated against the
    /// caller's own derivation. Callers MUST atomically rename their local
    /// channel record from the pre-rekey id (the one in the contact) to
    /// this value. Zero on error.
    pub channel_id: u64,
}


#[repr(C)]
pub struct ProducePrePairRequestMessageResult {
    pub error: DeRecError,
    /// Serialized outer plaintext `DeRecMessage` envelope carrying a
    /// `PrePairRequestMessage`. Ready to send over transport.
    pub envelope_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractPrePairRequestResult {
    pub error: DeRecError,
    /// Channel identifier decoded from the outer envelope's routing field.
    pub channel_id: u64,
    /// Inner `PrePairRequestMessage` proto bytes for chaining into
    /// [`produce_pre_pair_response_message`].
    pub request_proto_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ProducePrePairResponseMessageResult {
    pub error: DeRecError,
    /// Serialized outer plaintext `DeRecMessage` envelope carrying a
    /// `PrePairResponseMessage`. Ready to send over transport.
    pub envelope_wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ExtractPrePairResponseResult {
    pub error: DeRecError,
    /// Channel identifier decoded from the outer envelope's routing field.
    pub channel_id: u64,
    /// Inner `PrePairResponseMessage` proto bytes for chaining into
    /// [`process_pre_pair_response_message`].
    pub response_proto_bytes: DeRecBuffer,
}

/// On success the two key buffers hold the validated public keys republished
/// by the contact creator. On failure (status non-Ok, hash mismatch, etc.)
/// both buffers are empty; consult `error`.
#[repr(C)]
pub struct ProcessPrePairResponseMessageResult {
    pub error: DeRecError,
    pub mlkem_encapsulation_key: DeRecBuffer,
    pub ecies_public_key: DeRecBuffer,
    /// Nonce echoed from the original `ContactMessage`. Zero on failure.
    pub nonce: u64,
}

/// `contact_mode` must be a valid value of [`ContactMode`] (`0` = `INLINE_KEYS`,
/// `1` = `HASHED_KEYS`).
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn create_contact_message(
    channel_id: u64,
    contact_mode: i32,
    transport_protocol_ptr: *const u8,
    transport_protocol_len: usize,
) -> CreateContactMessageResult {
    let with_err = |error| CreateContactMessageResult {
        error,
        contact_wire_bytes: empty_buffer(),
        secret_key_material: empty_buffer(),
    };

    let contact_mode = match ContactMode::try_from(contact_mode) {
        Ok(m) => m,
        Err(_) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid ContactMode value: {contact_mode}"),
            ));
        }
    };

    let transport_protocol =
        match decode_transport_protocol(transport_protocol_ptr, transport_protocol_len) {
            Ok(t) => t,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::request::create_contact(
        channel_id.into(),
        contact_mode,
        transport_protocol,
    ) {
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

/// Structurally validate a proto-encoded `ContactMessage`. Returns a
/// successful [`DeRecError`] iff the contact's `(contact_mode, inline keys,
/// binding hash)` tuple satisfies the per-mode invariants enforced by the
/// pairing primitives. Intended for bindings to call at their parse
/// boundary (e.g. `FromProtoBytes`) so that the decoded value handed to
/// application code is guaranteed well-formed.
///
/// Failure codes:
/// - [`DEREC_CODE_FFI_BAD_PROTO`] if the bytes do not decode as a
///   `ContactMessage`.
/// - The library's `InvalidContactMessage` error code on any structural
///   violation (unknown `contact_mode`, mode/field mismatch, wrong
///   binding-hash length).
///
/// # Safety
///
/// `contact_message_ptr` must point to a readable range of
/// `contact_message_len` bytes (or be null with `len == 0`).
#[unsafe(no_mangle)]
pub extern "C" fn validate_contact_message(
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> DeRecError {
    let contact_message_bytes = match parse_buffer(
        contact_message_ptr,
        contact_message_len,
        "contact_message_ptr",
    ) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let contact_message = match ContactMessage::decode(contact_message_bytes) {
        Ok(c) => c,
        Err(_) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "contact_message_bytes is not a valid ContactMessage",
            );
        }
    };
    match crate::primitives::pairing::request::validate(&contact_message) {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
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
    let contact_message_bytes = match parse_buffer(
        contact_message_ptr,
        contact_message_len,
        "contact_message_ptr",
    ) {
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
pub extern "C" fn produce_pair_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
) -> ProducePairResponseMessageResult {
    let with_err = |error| ProducePairResponseMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
        peer_transport_protocol: empty_buffer(),
        shared_key: empty_buffer(),
        channel_id: 0,
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

    match crate::primitives::pairing::response::produce(
        crate::types::ChannelId(channel_id),
        &request,
        &pairing_secret_key_material,
        communication_info,
    ) {
        Ok(r) => ProducePairResponseMessageResult {
            error: success(),
            response_wire_bytes: vec_into_buffer(r.envelope),
            peer_transport_protocol: vec_into_buffer(r.peer_transport_protocol.encode_to_vec()),
            shared_key: vec_into_buffer(r.shared_key.to_vec()),
            channel_id: r.channel_id.into(),
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
        channel_id: 0,
    };

    let contact_message_bytes = match parse_buffer(
        contact_message_ptr,
        contact_message_len,
        "contact_message_ptr",
    ) {
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
            channel_id: r.channel_id.into(),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Builds a plaintext `PrePairRequestMessage` envelope. Used by the scanner
/// when the contact was sent with `contact_mode == HASHED_KEYS`. The envelope
/// is unencrypted — no shared key exists yet — so the caller does not pass
/// secret key material here.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pre_pair_request_message(
    transport_protocol_ptr: *const u8,
    transport_protocol_len: usize,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> ProducePrePairRequestMessageResult {
    let with_err = |error| ProducePrePairRequestMessageResult {
        error,
        envelope_wire_bytes: empty_buffer(),
    };

    let transport_protocol =
        match decode_transport_protocol(transport_protocol_ptr, transport_protocol_len) {
            Ok(t) => t,
            Err(e) => return with_err(e),
        };
    let contact_message_bytes = match parse_buffer(
        contact_message_ptr,
        contact_message_len,
        "contact_message_ptr",
    ) {
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

    match crate::primitives::pairing::request::produce_pre_pair_request(
        transport_protocol,
        &contact_message,
    ) {
        Ok(r) => ProducePrePairRequestMessageResult {
            error: success(),
            envelope_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Decodes a plaintext `PrePairRequestMessage` envelope.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_pre_pair_request(
    envelope_ptr: *const u8,
    envelope_len: usize,
) -> ExtractPrePairRequestResult {
    let with_err = |error| ExtractPrePairRequestResult {
        error,
        channel_id: 0,
        request_proto_bytes: empty_buffer(),
    };

    let envelope_bytes = match parse_buffer(envelope_ptr, envelope_len, "envelope_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };

    let channel_id = match DeRecMessage::decode(envelope_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::pairing::request::extract_pre_pair(envelope_bytes) {
        Ok(r) => ExtractPrePairRequestResult {
            error: success(),
            channel_id,
            request_proto_bytes: vec_into_buffer(r.request.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Builds a plaintext `PrePairResponseMessage` envelope republishing the
/// initiator's public keys. The keys come from `secret_key_material` (which
/// retains them alongside the secrets in `HASHED_KEYS` flows).
///
/// `request_proto_ptr` / `request_proto_len` must be the `request_proto_bytes`
/// returned by [`extract_pre_pair_request`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn produce_pre_pair_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProducePrePairResponseMessageResult {
    let with_err = |error| ProducePrePairResponseMessageResult {
        error,
        envelope_wire_bytes: empty_buffer(),
    };

    let request_bytes =
        match parse_buffer(request_proto_ptr, request_proto_len, "request_proto_ptr") {
            Ok(b) => b,
            Err(e) => return with_err(e),
        };
    let request = match PrePairRequestMessage::decode(request_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode PrePairRequestMessage: {e}"),
            ));
        }
    };
    let pairing_secret_key_material =
        match decode_secret_key_material(secret_key_material_ptr, secret_key_material_len) {
            Ok(m) => m,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::response::produce_pre_pair(
        crate::types::ChannelId(channel_id),
        &request,
        &pairing_secret_key_material,
    ) {
        Ok(r) => ProducePrePairResponseMessageResult {
            error: success(),
            envelope_wire_bytes: vec_into_buffer(r.envelope),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Decodes a plaintext `PrePairResponseMessage` envelope.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn extract_pre_pair_response(
    envelope_ptr: *const u8,
    envelope_len: usize,
) -> ExtractPrePairResponseResult {
    let with_err = |error| ExtractPrePairResponseResult {
        error,
        channel_id: 0,
        response_proto_bytes: empty_buffer(),
    };

    let envelope_bytes = match parse_buffer(envelope_ptr, envelope_len, "envelope_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };

    let channel_id = match DeRecMessage::decode(envelope_bytes) {
        Ok(e) => e.channel_id,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode envelope: {e}"),
            ));
        }
    };

    match crate::primitives::pairing::response::extract_pre_pair(envelope_bytes) {
        Ok(r) => ExtractPrePairResponseResult {
            error: success(),
            channel_id,
            response_proto_bytes: vec_into_buffer(r.response.encode_to_vec()),
        },
        Err(e) => with_err(from_lib_error(e)),
    }
}

/// Scanner-side: validates a decoded `PrePairResponseMessage` against the
/// original `ContactMessage`'s SHA-384 binding hash. On success returns the
/// validated public keys and echoed nonce. On any failure (non-Ok status,
/// hash mismatch, nonce mismatch, missing fields) returns an error and
/// empty buffers.
///
/// `response_proto_ptr` / `response_proto_len` must be the
/// `response_proto_bytes` returned by [`extract_pre_pair_response`].
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn process_pre_pair_response_message(
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    response_proto_ptr: *const u8,
    response_proto_len: usize,
) -> ProcessPrePairResponseMessageResult {
    let with_err = |error| ProcessPrePairResponseMessageResult {
        error,
        mlkem_encapsulation_key: empty_buffer(),
        ecies_public_key: empty_buffer(),
        nonce: 0,
    };

    let contact_message_bytes = match parse_buffer(
        contact_message_ptr,
        contact_message_len,
        "contact_message_ptr",
    ) {
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
    let response = match PrePairResponseMessage::decode(response_bytes) {
        Ok(r) => r,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to decode PrePairResponseMessage: {e}"),
            ));
        }
    };

    match crate::primitives::pairing::response::process_pre_pair(&contact_message, &response) {
        Ok(r) => ProcessPrePairResponseMessageResult {
            error: success(),
            mlkem_encapsulation_key: vec_into_buffer(r.mlkem_encapsulation_key),
            ecies_public_key: vec_into_buffer(r.ecies_public_key),
            nonce: r.nonce,
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
