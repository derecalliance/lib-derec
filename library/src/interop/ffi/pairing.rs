// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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

use crate::extensions::contact_message::ContactMessageExt as _;
use crate::extensions::transport_protocol::TransportProtocolExt as _;
use crate::interop::dto::ContactMessage as ContactMessageDto;
use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
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
pub struct EncodeContactMessageResult {
    pub error: DeRecError,
    /// Proto-encoded `ContactMessage`, ready to publish out of band.
    pub wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct DecodeContactMessageResult {
    pub error: DeRecError,
    /// UTF-8 JSON object. See [`encode_contact_message`] for the shape.
    pub contact_json: DeRecBuffer,
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
    pub peer_transports: DeRecBuffer,
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
/// [`crate::interop::ffi::error`]).
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

/// Single entry point for all three modes:
/// - `contact_mode == 0` (`INLINE_KEYS`) — keys inlined in contact.
/// - `contact_mode == 1` (`HASHED_KEYS`) — binding hash inlined; keys via PrePair.
/// - `contact_mode == 2` (`NO_KEYS`) — no key material; keys generated on the
///   fly by the responder when the `PrePairRequest` arrives.
///
/// `has_nonce == 0` lets the library generate a fresh random `u64`.
/// `has_nonce == 1` uses the supplied `nonce` value verbatim; required for
/// `NO_KEYS` where callers typically pick a small human-typable value.
///
/// On success `secret_key_material` is populated for `INLINE_KEYS` and
/// `HASHED_KEYS`; it is empty for `NO_KEYS` (no keys exist at
/// contact-creation time).
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[unsafe(no_mangle)]
pub extern "C" fn create_contact_message(
    channel_id: u64,
    contact_mode: i32,
    transport_protocols_ptr: *const u8,
    transport_protocols_len: usize,
    has_nonce: u32,
    nonce: u64,
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

    let own = match decode_transport_protocol_list(transport_protocols_ptr, transport_protocols_len)
    {
        Ok(t) => t,
        Err(e) => return with_err(e),
    };

    let nonce = if has_nonce != 0 { Some(nonce) } else { None };

    match crate::primitives::pairing::request::create_contact(
        channel_id.into(),
        contact_mode,
        own,
        nonce,
    ) {
        Ok(r) => CreateContactMessageResult {
            error: success(),
            contact_wire_bytes: vec_into_buffer(r.contact_message.encode_to_vec()),
            secret_key_material: match r.secret_key {
                Some(k) => vec_into_buffer(serialize_pairing_secret_key_material(&k)),
                None => empty_buffer(),
            },
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
    match contact_message.validate() {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
    }
}

/// Encodes a JSON [`ContactMessageDto`] to `ContactMessage` proto wire bytes.
/// Structurally validates the input first so a locally-constructed contact
/// that violates the mode/field invariant is rejected at the boundary rather
/// than silently serialized.
///
/// The JSON shape is [`ContactMessageDto`]'s serde representation with one
/// adjustment applied at this seam: `channel_id` and `nonce` are decimal
/// strings, matching the `u64`-as-decimal-string convention every other FFI
/// JSON payload uses (see [`crate::interop::ffi::protocol::flow`]) because a host
/// whose numbers are IEEE-754 doubles cannot round-trip a full-width `u64`.
/// A plain JSON number is also accepted for either field.
///
/// # Safety
///
/// `contact_json_ptr` must point to a readable range of `contact_json_len`
/// bytes (or be null with `len == 0`).
#[unsafe(no_mangle)]
pub extern "C" fn encode_contact_message(
    contact_json_ptr: *const u8,
    contact_json_len: usize,
) -> EncodeContactMessageResult {
    let with_err = |error| EncodeContactMessageResult {
        error,
        wire_bytes: empty_buffer(),
    };

    let json_bytes = match parse_buffer(contact_json_ptr, contact_json_len, "contact_json_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let mut json: serde_json::Value = match serde_json::from_slice(json_bytes) {
        Ok(v) => v,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("contact_json is not valid JSON: {e}"),
            ));
        }
    };
    if let Err(e) = u64_id_fields_to_numbers(&mut json) {
        return with_err(ffi_error(DEREC_CODE_FFI_BAD_PROTO, e));
    }
    let dto: ContactMessageDto = match serde_json::from_value(json) {
        Ok(d) => d,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("contact_json is not a valid ContactMessage: {e}"),
            ));
        }
    };

    let contact_message: ContactMessage = dto.into();
    if let Err(e) = contact_message.validate() {
        return with_err(from_lib_error(e));
    }
    EncodeContactMessageResult {
        error: success(),
        wire_bytes: vec_into_buffer(contact_message.encode_to_vec()),
    }
}

/// Decodes proto-encoded `ContactMessage` wire bytes into the JSON
/// [`ContactMessageDto`] shape described on [`encode_contact_message`].
/// Structurally validates the decoded value before returning it to
/// application code so consumers can trust the mode/field invariants
/// documented on the wire format.
///
/// # Safety
///
/// `contact_wire_ptr` must point to a readable range of `contact_wire_len`
/// bytes (or be null with `len == 0`).
#[unsafe(no_mangle)]
pub extern "C" fn decode_contact_message(
    contact_wire_ptr: *const u8,
    contact_wire_len: usize,
) -> DecodeContactMessageResult {
    let with_err = |error| DecodeContactMessageResult {
        error,
        contact_json: empty_buffer(),
    };

    let wire_bytes = match parse_buffer(contact_wire_ptr, contact_wire_len, "contact_wire_ptr") {
        Ok(b) => b,
        Err(e) => return with_err(e),
    };
    let contact_message = match ContactMessage::decode(wire_bytes) {
        Ok(c) => c,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("contact_wire_bytes is not a valid ContactMessage: {e}"),
            ));
        }
    };
    if let Err(e) = contact_message.validate() {
        return with_err(from_lib_error(e));
    }

    let dto: ContactMessageDto = contact_message.into();
    let mut json = match serde_json::to_value(&dto) {
        Ok(v) => v,
        Err(e) => {
            return with_err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to encode ContactMessage as JSON: {e}"),
            ));
        }
    };
    u64_id_fields_to_strings(&mut json);
    match serde_json::to_vec(&json) {
        Ok(bytes) => DecodeContactMessageResult {
            error: success(),
            contact_json: vec_into_buffer(bytes),
        },
        Err(e) => with_err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            format!("failed to serialize ContactMessage JSON: {e}"),
        )),
    }
}

/// The `ContactMessage` fields that cross this seam as decimal strings.
const CONTACT_U64_ID_FIELDS: [&str; 2] = ["channel_id", "nonce"];

/// `communication_info_ptr` may be null / zero-length to indicate no
/// communication info; otherwise it must be serialized [`CommunicationInfo`]
/// proto bytes. `parameter_range_ptr` follows the same convention and
/// carries serialized [`derec_proto::ParameterRange`] bytes.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn produce_pair_request_message(
    sender_kind: i32,
    transport_protocols_ptr: *const u8,
    transport_protocols_len: usize,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
    parameter_range_ptr: *const u8,
    parameter_range_len: usize,
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
    let own = match decode_transport_protocol_list(transport_protocols_ptr, transport_protocols_len)
    {
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
    let parameter_range =
        match decode_optional_parameter_range(parameter_range_ptr, parameter_range_len) {
            Ok(p) => p,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::request::produce(
        sender_kind,
        own,
        &contact_message,
        communication_info,
        parameter_range,
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
/// `parameter_range_ptr` may be null / zero-length to indicate no
/// parameter range; otherwise it must be serialized
/// [`derec_proto::ParameterRange`] proto bytes.
///
/// # Safety
///
/// Non-null input pointers must point to the corresponding readable byte ranges.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub extern "C" fn produce_pair_response_message(
    channel_id: u64,
    request_proto_ptr: *const u8,
    request_proto_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
    parameter_range_ptr: *const u8,
    parameter_range_len: usize,
    unsafe_connection: u32,
) -> ProducePairResponseMessageResult {
    let with_err = |error| ProducePairResponseMessageResult {
        error,
        response_wire_bytes: empty_buffer(),
        peer_transports: empty_buffer(),
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
    let parameter_range =
        match decode_optional_parameter_range(parameter_range_ptr, parameter_range_len) {
            Ok(p) => p,
            Err(e) => return with_err(e),
        };

    match crate::primitives::pairing::response::produce(
        crate::types::ChannelId(channel_id),
        &request,
        &pairing_secret_key_material,
        communication_info,
        parameter_range,
        crate::transport::TransportPolicy::new(unsafe_connection != 0),
    ) {
        Ok(r) => ProducePairResponseMessageResult {
            error: success(),
            response_wire_bytes: vec_into_buffer(r.envelope),
            peer_transports: vec_into_buffer(encode_transport_list(&r.peer_transports)),
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
    transport_protocols_ptr: *const u8,
    transport_protocols_len: usize,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> ProducePrePairRequestMessageResult {
    let with_err = |error| ProducePrePairRequestMessageResult {
        error,
        envelope_wire_bytes: empty_buffer(),
    };

    let transport_protocols =
        match decode_transport_protocol_list(transport_protocols_ptr, transport_protocols_len) {
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
        transport_protocols,
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

/// Rewrites [`CONTACT_U64_ID_FIELDS`] from JSON numbers to decimal strings.
fn u64_id_fields_to_strings(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for field in CONTACT_U64_ID_FIELDS {
        if let Some(n) = object.get(field).and_then(serde_json::Value::as_u64) {
            object.insert(field.to_owned(), serde_json::Value::String(n.to_string()));
        }
    }
}

/// Reverse of [`u64_id_fields_to_strings`]. A field already holding a JSON
/// number is left untouched.
fn u64_id_fields_to_numbers(value: &mut serde_json::Value) -> Result<(), String> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    for field in CONTACT_U64_ID_FIELDS {
        let Some(serde_json::Value::String(raw)) = object.get(field) else {
            continue;
        };
        let parsed: u64 = raw
            .parse()
            .map_err(|e| format!("{field} must be a decimal u64 string, got {raw:?}: {e}"))?;
        object.insert(field.to_owned(), serde_json::Value::Number(parsed.into()));
    }
    Ok(())
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

/// Decode a length-delimited sequence of `TransportProtocol` messages.
///
/// Each entry is a protobuf varint byte length followed by that many bytes
/// of an encoded `TransportProtocol` — the same framing protobuf itself
/// uses for a repeated embedded message field, so every binding can build
/// it with the varint writer its protobuf runtime already exposes.
///
/// The list is the caller's served endpoints in its own preference order,
/// and that order is preserved exactly. Every entry is validated at this
/// seam, as the single-endpoint decoder does.
/// Frame a list of endpoints the way `decode_transport_protocol_list` reads
/// one: each entry preceded by its varint byte length.
fn encode_transport_list(endpoints: &[TransportProtocol]) -> Vec<u8> {
    let mut out = Vec::new();
    for endpoint in endpoints {
        let entry = endpoint.encode_to_vec();
        prost::encoding::encode_varint(entry.len() as u64, &mut out);
        out.extend_from_slice(&entry);
    }
    out
}

fn decode_transport_protocol_list(
    ptr: *const u8,
    len: usize,
) -> Result<Vec<TransportProtocol>, DeRecError> {
    let mut bytes = parse_buffer(ptr, len, "transport_protocols_ptr")?;
    let mut out = Vec::new();

    while !bytes.is_empty() {
        let entry_len = prost::encoding::decode_varint(&mut bytes).map_err(|_| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "transport_protocols_bytes has a malformed length prefix",
            )
        })? as usize;

        if entry_len > bytes.len() {
            return Err(ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "transport_protocols_bytes length prefix overruns the buffer",
            ));
        }

        let (entry, rest) = bytes.split_at(entry_len);
        bytes = rest;

        let tp = TransportProtocol::decode(entry).map_err(|_| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "transport_protocols_bytes contains an invalid TransportProtocol",
            )
        })?;
        tp.validate()
            .map_err(|e| from_lib_error(crate::Error::Transport(e)))?;
        out.push(tp);
    }

    if out.is_empty() {
        return Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "transport_protocols_bytes must carry at least one TransportProtocol",
        ));
    }

    Ok(out)
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

fn decode_optional_parameter_range(
    ptr: *const u8,
    len: usize,
) -> Result<Option<derec_proto::ParameterRange>, DeRecError> {
    if ptr.is_null() || len == 0 {
        return Ok(None);
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    derec_proto::ParameterRange::decode(bytes)
        .map(Some)
        .map_err(|_| {
            ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "parameter_range_bytes is not a valid ParameterRange",
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

#[cfg(test)]
mod contact_message_json_tests {
    use super::*;
    use crate::interop::ffi::common::derec_free_buffer;
    use crate::interop::ffi::error::{DEREC_CATEGORY_OK, derec_free_error};

    /// Copies a returned buffer out and releases it, matching the ABI
    /// contract foreign callers follow.
    fn take_buffer(buffer: DeRecBuffer) -> Vec<u8> {
        if buffer.ptr.is_null() {
            return Vec::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec();
        derec_free_buffer(buffer.ptr, buffer.len);
        bytes
    }

    fn release(mut error: DeRecError) -> i32 {
        let code = error.code;
        unsafe { derec_free_error(&mut error) };
        code
    }

    fn encode(json: &str) -> EncodeContactMessageResult {
        encode_contact_message(json.as_ptr(), json.len())
    }

    fn decode(wire: &[u8]) -> DecodeContactMessageResult {
        decode_contact_message(wire.as_ptr(), wire.len())
    }

    /// `channel_id` and `nonce` are above 2^53 deliberately: a host whose
    /// numbers are doubles must still see the exact value, which is why
    /// they cross as decimal strings.
    const VALID_INLINE_KEYS_JSON: &str = r#"{
        "channel_id": "18446744073709551615",
        "transport_protocol": { "uri": "https://owner.example.com", "protocol": 0 },
        "nonce": "9007199254740993",
        "contact_mode": 0,
        "mlkem_encapsulation_key": [1, 2, 3],
        "ecies_public_key": [4, 5, 6],
        "timestamp": { "seconds": 1700000000, "nanos": 42 }
    }"#;

    #[test]
    fn json_survives_encode_decode_round_trip() {
        let encoded = encode(VALID_INLINE_KEYS_JSON);
        assert_eq!(release(encoded.error), 0);
        let wire = take_buffer(encoded.wire_bytes);
        assert!(!wire.is_empty());

        let decoded = decode(&wire);
        assert_eq!(release(decoded.error), 0);
        let json_bytes = take_buffer(decoded.contact_json);
        let value: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(value["channel_id"], "18446744073709551615");
        assert_eq!(value["nonce"], "9007199254740993");
        assert_eq!(value["contact_mode"], 0);
        assert_eq!(
            value["transport_protocol"]["uri"],
            "https://owner.example.com"
        );
        assert_eq!(value["transport_protocol"]["protocol"], 0);
        assert_eq!(
            value["mlkem_encapsulation_key"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(value["ecies_public_key"], serde_json::json!([4, 5, 6]));
        assert!(value.get("contact_binding_hash").is_none());
        assert_eq!(value["timestamp"]["seconds"], 1700000000);
        assert_eq!(value["timestamp"]["nanos"], 42);

        // Re-encoding the decoded JSON reproduces the same wire bytes.
        let json_text = String::from_utf8(json_bytes).unwrap();
        let re_encoded = encode(&json_text);
        assert_eq!(release(re_encoded.error), 0);
        assert_eq!(take_buffer(re_encoded.wire_bytes), wire);
    }

    /// An `INLINE_KEYS` contact that also carries a binding hash violates
    /// the mode/field invariant. Both directions must reject it — encode so
    /// a locally-built contact is never published, decode so application
    /// code can trust what it is handed.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn invalid_contact_is_rejected_in_both_directions() {
        let invalid_json = r#"{
            "channel_id": "7",
            "transport_protocol": { "uri": "https://owner.example.com", "protocol": 0 },
            "nonce": "9",
            "contact_mode": 0,
            "mlkem_encapsulation_key": [1, 2, 3],
            "ecies_public_key": [4, 5, 6],
            "contact_binding_hash": [7, 7, 7],
            "timestamp": { "seconds": 1700000000, "nanos": 0 }
        }"#;

        let encoded = encode(invalid_json);
        assert_eq!(
            release(encoded.error),
            crate::interop::ffi::error::DEREC_CODE_INVALID_CONTACT_MESSAGE
        );
        assert_eq!(take_buffer(encoded.wire_bytes), Vec::<u8>::new());

        // The same invalid value built as proto bytes without going through
        // the encoder, so the decoder's own gate is what is under test.
        let invalid_wire = ContactMessage {
            channel_id: 7,
            transport_protocol: Some(TransportProtocol {
                uri: "https://owner.example.com".to_owned(),
                protocol: 0,
            }),
            nonce: 9,
            contact_mode: ContactMode::InlineKeys as i32,
            mlkem_encapsulation_key: Some(vec![1, 2, 3]),
            ecies_public_key: Some(vec![4, 5, 6]),
            contact_binding_hash: Some(vec![7, 7, 7]),
            timestamp: None,
            supported_transports: Vec::new(),
        }
        .encode_to_vec();

        let decoded = decode(&invalid_wire);
        assert_eq!(
            release(decoded.error),
            crate::interop::ffi::error::DEREC_CODE_INVALID_CONTACT_MESSAGE
        );
        assert_eq!(take_buffer(decoded.contact_json), Vec::<u8>::new());
    }

    /// A contact produced by the library itself decodes without any
    /// hand-written JSON in the loop.
    /// Frame a list of endpoints the way `decode_transport_protocol_list`
    /// expects: each entry preceded by its varint byte length.
    fn encode_transport_list(entries: &[TransportProtocol]) -> Vec<u8> {
        let mut out = Vec::new();
        for tp in entries {
            let bytes = tp.encode_to_vec();
            prost::encoding::encode_varint(bytes.len() as u64, &mut out);
            out.extend_from_slice(&bytes);
        }
        out
    }

    #[test]
    fn library_produced_contact_decodes() {
        let transport = encode_transport_list(&[TransportProtocol {
            uri: "https://owner.example.com".to_owned(),
            protocol: 0,
        }]);
        let created = create_contact_message(
            42,
            ContactMode::InlineKeys as i32,
            transport.as_ptr(),
            transport.len(),
            1,
            99,
        );
        assert_eq!(release(created.error), 0);
        let wire = take_buffer(created.contact_wire_bytes);
        let _ = take_buffer(created.secret_key_material);

        let decoded = decode(&wire);
        assert_eq!(release(decoded.error), DEREC_CATEGORY_OK);
        let value: serde_json::Value =
            serde_json::from_slice(&take_buffer(decoded.contact_json)).unwrap();
        assert_eq!(value["channel_id"], "42");
        assert_eq!(value["nonce"], "99");
        assert_eq!(value["contact_mode"], 0);
    }
}

/// The pairing entry points as a foreign caller sees them: raw pointers,
/// length-delimited endpoint lists, and error codes rather than `Result`.
///
/// These matter because validation deliberately lives in the primitives
/// rather than being repeated per SDK — every binding inherits whatever this
/// seam enforces, so what it enforces is worth pinning.
#[cfg(test)]
mod pairing_entry_point_tests {
    use super::*;
    use crate::interop::ffi::common::derec_free_buffer;
    use crate::interop::ffi::error::{DEREC_CATEGORY_OK, derec_free_error};

    fn take(buffer: DeRecBuffer) -> Vec<u8> {
        if buffer.ptr.is_null() {
            return Vec::new();
        }
        let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec();
        derec_free_buffer(buffer.ptr, buffer.len);
        bytes
    }

    fn release(mut error: DeRecError) -> i32 {
        let code = error.code;
        unsafe { derec_free_error(&mut error) };
        code
    }

    fn endpoint(uri: &str, protocol: derec_proto::Protocol) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: protocol as i32,
        }
    }

    /// The framing every endpoint list crosses this seam in.
    fn framed(entries: &[TransportProtocol]) -> Vec<u8> {
        encode_transport_list(entries)
    }

    fn create_contact(
        mode: derec_proto::ContactMode,
        framed_list: &[u8],
    ) -> CreateContactMessageResult {
        create_contact_message(
            42,
            mode as i32,
            framed_list.as_ptr(),
            framed_list.len(),
            0,
            0,
        )
    }

    /// The happy path, and the shape the other tests deviate from.
    #[test]
    fn create_contact_accepts_a_framed_endpoint_list() {
        let list = framed(&[
            endpoint("grpcs://a.example:443", derec_proto::Protocol::Grpc),
            endpoint("https://a.example/derec", derec_proto::Protocol::Https),
        ]);
        let result = create_contact(derec_proto::ContactMode::InlineKeys, &list);

        assert_eq!(result.error.category, DEREC_CATEGORY_OK, "unexpected error");
        let contact =
            derec_proto::ContactMessage::decode(take(result.contact_wire_bytes).as_slice())
                .expect("the produced contact decodes");
        let _ = take(result.secret_key_material);

        assert_eq!(contact.supported_transports.len(), 2);
        // The first entry also fills the deprecated singular field.
        #[allow(deprecated)]
        {
            assert_eq!(
                contact.transport_protocol.as_ref().map(|t| t.uri.as_str()),
                Some("grpcs://a.example:443"),
            );
        }
    }

    /// An empty list names no endpoint, so the contact would be unusable.
    /// Rejected at the seam rather than producing a contact nobody can answer.
    #[test]
    fn create_contact_rejects_an_empty_endpoint_list() {
        let result = create_contact(derec_proto::ContactMode::InlineKeys, &[]);

        assert_ne!(
            release(result.error),
            0,
            "an empty endpoint list must be refused"
        );
        let _ = take(result.contact_wire_bytes);
        let _ = take(result.secret_key_material);
    }

    /// Malformed framing is caught here rather than decoding into garbage: a
    /// length prefix claiming more bytes than the buffer holds.
    #[test]
    fn a_length_prefix_overrunning_the_buffer_is_refused() {
        // Varint 0x7F promises 127 bytes; only two follow.
        let malformed = [0x7Fu8, 0x00, 0x00];
        let result = create_contact(derec_proto::ContactMode::InlineKeys, &malformed);

        assert_ne!(
            release(result.error),
            0,
            "a length prefix past the end must be refused"
        );
        let _ = take(result.contact_wire_bytes);
        let _ = take(result.secret_key_material);
    }

    /// A structurally invalid endpoint inside the list is refused, so an SDK
    /// cannot smuggle a mismatched scheme past the seam.
    #[test]
    fn a_scheme_mismatched_endpoint_in_the_list_is_refused() {
        let list = framed(&[endpoint("ws://a.example", derec_proto::Protocol::Https)]);
        let result = create_contact(derec_proto::ContactMode::InlineKeys, &list);

        assert_ne!(
            release(result.error),
            0,
            "a scheme-mismatched endpoint must be refused"
        );
        let _ = take(result.contact_wire_bytes);
        let _ = take(result.secret_key_material);
    }

    /// The PrePair entry point takes the same framing, and refuses an empty
    /// list for the same reason: the reply would have nowhere to go.
    #[test]
    fn produce_pre_pair_request_requires_at_least_one_endpoint() {
        let list = framed(&[endpoint(
            "https://a.example/derec",
            derec_proto::Protocol::Https,
        )]);
        let contact = create_contact(derec_proto::ContactMode::HashedKeys, &list);
        assert_eq!(contact.error.category, DEREC_CATEGORY_OK);
        let contact_bytes = take(contact.contact_wire_bytes);
        let _ = take(contact.secret_key_material);

        let empty = produce_pre_pair_request_message(
            std::ptr::null(),
            0,
            contact_bytes.as_ptr(),
            contact_bytes.len(),
        );
        assert_ne!(
            release(empty.error),
            0,
            "a PrePair request naming no endpoint must be refused"
        );
        let _ = take(empty.envelope_wire_bytes);

        let ok = produce_pre_pair_request_message(
            list.as_ptr(),
            list.len(),
            contact_bytes.as_ptr(),
            contact_bytes.len(),
        );
        assert_eq!(
            ok.error.category, DEREC_CATEGORY_OK,
            "a framed list must be accepted"
        );
        let _ = take(ok.envelope_wire_bytes);
    }

    /// A null pointer with a non-zero length is a caller bug, not a decode
    /// failure — it must be reported rather than dereferenced.
    #[test]
    fn a_null_pointer_with_a_non_zero_length_is_refused() {
        let result = create_contact_message(42, 0, std::ptr::null(), 8, 0, 0);

        assert_ne!(
            release(result.error),
            0,
            "a null pointer with a non-zero length must be refused"
        );
        let _ = take(result.contact_wire_bytes);
        let _ = take(result.secret_key_material);
    }
}
