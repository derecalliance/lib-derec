// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::{
    CommunicationInfo, ContactMessage, PairRequestMessage, PrePairRequestMessage, TransportProtocol,
    deserialize_pairing_secret_key_material, get_sender_kind,
    serialize_pairing_secret_key_material,
};
use crate::{
    primitives::pairing::request,
    utils::ContactMessageExt as _,
    wasm::{
        primitives::helpers::{from_js, to_js},
        ts_bindings_utils::{js_error, js_error_from_lib},
    },
};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct CreateContactResult {
    pub contact_message: ContactMessage,
    /// Empty for `NoKeys` mode (no keys are generated at
    /// contact-creation time). Populated for `InlineKeys` and
    /// `HashedKeys`.
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    pub initiator_contact_message: ContactMessage,
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub request: PairRequestMessage,
}

#[wasm_bindgen(js_name = "pairing_request_create_contact")]
pub fn create_contact(
    channel_id: u64,
    contact_mode: u32,
    transport_protocol: JsValue,
    nonce: JsValue,
) -> Result<JsValue, JsValue> {
    let contact_mode = derec_proto::ContactMode::try_from(contact_mode as i32).map_err(|_| {
        js_error(
            "INVALID_CONTACT_MODE",
            format!("invalid contact_mode value: {contact_mode}"),
        )
    })?;
    let transport_protocol: TransportProtocol = from_js(transport_protocol)?;
    let transport_protocol_proto: derec_proto::TransportProtocol = transport_protocol.into();
    let nonce = if nonce.is_null() || nonce.is_undefined() {
        None
    } else if nonce.is_bigint() {
        Some(
            u64::try_from(js_sys::BigInt::from(nonce))
                .map_err(|e| {
                    js_error("INVALID_NONCE", format!("nonce out of u64 range: {e:?}"))
                })?,
        )
    } else {
        Some(nonce.as_f64().ok_or_else(|| {
            js_error("INVALID_NONCE", "nonce must be BigInt, number, or null")
        })? as u64)
    };

    let result = request::create_contact(
        channel_id.into(),
        contact_mode,
        transport_protocol_proto,
        nonce,
    )
    .map_err(js_error_from_lib)?;

    let secret_key = match result.secret_key.as_ref() {
        Some(k) => serialize_pairing_secret_key_material(k)?,
        None => Vec::new(),
    };
    to_js(&CreateContactResult {
        contact_message: result.contact_message.into(),
        secret_key,
    })
}

/// Structurally validate a JS-side [`ContactMessage`]. Throws on any
/// mode/field inconsistency (unknown `contact_mode`, mode/field mismatch,
/// wrong binding-hash length).
#[wasm_bindgen(js_name = "pairing_contact_message_validate")]
pub fn validate_contact_message(contact_message: JsValue) -> Result<(), JsValue> {
    let cm: ContactMessage = from_js(contact_message)?;
    let cm_proto: derec_proto::ContactMessage = cm.into();
    cm_proto.validate().map_err(js_error_from_lib)
}

/// Encodes a [`ContactMessage`] to proto wire bytes. Structurally validates
/// the input first so a locally-constructed contact that violates the
/// mode/field invariant is rejected at the boundary rather than silently
/// serialized.
#[wasm_bindgen(js_name = "pairing_request_encode_contact")]
pub fn encode_contact(contact_message: JsValue) -> Result<Vec<u8>, JsValue> {
    let cm: ContactMessage = from_js(contact_message)?;
    let cm_proto: derec_proto::ContactMessage = cm.into();
    cm_proto.validate().map_err(js_error_from_lib)?;
    Ok(cm_proto.encode_to_vec())
}

/// Decodes a proto-encoded [`ContactMessage`]. Structurally validates the
/// decoded value before returning it to application code so consumers can
/// trust the mode/field invariants documented on the wire format.
#[wasm_bindgen(js_name = "pairing_request_decode_contact")]
pub fn decode_contact(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let cm = derec_proto::ContactMessage::decode(bytes)
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    cm.validate().map_err(js_error_from_lib)?;
    let cm_js: ContactMessage = cm.into();
    to_js(&cm_js)
}

#[wasm_bindgen(js_name = "pairing_request_produce")]
pub fn produce(
    kind: u32,
    transport_protocol: JsValue,
    contact_message: JsValue,
    communication_info: JsValue,
    parameter_range: JsValue,
) -> Result<JsValue, JsValue> {
    let sender_kind = get_sender_kind(kind)?;
    let transport_protocol: TransportProtocol = from_js(transport_protocol)?;
    let transport_protocol_proto: derec_proto::TransportProtocol = transport_protocol.into();
    let contact_message: ContactMessage = from_js(contact_message)?;
    let contact_message_proto: derec_proto::ContactMessage = contact_message.into();
    let communication_info: Option<CommunicationInfo> =
        if communication_info.is_null() || communication_info.is_undefined() {
            None
        } else {
            Some(from_js(communication_info)?)
        };
    let communication_info_proto: Option<derec_proto::CommunicationInfo> =
        communication_info.map(Into::into);
    let parameter_range_proto: Option<derec_proto::ParameterRange> =
        if parameter_range.is_null() || parameter_range.is_undefined() {
            None
        } else {
            let pr: super::ParameterRange = from_js(parameter_range)?;
            Some(pr.into())
        };

    let result = request::produce(
        sender_kind,
        transport_protocol_proto,
        &contact_message_proto,
        communication_info_proto,
        parameter_range_proto,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
        initiator_contact_message: result.initiator_contact_message.into(),
        secret_key: serialize_pairing_secret_key_material(&result.secret_key)?,
    })
}

#[wasm_bindgen(js_name = "pairing_request_extract")]
pub fn extract(envelope_bytes: &[u8], secret_key: &[u8]) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(secret_key)?;
    let result = request::extract(envelope_bytes, pairing_sk.ecies_secret_key())
        .map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        request: result.request.into(),
    })
}

#[derive(Serialize, Deserialize)]
pub struct ProducePrePairResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PrePairExtractResult {
    pub request: PrePairRequestMessage,
}

/// Scanner-side: build the plaintext `PrePairRequest` envelope for a
/// `HASHED_KEYS` contact.
#[wasm_bindgen(js_name = "pairing_request_produce_pre_pair")]
pub fn produce_pre_pair_request(
    transport_protocol: JsValue,
    contact_message: JsValue,
) -> Result<JsValue, JsValue> {
    let transport_protocol: TransportProtocol = from_js(transport_protocol)?;
    let transport_protocol_proto: derec_proto::TransportProtocol = transport_protocol.into();
    let contact_message: ContactMessage = from_js(contact_message)?;
    let contact_message_proto: derec_proto::ContactMessage = contact_message.into();

    let result =
        request::produce_pre_pair_request(transport_protocol_proto, &contact_message_proto)
            .map_err(js_error_from_lib)?;

    to_js(&ProducePrePairResult {
        envelope: result.envelope,
    })
}

/// Initiator-side: decode an inbound plaintext `PrePairRequest` envelope.
#[wasm_bindgen(js_name = "pairing_request_extract_pre_pair")]
pub fn extract_pre_pair(envelope_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let result = request::extract_pre_pair(envelope_bytes).map_err(js_error_from_lib)?;
    to_js(&PrePairExtractResult {
        request: result.request.into(),
    })
}
