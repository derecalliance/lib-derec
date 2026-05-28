// SPDX-License-Identifier: Apache-2.0

use super::{
    CommunicationInfo, ContactMessage, PairRequestMessage, TransportProtocol,
    deserialize_pairing_secret_key_material, get_sender_kind,
    serialize_pairing_secret_key_material,
};
use crate::{
    primitives::pairing::request,
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
pub fn create_contact(channel_id: u64, transport_protocol: JsValue) -> Result<JsValue, JsValue> {
    let transport_protocol: TransportProtocol = from_js(transport_protocol)?;
    let transport_protocol_proto: derec_proto::TransportProtocol = transport_protocol.into();

    let result = request::create_contact(channel_id.into(), transport_protocol_proto)
        .map_err(js_error_from_lib)?;

    to_js(&CreateContactResult {
        contact_message: result.contact_message.into(),
        secret_key: serialize_pairing_secret_key_material(&result.secret_key)?,
    })
}

#[wasm_bindgen(js_name = "pairing_request_encode_contact")]
pub fn encode_contact(contact_message: JsValue) -> Result<Vec<u8>, JsValue> {
    let cm: ContactMessage = from_js(contact_message)?;
    let cm_proto: derec_proto::ContactMessage = cm.into();
    Ok(cm_proto.encode_to_vec())
}

#[wasm_bindgen(js_name = "pairing_request_decode_contact")]
pub fn decode_contact(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let cm = derec_proto::ContactMessage::decode(bytes)
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    let cm_js: ContactMessage = cm.into();
    to_js(&cm_js)
}

#[wasm_bindgen(js_name = "pairing_request_produce")]
pub fn produce(
    kind: u32,
    transport_protocol: JsValue,
    contact_message: JsValue,
    communication_info: JsValue,
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

    let result = request::produce(
        sender_kind,
        transport_protocol_proto,
        &contact_message_proto,
        communication_info_proto,
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
