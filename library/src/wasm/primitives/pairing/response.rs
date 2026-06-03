// SPDX-License-Identifier: Apache-2.0

use super::{
    CommunicationInfo, ContactMessage, PairRequestMessage, PairResponseMessage,
    PrePairRequestMessage, PrePairResponseMessage, TransportProtocol,
    deserialize_pairing_secret_key_material,
};
use crate::{
    primitives::pairing::response,
    wasm::{
        primitives::helpers::{from_js, to_js},
        ts_bindings_utils::js_error_from_lib,
    },
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    pub peer_transport_protocol: TransportProtocol,
    #[serde(with = "serde_bytes")]
    pub shared_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub response: PairResponseMessage,
}

#[derive(Serialize, Deserialize)]
pub struct ProcessResult {
    #[serde(with = "serde_bytes")]
    pub shared_key: Vec<u8>,
}

#[wasm_bindgen(js_name = "pairing_response_produce")]
pub fn produce(
    channel_id: u64,
    request: JsValue,
    secret_key: &[u8],
    communication_info: JsValue,
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(secret_key)?;
    let request: PairRequestMessage = from_js(request)?;
    let request_proto: derec_proto::PairRequestMessage = request.into();
    let communication_info: Option<CommunicationInfo> =
        if communication_info.is_null() || communication_info.is_undefined() {
            None
        } else {
            Some(from_js(communication_info)?)
        };
    let communication_info_proto: Option<derec_proto::CommunicationInfo> =
        communication_info.map(Into::into);

    let result = response::produce(
        crate::types::ChannelId(channel_id),
        &request_proto,
        &pairing_sk,
        communication_info_proto,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
        peer_transport_protocol: result.peer_transport_protocol.into(),
        shared_key: result.shared_key.to_vec(),
    })
}

#[wasm_bindgen(js_name = "pairing_response_extract")]
pub fn extract(envelope_bytes: &[u8], secret_key: &[u8]) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(secret_key)?;
    let result = response::extract(envelope_bytes, pairing_sk.ecies_secret_key())
        .map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

#[wasm_bindgen(js_name = "pairing_response_process")]
pub fn process(
    contact_message: JsValue,
    response: JsValue,
    secret_key: &[u8],
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(secret_key)?;
    let contact_message: ContactMessage = from_js(contact_message)?;
    let contact_message_proto: derec_proto::ContactMessage = contact_message.into();
    let response: PairResponseMessage = from_js(response)?;
    let response_proto: derec_proto::PairResponseMessage = response.into();

    let result = response::process(&contact_message_proto, &response_proto, &pairing_sk)
        .map_err(js_error_from_lib)?;

    to_js(&ProcessResult {
        shared_key: result.shared_key.to_vec(),
    })
}

#[derive(Serialize, Deserialize)]
pub struct ProducePrePairResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PrePairExtractResult {
    pub response: PrePairResponseMessage,
}

#[derive(Serialize, Deserialize)]
pub struct ProcessPrePairResult {
    #[serde(with = "serde_bytes")]
    pub mlkem_encapsulation_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ecies_public_key: Vec<u8>,
    pub nonce: u64,
}

/// Contact-creator side: publish the actual public keys back to the scanner.
#[wasm_bindgen(js_name = "pairing_response_produce_pre_pair")]
pub fn produce_pre_pair(
    channel_id: u64,
    request: JsValue,
    secret_key: &[u8],
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(secret_key)?;
    let request: PrePairRequestMessage = from_js(request)?;
    let request_proto: derec_proto::PrePairRequestMessage = request.into();

    let result = response::produce_pre_pair(
        crate::types::ChannelId(channel_id),
        &request_proto,
        &pairing_sk,
    )
    .map_err(js_error_from_lib)?;

    to_js(&ProducePrePairResult {
        envelope: result.envelope,
    })
}

/// Scanner-side: decode the inbound plaintext `PrePairResponse` envelope.
#[wasm_bindgen(js_name = "pairing_response_extract_pre_pair")]
pub fn extract_pre_pair(envelope_bytes: &[u8]) -> Result<JsValue, JsValue> {
    let result = response::extract_pre_pair(envelope_bytes).map_err(js_error_from_lib)?;
    to_js(&PrePairExtractResult {
        response: result.response.into(),
    })
}

/// Scanner-side: validate the `PrePairResponse` against the contact's
/// SHA-384 binding hash. Returns the validated keys + nonce on match.
#[wasm_bindgen(js_name = "pairing_response_process_pre_pair")]
pub fn process_pre_pair(
    contact_message: JsValue,
    response: JsValue,
) -> Result<JsValue, JsValue> {
    let contact_message: ContactMessage = from_js(contact_message)?;
    let contact_message_proto: derec_proto::ContactMessage = contact_message.into();
    let response: PrePairResponseMessage = from_js(response)?;
    let response_proto: derec_proto::PrePairResponseMessage = response.into();

    let result = response::process_pre_pair(&contact_message_proto, &response_proto)
        .map_err(js_error_from_lib)?;

    to_js(&ProcessPrePairResult {
        mlkem_encapsulation_key: result.mlkem_encapsulation_key,
        ecies_public_key: result.ecies_public_key,
        nonce: result.nonce,
    })
}
