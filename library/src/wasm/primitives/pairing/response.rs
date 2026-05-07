// SPDX-License-Identifier: Apache-2.0

use super::{
    deserialize_pairing_secret_key_material, get_sender_kind, js_to_contact_message,
    transport_protocol_to_js, TransportProtocolJs,
};
use crate::{
    primitives::pairing::{request, response},
    wasm::ts_bindings_utils::{DeRecMessageJs, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::DeRecMessage;
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct ProduceResultJs {
    envelope: DeRecMessageJs,
    peer_transport_protocol: TransportProtocolJs,
    pairing_shared_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProcessResultJs {
    pairing_shared_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct RejectResultJs {
    envelope: Vec<u8>,
    peer_transport_protocol: TransportProtocolJs,
}

/// Accepts a pairing request and derives the initiator-side shared key.
///
/// # Arguments
///
/// * `kind` - Sender role: `0` = OwnerNonRecovery, `1` = OwnerRecovery, `2` = Helper
/// * `pair_request` - Outer `DeRecMessage` JS object from `pairing_request_produce`
/// * `pairing_secret_key_material` - Serialized initiator-side `PairingSecretKeyMaterial`
///
/// # Returns
///
/// A JS object with:
///
/// - `envelope`: outer `DeRecMessage` as a plain JS object
/// - `peer_transport_protocol`: plain JS object
/// - `pairing_shared_key`: final shared pairing key
#[wasm_bindgen(js_name = "pairing_response_accept")]
pub fn accept(
    kind: u32,
    pair_request: JsValue,
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(pairing_secret_key_material)?;

    let request_envelope = js_to_derec_message(pair_request, "pair_request")?;
    let request_bytes = request_envelope.encode_to_vec();

    let request::ExtractResult { request } =
        request::extract(&request_bytes, pairing_sk.ecies_secret_key())
            .map_err(js_error_from_lib)?;

    let response::AcceptResult {
        envelope,
        peer_transport_protocol,
        shared_key,
    } = response::accept(get_sender_kind(kind)?, &request, &pairing_sk, None)
        .map_err(js_error_from_lib)?;

    let envelope_decoded = DeRecMessage::decode(envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    let wrapper = ProduceResultJs {
        envelope: derec_message_to_js(envelope_decoded),
        peer_transport_protocol: transport_protocol_to_js(&peer_transport_protocol),
        pairing_shared_key: shared_key.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Produces a pairing rejection envelope (FAIL status) for an incoming pairing request.
///
/// Use this when the local user declines an incoming pairing request. The result
/// is a properly encrypted `PairResponseMessage` with `FAIL` status and a memo
/// describing the reason.
///
/// # Arguments
///
/// * `kind` - Sender role: `0` = OwnerNonRecovery, `1` = OwnerRecovery, `2` = Helper
/// * `raw_message` - Raw wire bytes of the incoming `DeRecMessage` (same bytes passed to `process()`)
/// * `pairing_secret_key_material` - Serialized `PairingSecretKeyMaterial` for the contact
/// * `memo` - Human-readable rejection reason
///
/// # Returns
///
/// A JS object with:
///
/// - `envelope`: serialized `DeRecMessage` as `Vec<u8>` (ready to send via transport)
/// - `peer_transport_protocol`: plain JS object with `{ uri, protocol }`
#[wasm_bindgen(js_name = "pairing_response_reject")]
pub fn reject(
    kind: u32,
    raw_message: &[u8],
    pairing_secret_key_material: &[u8],
    memo: &str,
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(pairing_secret_key_material)?;

    let request::ExtractResult { request } =
        request::extract(raw_message, pairing_sk.ecies_secret_key())
            .map_err(js_error_from_lib)?;

    let response::RejectResult {
        envelope,
        peer_transport_protocol,
    } = response::reject(
        get_sender_kind(kind)?,
        &request,
        derec_proto::StatusEnum::Fail,
        memo,
        None,
    )
    .map_err(js_error_from_lib)?;

    let wrapper = RejectResultJs {
        envelope,
        peer_transport_protocol: transport_protocol_to_js(&peer_transport_protocol),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Processes a pairing response envelope and derives the responder-side shared key.
///
/// # Arguments
///
/// * `contact_message` - Plain JS `ContactMessage` object from `pairing_request_produce`
/// * `pair_response` - Outer `DeRecMessage` JS object from `pairing_response_produce`
/// * `pairing_secret_key_material` - Serialized responder-side `PairingSecretKeyMaterial`
///
/// # Returns
///
/// A JS object with:
///
/// - `pairing_shared_key`: final shared pairing key
#[wasm_bindgen(js_name = "pairing_response_process")]
pub fn process(
    contact_message: JsValue,
    pair_response: JsValue,
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let contact_message = js_to_contact_message(contact_message)?;
    let pairing_sk = deserialize_pairing_secret_key_material(pairing_secret_key_material)?;

    let response_envelope = js_to_derec_message(pair_response, "pair_response")?;
    let response_bytes = response_envelope.encode_to_vec();

    let response::ExtractResult { response } =
        response::extract(&response_bytes, pairing_sk.ecies_secret_key())
            .map_err(js_error_from_lib)?;

    let response::ProcessResult { shared_key } =
        response::process(&contact_message, &response, &pairing_sk)
            .map_err(js_error_from_lib)?;

    let wrapper = ProcessResultJs {
        pairing_shared_key: shared_key.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
