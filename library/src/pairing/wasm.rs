// SPDX-License-Identifier: Apache-2.0

use crate::pairing::{
    CreateContactMessageResult, ProducePairingRequestMessageResult,
    ProducePairingResponseMessageResult, create_contact_message, process_pairing_response_message,
    produce_pairing_request_message, produce_pairing_response_message,
};
use crate::protos::derec_proto::SenderKind;
use crate::protos::derec_proto::{ContactMessage, PairRequestMessage, PairResponseMessage};
use crate::ts_bindings_utils::{js_error, js_error_from_lib};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use prost::Message;

use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsCreateContactMessageResult {
    contact_message: Vec<u8>,
    secret_key_material: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProducePairingRequestMessage {
    pair_request_message: Vec<u8>,
    secret_key_material: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProducePairingResponseMessage {
    pair_response_message: Vec<u8>,
    pairing_shared_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TsProcessPairingResponseMessage {
    pairing_shared_key: Vec<u8>,
}

#[wasm_bindgen]
pub fn ts_create_contact_message(channel_id: u64, transport_uri: &str) -> Result<JsValue, JsValue> {
    let CreateContactMessageResult {
        contact_message,
        secret_key,
    } = create_contact_message(channel_id.into(), transport_uri).map_err(js_error_from_lib)?;

    let wrapper = TsCreateContactMessageResult {
        contact_message: contact_message.encode_to_vec(),
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

#[wasm_bindgen]
pub fn ts_produce_pairing_request_message(
    channel_id: u64,
    kind: u32,
    contact_message: &[u8],
) -> Result<JsValue, JsValue> {
    let contact_msg = ContactMessage::decode(contact_message)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;

    let sender_kind = get_sender_kind(kind)?;

    let ProducePairingRequestMessageResult {
        pair_request_message,
        secret_key,
    } = produce_pairing_request_message(channel_id.into(), sender_kind, &contact_msg)
        .map_err(js_error_from_lib)?;

    let wrapper = TsProducePairingRequestMessage {
        pair_request_message: pair_request_message.encode_to_vec(),
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

#[wasm_bindgen]
pub fn ts_produce_pairing_response_message(
    kind: u32,
    pair_request_message: &[u8],
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let pair_request_msg = PairRequestMessage::decode(pair_request_message)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;

    let pairing_sk =
        PairingSecretKeyMaterial::deserialize_uncompressed(&mut &pairing_secret_key_material[..])
            .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))?;

    let ProducePairingResponseMessageResult {
        pair_response_message,
        shared_key,
    } = produce_pairing_response_message(get_sender_kind(kind)?, &pair_request_msg, &pairing_sk)
        .map_err(js_error_from_lib)?;

    let wrapper = TsProducePairingResponseMessage {
        pair_response_message: pair_response_message.encode_to_vec(),
        pairing_shared_key: shared_key.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

#[wasm_bindgen]
pub fn ts_process_pairing_response_message(
    contact_message: &[u8],
    pair_response_message: &[u8],
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let contact_msg = ContactMessage::decode(contact_message)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;
    let pair_response_msg = PairResponseMessage::decode(pair_response_message)
        .map_err(|e| js_error("PROTOBUF_DECODE", e.to_string()))?;
    let pairing_sk =
        PairingSecretKeyMaterial::deserialize_uncompressed(&mut &pairing_secret_key_material[..])
            .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))?;

    let lib_result =
        process_pairing_response_message(&contact_msg, &pair_response_msg, &pairing_sk)
            .map_err(js_error_from_lib)?;

    let wrapper = TsProcessPairingResponseMessage {
        pairing_shared_key: lib_result.shared_key.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

fn serialize_pairing_secret_key_material(
    sk: &PairingSecretKeyMaterial,
) -> Result<Vec<u8>, JsValue> {
    let mut buf = Vec::new();
    sk.serialize_uncompressed(&mut buf)
        .map_err(|e| js_error("SERIALIZATION_ERROR", format!("{e:?}")))?;

    Ok(buf)
}

fn get_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::SharerNonRecovery),
        1 => Ok(SenderKind::SharerRecovery),
        2 => Ok(SenderKind::Helper),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!("invalid sender kind: {kind}"),
        )),
    }
}
