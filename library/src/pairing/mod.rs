pub mod pairing;

pub use pairing::create_contact_message;
pub use pairing::produce_pairing_request_message;
pub use pairing::produce_pairing_response_message;
pub use pairing::process_pairing_response_message;

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use prost::Message;
use crate::protos::derec_proto::SenderKind;
use crate::protos::derec_proto::{ContactMessage, PairRequestMessage, PairResponseMessage};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use crate::Error;

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

fn sender_kind_from_u32(kind: u32) -> std::result::Result<SenderKind, Error> {
    match kind {
        0 => Ok(SenderKind::SharerNonRecovery),
        1 => Ok(SenderKind::SharerRecovery),
        2 => Ok(SenderKind::Helper),
        _ => Err(Error::InvalidInput(format!("Invalid sender kind: {kind}"))),
    }
}

fn to_js_error(err: Error) -> JsValue {
    JsValue::from_str(&err.to_string())
}

#[wasm_bindgen]
pub fn ts_create_contact_message(
    channel_id: u64,
    transport_uri: &str
) -> Result<JsValue, JsValue> {
    let lib_result = pairing::create_contact_message(
        channel_id,
        &transport_uri.to_string()
    ).map_err(to_js_error)?;

    let wrapper = TsCreateContactMessageResult {
        contact_message: lib_result.0.encode_to_vec(),
        secret_key_material: {
            let mut buf = Vec::new();
            lib_result.1
                .serialize_uncompressed(&mut buf)
                .map_err(|err| to_js_error(Error::Serialization(err.to_string())))?;
            buf
        }
    };
    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|err| to_js_error(Error::Serialization(err.to_string())))
}

#[wasm_bindgen]
pub fn ts_produce_pairing_request_message(
    channel_id: u64,
    kind: u32,
    contact_message: &[u8]
) -> Result<JsValue, JsValue> {
    let contact_msg = ContactMessage::decode(contact_message)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    let lib_result = pairing::produce_pairing_request_message(
        channel_id,
        sender_kind_from_u32(kind).map_err(to_js_error)?,
        &contact_msg
    ).map_err(to_js_error)?;

    let wrapper = TsProducePairingRequestMessage {
        pair_request_message: lib_result.0.encode_to_vec(),
        secret_key_material: {
            let mut buf = Vec::new();
            lib_result.1
                .serialize_uncompressed(&mut buf)
                .map_err(|err| to_js_error(Error::Serialization(err.to_string())))?;
            buf
        }
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|err| to_js_error(Error::Serialization(err.to_string())))
}

#[wasm_bindgen]
pub fn ts_produce_pairing_response_message(
    kind: u32,
    pair_request_message: &[u8],
    pairing_secret_key_material: &[u8]
) -> Result<JsValue, JsValue> {
    let pair_request_msg = PairRequestMessage::decode(pair_request_message)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    let pairing_sk = PairingSecretKeyMaterial::deserialize_uncompressed(
        &mut &pairing_secret_key_material[..]
    ).map_err(|err| to_js_error(Error::Serialization(err.to_string())))?;

    let lib_result = pairing::produce_pairing_response_message(
        sender_kind_from_u32(kind).map_err(to_js_error)?,
        &pair_request_msg,
        &pairing_sk
    ).map_err(to_js_error)?;

    let wrapper = TsProducePairingResponseMessage {
        pair_response_message: lib_result.0.encode_to_vec(),
        pairing_shared_key: lib_result.1.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|err| to_js_error(Error::Serialization(err.to_string())))
}

#[wasm_bindgen]
pub fn ts_process_pairing_response_message(
    contact_message: &[u8],
    pair_response_message: &[u8],
    pairing_secret_key_material: &[u8]
) -> Result<JsValue, JsValue> {
    let contact_msg = ContactMessage::decode(contact_message)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    let pair_response_msg = PairResponseMessage::decode(pair_response_message)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    let pairing_sk = PairingSecretKeyMaterial::deserialize_uncompressed(
        &mut &pairing_secret_key_material[..]
    ).map_err(|err| to_js_error(Error::Serialization(err.to_string())))?;

    let lib_result = pairing::process_pairing_response_message(
        &contact_msg,
        &pair_response_msg,
        &pairing_sk
    ).map_err(to_js_error)?;

    let wrapper = TsProcessPairingResponseMessage {
        pairing_shared_key: lib_result.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|err| to_js_error(Error::Serialization(err.to_string())))
}

#[cfg(test)]
mod test;
