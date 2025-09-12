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
pub fn ts_create_contact_message(
    channel_id: u64,
    transport_uri: &str
) -> JsValue {
    let lib_result = pairing::create_contact_message(
        channel_id,
        &transport_uri.to_string()
    );

    let wrapper = TsCreateContactMessageResult {
        contact_message: lib_result.0.encode_to_vec(),
        secret_key_material: {
            let mut buf = Vec::new();
            lib_result.1.serialize_uncompressed(&mut buf).unwrap();
            buf
        }
    };
    serde_wasm_bindgen::to_value(&wrapper).unwrap()
}

#[wasm_bindgen]
pub fn ts_produce_pairing_request_message(
    channel_id: u64,
    kind: u32,
    contact_message: &[u8]
) -> JsValue {
    let contact_msg = ContactMessage::decode(contact_message).unwrap();
    let lib_result = pairing::produce_pairing_request_message(
        channel_id,
        match kind {
            0 => SenderKind::SharerNonRecovery,
            1 => SenderKind::SharerRecovery,
            2 => SenderKind::Helper,
            _ => panic!("Invalid sender kind"),
        },
        &contact_msg
    );

    let wrapper = TsProducePairingRequestMessage {
        pair_request_message: lib_result.0.encode_to_vec(),
        secret_key_material: {
            let mut buf = Vec::new();
            lib_result.1.serialize_uncompressed(&mut buf).unwrap();
            buf
        }
    };

    serde_wasm_bindgen::to_value(&wrapper).unwrap()
}

#[wasm_bindgen]
pub fn ts_produce_pairing_response_message(
    kind: u32,
    pair_request_message: &[u8],
    pairing_secret_key_material: &[u8]
) -> JsValue {
    let pair_request_msg = PairRequestMessage::decode(pair_request_message).unwrap();
    let pairing_sk = PairingSecretKeyMaterial::deserialize_uncompressed(
        &mut &pairing_secret_key_material[..]
    ).unwrap();

    let lib_result = pairing::produce_pairing_response_message(
        match kind {
            0 => SenderKind::SharerNonRecovery,
            1 => SenderKind::SharerRecovery,
            2 => SenderKind::Helper,
            _ => panic!("Invalid sender kind"),
        },
        &pair_request_msg,
        &pairing_sk
    );

    let wrapper = TsProducePairingResponseMessage {
        pair_response_message: lib_result.0.encode_to_vec(),
        pairing_shared_key: lib_result.1.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper).unwrap()
}

#[wasm_bindgen]
pub fn ts_process_pairing_response_message(
    contact_message: &[u8],
    pair_response_message: &[u8],
    pairing_secret_key_material: &[u8]
) -> JsValue {
    let contact_msg = ContactMessage::decode(contact_message).unwrap();
    let pair_response_msg = PairResponseMessage::decode(pair_response_message).unwrap();
    let pairing_sk = PairingSecretKeyMaterial::deserialize_uncompressed(
        &mut &pairing_secret_key_material[..]
    ).unwrap();

    let lib_result = pairing::process_pairing_response_message(
        &contact_msg,
        &pair_response_msg,
        &pairing_sk
    );

    let wrapper = TsProcessPairingResponseMessage {
        pairing_shared_key: lib_result.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper).unwrap()
}

#[cfg(test)]
mod test;