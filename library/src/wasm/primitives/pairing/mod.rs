// SPDX-License-Identifier: Apache-2.0

pub mod request;
pub mod response;

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, SenderKind, TransportProtocol};
use wasm_bindgen::prelude::*;

use crate::ts_bindings_utils::js_error;

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct ContactMessageJs {
    pub channel_id: String,
    pub transport_protocol: TransportProtocolJs,
    pub nonce: String,
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct TransportProtocolJs {
    pub uri: String,
    pub protocol: String,
}

#[derive(serde::Deserialize)]
pub(super) struct TransportProtocolInput {
    pub uri: String,
    pub protocol: String,
}

pub(super) fn serialize_pairing_secret_key_material(
    sk: &PairingSecretKeyMaterial,
) -> Result<Vec<u8>, JsValue> {
    let mut buf = Vec::new();
    sk.serialize_uncompressed(&mut buf)
        .map_err(|e| js_error("SERIALIZATION_ERROR", format!("{e:?}")))?;
    Ok(buf)
}

pub(super) fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, JsValue> {
    PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..])
        .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))
}

pub(super) fn js_to_transport_protocol(val: JsValue) -> Result<TransportProtocol, JsValue> {
    let input: TransportProtocolInput = serde_wasm_bindgen::from_value(val)
        .map_err(|e| js_error("DECODE_ERROR", e.to_string()))?;
    let protocol = match input.protocol.to_lowercase().as_str() {
        "https" => 0,
        other => {
            return Err(js_error(
                "INVALID_PROTOCOL",
                format!("unknown protocol: {other}"),
            ))
        }
    };
    Ok(TransportProtocol {
        uri: input.uri,
        protocol,
    })
}

pub(super) fn js_to_contact_message(val: JsValue) -> Result<ContactMessage, JsValue> {
    let input: ContactMessageJs = serde_wasm_bindgen::from_value(val)
        .map_err(|e| js_error("DECODE_ERROR", e.to_string()))?;
    let channel_id = input
        .channel_id
        .parse::<u64>()
        .map_err(|e| js_error("DECODE_ERROR", format!("invalid channel_id: {e}")))?;
    let nonce = input
        .nonce
        .parse::<u64>()
        .map_err(|e| js_error("DECODE_ERROR", format!("invalid nonce: {e}")))?;
    let protocol = match input.transport_protocol.protocol.to_lowercase().as_str() {
        "https" => 0,
        other => {
            return Err(js_error(
                "INVALID_PROTOCOL",
                format!("unknown protocol: {other}"),
            ))
        }
    };
    Ok(ContactMessage {
        channel_id,
        transport_protocol: Some(TransportProtocol {
            uri: input.transport_protocol.uri,
            protocol,
        }),
        nonce,
        mlkem_encapsulation_key: input.mlkem_encapsulation_key,
        ecies_public_key: input.ecies_public_key,
        timestamp: None,
    })
}

pub(super) fn contact_message_to_js(cm: &ContactMessage) -> ContactMessageJs {
    let transport_protocol = cm
        .transport_protocol
        .as_ref()
        .map(transport_protocol_to_js)
        .unwrap_or_else(|| TransportProtocolJs {
            uri: String::new(),
            protocol: "https".to_owned(),
        });
    ContactMessageJs {
        channel_id: cm.channel_id.to_string(),
        transport_protocol,
        nonce: cm.nonce.to_string(),
        mlkem_encapsulation_key: cm.mlkem_encapsulation_key.clone(),
        ecies_public_key: cm.ecies_public_key.clone(),
    }
}

pub(super) fn transport_protocol_to_js(tp: &TransportProtocol) -> TransportProtocolJs {
    let protocol = match tp.protocol {
        0 => "https".to_owned(),
        n => format!("unknown({n})"),
    };
    TransportProtocolJs {
        uri: tp.uri.clone(),
        protocol,
    }
}

pub(super) fn get_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::OwnerNonRecovery),
        1 => Ok(SenderKind::OwnerRecovery),
        2 => Ok(SenderKind::Helper),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!("invalid sender kind: {kind}"),
        )),
    }
}
