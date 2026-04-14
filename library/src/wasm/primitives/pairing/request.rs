// SPDX-License-Identifier: Apache-2.0

use super::{
    contact_message_to_js, ContactMessageJs, deserialize_pairing_secret_key_material,
    get_sender_kind, js_to_contact_message, js_to_transport_protocol,
    serialize_pairing_secret_key_material, TransportProtocolJs,
};
use crate::{
    primitives::pairing::{request, response},
    ts_bindings_utils::{DeRecMessageJs, derec_message_to_js, js_error, js_error_from_lib, js_to_derec_message},
};
use derec_proto::{ContactMessage, DeRecMessage};
use prost::Message as _;
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct CreateContactResultJs {
    contact_message: ContactMessageJs,
    secret_key_material: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProduceResultJs {
    envelope: DeRecMessageJs,
    initiator_contact_message: ContactMessageJs,
    secret_key_material: Vec<u8>,
}

/// Creates a `ContactMessage` used to bootstrap pairing.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier associated with the generated pairing material
/// * `transport_protocol` - Plain JS object `{ protocol: "https", uri: "https://..." }`
///
/// # Returns
///
/// A JS object with:
///
/// - `contact_message`: plain JS object representing the `ContactMessage`
/// - `secret_key_material`: serialized `PairingSecretKeyMaterial`
#[wasm_bindgen(js_name = "pairing_request_create_contact")]
pub fn create_contact(channel_id: u64, transport_protocol: JsValue) -> Result<JsValue, JsValue> {
    let transport_protocol = js_to_transport_protocol(transport_protocol)?;

    let request::CreateContactResult {
        contact_message,
        secret_key,
    } = request::create_contact(channel_id.into(), transport_protocol)
        .map_err(js_error_from_lib)?;

    let wrapper = CreateContactResultJs {
        contact_message: contact_message_to_js(&contact_message),
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Serializes a `ContactMessage` JS object into raw protobuf bytes.
///
/// Useful for encoding a contact message into a QR code or other out-of-band channel.
/// The recipient can decode the bytes back with `pairing_request_decode_contact`.
///
/// # Arguments
///
/// * `contact_message` - Plain JS `ContactMessage` object as returned by `pairing_request_create_contact`
///
/// # Returns
///
/// Raw protobuf bytes (`Uint8Array`) suitable for base64url encoding into a QR payload.
#[wasm_bindgen(js_name = "pairing_request_encode_contact")]
pub fn encode_contact(contact_message: JsValue) -> Result<Vec<u8>, JsValue> {
    let cm = js_to_contact_message(contact_message)?;
    Ok(cm.encode_to_vec())
}

/// Deserializes a `ContactMessage` from raw protobuf bytes into a plain JS object.
///
/// Useful for decoding a contact message received via QR code or other out-of-band
/// channel before passing it to `pairing_request_produce`.
///
/// # Arguments
///
/// * `bytes` - Raw protobuf bytes of a serialized `ContactMessage`
///
/// # Returns
///
/// A plain JS `ContactMessage` object suitable for passing to `pairing_request_produce`.
#[wasm_bindgen(js_name = "pairing_request_decode_contact")]
pub fn decode_contact(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let cm = ContactMessage::decode(bytes)
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;
    serde_wasm_bindgen::to_value(&contact_message_to_js(&cm))
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Produces a pairing request envelope from a contact message.
///
/// # Arguments
///
/// * `kind` - Sender role: `0` = OwnerNonRecovery, `1` = OwnerRecovery, `2` = Helper
/// * `transport_protocol` - Plain JS object `{ protocol: "https", uri: "https://..." }`
/// * `contact_message` - Plain JS `ContactMessage` object as returned by `pairing_request_create_contact`
///
/// # Returns
///
/// A JS object with:
///
/// - `envelope`: outer `DeRecMessage` as a plain JS object
/// - `initiator_contact_message`: decoded initiator `ContactMessage` as a plain JS object
/// - `secret_key_material`: serialized responder-side `PairingSecretKeyMaterial`
#[wasm_bindgen(js_name = "pairing_request_produce")]
pub fn produce(
    kind: u32,
    transport_protocol: JsValue,
    contact_message: JsValue,
) -> Result<JsValue, JsValue> {
    let sender_kind = get_sender_kind(kind)?;
    let transport_protocol = js_to_transport_protocol(transport_protocol)?;
    let contact_message = js_to_contact_message(contact_message)?;

    let request::ProduceResult {
        envelope,
        initiator_contact_message,
        secret_key,
    } = request::produce(sender_kind, transport_protocol, &contact_message)
        .map_err(js_error_from_lib)?;

    let envelope_decoded = DeRecMessage::decode(envelope.as_slice())
        .map_err(|e| js_error("PROTOBUF_DECODE_ERROR", e.to_string()))?;

    let wrapper = ProduceResultJs {
        envelope: derec_message_to_js(envelope_decoded),
        initiator_contact_message: contact_message_to_js(&initiator_contact_message),
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
