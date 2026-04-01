// SPDX-License-Identifier: Apache-2.0

//! WASM bindings for the DeRec pairing flow.
//!
//! These bindings expose the Rust pairing functions to JavaScript consumers in both
//! browser and Node.js environments.
//!
//! # Binding model
//!
//! The pairing flow exchanges **raw bytes** at the public API boundary for wire messages,
//! and **plain JS objects** for structured values like `TransportProtocol`:
//!
//! - `create_contact_message` accepts a `TransportProtocol` JS object and returns plain
//!   serialized `ContactMessage` bytes
//! - `produce_pairing_request_message` accepts contact-message bytes and returns
//!   serialized outer `DeRecMessage` bytes containing an encrypted inner `PairRequestMessage`
//! - `produce_pairing_response_message` accepts serialized outer request bytes and returns
//!   serialized outer response bytes containing an encrypted inner `PairResponseMessage`
//! - `process_pairing_response_message` accepts contact bytes and response bytes and derives
//!   the final shared pairing key
//!
//! Secret pairing state is serialized into opaque byte arrays so it can be stored and later
//! passed back into subsequent pairing functions.
//!
//! # TransportProtocol representation
//!
//! `TransportProtocol` values are represented as plain JS objects at the boundary:
//!
//! ```json
//! { "protocol": "https", "uri": "https://example.com/derec" }
//! ```
//!
//! The `protocol` field is a lowercase string matching the enum variant name (e.g. `"https"`).

use crate::{
    pairing,
    ts_bindings_utils::{js_error, js_error_from_lib},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{SenderKind, TransportProtocol};
use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct CreateContactMessageResultJs {
    /// Plain serialized `ContactMessage` protobuf bytes.
    wire_bytes: Vec<u8>,
    /// Serialized `PairingSecretKeyMaterial`.
    secret_key_material: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProducePairingRequestMessageResultJs {
    /// Serialized outer `DeRecMessage` containing encrypted inner `PairRequestMessage`.
    wire_bytes: Vec<u8>,
    /// Transport information extracted from the contact message, indicating how to reach
    /// the initiator for subsequent protocol traffic.
    initiator_transport_protocol: TransportProtocolJs,
    /// Serialized `PairingSecretKeyMaterial`.
    secret_key_material: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct TransportProtocolJs {
    uri: String,
    /// Lowercase protocol name (e.g. `"https"`).
    protocol: String,
}

/// Input shape for `TransportProtocol` from JS: `{ protocol: "https", uri: "..." }`.
#[derive(serde::Deserialize)]
struct TransportProtocolInput {
    uri: String,
    protocol: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProducePairingResponseMessageResultJs {
    /// Serialized outer `DeRecMessage` containing encrypted inner `PairResponseMessage`.
    wire_bytes: Vec<u8>,
    /// Transport protocol extracted from the pairing request.
    responder_transport_protocol: TransportProtocolJs,
    /// Final derived pairing shared key.
    pairing_shared_key: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProcessPairingResponseMessageResultJs {
    /// Final derived pairing shared key.
    pairing_shared_key: Vec<u8>,
}

/// Creates a serialized `ContactMessage` used to bootstrap pairing.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier associated with the generated pairing material
/// * `transport_protocol` - Plain JS object `{ protocol: "https", uri: "https://..." }`
///   describing the transport endpoint the peer should use for subsequent traffic
///
/// # Returns
///
/// A JS object with:
///
/// - `wire_bytes`: serialized `ContactMessage` protobuf bytes
/// - `secret_key_material`: serialized `PairingSecretKeyMaterial`
#[wasm_bindgen]
pub fn create_contact_message(
    channel_id: u64,
    transport_protocol: JsValue,
) -> Result<JsValue, JsValue> {
    let transport_protocol = js_to_transport_protocol(transport_protocol)?;

    let pairing::CreateContactMessageResult {
        wire_bytes,
        secret_key,
    } = pairing::create_contact_message(channel_id.into(), transport_protocol)
        .map_err(js_error_from_lib)?;

    let wrapper = CreateContactMessageResultJs {
        wire_bytes,
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Produces a serialized pairing request envelope from a contact message.
///
/// This is the **responder-side** step: the party that received the out-of-band
/// contact creates the pairing request.
///
/// # Arguments
///
/// * `kind` - Sender role encoded as:
///   - `0` => `SharerNonRecovery`
///   - `1` => `SharerRecovery`
///   - `2` => `Helper`
/// * `transport_protocol` - Plain JS object `{ protocol: "https", uri: "https://..." }`
///   describing the responder's transport endpoint
/// * `contact_message_bytes` - Plain serialized `ContactMessage` bytes
///
/// # Returns
///
/// A JS object with:
///
/// - `wire_bytes`: serialized outer `DeRecMessage` bytes
/// - `initiator_transport_protocol`: transport information extracted from the contact message,
///   indicating how to reach the initiator for subsequent protocol traffic
/// - `secret_key_material`: serialized responder-side `PairingSecretKeyMaterial`
#[wasm_bindgen]
pub fn produce_pairing_request_message(
    kind: u32,
    transport_protocol: JsValue,
    contact_message_bytes: &[u8],
) -> Result<JsValue, JsValue> {
    let sender_kind = get_sender_kind(kind)?;
    let transport_protocol = js_to_transport_protocol(transport_protocol)?;

    let pairing::ProducePairingRequestMessageResult {
        wire_bytes,
        initiator_transport_protocol,
        secret_key,
    } = pairing::produce_pairing_request_message(sender_kind, transport_protocol, contact_message_bytes)
        .map_err(js_error_from_lib)?;

    let wrapper = ProducePairingRequestMessageResultJs {
        wire_bytes,
        initiator_transport_protocol: transport_protocol_to_js(&initiator_transport_protocol),
        secret_key_material: serialize_pairing_secret_key_material(&secret_key)?,
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Produces a serialized pairing response envelope and derives the initiator-side shared key.
///
/// This is the **initiator-side** step: the party that originally created the contact
/// processes the incoming pairing request and returns the pairing response.
///
/// # Arguments
///
/// * `kind` - Sender role encoded as:
///   - `0` => `SharerNonRecovery`
///   - `1` => `SharerRecovery`
///   - `2` => `Helper`
/// * `pair_request_wire_bytes` - Serialized outer `DeRecMessage` carrying encrypted inner request bytes
/// * `pairing_secret_key_material` - Serialized initiator-side `PairingSecretKeyMaterial`
///
/// # Returns
///
/// A JS object with:
///
/// - `wire_bytes`: serialized outer `DeRecMessage` bytes carrying encrypted inner response bytes
/// - `transport_protocol`: transport information extracted from the pairing request
/// - `pairing_shared_key`: final shared pairing key
#[wasm_bindgen]
pub fn produce_pairing_response_message(
    kind: u32,
    pair_request_wire_bytes: &[u8],
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(pairing_secret_key_material)?;

    let pairing::ProducePairingResponseMessageResult {
        wire_bytes,
        responder_transport_protocol,
        shared_key,
    } = pairing::produce_pairing_response_message(
        get_sender_kind(kind)?,
        pair_request_wire_bytes,
        &pairing_sk,
    )
    .map_err(js_error_from_lib)?;

    let wrapper = ProducePairingResponseMessageResultJs {
        wire_bytes,
        responder_transport_protocol: transport_protocol_to_js(&responder_transport_protocol),
        pairing_shared_key: shared_key.to_vec(),
    };

    serde_wasm_bindgen::to_value(&wrapper)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}

/// Processes a serialized pairing response envelope and derives the responder-side shared key.
///
/// This is the **responder-side** finalization step: the party that created the pairing request
/// processes the pairing response and derives the same final shared key.
///
/// # Arguments
///
/// * `contact_message_bytes` - Plain serialized `ContactMessage` bytes
/// * `pair_response_wire_bytes` - Serialized outer `DeRecMessage` carrying encrypted inner response bytes
/// * `pairing_secret_key_material` - Serialized responder-side `PairingSecretKeyMaterial`
///
/// # Returns
///
/// A JS object with:
///
/// - `pairing_shared_key`: final shared pairing key
#[wasm_bindgen]
pub fn process_pairing_response_message(
    contact_message_bytes: &[u8],
    pair_response_wire_bytes: &[u8],
    pairing_secret_key_material: &[u8],
) -> Result<JsValue, JsValue> {
    let pairing_sk = deserialize_pairing_secret_key_material(pairing_secret_key_material)?;

    let pairing::ProcessPairingResponseMessageResult { shared_key } =
        pairing::process_pairing_response_message(
            contact_message_bytes,
            pair_response_wire_bytes,
            &pairing_sk,
        )
        .map_err(js_error_from_lib)?;

    let wrapper = ProcessPairingResponseMessageResultJs {
        pairing_shared_key: shared_key.to_vec(),
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

fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, JsValue> {
    PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..])
        .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))
}

fn js_to_transport_protocol(val: JsValue) -> Result<TransportProtocol, JsValue> {
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

fn transport_protocol_to_js(tp: &TransportProtocol) -> TransportProtocolJs {
    let protocol = match tp.protocol {
        0 => "https".to_owned(),
        n => format!("unknown({n})"),
    };
    TransportProtocolJs {
        uri: tp.uri.clone(),
        protocol,
    }
}

fn get_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
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
