// SPDX-License-Identifier: Apache-2.0

//! Higher-level WASM binding: [`DeRecProtocolWasm`].
//!
//! This module exposes the same high-level orchestrator as the native
//! [`crate::protocol::DeRecProtocol`] but wired to JS-side store and transport
//! objects so that TypeScript applications can use it without managing raw
//! message routing.
//!
//! # Usage (TypeScript)
//!
//! ```ts
//! import init, { DeRecProtocol } from "@derec-alliance/web";
//!
//! await init();
//!
//! const protocol = new DeRecProtocol(
//!   contactStore,   // implements { load, save }
//!   shareStore,     // implements { load, save, loadChannelsForSecret, loadSecretsForChannel }
//!   secretStore,    // implements { load, save, remove }
//!   transport,      // implements { send }
//!   "https://my-node.example.com/derec",
//!   "https",
//! );
//!
//! // Owner: generate a contact message, read channel_id, serialize for QR.
//! const contact = await protocol.createContact();
//! const channelId = BigInt(contact.channel_id);
//!
//! // Owner: receive peer's ContactMessage object and begin pairing.
//! const channelId = await protocol.startPairing(0, peerContact); // 0 = OwnerNonRecovery
//!
//! // Feed incoming wire bytes; react to returned events.
//! const events = await protocol.process(rawBytes);
//! for (const ev of events) {
//!   if (ev.type === "PairingCompleted") { ... }
//! }
//! ```
//!
//! See each method's documentation for full details on event shapes and JS
//! interface contracts.

mod events;
pub(crate) mod pending_action_wire;
mod stores;

use std::collections::HashMap;

use crate::{
    protocol::{DeRecFlow, DeRecProtocol, DeRecProtocolBuilder},
    types::{ChannelId, Target, UserSecret},
    wasm::ts_bindings_utils::js_error,
};
use crate::wasm::primitives::pairing::{contact_message_to_js, js_to_contact_message};
use derec_proto::{SenderKind, TransportProtocol};
use js_sys::{Array, Uint8Array};
use stores::{JsChannelStore, JsSecretStore, JsShareStore, JsTransport};
use wasm_bindgen::prelude::*;

type WasmProtocol = DeRecProtocol<JsChannelStore, JsShareStore, JsSecretStore, JsTransport>;

/// Higher-level DeRec protocol orchestrator for TypeScript/JavaScript consumers.
///
/// Wraps [`DeRecProtocol`](crate::protocol::DeRecProtocol) with JS-side store
/// and transport adapters so that a TypeScript application can drive all five
/// protocol flows without routing raw bytes manually.
///
/// # Stores
///
/// Pass four JS objects that implement the interfaces documented on each
/// parameter.  All store methods must return `Promise`s — synchronous
/// implementations can wrap their result with `Promise.resolve(...)`.
///
/// # Events
///
/// [`process`](DeRecProtocolWasm::process) returns an `Array` of plain JS
/// objects, each with a `type` discriminant field:
///
/// | `type`             | Additional fields                                      |
/// |--------------------|--------------------------------------------------------|
/// | `PairingCompleted`  | `channel_id: string`, `kind: number`                   |
/// | `ShareStored`      | `channel_id: string`, `version: number`                |
/// | `ShareConfirmed`   | `channel_id: string`, `version: number`                |
/// | `ShareVerified`    | `channel_id: string`, `version: number`                |
/// | `SecretsDiscovered`| `channel_id: string`, `secrets: SecretVersionEntry[]`  |
/// | `SecretRecovered`  | `secret: Uint8Array`                                   |
/// | `NoOp`             | _(none)_                                               |
///
/// `SecretVersionEntry = { secret_id: Uint8Array, versions: { version: number, description: string }[] }`
#[wasm_bindgen]
pub struct DeRecProtocolWasm {
    inner: WasmProtocol,
}

#[wasm_bindgen]
impl DeRecProtocolWasm {
    /// Construct a [`DeRecProtocolWasm`] from JS-side store/transport objects.
    ///
    /// # Arguments
    ///
    /// * `channel_store` — JS object with `load(channelId: string): Promise<Uint8Array|null>`,
    ///   `save(channelId: string, bytes: Uint8Array): Promise<void>`, and
    ///   `listChannels(): Promise<string[]>`.
    ///   The bytes are JSON-encoded `Channel` records.
    ///
    /// * `share_store` — JS object with `load`, `save`, `loadChannelsForSecret`,
    ///   `loadSecretsForChannel` (see module-level docs for full signatures).
    ///
    /// * `secret_store` — JS object with
    ///   `load(channelId: string, kind: 0|1): Promise<Uint8Array|null>`,
    ///   `save(channelId: string, kind: 0|1, bytes: Uint8Array): Promise<void>`, and
    ///   `remove(channelId: string, kind: 0|1): Promise<void>`.
    ///   `kind 0` = `SharedKey` (32 raw bytes); `kind 1` = `PairingSecret` (serialized).
    ///
    /// * `transport` — JS object with
    ///   `send(endpoint: { protocol: string; uri: string }, message: Uint8Array): Promise<void>`.
    ///
    /// * `own_transport_uri` — The URI this node advertises to peers during pairing
    ///   (e.g. `"https://my-node.example.com/derec"`).
    ///
    /// * `own_transport_protocol` — Protocol string, currently must be `"https"`.
    /// # Arguments
    ///
    /// * `threshold` — Minimum number of shares required for reconstruction.
    /// * `keep_versions_count` — Number of recent versions each Helper must retain.
    #[wasm_bindgen(constructor)]
    pub fn new(
        channel_store: JsValue,
        share_store: JsValue,
        secret_store: JsValue,
        transport: JsValue,
        own_transport_uri: String,
        own_transport_protocol: String,
        threshold: u32,
        keep_versions_count: u32,
        secret_id: &[u8],
        communication_info: JsValue,
    ) -> Result<DeRecProtocolWasm, JsValue> {
        let protocol_num = match own_transport_protocol.to_lowercase().as_str() {
            "https" => 0i32,
            other => {
                return Err(js_error(
                    "INVALID_PROTOCOL",
                    format!("unknown protocol: {other}"),
                ))
            }
        };
        let own_transport = TransportProtocol {
            uri: own_transport_uri,
            protocol: protocol_num,
        };
        let info: HashMap<String, String> = if communication_info.is_null() || communication_info.is_undefined() {
            HashMap::new()
        } else {
            serde_wasm_bindgen::from_value(communication_info)
                .map_err(|e| js_error("INVALID_COMMUNICATION_INFO", e.to_string()))?
        };
        let inner = DeRecProtocolBuilder::new()
            .with_channel_store(JsChannelStore(channel_store))
            .with_share_store(JsShareStore(share_store))
            .with_secret_store(JsSecretStore(secret_store))
            .with_transport(JsTransport(transport))
            .with_own_transport(own_transport)
            .with_threshold(threshold as usize)
            .with_keep_versions_count(keep_versions_count as usize)
            .with_secret_id(secret_id.to_vec())
            .with_communication_info(info)
            .build();
        Ok(DeRecProtocolWasm { inner })
    }

    /// Generate an out-of-band contact message (QR code payload, deep link, …).
    ///
    /// Returns a plain JS `ContactMessage` object. The `channel_id` field identifies
    /// the pairing session and will match the `channel_id` in the eventual
    /// `PairingCompleted` event — read it directly from the returned object.
    ///
    /// The caller is responsible for serializing the contact for out-of-band
    /// delivery (QR code, deep link, etc.). The peer passes the deserialized object
    /// to [`start`](Self::start) with `FlowKind::Pairing`.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — Optional `BigInt` channel identifier. Pass `null` or
    ///   `undefined` to have the library generate a random one.
    ///
    /// TODO: document the full pairing lifecycle and how to use the returned
    /// `channel_id` field to track the pending pairing in application state.
    #[wasm_bindgen(js_name = "createContact")]
    pub async fn create_contact(&mut self, channel_id: JsValue) -> Result<JsValue, JsValue> {
        let id = parse_optional_channel_id(channel_id)?;
        let contact = self
            .inner
            .create_contact(id)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        serde_wasm_bindgen::to_value(&contact_message_to_js(&contact))
            .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
    }

    /// Unified entry point for initiating any protocol flow.
    ///
    /// # Arguments
    ///
    /// * `flow_kind` — Flow discriminant:
    ///   - `0` = Pairing (params: `{ kind: number, contact: ContactMessage, name?: string }`)
    ///   - `1` = Discovery (params: `{ target: BigInt | BigInt[] | null }`)
    ///   - `2` = ProtectSecret (params: `{ secrets: UserSecret[], description?: string }`)
    ///   - `3` = VerifyShares (params: `{ version: number, target: BigInt | BigInt[] | null }`)
    ///   - `4` = RecoverSecret (params: `{ secretId: Uint8Array, version: number }`)
    ///
    /// # Returns
    ///
    /// `BigInt` for Pairing (the channel_id), `null` for all others.
    #[wasm_bindgen(js_name = "start")]
    pub async fn start(&mut self, flow_kind: u32, params: JsValue) -> Result<JsValue, JsValue> {
        let flow = parse_flow(flow_kind, params)?;
        let result = self
            .inner
            .start(flow)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        match result {
            Some(channel_id) => Ok(js_sys::BigInt::from(channel_id).into()),
            None => Ok(JsValue::NULL),
        }
    }

    /// Accept a pending action from an `ActionRequired` event.
    ///
    /// # Arguments
    ///
    /// * `action_bytes` — Opaque `Uint8Array` from the `action` field of an `ActionRequired` event.
    ///
    /// # Returns
    ///
    /// An `Array` of event objects (same format as `process()`).
    pub async fn accept(&mut self, action_bytes: &[u8]) -> Result<JsValue, JsValue> {
        let action = pending_action_wire::deserialize(action_bytes)
            .map_err(|e| js_error("DECODE_ERROR", e))?;
        let rust_events = self
            .inner
            .accept(action)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }

    /// Reject a pending action from an `ActionRequired` event.
    ///
    /// # Arguments
    ///
    /// * `action_bytes` — Opaque `Uint8Array` from the `action` field of an `ActionRequired` event.
    /// * `memo` — Human-readable rejection reason.
    pub async fn reject(&mut self, action_bytes: &[u8], memo: &str) -> Result<(), JsValue> {
        let action = pending_action_wire::deserialize(action_bytes)
            .map_err(|e| js_error("DECODE_ERROR", e))?;
        self.inner
            .reject(action, memo)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Feed any incoming wire bytes to the protocol.
    ///
    /// Returns an `Array` of plain JS event objects (see struct-level docs for shapes).
    /// All five flows (pairing, sharing, verification, discovery, recovery) are
    /// handled through this single entry point.
    ///
    /// # Arguments
    ///
    /// * `message` — Raw wire bytes of an incoming `DeRecMessage`.
    pub async fn process(&mut self, message: &[u8]) -> Result<JsValue, JsValue> {
        let rust_events = self
            .inner
            .process(message)
            .await
            .map_err(|e| {
                web_sys::console::error_1(
                    &format!("[wasm-process] error: {e}").into(),
                );
                js_error("DEREC_ERROR", e.to_string())
            })?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }
}

fn parse_optional_channel_id(val: JsValue) -> Result<Option<ChannelId>, JsValue> {
    if val.is_null() || val.is_undefined() {
        return Ok(None);
    }
    Ok(Some(ChannelId(js_value_to_u64(val)?)))
}

/// Convert a JS BigInt or Number to a Rust `u64`.
fn js_value_to_u64(val: JsValue) -> Result<u64, JsValue> {
    if val.is_bigint() {
        let s = js_sys::BigInt::from(val)
            .to_string(10)
            .map_err(|e| js_error("DECODE_ERROR", format!("{e:?}")))?
            .as_string()
            .ok_or_else(|| js_error("DECODE_ERROR", "BigInt.toString returned non-string"))?;
        s.parse::<u64>()
            .map_err(|e| js_error("DECODE_ERROR", e.to_string()))
    } else {
        val.as_f64()
            .ok_or_else(|| js_error("DECODE_ERROR", "channel_id must be BigInt or number"))
            .map(|f| f as u64)
    }
}

fn parse_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::OwnerNonRecovery),
        1 => Ok(SenderKind::OwnerRecovery),
        2 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::Replica),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!("invalid sender kind: {kind}, must be 0, 1, 2, or 3"),
        )),
    }
}

/// Parse a JS discovery target into [`Target`].
///
/// - `null` / `undefined` → `All`
/// - `BigInt` or `number` → `Single`
/// - `Array<BigInt | number>` → `Many`
fn parse_target(val: JsValue) -> Result<Target, JsValue> {
    if val.is_null() || val.is_undefined() {
        return Ok(Target::All);
    }
    if val.is_bigint() || val.as_f64().is_some() {
        let id = js_value_to_u64(val)?;
        return Ok(Target::Single(ChannelId(id)));
    }
    if Array::is_array(&val) {
        let arr = Array::from(&val);
        let mut ids = Vec::with_capacity(arr.length() as usize);
        for i in 0..arr.length() {
            ids.push(ChannelId(js_value_to_u64(arr.get(i))?));
        }
        return Ok(Target::Many(ids));
    }
    Err(js_error(
        "INVALID_DISCOVERY_TARGET",
        "target must be null (all), a BigInt (single), or an array of BigInts (many)",
    ))
}

/// Parse a JS `Array<{ id: Uint8Array, name: string, data: Uint8Array }>` into
/// a `Vec<UserSecret>`.
fn parse_user_secrets(val: JsValue) -> Result<Vec<UserSecret>, JsValue> {
    let arr = Array::from(&val);
    let mut result = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        let entry = arr.get(i);
        let id = js_sys::Reflect::get(&entry, &JsValue::from_str("id"))
            .map_err(|e| js_error("DECODE_ERROR", format!("missing id: {e:?}")))?;
        let name = js_sys::Reflect::get(&entry, &JsValue::from_str("name"))
            .map_err(|e| js_error("DECODE_ERROR", format!("missing name: {e:?}")))?
            .as_string()
            .ok_or_else(|| js_error("DECODE_ERROR", "name must be a string"))?;
        let data = js_sys::Reflect::get(&entry, &JsValue::from_str("data"))
            .map_err(|e| js_error("DECODE_ERROR", format!("missing data: {e:?}")))?;
        result.push(UserSecret {
            id: Uint8Array::new(&id).to_vec(),
            name,
            data: Uint8Array::new(&data).to_vec(),
        });
    }
    Ok(result)
}

/// Parse a JS flow kind + params into a [`DeRecFlow`].
///
/// Flow kinds:
/// - `0` = Pairing: `{ kind: number, contact: ContactMessage, name?: string }`
/// - `1` = Discovery: `{ target: BigInt | BigInt[] | null }`
/// - `2` = ProtectSecret: `{ secrets: UserSecret[], description?: string }`
/// - `3` = VerifyShares: `{ version: number, target: BigInt | BigInt[] | null }`
/// - `4` = RecoverSecret: `{ secretId: Uint8Array, version: number }`
fn parse_flow(flow_kind: u32, params: JsValue) -> Result<DeRecFlow, JsValue> {
    match flow_kind {
        0 => {
            // Pairing
            let kind_val = js_sys::Reflect::get(&params, &JsValue::from_str("kind"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing kind: {e:?}")))?;
            let kind = kind_val
                .as_f64()
                .ok_or_else(|| js_error("DECODE_ERROR", "kind must be a number"))?
                as u32;
            let sender_kind = parse_sender_kind(kind)?;
            let contact_val = js_sys::Reflect::get(&params, &JsValue::from_str("contact"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing contact: {e:?}")))?;
            let contact = js_to_contact_message(contact_val)?;
            let name = js_sys::Reflect::get(&params, &JsValue::from_str("name"))
                .unwrap_or(JsValue::UNDEFINED)
                .as_string();
            Ok(DeRecFlow::Pairing {
                kind: sender_kind,
                contact,
                name,
            })
        }
        1 => {
            // Discovery
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            Ok(DeRecFlow::Discovery { target })
        }
        2 => {
            // ProtectSecret
            let secrets_val = js_sys::Reflect::get(&params, &JsValue::from_str("secrets"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secrets: {e:?}")))?;
            let secrets = parse_user_secrets(secrets_val)?;
            let description = js_sys::Reflect::get(&params, &JsValue::from_str("description"))
                .unwrap_or(JsValue::UNDEFINED)
                .as_string();
            Ok(DeRecFlow::ProtectSecret {
                secrets,
                description,
            })
        }
        3 => {
            // VerifyShares
            let version = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing version: {e:?}")))?
                .as_f64()
                .ok_or_else(|| js_error("DECODE_ERROR", "version must be a number"))?
                as i32;
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            Ok(DeRecFlow::VerifyShares { version, target })
        }
        4 => {
            // RecoverSecret
            let secret_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("secretId"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secretId: {e:?}")))?;
            let secret_id = Uint8Array::new(&secret_id_val).to_vec();
            let version = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing version: {e:?}")))?
                .as_f64()
                .ok_or_else(|| js_error("DECODE_ERROR", "version must be a number"))?
                as i32;
            Ok(DeRecFlow::RecoverSecret { secret_id, version })
        }
        _ => Err(js_error(
            "INVALID_FLOW_KIND",
            format!("invalid flow kind: {flow_kind}, must be 0..4"),
        )),
    }
}
