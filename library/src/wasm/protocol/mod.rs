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
//! const channelId = await protocol.startPairing(0, peerContact); // 0 = Owner
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
use std::time::Duration;

use crate::{
    protocol::{
        DeRecChannelStore, DeRecFlow, DeRecProtocol, DeRecProtocolBuilder, DeRecSecretStore,
        DeRecShareStore, SecretValue, Share, UnpairAck,
    },
    types::{Channel, ChannelId, ChannelStatus, SecretContainer, Target, UserSecret},
    wasm::{now_secs, ts_bindings_utils::js_error},
};
use derec_proto::DeRecSecret;
use prost::Message;
use serde::Serialize;
use crate::wasm::primitives::pairing::ContactMessage as PairingContactMessage;
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
/// `SecretVersionEntry = { secret_id: bigint, versions: { version: number, description: string }[] }`
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
    /// * `timeout_in_secs` — General protocol timeout (seconds). Used passively
    ///   in `process()` to discard expired messages / pending channels / stale
    ///   sharing rounds. Defaults to 300 when omitted. Active (wall-clock)
    ///   timeouts remain the application's responsibility.
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
        communication_info: JsValue,
        timeout_in_secs: Option<u32>,
        auto_respond_on_failure: Option<bool>,
        // `unpair_ack`: `"required"` (default) makes the unpair initiator
        // wait for the peer's acknowledgement before dropping local state.
        // `"not_required"` is fire-and-forget — state is dropped immediately
        // on `start(Unpair)` and any later response is ignored.
        unpair_ack: Option<String>,
        // `auto_reply_to`: when true, every outbound channel-mode request
        // stamps `request.replyTo = this.own_transport`. Default `false`.
        // See `DeRecProtocolBuilder::with_auto_reply_to` for the routing
        // semantics on the responder side.
        auto_reply_to: Option<bool>,
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
        let unpair_ack_value = match unpair_ack
            .as_deref()
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("required") => UnpairAck::Required,
            Some("not_required" | "notrequired" | "fire_and_forget") => UnpairAck::NotRequired,
            Some(other) => {
                return Err(js_error(
                    "INVALID_UNPAIR_ACK",
                    format!("unknown unpair_ack value: {other:?}; expected \"required\" or \"not_required\""),
                ));
            }
        };

        let inner = DeRecProtocolBuilder::new()
            .with_channel_store(JsChannelStore(channel_store))
            .with_share_store(JsShareStore(share_store))
            .with_secret_store(JsSecretStore(secret_store))
            .with_transport(JsTransport(transport))
            .with_own_transport(own_transport)
            .with_threshold(threshold as usize)
            .with_keep_versions_count(keep_versions_count as usize)
            .with_communication_info(info)
            .with_timeout(Duration::from_secs(timeout_in_secs.map_or(300, u64::from)))
            .with_auto_respond_on_failure(auto_respond_on_failure.unwrap_or(false))
            .with_unpair_ack(unpair_ack_value)
            .with_auto_reply_to(auto_reply_to.unwrap_or(false))
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
    /// * `contact_mode` — `0` for `InlineKeys` (keys embedded directly), `1`
    ///   for `HashedKeys` (contact carries only a SHA-384 binding hash; the
    ///   scanner fetches keys via a `PrePair` round-trip). `HashedKeys`
    ///   requires the protocol's `own_transport` to be ephemeral.
    ///
    /// TODO: document the full pairing lifecycle and how to use the returned
    /// `channel_id` field to track the pending pairing in application state.
    #[wasm_bindgen(js_name = "createContact")]
    pub async fn create_contact(
        &mut self,
        channel_id: JsValue,
        contact_mode: u32,
    ) -> Result<JsValue, JsValue> {
        let id = parse_optional_channel_id(channel_id)?;
        let mode = match contact_mode {
            0 => derec_proto::ContactMode::InlineKeys,
            1 => derec_proto::ContactMode::HashedKeys,
            other => {
                return Err(js_error(
                    "INVALID_CONTACT_MODE",
                    format!("unknown contact_mode: {other}; expected 0 (InlineKeys) or 1 (HashedKeys)"),
                ));
            }
        };
        let contact = self
            .inner
            .create_contact(id, mode)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        let contact: PairingContactMessage = contact.into();
        let serializer = serde_wasm_bindgen::Serializer::new()
            .serialize_large_number_types_as_bigints(true);
        use serde::Serialize as _;
        contact
            .serialize(&serializer)
            .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
    }

    /// Replace this node's local communication info. Does not contact peers —
    /// follow up with a `start(UpdateChannelInfo, ...)` to propagate.
    #[wasm_bindgen(js_name = "setCommunicationInfo")]
    pub fn set_communication_info(&mut self, info: JsValue) -> Result<(), JsValue> {
        let map: HashMap<String, String> = if info.is_null() || info.is_undefined() {
            HashMap::new()
        } else {
            serde_wasm_bindgen::from_value(info)
                .map_err(|e| js_error("INVALID_COMMUNICATION_INFO", e.to_string()))?
        };
        self.inner.set_communication_info(map);
        Ok(())
    }

    /// Replace this node's local transport endpoint. See
    /// `setCommunicationInfo` for the matching update-propagation flow.
    /// IMPORTANT: keep the old endpoint operational during the changeover —
    /// see the Rust docs on `set_own_transport` for the discipline.
    #[wasm_bindgen(js_name = "setOwnTransport")]
    pub fn set_own_transport(
        &mut self,
        uri: String,
        protocol: String,
    ) -> Result<(), JsValue> {
        let protocol_num = match protocol.to_lowercase().as_str() {
            "https" => 0i32,
            other => {
                return Err(js_error(
                    "INVALID_PROTOCOL",
                    format!("unknown protocol: {other}"),
                ));
            }
        };
        self.inner.set_own_transport(TransportProtocol {
            uri,
            protocol: protocol_num,
        });
        Ok(())
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
    /// * `status` — Numeric status code from `StatusEnum` (e.g. 2 for FAIL, 10 for REJECTED).
    /// * `memo` — Human-readable rejection reason.
    pub async fn reject(
        &mut self,
        action_bytes: &[u8],
        status: i32,
        memo: &str,
    ) -> Result<(), JsValue> {
        let action = pending_action_wire::deserialize(action_bytes)
            .map_err(|e| js_error("DECODE_ERROR", e))?;
        let status_enum =
            derec_proto::StatusEnum::try_from(status).map_err(|_| {
                js_error(
                    "INVALID_STATUS",
                    format!("invalid StatusEnum value: {status}"),
                )
            })?;
        self.inner
            .reject(action, status_enum, memo)
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
                let channel_id_str = e.channel_id.map(|c| c.0.to_string());
                if let Some((status, memo)) = e.as_non_ok_status() {
                    non_ok_status_error(status, memo, channel_id_str.as_deref())
                } else {
                    process_error(e.to_string(), channel_id_str.as_deref())
                }
            })?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }
}

/// Decode the bytes carried by a [`DeRecEvent::SecretRecovered`] event into
/// the structured secret bag (`SecretContainer`) — the *same* shape the owner
/// originally protected. The reconstructed bytes are protobuf, so the FE
/// can't `TextDecoder.decode()` them; this is the canonical unwrapper.
///
/// The wire layering is:
/// ```text
/// raw share fragments → VSS reconstruct → DeRecSecret { secret_data: bag_bytes }
///                                                              └─ SecretContainer { helpers, secrets }
/// ```
///
/// Returns a JS object:
/// ```ts
/// {
///   helpers: Array<{
///     channelId: string,           // u64 as decimal string
///     transportUri: string,
///     communicationInfo: Record<string, string>,
///     sharedKey: Uint8Array,       // 32 bytes
///   }>,
///   secrets: Array<{
///     id: Uint8Array,              // app-defined identifier (binary)
///     name: string,
///     data: Uint8Array,            // raw secret bytes (apps that store text decode with TextDecoder)
///   }>,
/// }
/// ```
#[wasm_bindgen(js_name = "decodeRecoveredSecretBag")]
pub fn decode_recovered_secret_bag(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let derec = DeRecSecret::decode(bytes).map_err(|e| {
        js_error("DECODE_ERROR", format!("DeRecSecret decode failed: {e}"))
    })?;
    let bag = SecretContainer::decode(derec.secret_data.as_slice()).map_err(|e| {
        js_error("DECODE_ERROR", format!("SecretContainer decode failed: {e}"))
    })?;

    // Note: `Vec<u8>` serializes as `Array<number>` by default via
    // serde-wasm-bindgen (matches how `SecretRecovered.secret` is exposed
    // elsewhere — the FE converts to `Uint8Array` at the boundary).
    #[derive(serde::Serialize)]
    struct HelperJs {
        #[serde(rename = "channelId")]
        channel_id: String,
        #[serde(rename = "transportUri")]
        transport_uri: String,
        #[serde(rename = "communicationInfo")]
        communication_info: HashMap<String, String>,
        #[serde(rename = "sharedKey")]
        shared_key: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    struct UserSecretJs {
        id: Vec<u8>,
        name: String,
        data: Vec<u8>,
    }
    #[derive(serde::Serialize)]
    struct BagJs {
        helpers: Vec<HelperJs>,
        secrets: Vec<UserSecretJs>,
    }

    let payload = BagJs {
        helpers: bag
            .helpers
            .into_iter()
            .map(|h| HelperJs {
                channel_id: h.channel_id.to_string(),
                transport_uri: h.transport_uri,
                communication_info: h.communication_info,
                shared_key: h.shared_key,
            })
            .collect(),
        secrets: bag
            .secrets
            .into_iter()
            .map(|s| UserSecretJs {
                id: s.id,
                name: s.name,
                data: s.data,
            })
            .collect(),
    };

    // `Serializer::new().serialize_maps_as_objects(true)` ensures the
    // `communicationInfo` HashMap comes through as a plain JS object rather
    // than a `Map` instance.
    payload
        .serialize(&serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true))
        .map_err(|e: serde_wasm_bindgen::Error| js_error("SERIALIZE_ERROR", e.to_string()))
}

/// Re-populate a set of empty stores from a recovered secret bag, so the
/// caller can resume in the "normal" (non-recovery) namespace as if the bag
/// had been distributed by this device originally.
///
/// For each helper in the decoded bag, three records are written:
///   - `channel_store.save(Channel { ... })` — the paired channel record,
///     including the app's `communication_info` carried in the bag.
///   - `secret_store.save(channel_id, SharedKey(...))` — the negotiated
///     symmetric key, restoring the helper's ability to decrypt our messages.
///   - `share_store.save(channel_id, Share { secret_id, version, bytes: [] })`
///     — an owner-side tracking entry so subsequent verify-share runs know
///     which helpers hold this `(secret_id, version)`.
///
/// The protocol library treats `communication_info` as opaque; whatever the
/// owner put there at protect time (typically `{ "name": "Alice" }`) is
/// restored verbatim.
///
/// **Caller's responsibility**: provide stores backed by an *empty* target
/// namespace (call `clearNamespace` first). This function does not wipe.
#[wasm_bindgen(js_name = "restoreFromRecoveredBag")]
pub async fn restore_from_recovered_bag(
    channel_store: JsValue,
    secret_store: JsValue,
    share_store: JsValue,
    recovered_bytes: &[u8],
    secret_id: &str,
    version: u32,
) -> Result<(), JsValue> {
    let secret_id_u64 = secret_id.parse::<u64>().map_err(|e| {
        js_error("INVALID_SECRET_ID", format!("secret_id must be a u64 decimal string: {e}"))
    })?;

    let derec = DeRecSecret::decode(recovered_bytes).map_err(|e| {
        js_error("DECODE_ERROR", format!("DeRecSecret decode failed: {e}"))
    })?;
    let bag = SecretContainer::decode(derec.secret_data.as_slice()).map_err(|e| {
        js_error("DECODE_ERROR", format!("SecretContainer decode failed: {e}"))
    })?;

    let mut ch_store = JsChannelStore(channel_store);
    let mut sec_store = JsSecretStore(secret_store);
    let mut sh_store = JsShareStore(share_store);

    let created_at = now_secs();
    // HTTPS is the only transport the reference app speaks; this mirrors the
    // value used by the protocol constructor for `own_transport_protocol`.
    const TRANSPORT_HTTPS: i32 = 0;

    for helper in bag.helpers {
        let channel_id = ChannelId(helper.channel_id);

        let shared_key: [u8; 32] = helper.shared_key.as_slice().try_into().map_err(|_| {
            js_error(
                "INVALID_SHARED_KEY",
                format!(
                    "shared_key for channel {} must be 32 bytes, got {}",
                    helper.channel_id,
                    helper.shared_key.len()
                ),
            )
        })?;

        let channel = Channel {
            id: channel_id,
            transport: derec_proto::TransportProtocol {
                uri: helper.transport_uri,
                protocol: TRANSPORT_HTTPS,
            },
            communication_info: helper.communication_info,
            status: ChannelStatus::Paired,
            created_at,
            // Re-established from the recovery bag: this node is the Owner.
            role: derec_proto::SenderKind::Owner,
        };

        ch_store
            .save(channel)
            .await
            .map_err(|e| js_error("CHANNEL_STORE_SAVE", e.to_string()))?;

        sec_store
            .save(channel_id, SecretValue::SharedKey(shared_key))
            .await
            .map_err(|e| js_error("SECRET_STORE_SAVE", e.to_string()))?;

        sh_store
            .save(
                channel_id,
                Share {
                    secret_id: secret_id_u64,
                    version,
                    // Owner-side tracking entry — the helper holds the real
                    // share bytes; the owner only records that it was sent.
                    bytes: Vec::new(),
                },
            )
            .await
            .map_err(|e| js_error("SHARE_STORE_SAVE", e.to_string()))?;
    }

    Ok(())
}

/// Produce a structured JS error for `NonOkStatus` responses.
///
/// Returns `{ code: "NON_OK_STATUS", message, status, memo, channel_id? }`.
fn non_ok_status_error(status: i32, memo: &str, channel_id: Option<&str>) -> JsValue {
    #[derive(serde::Serialize)]
    struct NonOkStatusError<'a> {
        code: &'static str,
        message: String,
        status: i32,
        memo: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel_id: Option<&'a str>,
    }

    serde_wasm_bindgen::to_value(&NonOkStatusError {
        code: "NON_OK_STATUS",
        message: format!("non-ok status (status={status}): {memo}"),
        status,
        memo,
        channel_id,
    })
    .unwrap_or_else(|_| JsValue::from_str("failed to serialize non-ok status error"))
}

/// Produce a structured JS error for general `process()` failures.
///
/// Returns `{ code: "DEREC_ERROR", message, channel_id? }`.
fn process_error(message: String, channel_id: Option<&str>) -> JsValue {
    #[derive(serde::Serialize)]
    struct ProcessErrorJs<'a> {
        code: &'static str,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel_id: Option<&'a str>,
    }

    serde_wasm_bindgen::to_value(&ProcessErrorJs {
        code: "DEREC_ERROR",
        message,
        channel_id,
    })
    .unwrap_or_else(|_| JsValue::from_str("failed to serialize process error"))
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
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        2 => Ok(SenderKind::Replica),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!("invalid sender kind: {kind}, valid values are 0 (Owner), 1 (Helper), 2 (Replica)"),
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
/// - `0` = Pairing: `{ kind: number, contact: ContactMessage, peerCommunicationInfo?: Record<string, string> }`
/// - `1` = Discovery: `{ target: BigInt | BigInt[] | null }`
/// - `2` = ProtectSecret: `{ secrets: UserSecret[], description?: string }`
/// - `3` = VerifyShares: `{ version: number, target: BigInt | BigInt[] | null }`
/// - `4` = RecoverSecret: `{ secretId: Uint8Array, version: number }`
/// - `5` = Unpair: `{ target: BigInt | BigInt[] | null, memo?: string }`
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
            let contact: PairingContactMessage = serde_wasm_bindgen::from_value(contact_val)
                .map_err(|e| js_error("DECODE_ERROR", e.to_string()))?;
            let contact: derec_proto::ContactMessage = contact.into();
            let raw = js_sys::Reflect::get(&params, &JsValue::from_str("peerCommunicationInfo"))
                .unwrap_or(JsValue::UNDEFINED);
            let peer_communication_info: HashMap<String, String> =
                if raw.is_null() || raw.is_undefined() {
                    HashMap::new()
                } else {
                    serde_wasm_bindgen::from_value(raw).map_err(|e| {
                        js_error("INVALID_PEER_COMMUNICATION_INFO", e.to_string())
                    })?
                };
            Ok(DeRecFlow::Pairing {
                kind: sender_kind,
                contact,
                peer_communication_info,
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
            let secret_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("secretId"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secretId: {e:?}")))?;
            let secret_id = js_value_to_u64(secret_id_val)?;
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            let secrets_val = js_sys::Reflect::get(&params, &JsValue::from_str("secrets"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secrets: {e:?}")))?;
            let secrets = parse_user_secrets(secrets_val)?;
            let description = js_sys::Reflect::get(&params, &JsValue::from_str("description"))
                .unwrap_or(JsValue::UNDEFINED)
                .as_string();
            Ok(DeRecFlow::ProtectSecret {
                secret_id,
                target,
                secrets,
                description,
            })
        }
        3 => {
            // VerifyShares
            let secret_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("secretId"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secretId: {e:?}")))?;
            let secret_id = js_value_to_u64(secret_id_val)?;
            let version = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing version: {e:?}")))?
                .as_f64()
                .ok_or_else(|| js_error("DECODE_ERROR", "version must be a number"))?
                as u32;
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            Ok(DeRecFlow::VerifyShares {
                secret_id,
                version,
                target,
            })
        }
        4 => {
            // RecoverSecret
            let secret_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("secretId"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing secretId: {e:?}")))?;
            let secret_id = js_value_to_u64(secret_id_val)?;
            let version = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("DECODE_ERROR", format!("missing version: {e:?}")))?
                .as_f64()
                .ok_or_else(|| js_error("DECODE_ERROR", "version must be a number"))?
                as u32;
            Ok(DeRecFlow::RecoverSecret { secret_id, version })
        }
        5 => {
            // Unpair
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            let memo = js_sys::Reflect::get(&params, &JsValue::from_str("memo"))
                .unwrap_or(JsValue::UNDEFINED)
                .as_string();
            Ok(DeRecFlow::Unpair { target, memo })
        }
        6 => {
            // UpdateChannelInfo
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            let communication_info_val =
                js_sys::Reflect::get(&params, &JsValue::from_str("communicationInfo"))
                    .unwrap_or(JsValue::UNDEFINED);
            let communication_info: Option<HashMap<String, String>> =
                if communication_info_val.is_null() || communication_info_val.is_undefined() {
                    None
                } else {
                    Some(
                        serde_wasm_bindgen::from_value(communication_info_val).map_err(|e| {
                            js_error("INVALID_COMMUNICATION_INFO", e.to_string())
                        })?,
                    )
                };
            let transport_uri_val = js_sys::Reflect::get(&params, &JsValue::from_str("transportUri"))
                .unwrap_or(JsValue::UNDEFINED);
            let transport_protocol = if transport_uri_val.is_null() || transport_uri_val.is_undefined()
            {
                None
            } else {
                let uri = transport_uri_val.as_string().ok_or_else(|| {
                    js_error("INVALID_TRANSPORT_URI", "transportUri must be a string")
                })?;
                let proto_val =
                    js_sys::Reflect::get(&params, &JsValue::from_str("transportProtocol"))
                        .unwrap_or(JsValue::UNDEFINED);
                let proto = match proto_val.as_string().as_deref() {
                    None | Some("") | Some("https") => 0i32,
                    Some(other) => {
                        return Err(js_error(
                            "INVALID_PROTOCOL",
                            format!("unknown transport protocol: {other}"),
                        ));
                    }
                };
                Some(TransportProtocol {
                    uri,
                    protocol: proto,
                })
            };
            Ok(DeRecFlow::UpdateChannelInfo {
                target,
                communication_info,
                transport_protocol,
            })
        }
        _ => Err(js_error(
            "INVALID_FLOW_KIND",
            format!("invalid flow kind: {flow_kind}, must be 0..6"),
        )),
    }
}
