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
// `pending_action_wire` lives in `crate::protocol` so both WASM and
// FFI bridges can share the same on-the-wire encoding for the opaque
// PendingAction blob.
pub(crate) use crate::protocol::pending_action_wire;
mod stores;

use std::collections::HashMap;
use std::time::Duration;

use crate::{
    protocol::{
        DeRecChannelStore, DeRecFlow, DeRecProtocol, DeRecProtocolBuilder, DeRecSecretStore,
        DeRecShareStore, SecretValue, Share, UnpairAck,
        types::{Channel, ChannelStatus, Target, UserSecret},
    },
    types::ChannelId,
    wasm::{
        now_secs,
        ts_bindings_utils::{js_error, js_error_from_lib},
    },
};
use crate::wasm::primitives::pairing::ContactMessage as PairingContactMessage;
use derec_proto::{SenderKind, TransportProtocol};
use js_sys::{Array, Uint8Array};
use stores::{JsChannelStore, JsSecretStore, JsShareStore, JsTransport, JsUserSecretStore};
use wasm_bindgen::prelude::*;

type WasmProtocol = DeRecProtocol<
    JsChannelStore,
    JsShareStore,
    JsSecretStore,
    JsUserSecretStore,
    JsTransport,
>;

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
/// | `SecretRecovered`  | `secret: { helpers, secrets, replicas, owner_replica_id }` (same nested shape as `ReplicaSecretReceived.secret`) |
/// | `NoOp`             | _(none)_                                               |
///
/// `SecretVersionEntry = { secret_id: bigint, versions: { version: number, description: string }[] }`
#[wasm_bindgen]
pub struct DeRecProtocolWasm {
    inner: WasmProtocol,
}

/// Fluent builder for [`DeRecProtocolWasm`]. Mirrors the Rust
/// [`crate::protocol::DeRecProtocolBuilder`] and the dotnet
/// `DeRecProtocolBuilder` method-for-method so a developer who already
/// knows one SDK can move between them without reaching for reference
/// docs.
///
/// Required setters: `withChannelStore`, `withShareStore`,
/// `withSecretStore`, `withTransport`, `withOwnTransport`. Calling
/// `build()` without all five throws.
///
/// All optional setters carry the defaults documented on the Rust
/// builder.
#[wasm_bindgen(js_name = DeRecProtocolBuilder)]
pub struct DeRecProtocolBuilderWasm {
    secret_id: u64,
    channel_store: Option<JsValue>,
    share_store: Option<JsValue>,
    secret_store: Option<JsValue>,
    user_secret_store: Option<JsValue>,
    transport: Option<JsValue>,
    own_transport_uri: Option<String>,
    own_transport_protocol_num: Option<i32>,
    threshold: u32,
    keep_versions_count: u32,
    communication_info: HashMap<String, String>,
    timeout_in_secs: u32,
    auto_respond_on_failure: bool,
    unpair_ack: UnpairAck,
    auto_reply_to: bool,
    auto_accept: crate::protocol::AutoAcceptPolicy,
    replica_id: Option<u64>,
}

#[wasm_bindgen(js_class = DeRecProtocolBuilder)]
impl DeRecProtocolBuilderWasm {
    /// `secretId` is a JS `bigint` or `number`. Identifies the single
    /// secret this protocol instance manages; apps that juggle multiple
    /// secrets instantiate one protocol per id.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_id: JsValue) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let secret_id = js_value_to_u64(secret_id)
            .map_err(|e| js_error("INVALID_SECRET_ID", format!("{e:?}")))?;
        Ok(DeRecProtocolBuilderWasm {
            secret_id,
            channel_store: None,
            share_store: None,
            secret_store: None,
            user_secret_store: None,
            transport: None,
            own_transport_uri: None,
            own_transport_protocol_num: None,
            threshold: 3,
            keep_versions_count: 3,
            communication_info: HashMap::new(),
            timeout_in_secs: 300,
            auto_respond_on_failure: false,
            unpair_ack: UnpairAck::Required,
            auto_reply_to: false,
            auto_accept: crate::protocol::AutoAcceptPolicy::default(),
            replica_id: None,
        })
    }

    #[wasm_bindgen(js_name = withChannelStore)]
    pub fn with_channel_store(mut self, store: JsValue) -> DeRecProtocolBuilderWasm {
        self.channel_store = Some(store);
        self
    }

    #[wasm_bindgen(js_name = withShareStore)]
    pub fn with_share_store(mut self, store: JsValue) -> DeRecProtocolBuilderWasm {
        self.share_store = Some(store);
        self
    }

    #[wasm_bindgen(js_name = withSecretStore)]
    pub fn with_secret_store(mut self, store: JsValue) -> DeRecProtocolBuilderWasm {
        self.secret_store = Some(store);
        self
    }

    #[wasm_bindgen(js_name = withUserSecretStore)]
    pub fn with_user_secret_store(mut self, store: JsValue) -> DeRecProtocolBuilderWasm {
        self.user_secret_store = Some(store);
        self
    }

    #[wasm_bindgen(js_name = withTransport)]
    pub fn with_transport(mut self, transport: JsValue) -> DeRecProtocolBuilderWasm {
        self.transport = Some(transport);
        self
    }

    /// `endpoint` shape: `{ uri: string, protocol: string }`.
    /// `protocol` must be `"https"` (the only protocol supported today).
    #[wasm_bindgen(js_name = withOwnTransport)]
    pub fn with_own_transport(
        mut self,
        endpoint: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        #[derive(serde::Deserialize)]
        struct EndpointShape {
            uri: String,
            protocol: String,
        }
        let parsed: EndpointShape = serde_wasm_bindgen::from_value(endpoint)
            .map_err(|e| js_error("INVALID_OWN_TRANSPORT", e.to_string()))?;
        let protocol_num = match parsed.protocol.to_lowercase().as_str() {
            "https" => 0i32,
            other => {
                return Err(js_error(
                    "INVALID_PROTOCOL",
                    format!("unknown protocol: {other}"),
                ));
            }
        };
        self.own_transport_uri = Some(parsed.uri);
        self.own_transport_protocol_num = Some(protocol_num);
        Ok(self)
    }

    /// Minimum number of shares required to reconstruct the secret.
    /// Default: 3.
    #[wasm_bindgen(js_name = withThreshold)]
    pub fn with_threshold(mut self, threshold: u32) -> DeRecProtocolBuilderWasm {
        self.threshold = threshold;
        self
    }

    /// Number of recent versions each helper must retain. Default: 3.
    #[wasm_bindgen(js_name = withKeepVersionsCount)]
    pub fn with_keep_versions_count(mut self, count: u32) -> DeRecProtocolBuilderWasm {
        self.keep_versions_count = count;
        self
    }

    /// Protocol-wide staleness boundary (seconds). Clamped to at least
    /// 1. Default: 300.
    #[wasm_bindgen(js_name = withTimeout)]
    pub fn with_timeout(mut self, timeout_in_secs: u32) -> DeRecProtocolBuilderWasm {
        self.timeout_in_secs = timeout_in_secs.max(1);
        self
    }

    /// `info` shape: `Record<string, string>`. Default: empty.
    #[wasm_bindgen(js_name = withCommunicationInfo)]
    pub fn with_communication_info(
        mut self,
        info: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let parsed: HashMap<String, String> = serde_wasm_bindgen::from_value(info)
            .map_err(|e| js_error("INVALID_COMMUNICATION_INFO", e.to_string()))?;
        self.communication_info = parsed;
        Ok(self)
    }

    /// Whether the protocol auto-replies on failed inbound processing.
    /// Default: false.
    #[wasm_bindgen(js_name = withAutoRespondOnFailure)]
    pub fn with_auto_respond_on_failure(mut self, enabled: bool) -> DeRecProtocolBuilderWasm {
        self.auto_respond_on_failure = enabled;
        self
    }

    /// `ack` is `"required"` (default) or `"not_required"`.
    #[wasm_bindgen(js_name = withUnpairAck)]
    pub fn with_unpair_ack(
        mut self,
        ack: String,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        self.unpair_ack = match ack.to_ascii_lowercase().as_str() {
            "required" => UnpairAck::Required,
            "not_required" | "notrequired" | "fire_and_forget" => UnpairAck::NotRequired,
            other => {
                return Err(js_error(
                    "INVALID_UNPAIR_ACK",
                    format!(
                        "unknown unpair_ack value: {other:?}; expected \"required\" or \"not_required\""
                    ),
                ));
            }
        };
        Ok(self)
    }

    /// Whether outbound requests stamp `replyTo = ownTransport`.
    /// Default: false.
    #[wasm_bindgen(js_name = withAutoReplyTo)]
    pub fn with_auto_reply_to(mut self, enabled: bool) -> DeRecProtocolBuilderWasm {
        self.auto_reply_to = enabled;
        self
    }

    /// Per-flow auto-accept policy.
    ///
    /// `policy` shape (all fields optional, default `false`):
    /// `{ pairing, prePair, storeShare, verifyShare, discovery, getShare, unpair, updateChannelInfo }`.
    ///
    /// When a field is `true`, `process()` internally accepts the
    /// matching incoming request and emits an `AutoAccepted` event in
    /// place of `ActionRequired`. See the Rust-side
    /// `AutoAcceptPolicy` rustdoc for the per-flow trade-offs.
    /// Default: every field `false`.
    #[wasm_bindgen(js_name = withAutoAccept)]
    pub fn with_auto_accept(
        mut self,
        policy: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        #[derive(serde::Deserialize, Default)]
        #[serde(rename_all = "camelCase", default)]
        struct AutoAcceptPolicyShape {
            pairing: bool,
            pre_pair: bool,
            store_share: bool,
            verify_share: bool,
            discovery: bool,
            get_share: bool,
            unpair: bool,
            update_channel_info: bool,
        }
        let parsed: AutoAcceptPolicyShape = serde_wasm_bindgen::from_value(policy)
            .map_err(|e| js_error("INVALID_AUTO_ACCEPT_POLICY", e.to_string()))?;
        self.auto_accept = crate::protocol::AutoAcceptPolicy {
            pairing: parsed.pairing,
            pre_pair: parsed.pre_pair,
            store_share: parsed.store_share,
            verify_share: parsed.verify_share,
            discovery: parsed.discovery,
            get_share: parsed.get_share,
            unpair: parsed.unpair,
            update_channel_info: parsed.update_channel_info,
        };
        Ok(self)
    }

    /// `id` is a JS `bigint` or `number`. Default: unset.
    #[wasm_bindgen(js_name = withReplicaId)]
    pub fn with_replica_id(
        mut self,
        id: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let v = js_value_to_u64(id)
            .map_err(|e| js_error("INVALID_REPLICA_ID", format!("{e:?}")))?;
        self.replica_id = Some(v);
        Ok(self)
    }

    /// Finalize the configuration. Throws if any of the required
    /// setters was not called.
    pub fn build(self) -> Result<DeRecProtocolWasm, JsValue> {
        let channel_store = self
            .channel_store
            .ok_or_else(|| js_error("BUILDER_MISSING", "withChannelStore is required"))?;
        let share_store = self
            .share_store
            .ok_or_else(|| js_error("BUILDER_MISSING", "withShareStore is required"))?;
        let secret_store = self
            .secret_store
            .ok_or_else(|| js_error("BUILDER_MISSING", "withSecretStore is required"))?;
        let user_secret_store = self
            .user_secret_store
            .ok_or_else(|| js_error("BUILDER_MISSING", "withUserSecretStore is required"))?;
        let transport = self
            .transport
            .ok_or_else(|| js_error("BUILDER_MISSING", "withTransport is required"))?;
        let own_transport_uri = self
            .own_transport_uri
            .ok_or_else(|| js_error("BUILDER_MISSING", "withOwnTransport is required"))?;
        let own_transport_protocol = self
            .own_transport_protocol_num
            .ok_or_else(|| js_error("BUILDER_MISSING", "withOwnTransport is required"))?;

        let proto_tp = TransportProtocol {
            uri: own_transport_uri,
            protocol: own_transport_protocol,
        };
        // Library-level structural + scheme/protocol validation —
        // `TryFrom` runs both the enum-discriminant check and the
        // URI rules in a single step. Catches plaintext downgrades
        // and unknown enums before the value can be propagated to
        // peers via pairing or UpdateChannelInfo.
        let own_transport = crate::transport::TransportProtocol::try_from(&proto_tp)
            .map_err(|e| js_error("INVALID_OWN_TRANSPORT", e.to_string()))?;

        let mut builder = DeRecProtocolBuilder::new(self.secret_id)
            .with_channel_store(JsChannelStore(channel_store))
            .with_share_store(JsShareStore(share_store))
            .with_secret_store(JsSecretStore(secret_store))
            .with_user_secret_store(JsUserSecretStore(user_secret_store))
            .with_transport(JsTransport(transport))
            .with_own_transport(own_transport)
            .with_threshold(self.threshold as usize)
            .with_keep_versions_count(self.keep_versions_count as usize)
            .with_communication_info(self.communication_info)
            .with_timeout(Duration::from_secs(u64::from(self.timeout_in_secs)))
            .with_auto_respond_on_failure(self.auto_respond_on_failure)
            .with_unpair_ack(self.unpair_ack)
            .with_auto_reply_to(self.auto_reply_to)
            .with_auto_accept(self.auto_accept);
        if let Some(id) = self.replica_id {
            builder = builder.with_replica_id(id);
        }
        let inner = builder.build().map_err(js_error_from_lib)?;
        Ok(DeRecProtocolWasm { inner })
    }
}

#[wasm_bindgen]
impl DeRecProtocolWasm {

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
    /// The secret identifier this protocol instance is bound to.
    #[wasm_bindgen(js_name = "secretId")]
    pub fn secret_id(&self) -> u64 {
        self.inner.secret_id()
    }

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
        let proto_tp = TransportProtocol {
            uri,
            protocol: protocol_num,
        };
        // Validation runs through the typed `TryFrom` so scheme +
        // enum mismatches are rejected before the URI is stored.
        let lib_tp = crate::transport::TransportProtocol::try_from(&proto_tp)
            .map_err(|e| js_error("INVALID_OWN_TRANSPORT", e.to_string()))?;
        self.inner
            .set_own_transport(lib_tp)
            .map_err(|e| js_error("INVALID_OWN_TRANSPORT", e.to_string()))?;
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

    /// Derive the human-readable fingerprint for a paired channel. Both
    /// sides of a replica pair derive the same fingerprint from the
    /// shared key, enabling out-of-band confirmation before the channel
    /// transitions from `Pending` to `Paired`.
    #[wasm_bindgen(js_name = "getFingerprint")]
    pub async fn get_fingerprint(&mut self, channel_id: JsValue) -> Result<String, JsValue> {
        let id = js_value_to_u64(channel_id)?;
        self.inner
            .get_fingerprint(ChannelId(id))
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Verify a fingerprint against the channel's locally-derived one. On
    /// match, the channel transitions from `Pending` to `Paired`. Returns
    /// `true` when the fingerprint matches and the channel is confirmed,
    /// `false` otherwise.
    #[wasm_bindgen(js_name = "verifyFingerprint")]
    pub async fn verify_fingerprint(
        &mut self,
        channel_id: JsValue,
        fingerprint: String,
    ) -> Result<bool, JsValue> {
        let id = js_value_to_u64(channel_id)?;
        self.inner
            .verify_fingerprint(ChannelId(id), &fingerprint)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
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

/// Re-populate a set of empty stores from a recovered [`Secret`], so the
/// caller can resume in the "normal" (non-recovery) namespace as if the
/// secret had been distributed by this device originally.
///
/// `recoveredSecret` is the **typed `Secret` object** carried by the
/// `SecretRecovered` event (`{ helpers, secrets, replicas,
/// ownerReplicaId }`), passed verbatim — no protobuf encode required.
///
/// For each helper in the recovered secret, three records are written:
///   - `channel_store.save(Channel { ... })` — the paired channel record,
///     including the app's `communication_info` carried in the secret.
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
#[wasm_bindgen(js_name = "restoreFromRecoveredSecret")]
pub async fn restore_from_recovered_secret(
    channel_store: JsValue,
    secret_store: JsValue,
    share_store: JsValue,
    recovered_secret: JsValue,
    secret_id: &str,
    version: u32,
) -> Result<(), JsValue> {
    let secret_id_u64 = secret_id.parse::<u64>().map_err(|e| {
        js_error("INVALID_SECRET_ID", format!("secret_id must be a u64 decimal string: {e}"))
    })?;

    // Mirror the JS-side shape that `SecretRecovered.secret` exposes
    // (`SecretWire` in `events/wire.rs`). serde-wasm-bindgen converts
    // the camelCase JS keys back into the snake_case fields the
    // wire shape uses.
    #[derive(serde::Deserialize)]
    struct HelperInput {
        channel_id: String,
        transport_uri: String,
        #[serde(default)]
        communication_info: HashMap<String, String>,
        shared_key: Vec<u8>,
    }
    #[derive(serde::Deserialize)]
    struct SecretInput {
        helpers: Vec<HelperInput>,
    }
    let restored: SecretInput = serde_wasm_bindgen::from_value(recovered_secret)
        .map_err(|e| js_error("INVALID_RECOVERED_SECRET", e.to_string()))?;

    let mut ch_store = JsChannelStore(channel_store);
    let mut sec_store = JsSecretStore(secret_store);
    let mut sh_store = JsShareStore(share_store);

    let created_at = now_secs();
    // HTTPS is the only transport the reference app speaks; this mirrors the
    // value used by the protocol constructor for `own_transport_protocol`.
    const TRANSPORT_HTTPS: i32 = 0;

    for helper in restored.helpers {
        let channel_id_u64 = helper.channel_id.parse::<u64>().map_err(|e| {
            js_error(
                "INVALID_CHANNEL_ID",
                format!("channel_id must be a u64 decimal string: {e}"),
            )
        })?;
        let channel_id = ChannelId(channel_id_u64);

        let shared_key: [u8; 32] = helper.shared_key.as_slice().try_into().map_err(|_| {
            js_error(
                "INVALID_SHARED_KEY",
                format!(
                    "shared_key for channel {} must be 32 bytes, got {}",
                    channel_id_u64,
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
            // Helper channel record — replicas are not part of the recovery bag.
            replica_id: None,
        };

        ch_store
            .save(secret_id_u64, channel)
            .await
            .map_err(|e| js_error("CHANNEL_STORE_SAVE", e.to_string()))?;

        sec_store
            .save(
                secret_id_u64,
                channel_id,
                SecretValue::SharedKey(shared_key),
            )
            .await
            .map_err(|e| js_error("SECRET_STORE_SAVE", e.to_string()))?;

        sh_store
            .save(
                secret_id_u64,
                channel_id,
                Share {
                    secret_id: secret_id_u64,
                    version,
                    // Owner-side tracking-only entry created from a
                    // separate test fixture path — there is no producing
                    // replica here, so `replica_id` is None.
                    replica_id: None,
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
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!("invalid sender kind: {kind}, valid values are 0 (Owner), 1 (Helper), 3 (ReplicaSource), 4 (ReplicaDestination)"),
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
            //
            // Wire-shape mirrors the dotnet `UpdateChannelInfoParams`:
            // `{ target, communication_info?, transport_protocol?: { uri, protocol: number } }`.
            // Field names are snake_case for SDK parity.
            let target_val = js_sys::Reflect::get(&params, &JsValue::from_str("target"))
                .unwrap_or(JsValue::UNDEFINED);
            let target = parse_target(target_val)?;
            let communication_info_val =
                js_sys::Reflect::get(&params, &JsValue::from_str("communication_info"))
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
            let transport_protocol_val =
                js_sys::Reflect::get(&params, &JsValue::from_str("transport_protocol"))
                    .unwrap_or(JsValue::UNDEFINED);
            let transport_protocol = if transport_protocol_val.is_null()
                || transport_protocol_val.is_undefined()
            {
                None
            } else {
                #[derive(serde::Deserialize)]
                struct TransportShape {
                    uri: String,
                    protocol: i32,
                }
                let parsed: TransportShape = serde_wasm_bindgen::from_value(transport_protocol_val)
                    .map_err(|e| js_error("INVALID_TRANSPORT_PROTOCOL", e.to_string()))?;
                Some(TransportProtocol {
                    uri: parsed.uri,
                    protocol: parsed.protocol,
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
