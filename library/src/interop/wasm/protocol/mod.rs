// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
//! import { init, ContactMode, DeRecProtocolBuilder, FlowKind, SenderKind } from "@derec-alliance/web";
//!
//! await init(); // web only; the nodejs package needs no initialisation
//!
//! const protocol = new DeRecProtocolBuilder(secretId)
//!   .withChannelStore(channelStore)
//!   .withShareStore(shareStore)
//!   .withSecretStore(secretStore)
//!   .withUserSecretStore(userSecretStore)
//!   .withStateStore(stateStore)
//!   .withTransport(transport)
//!   .withOwnTransports([{ uri: "https://my-node.example.com/derec", protocol: "https" }])
//!   .build();
//!
//! // Responder: mint a contact message and hand it to the peer out of band.
//! const contact = await protocol.createContact(null, ContactMode.InlineKeys);
//!
//! // Initiator: begin pairing from the peer's contact message.
//! await protocol.start(FlowKind.Pairing, { kind: SenderKind.Owner, contact: peerContact });
//!
//! // Feed incoming wire bytes; react to returned events.
//! const events = await protocol.process(rawBytes);
//! for (const ev of events) {
//!   if (ev.type === "PairingCompleted") { ... }
//! }
//! ```
//!
//! The store and transport interfaces and every event shape are declared in
//! the package's `index.d.ts`.

mod events;

pub(super) use crate::interop::protocol_names::{
    protocol_discriminant_to_name, protocol_name_to_discriminant,
};

// `pending_action_wire` lives in `crate::protocol::utils` so both WASM
// and FFI bridges can share the same on-the-wire encoding for the opaque
// PendingAction blob.
pub(crate) use crate::protocol::utils::pending_action_wire;
mod stores;

use std::collections::HashMap;
use std::time::Duration;

use crate::interop::protocol_names::unpair_ack_from_name;
use crate::interop::wasm::primitives::pairing::ContactMessage as PairingContactMessage;
use crate::{
    interop::wasm::ts_bindings_utils::{js_error, js_error_from_lib},
    protocol::{
        DeRecFlow, DeRecProtocol, DeRecProtocolBuilder, UnpairAck,
        types::{Target, UserSecret},
    },
    types::ChannelId,
};
use derec_proto::{SenderKind, TransportProtocol};
use js_sys::{Array, Uint8Array};
use stores::{
    JsChannelStore, JsSecretStore, JsShareStore, JsStateStore, JsTransport, JsUserSecretStore,
};
use wasm_bindgen::prelude::*;

type WasmProtocol = DeRecProtocol<
    JsChannelStore,
    JsShareStore,
    JsSecretStore,
    JsUserSecretStore,
    JsStateStore,
    JsTransport,
>;

/// Higher-level DeRec protocol orchestrator for TypeScript/JavaScript consumers.
///
/// Wraps [`crate::protocol::DeRecProtocol`] with JS-side store
/// and transport adapters so that a TypeScript application can drive every
/// protocol flow without routing raw bytes manually. Built with
/// [`DeRecProtocolBuilderWasm`] (`DeRecProtocolBuilder` in JS).
///
/// # Stores
///
/// The five stores and the transport are JS objects implementing the
/// `ChannelStore`, `ShareStore`, `SecretStore`, `UserSecretStore`,
/// `StateStore` and `Transport` interfaces in `index.d.ts`. All their methods
/// must return `Promise`s — synchronous implementations can wrap their result
/// with `Promise.resolve(...)`.
///
/// # Concurrency
///
/// Every method that touches protocol state is `async` and runs under one
/// lock per instance, so overlapping calls on the same instance — a
/// `tick` timer firing while `process` handles an inbound message — queue
/// and run one at a time, in the order they were made. Distinct instances
/// do not share the lock: two instances bound to the same `secret_id` and
/// the same stores must still be serialized by the caller.
///
/// A store or transport callback must not await a call on the instance
/// that invoked it: that call queues behind the one waiting on the
/// callback, and neither settles. Calling `free()` while a call is in
/// flight throws.
///
/// Methods take `&self` for this reason: wasm-bindgen holds the borrow of
/// the instance for an async call's whole lifetime, so under `&mut self` an
/// overlapping call fails that borrow outside its promise and never
/// settles.
///
/// # Events
///
/// [`process`](DeRecProtocolWasm::process), [`start`](DeRecProtocolWasm::start),
/// [`accept`](DeRecProtocolWasm::accept), [`tick`](DeRecProtocolWasm::tick)
/// and [`restore`](DeRecProtocolWasm::restore) return an `Array` of plain JS
/// objects, one per [`crate::protocol::DeRecEvent`], each tagged by a `type`
/// field naming the variant. Every `u64` identifier (`channel_id`,
/// `secret_id`, `replica_id`, `trace_id`) is a decimal string. The full set of
/// shapes is the `DeRecEvent` union in `index.d.ts`.
#[wasm_bindgen]
pub struct DeRecProtocolWasm {
    inner: tokio::sync::Mutex<WasmProtocol>,
    secret_id: u64,
}

/// JS-side shape of [`crate::protocol::types::Timeouts`]. Every field is
/// optional; absent means the library's default stands. Mirrors the FFI
/// `"timeouts"` config object so the two bindings cannot drift.
#[derive(serde::Deserialize)]
struct TimeoutsJs {
    #[serde(default)]
    inbound_message_secs: Option<u64>,
    #[serde(default)]
    sharing_round_secs: Option<u64>,
    #[serde(default)]
    unpair_ack_secs: Option<u64>,
    #[serde(default)]
    expired_channels: Option<ExpiredChannelsJs>,
}

#[derive(serde::Deserialize)]
struct ExpiredChannelsJs {
    enabled: bool,
    timeout_in_secs: u64,
}

impl TimeoutsJs {
    fn to_timeouts(&self) -> crate::protocol::types::Timeouts {
        let d = crate::protocol::types::Timeouts::default();
        crate::protocol::types::Timeouts {
            inbound_message: self
                .inbound_message_secs
                .map_or(d.inbound_message, Duration::from_secs),
            sharing_round: self
                .sharing_round_secs
                .map_or(d.sharing_round, Duration::from_secs),
            unpair_ack: self
                .unpair_ack_secs
                .map_or(d.unpair_ack, Duration::from_secs),
            expired_channels: self
                .expired_channels
                .as_ref()
                .map_or(d.expired_channels, |e| {
                    crate::protocol::ExpiredChannelCleanup::new(e.enabled, e.timeout_in_secs)
                }),
        }
    }
}

/// Fluent builder for [`DeRecProtocolWasm`]. Mirrors the Rust
/// [`crate::protocol::DeRecProtocolBuilder`] and the dotnet
/// `DeRecProtocolBuilder` method-for-method so a developer who already
/// knows one SDK can move between them without reaching for reference
/// docs.
///
/// Required setters: `withChannelStore`, `withShareStore`,
/// `withSecretStore`, `withUserSecretStore`, `withStateStore`,
/// `withTransport`, and `withOwnTransports`. Calling `build()` without all
/// seven throws.
///
/// An optional setter that is never called leaves the Rust builder's default
/// in force: the value is forwarded only when the application supplied one.
#[wasm_bindgen(js_name = DeRecProtocolBuilder)]
pub struct DeRecProtocolBuilderWasm {
    secret_id: u64,
    channel_store: Option<JsValue>,
    share_store: Option<JsValue>,
    secret_store: Option<JsValue>,
    user_secret_store: Option<JsValue>,
    state_store: Option<JsValue>,
    transport: Option<JsValue>,
    /// Set by `withOwnTransports`, in preference order.
    own_transports: Vec<crate::transport::TransportProtocol>,
    threshold: Option<u32>,
    keep_versions_count: Option<u32>,
    communication_info: Option<HashMap<String, String>>,
    timeouts: Option<TimeoutsJs>,
    unsafe_connection: Option<bool>,
    auto_respond_on_failure: Option<bool>,
    unpair_ack: Option<UnpairAck>,
    auto_reply_to: Option<bool>,
    auto_accept: Option<crate::protocol::AutoAcceptPolicy>,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
}

#[wasm_bindgen(js_class = DeRecProtocolBuilder)]
impl DeRecProtocolBuilderWasm {
    /// `secretId` is a JS `bigint` or `number`. Identifies the single
    /// secret this protocol instance manages; apps that juggle multiple
    /// secrets instantiate one protocol per id.
    #[wasm_bindgen(constructor)]
    pub fn new(secret_id: JsValue) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let secret_id = js_value_to_u64(secret_id)
            .map_err(|e| js_error("invalid_secret_id", format!("{e:?}")))?;
        Ok(DeRecProtocolBuilderWasm {
            secret_id,
            channel_store: None,
            share_store: None,
            secret_store: None,
            user_secret_store: None,
            state_store: None,
            transport: None,
            own_transports: Vec::new(),
            threshold: None,
            keep_versions_count: None,
            communication_info: None,
            timeouts: None,
            unsafe_connection: None,
            auto_respond_on_failure: None,
            unpair_ack: None,
            auto_reply_to: None,
            auto_accept: None,
            replica_id: None,
            parameter_range: None,
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

    #[wasm_bindgen(js_name = withStateStore)]
    pub fn with_state_store(mut self, store: JsValue) -> DeRecProtocolBuilderWasm {
        self.state_store = Some(store);
        self
    }

    #[wasm_bindgen(js_name = withTransport)]
    pub fn with_transport(mut self, transport: JsValue) -> DeRecProtocolBuilderWasm {
        self.transport = Some(transport);
        self
    }

    /// Every transport endpoint this application serves, in preference
    /// order. `transports` is an array of `{ uri: string, protocol: string
    /// }` objects, `protocol` being `"https"` or `"grpc"`
    /// (case-insensitive).
    ///
    /// The order is the application's own preference and decides which of
    /// a peer's offered endpoints is used. Every listed transport must
    /// actually be served, because delivery is push-only — listing an
    /// endpoint this application does not serve makes pairing succeed and
    /// replies vanish.
    #[wasm_bindgen(js_name = withOwnTransports)]
    pub fn with_own_transports(
        mut self,
        transports: Vec<JsValue>,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        #[derive(serde::Deserialize)]
        struct EndpointShape {
            uri: String,
            protocol: String,
        }
        let mut parsed_transports = Vec::with_capacity(transports.len());
        for endpoint in transports {
            let parsed: EndpointShape = serde_wasm_bindgen::from_value(endpoint)
                .map_err(|e| js_error("invalid_own_transport", e.to_string()))?;
            let protocol_num =
                protocol_name_to_discriminant(&parsed.protocol).ok_or_else(|| {
                    js_error(
                        "invalid_protocol",
                        format!("unknown protocol: {}", parsed.protocol.to_lowercase()),
                    )
                })?;
            let proto_tp = TransportProtocol {
                uri: parsed.uri,
                protocol: protocol_num,
            };
            // Structural + scheme/protocol validation, run per entry, order
            // preserved verbatim — it is the application's preference.
            let tp = crate::transport::TransportProtocol::try_from(&proto_tp)
                .map_err(|e| js_error("invalid_own_transport", e.to_string()))?;
            parsed_transports.push(tp);
        }
        self.own_transports = parsed_transports;
        Ok(self)
    }

    /// Minimum number of shares required to reconstruct the secret.
    /// Default: [`crate::protocol::DEFAULT_THRESHOLD`].
    #[wasm_bindgen(js_name = withThreshold)]
    pub fn with_threshold(mut self, threshold: u32) -> DeRecProtocolBuilderWasm {
        self.threshold = Some(threshold);
        self
    }

    /// Number of recent versions each helper must retain.
    /// Default: [`crate::protocol::DEFAULT_KEEP_VERSIONS_COUNT`].
    #[wasm_bindgen(js_name = withKeepVersionsCount)]
    pub fn with_keep_versions_count(mut self, count: u32) -> DeRecProtocolBuilderWasm {
        self.keep_versions_count = Some(count);
        self
    }

    /// Accept plaintext transport endpoints — `http://` and `grpc://`.
    /// **Development only.** Default `false`.
    ///
    /// With it `false`, plaintext is accepted only for an endpoint this
    /// device configured for *itself* that names loopback (`localhost`,
    /// `127.0.0.1`, `::1`) — so a local dev server needs no configuration.
    /// With it `true`, plaintext is accepted for any host on any path,
    /// including endpoints a peer supplies. That is what makes the LAN case
    /// work (a phone against a laptop), and why the name is blunt.
    #[wasm_bindgen(js_name = withUnsafeConnection)]
    pub fn with_unsafe_connection(mut self, allow: bool) -> DeRecProtocolBuilderWasm {
        self.unsafe_connection = Some(allow);
        self
    }

    /// Configure the four waiting periods in one call.
    ///
    /// Object shape — every field optional, and **absent means "keep the
    /// library default"**:
    ///
    /// ```text
    /// {
    ///   inbound_message_secs?: number,   // staleness / replay window
    ///   sharing_round_secs?:   number,
    ///   unpair_ack_secs?:      number,
    ///   expired_channels?:     { enabled: boolean, timeout_in_secs: number },
    /// }
    /// ```
    ///
    /// Values are forwarded verbatim; clamping and the meaning of a disabled
    /// `expired_channels` are library decisions, not this shim's. Not calling
    /// this leaves every default in force.
    #[wasm_bindgen(js_name = withTimeouts)]
    pub fn with_timeouts(mut self, timeouts: JsValue) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let parsed: TimeoutsJs = serde_wasm_bindgen::from_value(timeouts)
            .map_err(|e| js_error("invalid_timeouts", e.to_string()))?;
        self.timeouts = Some(parsed);
        Ok(self)
    }

    /// `info` shape: `Record<string, string>`. Default: empty.
    #[wasm_bindgen(js_name = withCommunicationInfo)]
    pub fn with_communication_info(
        mut self,
        info: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let parsed: HashMap<String, String> = serde_wasm_bindgen::from_value(info)
            .map_err(|e| js_error("invalid_communication_info", e.to_string()))?;
        self.communication_info = Some(parsed);
        Ok(self)
    }

    /// Whether the protocol auto-replies on failed inbound processing.
    /// Default: false.
    #[wasm_bindgen(js_name = withAutoRespondOnFailure)]
    pub fn with_auto_respond_on_failure(mut self, enabled: bool) -> DeRecProtocolBuilderWasm {
        self.auto_respond_on_failure = Some(enabled);
        self
    }

    /// `ack` is exactly `"required"` (default) or `"not_required"`, naming
    /// [`UnpairAck::Required`] and [`UnpairAck::NotRequired`].
    #[wasm_bindgen(js_name = withUnpairAck)]
    pub fn with_unpair_ack(mut self, ack: String) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        self.unpair_ack = Some(unpair_ack_from_name(&ack).ok_or_else(|| {
            js_error(
                "invalid_unpair_ack",
                format!(
                    "unknown unpair_ack value: {ack:?}; expected \"required\" or \"not_required\""
                ),
            )
        })?);
        Ok(self)
    }

    /// Whether outbound requests carry this node's own transports as their reply-to list.
    /// Default: false.
    #[wasm_bindgen(js_name = withAutoReplyTo)]
    pub fn with_auto_reply_to(mut self, enabled: bool) -> DeRecProtocolBuilderWasm {
        self.auto_reply_to = Some(enabled);
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
            .map_err(|e| js_error("invalid_auto_accept_policy", e.to_string()))?;
        self.auto_accept = Some(crate::protocol::AutoAcceptPolicy {
            pairing: parsed.pairing,
            pre_pair: parsed.pre_pair,
            store_share: parsed.store_share,
            verify_share: parsed.verify_share,
            discovery: parsed.discovery,
            get_share: parsed.get_share,
            unpair: parsed.unpair,
            update_channel_info: parsed.update_channel_info,
        });
        Ok(self)
    }

    /// `id` is a JS `bigint` or `number`. Default: unset.
    #[wasm_bindgen(js_name = withReplicaId)]
    pub fn with_replica_id(mut self, id: JsValue) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        let v =
            js_value_to_u64(id).map_err(|e| js_error("invalid_replica_id", format!("{e:?}")))?;
        self.replica_id = Some(v);
        Ok(self)
    }

    /// Declare the local node's acceptable parameter range for pair
    /// negotiation. `range` is a JS object whose keys match the
    /// `ParameterRange` interface every binding already declares —
    /// `min_share_size`, `max_share_size`, `min_time_between_verifications`,
    /// … — so one shape serves the wasm and FFI paths alike. Each field is
    /// `i64`: accept either a number or a `BigInt` on the JS side. Every
    /// field is optional and defaults to `0`, which the proto reads as no
    /// constraint on that dimension. Default: unset (no constraints
    /// advertised, every peer range accepted).
    #[wasm_bindgen(js_name = withParameterRange)]
    pub fn with_parameter_range(
        mut self,
        range: JsValue,
    ) -> Result<DeRecProtocolBuilderWasm, JsValue> {
        #[derive(serde::Deserialize)]
        struct In {
            #[serde(default)]
            min_share_size: i64,
            #[serde(default)]
            max_share_size: i64,
            #[serde(default)]
            min_time_between_verifications: i64,
            #[serde(default)]
            max_time_between_verifications: i64,
            #[serde(default)]
            min_time_between_share_updates: i64,
            #[serde(default)]
            max_time_between_share_updates: i64,
            #[serde(default)]
            min_unresponsive_deletion_timeout: i64,
            #[serde(default)]
            max_unresponsive_deletion_timeout: i64,
            #[serde(default)]
            min_unresponsive_deactivation_timeout: i64,
            #[serde(default)]
            max_unresponsive_deactivation_timeout: i64,
        }
        let parsed: In = serde_wasm_bindgen::from_value(range)
            .map_err(|e| js_error("invalid_parameter_range", e.to_string()))?;
        self.parameter_range = Some(derec_proto::ParameterRange {
            min_share_size: parsed.min_share_size,
            max_share_size: parsed.max_share_size,
            min_time_between_verifications: parsed.min_time_between_verifications,
            max_time_between_verifications: parsed.max_time_between_verifications,
            min_time_between_share_updates: parsed.min_time_between_share_updates,
            max_time_between_share_updates: parsed.max_time_between_share_updates,
            min_unresponsive_deletion_timeout: parsed.min_unresponsive_deletion_timeout,
            max_unresponsive_deletion_timeout: parsed.max_unresponsive_deletion_timeout,
            min_unresponsive_deactivation_timeout: parsed.min_unresponsive_deactivation_timeout,
            max_unresponsive_deactivation_timeout: parsed.max_unresponsive_deactivation_timeout,
        });
        Ok(self)
    }

    /// Finalize the configuration. Throws if any of the required
    /// setters was not called.
    pub fn build(self) -> Result<DeRecProtocolWasm, JsValue> {
        let channel_store = self
            .channel_store
            .ok_or_else(|| js_error("builder_missing", "withChannelStore is required"))?;
        let share_store = self
            .share_store
            .ok_or_else(|| js_error("builder_missing", "withShareStore is required"))?;
        let secret_store = self
            .secret_store
            .ok_or_else(|| js_error("builder_missing", "withSecretStore is required"))?;
        let user_secret_store = self
            .user_secret_store
            .ok_or_else(|| js_error("builder_missing", "withUserSecretStore is required"))?;
        let state_store = self
            .state_store
            .ok_or_else(|| js_error("builder_missing", "withStateStore is required"))?;
        let transport = self
            .transport
            .ok_or_else(|| js_error("builder_missing", "withTransport is required"))?;
        let mut builder = DeRecProtocolBuilder::new(self.secret_id)
            .with_channel_store(JsChannelStore(channel_store))
            .with_share_store(JsShareStore(share_store))
            .with_secret_store(JsSecretStore(secret_store))
            .with_user_secret_store(JsUserSecretStore(user_secret_store))
            .with_state_store(JsStateStore(state_store))
            .with_transport(JsTransport(transport))
            .with_own_transports(self.own_transports);
        if let Some(threshold) = self.threshold {
            builder = builder.with_threshold(threshold as usize);
        }
        if let Some(count) = self.keep_versions_count {
            builder = builder.with_keep_versions_count(count as usize);
        }
        if let Some(info) = self.communication_info {
            builder = builder.with_communication_info(info);
        }
        if let Some(enabled) = self.auto_respond_on_failure {
            builder = builder.with_auto_respond_on_failure(enabled);
        }
        if let Some(ack) = self.unpair_ack {
            builder = builder.with_unpair_ack(ack);
        }
        if let Some(enabled) = self.auto_reply_to {
            builder = builder.with_auto_reply_to(enabled);
        }
        if let Some(policy) = self.auto_accept {
            builder = builder.with_auto_accept(policy);
        }
        if let Some(allow) = self.unsafe_connection {
            builder = builder.with_unsafe_connection(allow);
        }
        if let Some(t) = self.timeouts {
            builder = builder.with_timeouts(t.to_timeouts());
        }
        if let Some(id) = self.replica_id {
            builder = builder.with_replica_id(id);
        }
        if let Some(range) = self.parameter_range {
            builder = builder.with_parameter_range(range);
        }
        let inner = builder.build().map_err(js_error_from_lib)?;
        Ok(DeRecProtocolWasm {
            secret_id: inner.secret_id(),
            inner: tokio::sync::Mutex::new(inner),
        })
    }
}

#[wasm_bindgen]
impl DeRecProtocolWasm {
    /// The secret identifier this protocol instance is bound to.
    #[wasm_bindgen(js_name = "secretId")]
    pub fn secret_id(&self) -> u64 {
        self.secret_id
    }

    /// Single entry point for all three contact modes (`InlineKeys`,
    /// `HashedKeys`, `NoKeys`).
    ///
    /// * `channel_id` — `null`/`undefined` lets the library mint a
    ///   random id; otherwise `bigint` / `number` is used verbatim.
    /// * `contact_mode` — `0` (InlineKeys), `1` (HashedKeys), `2` (NoKeys).
    /// * `nonce` — `null`/`undefined` lets the library generate a fresh
    ///   random `u64`; otherwise the supplied `bigint`/`number` is used.
    ///   Required for `NoKeys` where callers typically pick a small
    ///   human-typable value.
    #[wasm_bindgen(js_name = "createContact")]
    pub async fn create_contact(
        &self,
        channel_id: JsValue,
        contact_mode: u32,
        nonce: JsValue,
    ) -> Result<JsValue, JsValue> {
        let id = parse_optional_channel_id(channel_id)?;
        let mode = match contact_mode {
            0 => derec_proto::ContactMode::InlineKeys,
            1 => derec_proto::ContactMode::HashedKeys,
            2 => derec_proto::ContactMode::NoKeys,
            other => {
                return Err(js_error(
                    "invalid_contact_mode",
                    format!(
                        "unknown contact_mode: {other}; expected 0 (InlineKeys), 1 (HashedKeys), or 2 (NoKeys)"
                    ),
                ));
            }
        };
        let nonce = if nonce.is_null() || nonce.is_undefined() {
            None
        } else {
            Some(js_value_to_u64(nonce)?)
        };
        let contact = self
            .inner
            .lock()
            .await
            .create_contact(id, mode, nonce)
            .await
            .map_err(js_error_from_lib)?;
        let contact: PairingContactMessage = contact.into();
        let serializer =
            serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
        use serde::Serialize as _;
        contact
            .serialize(&serializer)
            .map_err(|e| js_error("wasm_serialize_error", e.to_string()))
    }

    /// Replace this node's local communication info. Does not contact peers —
    /// follow up with a `start(UpdateChannelInfo, ...)` to propagate.
    #[wasm_bindgen(js_name = "setCommunicationInfo")]
    pub async fn set_communication_info(&self, info: JsValue) -> Result<(), JsValue> {
        let map: HashMap<String, String> = if info.is_null() || info.is_undefined() {
            HashMap::new()
        } else {
            serde_wasm_bindgen::from_value(info)
                .map_err(|e| js_error("invalid_communication_info", e.to_string()))?
        };
        self.inner.lock().await.set_communication_info(map);
        Ok(())
    }

    /// Replace every endpoint this node advertises, in preference order.
    ///
    /// `transports` is an array of `{ uri: string, protocol: string }`
    /// objects, same shape as `withOwnTransports`, and is its runtime
    /// counterpart. A node serves at most one endpoint per protocol, so this list
    /// is a preference order over distinct protocols and two entries of the
    /// same protocol are rejected.
    ///
    /// Every entry is validated before any is stored, so a malformed URI
    /// leaves the previous set intact. IMPORTANT: keep the old endpoints
    /// operational during the changeover — see the Rust docs on
    /// `set_own_transports` for the discipline.
    #[wasm_bindgen(js_name = "setOwnTransports")]
    pub async fn set_own_transports(&self, transports: Vec<JsValue>) -> Result<(), JsValue> {
        #[derive(serde::Deserialize)]
        struct EndpointShape {
            uri: String,
            protocol: String,
        }
        let mut validated = Vec::with_capacity(transports.len());
        for endpoint in transports {
            let parsed: EndpointShape = serde_wasm_bindgen::from_value(endpoint)
                .map_err(|e| js_error("invalid_own_transport", e.to_string()))?;
            let protocol_num =
                protocol_name_to_discriminant(&parsed.protocol).ok_or_else(|| {
                    js_error(
                        "invalid_protocol",
                        format!("unknown protocol: {}", parsed.protocol.to_lowercase()),
                    )
                })?;
            let proto_tp = TransportProtocol {
                uri: parsed.uri,
                protocol: protocol_num,
            };
            validated.push(
                crate::transport::TransportProtocol::try_from(&proto_tp)
                    .map_err(|e| js_error("invalid_own_transport", e.to_string()))?,
            );
        }
        self.inner
            .lock()
            .await
            .set_own_transports(validated)
            .map_err(|e| js_error("invalid_own_transport", e.to_string()))?;
        Ok(())
    }

    /// Unified entry point for initiating any protocol flow.
    ///
    /// # Arguments
    ///
    /// * `flow_kind` — `FlowKind` discriminant: `0` Pairing, `1` Discovery,
    ///   `2` ProtectSecret, `3` VerifyShares, `4` RecoverSecret, `5` Unpair,
    ///   `6` UpdateChannelInfo, `7` ReplicaDiscovery, `8` UnpairReplica.
    /// * `params` — the flow's parameters, declared per kind in `index.d.ts`
    ///   as `PairingParams`, `DiscoveryParams`, … `UnpairReplicaParams`.
    ///
    /// # Returns
    ///
    /// An `Array` of `*Started` / `*Failed` events describing the
    /// dispatched requests. Same shape as `process()`.
    #[wasm_bindgen(js_name = "start")]
    pub async fn start(&self, flow_kind: u32, params: JsValue) -> Result<JsValue, JsValue> {
        let flow = parse_flow(flow_kind, params)?;
        let rust_events = self
            .inner
            .lock()
            .await
            .start(flow)
            .await
            .map_err(js_error_from_lib)?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }

    /// Derive the human-readable fingerprint for a paired channel. Both
    /// sides of a replica pair derive the same fingerprint from the
    /// shared key, enabling out-of-band confirmation before the channel
    /// transitions from `Pending` to `Paired`.
    #[wasm_bindgen(js_name = "getFingerprint")]
    pub async fn get_fingerprint(&self, channel_id: JsValue) -> Result<String, JsValue> {
        let id = js_value_to_u64(channel_id)?;
        self.inner
            .lock()
            .await
            .get_fingerprint(ChannelId(id))
            .await
            .map_err(js_error_from_lib)
    }

    /// Verify a fingerprint against the channel's locally-derived one. On
    /// match, the channel transitions from `Pending` to `Paired`. Returns
    /// `true` when the fingerprint matches and the channel is confirmed,
    /// `false` otherwise.
    #[wasm_bindgen(js_name = "verifyFingerprint")]
    pub async fn verify_fingerprint(
        &self,
        channel_id: JsValue,
        fingerprint: String,
    ) -> Result<bool, JsValue> {
        let id = js_value_to_u64(channel_id)?;
        self.inner
            .lock()
            .await
            .verify_fingerprint(ChannelId(id), &fingerprint)
            .await
            .map_err(js_error_from_lib)
    }

    /// Remove `Pending` channels older than `older_than_secs`, along with
    /// their pairing keys.
    ///
    /// Independent of the configured cleanup policy — it sweeps at the
    /// threshold given, even when the policy is disabled. The age
    /// comparison is strict, so a channel created within the current
    /// second survives even `0`.
    ///
    /// # Returns
    ///
    /// An `Array` of removed channel ids as decimal strings.
    ///
    /// `older_than_secs` is a `u64`: a `bigint`, a non-negative safe-integer
    /// `number`, or a decimal string.
    #[wasm_bindgen(js_name = removeExpiredChannels)]
    pub async fn remove_expired_channels(
        &self,
        older_than_secs: JsValue,
    ) -> Result<JsValue, JsValue> {
        let older_than_secs = js_value_to_u64(older_than_secs)?;
        let ids = self
            .inner
            .lock()
            .await
            .remove_expired_channels(older_than_secs)
            .await
            .map_err(js_error_from_lib)?;
        let decimal: Vec<String> = ids.iter().map(|c| c.0.to_string()).collect();
        serde_wasm_bindgen::to_value(&decimal)
            .map_err(|e| js_error("wasm_serialize_error", e.to_string()))
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
    pub async fn accept(&self, action_bytes: &[u8]) -> Result<JsValue, JsValue> {
        let action = pending_action_wire::deserialize(action_bytes)
            .map_err(|e| js_error("decode_error", e))?;
        let rust_events = self
            .inner
            .lock()
            .await
            .accept(action)
            .await
            .map_err(js_error_from_lib)?;
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
        &self,
        action_bytes: &[u8],
        status: i32,
        memo: &str,
    ) -> Result<(), JsValue> {
        let action = pending_action_wire::deserialize(action_bytes)
            .map_err(|e| js_error("decode_error", e))?;
        let status_enum = derec_proto::StatusEnum::try_from(status).map_err(|_| {
            js_error(
                "invalid_status",
                format!("invalid StatusEnum value: {status}"),
            )
        })?;
        self.inner
            .lock()
            .await
            .reject(action, status_enum, memo)
            .await
            .map_err(js_error_from_lib)
    }

    /// Advance time-driven state without an inbound message.
    ///
    /// Timeouts are otherwise only evaluated by `process`, so a publish whose
    /// helpers all go quiet has nothing left to close it. Call this from a
    /// timer — `setInterval`, a service-worker alarm, a job runner — at an
    /// interval shorter than the configured timeout.
    ///
    /// Returns an `Array` of plain JS event objects, empty when nothing was
    /// in flight. Safe to call at any time.
    pub async fn tick(&self) -> Result<JsValue, JsValue> {
        let rust_events = self.inner.lock().await.tick().await;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }

    /// Feed any incoming wire bytes to the protocol.
    ///
    /// Returns an `Array` of plain JS event objects (see struct-level docs for shapes).
    /// Every inbound flow — pairing, sharing, verification, discovery,
    /// recovery, unpairing, channel-info updates and the replica flows — is
    /// handled through this single entry point.
    ///
    /// # Arguments
    ///
    /// * `message` — Raw wire bytes of an incoming `DeRecMessage`.
    pub async fn process(&self, message: &[u8]) -> Result<JsValue, JsValue> {
        let rust_events = self
            .inner
            .lock()
            .await
            .process(message)
            .await
            .map_err(|e| {
                let error = js_error_from_lib(e.source);
                if let Some(channel_id) = e.channel_id {
                    let _ = js_sys::Reflect::set(
                        &error,
                        &JsValue::from_str("channel_id"),
                        &JsValue::from_str(&channel_id.0.to_string()),
                    );
                }
                error
            })?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }

    /// Rebuild this protocol's `secret_id` namespace from a recovered
    /// `Secret`. Mirrors [`crate::protocol::DeRecProtocol::restore`] —
    /// see that method for the full contract.
    ///
    /// `recoveredSecret` is the typed `Secret` object carried by the
    /// `SecretRecovered` event; pass it verbatim. A helper or member whose
    /// `transports` is empty, `null` or absent gets no channel; it is
    /// reported as a `PeerNotRestored` event in the returned array and the
    /// rest of the roster is restored.
    ///
    /// Errors surface as a `DeRecError` (`category`, `code`, `message`):
    ///
    /// | code               | meaning                                                          |
    /// |--------------------|------------------------------------------------------------------|
    /// | `already_restored` | A user-secret snapshot already exists for this `secret_id`.      |
    /// | `restore_conflict` | Channels live at ids restore is about to write. The error        |
    /// |                    | carries `channel_ids: string[]` listing the collisions.          |
    /// | `invariant`        | The recovered `Secret` is internally inconsistent.               |
    /// | `invalid_recovered_secret` | `recoveredSecret` is malformed — e.g. a missing or       |
    /// |                    | non-decimal `channel_id` / `replica_id`.                         |
    /// | `store_error`      | A store call failed mid-restore; `category` names the store.     |
    #[wasm_bindgen(js_name = "restore")]
    pub async fn restore(
        &self,
        recovered_secret: JsValue,
        version: u32,
    ) -> Result<JsValue, JsValue> {
        let secret = parse_recovered_secret(recovered_secret)?;
        let rust_events = self
            .inner
            .lock()
            .await
            .restore(&secret, version)
            .await
            .map_err(js_error_from_lib)?;
        let js_events = Array::new();
        for event in rust_events {
            js_events.push(&events::event_to_js(event)?);
        }
        Ok(js_events.into())
    }
}

fn parse_recovered_secret(value: JsValue) -> Result<crate::protocol::types::Secret, JsValue> {
    serde_wasm_bindgen::from_value::<crate::interop::recovered_secret::RecoveredSecretIn>(value)
        .map_err(|e| js_error("invalid_recovered_secret", e.to_string()))?
        .into_secret()
        .map_err(|e| js_error("invalid_recovered_secret", e))
}

fn parse_optional_channel_id(val: JsValue) -> Result<Option<ChannelId>, JsValue> {
    if val.is_null() || val.is_undefined() {
        return Ok(None);
    }
    Ok(Some(ChannelId(js_value_to_u64(val)?)))
}

/// Convert a JS value to a Rust `u64` without loss.
///
/// Accepts a `bigint`, a `number`, or a decimal string. Strings are the
/// documented wire convention for u64 identifiers on the JS/TS surface (see
/// `packages/{nodejs,web}/index.d.ts`) — they dodge `Number.MAX_SAFE_INTEGER`
/// without forcing every caller to reach for BigInt.
///
/// A `number` must be a non-negative safe integer: a fraction, a negative, a
/// non-finite value, or one above `Number.MAX_SAFE_INTEGER` (which may already
/// have been rounded) is rejected rather than truncated. A `bigint` or string
/// must be in `u64` range, and a string must be plain decimal digits.
fn js_value_to_u64(val: JsValue) -> Result<u64, JsValue> {
    if val.is_bigint() {
        let s = js_sys::BigInt::from(val)
            .to_string(10)
            .map_err(|e| js_error("decode_error", format!("{e:?}")))?
            .as_string()
            .ok_or_else(|| js_error("decode_error", "BigInt.toString returned non-string"))?;
        crate::interop::recovered_secret::parse_decimal_u64(&s, "bigint")
            .map_err(|e| js_error("decode_error", e))
    } else if let Some(s) = val.as_string() {
        crate::interop::recovered_secret::parse_decimal_u64(&s, "string")
            .map_err(|e| js_error("decode_error", e))
    } else if let Some(f) = val.as_f64() {
        exact_u64_from_f64(f).ok_or_else(|| {
            js_error(
                "decode_error",
                format!(
                    "number {f} is not a non-negative safe integer; pass a bigint or decimal string"
                ),
            )
        })
    } else {
        Err(js_error(
            "decode_error",
            "value must be BigInt, number, or decimal string",
        ))
    }
}

/// `Number.MAX_SAFE_INTEGER`: the largest integer every `number` up to which
/// is exactly representable.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

fn exact_u64_from_f64(f: f64) -> Option<u64> {
    (f.is_finite() && f.fract() == 0.0 && (0.0..=MAX_SAFE_INTEGER).contains(&f)).then_some(f as u64)
}

/// Convert a JS `number` to a Rust `u32` without loss: it must be an integer
/// in `0..=u32::MAX`.
fn js_number_to_u32(val: &JsValue, field: &str) -> Result<u32, JsValue> {
    val.as_f64()
        .filter(|f| f.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(f))
        .map(|f| f as u32)
        .ok_or_else(|| {
            js_error(
                "decode_error",
                format!("{field} must be an integer in 0..=4294967295"),
            )
        })
}

fn parse_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        _ => Err(js_error(
            "invalid_sender_kind",
            format!(
                "invalid sender kind: {kind}, valid values are 0 (Owner), 1 (Helper), 3 (ReplicaSource), 4 (ReplicaDestination)"
            ),
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
        "invalid_discovery_target",
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
            .map_err(|e| js_error("decode_error", format!("missing id: {e:?}")))?;
        let name = js_sys::Reflect::get(&entry, &JsValue::from_str("name"))
            .map_err(|e| js_error("decode_error", format!("missing name: {e:?}")))?
            .as_string()
            .ok_or_else(|| js_error("decode_error", "name must be a string"))?;
        let data = js_sys::Reflect::get(&entry, &JsValue::from_str("data"))
            .map_err(|e| js_error("decode_error", format!("missing data: {e:?}")))?;
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
/// - `1` = Discovery: `{ target?: Target }`
/// - `2` = ProtectSecret: `{ secrets: UserSecret[], description?: string }`
/// - `3` = VerifyShares: `{ secretId: u64, version: number, target?: Target }`
/// - `4` = RecoverSecret: `{ secretId: u64, version: number }`
/// - `5` = Unpair: `{ channel_id: u64, memo?: string }`
/// - `6` = UpdateChannelInfo: `{ target?: Target, communication_info?: Record<string, string>, own_transports?: { uri: string, protocol: "https" | "grpc" }[] }`
/// - `7` = ReplicaDiscovery: no params
/// - `8` = UnpairReplica: `{ replica_id: string, memo?: string }`
///
/// `u64` is a `bigint`, a non-negative safe-integer `number`, or a decimal
/// string; `Target` is `null`/absent (every channel), a `bigint`/`number`, or an array
/// of them.
fn parse_flow(flow_kind: u32, params: JsValue) -> Result<DeRecFlow, JsValue> {
    match flow_kind {
        0 => {
            // Pairing
            let kind_val = js_sys::Reflect::get(&params, &JsValue::from_str("kind"))
                .map_err(|e| js_error("decode_error", format!("missing kind: {e:?}")))?;
            let kind = js_number_to_u32(&kind_val, "kind")?;
            let sender_kind = parse_sender_kind(kind)?;
            let contact_val = js_sys::Reflect::get(&params, &JsValue::from_str("contact"))
                .map_err(|e| js_error("decode_error", format!("missing contact: {e:?}")))?;
            let contact: PairingContactMessage = serde_wasm_bindgen::from_value(contact_val)
                .map_err(|e| js_error("decode_error", e.to_string()))?;
            let contact: derec_proto::ContactMessage = contact.into();
            let raw = js_sys::Reflect::get(&params, &JsValue::from_str("peerCommunicationInfo"))
                .unwrap_or(JsValue::UNDEFINED);
            let peer_communication_info: HashMap<String, String> =
                if raw.is_null() || raw.is_undefined() {
                    HashMap::new()
                } else {
                    serde_wasm_bindgen::from_value(raw)
                        .map_err(|e| js_error("invalid_peer_communication_info", e.to_string()))?
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
                .map_err(|e| js_error("decode_error", format!("missing secrets: {e:?}")))?;
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
                .map_err(|e| js_error("decode_error", format!("missing secretId: {e:?}")))?;
            let secret_id = js_value_to_u64(secret_id_val)?;
            let version_val = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("decode_error", format!("missing version: {e:?}")))?;
            let version = js_number_to_u32(&version_val, "version")?;
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
                .map_err(|e| js_error("decode_error", format!("missing secretId: {e:?}")))?;
            let secret_id = js_value_to_u64(secret_id_val)?;
            let version_val = js_sys::Reflect::get(&params, &JsValue::from_str("version"))
                .map_err(|e| js_error("decode_error", format!("missing version: {e:?}")))?;
            let version = js_number_to_u32(&version_val, "version")?;
            Ok(DeRecFlow::RecoverSecret { secret_id, version })
        }
        5 => {
            // Unpair
            let channel_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("channel_id"))
                .map_err(|e| js_error("decode_error", format!("missing channel_id: {e:?}")))?;
            let channel_id = ChannelId(js_value_to_u64(channel_id_val)?);
            let memo = js_sys::Reflect::get(&params, &JsValue::from_str("memo"))
                .unwrap_or(JsValue::UNDEFINED)
                .as_string();
            Ok(DeRecFlow::Unpair { channel_id, memo })
        }
        6 => {
            // UpdateChannelInfo
            //
            // Wire-shape mirrors the dotnet `UpdateChannelInfoParams`:
            // `{ target, communication_info?, own_transports?: { uri, protocol: "https" | "grpc" }[] }`.
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
                        serde_wasm_bindgen::from_value(communication_info_val)
                            .map_err(|e| js_error("invalid_communication_info", e.to_string()))?,
                    )
                };
            #[derive(serde::Deserialize)]
            struct TransportShape {
                uri: String,
                #[serde(deserialize_with = "crate::interop::protocol_names::protocol_from_name")]
                protocol: i32,
            }
            let read_one = |v: JsValue| -> Result<TransportProtocol, JsValue> {
                let parsed: TransportShape = serde_wasm_bindgen::from_value(v)
                    .map_err(|e| js_error("invalid_transport_protocol", e.to_string()))?;
                Ok(TransportProtocol {
                    uri: parsed.uri,
                    protocol: parsed.protocol,
                })
            };

            let own_transports_val =
                js_sys::Reflect::get(&params, &JsValue::from_str("own_transports"))
                    .unwrap_or(JsValue::UNDEFINED);
            let own_transports =
                if own_transports_val.is_null() || own_transports_val.is_undefined() {
                    Vec::new()
                } else {
                    let array = js_sys::Array::from(&own_transports_val);
                    let mut out = Vec::with_capacity(array.length() as usize);
                    for entry in array.iter() {
                        out.push(read_one(entry)?);
                    }
                    out
                };
            Ok(DeRecFlow::UpdateChannelInfo {
                target,
                communication_info,
                own_transports,
            })
        }
        8 => {
            // UnpairReplica: `{ replica_id, memo? }`. `replica_id` is a
            // decimal string so large values survive JS number handling.
            let replica_id_val = js_sys::Reflect::get(&params, &JsValue::from_str("replica_id"))
                .unwrap_or(JsValue::UNDEFINED);
            // A decimal string, so ids above 2^53 survive JS number handling.
            let replica_id: u64 = replica_id_val
                .as_string()
                .ok_or_else(|| {
                    js_error(
                        "invalid_flow_params",
                        "replica_id must be a decimal string".to_owned(),
                    )
                })?
                .parse::<u64>()
                .map_err(|e| {
                    js_error(
                        "invalid_flow_params",
                        format!("replica_id must be a decimal u64: {e}"),
                    )
                })?;
            let memo_val = js_sys::Reflect::get(&params, &JsValue::from_str("memo"))
                .unwrap_or(JsValue::UNDEFINED);
            let memo = if memo_val.is_null() || memo_val.is_undefined() {
                None
            } else {
                memo_val.as_string()
            };
            Ok(DeRecFlow::UnpairReplica { replica_id, memo })
        }
        7 => {
            // ReplicaDiscovery takes no parameters: the group and this device's own
            // version are both read from the stores.
            Ok(DeRecFlow::ReplicaDiscovery)
        }
        _ => Err(js_error(
            "invalid_flow_kind",
            format!("invalid flow kind: {flow_kind}, must be 0..8"),
        )),
    }
}
