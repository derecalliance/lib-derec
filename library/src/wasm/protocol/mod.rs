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
//!   if (ev.type === "PairingComplete") { ... }
//! }
//! ```
//!
//! See each method's documentation for full details on event shapes and JS
//! interface contracts.

mod events;
mod stores;

use crate::{
    primitives::channels_discovery::response::ChannelEntry,
    protocol::DeRecProtocol,
    types::{ChannelId, Secret},
    wasm::ts_bindings_utils::js_error,
};
use crate::wasm::primitives::pairing::{contact_message_to_js, js_to_contact_message};
use derec_proto::{SenderKind, TransportProtocol};
use js_sys::Array;
use stores::{JsContactStore, JsSecretStore, JsShareStore, JsTransport};
use wasm_bindgen::prelude::*;

type WasmProtocol = DeRecProtocol<JsContactStore, JsShareStore, JsSecretStore, JsTransport>;

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
/// | `PairingComplete`  | `channel_id: string`, `kind: number`                   |
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
    /// * `contact_store` — JS object with `load(channelId: string): Promise<Uint8Array|null>` and
    ///   `save(channelId: string, bytes: Uint8Array): Promise<void>`.
    ///   The bytes are raw protobuf-encoded `ContactMessage`s.
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
    #[wasm_bindgen(constructor)]
    pub fn new(
        contact_store: JsValue,
        share_store: JsValue,
        secret_store: JsValue,
        transport: JsValue,
        own_transport_uri: String,
        own_transport_protocol: String,
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
        let inner = DeRecProtocol::new(
            JsContactStore(contact_store),
            JsShareStore(share_store),
            JsSecretStore(secret_store),
            JsTransport(transport),
            own_transport,
        );
        Ok(DeRecProtocolWasm { inner })
    }

    /// Generate an out-of-band contact message (QR code payload, deep link, …).
    ///
    /// Returns a plain JS `ContactMessage` object. The `channel_id` field identifies
    /// the pairing session and will match the `channel_id` in the eventual
    /// `PairingComplete` event — read it directly from the returned object.
    ///
    /// The caller is responsible for serializing the contact for out-of-band
    /// delivery (QR code, deep link, etc.). The peer passes the deserialized object
    /// to [`startPairing`](Self::start_pairing).
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

    /// Begin pairing after receiving a peer's contact out-of-band.
    ///
    /// Accepts the plain JS `ContactMessage` object returned by
    /// [`createContact`](Self::create_contact) on the peer side (deserialized
    /// by the caller from whatever out-of-band format was used — QR, deep link, etc.).
    ///
    /// Sends a `PairRequestMessage` to the peer and returns the `channel_id`
    /// extracted from the contact. Store it to correlate the eventual
    /// [`PairingComplete`] event with the correct peer.
    ///
    /// # Arguments
    ///
    /// * `kind`    — Sender role: `0` = OwnerNonRecovery, `1` = OwnerRecovery, `2` = Helper.
    /// * `contact` — Plain JS `ContactMessage` object as returned by `createContact`.
    ///
    /// # Returns
    ///
    /// A `BigInt` representing the `channel_id` from the contact message.
    ///
    /// TODO: document the full pairing lifecycle and how to use the returned
    /// `channel_id` to track pending pairings in application state.
    #[wasm_bindgen(js_name = "startPairing")]
    pub async fn start_pairing(
        &mut self,
        kind: u32,
        contact: JsValue,
    ) -> Result<js_sys::BigInt, JsValue> {
        let contact = js_to_contact_message(contact)?;
        let sender_kind = parse_sender_kind(kind)?;
        let channel_id = self
            .inner
            .start_pairing(sender_kind, contact)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        Ok(js_sys::BigInt::from(channel_id))
    }

    /// Send a discovery request to the Helper on `channel_id`.
    ///
    /// Call this after receiving a `PairingComplete { kind: 1 }` (OwnerRecovery) event
    /// and completing any required out-of-band authentication with the Helper.
    ///
    /// The Helper responds with the list of all secrets it holds for this channel.
    /// [`process`](Self::process) emits a `SecretsDiscovered` event when the response arrives.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — BigInt channel identifier from the `PairingComplete` event.
    #[wasm_bindgen(js_name = "requestDiscovery")]
    pub async fn request_discovery(&mut self, channel_id: u64) -> Result<(), JsValue> {
        self.inner
            .request_discovery(ChannelId(channel_id))
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Start the replica confirmation flow by sending a fingerprint to the peer.
    ///
    /// Returns a `Uint8Array` containing the 16-digit fingerprint (each byte 0–9)
    /// for the application to display to the user.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — BigInt channel identifier from the `PairingComplete` event.
    /// * `replica_id` — Caller's replica identifier.
    #[wasm_bindgen(js_name = "startReplicaConfirmation")]
    pub async fn start_replica_confirmation(
        &mut self,
        channel_id: u64,
        replica_id: i32,
    ) -> Result<Vec<u8>, JsValue> {
        let fingerprint = self
            .inner
            .start_replica_confirmation(ChannelId(channel_id), replica_id)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
        Ok(fingerprint.to_vec())
    }

    /// Confirm a Replica channel after the user verified the fingerprint.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — BigInt channel identifier.
    /// * `replica_id` — Responder's replica identifier.
    #[wasm_bindgen(js_name = "confirmReplica")]
    pub async fn confirm_replica(
        &mut self,
        channel_id: u64,
        replica_id: i32,
    ) -> Result<(), JsValue> {
        self.inner
            .confirm_replica(ChannelId(channel_id), replica_id)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Request channels discovery from the Owner on the given Replica channel.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — BigInt channel identifier.
    /// * `last_batch_index` — Index of the last batch received (0 for initial request).
    #[wasm_bindgen(js_name = "requestChannelsDiscovery")]
    pub async fn request_channels_discovery(
        &mut self,
        channel_id: u64,
        last_batch_index: i32,
    ) -> Result<(), JsValue> {
        self.inner
            .request_channels_discovery(ChannelId(channel_id), last_batch_index)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Respond to a channels discovery request from a Replica.
    ///
    /// # Arguments
    ///
    /// * `channel_id` — BigInt channel identifier of the Replica channel.
    /// * `entries` — JS array of `{ channel_id: number, shared_key: Uint8Array }` objects.
    /// * `total_batches` — Total number of batches.
    /// * `current_batch` — 1-based index of this batch.
    #[wasm_bindgen(js_name = "respondChannelsDiscovery")]
    pub async fn respond_channels_discovery(
        &mut self,
        channel_id: u64,
        entries: JsValue,
        total_batches: i32,
        current_batch: i32,
    ) -> Result<(), JsValue> {
        #[derive(serde::Deserialize)]
        struct ChannelEntryJs {
            channel_id: u64,
            shared_key: Vec<u8>,
        }

        let entries_js: Vec<ChannelEntryJs> = serde_wasm_bindgen::from_value(entries)
            .map_err(|e| js_error("WASM_DESERIALIZE_ERROR", e.to_string()))?;

        let channel_entries: Vec<ChannelEntry> = entries_js
            .into_iter()
            .map(|e| {
                let key: [u8; 32] = e.shared_key.as_slice().try_into().map_err(|_| {
                    js_error(
                        "INVALID_SHARED_KEY_LENGTH",
                        "each entry shared_key must be exactly 32 bytes".to_string(),
                    )
                })?;
                Ok(ChannelEntry {
                    channel_id: ChannelId(e.channel_id),
                    shared_key: key,
                })
            })
            .collect::<Result<Vec<_>, JsValue>>()?;

        self.inner
            .respond_channels_discovery(
                ChannelId(channel_id),
                &channel_entries,
                total_batches,
                current_batch,
            )
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Split a secret and send one share to each of the specified Helpers.
    ///
    /// # Arguments
    ///
    /// * `secret_id` — Application-defined identifier for the secret.
    /// * `secret_data` — Raw secret bytes to protect.
    /// * `description` — Human-readable label (shown to the Owner during recovery).
    /// * `version` — Monotonically increasing version number.
    /// * `threshold` — Minimum number of shares required for reconstruction.
    /// * `helpers` — `BigInt[]` of channel IDs that should receive a share.
    /// * `keep_list` — `number[]` of version numbers the Helper must retain. Pass `[]`
    ///   to apply the default retention policy.
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(js_name = "protectSecret")]
    pub async fn protect_secret(
        &mut self,
        secret_id: &[u8],
        secret_data: &[u8],
        description: String,
        version: i32,
        threshold: u32,
        helpers: JsValue,
        keep_list: JsValue,
    ) -> Result<(), JsValue> {
        let helper_ids = parse_u64_array(helpers)?;
        let keep_versions = parse_i32_array(keep_list)?;
        let secret = Secret {
            id: secret_id.to_vec(),
            version,
            data: secret_data.to_vec(),
            description,
        };
        self.inner
            .protect_secret(secret, threshold as usize, &helper_ids, &keep_versions)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Send verification challenges to all Helpers that hold a share for `(secret_id, version)`.
    ///
    /// # Arguments
    ///
    /// * `secret_id` — Application-defined secret identifier.
    /// * `version` — Version to verify.
    #[wasm_bindgen(js_name = "verifyShares")]
    pub async fn verify_shares(&mut self, secret_id: &[u8], version: i32) -> Result<(), JsValue> {
        self.inner
            .verify_shares(secret_id, version)
            .await
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))
    }

    /// Request shares from Helpers to recover a secret.
    ///
    /// Call this after `SecretsDiscovered` events have been collected from enough
    /// Helpers and the desired `(secret_id, version)` has been identified.
    ///
    /// [`process`](Self::process) emits `SecretRecovered` once a threshold of
    /// share responses arrive and reconstruction succeeds.
    ///
    /// # Arguments
    ///
    /// * `secret_id` — Application-defined secret identifier.
    /// * `version` — Version to recover.
    /// * `helpers` — `BigInt[]` of channel IDs that hold a share for this secret.
    #[wasm_bindgen(js_name = "recoverSecret")]
    pub async fn recover_secret(
        &mut self,
        secret_id: &[u8],
        version: i32,
        helpers: JsValue,
    ) -> Result<(), JsValue> {
        let helper_ids = parse_u64_array(helpers)?;
        self.inner
            .recover_secret(secret_id.to_vec(), version, &helper_ids)
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
            .map_err(|e| js_error("DEREC_ERROR", e.to_string()))?;
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

fn parse_u64_array(val: JsValue) -> Result<Vec<ChannelId>, JsValue> {
    let arr = Array::from(&val);
    let mut result = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        result.push(ChannelId(js_value_to_u64(arr.get(i))?));
    }
    Ok(result)
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

fn parse_i32_array(val: JsValue) -> Result<Vec<i32>, JsValue> {
    let arr = Array::from(&val);
    let mut result = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        let v = arr
            .get(i)
            .as_f64()
            .ok_or_else(|| js_error("DECODE_ERROR", "version must be a number"))?;
        result.push(v as i32);
    }
    Ok(result)
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
