// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! JS-side adapters for the protocol's store and transport traits.
//!
//! Each adapter holds a `JsValue` pointing to a JS object that implements the
//! corresponding interface.  Trait methods call into JS via `js_sys::Reflect`,
//! await the returned `Promise`, and convert the result back to a Rust type.
//!
//! ## JS interface contracts
//!
//! Every `u64` (`secretId`, `channelId`, `replicaId`) crosses as a decimal
//! string, because a JS number cannot hold one exactly. Every method returns a
//! `Promise`; a rejection or a throw is a backend failure unless stated
//! otherwise. These are the interfaces the adapters below call, and the ones
//! `packages/nodejs/index.d.ts`, `packages/web/index.d.ts` and
//! `packages/react-native/src/types.ts` declare.
//!
//! ### `SecretStore`
//! ```ts
//! // kind 0 = SharedKey (32 raw bytes), 1 = PairingSecret (serialized key
//! // material), 2 = PairingContact (protobuf ContactMessage).
//! type SecretKind = 0 | 1 | 2;
//! interface SecretStore {
//!   load(secretId: string, channelId: string, kind: SecretKind): Promise<Uint8Array | null | undefined>;
//!   // Exactly one entry per id in `channelIds`, in order; `null` or
//!   // `undefined` where nothing of `kind` is stored.
//!   loadMany(secretId: string, channelIds: string[], kind: SecretKind): Promise<Array<Uint8Array | null | undefined>>;
//!   save(secretId: string, channelId: string, kind: SecretKind, value: Uint8Array): Promise<void>;
//!   remove(secretId: string, channelId: string, kind: SecretKind): Promise<void>;
//!   // `remove` for each `[channelId, kind]` entry; an entry with nothing
//!   // stored is skipped.
//!   removeMany(secretId: string, entries: [channelId: string, kind: SecretKind][]): Promise<void>;
//! }
//! ```
//!
//! ### `ChannelStore`
//! ```ts
//! type ChannelStatusName = "Pending" | "Paired" | "Unpairing";
//! type SenderKindName = "Owner" | "Helper" | "ReplicaSource" | "ReplicaDestination";
//! type ReplicaRoleName = "Source" | "Destination";
//! // Every empty field selects everything; `exclude` applies after `ids`.
//! interface ChannelFilter<Role> { ids: string[]; status: ChannelStatusName[]; role: Role | null; exclude: string[] }
//! interface ChannelStore {
//!   // A record is addressed by `(channelId, replicaId)`: `replicaId` "0" is
//!   // the helper channel at `channelId`, any other value that replica-group
//!   // member, keyed by `replicaId` alone. Bytes are a JSON `ChannelRecord`.
//!   load(secretId: string, channelId: string, replicaId: string): Promise<Uint8Array | null | undefined>;
//!   save(secretId: string, channelId: string, replicaId: string, bytes: Uint8Array): Promise<void>;
//!   // Whether a record was removed.
//!   remove(secretId: string, channelId: string, replicaId: string): Promise<boolean>;
//!   // `remove` for each `[channelId, replicaId]` entry; an entry that names
//!   // no record is skipped.
//!   removeMany(secretId: string, queries: [channelId: string, replicaId: string][]): Promise<void>;
//!   // JSON arrays of `HelperChannel` / `ReplicaMember` records the filter
//!   // selects; `null`, `undefined` or an empty buffer is an empty list.
//!   // The `listReplicas` order picks the successor when the source leaves.
//!   listHelpers(secretId: string, filter: ChannelFilter<SenderKindName>): Promise<Uint8Array | null | undefined>;
//!   listReplicas(secretId: string, filter: ChannelFilter<ReplicaRoleName>): Promise<Uint8Array | null | undefined>;
//!   // Undirected and idempotent.
//!   linkChannel(secretId: string, a: string, b: string): Promise<void>;
//!   // The transitive closure of `channelId`, including `channelId` itself.
//!   linkedChannels(secretId: string, channelId: string): Promise<string[]>;
//! }
//! ```
//!
//! ### `ShareStore`
//! ```ts
//! // `secretId` on a share names the secret the bytes belong to; on a helper
//! // it is the owner's id and differs from the `secretId` partition every
//! // method takes. Key rows on the argument. `subshares` is the owner-side
//! // subshare count and `threshold` the owner-side threshold the version was
//! // split with; store and return them as given. Each is absent on a
//! // helper's share and on owner rows written before it existed.
//! interface Share { secretId: string; version: number; bytes: Uint8Array; subshares?: number | null; threshold?: number | null }
//! interface ShareStore {
//!   // For `load` and `loadMany`, an empty `versions` selects every version.
//!   load(secretId: string, channelId: string, versions: number[]): Promise<Share[]>;
//!   // Each share paired with the channel it is stored under.
//!   loadMany(secretId: string, channelIds: string[], versions: number[]): Promise<[channelId: string, share: Share][]>;
//!   // Discovery: every version of every share on these channels.
//!   loadAll(secretId: string, channelIds: string[]): Promise<Share[]>;
//!   // The highest version stored under `secretId`, or `null` when none is.
//!   latestVersion(secretId: string): Promise<number | null>;
//!   // May reject or throw a `shareStoreRefusal(reason)` `Error` to refuse a
//!   // share update on a helper channel.
//!   save(secretId: string, channelId: string, share: Share): Promise<void>;
//!   // Drop every share stored under `(secretId, channelId)`; a channel with
//!   // nothing stored is a no-op.
//!   removeChannel(secretId: string, channelId: string): Promise<void>;
//!   // Drop the shares stored under `(secretId, channelId)` at each listed
//!   // version. A version that is not stored is skipped.
//!   removeVersions(secretId: string, channelId: string, versions: number[]): Promise<void>;
//!   // `removeVersions` for each `[channelId, versions]` entry, in one call.
//!   removeVersionsMany(secretId: string, entries: [channelId: string, versions: number[]][]): Promise<void>;
//!   // Owner only: the one version, other than `version`, every Helper keeps
//!   // after `version` is distributed: the last version that met threshold.
//!   // `0` keeps no other version. Must be below `version`.
//!   keepVersion(secretId: string, version: number): Promise<number>;
//!   // Called once per accepted verification challenge on a helper channel.
//!   // Reject or throw a `shareStoreRefusal(reason)` `Error` to refuse the
//!   // verification; any other rejection or throw is a backend failure.
//!   recordVerification(secretId: string, channelId: string, version: number): Promise<void>;
//! }
//! ```
//!
//! ### `UserSecretStore`
//! ```ts
//! interface UserSecrets {
//!   version: number;
//!   secrets: { id: Uint8Array; name: string; data: Uint8Array }[];
//!   description?: string;
//!   // Decimal id of the member that published `version`; store and return
//!   // it unchanged.
//!   author_replica_id?: string;
//!   // The recorded threshold; store and return it as given.
//!   threshold?: number | null;
//! }
//! interface UserSecretStore {
//!   loadLatest(secretId: string): Promise<UserSecrets | null | undefined>;
//!   saveLatest(secretId: string, value: UserSecrets): Promise<void>;
//!   remove(secretId: string): Promise<void>;
//! }
//! ```
//!
//! ### `StateStore`
//! ```ts
//! // kind 0 = PendingVerification, 1 = PendingRecovery, 2 = PendingUnpair,
//! // 3 = SharingRound, 4 = PendingReplicaDiscovery.
//! type StateKind = 0 | 1 | 2 | 3 | 4;
//! interface StateStore {
//!   // Buffers are JSON `StateItemRecord` / `StateKeyRecord`; store an item
//!   // under its key and return the exact bytes received.
//!   save(secretId: string, itemJson: Uint8Array): Promise<void>;
//!   load(secretId: string, keyJson: Uint8Array): Promise<Uint8Array | null | undefined>;
//!   // Whether a row was removed.
//!   remove(secretId: string, keyJson: Uint8Array): Promise<boolean>;
//!   // `keysJson` is a JSON array of the keys `remove` takes; a key with no
//!   // row is skipped.
//!   removeMany(secretId: string, keysJson: Uint8Array): Promise<void>;
//!   loadAll(secretId: string, kind: StateKind): Promise<Uint8Array[]>;
//! }
//! ```
//!
//! ### `Transport`
//! ```ts
//! interface Endpoint { uri: string; protocol: "https" | "grpc" }
//! interface Transport {
//!   // The peer's whole endpoint set, in its order; which to dial is the
//!   // implementation's choice.
//!   send(endpoints: ReadonlyArray<Endpoint>, message: Uint8Array): Promise<void>;
//! }
//! ```

use derec_proto::{ContactMessage, TransportProtocol};
use js_sys::{Array, Function, Promise, Uint8Array};
use prost::Message as _;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use crate::{
    Error,
    protocol::{
        error::{ChannelStoreError, Refusal, SecretStoreError, ShareStoreError, StateStoreError},
        traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecStateStore, DeRecTransport, DeRecUserSecretStore, SecretStoreFuture,
            ShareStoreFuture, StateStoreFuture, TransportFuture,
        },
        types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy,
            PairingKeyMaterial, ReplicaFilter, ReplicaMember, SecretKind, SecretValue, Share,
            StateItem, StateKey, StateKind, UserSecret, UserSecrets,
        },
    },
    types::ChannelId,
};

/// A simple string-backed error for wrapping JS call failures.
#[derive(Debug)]
struct JsCallError(String);

impl std::fmt::Display for JsCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for JsCallError {}

fn box_err(msg: String) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    Box::new(JsCallError(msg))
}

fn call_method(obj: &JsValue, method: &str, args: &Array) -> Result<JsValue, String> {
    let func_val = js_sys::Reflect::get(obj, &JsValue::from_str(method))
        .map_err(|e| format!("failed to get method '{method}': {e:?}"))?;
    let func = Function::from(func_val);
    func.apply(obj, args)
        .map_err(|e| format!("failed to call method '{method}': {e:?}"))
}

async fn resolve_promise(val: JsValue) -> Result<JsValue, String> {
    JsFuture::from(Promise::from(val))
        .await
        .map_err(|e| format!("promise rejected: {e:?}"))
}

/// Same as [`call_method`], but keeps the thrown value instead of
/// stringifying it, so a caller can read a `refusal` property off it.
fn call_method_value(obj: &JsValue, method: &str, args: &Array) -> Result<JsValue, JsValue> {
    let func_val = js_sys::Reflect::get(obj, &JsValue::from_str(method))?;
    Function::from(func_val).apply(obj, args)
}

/// Same as [`resolve_promise`], but keeps the rejection value instead of
/// stringifying it, so a caller can read a `refusal` property off it.
async fn resolve_promise_value(val: JsValue) -> Result<JsValue, JsValue> {
    JsFuture::from(Promise::from(val)).await
}

/// Reads the `refusal` property a JS `ShareStore` tags its thrown/rejected
/// value with — see [`crate::interop::wasm::ts_bindings_utils::share_store_refusal`]
/// — and maps its wire string to a [`Refusal`]. `None` for any other shape,
/// which callers treat as an ordinary backend failure.
fn refusal_from_js(value: &JsValue) -> Option<Refusal> {
    js_sys::Reflect::get(value, &JsValue::from_str("refusal"))
        .ok()
        .and_then(|v| v.as_string())
        .and_then(|reason| refusal_from_reason(&reason))
}

/// The wire-string-to-[`Refusal`] mapping [`refusal_from_js`] applies, pulled
/// out as a pure function so it can be unit tested independently of
/// `JsValue`.
fn refusal_from_reason(reason: &str) -> Option<Refusal> {
    match reason {
        "too_frequent" => Some(Refusal::TooFrequent),
        "size_limit_exceeded" => Some(Refusal::SizeLimitExceeded),
        "rejected" => Some(Refusal::Rejected),
        _ => None,
    }
}

/// Maps a failed `save`/`recordVerification` call's thrown or rejected
/// `JsValue` to a [`ShareStoreError`]: a recognised `refusal` tag becomes
/// [`ShareStoreError::Refused`], anything else an ordinary
/// [`ShareStoreError::Backend`].
fn share_store_call_error(method: &str, value: &JsValue) -> ShareStoreError {
    match refusal_from_js(value) {
        Some(refusal) => ShareStoreError::Refused(refusal),
        None => {
            ShareStoreError::Backend(box_err(format!("share store {method} failed: {value:?}")))
        }
    }
}

fn decode_secret_value(kind: SecretKind, bytes: &[u8]) -> Result<SecretValue, SecretStoreError> {
    match kind {
        SecretKind::SharedKey => {
            if bytes.len() != 32 {
                return Err(SecretStoreError::Backend(box_err(format!(
                    "shared key must be 32 bytes, got {}",
                    bytes.len()
                ))));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(bytes);
            Ok(SecretValue::SharedKey(key))
        }
        SecretKind::PairingSecret => Ok(SecretValue::PairingSecret(
            PairingKeyMaterial::from_bytes(bytes.to_vec()),
        )),
        SecretKind::PairingContact => {
            let contact = ContactMessage::decode(bytes)
                .map_err(|e| SecretStoreError::Backend(box_err(e.to_string())))?;
            Ok(SecretValue::PairingContact(contact))
        }
    }
}

/// Adapter wrapping a JS `SecretStore` object.
pub struct JsSecretStore(pub JsValue);

impl DeRecSecretStore for JsSecretStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        let kind_num = kind as u32;
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_f64(kind_num as f64));
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            let bytes = Uint8Array::new(&value).to_vec();
            Ok(Some(decode_secret_value(kind, &bytes)?))
        })
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let ids_vec: Vec<String> = channel_ids.iter().map(|c| c.0.to_string()).collect();
        let requested = channel_ids.to_vec();
        let kind_num = kind as u32;
        Box::pin(async move {
            let js_ids = Array::new();
            for id in &ids_vec {
                js_ids.push(&JsValue::from_str(id));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_ids);
            args.push(&JsValue::from_f64(kind_num as f64));
            let promise_val = call_method(&obj, "loadMany", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            let entries: Vec<Option<Vec<u8>>> = Array::from(&value)
                .iter()
                .map(|raw| {
                    (!raw.is_null() && !raw.is_undefined()).then(|| Uint8Array::new(&raw).to_vec())
                })
                .collect();
            crate::interop::secret_batch::collect(
                &requested,
                entries,
                kind,
                missing_policy,
                |bytes| decode_secret_value(kind, &bytes),
            )
        })
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let (kind_num, bytes) = match &value {
                SecretValue::SharedKey(key) => (0u32, key.to_vec()),
                SecretValue::PairingSecret(material) => (1u32, material.as_bytes().to_vec()),
                SecretValue::PairingContact(contact) => (2u32, contact.encode_to_vec()),
            };
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_f64(kind_num as f64));
            args.push(&js_bytes);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        let kind_num = kind as u32;
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_f64(kind_num as f64));
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove_many(
        &mut self,
        secret_id: u64,
        entries: &[(ChannelId, SecretKind)],
    ) -> SecretStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let pairs = Array::new();
        for &(channel_id, kind) in entries {
            let pair = Array::new();
            pair.push(&JsValue::from_str(&channel_id.0.to_string()));
            pair.push(&JsValue::from_f64(kind as u32 as f64));
            pairs.push(&pair);
        }
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&pairs);
            let promise_val = call_method(&obj, "removeMany", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }
}

/// Adapter wrapping a JS `ChannelStore` object; the JS interface is
/// `ChannelStore` in the module docs.
///
/// A record is addressed by `(channelId, replicaId)`. A `replicaId` of `"0"` —
/// the value [`crate::types::ReplicaId`] reserves as "absent" — addresses the
/// helper channel at `channelId`.
///
/// Any other value addresses that member of the replica group, and the member
/// is keyed by **`replicaId` alone**. The accompanying `channelId` is context,
/// not part of the key: a member moves between channels during an admission
/// handover while remaining the same member, and a lookup that required both
/// to match would miss it exactly when the move needs to be observed. Backends
/// therefore keep two maps — helpers by `channelId`, members by `replicaId` —
/// not one keyed by the pair.
///
/// `load`/`save` bytes are a JSON-encoded [`ChannelRecord`]. `listHelpers` and
/// `listReplicas` return a JSON array of [`HelperChannel`] and
/// [`ReplicaMember`] respectively. `linkedChannels` returns the transitive
/// closure of `channelId` (including `channelId` itself).
///
/// The order `listReplicas` returns is significant in exactly one situation —
/// it selects the successor when the group's source is removed. See
/// [`crate::protocol::DeRecChannelStore::replicas`] for the full contract.
pub struct JsChannelStore(pub JsValue);

/// Flatten a query into the `(channelId, replicaId)` string pair the JS
/// interface takes. `replicaId == "0"` addresses the helper channel.
fn query_key(query: ChannelQuery) -> (String, String) {
    match query {
        ChannelQuery::Helper { channel_id } => (channel_id.0.to_string(), "0".to_owned()),
        ChannelQuery::Replica {
            channel_id,
            replica_id,
        } => (channel_id.0.to_string(), replica_id.0.to_string()),
    }
}

/// The address a record is stored at, derived from the record itself so a
/// caller cannot save one under the wrong key.
fn record_key(record: &ChannelRecord) -> (String, String) {
    match record {
        ChannelRecord::Helper(h) => (h.channel_id.0.to_string(), "0".to_owned()),
        ChannelRecord::Replica(r) => (r.channel_id.0.to_string(), r.replica_id.0.to_string()),
    }
}

/// Call a listing method and decode its JSON array. A `null`/`undefined` or
/// empty buffer is an empty list, not an error.
/// A listing filter, as the plain JS object the store method receives:
/// `{ ids, status, role, exclude }`.
///
/// Ids cross as **decimal strings**, matching every other `u64` on this
/// bridge — a JS number cannot hold one exactly. Statuses and the role cross
/// as their Rust variant names, matching the records the same store returns.
fn encode_filter<Role: serde::Serialize>(
    ids: &[u64],
    status: &[crate::protocol::types::ChannelStatus],
    role: Option<&Role>,
    exclude: &[u64],
) -> Result<JsValue, ChannelStoreError> {
    let obj = js_sys::Object::new();
    let set = |key: &str, value: &JsValue| -> Result<(), ChannelStoreError> {
        js_sys::Reflect::set(&obj, &JsValue::from_str(key), value)
            .map(|_| ())
            .map_err(|e| ChannelStoreError::Backend(box_err(format!("{e:?}"))))
    };

    let id_array = |values: &[u64]| {
        let arr = Array::new();
        for v in values {
            arr.push(&JsValue::from_str(&v.to_string()));
        }
        arr
    };
    set("ids", &id_array(ids))?;
    set("exclude", &id_array(exclude))?;

    let status_array = Array::new();
    for s in status {
        let encoded = serde_wasm_bindgen::to_value(s)
            .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
        status_array.push(&encoded);
    }
    set("status", &status_array)?;

    let role = match role {
        Some(r) => serde_wasm_bindgen::to_value(r)
            .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?,
        None => JsValue::NULL,
    };
    set("role", &role)?;

    Ok(obj.into())
}

async fn list_records<T: serde::de::DeserializeOwned>(
    obj: &JsValue,
    method: &str,
    secret_str: &str,
    filter: JsValue,
) -> Result<Vec<T>, ChannelStoreError> {
    let args = Array::new();
    args.push(&JsValue::from_str(secret_str));
    args.push(&filter);
    let promise_val =
        call_method(obj, method, &args).map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
    let value = resolve_promise(promise_val)
        .await
        .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
    if value.is_null() || value.is_undefined() {
        return Ok(Vec::new());
    }
    let bytes = Uint8Array::new(&value).to_vec();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&bytes).map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))
}

impl DeRecChannelStore for JsChannelStore {
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let (channel_str, replica_str) = query_key(query);
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_str(&replica_str));
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            let bytes = Uint8Array::new(&value).to_vec();
            if bytes.is_empty() {
                return Ok(None);
            }
            let record: ChannelRecord = serde_json::from_slice(&bytes)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            Ok(Some(record))
        })
    }

    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let (channel_str, replica_str) = record_key(&record);
        Box::pin(async move {
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_str(&replica_str));
            args.push(&js_bytes);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let (channel_str, replica_str) = query_key(query);
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_str(&replica_str));
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            value.as_bool().ok_or_else(|| {
                ChannelStoreError::Backend(box_err("remove must return a boolean".to_string()))
            })
        })
    }

    fn remove_many(
        &mut self,
        secret_id: u64,
        queries: &[ChannelQuery],
    ) -> ChannelStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let pairs = Array::new();
        for query in queries {
            let (channel_str, replica_str) = query_key(*query);
            let pair = Array::new();
            pair.push(&JsValue::from_str(&channel_str));
            pair.push(&JsValue::from_str(&replica_str));
            pairs.push(&pair);
        }
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&pairs);
            let promise_val = call_method(&obj, "removeMany", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn helpers(
        &self,
        secret_id: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let ids: Vec<u64> = filter.ids.iter().map(|c| c.0).collect();
            let exclude: Vec<u64> = filter.exclude.iter().map(|c| c.0).collect();
            let filter = encode_filter(&ids, &filter.status, filter.role.as_ref(), &exclude)?;
            list_records(&obj, "listHelpers", &secret_str, filter).await
        })
    }

    fn replicas(
        &self,
        secret_id: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let ids: Vec<u64> = filter.ids.iter().map(|r| r.0).collect();
            let exclude: Vec<u64> = filter.exclude.iter().map(|r| r.0).collect();
            let filter = encode_filter(&ids, &filter.status, filter.role.as_ref(), &exclude)?;
            list_records(&obj, "listReplicas", &secret_str, filter).await
        })
    }

    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let a_str = a.0.to_string();
        let b_str = b.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&a_str));
            args.push(&JsValue::from_str(&b_str));
            let promise_val = call_method(&obj, "linkChannel", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "linkedChannels", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let s = arr.get(i).as_string().ok_or_else(|| {
                    ChannelStoreError::Backend(box_err(
                        "linkedChannels must return an array of channel-id strings".to_string(),
                    ))
                })?;
                let id = s
                    .parse::<u64>()
                    .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
                result.push(ChannelId(id));
            }
            Ok(result)
        })
    }
}

/// Adapter wrapping a JS `ShareStore` object.
pub struct JsShareStore(pub JsValue);

fn share_to_js(share: &Share) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"secretId".into(),
        &JsValue::from_str(&share.secret_id.to_string()),
    )
    .unwrap_or_default();
    js_sys::Reflect::set(
        &obj,
        &"version".into(),
        &JsValue::from_f64(share.version as f64),
    )
    .unwrap_or_default();
    let js_bytes = Uint8Array::from(share.bytes.as_slice());
    js_sys::Reflect::set(&obj, &"bytes".into(), &js_bytes).unwrap_or_default();
    for (key, value) in [
        ("subshares", share.subshares),
        ("threshold", share.threshold),
    ] {
        if let Some(value) = value {
            js_sys::Reflect::set(&obj, &key.into(), &JsValue::from_f64(f64::from(value)))
                .unwrap_or_default();
        }
    }
    obj.into()
}

/// `value` as a `u32`: a `number` that is an integer in `0..=u32::MAX`.
fn u32_from_js(value: &JsValue) -> Option<u32> {
    value
        .as_f64()
        .filter(|n| n.fract() == 0.0 && *n >= 0.0 && *n <= f64::from(u32::MAX))
        .map(|n| n as u32)
}

/// `record[key]`: `undefined` or `null` is none, otherwise a string. `what`
/// names the record in the error.
fn optional_string_from_js(
    item: &JsValue,
    what: &str,
    key: &str,
) -> Result<Option<String>, ShareStoreError> {
    let value = js_sys::Reflect::get(item, &key.into()).unwrap_or(JsValue::UNDEFINED);
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    value.as_string().map(Some).ok_or_else(|| {
        ShareStoreError::Backend(box_err(format!(
            "{what}.{key} must be a string, null or undefined"
        )))
    })
}

/// `record[key]`: `undefined` or `null` is none, otherwise a `u32`. `what`
/// names the record in the error.
fn optional_u32_from_js(
    item: &JsValue,
    what: &str,
    key: &str,
) -> Result<Option<u32>, ShareStoreError> {
    let value = js_sys::Reflect::get(item, &key.into()).unwrap_or(JsValue::UNDEFINED);
    if value.is_undefined() || value.is_null() {
        return Ok(None);
    }
    u32_from_js(&value).map(Some).ok_or_else(|| {
        ShareStoreError::Backend(box_err(format!(
            "{what}.{key} must be a u32, null or undefined"
        )))
    })
}

fn share_from_js(item: &JsValue) -> Result<Share, ShareStoreError> {
    let secret_id_str = js_sys::Reflect::get(item, &"secretId".into())
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    let secret_id = secret_id_str.parse::<u64>().map_err(|e| {
        ShareStoreError::Backend(box_err(format!(
            "share.secretId must be a numeric string: {e}"
        )))
    })?;
    let version = js_sys::Reflect::get(item, &"version".into())
        .ok()
        .and_then(|v| u32_from_js(&v))
        .ok_or_else(|| {
            ShareStoreError::Backend(box_err("share.version must be a u32".to_string()))
        })?;
    let bytes_val = js_sys::Reflect::get(item, &"bytes".into()).unwrap_or(JsValue::null());
    let bytes = Uint8Array::new(&bytes_val).to_vec();
    Ok(Share {
        secret_id,
        version,
        bytes,
        subshares: optional_u32_from_js(item, "share", "subshares")?,
        threshold: optional_u32_from_js(item, "share", "threshold")?,
    })
}

impl DeRecShareStore for JsShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        let versions_vec: Vec<u32> = versions.to_vec();
        Box::pin(async move {
            let js_versions = Array::new();
            for v in &versions_vec {
                js_versions.push(&JsValue::from_f64(*v as f64));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_versions);
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                result.push(share_from_js(&arr.get(i))?);
            }
            Ok(result)
        })
    }

    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            let promise_val = call_method(&obj, "latestVersion", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                Ok(None)
            } else {
                let v = u32_from_js(&value).ok_or_else(|| {
                    ShareStoreError::Backend(box_err(
                        "latestVersion must return a u32 or null".to_string(),
                    ))
                })?;
                Ok(Some(v))
            }
        })
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&share_to_js(&share));
            let promise_val = call_method_value(&obj, "save", &args)
                .map_err(|e| share_store_call_error("save", &e))?;
            resolve_promise_value(promise_val)
                .await
                .map_err(|e| share_store_call_error("save", &e))?;
            Ok(())
        })
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<(ChannelId, Share)>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let ids_vec: Vec<String> = channel_ids.iter().map(|c| c.0.to_string()).collect();
        let versions_vec: Vec<u32> = versions.to_vec();
        Box::pin(async move {
            let js_ids = Array::new();
            for id in &ids_vec {
                js_ids.push(&JsValue::from_str(id));
            }
            let js_versions = Array::new();
            for v in &versions_vec {
                js_versions.push(&JsValue::from_f64(*v as f64));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_ids);
            args.push(&js_versions);
            let promise_val = call_method(&obj, "loadMany", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let pair = Array::from(&arr.get(i));
                let channel_id = pair
                    .get(0)
                    .as_string()
                    .and_then(|id| id.parse::<u64>().ok())
                    .ok_or_else(|| {
                        ShareStoreError::Backend(box_err(
                            "loadMany entries must be [channelId: decimal string, share]"
                                .to_string(),
                        ))
                    })?;
                result.push((ChannelId(channel_id), share_from_js(&pair.get(1))?));
            }
            Ok(result)
        })
    }

    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let ids_vec: Vec<String> = channel_ids.iter().map(|c| c.0.to_string()).collect();
        Box::pin(async move {
            let js_ids = Array::new();
            for id in &ids_vec {
                js_ids.push(&JsValue::from_str(id));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_ids);
            let promise_val = call_method(&obj, "loadAll", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                result.push(share_from_js(&arr.get(i))?);
            }
            Ok(result)
        })
    }

    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "removeChannel", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove_versions(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        let versions_vec: Vec<u32> = versions.to_vec();
        Box::pin(async move {
            let js_versions = Array::new();
            for v in &versions_vec {
                js_versions.push(&JsValue::from_f64(*v as f64));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_versions);
            let promise_val = call_method(&obj, "removeVersions", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove_versions_many(
        &mut self,
        secret_id: u64,
        entries: &[(ChannelId, Vec<u32>)],
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let pairs = Array::new();
        for (channel_id, versions) in entries {
            let js_versions = Array::new();
            for v in versions {
                js_versions.push(&JsValue::from_f64(f64::from(*v)));
            }
            let pair = Array::new();
            pair.push(&JsValue::from_str(&channel_id.0.to_string()));
            pair.push(&js_versions);
            pairs.push(&pair);
        }
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&pairs);
            let promise_val = call_method(&obj, "removeVersionsMany", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn keep_version(&self, secret_id: u64, version: u32) -> ShareStoreFuture<'_, u32> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_f64(f64::from(version)));
            let promise_val = call_method(&obj, "keepVersion", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            value
                .as_f64()
                .filter(|f| f.fract() == 0.0 && (0.0..=f64::from(u32::MAX)).contains(f))
                .map(|f| f as u32)
                .ok_or_else(|| {
                    ShareStoreError::Backend(box_err(
                        "keepVersion must return an integer in 0..=4294967295".to_string(),
                    ))
                })
        })
    }

    fn record_verification(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        version: u32,
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&JsValue::from_f64(f64::from(version)));
            let promise_val = call_method_value(&obj, "recordVerification", &args)
                .map_err(|e| share_store_call_error("recordVerification", &e))?;
            resolve_promise_value(promise_val)
                .await
                .map_err(|e| share_store_call_error("recordVerification", &e))?;
            Ok(())
        })
    }
}

/// Adapter wrapping a JS `UserSecretStore` object; the JS interface is
/// `UserSecretStore` in the module docs.
pub struct JsUserSecretStore(pub JsValue);

fn user_secrets_to_js(value: &UserSecrets) -> JsValue {
    let obj = js_sys::Object::new();
    js_sys::Reflect::set(
        &obj,
        &"version".into(),
        &JsValue::from_f64(f64::from(value.version)),
    )
    .unwrap_or_default();
    let entries = Array::new();
    for s in &value.secrets {
        let entry = js_sys::Object::new();
        let id = Uint8Array::from(s.id.as_slice());
        let data = Uint8Array::from(s.data.as_slice());
        js_sys::Reflect::set(&entry, &"id".into(), &id).unwrap_or_default();
        js_sys::Reflect::set(&entry, &"name".into(), &JsValue::from_str(&s.name))
            .unwrap_or_default();
        js_sys::Reflect::set(&entry, &"data".into(), &data).unwrap_or_default();
        entries.push(&entry);
    }
    js_sys::Reflect::set(&obj, &"secrets".into(), &entries).unwrap_or_default();
    if let Some(d) = value.description.as_deref() {
        js_sys::Reflect::set(&obj, &"description".into(), &JsValue::from_str(d))
            .unwrap_or_default();
    }
    if let Some(author) = value.author_replica_id {
        js_sys::Reflect::set(
            &obj,
            &"author_replica_id".into(),
            &JsValue::from_str(&author.to_string()),
        )
        .unwrap_or_default();
    }
    if let Some(threshold) = value.threshold {
        js_sys::Reflect::set(
            &obj,
            &"threshold".into(),
            &JsValue::from_f64(f64::from(threshold)),
        )
        .unwrap_or_default();
    }
    obj.into()
}

fn user_secrets_from_js(value: &JsValue) -> Result<UserSecrets, ShareStoreError> {
    let version = js_sys::Reflect::get(value, &"version".into())
        .ok()
        .and_then(|v| u32_from_js(&v))
        .ok_or_else(|| {
            ShareStoreError::Backend(box_err("userSecrets.version must be a u32".to_string()))
        })?;
    #[derive(serde::Deserialize)]
    struct UserSecretShape {
        #[serde(with = "serde_bytes")]
        id: Vec<u8>,
        name: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    }
    let entries_val = js_sys::Reflect::get(value, &"secrets".into()).unwrap_or(JsValue::UNDEFINED);
    if !Array::is_array(&entries_val) {
        return Err(ShareStoreError::Backend(box_err(
            "userSecrets.secrets must be an array".to_string(),
        )));
    }
    let secrets = serde_wasm_bindgen::from_value::<Vec<UserSecretShape>>(entries_val)
        .map_err(|e| {
            ShareStoreError::Backend(box_err(format!("invalid userSecrets.secrets: {e}")))
        })?
        .into_iter()
        .map(|s| UserSecret {
            id: s.id,
            name: s.name,
            data: s.data,
        })
        .collect();
    let description = optional_string_from_js(value, "userSecrets", "description")?;
    let author_replica_id = optional_string_from_js(value, "userSecrets", "author_replica_id")?
        .map(|id| {
            id.parse::<u64>().map_err(|_| {
                ShareStoreError::Backend(box_err(format!(
                    "userSecrets.author_replica_id is not a decimal u64: {id}"
                )))
            })
        })
        .transpose()?;
    Ok(UserSecrets {
        version,
        secrets,
        description,
        author_replica_id,
        threshold: optional_u32_from_js(value, "userSecrets", "threshold")?,
    })
}

impl DeRecUserSecretStore for JsUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            let promise_val = call_method(&obj, "loadLatest", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                Ok(None)
            } else {
                Ok(Some(user_secrets_from_js(&value)?))
            }
        })
    }

    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let js_value = user_secrets_to_js(&value);
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_value);
            let promise_val = call_method(&obj, "saveLatest", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }
}

/// Adapter wrapping a JS `Transport` object.
pub struct JsTransport(pub JsValue);

#[derive(serde::Serialize)]
struct EndpointJs {
    protocol: String,
    uri: String,
}

impl DeRecTransport for JsTransport {
    fn send(&self, endpoints: &[TransportProtocol], message: Vec<u8>) -> TransportFuture<'_> {
        // Every entry point that produces a `TransportProtocol` — builder
        // config, peer-supplied endpoints decoded off the wire — validates
        // the `protocol` discriminant before it reaches here, so an unknown
        // one should be unreachable in practice. Treated as a hard failure
        // rather than handed to JS as a meaningless `"unknown"` string: the
        // application cannot act on a protocol name it doesn't recognise.
        let mut js_endpoints = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let Some(protocol) = super::protocol_discriminant_to_name(endpoint.protocol) else {
                return Box::pin(async move {
                    Err(Error::InvalidInput(
                        "unknown transport protocol discriminant",
                    ))
                });
            };
            js_endpoints.push(EndpointJs {
                protocol: protocol.to_owned(),
                uri: endpoint.uri.to_owned(),
            });
        }

        let obj = self.0.clone();
        Box::pin(async move {
            // The whole set, in the peer's order. Which to dial, and whether
            // to fall back, is the JS implementation's choice.
            let endpoints_js = serde_wasm_bindgen::to_value(&js_endpoints)
                .map_err(|_| Error::InvalidInput("failed to serialize endpoints"))?;
            let js_message = Uint8Array::from(message.as_slice());
            let args = Array::new();
            args.push(&endpoints_js);
            args.push(&js_message);
            let promise_val = call_method(&obj, "send", &args)
                .map_err(|_| Error::InvalidInput("transport.send call failed"))?;
            resolve_promise(promise_val)
                .await
                .map_err(|_| Error::InvalidInput("transport.send promise rejected"))?;
            Ok(())
        })
    }
}

/// The serializable projections of [`StateKey`] / [`StateItem`] are shared
/// with the FFI store shim and every out-of-process backend, so the JSON
/// contract cannot drift between them.
use crate::protocol::types::state_record::{StateItemRecord, StateKeyRecord};

fn state_kind_to_u32(kind: StateKind) -> u32 {
    match kind {
        StateKind::PendingVerification => 0,
        StateKind::PendingRecovery => 1,
        StateKind::PendingUnpair => 2,
        StateKind::SharingRound => 3,
        StateKind::PendingReplicaDiscovery => 4,
    }
}

/// Adapter wrapping a JS `StateStore` object; the JS interface is
/// `StateStore` in the module docs.
///
/// The buffers are JSON-encoded records matching the Rust-side
/// `StateItemRecord` / `StateKeyRecord`.
pub struct JsStateStore(pub JsValue);

impl DeRecStateStore for JsStateStore {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let record = StateItemRecord::from(&item);
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_bytes);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let key_record = StateKeyRecord::from(&key);
            let key_bytes = serde_json::to_vec(&key_record)
                .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
            let js_key = Uint8Array::from(key_bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_key);
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            let bytes = Uint8Array::new(&value).to_vec();
            let record: StateItemRecord = serde_json::from_slice(&bytes)
                .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
            let item = record
                .into_item()
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            Ok(Some(item))
        })
    }

    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let key_record = StateKeyRecord::from(&key);
            let key_bytes = serde_json::to_vec(&key_record)
                .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
            let js_key = Uint8Array::from(key_bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_key);
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            value.as_bool().ok_or_else(|| {
                StateStoreError::Backend(box_err("remove must return a boolean".to_string()))
            })
        })
    }

    fn remove_many(&mut self, secret_id: u64, keys: &[StateKey]) -> StateStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let records: Vec<StateKeyRecord> = keys.iter().map(StateKeyRecord::from).collect();
        Box::pin(async move {
            let keys_bytes = serde_json::to_vec(&records)
                .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&Uint8Array::from(keys_bytes.as_slice()));
            let promise_val = call_method(&obj, "removeMany", &args)
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let kind_num = state_kind_to_u32(kind);
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_f64(kind_num as f64));
            let promise_val = call_method(&obj, "loadAll", &args)
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| StateStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut out = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let entry = arr.get(i);
                let bytes = Uint8Array::new(&entry).to_vec();
                let record: StateItemRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| StateStoreError::Backend(box_err(e.to_string())))?;
                out.push(
                    record
                        .into_item()
                        .map_err(|e| StateStoreError::Backend(box_err(e)))?,
                );
            }
            Ok(out)
        })
    }
}
