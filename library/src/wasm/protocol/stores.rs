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
//! ### `SecretStore`
//! ```ts
//! interface SecretStore {
//!   load(channelId: string, kind: 0 | 1): Promise<Uint8Array | null | undefined>;
//!   save(channelId: string, kind: 0 | 1, value: Uint8Array): Promise<void>;
//!   remove(channelId: string, kind: 0 | 1): Promise<void>;
//! }
//! // kind 0 = SharedKey (32 raw bytes), kind 1 = PairingSecret (ark-serialized)
//! ```
//!
//! ### `ChannelStore`
//! ```ts
//! interface ChannelStore {
//!   load(channelId: string): Promise<Uint8Array | null | undefined>;
//!   save(channelId: string, contactBytes: Uint8Array): Promise<void>;
//!   listChannels(): Promise<string[]>;
//!   // Channel linking (same Owner identity); undirected, idempotent, transitive.
//!   linkChannel(channelId: string, linkedChannelId: string): Promise<void>;
//!   // Transitive closure INCLUDING channelId itself.
//!   linkedChannels(channelId: string): Promise<string[]>;
//! }
//! // Uint8Array is the raw protobuf encoding of a Channel record.
//! ```
//!
//! ### `ShareStore`
//! ```ts
//! interface Share { secretId: string; version: number; bytes: Uint8Array }
//! interface ShareStore {
//!   // `secretId` is the u64 secret identifier as a decimal string.
//!   // For `load`/`loadMany`, an empty `versions` array means "all versions of secretId".
//!   load(channelId: string, secretId: string, versions: number[]): Promise<Share[]>;
//!   loadMany(channelIds: string[], secretId: string, versions: number[]): Promise<Share[]>;
//!   // Discovery-only: all secrets and versions for these channels.
//!   loadAll(channelIds: string[]): Promise<Share[]>;
//!   save(channelId: string, share: Share): Promise<void>;
//!   // Drop EVERY share stored under channelId (all secret_ids, all versions).
//!   // Called when an unpair flow tears down a channel. Implementations must
//!   // treat a non-existent channel as a no-op.
//!   removeChannel(channelId: string): Promise<void>;
//!   latestVersion(): Promise<number | null>;
//! }
//! ```
//!
//! ### `Transport`
//! ```ts
//! interface Transport {
//!   send(endpoint: { protocol: string; uri: string }, message: Uint8Array): Promise<void>;
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
        error::{ChannelStoreError, SecretStoreError, ShareStoreError, StateStoreError},
        traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecStateStore, DeRecTransport, DeRecUserSecretStore, SecretStoreFuture,
            ShareStoreFuture, StateStoreFuture, TransportFuture,
        },
        types::{
            ChannelQuery, ChannelRecord, HelperChannel, MissingPolicy, PairingKeyMaterial,
            ReplicaMember, SecretKind, SecretValue, Share, StateItem, StateKey, StateKind,
            UserSecret, UserSecrets,
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
        let raw_ids: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let kind_num = kind as u32;
        let policy_str = match missing_policy {
            MissingPolicy::Skip => "skip",
            MissingPolicy::Fail => "fail",
        };
        Box::pin(async move {
            let js_ids = Array::new();
            for id in &ids_vec {
                js_ids.push(&JsValue::from_str(id));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&js_ids);
            args.push(&JsValue::from_f64(kind_num as f64));
            args.push(&JsValue::from_str(policy_str));
            let promise_val = call_method(&obj, "loadMany", &args)
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| SecretStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            let mut missing: Vec<u64> = Vec::new();
            for i in 0..arr.length() {
                let cid = *raw_ids.get(i as usize).ok_or_else(|| {
                    SecretStoreError::Backend(box_err(
                        "loadMany returned more entries than requested".to_string(),
                    ))
                })?;
                let raw = arr.get(i);
                if raw.is_null() || raw.is_undefined() {
                    missing.push(cid);
                    continue;
                }
                let bytes = Uint8Array::new(&raw).to_vec();
                let value = decode_secret_value(kind, &bytes)?;
                result.push((ChannelId(cid), value));
            }
            if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
                return Err(SecretStoreError::MissingEntries {
                    kind,
                    channel_ids: missing,
                });
            }
            Ok(result)
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
}

/// Adapter wrapping a JS `ChannelStore` object.
///
/// # JS interface contract
///
/// ```ts
/// interface ChannelStore {
///   load(secretId: string, channelId: string, replicaId: string): Promise<Uint8Array | null>;
///   save(secretId: string, channelId: string, replicaId: string, bytes: Uint8Array): Promise<void>;
///   remove(secretId: string, channelId: string, replicaId: string): Promise<boolean>;
///   listHelpers(secretId: string): Promise<Uint8Array | null>;
///   listReplicas(secretId: string): Promise<Uint8Array | null>;
///   linkChannel(secretId: string, channelId: string, linkedChannelId: string): Promise<void>;
///   linkedChannels(secretId: string, channelId: string): Promise<string[]>;
/// }
/// ```
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
async fn list_records<T: serde::de::DeserializeOwned>(
    obj: &JsValue,
    method: &str,
    secret_str: &str,
) -> Result<Vec<T>, ChannelStoreError> {
    let args = Array::new();
    args.push(&JsValue::from_str(secret_str));
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
            Ok(value.as_bool().unwrap_or(false))
        })
    }

    fn helpers(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move { list_records(&obj, "listHelpers", &secret_str).await })
    }

    fn replicas(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move { list_records(&obj, "listReplicas", &secret_str).await })
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
    obj.into()
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
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            ShareStoreError::Backend(box_err("share.version must be a number".to_string()))
        })? as u32;
    let bytes_val = js_sys::Reflect::get(item, &"bytes".into()).unwrap_or(JsValue::null());
    let bytes = Uint8Array::new(&bytes_val).to_vec();
    // `replicaId` is an optional decimal-string on the JS side
    // (matching `derec.replica_id` and `Channel.replicaId`). Missing /
    // null / empty string all map to `None`.
    Ok(Share {
        secret_id,
        version,
        bytes,
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
                let v = value.as_f64().ok_or_else(|| {
                    ShareStoreError::Backend(box_err(
                        "latestVersion must return a number or null".to_string(),
                    ))
                })? as u32;
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
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
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
                result.push(share_from_js(&arr.get(i))?);
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
}

/// Adapter wrapping a JS `UserSecretStore` object.
///
/// JS interface contract:
/// ```ts
/// interface UserSecretStore {
///   loadLatest(secretId: string): Promise<UserSecrets | null | undefined>;
///   saveLatest(secretId: string, value: UserSecrets): Promise<void>;
///   remove(secretId: string): Promise<void>;
/// }
/// type UserSecrets = {
///   version: number;
///   secrets: { id: Uint8Array; name: string; data: Uint8Array }[];
///   description?: string;
/// };
/// ```
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
    obj.into()
}

fn user_secrets_from_js(value: &JsValue) -> Result<UserSecrets, ShareStoreError> {
    let version = js_sys::Reflect::get(value, &"version".into())
        .ok()
        .and_then(|v| v.as_f64())
        .ok_or_else(|| {
            ShareStoreError::Backend(box_err("userSecrets.version must be a number".to_string()))
        })? as u32;
    let entries_val = js_sys::Reflect::get(value, &"secrets".into()).unwrap_or(JsValue::null());
    let entries_arr = Array::from(&entries_val);
    let mut secrets = Vec::with_capacity(entries_arr.length() as usize);
    for i in 0..entries_arr.length() {
        let item = entries_arr.get(i);
        let id_val = js_sys::Reflect::get(&item, &"id".into()).unwrap_or(JsValue::null());
        let data_val = js_sys::Reflect::get(&item, &"data".into()).unwrap_or(JsValue::null());
        let name = js_sys::Reflect::get(&item, &"name".into())
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        secrets.push(UserSecret {
            id: Uint8Array::new(&id_val).to_vec(),
            name,
            data: Uint8Array::new(&data_val).to_vec(),
        });
    }
    let description = js_sys::Reflect::get(value, &"description".into())
        .ok()
        .and_then(|v| v.as_string());
    // The JS-side store carries only the user-facing snapshot; the
    // `replicas` cache is rebuilt on the next ProtectSecret round from
    // live channel state.
    Ok(UserSecrets {
        version,
        secrets,
        description,
        replicas: None,
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
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        let obj = self.0.clone();
        let protocol = match endpoint.protocol {
            0 => "https",
            _ => "unknown",
        }
        .to_owned();
        let uri = endpoint.uri.to_owned();
        Box::pin(async move {
            let endpoint_js = serde_wasm_bindgen::to_value(&EndpointJs { protocol, uri })
                .map_err(|_| Error::InvalidInput("failed to serialize endpoint"))?;
            let js_message = Uint8Array::from(message.as_slice());
            let args = Array::new();
            args.push(&endpoint_js);
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
        StateKind::PendingSyncCheck => 4,
    }
}

/// Adapter wrapping a JS `StateStore` object.
///
/// # JS interface contract
///
/// ```ts
/// interface StateStore {
///   save(secretId: string, itemJson: Uint8Array): Promise<void>;
///   load(secretId: string, keyJson: Uint8Array): Promise<Uint8Array | null>;
///   remove(secretId: string, keyJson: Uint8Array): Promise<boolean>;
///   loadAll(secretId: string, kind: number): Promise<Uint8Array[]>;
/// }
/// ```
///
/// The buffers are JSON-encoded records matching the Rust-side
/// `StateItemRecord` / `StateKeyRecord`. `kind` values are `0` =
/// PendingVerification, `1` = PendingRecovery, `2` = PendingUnpair.
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
            Ok(value.as_bool().unwrap_or(false))
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
