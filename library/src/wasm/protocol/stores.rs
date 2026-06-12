// SPDX-License-Identifier: Apache-2.0

//! JS-side adapters for the four protocol traits.
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

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, TransportProtocol};
use js_sys::{Array, Function, Promise, Uint8Array};
use prost::Message as _;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

use crate::{
    Error,
    protocol::{
        error::{ChannelStoreError, SecretStoreError, ShareStoreError},
        traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore,
            DeRecShareStore, DeRecTransport, DeRecUserSecretStore, SecretStoreFuture,
            ShareStoreFuture, TransportFuture,
        },
        types::{Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecret, UserSecrets},
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
        SecretKind::PairingSecret => {
            let material = PairingSecretKeyMaterial::deserialize_compressed(&mut &bytes[..])
                .map_err(|e| SecretStoreError::Backend(box_err(e.to_string())))?;
            Ok(SecretValue::PairingSecret(material))
        }
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
                SecretValue::PairingSecret(material) => {
                    let mut buf = Vec::new();
                    material
                        .serialize_compressed(&mut buf)
                        .map_err(|e| SecretStoreError::Backend(box_err(format!("{e:?}"))))?;
                    (1u32, buf)
                }
                SecretValue::PairingContact(contact) => {
                    (2u32, contact.encode_to_vec())
                }
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
///   load(channelId: string): Promise<Uint8Array | null>;
///   save(channelId: string, bytes: Uint8Array): Promise<void>;
///   listChannels(): Promise<string[]>;
///   linkChannel(channelId: string, linkedChannelId: string): Promise<void>;
///   linkedChannels(channelId: string): Promise<string[]>;
/// }
/// ```
///
/// The bytes are JSON-encoded [`Channel`] records. `linkedChannels` returns the
/// transitive closure of `channelId` (including `channelId` itself).
pub struct JsChannelStore(pub JsValue);

impl DeRecChannelStore for JsChannelStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            let bytes = Uint8Array::new(&value).to_vec();
            let channel: Channel = serde_json::from_slice(&bytes)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            Ok(Some(channel))
        })
    }

    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            let promise_val = call_method(&obj, "listChannels", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);

            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let item = arr.get(i);
                let s = item.as_string().ok_or_else(|| {
                    ChannelStoreError::Backend(box_err("channel id must be a string".to_string()))
                })?;
                let id = s
                    .parse::<u64>()
                    .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
                let channel_id = ChannelId(id);

                let load_args = Array::new();
                load_args.push(&JsValue::from_str(&secret_str));
                load_args.push(&JsValue::from_str(&s));
                let load_promise = call_method(&obj, "load", &load_args)
                    .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
                let load_value = resolve_promise(load_promise)
                    .await
                    .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;

                if load_value.is_null() || load_value.is_undefined() {
                    continue;
                }
                let bytes = Uint8Array::new(&load_value).to_vec();
                let channel: Channel = serde_json::from_slice(&bytes)
                    .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
                debug_assert_eq!(channel.id, channel_id);
                result.push(channel);
            }
            Ok(result)
        })
    }

    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel.id.0.to_string();
        Box::pin(async move {
            let bytes = serde_json::to_vec(&channel)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_bytes);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool> {
        let obj = self.0.clone();
        let secret_str = secret_id.to_string();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&secret_str));
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(value.as_bool().unwrap_or(false))
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
    js_sys::Reflect::set(&obj, &"secretId".into(), &JsValue::from_str(&share.secret_id.to_string()))
        .unwrap_or_default();
    js_sys::Reflect::set(&obj, &"version".into(), &JsValue::from_f64(share.version as f64))
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
    let secret_id = secret_id_str
        .parse::<u64>()
        .map_err(|e| ShareStoreError::Backend(box_err(format!("share.secretId must be a numeric string: {e}"))))?;
    let version = js_sys::Reflect::get(item, &"version".into())
        .ok()
        .and_then(|v| v.as_f64())
        .ok_or_else(|| ShareStoreError::Backend(box_err("share.version must be a number".to_string())))?
        as u32;
    let bytes_val = js_sys::Reflect::get(item, &"bytes".into())
        .unwrap_or(JsValue::null());
    let bytes = Uint8Array::new(&bytes_val).to_vec();
    Ok(Share { secret_id, version, bytes })
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
                let v = value
                    .as_f64()
                    .ok_or_else(|| ShareStoreError::Backend(box_err(
                        "latestVersion must return a number or null".to_string(),
                    )))?
                    as u32;
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
            ShareStoreError::Backend(box_err(
                "userSecrets.version must be a number".to_string(),
            ))
        })? as u32;
    let entries_val = js_sys::Reflect::get(value, &"secrets".into())
        .unwrap_or(JsValue::null());
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
    Ok(UserSecrets { version, secrets, description })
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

    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()> {
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
