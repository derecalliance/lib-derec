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
//! ### `ContactStore`
//! ```ts
//! interface ContactStore {
//!   load(channelId: string): Promise<Uint8Array | null | undefined>;
//!   save(channelId: string, contactBytes: Uint8Array): Promise<void>;
//! }
//! // Uint8Array is the raw protobuf encoding of a ContactMessage.
//! ```
//!
//! ### `ShareStore`
//! ```ts
//! interface ShareStore {
//!   load(channelId: string, secretId: Uint8Array, version: number): Promise<Uint8Array | null | undefined>;
//!   save(channelId: string, secretId: Uint8Array, version: number, encoded: Uint8Array): Promise<void>;
//!   loadChannelsForSecret(secretId: Uint8Array, version: number): Promise<string[]>;
//!   loadSecretsForChannel(channelId: string): Promise<Array<[Uint8Array, number[]]>>;
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
        error::{ContactStoreError, SecretStoreError, ShareStoreError},
        traits::{
            ContactStoreFuture, DeRecContactStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
            SecretKind, SecretStoreFuture, SecretValue, ShareStoreFuture, TransportFuture,
        },
    },
    types::ChannelId,
};

// ── Error helpers ─────────────────────────────────────────────────────────────

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

// ── JS bridge helpers ─────────────────────────────────────────────────────────

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

// ── JsSecretStore ─────────────────────────────────────────────────────────────

/// Adapter wrapping a JS `SecretStore` object.
pub struct JsSecretStore(pub JsValue);

impl DeRecSecretStore for JsSecretStore {
    fn load(
        &self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let kind_num = kind as u32;
        Box::pin(async move {
            let args = Array::new();
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
            match kind {
                SecretKind::SharedKey => {
                    if bytes.len() != 32 {
                        return Err(SecretStoreError::Backend(box_err(format!(
                            "shared key must be 32 bytes, got {}",
                            bytes.len()
                        ))));
                    }
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    Ok(Some(SecretValue::SharedKey(key)))
                }
                SecretKind::PairingSecret => {
                    let material =
                        PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..])
                            .map_err(|e| SecretStoreError::Backend(box_err(e.to_string())))?;
                    Ok(Some(SecretValue::PairingSecret(material)))
                }
            }
        })
    }

    fn save(&mut self, channel_id: ChannelId, value: SecretValue) -> SecretStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let (kind_num, bytes) = match &value {
                SecretValue::SharedKey(key) => (0u32, key.to_vec()),
                SecretValue::PairingSecret(material) => {
                    let mut buf = Vec::new();
                    material
                        .serialize_uncompressed(&mut buf)
                        .map_err(|e| SecretStoreError::Backend(box_err(format!("{e:?}"))))?;
                    (1u32, buf)
                }
            };
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
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

    fn remove(&mut self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let kind_num = kind as u32;
        Box::pin(async move {
            let args = Array::new();
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

// ── JsContactStore ────────────────────────────────────────────────────────────

/// Adapter wrapping a JS `ContactStore` object.
pub struct JsContactStore(pub JsValue);

impl DeRecContactStore for JsContactStore {
    fn load(&self, channel_id: ChannelId) -> ContactStoreFuture<'_, Option<ContactMessage>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ContactStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ContactStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            let bytes = Uint8Array::new(&value).to_vec();
            let msg = ContactMessage::decode(bytes.as_slice())
                .map_err(|e| ContactStoreError::Backend(box_err(e.to_string())))?;
            Ok(Some(msg))
        })
    }

    fn save(
        &mut self,
        channel_id: ChannelId,
        contact: ContactMessage,
    ) -> ContactStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let bytes = contact.encode_to_vec();
        Box::pin(async move {
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_bytes);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| ContactStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ContactStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }
}

// ── JsShareStore ──────────────────────────────────────────────────────────────

/// Adapter wrapping a JS `ShareStore` object.
pub struct JsShareStore(pub JsValue);

impl DeRecShareStore for JsShareStore {
    fn load(
        &self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
    ) -> ShareStoreFuture<'_, Option<Vec<u8>>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let secret_id_vec = secret_id.to_vec();
        Box::pin(async move {
            let js_secret_id = Uint8Array::from(secret_id_vec.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_secret_id);
            args.push(&JsValue::from_f64(version as f64));
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            if value.is_null() || value.is_undefined() {
                return Ok(None);
            }
            Ok(Some(Uint8Array::new(&value).to_vec()))
        })
    }

    fn save(
        &mut self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
        encoded: Vec<u8>,
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let secret_id_vec = secret_id.to_vec();
        Box::pin(async move {
            let js_secret_id = Uint8Array::from(secret_id_vec.as_slice());
            let js_encoded = Uint8Array::from(encoded.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_secret_id);
            args.push(&JsValue::from_f64(version as f64));
            args.push(&js_encoded);
            let promise_val = call_method(&obj, "save", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            Ok(())
        })
    }

    fn load_channels_for_secret(
        &self,
        secret_id: &[u8],
        version: i32,
    ) -> ShareStoreFuture<'_, Vec<ChannelId>> {
        let obj = self.0.clone();
        let secret_id_vec = secret_id.to_vec();
        Box::pin(async move {
            let js_secret_id = Uint8Array::from(secret_id_vec.as_slice());
            let args = Array::new();
            args.push(&js_secret_id);
            args.push(&JsValue::from_f64(version as f64));
            let promise_val = call_method(&obj, "loadChannelsForSecret", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let arr = Array::from(&value);
            let mut ids = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let item = arr.get(i);
                let s = item.as_string().ok_or_else(|| {
                    ShareStoreError::Backend(box_err("channel id must be a string".to_string()))
                })?;
                let id = s
                    .parse::<u64>()
                    .map_err(|e| ShareStoreError::Backend(box_err(e.to_string())))?;
                ids.push(ChannelId(id));
            }
            Ok(ids)
        })
    }

    fn load_secrets_for_channel(
        &self,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, Vec<(Vec<u8>, Vec<i32>)>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "loadSecretsForChannel", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            // Expects Array<[Uint8Array, number[]]>
            let arr = Array::from(&value);
            let mut secrets = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let entry = Array::from(&arr.get(i));
                let secret_id = Uint8Array::new(&entry.get(0)).to_vec();
                let versions_js = Array::from(&entry.get(1));
                let mut versions = Vec::with_capacity(versions_js.length() as usize);
                for j in 0..versions_js.length() {
                    let v = versions_js.get(j).as_f64().ok_or_else(|| {
                        ShareStoreError::Backend(box_err("version must be a number".to_string()))
                    })?;
                    versions.push(v as i32);
                }
                secrets.push((secret_id, versions));
            }
            Ok(secrets)
        })
    }
}

// ── JsTransport ───────────────────────────────────────────────────────────────

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
        let uri = endpoint.uri.clone();
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
