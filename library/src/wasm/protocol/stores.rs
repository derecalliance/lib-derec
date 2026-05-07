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
//!   listChannels(): Promise<string[]>;
//! }
//! // Uint8Array is the raw protobuf encoding of a ContactMessage.
//! ```
//!
//! ### `ShareStore`
//! ```ts
//! interface ShareStore {
//!   load(channelId: string, versions: number[]): Promise<Array<[number, Uint8Array]>>;
//!   save(channelId: string, version: number, encoded: Uint8Array): Promise<void>;
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
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
            SecretKind, SecretStoreFuture, SecretValue, ShareStoreFuture, TransportFuture,
        },
    },
    types::{Channel, ChannelId, ChannelStatus},
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
                SecretKind::PairingContact => {
                    let contact = ContactMessage::decode(bytes.as_slice())
                        .map_err(|e| SecretStoreError::Backend(box_err(e.to_string())))?;
                    Ok(Some(SecretValue::PairingContact(contact)))
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
                SecretValue::PairingContact(contact) => {
                    (2u32, contact.encode_to_vec())
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

// ── JsChannelStore ───────────────────────────────────────────────────────────

/// Adapter wrapping a JS `ChannelStore` object.
///
/// # JS interface contract
///
/// ```ts
/// interface ChannelStore {
///   load(channelId: string): Promise<Uint8Array | null>;
///   save(channelId: string, bytes: Uint8Array): Promise<void>;
///   listChannels(): Promise<string[]>;
/// }
/// ```
///
/// The bytes are JSON-encoded [`Channel`] records.
pub struct JsChannelStore(pub JsValue);

/// Serializable representation of a [`Channel`] for JS store persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChannelRecord {
    channel_id: u64,
    transport_uri: String,
    transport_protocol: i32,
    name: String,
    #[serde(default = "default_channel_status")]
    status: String,
    #[serde(default)]
    created_at: u64,
}

fn default_channel_status() -> String {
    "paired".to_owned()
}

impl From<&Channel> for ChannelRecord {
    fn from(ch: &Channel) -> Self {
        let status = match ch.status {
            ChannelStatus::Pending => "pending",
            ChannelStatus::Paired => "paired",
        };
        Self {
            channel_id: ch.id.0,
            transport_uri: ch.transport.uri.clone(),
            transport_protocol: ch.transport.protocol,
            name: ch.name.clone(),
            status: status.to_owned(),
            created_at: ch.created_at,
        }
    }
}

impl From<ChannelRecord> for Channel {
    fn from(rec: ChannelRecord) -> Self {
        let status = match rec.status.as_str() {
            "pending" => ChannelStatus::Pending,
            _ => ChannelStatus::Paired,
        };
        Self {
            id: ChannelId(rec.channel_id),
            transport: TransportProtocol {
                uri: rec.transport_uri,
                protocol: rec.transport_protocol,
            },
            name: rec.name,
            status,
            created_at: rec.created_at,
        }
    }
}

impl DeRecChannelStore for JsChannelStore {
    fn load(&self, channel_id: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
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
            let record: ChannelRecord = serde_json::from_slice(&bytes)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            Ok(Some(record.into()))
        })
    }

    fn channels(&self) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let obj = self.0.clone();
        Box::pin(async move {
            let args = Array::new();
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
                let record: ChannelRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
                let channel: Channel = record.into();
                // Sanity check: the stored channel_id must match the index key
                debug_assert_eq!(channel.id, channel_id);
                result.push(channel);
            }
            Ok(result)
        })
    }

    fn save(&mut self, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel.id.0.to_string();
        let record = ChannelRecord::from(&channel);
        Box::pin(async move {
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| ChannelStoreError::Backend(box_err(e.to_string())))?;
            let js_bytes = Uint8Array::from(bytes.as_slice());
            let args = Array::new();
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

    fn remove(&mut self, channel_id: ChannelId) -> ChannelStoreFuture<'_, bool> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            let promise_val = call_method(&obj, "remove", &args)
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ChannelStoreError::Backend(box_err(e)))?;
            Ok(value.as_bool().unwrap_or(false))
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
        versions: &[i32],
    ) -> ShareStoreFuture<'_, Vec<(i32, Vec<u8>)>> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        let versions_vec: Vec<i32> = versions.to_vec();
        Box::pin(async move {
            let js_versions = Array::new();
            for v in &versions_vec {
                js_versions.push(&JsValue::from_f64(*v as f64));
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
            args.push(&js_versions);
            let promise_val = call_method(&obj, "load", &args)
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            let value = resolve_promise(promise_val)
                .await
                .map_err(|e| ShareStoreError::Backend(box_err(e)))?;
            // Expects Array<[number, Uint8Array]>
            let arr = Array::from(&value);
            let mut result = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                let entry = Array::from(&arr.get(i));
                let v = entry.get(0).as_f64().ok_or_else(|| {
                    ShareStoreError::Backend(box_err("version must be a number".to_string()))
                })? as i32;
                let data = Uint8Array::new(&entry.get(1)).to_vec();
                result.push((v, data));
            }
            Ok(result)
        })
    }

    fn latest_version(&self) -> ShareStoreFuture<'_, Option<i32>> {
        let obj = self.0.clone();
        Box::pin(async move {
            let args = Array::new();
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
                    .ok_or_else(|| ShareStoreError::Backend(box_err("latestVersion must return a number or null".to_string())))?
                    as i32;
                Ok(Some(v))
            }
        })
    }

    fn save(
        &mut self,
        channel_id: ChannelId,
        version: i32,
        encoded: Vec<u8>,
    ) -> ShareStoreFuture<'_, ()> {
        let obj = self.0.clone();
        let channel_str = channel_id.0.to_string();
        Box::pin(async move {
            let js_encoded = Uint8Array::from(encoded.as_slice());
            let args = Array::new();
            args.push(&JsValue::from_str(&channel_str));
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
