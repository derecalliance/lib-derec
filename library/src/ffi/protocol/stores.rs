// SPDX-License-Identifier: Apache-2.0

//! Managed-callback adapters that satisfy the four core protocol traits
//! ([`DeRecChannelStore`], [`DeRecSecretStore`], [`DeRecShareStore`],
//! [`DeRecTransport`]) by delegating to C function pointers supplied by
//! the foreign caller.
//!
//! The wire format for complex types (Channel, Share, SecretValue) is
//! JSON. `Channel` rides serde directly — its derives produce a stable
//! shape with a top-level `id` (decimal-serialized u64), a nested
//! `transport: { uri, protocol }` object, and variant-name strings for
//! `status` and `role`. `Share` and `SecretValue` keep dedicated record
//! wrappers because their on-wire shapes differ from their in-memory
//! ones (e.g. `secret_id` is stringified for JS interop). The same
//! schema is consumed by the WASM bridge so a single C# / TS
//! deserializer covers both.

use std::os::raw::c_void;

use prost::Message as _;

use crate::protocol::{
    ChannelStoreError, ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore,
    DeRecShareStore, DeRecTransport, MissingPolicy, SecretKind, SecretStoreError,
    SecretStoreFuture, SecretValue, Share, ShareStoreError, ShareStoreFuture,
    TransportFuture,
};

/// Lightweight error wrapper so we can put owned strings into the
/// trait-object `Backend` variants — matches the WASM bridge's pattern.
#[derive(Debug)]
struct CallbackError(String);

impl std::fmt::Display for CallbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CallbackError {}

fn boxed_err(msg: String) -> Box<dyn std::error::Error + Send + Sync + 'static> {
    Box::new(CallbackError(msg))
}

/// Drives a load-style C callback that writes its result to
/// `(*out_ptr, *out_len)` and returns a status code, then copies the
/// bytes into a Rust `Vec` and releases the caller's buffer via
/// `free_buffer`. Return-code convention is the one documented on
/// every load callback in this module: `0` = success, `1` = not found,
/// anything else = backend failure. `label` is the store kind name
/// (e.g. `"channel store"`) used to disambiguate the error message.
fn fetch_callback_bytes(
    user_data: *mut c_void,
    free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
    label: &str,
    f: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
) -> Result<Option<Vec<u8>>, String> {
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;
    let rc = f(&mut ptr as *mut _, &mut len as *mut _);
    if rc == 0 {
        if ptr.is_null() || len == 0 {
            return Ok(Some(Vec::new()));
        }
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len).to_vec() };
        free_buffer(user_data, ptr, len);
        Ok(Some(bytes))
    } else if rc == 1 {
        if !ptr.is_null() && len != 0 {
            free_buffer(user_data, ptr, len);
        }
        Ok(None)
    } else {
        if !ptr.is_null() && len != 0 {
            free_buffer(user_data, ptr, len);
        }
        Err(format!("{label} callback failed (rc={rc})"))
    }
}
use crate::protocol::types::Channel;
use crate::types::ChannelId;
use derec_proto::TransportProtocol;

/// JSON-on-the-wire shape of a [`Share`] consumed by
/// [`DotnetShareStore`].
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct ShareRecord {
    pub secret_id: String,
    pub version: u32,
    pub bytes: Vec<u8>,
}

impl From<&Share> for ShareRecord {
    fn from(s: &Share) -> Self {
        Self {
            secret_id: s.secret_id.to_string(),
            version: s.version,
            bytes: s.bytes.clone(),
        }
    }
}

impl ShareRecord {
    #[allow(dead_code)]
    pub(crate) fn into_share(self) -> Result<Share, String> {
        let secret_id = self
            .secret_id
            .parse::<u64>()
            .map_err(|e| format!("share secret_id is not a decimal u64: {e}"))?;
        Ok(Share {
            secret_id,
            version: self.version,
            bytes: self.bytes,
        })
    }
}

/// JSON-on-the-wire shape of [`SecretValue`]. `kind` matches
/// [`SecretKind`]:
/// - `0` = SharedKey — `bytes` is the 32-byte symmetric key
/// - `1` = PairingSecret — `bytes` is the ark-serialize encoding of
///   [`PairingSecretKeyMaterial`]
/// - `2` = PairingContact — `bytes` is the prost-encoded
///   [`derec_proto::ContactMessage`]
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SecretValueRecord {
    pub kind: u32,
    pub bytes: Vec<u8>,
}

impl TryFrom<&SecretValue> for SecretValueRecord {
    type Error = String;

    fn try_from(v: &SecretValue) -> Result<Self, Self::Error> {
        match v {
            SecretValue::SharedKey(k) => Ok(Self {
                kind: 0,
                bytes: k.to_vec(),
            }),
            SecretValue::PairingSecret(sk) => {
                use ark_serialize::CanonicalSerialize as _;
                let mut buf = Vec::new();
                sk.serialize_compressed(&mut buf).map_err(|e| {
                    format!("failed to serialize PairingSecretKeyMaterial: {e}")
                })?;
                Ok(Self { kind: 1, bytes: buf })
            }
            SecretValue::PairingContact(c) => Ok(Self {
                kind: 2,
                bytes: c.encode_to_vec(),
            }),
        }
    }
}

impl SecretValueRecord {
    pub(crate) fn into_value(self) -> Result<SecretValue, String> {
        match self.kind {
            0 => {
                let arr: [u8; 32] = self
                    .bytes
                    .try_into()
                    .map_err(|_| "SharedKey payload must be 32 bytes".to_string())?;
                Ok(SecretValue::SharedKey(arr))
            }
            1 => {
                use ark_serialize::CanonicalDeserialize as _;
                let sk = derec_cryptography::pairing::PairingSecretKeyMaterial::deserialize_compressed(
                    self.bytes.as_slice(),
                )
                .map_err(|e| format!("failed to deserialize PairingSecretKeyMaterial: {e}"))?;
                Ok(SecretValue::PairingSecret(sk))
            }
            2 => {
                let cm = derec_proto::ContactMessage::decode(self.bytes.as_slice())
                    .map_err(|e| format!("failed to decode ContactMessage: {e}"))?;
                Ok(SecretValue::PairingContact(cm))
            }
            other => Err(format!("unknown SecretKind: {other}")),
        }
    }
}

fn secret_kind_to_u32(kind: SecretKind) -> u32 {
    match kind {
        SecretKind::SharedKey => 0,
        SecretKind::PairingSecret => 1,
        SecretKind::PairingContact => 2,
    }
}

/// Caller-supplied callbacks for channel persistence.
///
/// All function pointers are invoked synchronously from the protocol's
/// async core (the FFI shim drives futures with `block_on`). Buffer
/// ownership for any byte payload returned via out-parameters belongs
/// to the caller; the shim copies into a Rust `Vec` and then calls
/// [`Self::free_buffer`] to release the original allocation.
///
/// Return code convention:
/// - `0` on success
/// - `1` on "not found" (only meaningful for `load`)
/// - any other value indicates a backend failure; the shim wraps it as
///   [`ChannelStoreError::Backend`]
#[repr(C)]
pub struct ChannelStoreCallbacks {
    pub user_data: *mut c_void,
    /// Load the channel for `channel_id`. On success writes the
    /// JSON-encoded [`Channel`] bytes to `*out_ptr` / `*out_len`
    /// and returns 0. Return 1 with `*out_ptr = null` / `*out_len = 0`
    /// for "not found". Any other return code is a backend error.
    pub load: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// Persist `bytes` (a JSON-encoded [`Channel`]) under
    /// `channel_id`. Returns 0 on success.
    pub save: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        bytes: *const u8,
        len: usize,
    ) -> i32,
    /// Remove the channel for `channel_id`. Writes 1 to `*out_existed`
    /// if a channel was deleted, 0 if it didn't exist. Returns 0 on
    /// success.
    pub remove: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        out_existed: *mut u32,
    ) -> i32,
    /// List every channel id currently in the store. Writes a JSON
    /// `[u64, u64, ...]` array (lowercase decimal) to
    /// `*out_ptr` / `*out_len`. Returns 0 on success.
    pub list_channels: extern "C" fn(
        user_data: *mut c_void,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// Record an undirected link between two channels. Returns 0 on
    /// success.
    pub link_channel: extern "C" fn(user_data: *mut c_void, a: u64, b: u64) -> i32,
    /// Return the transitive closure (JSON `[u64, ...]`) of channel
    /// ids linked to `channel_id`, **including `channel_id` itself**.
    /// Returns 0 on success.
    pub linked_channels: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// Release a buffer the caller previously allocated for one of the
    /// `out_ptr` parameters above. The shim invokes this immediately
    /// after copying the bytes out.
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied callbacks for secret persistence.
#[repr(C)]
pub struct SecretStoreCallbacks {
    pub user_data: *mut c_void,
    /// Load a secret of `kind` for `channel_id`. On success writes the
    /// JSON-encoded [`SecretValueRecord`] to `*out_ptr` / `*out_len`
    /// and returns 0. Return 1 (with null out) for "not found".
    pub load: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        kind: u32,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// Persist `bytes` (a JSON-encoded [`SecretValueRecord`]) under
    /// `(channel_id, kind)`. Returns 0 on success.
    pub save: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        kind: u32,
        bytes: *const u8,
        len: usize,
    ) -> i32,
    pub remove: extern "C" fn(user_data: *mut c_void, channel_id: u64, kind: u32) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied callbacks for share persistence. Variable-length
/// arrays (`channel_ids[]`, `versions[]`) cross the FFI as JSON
/// strings, matching the `Vec<u8>` ↔ JSON-array convention used for
/// every other wire-format buffer in this module.
#[repr(C)]
pub struct ShareStoreCallbacks {
    pub user_data: *mut c_void,
    /// `load(channel_id, secret_id, versions_json_ptr, versions_json_len,
    ///       out_ptr, out_len)` — `versions_json` is a JSON `[u32, ...]`
    /// (empty array = all versions). Out is a JSON `[ShareRecord, ...]`.
    pub load: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        secret_id: u64,
        versions_json_ptr: *const u8,
        versions_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// `load_many(channel_ids_json, secret_id, versions_json, out)`
    pub load_many: extern "C" fn(
        user_data: *mut c_void,
        channel_ids_json_ptr: *const u8,
        channel_ids_json_len: usize,
        secret_id: u64,
        versions_json_ptr: *const u8,
        versions_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// `load_all(channel_ids_json, out)`
    pub load_all: extern "C" fn(
        user_data: *mut c_void,
        channel_ids_json_ptr: *const u8,
        channel_ids_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// `latest_version(out_has_version, out_version)`. Writes
    /// `*out_has_version = 1` and `*out_version = v` when a version
    /// exists; `*out_has_version = 0` when the store is empty.
    pub latest_version: extern "C" fn(
        user_data: *mut c_void,
        out_has_version: *mut u32,
        out_version: *mut u32,
    ) -> i32,
    /// `save(channel_id, share_json_ptr, share_json_len)`
    pub save: extern "C" fn(
        user_data: *mut c_void,
        channel_id: u64,
        share_json_ptr: *const u8,
        share_json_len: usize,
    ) -> i32,
    /// `remove_channel(channel_id)`
    pub remove_channel: extern "C" fn(user_data: *mut c_void, channel_id: u64) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied transport callback.
#[repr(C)]
pub struct TransportCallbacks {
    pub user_data: *mut c_void,
    pub send: extern "C" fn(
        user_data: *mut c_void,
        uri_ptr: *const u8,
        uri_len: usize,
        protocol: i32,
        bytes: *const u8,
        len: usize,
    ) -> i32,
}

pub struct DotnetChannelStore {
    pub(crate) cb: ChannelStoreCallbacks,
}

/// SAFETY: the foreign caller is responsible for ensuring `user_data`
/// and the function pointers it hands over satisfy `Send + Sync`.
unsafe impl Send for DotnetChannelStore {}
unsafe impl Sync for DotnetChannelStore {}

impl DotnetChannelStore {
    fn fetch_bytes(
        &self,
        f: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<Option<Vec<u8>>, String> {
        fetch_callback_bytes(self.cb.user_data, self.cb.free_buffer, "channel store", f)
    }
}

impl DeRecChannelStore for DotnetChannelStore {
    fn load(&self, channel_id: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.load)(self.cb.user_data, channel_id.0, p, l)
        });
        Box::pin(async move {
            match bytes_res {
                Err(e) => Err(ChannelStoreError::Backend(e.into())),
                Ok(None) => Ok(None),
                Ok(Some(bytes)) if bytes.is_empty() => Ok(None),
                Ok(Some(bytes)) => {
                    let channel: Channel = serde_json::from_slice(&bytes)
                        .map_err(|e| {
                            ChannelStoreError::Backend(
                                format!("invalid Channel JSON: {e}").into(),
                            )
                        })?;
                    Ok(Some(channel))
                }
            }
        })
    }

    fn save(&mut self, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let channel_id = channel.id.0;
        let cb = &self.cb;
        let res = (|| -> Result<(), ChannelStoreError> {
            let bytes = serde_json::to_vec(&channel).map_err(|e| {
                ChannelStoreError::Backend(format!("Channel JSON: {e}").into())
            })?;
            let rc = (cb.save)(cb.user_data, channel_id, bytes.as_ptr(), bytes.len());
            if rc != 0 {
                return Err(ChannelStoreError::Backend(
                    format!("channel store save failed (rc={rc})").into(),
                ));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove(&mut self, channel_id: ChannelId) -> ChannelStoreFuture<'_, bool> {
        let cb = &self.cb;
        let res = (|| -> Result<bool, ChannelStoreError> {
            let mut existed: u32 = 0;
            let rc = (cb.remove)(cb.user_data, channel_id.0, &mut existed as *mut _);
            if rc != 0 {
                return Err(ChannelStoreError::Backend(
                    format!("channel store remove failed (rc={rc})").into(),
                ));
            }
            Ok(existed != 0)
        })();
        Box::pin(async move { res })
    }

    fn channels(&self) -> ChannelStoreFuture<'_, Vec<Channel>> {
        // The FFI surface exposes `list_channels` and a per-id `load`,
        // so the trait's `channels()` materializes by enumerating the
        // ids and loading each record.
        let list_bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.list_channels)(self.cb.user_data, p, l)
        });
        // `fetch_bytes` returns Ok(None) only when the C side returned
        // 1; list_channels has no "not found" semantics — treat it as
        // an empty list.
        let cb = &self.cb;
        let res = (|| -> Result<Vec<Channel>, ChannelStoreError> {
            let bytes = match list_bytes_res {
                Err(e) => return Err(ChannelStoreError::Backend(boxed_err(e))),
                Ok(None) => Vec::new(),
                Ok(Some(b)) => b,
            };
            let ids: Vec<u64> = if bytes.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&bytes).map_err(|e| {
                    ChannelStoreError::Backend(format!("list_channels JSON: {e}").into())
                })?
            };
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let mut ptr: *mut u8 = std::ptr::null_mut();
                let mut len: usize = 0;
                let rc = (cb.load)(cb.user_data, id, &mut ptr as *mut _, &mut len as *mut _);
                if rc != 0 {
                    if !ptr.is_null() && len != 0 {
                        (cb.free_buffer)(cb.user_data, ptr, len);
                    }
                    continue;
                }
                if ptr.is_null() || len == 0 {
                    continue;
                }
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len).to_vec() };
                (cb.free_buffer)(cb.user_data, ptr, len);
                let channel: Channel = serde_json::from_slice(&bytes).map_err(|e| {
                    ChannelStoreError::Backend(format!("Channel JSON: {e}").into())
                })?;
                out.push(channel);
            }
            Ok(out)
        })();
        Box::pin(async move { res })
    }

    fn link_channel(&mut self, a: ChannelId, b: ChannelId) -> ChannelStoreFuture<'_, ()> {
        let cb = &self.cb;
        let rc = (cb.link_channel)(cb.user_data, a.0, b.0);
        Box::pin(async move {
            if rc != 0 {
                Err(ChannelStoreError::Backend(
                    format!("link_channel failed (rc={rc})").into(),
                ))
            } else {
                Ok(())
            }
        })
    }

    fn linked_channels(
        &self,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.linked_channels)(self.cb.user_data, channel_id.0, p, l)
        });
        Box::pin(async move {
            let bytes = match bytes_res {
                Err(e) => return Err(ChannelStoreError::Backend(boxed_err(e))),
                Ok(None) => Vec::new(),
                Ok(Some(b)) => b,
            };
            if bytes.is_empty() {
                return Ok(vec![channel_id]);
            }
            let ids: Vec<u64> = serde_json::from_slice(&bytes).map_err(|e| {
                ChannelStoreError::Backend(boxed_err(format!(
                    "linked_channels JSON: {e}"
                )))
            })?;
            Ok(ids.into_iter().map(ChannelId).collect())
        })
    }
}

pub struct DotnetSecretStore {
    pub(crate) cb: SecretStoreCallbacks,
}

unsafe impl Send for DotnetSecretStore {}
unsafe impl Sync for DotnetSecretStore {}

impl DotnetSecretStore {
    fn fetch_bytes(
        &self,
        f: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<Option<Vec<u8>>, String> {
        fetch_callback_bytes(self.cb.user_data, self.cb.free_buffer, "secret store", f)
    }
}

impl DeRecSecretStore for DotnetSecretStore {
    fn load(
        &self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let kind_u32 = secret_kind_to_u32(kind);
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.load)(self.cb.user_data, channel_id.0, kind_u32, p, l)
        });
        Box::pin(async move {
            match bytes_res {
                Err(e) => Err(SecretStoreError::Backend(e.into())),
                Ok(None) => Ok(None),
                Ok(Some(bytes)) if bytes.is_empty() => Ok(None),
                Ok(Some(bytes)) => {
                    let record: SecretValueRecord = serde_json::from_slice(&bytes)
                        .map_err(|e| {
                            SecretStoreError::Backend(
                                format!("SecretValue JSON: {e}").into(),
                            )
                        })?;
                    let value = record.into_value().map_err(|e| {
                        SecretStoreError::Backend(format!("SecretValue: {e}").into())
                    })?;
                    Ok(Some(value))
                }
            }
        })
    }

    fn load_many(
        &self,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let ids = channel_ids.to_vec();
        let kind_u32 = secret_kind_to_u32(kind);
        let cb = &self.cb;
        let res = (|| -> Result<Vec<(ChannelId, SecretValue)>, SecretStoreError> {
            let mut out = Vec::with_capacity(ids.len());
            let mut missing: Vec<ChannelId> = Vec::new();
            for id in &ids {
                let mut ptr: *mut u8 = std::ptr::null_mut();
                let mut len: usize = 0;
                let rc = (cb.load)(
                    cb.user_data,
                    id.0,
                    kind_u32,
                    &mut ptr as *mut _,
                    &mut len as *mut _,
                );
                if rc == 1 {
                    if !ptr.is_null() && len != 0 {
                        (cb.free_buffer)(cb.user_data, ptr, len);
                    }
                    missing.push(*id);
                    continue;
                }
                if rc != 0 {
                    if !ptr.is_null() && len != 0 {
                        (cb.free_buffer)(cb.user_data, ptr, len);
                    }
                    return Err(SecretStoreError::Backend(
                        format!("secret store load failed (rc={rc})").into(),
                    ));
                }
                if ptr.is_null() || len == 0 {
                    missing.push(*id);
                    continue;
                }
                let bytes = unsafe { std::slice::from_raw_parts(ptr, len).to_vec() };
                (cb.free_buffer)(cb.user_data, ptr, len);
                let record: SecretValueRecord = serde_json::from_slice(&bytes)
                    .map_err(|e| {
                        SecretStoreError::Backend(format!("SecretValue JSON: {e}").into())
                    })?;
                let value = record.into_value().map_err(|e| {
                    SecretStoreError::Backend(format!("SecretValue: {e}").into())
                })?;
                out.push((*id, value));
            }
            if !missing.is_empty() && matches!(missing_policy, MissingPolicy::Fail) {
                return Err(SecretStoreError::MissingEntries {
                    kind,
                    channel_ids: missing.into_iter().map(|c| c.0).collect(),
                });
            }
            Ok(out)
        })();
        Box::pin(async move { res })
    }

    fn save(
        &mut self,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        let cb = &self.cb;
        let res = (|| -> Result<(), SecretStoreError> {
            let record = SecretValueRecord::try_from(&value)
                .map_err(|e| SecretStoreError::Backend(boxed_err(e)))?;
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                SecretStoreError::Backend(boxed_err(format!("SecretValue JSON: {e}")))
            })?;
            let rc = (cb.save)(
                cb.user_data,
                channel_id.0,
                record.kind,
                bytes.as_ptr(),
                bytes.len(),
            );
            if rc != 0 {
                return Err(SecretStoreError::Backend(boxed_err(format!(
                    "secret store save failed (rc={rc})"
                ))));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove(
        &mut self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        let kind_u32 = secret_kind_to_u32(kind);
        let cb = &self.cb;
        let rc = (cb.remove)(cb.user_data, channel_id.0, kind_u32);
        Box::pin(async move {
            if rc != 0 {
                Err(SecretStoreError::Backend(
                    format!("secret store remove failed (rc={rc})").into(),
                ))
            } else {
                Ok(())
            }
        })
    }
}

/// Real DotnetShareStore — bridges to managed C# callbacks via the
/// function pointers in [`ShareStoreCallbacks`].
pub struct DotnetShareStore {
    pub(crate) cb: ShareStoreCallbacks,
}

unsafe impl Send for DotnetShareStore {}
unsafe impl Sync for DotnetShareStore {}

impl DotnetShareStore {
    fn fetch_share_list(&self, bytes: Result<Option<Vec<u8>>, String>) -> Result<Vec<Share>, ShareStoreError> {
        let bytes = match bytes {
            Err(e) => return Err(ShareStoreError::Backend(boxed_err(e))),
            Ok(None) => return Ok(Vec::new()),
            Ok(Some(b)) => b,
        };
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let records: Vec<ShareRecord> = serde_json::from_slice(&bytes).map_err(|e| {
            ShareStoreError::Backend(boxed_err(format!("ShareRecord JSON: {e}")))
        })?;
        records
            .into_iter()
            .map(|r| r.into_share().map_err(|e| ShareStoreError::Backend(boxed_err(e))))
            .collect()
    }

    fn fetch_bytes(
        &self,
        f: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<Option<Vec<u8>>, String> {
        fetch_callback_bytes(self.cb.user_data, self.cb.free_buffer, "share store", f)
    }
}

impl DeRecShareStore for DotnetShareStore {
    fn load(
        &self,
        channel_id: ChannelId,
        secret_id: u64,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let versions_json = serde_json::to_vec(versions).unwrap_or_else(|_| b"[]".to_vec());
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load)(
                self.cb.user_data,
                channel_id.0,
                secret_id,
                versions_json.as_ptr(),
                versions_json.len(),
                p,
                l,
            )
        });
        let res = self.fetch_share_list(result);
        Box::pin(async move { res })
    }

    fn load_many(
        &self,
        channel_ids: &[ChannelId],
        secret_id: u64,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids_json: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let channel_ids_bytes = serde_json::to_vec(&channel_ids_json).unwrap_or_default();
        let versions_json = serde_json::to_vec(versions).unwrap_or_else(|_| b"[]".to_vec());
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load_many)(
                self.cb.user_data,
                channel_ids_bytes.as_ptr(),
                channel_ids_bytes.len(),
                secret_id,
                versions_json.as_ptr(),
                versions_json.len(),
                p,
                l,
            )
        });
        let res = self.fetch_share_list(result);
        Box::pin(async move { res })
    }

    fn load_all(&self, channel_ids: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids_json: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let channel_ids_bytes = serde_json::to_vec(&channel_ids_json).unwrap_or_default();
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load_all)(
                self.cb.user_data,
                channel_ids_bytes.as_ptr(),
                channel_ids_bytes.len(),
                p,
                l,
            )
        });
        let res = self.fetch_share_list(result);
        Box::pin(async move { res })
    }

    fn latest_version(&self) -> ShareStoreFuture<'_, Option<u32>> {
        let cb = &self.cb;
        let mut has: u32 = 0;
        let mut version: u32 = 0;
        let rc = (cb.latest_version)(
            cb.user_data,
            &mut has as *mut _,
            &mut version as *mut _,
        );
        Box::pin(async move {
            if rc != 0 {
                Err(ShareStoreError::Backend(boxed_err(format!(
                    "latest_version failed (rc={rc})"
                ))))
            } else if has != 0 {
                Ok(Some(version))
            } else {
                Ok(None)
            }
        })
    }

    fn save(&mut self, channel_id: ChannelId, share: Share) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let res = (|| -> Result<(), ShareStoreError> {
            let record = ShareRecord::from(&share);
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                ShareStoreError::Backend(boxed_err(format!("Share JSON: {e}")))
            })?;
            let rc = (cb.save)(cb.user_data, channel_id.0, bytes.as_ptr(), bytes.len());
            if rc != 0 {
                return Err(ShareStoreError::Backend(boxed_err(format!(
                    "share store save failed (rc={rc})"
                ))));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove_channel(&mut self, channel_id: ChannelId) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let rc = (cb.remove_channel)(cb.user_data, channel_id.0);
        Box::pin(async move {
            if rc != 0 {
                Err(ShareStoreError::Backend(boxed_err(format!(
                    "share store remove_channel failed (rc={rc})"
                ))))
            } else {
                Ok(())
            }
        })
    }
}

/// Transport adapter for the FFI bridge — `send` invokes the
/// foreign callback directly with no buffering.
pub struct DotnetTransport {
    pub(crate) cb: TransportCallbacks,
}

unsafe impl Send for DotnetTransport {}
unsafe impl Sync for DotnetTransport {}

impl DeRecTransport for DotnetTransport {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        let cb = &self.cb;
        let uri = endpoint.uri.clone();
        let protocol = endpoint.protocol;
        let rc = (cb.send)(
            cb.user_data,
            uri.as_ptr(),
            uri.len(),
            protocol,
            message.as_ptr(),
            message.len(),
        );
        Box::pin(async move {
            if rc != 0 {
                // crate::Error's variants take &'static str, so we lose
                // the dynamic rc in the surface error — callers can log
                // it through the transport callback's own side channel.
                Err(crate::Error::Invariant("transport send failed"))
            } else {
                Ok(())
            }
        })
    }
}
