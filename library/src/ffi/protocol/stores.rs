// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
    DeRecShareStore, DeRecStateStore, DeRecTransport, DeRecUserSecretStore, MissingPolicy,
    SecretKind, SecretStoreError, SecretStoreFuture, SecretValue, Share, ShareStoreError,
    ShareStoreFuture, StateItem, StateKey, StateKind, StateStoreError, StateStoreFuture,
    TransportFuture,
};
use crate::protocol::types::{UserSecret, UserSecrets};

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
            replica_id: None,
            bytes: self.bytes,
        })
    }
}

/// JSON-on-the-wire shape of [`SecretValue`]. `kind` matches
/// [`SecretKind`]:
/// - `0` = SharedKey — `bytes` is the 32-byte symmetric key
/// - `1` = PairingSecret — `bytes` is the opaque
///   [`PairingKeyMaterial`](crate::protocol::PairingKeyMaterial) blob
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
            SecretValue::PairingSecret(sk) => Ok(Self {
                kind: 1,
                bytes: sk.as_bytes().to_vec(),
            }),
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
            1 => Ok(SecretValue::PairingSecret(
                crate::protocol::PairingKeyMaterial::from_bytes(self.bytes),
            )),
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

/// JSON-on-the-wire shape of a [`StateKey`]. `kind` matches
/// [`StateKind`]:
/// - `0` = PendingVerification — `channel_id` present (stringified u64)
/// - `1` = PendingRecovery — `version` present
/// - `2` = PendingUnpair — `channel_id` present (stringified u64)
/// - `3` = SharingRound — no secondary key
///
/// Absent fields are serialized as JSON `null` on outbound and are
/// required-per-kind on inbound.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct StateKeyRecord {
    pub kind: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl From<&StateKey> for StateKeyRecord {
    fn from(k: &StateKey) -> Self {
        match k {
            StateKey::PendingVerification { channel_id } => Self {
                kind: 0,
                channel_id: Some(channel_id.0.to_string()),
                version: None,
            },
            StateKey::PendingRecovery { version } => Self {
                kind: 1,
                channel_id: None,
                version: Some(*version),
            },
            StateKey::PendingUnpair { channel_id } => Self {
                kind: 2,
                channel_id: Some(channel_id.0.to_string()),
                version: None,
            },
            StateKey::SharingRound => Self {
                kind: 3,
                channel_id: None,
                version: None,
            },
        }
    }
}

/// JSON-on-the-wire shape of a [`StateItem`]. `kind` matches
/// [`StateKind`] (identical numbering to [`StateKeyRecord::kind`]):
/// - `0` = PendingVerification — `channel_id`, `bytes` (prost-encoded
///   [`derec_proto::VerifyShareRequestMessage`])
/// - `1` = PendingRecovery — `version`, `shares` (each entry is a
///   prost-encoded [`derec_proto::GetShareResponseMessage`])
/// - `2` = PendingUnpair — `channel_id`, `started_at` (stringified u64
///   unix-seconds)
/// - `3` = SharingRound — `version`, `pending`, `confirmed`, `failed`
///   (each channel-id set is stringified u64s), `started_at`
///   (stringified u64 unix-seconds)
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct StateItemRecord {
    pub kind: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<Vec<u8>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<Vec<String>>,
}

impl From<&StateItem> for StateItemRecord {
    fn from(v: &StateItem) -> Self {
        match v {
            StateItem::PendingVerification { channel_id, request } => Self {
                kind: 0,
                channel_id: Some(channel_id.0.to_string()),
                version: None,
                started_at: None,
                bytes: Some(request.encode_to_vec()),
                shares: None,
                pending: None,
                confirmed: None,
                failed: None,
            },
            StateItem::PendingRecovery { version, shares } => Self {
                kind: 1,
                channel_id: None,
                version: Some(*version),
                started_at: None,
                bytes: None,
                shares: Some(shares.iter().map(|s| s.encode_to_vec()).collect()),
                pending: None,
                confirmed: None,
                failed: None,
            },
            StateItem::PendingUnpair { channel_id, started_at } => Self {
                kind: 2,
                channel_id: Some(channel_id.0.to_string()),
                version: None,
                started_at: Some(started_at.to_string()),
                bytes: None,
                shares: None,
                pending: None,
                confirmed: None,
                failed: None,
            },
            StateItem::SharingRound {
                version,
                pending,
                confirmed,
                failed,
                started_at,
            } => Self {
                kind: 3,
                channel_id: None,
                version: Some(*version),
                started_at: Some(started_at.to_string()),
                bytes: None,
                shares: None,
                pending: Some(pending.iter().map(|c| c.0.to_string()).collect()),
                confirmed: Some(confirmed.iter().map(|c| c.0.to_string()).collect()),
                failed: Some(failed.iter().map(|c| c.0.to_string()).collect()),
            },
        }
    }
}

fn parse_channel_id_set(
    raw: Option<Vec<String>>,
    field: &str,
) -> Result<std::collections::HashSet<ChannelId>, String> {
    raw.ok_or_else(|| format!("SharingRound requires {field}"))?
        .into_iter()
        .map(|s| {
            s.parse::<u64>()
                .map(ChannelId)
                .map_err(|e| format!("{field} entry not a decimal u64: {e}"))
        })
        .collect()
}

impl StateItemRecord {
    pub(crate) fn into_item(self) -> Result<StateItem, String> {
        match self.kind {
            0 => {
                let channel_id_str = self
                    .channel_id
                    .ok_or_else(|| "PendingVerification requires channel_id".to_string())?;
                let channel_id = channel_id_str
                    .parse::<u64>()
                    .map(ChannelId)
                    .map_err(|e| format!("channel_id not a decimal u64: {e}"))?;
                let bytes = self
                    .bytes
                    .ok_or_else(|| "PendingVerification requires bytes".to_string())?;
                let request =
                    derec_proto::VerifyShareRequestMessage::decode(bytes.as_slice())
                        .map_err(|e| format!("VerifyShareRequestMessage decode: {e}"))?;
                Ok(StateItem::PendingVerification { channel_id, request })
            }
            1 => {
                let version = self
                    .version
                    .ok_or_else(|| "PendingRecovery requires version".to_string())?;
                let raw_shares = self
                    .shares
                    .ok_or_else(|| "PendingRecovery requires shares".to_string())?;
                let mut shares = Vec::with_capacity(raw_shares.len());
                for (i, blob) in raw_shares.into_iter().enumerate() {
                    let msg = derec_proto::GetShareResponseMessage::decode(blob.as_slice())
                        .map_err(|e| format!("GetShareResponseMessage[{i}] decode: {e}"))?;
                    shares.push(msg);
                }
                Ok(StateItem::PendingRecovery { version, shares })
            }
            2 => {
                let channel_id_str = self
                    .channel_id
                    .ok_or_else(|| "PendingUnpair requires channel_id".to_string())?;
                let channel_id = channel_id_str
                    .parse::<u64>()
                    .map(ChannelId)
                    .map_err(|e| format!("channel_id not a decimal u64: {e}"))?;
                let started_at_str = self
                    .started_at
                    .ok_or_else(|| "PendingUnpair requires started_at".to_string())?;
                let started_at = started_at_str
                    .parse::<u64>()
                    .map_err(|e| format!("started_at not a decimal u64: {e}"))?;
                Ok(StateItem::PendingUnpair { channel_id, started_at })
            }
            3 => {
                let version = self
                    .version
                    .ok_or_else(|| "SharingRound requires version".to_string())?;
                let started_at_str = self
                    .started_at
                    .ok_or_else(|| "SharingRound requires started_at".to_string())?;
                let started_at = started_at_str
                    .parse::<u64>()
                    .map_err(|e| format!("started_at not a decimal u64: {e}"))?;
                let pending = parse_channel_id_set(self.pending, "pending")?;
                let confirmed = parse_channel_id_set(self.confirmed, "confirmed")?;
                let failed = parse_channel_id_set(self.failed, "failed")?;
                Ok(StateItem::SharingRound {
                    version,
                    pending,
                    confirmed,
                    failed,
                    started_at,
                })
            }
            other => Err(format!("unknown StateKind: {other}")),
        }
    }
}

fn state_kind_to_u32(kind: StateKind) -> u32 {
    match kind {
        StateKind::PendingVerification => 0,
        StateKind::PendingRecovery => 1,
        StateKind::PendingUnpair => 2,
        StateKind::SharingRound => 3,
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
    pub load: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub save: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        bytes: *const u8,
        len: usize,
    ) -> i32,
    pub remove: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        out_existed: *mut u32,
    ) -> i32,
    pub list_channels: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub link_channel: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        a: u64,
        b: u64,
    ) -> i32,
    pub linked_channels: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied callbacks for secret persistence.
#[repr(C)]
pub struct SecretStoreCallbacks {
    pub user_data: *mut c_void,
    pub load: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        kind: u32,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub save: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        kind: u32,
        bytes: *const u8,
        len: usize,
    ) -> i32,
    pub remove: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        kind: u32,
    ) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied callbacks for share persistence. Variable-length
/// arrays (`channel_ids[]`, `versions[]`) cross the FFI as JSON
/// strings, matching the `Vec<u8>` ↔ JSON-array convention used for
/// every other wire-format buffer in this module.
#[repr(C)]
pub struct ShareStoreCallbacks {
    pub user_data: *mut c_void,
    pub load: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        versions_json_ptr: *const u8,
        versions_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub load_many: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_ids_json_ptr: *const u8,
        channel_ids_json_len: usize,
        versions_json_ptr: *const u8,
        versions_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub load_all: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_ids_json_ptr: *const u8,
        channel_ids_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub latest_version: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        out_has_version: *mut u32,
        out_version: *mut u32,
    ) -> i32,
    pub save: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        share_json_ptr: *const u8,
        share_json_len: usize,
    ) -> i32,
    pub remove_channel: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
    ) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// Caller-supplied callbacks for the user-secret store. Methods cross
/// the FFI keyed by `secret_id`; the `UserSecrets` payload travels as a
/// JSON buffer matching [`UserSecretsRecord`].
#[repr(C)]
pub struct UserSecretStoreCallbacks {
    pub user_data: *mut c_void,
    /// `load_latest(secret_id, out_ptr, out_len)` — writes the JSON
    /// payload (or `out_len = 0` if absent). Caller releases the buffer
    /// via `free_buffer`.
    pub load_latest: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    /// `save_latest(secret_id, value_json_ptr, value_json_len)`.
    pub save_latest: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        value_json_ptr: *const u8,
        value_json_len: usize,
    ) -> i32,
    /// `remove(secret_id)` — idempotent.
    pub remove: extern "C" fn(user_data: *mut c_void, secret_id: u64) -> i32,
    pub free_buffer: extern "C" fn(user_data: *mut c_void, ptr: *mut u8, len: usize),
}

/// JSON-on-the-wire shape of [`UserSecrets`] consumed by
/// [`DotnetUserSecretStore`].
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct UserSecretsRecord {
    pub version: u32,
    pub secrets: Vec<UserSecretRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct UserSecretRecord {
    pub id: Vec<u8>,
    pub name: String,
    pub data: Vec<u8>,
}

impl From<&UserSecrets> for UserSecretsRecord {
    fn from(v: &UserSecrets) -> Self {
        Self {
            version: v.version,
            secrets: v
                .secrets
                .iter()
                .map(|s| UserSecretRecord {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    data: s.data.clone(),
                })
                .collect(),
            description: v.description.clone(),
        }
    }
}

impl From<UserSecretsRecord> for UserSecrets {
    fn from(r: UserSecretsRecord) -> Self {
        Self {
            version: r.version,
            secrets: r
                .secrets
                .into_iter()
                .map(|s| UserSecret {
                    id: s.id,
                    name: s.name,
                    data: s.data,
                })
                .collect(),
            description: r.description,
            // The FFI side trades only the user-facing snapshot for
            // now; the `replicas` cache is rebuilt on the next
            // ProtectSecret round from live channel state.
            replicas: None,
        }
    }
}

/// Caller-supplied callbacks for orchestrator in-flight state
/// ([`DeRecStateStore`]). The item and key travel as JSON buffers
/// matching [`StateItemRecord`] / [`StateKeyRecord`].
///
/// # Return codes
///
/// - `load`: `0` = found (record written), `1` = not found (empty
///   payload), other = backend failure.
/// - `remove`: `0` = ok (`*out_removed` set to `0` or `1`), other =
///   backend failure.
/// - `save` / `load_all`: `0` = ok, other = backend failure.
#[repr(C)]
pub struct StateStoreCallbacks {
    pub user_data: *mut c_void,
    pub save: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        item_json_ptr: *const u8,
        item_json_len: usize,
    ) -> i32,
    pub load: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        key_json_ptr: *const u8,
        key_json_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub remove: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        key_json_ptr: *const u8,
        key_json_len: usize,
        out_removed: *mut u32,
    ) -> i32,
    pub load_all: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        kind: u32,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
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
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>> {
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.load)(self.cb.user_data, secret_id, channel_id.0, p, l)
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

    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        let channel_id = channel.id.0;
        let cb = &self.cb;
        let res = (|| -> Result<(), ChannelStoreError> {
            let bytes = serde_json::to_vec(&channel).map_err(|e| {
                ChannelStoreError::Backend(format!("Channel JSON: {e}").into())
            })?;
            let rc = (cb.save)(cb.user_data, secret_id, channel_id, bytes.as_ptr(), bytes.len());
            if rc != 0 {
                return Err(ChannelStoreError::Backend(
                    format!("channel store save failed (rc={rc})").into(),
                ));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool> {
        let cb = &self.cb;
        let res = (|| -> Result<bool, ChannelStoreError> {
            let mut existed: u32 = 0;
            let rc = (cb.remove)(
                cb.user_data,
                secret_id,
                channel_id.0,
                &mut existed as *mut _,
            );
            if rc != 0 {
                return Err(ChannelStoreError::Backend(
                    format!("channel store remove failed (rc={rc})").into(),
                ));
            }
            Ok(existed != 0)
        })();
        Box::pin(async move { res })
    }

    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let list_bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.list_channels)(self.cb.user_data, secret_id, p, l)
        });
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
                let rc = (cb.load)(
                    cb.user_data,
                    secret_id,
                    id,
                    &mut ptr as *mut _,
                    &mut len as *mut _,
                );
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

    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        let cb = &self.cb;
        let rc = (cb.link_channel)(cb.user_data, secret_id, a.0, b.0);
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
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.linked_channels)(self.cb.user_data, secret_id, channel_id.0, p, l)
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
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let kind_u32 = secret_kind_to_u32(kind);
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.load)(self.cb.user_data, secret_id, channel_id.0, kind_u32, p, l)
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
        secret_id: u64,
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
                    secret_id,
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
        secret_id: u64,
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
                secret_id,
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
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        let kind_u32 = secret_kind_to_u32(kind);
        let cb = &self.cb;
        let rc = (cb.remove)(cb.user_data, secret_id, channel_id.0, kind_u32);
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
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let versions_json = serde_json::to_vec(versions).unwrap_or_else(|_| b"[]".to_vec());
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load)(
                self.cb.user_data,
                secret_id,
                channel_id.0,
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
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids_json: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let channel_ids_bytes = serde_json::to_vec(&channel_ids_json).unwrap_or_default();
        let versions_json = serde_json::to_vec(versions).unwrap_or_else(|_| b"[]".to_vec());
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load_many)(
                self.cb.user_data,
                secret_id,
                channel_ids_bytes.as_ptr(),
                channel_ids_bytes.len(),
                versions_json.as_ptr(),
                versions_json.len(),
                p,
                l,
            )
        });
        let res = self.fetch_share_list(result);
        Box::pin(async move { res })
    }

    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let channel_ids_json: Vec<u64> = channel_ids.iter().map(|c| c.0).collect();
        let channel_ids_bytes = serde_json::to_vec(&channel_ids_json).unwrap_or_default();
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load_all)(
                self.cb.user_data,
                secret_id,
                channel_ids_bytes.as_ptr(),
                channel_ids_bytes.len(),
                p,
                l,
            )
        });
        let res = self.fetch_share_list(result);
        Box::pin(async move { res })
    }

    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        let cb = &self.cb;
        let mut has: u32 = 0;
        let mut version: u32 = 0;
        let rc = (cb.latest_version)(
            cb.user_data,
            secret_id,
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

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let res = (|| -> Result<(), ShareStoreError> {
            let record = ShareRecord::from(&share);
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                ShareStoreError::Backend(boxed_err(format!("Share JSON: {e}")))
            })?;
            let rc = (cb.save)(
                cb.user_data,
                secret_id,
                channel_id.0,
                bytes.as_ptr(),
                bytes.len(),
            );
            if rc != 0 {
                return Err(ShareStoreError::Backend(boxed_err(format!(
                    "share store save failed (rc={rc})"
                ))));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let rc = (cb.remove_channel)(cb.user_data, secret_id, channel_id.0);
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

/// User-secret store adapter for the FFI bridge.
pub struct DotnetUserSecretStore {
    pub(crate) cb: UserSecretStoreCallbacks,
}

unsafe impl Send for DotnetUserSecretStore {}
unsafe impl Sync for DotnetUserSecretStore {}

impl DotnetUserSecretStore {
    fn fetch_bytes(
        &self,
        f: impl FnOnce(*mut *mut u8, *mut usize) -> i32,
    ) -> Result<Option<Vec<u8>>, String> {
        fetch_callback_bytes(self.cb.user_data, self.cb.free_buffer, "user secret store", f)
    }
}

impl DeRecUserSecretStore for DotnetUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let result = self.fetch_bytes(|p, l| {
            (self.cb.load_latest)(self.cb.user_data, secret_id, p, l)
        });
        let res = match result {
            Err(e) => Err(ShareStoreError::Backend(boxed_err(e))),
            Ok(None) => Ok(None),
            Ok(Some(bytes)) if bytes.is_empty() => Ok(None),
            Ok(Some(bytes)) => serde_json::from_slice::<UserSecretsRecord>(&bytes)
                .map(|r| Some(r.into()))
                .map_err(|e| ShareStoreError::Backend(boxed_err(format!("UserSecrets JSON: {e}")))),
        };
        Box::pin(async move { res })
    }

    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let res = (|| -> Result<(), ShareStoreError> {
            let record = UserSecretsRecord::from(&value);
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                ShareStoreError::Backend(boxed_err(format!("UserSecrets JSON: {e}")))
            })?;
            let rc = (cb.save_latest)(cb.user_data, secret_id, bytes.as_ptr(), bytes.len());
            if rc != 0 {
                return Err(ShareStoreError::Backend(boxed_err(format!(
                    "user secret store save_latest failed (rc={rc})"
                ))));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        let cb = &self.cb;
        let rc = (cb.remove)(cb.user_data, secret_id);
        Box::pin(async move {
            if rc != 0 {
                Err(ShareStoreError::Backend(boxed_err(format!(
                    "user secret store remove failed (rc={rc})"
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

/// Managed-callback adapter for the orchestrator state store. Wire
/// format matches [`StateItemRecord`] / [`StateKeyRecord`] — JSON
/// buffers with protobuf-encoded payloads inside byte arrays.
pub struct DotnetStateStore {
    pub(crate) cb: StateStoreCallbacks,
}

unsafe impl Send for DotnetStateStore {}
unsafe impl Sync for DotnetStateStore {}

impl DeRecStateStore for DotnetStateStore {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        let cb = &self.cb;
        let res = (|| -> Result<(), StateStoreError> {
            let record = StateItemRecord::from(&item);
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                StateStoreError::Backend(boxed_err(format!("StateItem JSON: {e}")))
            })?;
            let rc = (cb.save)(cb.user_data, secret_id, bytes.as_ptr(), bytes.len());
            if rc != 0 {
                return Err(StateStoreError::Backend(boxed_err(format!(
                    "state store save failed (rc={rc})"
                ))));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let cb = &self.cb;
        let res = (|| -> Result<Option<StateItem>, StateStoreError> {
            let key_record = StateKeyRecord::from(&key);
            let key_bytes = serde_json::to_vec(&key_record).map_err(|e| {
                StateStoreError::Backend(boxed_err(format!("StateKey JSON: {e}")))
            })?;
            let bytes = fetch_callback_bytes(
                cb.user_data,
                cb.free_buffer,
                "state store",
                |p, l| {
                    (cb.load)(
                        cb.user_data,
                        secret_id,
                        key_bytes.as_ptr(),
                        key_bytes.len(),
                        p,
                        l,
                    )
                },
            )
            .map_err(|e| StateStoreError::Backend(boxed_err(e)))?;
            let Some(bytes) = bytes else { return Ok(None) };
            if bytes.is_empty() {
                return Ok(None);
            }
            let record: StateItemRecord = serde_json::from_slice(&bytes).map_err(|e| {
                StateStoreError::Backend(boxed_err(format!("StateItem JSON: {e}")))
            })?;
            let item = record
                .into_item()
                .map_err(|e| StateStoreError::Backend(boxed_err(e)))?;
            Ok(Some(item))
        })();
        Box::pin(async move { res })
    }

    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let cb = &self.cb;
        let res = (|| -> Result<bool, StateStoreError> {
            let key_record = StateKeyRecord::from(&key);
            let key_bytes = serde_json::to_vec(&key_record).map_err(|e| {
                StateStoreError::Backend(boxed_err(format!("StateKey JSON: {e}")))
            })?;
            let mut removed: u32 = 0;
            let rc = (cb.remove)(
                cb.user_data,
                secret_id,
                key_bytes.as_ptr(),
                key_bytes.len(),
                &mut removed as *mut _,
            );
            if rc != 0 {
                return Err(StateStoreError::Backend(boxed_err(format!(
                    "state store remove failed (rc={rc})"
                ))));
            }
            Ok(removed != 0)
        })();
        Box::pin(async move { res })
    }

    fn load_all(
        &self,
        secret_id: u64,
        kind: StateKind,
    ) -> StateStoreFuture<'_, Vec<StateItem>> {
        let cb = &self.cb;
        let kind_u32 = state_kind_to_u32(kind);
        let res = (|| -> Result<Vec<StateItem>, StateStoreError> {
            let bytes = fetch_callback_bytes(
                cb.user_data,
                cb.free_buffer,
                "state store",
                |p, l| (cb.load_all)(cb.user_data, secret_id, kind_u32, p, l),
            )
            .map_err(|e| StateStoreError::Backend(boxed_err(e)))?;
            let Some(bytes) = bytes else { return Ok(Vec::new()) };
            if bytes.is_empty() {
                return Ok(Vec::new());
            }
            let records: Vec<StateItemRecord> =
                serde_json::from_slice(&bytes).map_err(|e| {
                    StateStoreError::Backend(boxed_err(format!(
                        "StateItem list JSON: {e}"
                    )))
                })?;
            let mut out = Vec::with_capacity(records.len());
            for r in records {
                out.push(r.into_item().map_err(|e| {
                    StateStoreError::Backend(boxed_err(e))
                })?);
            }
            Ok(out)
        })();
        Box::pin(async move { res })
    }
}
