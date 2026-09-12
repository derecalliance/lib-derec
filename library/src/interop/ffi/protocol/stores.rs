// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Managed-callback adapters that satisfy the protocol's store and
//! transport traits ([`DeRecChannelStore`], [`DeRecSecretStore`],
//! [`DeRecShareStore`], [`DeRecUserSecretStore`], [`DeRecStateStore`],
//! [`DeRecTransport`]) by delegating to C function pointers supplied by
//! the foreign caller.
//!
//! The wire format for complex types (Channel, Share, SecretValue) is
//! JSON. `Channel` rides serde directly — its derives produce a stable
//! shape with a top-level `id` (decimal-serialized u64), a nested
//! `transport: { uri, protocol }` object, and variant-name strings for
//! `status` and `peer_role`. `Share` and `SecretValue` keep dedicated record
//! wrappers because their on-wire shapes differ from their in-memory
//! ones (e.g. `secret_id` is stringified for JS interop). The same
//! schema is consumed by the WASM bridge so a single C# / TS
//! deserializer covers both.

use std::os::raw::c_void;

use prost::Message as _;

use crate::protocol::types::state_record::{StateItemRecord, StateKeyRecord};
use crate::protocol::types::{UserSecret, UserSecrets};
use crate::protocol::{
    ChannelStoreError, ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
    DeRecStateStore, DeRecTransport, DeRecUserSecretStore, MissingPolicy, SecretKind,
    SecretStoreError, SecretStoreFuture, SecretValue, Share, ShareStoreError, ShareStoreFuture,
    StateItem, StateKey, StateKind, StateStoreError, StateStoreFuture, TransportFuture,
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
use crate::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, ReplicaFilter, ReplicaMember,
};
use crate::types::ChannelId;

/// Flatten a query into the `(channel_id, replica_id)` pair the vtable takes.
/// `replica_id == 0` addresses the helper channel; see [`ChannelStoreCallbacks`].
fn query_key(query: ChannelQuery) -> (u64, u64) {
    match query {
        ChannelQuery::Helper { channel_id } => (channel_id.0, 0),
        ChannelQuery::Replica {
            channel_id,
            replica_id,
        } => (channel_id.0, replica_id.0),
    }
}

/// The address a record is stored at, derived from the record itself so a
/// caller cannot save one under the wrong key.
fn record_key(record: &ChannelRecord) -> (u64, u64) {
    match record {
        ChannelRecord::Helper(h) => (h.channel_id.0, 0),
        ChannelRecord::Replica(r) => (r.channel_id.0, r.replica_id.0),
    }
}

/// Decode a listing callback's JSON array; an absent or empty buffer is an
/// empty list, not an error.
fn decode_list<T: serde::de::DeserializeOwned>(
    bytes_res: Result<Option<Vec<u8>>, String>,
    label: &str,
) -> Result<Vec<T>, ChannelStoreError> {
    let bytes = match bytes_res {
        Err(e) => return Err(ChannelStoreError::Backend(boxed_err(e))),
        Ok(None) => return Ok(Vec::new()),
        Ok(Some(b)) => b,
    };
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| ChannelStoreError::Backend(format!("{label} JSON: {e}").into()))
}

/// The wire shape of a listing filter.
///
/// Ids are **decimal strings**, not JSON numbers. `ChannelId` and `ReplicaId`
/// are transparent `u64`s, so serialising the filter directly emits numbers —
/// which is lossless for the .NET and Go bindings but not for React Native,
/// whose bridge parses this JSON with JavaScript's `JSON.parse`. Every id
/// above 2^53 is silently rounded there: a channel id of
/// `12528301489426105160` reaches the store as `12528301489426104320`, so a
/// by-id filter matches nothing and the flow fans out to no one.
///
/// Stringifying downstream cannot repair it — by then the value is already a
/// rounded double — so the ids have to be strings before `JSON.parse` sees
/// them. Same reasoning, and same shape, as `encode_filter` on the WASM
/// bridge.
#[derive(serde::Serialize)]
struct ChannelFilterWire<'a, Role: serde::Serialize> {
    ids: Vec<String>,
    status: &'a [crate::protocol::types::ChannelStatus],
    role: Option<&'a Role>,
    exclude: Vec<String>,
}

/// Encode a listing filter for the callback that will apply it.
fn encode_filter<Role: serde::Serialize>(
    ids: &[u64],
    status: &[crate::protocol::types::ChannelStatus],
    role: Option<&Role>,
    exclude: &[u64],
    label: &str,
) -> Result<Vec<u8>, ChannelStoreError> {
    let wire = ChannelFilterWire {
        ids: ids.iter().map(u64::to_string).collect(),
        status,
        role,
        exclude: exclude.iter().map(u64::to_string).collect(),
    };
    serde_json::to_vec(&wire)
        .map_err(|e| ChannelStoreError::Backend(format!("{label} filter JSON: {e}").into()))
}
use derec_proto::TransportProtocol;

/// JSON-on-the-wire shape of a [`Share`] consumed by
/// [`DotnetShareStore`].
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

fn state_kind_to_u32(kind: StateKind) -> u32 {
    match kind {
        StateKind::PendingVerification => 0,
        StateKind::PendingRecovery => 1,
        StateKind::PendingUnpair => 2,
        StateKind::SharingRound => 3,
        StateKind::PendingReplicaDiscovery => 4,
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
///
/// # Addressing a record
///
/// `load`, `save` and `remove` take a `(channel_id, replica_id)` pair. A
/// `replica_id` of `0` — the value [`crate::types::ReplicaId`] reserves as
/// "absent" — addresses the helper channel at `channel_id`.
///
/// Any other value addresses that member of the replica group, and the member
/// is keyed by **`replica_id` alone**. The accompanying `channel_id` is
/// context, not part of the key: a member moves between channels during an
/// admission handover while remaining the same member, and a lookup that
/// required both to match would miss it exactly when the move needs to be
/// observed. Backends therefore keep two maps — helpers by `channel_id`,
/// members by `replica_id` — not one keyed by the pair.
///
/// The `bytes` payload of `save`, and the buffer `load` returns, are a
/// JSON-encoded [`crate::protocol::types::ChannelRecord`]. `list_helpers` and
/// `list_replicas` return a JSON array of
/// [`crate::protocol::types::HelperChannel`] and
/// [`crate::protocol::types::ReplicaMember`] respectively.
///
/// Both listing callbacks receive a `filter` buffer holding a JSON-encoded
/// [`crate::protocol::types::HelperFilter`] or
/// [`crate::protocol::types::ReplicaFilter`] — an object with `ids`, `status`,
/// `role` and `exclude`, where an empty array or a null `role` restricts
/// nothing. A backend should apply it in its query rather than by listing
/// everything and discarding rows; see
/// [`crate::protocol::types::ChannelFilter`]. The library re-applies it to
/// whatever comes back, so ignoring it is slow rather than wrong — but
/// returning fewer rows than it selects is wrong, and undetectable. The buffer is owned
/// by the caller and valid only for the duration of the call.
///
/// The order `list_replicas` returns is significant in exactly one situation —
/// it selects the successor when the group's source is removed. See
/// [`crate::protocol::DeRecChannelStore::replicas`] for the full contract.
#[repr(C)]
pub struct ChannelStoreCallbacks {
    pub user_data: *mut c_void,
    pub load: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        replica_id: u64,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub save: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        replica_id: u64,
        bytes: *const u8,
        len: usize,
    ) -> i32,
    pub remove: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        channel_id: u64,
        replica_id: u64,
        out_existed: *mut u32,
    ) -> i32,
    pub list_helpers: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        filter: *const u8,
        filter_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub list_replicas: extern "C" fn(
        user_data: *mut c_void,
        secret_id: u64,
        filter: *const u8,
        filter_len: usize,
        out_ptr: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32,
    pub link_channel: extern "C" fn(user_data: *mut c_void, secret_id: u64, a: u64, b: u64) -> i32,
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
    pub remove:
        extern "C" fn(user_data: *mut c_void, secret_id: u64, channel_id: u64, kind: u32) -> i32,
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
    pub remove_channel:
        extern "C" fn(user_data: *mut c_void, secret_id: u64, channel_id: u64) -> i32,
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
    /// Deliver `bytes` to a peer reachable at any of `endpoints`.
    ///
    /// `endpoints` is a length-delimited sequence of encoded
    /// `TransportProtocol` messages — each entry preceded by its protobuf
    /// varint byte length, the same framing protobuf uses for a repeated
    /// embedded message field. They are the endpoints that peer advertised,
    /// in the order it offered them, already filtered to those the library
    /// will record.
    ///
    /// The library does not rank them. Which endpoint to dial, and whether
    /// to fall back to another when one is unreachable, is the
    /// implementation's choice. Return `0` once the message has reached any
    /// one of them; non-zero only when it reached none.
    pub send: extern "C" fn(
        user_data: *mut c_void,
        endpoints_ptr: *const u8,
        endpoints_len: usize,
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
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let (channel_id, replica_id) = query_key(query);
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.load)(self.cb.user_data, secret_id, channel_id, replica_id, p, l)
        });
        Box::pin(async move {
            match bytes_res {
                Err(e) => Err(ChannelStoreError::Backend(e.into())),
                Ok(None) => Ok(None),
                Ok(Some(bytes)) if bytes.is_empty() => Ok(None),
                Ok(Some(bytes)) => {
                    let record: ChannelRecord = serde_json::from_slice(&bytes).map_err(|e| {
                        ChannelStoreError::Backend(
                            format!("invalid ChannelRecord JSON: {e}").into(),
                        )
                    })?;
                    Ok(Some(record))
                }
            }
        })
    }

    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        let (channel_id, replica_id) = record_key(&record);
        let cb = &self.cb;
        let res = (|| -> Result<(), ChannelStoreError> {
            let bytes = serde_json::to_vec(&record).map_err(|e| {
                ChannelStoreError::Backend(format!("ChannelRecord JSON: {e}").into())
            })?;
            let rc = (cb.save)(
                cb.user_data,
                secret_id,
                channel_id,
                replica_id,
                bytes.as_ptr(),
                bytes.len(),
            );
            if rc != 0 {
                return Err(ChannelStoreError::Backend(
                    format!("channel store save failed (rc={rc})").into(),
                ));
            }
            Ok(())
        })();
        Box::pin(async move { res })
    }

    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let (channel_id, replica_id) = query_key(query);
        let cb = &self.cb;
        let res = (|| -> Result<bool, ChannelStoreError> {
            let mut existed: u32 = 0;
            let rc = (cb.remove)(
                cb.user_data,
                secret_id,
                channel_id,
                replica_id,
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

    fn helpers(
        &self,
        secret_id: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let ids: Vec<u64> = filter.ids.iter().map(|c| c.0).collect();
        let exclude: Vec<u64> = filter.exclude.iter().map(|c| c.0).collect();
        let encoded = match encode_filter(
            &ids,
            &filter.status,
            filter.role.as_ref(),
            &exclude,
            "list_helpers",
        ) {
            Ok(bytes) => bytes,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.list_helpers)(
                self.cb.user_data,
                secret_id,
                encoded.as_ptr(),
                encoded.len(),
                p,
                l,
            )
        });
        Box::pin(async move { decode_list(bytes_res, "list_helpers") })
    }

    fn replicas(
        &self,
        secret_id: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let ids: Vec<u64> = filter.ids.iter().map(|r| r.0).collect();
        let exclude: Vec<u64> = filter.exclude.iter().map(|r| r.0).collect();
        let encoded = match encode_filter(
            &ids,
            &filter.status,
            filter.role.as_ref(),
            &exclude,
            "list_replicas",
        ) {
            Ok(bytes) => bytes,
            Err(e) => return Box::pin(async move { Err(e) }),
        };
        let bytes_res = self.fetch_bytes(|p, l| {
            (self.cb.list_replicas)(
                self.cb.user_data,
                secret_id,
                encoded.as_ptr(),
                encoded.len(),
                p,
                l,
            )
        });
        Box::pin(async move { decode_list(bytes_res, "list_replicas") })
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
                ChannelStoreError::Backend(boxed_err(format!("linked_channels JSON: {e}")))
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
                    let record: SecretValueRecord =
                        serde_json::from_slice(&bytes).map_err(|e| {
                            SecretStoreError::Backend(format!("SecretValue JSON: {e}").into())
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
                let record: SecretValueRecord = serde_json::from_slice(&bytes).map_err(|e| {
                    SecretStoreError::Backend(format!("SecretValue JSON: {e}").into())
                })?;
                let value = record
                    .into_value()
                    .map_err(|e| SecretStoreError::Backend(format!("SecretValue: {e}").into()))?;
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
    fn fetch_share_list(
        &self,
        bytes: Result<Option<Vec<u8>>, String>,
    ) -> Result<Vec<Share>, ShareStoreError> {
        let bytes = match bytes {
            Err(e) => return Err(ShareStoreError::Backend(boxed_err(e))),
            Ok(None) => return Ok(Vec::new()),
            Ok(Some(b)) => b,
        };
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        let records: Vec<ShareRecord> = serde_json::from_slice(&bytes)
            .map_err(|e| ShareStoreError::Backend(boxed_err(format!("ShareRecord JSON: {e}"))))?;
        records
            .into_iter()
            .map(|r| {
                r.into_share()
                    .map_err(|e| ShareStoreError::Backend(boxed_err(e)))
            })
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
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| ShareStoreError::Backend(boxed_err(format!("Share JSON: {e}"))))?;
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
        fetch_callback_bytes(
            self.cb.user_data,
            self.cb.free_buffer,
            "user secret store",
            f,
        )
    }
}

impl DeRecUserSecretStore for DotnetUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let result =
            self.fetch_bytes(|p, l| (self.cb.load_latest)(self.cb.user_data, secret_id, p, l));
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

    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
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
    fn send(&self, endpoints: &[TransportProtocol], message: Vec<u8>) -> TransportFuture<'_> {
        use prost::Message as _;

        let cb = &self.cb;
        // Length-delimited framing: one varint length per entry, then its
        // encoded bytes. Keeps the C ABI a single (ptr, len) pair however
        // many endpoints a peer advertised.
        let mut framed = Vec::new();
        for endpoint in endpoints {
            let entry = endpoint.encode_to_vec();
            prost::encoding::encode_varint(entry.len() as u64, &mut framed);
            framed.extend_from_slice(&entry);
        }

        let rc = (cb.send)(
            cb.user_data,
            framed.as_ptr(),
            framed.len(),
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
            let bytes = serde_json::to_vec(&record)
                .map_err(|e| StateStoreError::Backend(boxed_err(format!("StateItem JSON: {e}"))))?;
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
            let key_bytes = serde_json::to_vec(&key_record)
                .map_err(|e| StateStoreError::Backend(boxed_err(format!("StateKey JSON: {e}"))))?;
            let bytes =
                fetch_callback_bytes(cb.user_data, cb.free_buffer, "state store", |p, l| {
                    (cb.load)(
                        cb.user_data,
                        secret_id,
                        key_bytes.as_ptr(),
                        key_bytes.len(),
                        p,
                        l,
                    )
                })
                .map_err(|e| StateStoreError::Backend(boxed_err(e)))?;
            let Some(bytes) = bytes else { return Ok(None) };
            if bytes.is_empty() {
                return Ok(None);
            }
            let record: StateItemRecord = serde_json::from_slice(&bytes)
                .map_err(|e| StateStoreError::Backend(boxed_err(format!("StateItem JSON: {e}"))))?;
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
            let key_bytes = serde_json::to_vec(&key_record)
                .map_err(|e| StateStoreError::Backend(boxed_err(format!("StateKey JSON: {e}"))))?;
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

    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let cb = &self.cb;
        let kind_u32 = state_kind_to_u32(kind);
        let res = (|| -> Result<Vec<StateItem>, StateStoreError> {
            let bytes =
                fetch_callback_bytes(cb.user_data, cb.free_buffer, "state store", |p, l| {
                    (cb.load_all)(cb.user_data, secret_id, kind_u32, p, l)
                })
                .map_err(|e| StateStoreError::Backend(boxed_err(e)))?;
            let Some(bytes) = bytes else {
                return Ok(Vec::new());
            };
            if bytes.is_empty() {
                return Ok(Vec::new());
            }
            let records: Vec<StateItemRecord> = serde_json::from_slice(&bytes).map_err(|e| {
                StateStoreError::Backend(boxed_err(format!("StateItem list JSON: {e}")))
            })?;
            let mut out = Vec::with_capacity(records.len());
            for r in records {
                out.push(
                    r.into_item()
                        .map_err(|e| StateStoreError::Backend(boxed_err(e)))?,
                );
            }
            Ok(out)
        })();
        Box::pin(async move { res })
    }
}

#[cfg(test)]
mod filter_wire_tests {
    use super::*;
    use crate::protocol::types::{ChannelStatus, HelperFilter};
    use crate::types::ChannelId;

    /// Ids cross as decimal strings, so a u64 beyond `Number.MAX_SAFE_INTEGER`
    /// survives the React Native bridge's `JSON.parse`.
    ///
    /// As a number this id comes back as `12528301489426104320` — 840 short —
    /// and a by-id filter then matches nothing, which is how a discovery
    /// fan-out reached zero peers with every other suite green. Nothing
    /// downstream can repair it: by then the value is a rounded double.
    #[test]
    fn ids_are_encoded_as_decimal_strings() {
        const WIDE: u64 = 12_528_301_489_426_105_160;
        assert!(
            WIDE as f64 as u64 != WIDE,
            "this id must be one a double cannot hold, or the test proves nothing"
        );

        let filter = HelperFilter {
            ids: vec![ChannelId(WIDE)],
            status: vec![ChannelStatus::Paired],
            role: None,
            exclude: vec![ChannelId(u64::MAX)],
        };
        let ids: Vec<u64> = filter.ids.iter().map(|c| c.0).collect();
        let exclude: Vec<u64> = filter.exclude.iter().map(|c| c.0).collect();
        let json = encode_filter(&ids, &filter.status, filter.role.as_ref(), &exclude, "test")
            .expect("filter encodes");
        let text = String::from_utf8(json).expect("utf8");

        assert!(
            text.contains(&format!("\"{WIDE}\"")),
            "id must be quoted, got {text}"
        );
        assert!(
            text.contains(&format!("\"{}\"", u64::MAX)),
            "exclude must be quoted, got {text}"
        );
        assert!(
            !text.contains(&format!(":[{WIDE}")) && !text.contains(&format!(",{WIDE}")),
            "no bare numeric id may appear, got {text}"
        );
    }
}
