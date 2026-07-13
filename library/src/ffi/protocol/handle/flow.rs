// SPDX-License-Identifier: Apache-2.0

//! Event-loop entry points: `start` / `process` / `accept` / `reject`.
//! Each one drives the protocol's async core via the per-handle tokio
//! runtime and returns either a typed result or a JSON event array.

use super::DeRecProtocolHandle;
use crate::ffi::common::{empty_buffer, vec_into_buffer, DeRecBuffer};
use crate::ffi::error::{
    ffi_error, from_lib_error, success, DeRecError, DEREC_CODE_FFI_BAD_PROTO,
    DEREC_CODE_FFI_BAD_UTF8, DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR,
};
use crate::ffi::protocol::events::encode_events;
use crate::ffi::protocol::flow as flow_params;

/// Start a new flow. `flow_kind` matches the constants in
/// [`crate::ffi::protocol::flow`]. `params_json_*` is a UTF-8 JSON blob
/// shaped to the matching `*ParamsJson` struct in that module.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `params_json_ptr`/`params_json_len`
/// must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_start(
    handle: *mut DeRecProtocolHandle,
    flow_kind: u32,
    params_json_ptr: *const u8,
    params_json_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if params_json_len > 0 && params_json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "params_json_ptr is null but len > 0").into();
    }
    let params_bytes = if params_json_len == 0 {
        b""[..].to_vec()
    } else {
        unsafe { std::slice::from_raw_parts(params_json_ptr, params_json_len) }.to_vec()
    };

    let flow = match flow_params::parse_flow(flow_kind, &params_bytes) {
        Ok(f) => f,
        Err(e) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, e).into(),
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.start(flow)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e).into(),
    }
}

/// Result type for entry points that return a `Vec<DeRecEvent>`.
#[repr(C)]
pub struct DeRecProtocolEventsResult {
    pub error: DeRecError,
    /// UTF-8 JSON array of events. See [`crate::ffi::protocol::events`]
    /// for the per-variant shape. Caller releases via
    /// [`crate::ffi::derec_free_buffer`].
    pub events_json: DeRecBuffer,
}

impl From<DeRecError> for DeRecProtocolEventsResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            events_json: empty_buffer(),
        }
    }
}

/// Process an inbound `DeRecMessage` envelope. See
/// [`crate::protocol::DeRecProtocol::process`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `message_ptr`/`message_len` must
/// describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_process(
    handle: *mut DeRecProtocolHandle,
    message_ptr: *const u8,
    message_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if message_len > 0 && message_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "message_ptr is null but len > 0").into();
    }
    let bytes = if message_len == 0 {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(message_ptr, message_len) }.to_vec()
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.process(&bytes)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e.source).into(),
    }
}

/// Accept a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::accept`]. The `action_bytes` blob
/// is the exact payload the caller received in the event — the FFI
/// wire format is the encoding produced by
/// [`crate::protocol::pending_action_wire::serialize`].
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
/// describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_accept(
    handle: *mut DeRecProtocolHandle,
    action_ptr: *const u8,
    action_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if action_len == 0 || action_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "action_ptr is null or len == 0").into();
    }
    let bytes = unsafe { std::slice::from_raw_parts(action_ptr, action_len) };
    let action = match crate::protocol::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("PendingAction decode: {e}"),
            )
            .into();
        }
    };
    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.accept(action)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e).into(),
    }
}

/// Reject a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::reject`]. `status` matches
/// `derec_proto::StatusEnum` and `memo_ptr`/`memo_len` is an optional
/// UTF-8 string body (`memo_len == 0` for absent).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `action_ptr`/`action_len` must
/// describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_reject(
    handle: *mut DeRecProtocolHandle,
    action_ptr: *const u8,
    action_len: usize,
    status: i32,
    memo_ptr: *const u8,
    memo_len: usize,
) -> DeRecError {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null");
    }
    if action_len == 0 || action_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "action_ptr is null or len == 0");
    }
    let bytes = unsafe { std::slice::from_raw_parts(action_ptr, action_len) };
    let action = match crate::protocol::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return ffi_error(DEREC_CODE_FFI_BAD_PROTO, format!("PendingAction decode: {e}"));
        }
    };
    let memo = if memo_len == 0 {
        String::new()
    } else if memo_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "memo_ptr is null but len > 0");
    } else {
        let bytes = unsafe { std::slice::from_raw_parts(memo_ptr, memo_len) };
        match std::str::from_utf8(bytes) {
            Ok(s) => s.to_owned(),
            Err(_) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, "memo is not valid UTF-8"),
        }
    };

    let status_enum = match derec_proto::StatusEnum::try_from(status) {
        Ok(s) => s,
        Err(_) => {
            return ffi_error(
                DEREC_CODE_FFI_INVALID_ENUM,
                format!("invalid StatusEnum: {status}"),
            );
        }
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.reject(action, status_enum, &memo)) {
        Ok(()) => success(),
        Err(e) => from_lib_error(e),
    }
}

/// Rebuild this protocol's `secret_id` namespace from a recovered
/// `Secret`. See [`crate::protocol::DeRecProtocol::restore`] for the
/// full contract and error semantics.
///
/// `params_json_*` is a UTF-8 JSON blob of the shape:
///
/// ```json
/// {
///   "version": 7,
///   "recovered_secret": {
///     "helpers": [{ "channel_id": "11", "transport_uri": "...",
///                   "shared_key": [..32 bytes..],
///                   "communication_info": {} }],
///     "secrets": [{ "id": [..], "name": "...", "data": [..] }],
///     "replicas": [{ "channel_id": "21", "transport_uri": "...",
///                    "replica_id": "0xCAFE", "sender_kind": 3,
///                    "communication_info": {} }],
///     "owner_replica_id": "48879",
///     "replica_group_shared_key": [..32 bytes..]
///   }
/// }
/// ```
///
/// Field names mirror `SecretWire` in `protocol/events/wire.rs` — the
/// same shape `SecretRecovered` carries. `channel_id`, `replica_id`,
/// and `owner_replica_id` are decimal `u64` strings (empty / absent
/// means zero).
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`]. `params_json_ptr`/`params_json_len`
/// must describe a readable byte range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_restore(
    handle: *mut DeRecProtocolHandle,
    params_json_ptr: *const u8,
    params_json_len: usize,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }
    if params_json_len == 0 || params_json_ptr.is_null() {
        return ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "params_json_ptr is null or len == 0",
        )
        .into();
    }
    let bytes = unsafe { std::slice::from_raw_parts(params_json_ptr, params_json_len) };
    let json = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            return ffi_error(DEREC_CODE_FFI_BAD_UTF8, "params_json is not valid UTF-8").into();
        }
    };

    let params: RestoreParamsJson = match serde_json::from_str(json) {
        Ok(p) => p,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("restore params JSON: {e}"),
            )
            .into();
        }
    };

    let secret = match params.recovered_secret.into_secret() {
        Ok(s) => s,
        Err(e) => return ffi_error(DEREC_CODE_FFI_BAD_PROTO, e).into(),
    };

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    match h.runtime.block_on(inner.restore(&secret, params.version)) {
        Ok(events) => {
            let json = encode_events(events);
            DeRecProtocolEventsResult {
                error: success(),
                events_json: vec_into_buffer(json),
            }
        }
        Err(e) => from_lib_error(e).into(),
    }
}

#[derive(serde::Deserialize)]
struct RestoreParamsJson {
    version: u32,
    recovered_secret: SecretJsonIn,
}

#[derive(serde::Deserialize)]
struct SecretJsonIn {
    #[serde(default)]
    helpers: Vec<HelperJsonIn>,
    #[serde(default)]
    secrets: Vec<UserSecretJsonIn>,
    #[serde(default)]
    replicas: Option<ReplicasJsonIn>,
    #[serde(default)]
    owner_replica_id: String,
}

#[derive(serde::Deserialize)]
struct ReplicasJsonIn {
    #[serde(default)]
    replicas: Vec<ReplicaJsonIn>,
    #[serde(default)]
    shared_key: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct HelperJsonIn {
    channel_id: String,
    transport_uri: String,
    shared_key: Vec<u8>,
    #[serde(default)]
    communication_info: std::collections::HashMap<String, String>,
}

#[derive(serde::Deserialize)]
struct ReplicaJsonIn {
    channel_id: String,
    transport_uri: String,
    #[serde(default)]
    communication_info: std::collections::HashMap<String, String>,
    replica_id: String,
    sender_kind: i32,
}

#[derive(serde::Deserialize)]
struct UserSecretJsonIn {
    id: Vec<u8>,
    name: String,
    data: Vec<u8>,
}

impl SecretJsonIn {
    fn into_secret(self) -> Result<crate::protocol::types::Secret, String> {
        fn parse_u64(s: &str, ctx: &str) -> Result<u64, String> {
            if s.is_empty() {
                return Ok(0);
            }
            s.parse::<u64>()
                .map_err(|e| format!("{ctx} must be a u64 decimal string: {e}"))
        }

        let helpers = self
            .helpers
            .into_iter()
            .map(|h| -> Result<_, String> {
                Ok(crate::protocol::types::HelperInfo {
                    channel_id: parse_u64(&h.channel_id, "helper.channel_id")?,
                    transport_uri: h.transport_uri,
                    shared_key: h.shared_key,
                    communication_info: h.communication_info,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let replicas = self
            .replicas
            .map(|g| -> Result<_, String> {
                let replicas = g
                    .replicas
                    .into_iter()
                    .map(|r| -> Result<_, String> {
                        Ok(crate::protocol::types::ReplicaInfo {
                            channel_id: parse_u64(&r.channel_id, "replica.channel_id")?,
                            transport_uri: r.transport_uri,
                            communication_info: r.communication_info,
                            replica_id: parse_u64(&r.replica_id, "replica.replica_id")?,
                            sender_kind: r.sender_kind,
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(crate::protocol::types::Replicas {
                    replicas,
                    shared_key: g.shared_key,
                })
            })
            .transpose()?;

        let secrets = self
            .secrets
            .into_iter()
            .map(|s| crate::protocol::types::UserSecret {
                id: s.id,
                name: s.name,
                data: s.data,
            })
            .collect();

        Ok(crate::protocol::types::Secret {
            helpers,
            secrets,
            replicas,
            owner_replica_id: parse_u64(&self.owner_replica_id, "owner_replica_id")?,
        })
    }
}
