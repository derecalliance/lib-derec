// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Event-loop entry points: `start` / `process` / `accept` / `reject`.
//! Each one drives the protocol's async core via the per-handle tokio
//! runtime and returns either a typed result or a JSON event array.

use super::DeRecProtocolHandle;
use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_BAD_UTF8, DEREC_CODE_FFI_INVALID_ENUM,
    DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error, success,
};
use crate::interop::ffi::protocol::events::encode_events;
use crate::interop::ffi::protocol::flow as flow_params;

/// Start a new flow. `flow_kind` matches the constants in
/// [`crate::interop::ffi::protocol::flow`]. `params_json_*` is a UTF-8 JSON blob
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
        return ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "params_json_ptr is null but len > 0",
        )
        .into();
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
    /// UTF-8 JSON array of events. See [`crate::interop::ffi::protocol::events`]
    /// for the per-variant shape. Caller releases via
    /// [`crate::interop::ffi::derec_free_buffer`].
    pub events_json: DeRecBuffer,
}

/// Result of [`derec_protocol_restore`].
///
/// A restore refused because channels already exist at the recovered ids
/// reports which ones in `conflicting_channel_ids_json`, so the application
/// can clear exactly those and retry.
#[repr(C)]
pub struct DeRecProtocolRestoreResult {
    pub error: DeRecError,
    /// UTF-8 JSON array of events, as on [`DeRecProtocolEventsResult`].
    pub events_json: DeRecBuffer,
    /// UTF-8 JSON array of decimal-string channel ids. Non-empty only when
    /// `error.code` is `DEREC_CODE_RESTORE_CONFLICT`. Caller releases via
    /// [`crate::interop::ffi::derec_free_buffer`].
    pub conflicting_channel_ids_json: DeRecBuffer,
}

impl From<DeRecError> for DeRecProtocolRestoreResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            events_json: empty_buffer(),
            conflicting_channel_ids_json: empty_buffer(),
        }
    }
}

impl From<DeRecError> for DeRecProtocolEventsResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            events_json: empty_buffer(),
        }
    }
}

/// Result of [`derec_protocol_process`].
///
/// A failed call still carries the events produced before the failure in
/// `events_json`, and names the channel the failing message came from.
#[repr(C)]
pub struct DeRecProtocolProcessResult {
    pub error: DeRecError,
    /// UTF-8 JSON array of events, as on [`DeRecProtocolEventsResult`].
    /// Filled on success and on failure.
    pub events_json: DeRecBuffer,
    /// Whether `channel_id` is set. False on success and when the bytes
    /// were not a decodable envelope.
    pub has_channel_id: bool,
    /// The channel the failing message came from.
    pub channel_id: u64,
}

impl From<DeRecError> for DeRecProtocolProcessResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            events_json: empty_buffer(),
            has_channel_id: false,
            channel_id: 0,
        }
    }
}

/// Process an inbound `DeRecMessage` envelope. See
/// [`crate::protocol::DeRecProtocol::process`]. On failure the result still
/// carries the events produced before it and the failing channel.
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
) -> DeRecProtocolProcessResult {
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
        Ok(events) => DeRecProtocolProcessResult {
            error: success(),
            events_json: vec_into_buffer(encode_events(events)),
            has_channel_id: false,
            channel_id: 0,
        },
        Err(e) => DeRecProtocolProcessResult {
            error: from_lib_error(e.source),
            events_json: vec_into_buffer(encode_events(e.events)),
            has_channel_id: e.channel_id.is_some(),
            channel_id: e.channel_id.map_or(0, |id| id.0),
        },
    }
}

/// Advance time-driven state without an inbound message. See
/// [`crate::protocol::DeRecProtocol::tick`].
///
/// Intended for a scheduler — a timer, a cron job, a queue heartbeat —
/// in deployments where nothing else would ever evaluate timeouts. Safe
/// to call on an idle protocol: it returns an empty event array.
///
/// # Safety
///
/// `handle` must be a valid pointer returned by
/// [`super::derec_protocol_new`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_tick(
    handle: *mut DeRecProtocolHandle,
) -> DeRecProtocolEventsResult {
    if handle.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "handle is null").into();
    }

    let h = unsafe { &*handle };
    let mut inner = h.lock_inner();
    let events = h.runtime.block_on(inner.tick());
    DeRecProtocolEventsResult {
        error: success(),
        events_json: vec_into_buffer(encode_events(events)),
    }
}

/// Accept a pending action from an `ActionRequired` event. See
/// [`crate::protocol::DeRecProtocol::accept`]. The `action_bytes` blob
/// is the exact payload the caller received in the event — the FFI
/// wire format is the encoding produced by
/// [`crate::protocol::utils::pending_action_wire::serialize`].
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
    let action = match crate::protocol::utils::pending_action_wire::deserialize(bytes) {
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
    let action = match crate::protocol::utils::pending_action_wire::deserialize(bytes) {
        Ok(a) => a,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("PendingAction decode: {e}"),
            );
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
///     "helpers": [{ "channel_id": "11",
///                   "transports": [{ "uri": "https://helper.example", "protocol": "https" }],
///                   "shared_key": [..32 bytes..],
///                   "communication_info": {} }],
///     "secrets": [{ "id": [..], "name": "...", "data": [..] }],
///     "replicas": {
///       "channel_id": "21",
///       "members": [{ "replica_id": "51966",
///                     "transports": [{ "uri": "https://replica.example", "protocol": "https" }],
///                     "role": "Source", "communication_info": {} }],
///       "shared_key": [..32 bytes..]
///     }
///   }
/// }
/// ```
///
/// Field names mirror `SecretWire` in `protocol/events/wire.rs` — the
/// same shape `SecretRecovered` carries, so the `secret` of that event can
/// be passed back unchanged. `channel_id` and `replica_id` are required
/// decimal `u64` strings; an absent, empty, or malformed id is rejected.
/// `transports` is every endpoint the peer advertised, in its preference
/// order; `protocol` is its name, `"https"` or `"grpc"`. An absent or
/// `null` `transports` reads as an empty list, and a helper or member with
/// no endpoint gets no channel: restore skips it and reports it as a
/// `PeerNotRestored` event. `role` is `"Source"` or `"Destination"`.
///
/// `replicas` is an **object**, not an array, and is omitted entirely when
/// the `secret_id` has no replica group. Every member of the group shares
/// the one `channel_id` and the one `shared_key` it carries, so neither is
/// repeated per member; a member is identified by `replica_id` alone, and
/// the group's source is the member whose `role` is `"Source"`.
///
/// On success the result carries the events the restore produced, as
/// [`DeRecProtocolEventsResult`] does — one `PeerNotRestored` per skipped
/// helper or member among them. When channels already exist at ids
/// restore is about to write, `error.code` is
/// `DEREC_CODE_RESTORE_CONFLICT` and `conflicting_channel_ids_json` lists
/// exactly those ids; nothing is written, so the application can clear
/// them and retry.
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
) -> DeRecProtocolRestoreResult {
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
            DeRecProtocolRestoreResult {
                error: success(),
                events_json: vec_into_buffer(json),
                conflicting_channel_ids_json: empty_buffer(),
            }
        }
        Err(e) => {
            let conflicting = match &e {
                crate::Error::Restore(crate::protocol::RestoreError::Conflict(ids)) => {
                    let ids: Vec<String> = ids.iter().map(|c| c.0.to_string()).collect();
                    vec_into_buffer(serde_json::to_vec(&ids).expect("a list of strings serializes"))
                }
                _ => empty_buffer(),
            };
            DeRecProtocolRestoreResult {
                error: from_lib_error(e),
                events_json: empty_buffer(),
                conflicting_channel_ids_json: conflicting,
            }
        }
    }
}

#[derive(serde::Deserialize)]
struct RestoreParamsJson {
    version: u32,
    recovered_secret: crate::interop::recovered_secret::RecoveredSecretIn,
}
