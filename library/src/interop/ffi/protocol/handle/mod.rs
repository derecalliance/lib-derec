// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Opaque [`DeRecProtocolHandle`] + FFI entry points. Each
//! `derec_protocol_*` function is the FFI counterpart of a method on
//! [`crate::protocol::DeRecProtocol`], organized into submodules by
//! domain: [`config`] for runtime-mutable settings, [`pairing`] for
//! contact / fingerprint helpers, and [`flow`] for the
//! `start` / `process` / `accept` / `reject` event-loop surface.

use std::collections::HashMap;

use prost::Message as _;

use crate::extensions::communication_info::CommunicationInfoExt as _;
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_INVALID_ENUM, DEREC_CODE_FFI_NULL_PTR, DeRecError,
    ffi_error, success,
};
use crate::interop::ffi::protocol::stores::{
    ChannelStoreCallbacks, DotnetChannelStore, DotnetSecretStore, DotnetShareStore,
    DotnetStateStore, DotnetTransport, DotnetUserSecretStore, SecretStoreCallbacks,
    ShareStoreCallbacks, StateStoreCallbacks, TransportCallbacks, UserSecretStoreCallbacks,
};
use crate::protocol::{DeRecProtocolBuilder, DeRecProtocolConfig};

mod config;
mod flow;
mod pairing;

pub(super) type Protocol = crate::protocol::DeRecProtocol<
    DotnetChannelStore,
    DotnetShareStore,
    DotnetSecretStore,
    DotnetUserSecretStore,
    DotnetStateStore,
    DotnetTransport,
>;

/// Opaque handle returned by [`derec_protocol_new`] and consumed by
/// every other entry point in this module. Holds the protocol instance + the
/// per-handle tokio runtime used to drive the async core synchronously.
///
/// The `inner` protocol is wrapped in [`std::sync::Mutex`] so concurrent
/// FFI calls from different host threads (.NET worker pool, Node.js
/// worker_threads, etc.) are safe by construction. Each entry point
/// locks the mutex for the duration of its call, serializing access to
/// the protocol state — no `&mut DeRecProtocolHandle` is ever
/// materialized, so aliased `&mut` references (which would be immediate
/// undefined behavior) cannot arise even under contention. The tokio
/// `Runtime` itself is `Sync` and accepts `&self` `block_on`, but
/// holding the protocol lock across `block_on` also serializes runtime
/// invocations on the current-thread executor.
pub struct DeRecProtocolHandle {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) inner: std::sync::Mutex<Protocol>,
}

impl DeRecProtocolHandle {
    /// Lock the inner protocol for exclusive access. Recovers from a
    /// poisoned mutex (a panic in an earlier entry point) by extracting
    /// the inner state — panicking across the FFI boundary is itself
    /// undefined behavior, so the poison-tolerant pattern is the right
    /// default here.
    pub(super) fn lock_inner(&self) -> std::sync::MutexGuard<'_, Protocol> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Validate a `(uri, protocol)` pair at the FFI boundary using the
/// library-level [`crate::transport::validate`] rules. Errors are
/// surfaced through [`crate::interop::ffi::error::from_lib_error`] so the
/// host sees the same `DEREC_CODE_TRANSPORT_INVALID` regardless of
/// whether the validator fired from the FFI entry point or from a
/// wire-decode path inside the protocol.
pub(super) fn validate_transport(
    uri: &str,
    protocol: i32,
) -> Result<crate::transport::TransportProtocol, DeRecError> {
    let proto = derec_proto::TransportProtocol {
        uri: uri.to_owned(),
        protocol,
    };
    // `TryFrom` runs both the enum-discriminant check and the URI
    // structural validation; a single `?` covers both.
    crate::transport::TransportProtocol::try_from(&proto)
        .map_err(|e| crate::interop::ffi::error::from_lib_error(crate::Error::Transport(e)))
}

/// Result type for [`derec_protocol_new`].
#[repr(C)]
pub struct DeRecProtocolNewResult {
    pub error: DeRecError,
    /// On success, the opaque handle. On error, null.
    pub handle: *mut DeRecProtocolHandle,
}

impl From<DeRecError> for DeRecProtocolNewResult {
    fn from(error: DeRecError) -> Self {
        Self {
            error,
            handle: std::ptr::null_mut(),
        }
    }
}

/// Split [`derec_protocol_new`]'s config JSON into the per-instance
/// `secret_id` and the [`DeRecProtocolConfig`] every binding shares, parsed
/// through the config's own canonical JSON (unknown keys refused).
///
/// Two values the config refuses while parsing keep the codes this entry
/// point has always reported for them: an `unpair_ack` code or name outside
/// the enum is `DEREC_CODE_FFI_INVALID_ENUM`, and an own transport whose
/// `protocol` discriminant names no protocol is
/// `DEREC_CODE_TRANSPORT_INVALID`. Every other malformed value is
/// `DEREC_CODE_FFI_BAD_PROTO`.
fn parse_config(json: &[u8]) -> Result<(u64, DeRecProtocolConfig), DeRecError> {
    use serde_json::Value;

    let not_valid = |e: &dyn std::fmt::Display| {
        ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            format!("config_json is not valid: {e}"),
        )
    };
    let mut map = match serde_json::from_slice::<Value>(json).map_err(|e| not_valid(&e))? {
        Value::Object(map) => map,
        _ => return Err(not_valid(&"expected a JSON object")),
    };

    let secret_id = match map.remove("secret_id") {
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| ffi_error(DEREC_CODE_FFI_BAD_PROTO, "secret_id is not a valid u64"))?,
        Some(_) => {
            return Err(not_valid(
                &"secret_id must be a u64 written as a decimal string",
            ));
        }
        None => return Err(not_valid(&"missing field `secret_id`")),
    };

    if let Some(e) = unpair_ack_out_of_range(map.get("unpair_ack")) {
        return Err(e);
    }
    if let Some(Value::Array(entries)) = map.get("own_transports") {
        for entry in entries {
            let Some(discriminant) = entry
                .get("protocol")
                .and_then(Value::as_i64)
                .and_then(|d| i32::try_from(d).ok())
            else {
                continue;
            };
            if derec_proto::Protocol::try_from(discriminant).is_err() {
                let uri = entry.get("uri").and_then(Value::as_str).unwrap_or_default();
                validate_transport(uri, discriminant)?;
            }
        }
    }

    let config = serde_json::from_value(Value::Object(map)).map_err(|e| not_valid(&e))?;
    Ok((secret_id, config))
}

/// The `DEREC_CODE_FFI_INVALID_ENUM` error for an `unpair_ack` that is a
/// code or a name but not one of [`crate::protocol::UnpairAck`]'s: `0` /
/// `"required"` or `1` / `"not_required"`. `None` for a valid value, an
/// absent one, or one of another JSON type, which fails to parse instead.
fn unpair_ack_out_of_range(value: Option<&serde_json::Value>) -> Option<DeRecError> {
    let shown = match value? {
        serde_json::Value::Number(n) => {
            let code = n.as_i64().and_then(|c| i32::try_from(c).ok())?;
            if code == 0 || code == 1 {
                return None;
            }
            code.to_string()
        }
        serde_json::Value::String(name) => {
            if crate::interop::protocol_names::unpair_ack_from_name(name).is_some() {
                return None;
            }
            format!("{name:?}")
        }
        _ => return None,
    };
    Some(ffi_error(
        DEREC_CODE_FFI_INVALID_ENUM,
        format!("invalid unpair_ack: {shown}"),
    ))
}

/// Constructs a [`crate::protocol::DeRecProtocol`] with scalar config
/// bundled as JSON, for FFI callers that cannot pass many native
/// arguments in a single call — e.g. Go via `purego` (no cgo), which
/// panics with "too many stack arguments" past a handful of
/// parameters. Scalar configuration is bundled into a single JSON
/// buffer; `communication_info` travels either in that JSON or as a
/// separate proto-encoded `CommunicationInfo` buffer; the 6 store/transport callback structs
/// are still passed as individual pointers, since purego marshals
/// pointer-sized arguments natively.
///
/// `config_json` is a JSON object holding `secret_id` plus the canonical
/// [`DeRecProtocolConfig`] JSON, all field names `snake_case`. `secret_id`
/// is the only required field. The rest is parsed as a
/// [`DeRecProtocolConfig`] and applied with
/// [`crate::protocol::DeRecProtocolBuilder::with_config`]: an omitted field
/// keeps [`crate::protocol::DeRecProtocolBuilder::new`]'s own default for
/// that setting, and a field that is present is used as given, including
/// `0`, and validated by the builder. A key the config does not define is
/// rejected with `DEREC_CODE_FFI_BAD_PROTO` rather than ignored.
///
/// ```json
/// {
///   "secret_id": "12345678901234567890",
///   "own_transports": [{ "uri": "https://example.com/derec", "protocol": "https" }],
///   "threshold": 3,
///   "auto_respond_on_failure": false,
///   "unpair_ack": 0,
///   "auto_reply_to": false,
///   "auto_accept": {
///     "pairing": false,
///     "pre_pair": false,
///     "store_share": false,
///     "verify_share": false,
///     "discovery": false,
///     "get_share": false,
///     "unpair": false,
///     "update_channel_info": false
///   },
///   "timeouts": {
///     "inbound_message_secs": 300,
///     "sharing_round_secs": 60,
///     "unpair_ack_secs": 60,
///     "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
///   },
///   "unsafe_connection": false,
///   "replica_id": null,
///   "parameter_range": {
///     "min_share_size": 0,
///     "max_share_size": 0,
///     "min_time_between_verifications": 0,
///     "max_time_between_verifications": 0,
///     "min_time_between_share_updates": 0,
///     "max_time_between_share_updates": 0,
///     "min_unresponsive_deletion_timeout": 0,
///     "max_unresponsive_deletion_timeout": 0,
///     "min_unresponsive_deactivation_timeout": 0,
///     "max_unresponsive_deactivation_timeout": 0
///   },
///   "max_subshares": null
/// }
/// ```
///
/// - `secret_id`: decimal-string `u64`.
/// - `own_transports`: every endpoint this application serves, in
///   preference order — the order decides which of a peer's offered
///   endpoints is used. `protocol` is its name (`"https"`, `"grpc"`) or
///   its `derec_proto::Protocol` discriminant (`0`, `1`). Each entry is validated, and
///   two entries of the same protocol are rejected. An unknown discriminant
///   or an invalid URI is rejected with `DEREC_CODE_TRANSPORT_INVALID`.
///   Required: an absent or empty list is refused, since a node with no
///   endpoint cannot be reached by any peer.
/// - `threshold`: omitted means [`crate::protocol::DEFAULT_THRESHOLD`]. A
///   `threshold` below `2` is rejected with `DEREC_CODE_INVALID_INPUT`.
/// - `unpair_ack`: `0` / `"required"` = Required, `1` / `"not_required"` =
///   NotRequired; omitted means Required.
///   Any other value is rejected with `DEREC_CODE_FFI_INVALID_ENUM`.
/// - `auto_respond_on_failure` / `auto_reply_to`: omitted means `false`.
/// - `timeouts`: the four waiting periods, in whole seconds. Each field is
///   optional and omitted means the [`crate::protocol::types::Timeouts`]
///   default. `expired_channels` is the automatic removal of `Pending`
///   channels; both of its fields are always sent, and when `enabled` is
///   `false` the timeout is ignored by the library.
/// - `unsafe_connection`: accept plaintext `http://` and `grpc://`
///   endpoints. Development only; omitted means `false`.
/// - `replica_id`: decimal-string `u64`, or absent/`null` for "no
///   replica id".
/// - `auto_accept`: each flow is individually optional; an omitted flow
///   takes [`crate::protocol::AutoAcceptPolicy::default()`]'s value.
/// - `parameter_range`: the bounds advertised during pair negotiation,
///   mirroring [`derec_proto::ParameterRange`]. Optional object; every bound
///   is optional, omitted means `0` ("no constraint"), and each may be a JSON
///   number or a decimal string.
/// - `communication_info`: optional flat JSON object of string keys to
///   string values. Mutually exclusive with a non-empty
///   `communication_info_ptr` buffer; omitted with an empty buffer means
///   no entries.
/// - `max_subshares`: decimal-string `u64` capping the total subshares one
///   sharing round may split the secret into, or absent/`null` for no cap.
///   A cap below `threshold` is rejected by the builder with
///   `DEREC_CODE_INVALID_INPUT`; a round over the cap fails with
///   `DEREC_CODE_TOO_MANY_SUBSHARES`.
///
/// # Safety
///
/// - `config_json_ptr` must be valid for reads of `config_json_len`
///   bytes.
/// - `communication_info_ptr` must be valid for reads of
///   `communication_info_len` bytes when the length is non-zero.
/// - All 6 callback pointers must be valid for reads of their pointee
///   struct, and must outlive the returned handle.
/// - The caller must invoke [`derec_protocol_free`] exactly once to
///   release the returned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_new(
    config_json_ptr: *const u8,
    config_json_len: usize,
    communication_info_ptr: *const u8,
    communication_info_len: usize,
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
    user_secret_store_cb: *const UserSecretStoreCallbacks,
    state_store_cb: *const StateStoreCallbacks,
    transport_cb: *const TransportCallbacks,
) -> DeRecProtocolNewResult {
    if config_json_ptr.is_null() {
        return ffi_error(DEREC_CODE_FFI_NULL_PTR, "config_json_ptr is null").into();
    }
    let json_bytes = unsafe { std::slice::from_raw_parts(config_json_ptr, config_json_len) };
    let (secret_id, mut config) = match parse_config(json_bytes) {
        Ok(parsed) => parsed,
        Err(e) => return e.into(),
    };

    let info = match unsafe {
        resolve_communication_info(
            config.communication_info.take(),
            communication_info_ptr,
            communication_info_len,
        )
    } {
        Ok(i) => i,
        Err(e) => return e.into(),
    };
    config.communication_info = Some(info);

    unsafe {
        construct_protocol(
            secret_id,
            config,
            channel_store_cb,
            secret_store_cb,
            share_store_cb,
            user_secret_store_cb,
            state_store_cb,
            transport_cb,
        )
    }
}

/// Release a handle previously returned by [`derec_protocol_new`].
/// Safe to call with a null pointer.
///
/// # Safety
///
/// `handle` must satisfy ALL of:
///
/// - It is a pointer previously returned by [`derec_protocol_new`],
///   or it is null.
/// - It has not already been freed (no double-free).
/// - **No other thread is executing any `derec_protocol_*` function on
///   this handle while this call is in flight.** The interior
///   [`std::sync::Mutex`] protects against aliased `&mut` references
///   *within* the live allocation, but it cannot protect the
///   allocation itself from being dropped — a concurrent
///   `derec_protocol_process` / `accept` / `set_*` call that holds
///   the lock would be reading freed memory the moment this function
///   returns. Host bindings (.NET `Dispose`, Node.js / WASM
///   teardown) are responsible for draining or cancelling in-flight
///   calls before invoking `derec_protocol_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_protocol_free(handle: *mut DeRecProtocolHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle));
    }
}

/// Pick the `communication_info` map [`derec_protocol_new`] was given: the
/// `communication_info` key of its config JSON, or its proto buffer
/// argument. Both at once is an error, so neither silently wins.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes when `len != 0`.
unsafe fn resolve_communication_info(
    from_config: Option<HashMap<String, String>>,
    ptr: *const u8,
    len: usize,
) -> Result<HashMap<String, String>, DeRecError> {
    match from_config {
        Some(_) if len != 0 => Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info supplied both in config_json and as a proto buffer",
        )),
        Some(map) => Ok(map),
        None => unsafe { decode_communication_info(ptr, len) },
    }
}

/// Decode a serialized [`derec_proto::CommunicationInfo`] proto buffer
/// into the `<String, String>` map the core protocol accepts. Used by
/// [`derec_protocol_new`], which takes `communication_info` as
/// a proto buffer separate from the rest of its JSON configuration.
///
/// # Safety
///
/// `ptr` must be valid for reads of `len` bytes when `len != 0`.
unsafe fn decode_communication_info(
    ptr: *const u8,
    len: usize,
) -> Result<HashMap<String, String>, DeRecError> {
    if len == 0 {
        return Ok(HashMap::new());
    }
    if ptr.is_null() {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "communication_info_ptr is null but length is non-zero",
        ));
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    match derec_proto::CommunicationInfo::decode(bytes) {
        Ok(c) => Ok(c.to_map()),
        Err(_) => Err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "communication_info is not a valid CommunicationInfo proto",
        )),
    }
}

/// Construction logic for [`derec_protocol_new`]: takes the parsed
/// `secret_id` and [`DeRecProtocolConfig`] plus the 6 store/transport
/// callback pointers, reads each callback struct, builds the
/// [`DeRecProtocolBuilder`], and wraps the result in a handle bound to a
/// fresh single-thread tokio runtime.
///
/// # Safety
///
/// - All 6 callback pointers must be valid for reads of their pointee
///   struct.
/// - `channel_store_cb`/`secret_store_cb`/`share_store_cb`/`user_secret_store_cb`/
///   `state_store_cb`/`transport_cb` must outlive the returned handle.
#[allow(clippy::too_many_arguments)]
unsafe fn construct_protocol(
    secret_id: u64,
    config: DeRecProtocolConfig,
    channel_store_cb: *const ChannelStoreCallbacks,
    secret_store_cb: *const SecretStoreCallbacks,
    share_store_cb: *const ShareStoreCallbacks,
    user_secret_store_cb: *const UserSecretStoreCallbacks,
    state_store_cb: *const StateStoreCallbacks,
    transport_cb: *const TransportCallbacks,
) -> DeRecProtocolNewResult {
    if channel_store_cb.is_null()
        || secret_store_cb.is_null()
        || share_store_cb.is_null()
        || user_secret_store_cb.is_null()
        || state_store_cb.is_null()
        || transport_cb.is_null()
    {
        return ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            "store/transport callback pointer is null",
        )
        .into();
    }

    let channel_store = DotnetChannelStore {
        cb: unsafe { std::ptr::read(channel_store_cb) },
    };
    let secret_store = DotnetSecretStore {
        cb: unsafe { std::ptr::read(secret_store_cb) },
    };
    let share_store = DotnetShareStore {
        cb: unsafe { std::ptr::read(share_store_cb) },
    };
    let user_secret_store = DotnetUserSecretStore {
        cb: unsafe { std::ptr::read(user_secret_store_cb) },
    };
    let state_store = DotnetStateStore {
        cb: unsafe { std::ptr::read(state_store_cb) },
    };
    let transport = DotnetTransport {
        cb: unsafe { std::ptr::read(transport_cb) },
    };

    let builder = DeRecProtocolBuilder::new(secret_id)
        .with_channel_store(channel_store)
        .with_share_store(share_store)
        .with_secret_store(secret_store)
        .with_user_secret_store(user_secret_store)
        .with_state_store(state_store)
        .with_transport(transport)
        .with_config(config);

    let inner = match builder.build() {
        Ok(p) => p,
        Err(e) => return crate::interop::ffi::error::from_lib_error(e).into(),
    };

    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(e) => {
            return ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                format!("failed to build tokio runtime: {e}"),
            )
            .into();
        }
    };

    let handle = Box::new(DeRecProtocolHandle {
        runtime,
        inner: std::sync::Mutex::new(inner),
    });
    DeRecProtocolNewResult {
        error: success(),
        handle: Box::into_raw(handle),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::ffi::error::DEREC_CODE_TRANSPORT_INVALID;
    use crate::protocol::UnpairAck;

    /// The error's code and message, with the error released.
    fn take(mut err: DeRecError) -> (i32, String) {
        let message = if err.message.is_null() {
            String::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(err.message) }
                .to_string_lossy()
                .into_owned()
        };
        let code = err.code;
        unsafe { crate::interop::ffi::error::derec_free_error(&mut err) };
        (code, message)
    }

    fn parse(json: &str) -> Result<(u64, DeRecProtocolConfig), (i32, String)> {
        parse_config(json.as_bytes()).map_err(take)
    }

    fn parsed(json: &str) -> DeRecProtocolConfig {
        match parse(json) {
            Ok((_, config)) => config,
            Err((code, message)) => panic!("{json} refused with {code}: {message}"),
        }
    }

    fn refused(json: &str) -> (i32, String) {
        match parse(json) {
            Ok(_) => panic!("{json} must be refused"),
            Err(e) => e,
        }
    }

    /// `secret_id` alone is a valid config: every other setting is left to
    /// the builder's own default.
    #[test]
    fn secret_id_alone_leaves_every_setting_unset() {
        let (secret_id, config) = parse(r#"{"secret_id": "18446744073709551615"}"#)
            .unwrap_or_else(|(c, m)| panic!("{c}: {m}"));
        assert_eq!(secret_id, u64::MAX);
        assert_eq!(config, DeRecProtocolConfig::default());
    }

    /// `secret_id` is required and is a decimal-string `u64`.
    #[test]
    fn secret_id_is_a_required_decimal_string() {
        for bad in [
            r#"{}"#,
            r#"{"secret_id": 1}"#,
            r#"{"secret_id": null}"#,
            r#"{"secret_id": "12x"}"#,
            r#"{"secret_id": "-1"}"#,
        ] {
            let (code, message) = refused(bad);
            assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO, "{bad}: {message}");
            assert!(message.contains("secret_id"), "{bad}: {message}");
        }
        let (code, _) = refused("not json");
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO);
        let (code, _) = refused(r#"["secret_id"]"#);
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO);
    }

    /// A key the canonical config does not define is refused, at the top
    /// level and inside nested objects, instead of being ignored.
    #[test]
    fn unknown_keys_are_refused() {
        for bad in [
            r#"{"secret_id": "1", "own_transport_uri": "", "own_transport_protocol": 1}"#,
            r#"{"secret_id": "1", "treshold": 3}"#,
            r#"{"secret_id": "1", "timeouts": {"sharing_round": 30}}"#,
            r#"{"secret_id": "1", "auto_accept": {"pair": true}}"#,
            r#"{"secret_id": "1", "own_transports": [{"uri": "https://a.example", "protocol": "https", "weight": 1}]}"#,
        ] {
            let (code, message) = refused(bad);
            assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO, "{bad}: {message}");
            assert!(message.contains("unknown field"), "{bad}: {message}");
        }
    }

    /// `unpair_ack` takes the discriminant or the binding-facing name; any
    /// other code or name is refused as an invalid enum value.
    #[test]
    fn unpair_ack_accepts_code_or_name_and_refuses_the_rest() {
        let ack = |value: &str| {
            parsed(&format!(r#"{{"secret_id": "1", "unpair_ack": {value}}}"#)).unpair_ack
        };
        assert_eq!(ack("0"), Some(UnpairAck::Required));
        assert_eq!(ack("1"), Some(UnpairAck::NotRequired));
        assert_eq!(ack(r#""required""#), Some(UnpairAck::Required));
        assert_eq!(ack(r#""not_required""#), Some(UnpairAck::NotRequired));
        assert_eq!(ack("null"), None);
        for bad in ["2", "-1", r#""Required""#, r#""notrequired""#] {
            let (code, message) = refused(&format!(r#"{{"secret_id": "1", "unpair_ack": {bad}}}"#));
            assert_eq!(code, DEREC_CODE_FFI_INVALID_ENUM, "{bad}: {message}");
            assert!(message.contains("invalid unpair_ack"), "{bad}: {message}");
        }
        let (code, _) = refused(r#"{"secret_id": "1", "unpair_ack": true}"#);
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO);
    }

    /// An own transport's `protocol` is its name or a known discriminant. An
    /// unknown discriminant is an invalid transport; an unknown name does not
    /// parse.
    #[test]
    fn own_transport_protocols_take_a_name_or_a_known_discriminant() {
        let config = parsed(
            r#"{"secret_id": "1", "own_transports": [
                {"uri": "https://a.example/derec", "protocol": 0},
                {"uri": "grpcs://a.example:443", "protocol": "GRPC"}
            ]}"#,
        );
        let transports = config.own_transports.expect("set");
        assert_eq!(transports[0].protocol, derec_proto::Protocol::Https);
        assert_eq!(transports[1].protocol, derec_proto::Protocol::Grpc);

        let (code, message) = refused(
            r#"{"secret_id": "1", "own_transports": [{"uri": "https://a.example", "protocol": 99}]}"#,
        );
        assert_eq!(code, DEREC_CODE_TRANSPORT_INVALID, "{message}");

        let (code, message) = refused(
            r#"{"secret_id": "1", "own_transports": [{"uri": "https://a.example", "protocol": "smtp"}]}"#,
        );
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO, "{message}");
    }

    /// The `u64` settings are decimal strings; anything else does not parse.
    #[test]
    fn u64_settings_are_decimal_strings() {
        let config = parsed(
            r#"{"secret_id": "1", "max_subshares": "18446744073709551615", "replica_id": "9007199254740993"}"#,
        );
        assert_eq!(config.max_subshares, Some(u64::MAX));
        assert_eq!(config.replica_id, Some(9_007_199_254_740_993));
        let config = parsed(r#"{"secret_id": "1", "max_subshares": null, "replica_id": null}"#);
        assert_eq!(config.max_subshares, None);
        assert_eq!(config.replica_id, None);
        for bad in [
            r#"{"secret_id": "1", "max_subshares": "12x"}"#,
            r#"{"secret_id": "1", "max_subshares": 12}"#,
            r#"{"secret_id": "1", "replica_id": "12x"}"#,
            r#"{"secret_id": "1", "replica_id": 5}"#,
        ] {
            let (code, message) = refused(bad);
            assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO, "{bad}: {message}");
        }
    }

    /// Parameter-range bounds keep full `i64` precision when written as
    /// decimal strings, still accept JSON numbers, and default to `0`.
    #[test]
    fn parameter_range_accepts_decimal_strings_and_numbers() {
        let config = parsed(
            r#"{"secret_id": "1", "parameter_range": {
                "min_share_size": "9007199254740993",
                "max_share_size": 4096,
                "max_unresponsive_deactivation_timeout": "-9223372036854775808"
            }}"#,
        );
        let range = config.parameter_range.expect("range present");
        assert_eq!(range.min_share_size, 9_007_199_254_740_993);
        assert_eq!(range.max_share_size, 4096);
        assert_eq!(range.max_unresponsive_deactivation_timeout, i64::MIN);
        assert_eq!(range.min_time_between_verifications, 0);

        let (code, _) =
            refused(r#"{"secret_id": "1", "parameter_range": {"min_share_size": "12x"}}"#);
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO);
    }

    /// `communication_info` in the config JSON is used as-is, the proto
    /// buffer is still honored when the key is absent, and supplying both
    /// is rejected.
    #[test]
    fn communication_info_comes_from_exactly_one_source() {
        let config = parsed(r#"{"secret_id": "1", "communication_info": {"name": "alice"}}"#);
        let from_json =
            unsafe { resolve_communication_info(config.communication_info, std::ptr::null(), 0) }
                .unwrap_or_else(|e| panic!("json map refused: {}", e.code));
        assert_eq!(from_json.get("name").map(String::as_str), Some("alice"));

        let mut map = HashMap::new();
        map.insert("name".to_owned(), "bob".to_owned());
        let proto = derec_proto::CommunicationInfo::from_map(&map).encode_to_vec();
        let from_proto = unsafe { resolve_communication_info(None, proto.as_ptr(), proto.len()) }
            .unwrap_or_else(|e| panic!("proto buffer refused: {}", e.code));
        assert_eq!(from_proto, map);

        let neither = unsafe { resolve_communication_info(None, std::ptr::null(), 0) }
            .unwrap_or_else(|e| panic!("absent refused: {}", e.code));
        assert!(neither.is_empty());

        let both = unsafe {
            resolve_communication_info(Some(HashMap::new()), proto.as_ptr(), proto.len())
        };
        let (code, _) = take(both.expect_err("both sources rejected"));
        assert_eq!(code, DEREC_CODE_FFI_BAD_PROTO);
    }

    type InMemProtocol = crate::protocol::DeRecProtocol<
        crate::protocol::test::InMemChannelStore,
        crate::protocol::test::InMemShareStore,
        crate::protocol::test::InMemSecretStore,
        crate::protocol::test::InMemUserSecretStore,
        crate::protocol::test::InMemStateStore,
        crate::protocol::test::NoopTransport,
    >;

    /// Builds through the same path as [`derec_protocol_new`], with the
    /// in-memory store doubles in place of the host's callback tables.
    fn build_from(json: &str) -> crate::Result<InMemProtocol> {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport,
        };
        let (secret_id, config) = parse(json).unwrap_or_else(|(c, m)| panic!("{c}: {m}"));
        DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_state_store(InMemStateStore)
            .with_transport(NoopTransport)
            .with_config(config)
            .build()
    }

    /// A JSON config naming every field builds, and each field lands on the
    /// resulting protocol with the value the JSON gave it.
    #[test]
    fn a_full_json_config_builds_with_every_field_applied() {
        let protocol = build_from(
            r#"{
                "secret_id": "12345678901234567890",
                "own_transports": [{ "uri": "https://example.com/derec", "protocol": "https" }],
                "threshold": 3,
                "auto_respond_on_failure": false,
                "unpair_ack": 0,
                "auto_reply_to": false,
                "auto_accept": {
                    "pairing": false, "pre_pair": false, "store_share": false,
                    "verify_share": false, "discovery": false, "get_share": false,
                    "unpair": false, "update_channel_info": false
                },
                "timeouts": {
                    "inbound_message_secs": 300,
                    "sharing_round_secs": 60,
                    "unpair_ack_secs": 60,
                    "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
                },
                "unsafe_connection": false,
                "replica_id": null,
                "parameter_range": {
                    "min_share_size": 0, "max_share_size": 0,
                    "min_time_between_verifications": 0, "max_time_between_verifications": 0,
                    "min_time_between_share_updates": 0, "max_time_between_share_updates": 0,
                    "min_unresponsive_deletion_timeout": 0, "max_unresponsive_deletion_timeout": 0,
                    "min_unresponsive_deactivation_timeout": 0,
                    "max_unresponsive_deactivation_timeout": 0
                },
                "max_subshares": null
            }"#,
        )
        .expect("documented config builds");
        assert_eq!(protocol.secret_id(), 12_345_678_901_234_567_890);
        assert_eq!(protocol.replica_id, None);
        assert_eq!(protocol.max_subshares, None);
        assert_eq!(
            protocol.own_transports[0].uri,
            "https://example.com/derec".to_owned()
        );
    }

    /// A config with no own transports is refused when the protocol is
    /// built, as before.
    #[test]
    fn a_config_without_own_transports_does_not_build() {
        match build_from(r#"{"secret_id": "1"}"#) {
            Err(crate::Error::InvalidInput(message)) => {
                assert!(message.contains("own transports"), "{message}")
            }
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("a config without own transports must not build"),
        }
    }

    /// An own transport whose URI fails validation is refused at build with
    /// the transport error the FFI reports as `DEREC_CODE_TRANSPORT_INVALID`.
    #[test]
    fn an_invalid_own_transport_uri_is_a_transport_error() {
        let err = match build_from(
            r#"{"secret_id": "1", "own_transports": [{"uri": "not a uri", "protocol": "https"}]}"#,
        ) {
            Err(e) => e,
            Ok(_) => panic!("an invalid URI must not build"),
        };
        let (code, _) = take(crate::interop::ffi::error::from_lib_error(err));
        assert_eq!(code, DEREC_CODE_TRANSPORT_INVALID);
    }

    /// Both configs of the shared fixture every SDK loads build through the
    /// FFI path once a `secret_id` is added.
    #[test]
    fn the_shared_fixture_configs_build() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../tests/fixtures/protocol_config.json"
        ))
        .expect("fixture is JSON");
        for name in ["full", "minimal"] {
            let mut config = fixture[name].clone();
            config
                .as_object_mut()
                .expect("config is an object")
                .insert("secret_id".to_owned(), "7".into());
            let protocol = build_from(&config.to_string())
                .unwrap_or_else(|e| panic!("`{name}` fixture does not build: {e:?}"));
            assert_eq!(protocol.secret_id(), 7);
        }
    }
}
