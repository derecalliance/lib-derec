// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! C FFI for envelope-level helpers that operate on raw DeRecMessage bytes.
//!
//! The outer `DeRecMessage` envelope is plaintext, so a handful of metadata
//! fields can be read or rewritten without touching the encrypted inner
//! payload: `trace_id`, the opaque correlation token described on
//! `DeRecMessage.traceId`, and the message identity the application's
//! replay detection keys on.

use std::slice;

use crate::derec_message::{apply_trace_id, message_id, read_trace_id};
use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, from_lib_error,
    success,
};

#[repr(C)]
pub struct ApplyTraceIdResult {
    pub error: DeRecError,
    /// Re-encoded envelope bytes with `trace_id` overwritten. Empty on error.
    pub wire_bytes: DeRecBuffer,
}

#[repr(C)]
pub struct ReadTraceIdResult {
    pub error: DeRecError,
    /// Trace id read off the envelope. Zero on error (also zero if the
    /// sender did not set one — the protobuf default is indistinguishable).
    pub trace_id: u64,
}

#[repr(C)]
pub struct MessageIdResult {
    pub error: DeRecError,
    /// SHA-256 of the envelope's encrypted `message` field (32 bytes). Empty
    /// on error.
    pub id: DeRecBuffer,
    /// The envelope's send time, in seconds since the Unix epoch. Zero on
    /// error.
    pub timestamp: u64,
}

/// Overwrite `trace_id` on an already-produced envelope and return the
/// re-encoded bytes.
///
/// Mirrors [`crate::derec_message::apply_trace_id`]. Useful for FFI consumers
/// using primitives directly: the `produce_*_request_message` family emits
/// envelopes with `trace_id = 0`, so callers who want correlation produce +
/// then call this. The orchestrator does this automatically end-to-end.
///
/// # Safety
///
/// `envelope_ptr` must point to a readable byte range of length `envelope_len`.
#[unsafe(no_mangle)]
pub extern "C" fn apply_trace_id_to_envelope(
    envelope_ptr: *const u8,
    envelope_len: usize,
    trace_id: u64,
) -> ApplyTraceIdResult {
    let with_err = |error| ApplyTraceIdResult {
        error,
        wire_bytes: empty_buffer(),
    };

    if envelope_ptr.is_null() && envelope_len > 0 {
        return with_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "envelope_ptr is null"));
    }
    let bytes = if envelope_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(envelope_ptr, envelope_len) }
    };

    match apply_trace_id(bytes, trace_id) {
        Ok(out) => ApplyTraceIdResult {
            error: success(),
            wire_bytes: vec_into_buffer(out),
        },
        Err(_) => with_err(ffi_error(
            DEREC_CODE_FFI_BAD_PROTO,
            "failed to decode DeRecMessage envelope",
        )),
    }
}

/// Read `trace_id` off an envelope without touching the encrypted inner
/// payload. Pair with [`apply_trace_id_to_envelope`] for primitive-level
/// request/response correlation.
///
/// # Safety
///
/// `envelope_ptr` must point to a readable byte range of length `envelope_len`.
#[unsafe(no_mangle)]
pub extern "C" fn read_trace_id_from_envelope(
    envelope_ptr: *const u8,
    envelope_len: usize,
) -> ReadTraceIdResult {
    if envelope_ptr.is_null() && envelope_len > 0 {
        return ReadTraceIdResult {
            error: ffi_error(DEREC_CODE_FFI_NULL_PTR, "envelope_ptr is null"),
            trace_id: 0,
        };
    }
    let bytes = if envelope_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(envelope_ptr, envelope_len) }
    };

    match read_trace_id(bytes) {
        Ok(trace_id) => ReadTraceIdResult {
            error: success(),
            trace_id,
        },
        Err(_) => ReadTraceIdResult {
            error: ffi_error(
                DEREC_CODE_FFI_BAD_PROTO,
                "failed to decode DeRecMessage envelope",
            ),
            trace_id: 0,
        },
    }
}

/// Identify an envelope for replay and reflection detection: the same `id`
/// for every copy of one message, whatever its unauthenticated cleartext
/// fields say, and a different one for every other message.
///
/// Mirrors [`crate::derec_message::message_id`].
///
/// # Safety
///
/// `envelope_ptr` must point to a readable byte range of length `envelope_len`.
#[unsafe(no_mangle)]
pub extern "C" fn message_id_from_envelope(
    envelope_ptr: *const u8,
    envelope_len: usize,
) -> MessageIdResult {
    let with_err = |error| MessageIdResult {
        error,
        id: empty_buffer(),
        timestamp: 0,
    };

    if envelope_ptr.is_null() && envelope_len > 0 {
        return with_err(ffi_error(DEREC_CODE_FFI_NULL_PTR, "envelope_ptr is null"));
    }
    let bytes = if envelope_len == 0 {
        &[][..]
    } else {
        unsafe { slice::from_raw_parts(envelope_ptr, envelope_len) }
    };

    match message_id(bytes) {
        Ok(identity) => MessageIdResult {
            error: success(),
            id: vec_into_buffer(identity.id.to_vec()),
            timestamp: identity.timestamp,
        },
        Err(error) => with_err(from_lib_error(error)),
    }
}
