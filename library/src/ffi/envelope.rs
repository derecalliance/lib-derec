// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! C FFI for envelope-level helpers that operate on raw DeRecMessage bytes.
//!
//! The outer `DeRecMessage` envelope is plaintext, so a handful of metadata
//! fields can be read or rewritten without touching the encrypted inner
//! payload. Today these helpers expose only `trace_id` — the opaque
//! correlation token described on `DeRecMessage.traceId` — but the module is
//! the natural home for any future envelope-level utilities.

use crate::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, success,
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
        unsafe { std::slice::from_raw_parts(envelope_ptr, envelope_len) }
    };

    match crate::derec_message::apply_trace_id(bytes, trace_id) {
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
        unsafe { std::slice::from_raw_parts(envelope_ptr, envelope_len) }
    };

    match crate::derec_message::read_trace_id(bytes) {
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
