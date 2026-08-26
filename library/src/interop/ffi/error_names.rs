// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Stable string names for the numeric `DEREC_CATEGORY_*` / `DEREC_CODE_*`
//! discriminants.
//!
//! The WASM bindings surface errors to JavaScript as strings, while the C ABI
//! carries `i32`. These accessors let an FFI consumer produce the identical
//! strings without embedding a copy of the mapping, keeping the crate the
//! single source of truth for error naming.

use std::ffi::c_char;

use crate::interop::ffi::error::*;

/// Static NUL-terminated name for a `DEREC_CATEGORY_*` value.
///
/// Returns `"unknown"` for unrecognized values. The returned pointer has
/// static lifetime and must **not** be freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_error_category_name(category: i32) -> *const c_char {
    let name: &'static str = match category {
        DEREC_CATEGORY_OK => "ok\0",
        DEREC_CATEGORY_FFI => "ffi\0",
        DEREC_CATEGORY_PAIRING => "pairing\0",
        DEREC_CATEGORY_SHARING => "sharing\0",
        DEREC_CATEGORY_RECOVERY => "recovery\0",
        DEREC_CATEGORY_VERIFICATION => "verification\0",
        DEREC_CATEGORY_DISCOVERY => "discovery\0",
        DEREC_CATEGORY_UNPAIRING => "unpairing\0",
        DEREC_CATEGORY_DEREC_MESSAGE => "derec_message\0",
        DEREC_CATEGORY_SECRET_STORE => "secret_store\0",
        DEREC_CATEGORY_CHANNEL_STORE => "channel_store\0",
        DEREC_CATEGORY_SHARE_STORE => "share_store\0",
        DEREC_CATEGORY_INVALID_INPUT => "input\0",
        DEREC_CATEGORY_PROTOBUF => "protobuf\0",
        DEREC_CATEGORY_INVARIANT => "invariant\0",
        DEREC_CATEGORY_STATE_STORE => "state_store\0",
        _ => "unknown\0",
    };
    name.as_ptr() as *const c_char
}

/// Static NUL-terminated name for a `DEREC_CODE_*` value.
///
/// Returns `"unknown"` for unrecognized values. The returned pointer has
/// static lifetime and must **not** be freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_error_code_name(code: i32) -> *const c_char {
    let name: &'static str = match code {
        DEREC_CODE_OK => "ok\0",
        DEREC_CODE_NON_OK_STATUS => "non_ok_status\0",
        DEREC_CODE_VERSION_MISMATCH => "version_mismatch\0",
        DEREC_CODE_INVARIANT => "invariant\0",
        DEREC_CODE_INVALID_INPUT => "invalid_input\0",
        DEREC_CODE_PROTOBUF_DECODE => "protobuf_decode\0",
        DEREC_CODE_PROTOBUF_ENCODE => "protobuf_encode\0",
        DEREC_CODE_PROTOCOL_VIOLATION => "protocol_violation\0",
        DEREC_CODE_STORE_ERROR => "store_error\0",
        DEREC_CODE_BUILDER_ERROR => "builder_error\0",
        DEREC_CODE_MISSING_SHARED_KEY => "missing_shared_key\0",
        DEREC_CODE_ROLE_MISMATCH => "role_mismatch\0",
        DEREC_CODE_REPLICA_ID_NOT_CONFIGURED => "replica_id_not_configured\0",
        DEREC_CODE_CHANNEL_ALREADY_PAIRED => "channel_already_paired\0",
        DEREC_CODE_ALREADY_RESTORED => "already_restored\0",
        DEREC_CODE_RESTORE_CONFLICT => "restore_conflict\0",
        DEREC_CODE_REPLICA_ID_CONFLICT => "replica_id_conflict\0",
        DEREC_CODE_ENCRYPTION => "encryption\0",
        DEREC_CODE_KEYGEN => "keygen\0",
        DEREC_CODE_FINISH_PAIRING_INITIATOR => "finish_pairing_initiator\0",
        DEREC_CODE_FINISH_PAIRING_RESPONDER => "finish_pairing_responder\0",
        DEREC_CODE_EMPTY_TRANSPORT_URI => "empty_transport_uri\0",
        DEREC_CODE_INVALID_CONTACT_MESSAGE => "invalid_contact_message\0",
        DEREC_CODE_INVALID_PAIR_REQUEST_MESSAGE => "invalid_pair_request_message\0",
        DEREC_CODE_INVALID_PAIR_RESPONSE_MESSAGE => "invalid_pair_response_message\0",
        DEREC_CODE_PREPAIR_HASH_MISMATCH => "prepair_hash_mismatch\0",
        DEREC_CODE_MISSING_REPLICA_ID => "missing_replica_id\0",
        DEREC_CODE_UNEXPECTED_REPLICA_ID => "unexpected_replica_id\0",
        DEREC_CODE_INCOMPATIBLE_PARAMETER_RANGE => "incompatible_parameter_range\0",
        DEREC_CODE_EMPTY_CHANNELS => "empty_channels\0",
        DEREC_CODE_DUPLICATE_CHANNEL_ID => "duplicate_channel_id\0",
        DEREC_CODE_INVALID_THRESHOLD => "invalid_threshold\0",
        DEREC_CODE_EMPTY_SECRET_DATA => "empty_secret_data\0",
        DEREC_CODE_VSS_SHARE_FAILED => "vss_share_failed\0",
        DEREC_CODE_EMPTY_RESPONSES => "empty_responses\0",
        DEREC_CODE_EMPTY_COMMITTED_DEREC_SHARE => "empty_committed_derec_share\0",
        DEREC_CODE_DECODE_COMMITTED_DEREC_SHARE => "decode_committed_derec_share\0",
        DEREC_CODE_DECODE_DEREC_SHARE => "decode_derec_share\0",
        DEREC_CODE_SECRET_ID_MISMATCH => "secret_id_mismatch\0",
        DEREC_CODE_RECONSTRUCTION_FAILED => "reconstruction_failed\0",
        DEREC_CODE_MALFORMED_RECOVERED_SECRET => "malformed_recovered_secret\0",
        DEREC_CODE_FFI_NULL_PTR => "ffi_null_ptr\0",
        DEREC_CODE_FFI_BAD_LENGTH => "ffi_bad_length\0",
        DEREC_CODE_FFI_BAD_UTF8 => "ffi_bad_utf8\0",
        DEREC_CODE_FFI_BAD_PROTO => "ffi_bad_proto\0",
        DEREC_CODE_FFI_INVALID_ENUM => "ffi_invalid_enum\0",
        DEREC_CODE_FFI_BAD_SHARED_KEY => "ffi_bad_shared_key\0",
        DEREC_CODE_FFI_NUL_IN_STRING => "ffi_nul_in_string\0",
        DEREC_CODE_TRANSPORT_INVALID => "transport_invalid\0",
        _ => "unknown\0",
    };
    name.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn category(value: i32) -> String {
        unsafe { CStr::from_ptr(derec_error_category_name(value)) }
            .to_string_lossy()
            .into_owned()
    }

    fn code(value: i32) -> String {
        unsafe { CStr::from_ptr(derec_error_code_name(value)) }
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn category_names_match_the_wasm_surface() {
        assert_eq!(
            category(crate::interop::ffi::error::DEREC_CATEGORY_OK),
            "ok"
        );
        assert_eq!(
            category(crate::interop::ffi::error::DEREC_CATEGORY_FFI),
            "ffi"
        );
        assert_eq!(
            category(crate::interop::ffi::error::DEREC_CATEGORY_PAIRING),
            "pairing"
        );
        assert_eq!(
            category(crate::interop::ffi::error::DEREC_CATEGORY_SHARE_STORE),
            "share_store"
        );
        assert_eq!(
            category(crate::interop::ffi::error::DEREC_CATEGORY_INVALID_INPUT),
            "input"
        );
    }

    #[test]
    fn code_names_are_stable() {
        assert_eq!(code(crate::interop::ffi::error::DEREC_CODE_OK), "ok");
        assert_eq!(
            code(crate::interop::ffi::error::DEREC_CODE_NON_OK_STATUS),
            "non_ok_status"
        );
        assert_eq!(
            code(crate::interop::ffi::error::DEREC_CODE_MISSING_SHARED_KEY),
            "missing_shared_key"
        );
    }

    #[test]
    fn unknown_values_do_not_panic() {
        assert_eq!(category(9999), "unknown");
        assert_eq!(code(-1), "unknown");
    }

    #[test]
    fn every_declared_code_has_a_name() {
        // Guards against a new DEREC_CODE_* constant landing without a name.
        // Iterates DECLARED_CODES directly rather than a numeric range, so
        // codes outside any particular range (e.g. the FFI_* and
        // TRANSPORT_* families) are still covered.
        for &value in DECLARED_CODES {
            assert_ne!(code(value), "unknown", "declared code {value} has no name");
        }
    }

    #[test]
    fn undeclared_codes_are_unknown() {
        for value in [7777, 8888, -5] {
            assert!(
                !DECLARED_CODES.contains(&value),
                "test value {value} collides with a declared code"
            );
            assert_eq!(code(value), "unknown");
        }
    }

    const DECLARED_CODES: &[i32] = &[
        crate::interop::ffi::error::DEREC_CODE_OK,
        crate::interop::ffi::error::DEREC_CODE_NON_OK_STATUS,
        crate::interop::ffi::error::DEREC_CODE_VERSION_MISMATCH,
        crate::interop::ffi::error::DEREC_CODE_INVARIANT,
        crate::interop::ffi::error::DEREC_CODE_INVALID_INPUT,
        crate::interop::ffi::error::DEREC_CODE_PROTOBUF_DECODE,
        crate::interop::ffi::error::DEREC_CODE_PROTOBUF_ENCODE,
        crate::interop::ffi::error::DEREC_CODE_PROTOCOL_VIOLATION,
        crate::interop::ffi::error::DEREC_CODE_STORE_ERROR,
        crate::interop::ffi::error::DEREC_CODE_BUILDER_ERROR,
        crate::interop::ffi::error::DEREC_CODE_MISSING_SHARED_KEY,
        crate::interop::ffi::error::DEREC_CODE_ROLE_MISMATCH,
        crate::interop::ffi::error::DEREC_CODE_REPLICA_ID_NOT_CONFIGURED,
        crate::interop::ffi::error::DEREC_CODE_CHANNEL_ALREADY_PAIRED,
        crate::interop::ffi::error::DEREC_CODE_ALREADY_RESTORED,
        crate::interop::ffi::error::DEREC_CODE_RESTORE_CONFLICT,
        crate::interop::ffi::error::DEREC_CODE_REPLICA_ID_CONFLICT,
        crate::interop::ffi::error::DEREC_CODE_ENCRYPTION,
        crate::interop::ffi::error::DEREC_CODE_KEYGEN,
        crate::interop::ffi::error::DEREC_CODE_FINISH_PAIRING_INITIATOR,
        crate::interop::ffi::error::DEREC_CODE_FINISH_PAIRING_RESPONDER,
        crate::interop::ffi::error::DEREC_CODE_EMPTY_TRANSPORT_URI,
        crate::interop::ffi::error::DEREC_CODE_INVALID_CONTACT_MESSAGE,
        crate::interop::ffi::error::DEREC_CODE_INVALID_PAIR_REQUEST_MESSAGE,
        crate::interop::ffi::error::DEREC_CODE_INVALID_PAIR_RESPONSE_MESSAGE,
        crate::interop::ffi::error::DEREC_CODE_PREPAIR_HASH_MISMATCH,
        crate::interop::ffi::error::DEREC_CODE_MISSING_REPLICA_ID,
        crate::interop::ffi::error::DEREC_CODE_UNEXPECTED_REPLICA_ID,
        crate::interop::ffi::error::DEREC_CODE_INCOMPATIBLE_PARAMETER_RANGE,
        crate::interop::ffi::error::DEREC_CODE_EMPTY_CHANNELS,
        crate::interop::ffi::error::DEREC_CODE_DUPLICATE_CHANNEL_ID,
        crate::interop::ffi::error::DEREC_CODE_INVALID_THRESHOLD,
        crate::interop::ffi::error::DEREC_CODE_EMPTY_SECRET_DATA,
        crate::interop::ffi::error::DEREC_CODE_VSS_SHARE_FAILED,
        crate::interop::ffi::error::DEREC_CODE_EMPTY_RESPONSES,
        crate::interop::ffi::error::DEREC_CODE_EMPTY_COMMITTED_DEREC_SHARE,
        crate::interop::ffi::error::DEREC_CODE_DECODE_COMMITTED_DEREC_SHARE,
        crate::interop::ffi::error::DEREC_CODE_DECODE_DEREC_SHARE,
        crate::interop::ffi::error::DEREC_CODE_SECRET_ID_MISMATCH,
        crate::interop::ffi::error::DEREC_CODE_RECONSTRUCTION_FAILED,
        crate::interop::ffi::error::DEREC_CODE_MALFORMED_RECOVERED_SECRET,
        crate::interop::ffi::error::DEREC_CODE_FFI_NULL_PTR,
        crate::interop::ffi::error::DEREC_CODE_FFI_BAD_LENGTH,
        crate::interop::ffi::error::DEREC_CODE_FFI_BAD_UTF8,
        crate::interop::ffi::error::DEREC_CODE_FFI_BAD_PROTO,
        crate::interop::ffi::error::DEREC_CODE_FFI_INVALID_ENUM,
        crate::interop::ffi::error::DEREC_CODE_FFI_BAD_SHARED_KEY,
        crate::interop::ffi::error::DEREC_CODE_FFI_NUL_IN_STRING,
        crate::interop::ffi::error::DEREC_CODE_TRANSPORT_INVALID,
    ];
}
