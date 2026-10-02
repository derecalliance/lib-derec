// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Stable string names for the numeric `DEREC_CATEGORY_*` / `DEREC_CODE_*`
//! discriminants.
//!
//! The WASM bindings surface errors to JavaScript as strings, while the C ABI
//! carries `i32`. These accessors let an FFI consumer produce the identical
//! strings without embedding a copy of the mapping; both read the one table
//! in `crate::interop::error_codes`.

use std::ffi::c_char;

use crate::interop::error_codes::{Category, Code};

/// Static NUL-terminated name for a `DEREC_CATEGORY_*` value.
///
/// Returns `"unknown"` for unrecognized values. The returned pointer has
/// static lifetime and must **not** be freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_error_category_name(category: i32) -> *const c_char {
    let name = Category::from_i32(category).map_or("unknown\0", Category::c_name);
    name.as_ptr() as *const c_char
}

/// Static NUL-terminated name for a `DEREC_CODE_*` value.
///
/// Returns `"unknown"` for unrecognized values. The returned pointer has
/// static lifetime and must **not** be freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_error_code_name(code: i32) -> *const c_char {
    let name = Code::from_i32(code).map_or("unknown\0", Code::c_name);
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

    /// Every `DEREC_CODE_*` constant declared in `error.rs`, read from the
    /// source so a new code cannot be left out of this check.
    fn declared_codes() -> Vec<(String, i32)> {
        include_str!("error.rs")
            .lines()
            .filter_map(|line| {
                let rest = line.trim().strip_prefix("pub const DEREC_CODE_")?;
                let (name, value) = rest.split_once(": i32 = ")?;
                let value = value.trim_end_matches(';').parse().ok()?;
                Some((format!("DEREC_CODE_{name}"), value))
            })
            .collect()
    }

    #[test]
    fn every_declared_code_has_a_name() {
        let declared = declared_codes();
        assert!(!declared.is_empty(), "no DEREC_CODE_* constants were read");
        for (name, value) in declared {
            assert_ne!(code(value), "unknown", "{name} ({value}) has no name");
        }
    }

    /// Each `DEREC_CATEGORY_*` constant is the discriminant of the matching
    /// table member.
    #[test]
    fn every_declared_category_matches_the_shared_table() {
        use crate::interop::ffi::error::*;
        let declared = [
            (DEREC_CATEGORY_OK, Category::Ok),
            (DEREC_CATEGORY_FFI, Category::Ffi),
            (DEREC_CATEGORY_PAIRING, Category::Pairing),
            (DEREC_CATEGORY_SHARING, Category::Sharing),
            (DEREC_CATEGORY_RECOVERY, Category::Recovery),
            (DEREC_CATEGORY_VERIFICATION, Category::Verification),
            (DEREC_CATEGORY_DISCOVERY, Category::Discovery),
            (DEREC_CATEGORY_UNPAIRING, Category::Unpairing),
            (DEREC_CATEGORY_DEREC_MESSAGE, Category::DeRecMessage),
            (DEREC_CATEGORY_SECRET_STORE, Category::SecretStore),
            (DEREC_CATEGORY_CHANNEL_STORE, Category::ChannelStore),
            (DEREC_CATEGORY_SHARE_STORE, Category::ShareStore),
            (DEREC_CATEGORY_INVALID_INPUT, Category::InvalidInput),
            (DEREC_CATEGORY_PROTOBUF, Category::Protobuf),
            (DEREC_CATEGORY_INVARIANT, Category::Invariant),
            (DEREC_CATEGORY_STATE_STORE, Category::StateStore),
        ];
        for (value, category) in declared {
            assert_eq!(value, category as i32, "{category:?}");
        }
        assert_eq!(declared.len(), Category::ALL.len());
    }

    /// Each `DEREC_CODE_*` constant is the discriminant of the table member
    /// whose name is the constant's suffix in lowercase, so the C header and
    /// the names WASM reports cannot drift apart.
    #[test]
    fn every_declared_code_matches_the_shared_table() {
        for (name, value) in declared_codes() {
            let suffix = name.trim_start_matches("DEREC_CODE_").to_lowercase();
            assert_eq!(code(value), suffix, "{name} ({value})");
        }
        assert_eq!(declared_codes().len(), Code::ALL.len());
    }

    #[test]
    fn undeclared_codes_are_unknown() {
        for value in [7777, 8888, -5] {
            assert!(
                !declared_codes().iter().any(|(_, v)| *v == value),
                "test value {value} collides with a declared code"
            );
            assert_eq!(code(value), "unknown");
        }
    }
}
