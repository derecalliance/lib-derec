// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Transport protocol names for FFI hosts that expose endpoints by name.
//!
//! The WASM bindings hand JavaScript `{ protocol: "https" | "grpc", uri }`.
//! A host binding over the C ABI that offers the same shape asks the crate
//! for the mapping through these accessors rather than keeping a copy of it.

use std::ffi::c_char;

/// Static NUL-terminated name (`"https"` or `"grpc"`) for a
/// `derec_proto::Protocol` discriminant.
///
/// Returns NULL for a discriminant outside the defined protocols. The
/// returned pointer has static lifetime and must **not** be freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_transport_protocol_name(protocol: i32) -> *const c_char {
    let name: &'static str =
        match crate::interop::protocol_names::protocol_discriminant_to_name(protocol) {
            Some("https") => "https\0",
            Some("grpc") => "grpc\0",
            _ => return std::ptr::null(),
        };
    name.as_ptr() as *const c_char
}

/// `derec_proto::Protocol` discriminant for a protocol name, compared
/// case-insensitively.
///
/// Returns `-1` when the name is not valid UTF-8 or names no defined
/// protocol.
///
/// # Safety
///
/// `name_ptr`/`name_len` must describe a readable byte range, or `name_len`
/// must be zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn derec_transport_protocol_discriminant(
    name_ptr: *const u8,
    name_len: usize,
) -> i32 {
    if name_ptr.is_null() || name_len == 0 {
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts(name_ptr, name_len) };
    std::str::from_utf8(bytes)
        .ok()
        .and_then(crate::interop::protocol_names::protocol_name_to_discriminant)
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn name(protocol: i32) -> Option<String> {
        let ptr = derec_transport_protocol_name(protocol);
        (!ptr.is_null()).then(|| {
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned()
        })
    }

    fn discriminant(name: &str) -> i32 {
        unsafe { derec_transport_protocol_discriminant(name.as_ptr(), name.len()) }
    }

    #[test]
    fn every_defined_protocol_has_a_name_that_maps_back() {
        for protocol in [derec_proto::Protocol::Https, derec_proto::Protocol::Grpc] {
            let n = name(protocol.into()).expect("defined protocol has a name");
            assert_eq!(discriminant(&n), protocol as i32);
        }
        assert_eq!(
            name(derec_proto::Protocol::Grpc.into()).as_deref(),
            Some("grpc")
        );
    }

    #[test]
    fn undefined_values_are_reported_not_guessed() {
        assert_eq!(name(99), None);
        assert_eq!(discriminant("websocket"), -1);
        assert_eq!(discriminant(""), -1);
        assert_eq!(discriminant("GRPC"), derec_proto::Protocol::Grpc as i32);
    }
}
