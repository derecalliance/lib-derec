// SPDX-License-Identifier: Apache-2.0

//! C FFI accessor for the current DeRec protocol version.

#[repr(C)]
pub struct DeRecProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

#[unsafe(no_mangle)]
pub extern "C" fn derec_protocol_version() -> DeRecProtocolVersion {
    let version = crate::protocol_version::ProtocolVersion::current();
    DeRecProtocolVersion {
        major: version.major,
        minor: version.minor,
    }
}
