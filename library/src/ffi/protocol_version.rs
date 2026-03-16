#[repr(C)]
pub struct DeRecProtocolVersion {
    pub major: i32,
    pub minor: i32,
}

#[unsafe(no_mangle)]
pub extern "C" fn derec_protocol_version() -> DeRecProtocolVersion {
    let version = crate::protocol_version::ProtocolVersion::current();

    DeRecProtocolVersion {
        major: version.major,
        minor: version.minor,
    }
}
