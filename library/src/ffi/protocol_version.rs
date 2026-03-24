//! C FFI exports for querying the current DeRec protocol version.
//!
//! This module provides a minimal C-compatible interface for retrieving the
//! protocol version used by the underlying Rust SDK.
//!
//! # Purpose
//!
//! The DeRec protocol includes explicit versioning (major/minor) that is embedded
//! in [`DeRecMessage`] envelopes. Foreign language bindings may need to:
//!
//! - Inspect the current protocol version
//! - Expose it for debugging or logging
//! - Ensure compatibility between components
//!
//! This module exposes that information through a simple value-returning function
//! with no dynamic allocation.
//!
//! # FFI Conventions
//!
//! - The version is returned as a plain `#[repr(C)]` struct
//! - No heap allocation or buffer management is involved
//! - The function is pure and has no side effects
//!
//! # Notes
//!
//! - The returned version corresponds to [`ProtocolVersion::current`] in the Rust SDK
//! - Version values are stable for a given build of the library
//! - Callers should treat the version as informational unless they implement
//!   explicit compatibility logic

/// C-compatible representation of the DeRec protocol version.
///
/// This struct mirrors the Rust [`ProtocolVersion`] type and contains:
///
/// - `major`: Major protocol version
/// - `minor`: Minor protocol version
///
/// The meaning of these fields follows standard semantic versioning conventions:
///
/// - Changes to `major` indicate breaking protocol changes
/// - Changes to `minor` indicate backward-compatible additions or updates
#[repr(C)]
pub struct DeRecProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

/// Returns the current DeRec protocol version used by the SDK.
///
/// This function is a simple FFI accessor over [`ProtocolVersion::current`].
///
/// # Returns
///
/// Returns a [`DeRecProtocolVersion`] struct containing:
///
/// - `major`: Major protocol version
/// - `minor`: Minor protocol version
///
/// # Errors
///
/// This function does not fail and always returns a valid version.
///
/// # Safety
///
/// This function does not take any pointers and does not perform any unsafe
/// memory access. It is safe to call from any foreign language environment.
#[unsafe(no_mangle)]
pub extern "C" fn derec_protocol_version() -> DeRecProtocolVersion {
    let version = crate::protocol_version::ProtocolVersion::current();

    DeRecProtocolVersion {
        major: version.major,
        minor: version.minor,
    }
}
