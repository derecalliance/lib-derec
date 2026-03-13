use std::fmt;

/// DeRec protocol version supported by this SDK.
///
/// This type represents the protocol-level version carried in the
/// [`DeRecMessage`](derec_proto::DeRecMessage) envelope:
///
/// - `protocolVersionMajor`
/// - `protocolVersionMinor`
///
/// This is **not** the same as the Rust crate version, npm package version,
/// or NuGet package version. Package versions identify SDK releases, while
/// `ProtocolVersion` identifies the DeRec wire protocol version expected by
/// protocol messages.
///
/// # Fields
///
/// * `major` - Protocol major version.
/// * `minor` - Protocol minor version.
///
/// # Compatibility
///
/// The compatibility policy associated with protocol major/minor versions is
/// defined by the DeRec protocol specification, not by this helper type.
///
/// # Example
///
/// ```rust
/// use derec_library::protocol_version::ProtocolVersion;
///
/// let version = ProtocolVersion::current();
///
/// assert!(version.major >= 0);
/// assert!(version.minor >= 0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: i32,
    pub minor: i32,
}

impl ProtocolVersion {
    /// Returns the current DeRec protocol version supported by this SDK.
    ///
    /// This value corresponds to the protocol version that should be written
    /// into the `protocolVersionMajor` and `protocolVersionMinor` fields of
    /// the `DeRecMessage` envelope.
    ///
    /// This function reports the supported **protocol** version only. It does
    /// not expose the crate or package release version.
    ///
    /// # Returns
    ///
    /// Returns the current [`ProtocolVersion`] supported by this SDK.
    ///
    /// # Example
    ///
    /// ```rust
    /// use derec_library::protocol_version::ProtocolVersion;
    ///
    /// let version = ProtocolVersion::current();
    ///
    /// println!("DeRec protocol version: {}.{}", version.major, version.minor);
    /// ```
    pub const fn current() -> Self {
        CURRENT
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Current DeRec protocol version supported by this SDK.
///
/// This constant is the source of truth for the protocol version reported by
/// [`ProtocolVersion::current`].
///
/// # Example
///
/// ```rust
/// use derec_library::protocol_version::{CURRENT, ProtocolVersion};
///
/// assert_eq!(CURRENT, ProtocolVersion::current());
/// ```
pub const CURRENT: ProtocolVersion = ProtocolVersion { major: 0, minor: 0 };
