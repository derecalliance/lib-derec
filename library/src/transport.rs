// SPDX-License-Identifier: Apache-2.0

//! Library-level transport endpoint type + validation.
//!
//! This is the canonical [`TransportProtocol`] for library callers.
//! It mirrors [`derec_proto::TransportProtocol`] (the protobuf wire
//! type) but holds the protocol enum as a typed value rather than
//! a raw `i32`, exposes [`TransportProtocol::validate`] as a method,
//! and is `From<&str>` / `From<String>` for the common case where
//! the caller just has a URI in hand.
//!
//! ## Validation rules
//!
//! [`TransportProtocol::validate`] enforces:
//!
//! 1. **Length cap** — URI ≤ [`MAX_TRANSPORT_URI_LEN`] bytes.
//! 2. **No control characters** — bytes `< 0x20` or `= 0x7F` are
//!    rejected (NUL, embedded newlines, terminal escape codes).
//! 3. **Scheme matches the protocol** — `Protocol::Https` ⇒ the URI
//!    must start with `https://`. Catches plaintext / mismatched
//!    schemes (`http://`, `ws://`, …) being smuggled in alongside an
//!    HTTPS discriminant.
//! 4. **Non-empty URI** — `EmptyUri` is the explicit error.
//!
//! Unknown `protocol` discriminants are caught at the *conversion*
//! boundary by [`TryFrom<derec_proto::TransportProtocol>`] (or by
//! [`TryFrom<&derec_proto::TransportProtocol>`]), so they never reach
//! the typed [`TransportProtocol`] in the first place.

use derec_proto::Protocol;
use serde::{Deserialize, Serialize};

/// Maximum accepted transport URI length, in bytes.
///
/// Matches the de-facto 2048-byte limit most HTTP stacks enforce
/// for request URIs. Pairing payloads embed the URI verbatim, so
/// capping it also bounds the propagated blob size.
pub const MAX_TRANSPORT_URI_LEN: usize = 2048;

/// Library-level transport endpoint.
///
/// Use this type in your `DeRecProtocolBuilder` / `set_own_transport`
/// calls; the library converts to the protobuf wire form internally
/// when it needs to encode messages. Construct it from a string with
/// [`From`] / [`Into`] (which defaults the protocol to
/// [`Protocol::Https`], the only currently-defined variant), or
/// directly with [`TransportProtocol::new`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TransportProtocol {
    pub uri: String,
    /// Serialized as the protobuf enum's `i32` discriminant so the
    /// wire shape stays compatible with [`derec_proto::TransportProtocol`]
    /// — important because every binding's JSON Channel marshaller
    /// round-trips this field via the proto-style `{uri, protocol: 0}`
    /// representation.
    #[serde(with = "protocol_as_i32")]
    pub protocol: Protocol,
}

mod protocol_as_i32 {
    use super::Protocol;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(p: &Protocol, ser: S) -> Result<S::Ok, S::Error> {
        i32::from(*p).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Protocol, D::Error> {
        let raw = i32::deserialize(de)?;
        Protocol::try_from(raw).map_err(|_| {
            serde::de::Error::custom(format!("unknown Protocol discriminant {raw}"))
        })
    }
}

impl TransportProtocol {
    /// Construct a [`TransportProtocol`] directly from its components.
    pub fn new(uri: impl Into<String>, protocol: Protocol) -> Self {
        Self {
            uri: uri.into(),
            protocol,
        }
    }

    /// Validate the endpoint's structural soundness + scheme/protocol
    /// consistency. See the module docs for the rules.
    pub fn validate(&self) -> Result<(), TransportValidationError> {
        if self.uri.is_empty() {
            return Err(TransportValidationError::EmptyUri);
        }
        if self.uri.len() > MAX_TRANSPORT_URI_LEN {
            return Err(TransportValidationError::UriTooLong {
                got: self.uri.len(),
                limit: MAX_TRANSPORT_URI_LEN,
            });
        }
        if self.uri.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err(TransportValidationError::ControlCharacters);
        }
        let required_scheme = match self.protocol {
            Protocol::Https => "https://",
        };
        if !self.uri.starts_with(required_scheme) {
            return Err(TransportValidationError::SchemeMismatch {
                expected: required_scheme,
                protocol: self.protocol,
            });
        }
        Ok(())
    }
}

impl From<&str> for TransportProtocol {
    /// Build a [`TransportProtocol`] from a URI literal, defaulting
    /// the protocol enum to [`Protocol::Https`] — the only currently
    /// defined variant. Call [`TransportProtocol::validate`]
    /// afterwards to confirm the scheme matches.
    fn from(uri: &str) -> Self {
        Self {
            uri: uri.to_owned(),
            protocol: Protocol::Https,
        }
    }
}

impl From<String> for TransportProtocol {
    /// Same as [`From<&str>`](TransportProtocol#impl-From<%26str>-for-TransportProtocol):
    /// defaults the protocol to [`Protocol::Https`].
    fn from(uri: String) -> Self {
        Self {
            uri,
            protocol: Protocol::Https,
        }
    }
}

impl From<TransportProtocol> for derec_proto::TransportProtocol {
    /// Infallible conversion to the protobuf wire type. Used by the
    /// library when it needs to serialize an endpoint into a
    /// `ContactMessage` / `PairRequest` / etc.
    fn from(tp: TransportProtocol) -> Self {
        Self {
            uri: tp.uri,
            protocol: tp.protocol.into(),
        }
    }
}

impl From<&TransportProtocol> for derec_proto::TransportProtocol {
    fn from(tp: &TransportProtocol) -> Self {
        Self {
            uri: tp.uri.clone(),
            protocol: tp.protocol.into(),
        }
    }
}

impl TryFrom<derec_proto::TransportProtocol> for TransportProtocol {
    type Error = TransportValidationError;

    /// Fallible conversion **from** the protobuf wire type.
    ///
    /// Runs the full validation chain — first parses the `protocol`
    /// field as a defined [`Protocol`] variant (fails on unknown
    /// `i32` discriminants), then [`validate`](Self::validate)s the
    /// URI rules. Callers handling untrusted input (wire decode,
    /// FFI/WASM boundary) can therefore use a single `?` to assert
    /// the value is well-formed without a follow-up
    /// `.validate()` call.
    fn try_from(p: derec_proto::TransportProtocol) -> Result<Self, Self::Error> {
        let protocol = Protocol::try_from(p.protocol)
            .map_err(|_| TransportValidationError::UnknownProtocol(p.protocol))?;
        let tp = Self {
            uri: p.uri,
            protocol,
        };
        tp.validate()?;
        Ok(tp)
    }
}

impl TryFrom<&derec_proto::TransportProtocol> for TransportProtocol {
    type Error = TransportValidationError;

    /// Borrowed counterpart of
    /// [`TryFrom<derec_proto::TransportProtocol>`](Self#impl-TryFrom<TransportProtocol>-for-TransportProtocol).
    /// Same validation chain, but clones the URI string instead of
    /// taking ownership.
    fn try_from(p: &derec_proto::TransportProtocol) -> Result<Self, Self::Error> {
        let protocol = Protocol::try_from(p.protocol)
            .map_err(|_| TransportValidationError::UnknownProtocol(p.protocol))?;
        let tp = Self {
            uri: p.uri.clone(),
            protocol,
        };
        tp.validate()?;
        Ok(tp)
    }
}

/// Extension trait that gives the prost wire type
/// [`derec_proto::TransportProtocol`] the same `validate()` shape as the
/// library wrapper [`TransportProtocol`]. Defined here because the wire
/// type lives in another crate — the orphan rule blocks adding an
/// inherent method.
///
/// Brought into scope at every boundary where a remotely-controlled or
/// application-supplied [`derec_proto::TransportProtocol`] surfaces:
/// peer-extracted `reply_to` / `transport_protocol` fields inside
/// `extract` primitives, the orchestrator's `on_request` handlers, and
/// the FFI seam helpers. Centralising the gate in one impl keeps the
/// rejection semantics uniform across SDKs through
/// [`crate::Error::Transport`].
pub trait TransportProtocolExt {
    /// Validate the endpoint's structural soundness + scheme/protocol
    /// consistency. Same rules as [`TransportProtocol::validate`]:
    /// non-empty URI ≤ [`MAX_TRANSPORT_URI_LEN`] bytes, no control
    /// characters, known `protocol` discriminant, and the URI scheme
    /// matches the declared protocol.
    fn validate(&self) -> Result<(), TransportValidationError>;
}

impl TransportProtocolExt for derec_proto::TransportProtocol {
    fn validate(&self) -> Result<(), TransportValidationError> {
        TransportProtocol::try_from(self).map(|_| ())
    }
}

/// Structured error returned by [`TransportProtocol::validate`] and
/// by [`TryFrom`] conversions from the protobuf wire type. Surfaced
/// via [`crate::Error::Transport`] and from there into the FFI's
/// [`DeRecError`](crate::ffi::error::DeRecError) and the WASM
/// `{code, message}` shape.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportValidationError {
    #[error("transport uri is empty")]
    EmptyUri,

    #[error(
        "transport uri length {got} exceeds cap {limit} bytes — refusing to propagate"
    )]
    UriTooLong { got: usize, limit: usize },

    #[error(
        "transport uri contains control characters (bytes < 0x20 or = 0x7F are not allowed)"
    )]
    ControlCharacters,

    #[error("unknown TransportProtocol.protocol discriminant: {0}")]
    UnknownProtocol(i32),

    #[error(
        "transport uri must start with `{expected}` for protocol {protocol:?} \
         — rejecting plaintext / mismatched scheme"
    )]
    SchemeMismatch {
        expected: &'static str,
        protocol: Protocol,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_defaults_to_https() {
        let tp: TransportProtocol = "https://owner.example.com".into();
        assert_eq!(tp.uri, "https://owner.example.com");
        assert_eq!(tp.protocol, Protocol::Https);
        tp.validate().unwrap();
    }

    #[test]
    fn validate_rejects_plaintext_scheme() {
        let tp: TransportProtocol = "http://owner.example.com".into();
        assert!(matches!(
            tp.validate(),
            Err(TransportValidationError::SchemeMismatch {
                expected: "https://",
                protocol: Protocol::Https,
            })
        ));
    }

    #[test]
    fn validate_rejects_control_characters() {
        let tp = TransportProtocol::new("https://owner.example.com\n", Protocol::Https);
        assert!(matches!(
            tp.validate(),
            Err(TransportValidationError::ControlCharacters)
        ));
    }

    #[test]
    fn validate_rejects_oversize_uri() {
        let oversize = format!("https://{}", "a".repeat(MAX_TRANSPORT_URI_LEN));
        let tp: TransportProtocol = oversize.into();
        assert!(matches!(
            tp.validate(),
            Err(TransportValidationError::UriTooLong { .. })
        ));
    }

    #[test]
    fn try_from_proto_rejects_unknown_enum() {
        let proto = derec_proto::TransportProtocol {
            uri: "https://x".to_owned(),
            protocol: 9999,
        };
        let res: Result<TransportProtocol, _> = (&proto).try_into();
        assert!(matches!(
            res,
            Err(TransportValidationError::UnknownProtocol(9999))
        ));
    }

    #[test]
    fn try_from_proto_also_runs_uri_validation() {
        // Known protocol enum, but the URI scheme doesn't match.
        // `TryFrom` should reject without needing a follow-up
        // `.validate()` call.
        let proto = derec_proto::TransportProtocol {
            uri: "http://owner.example.com".to_owned(),
            protocol: 0, // Https
        };
        let res: Result<TransportProtocol, _> = (&proto).try_into();
        assert!(matches!(
            res,
            Err(TransportValidationError::SchemeMismatch {
                expected: "https://",
                ..
            })
        ));
    }

    #[test]
    fn roundtrip_to_proto_and_back() {
        let original = TransportProtocol::new("https://owner.example.com", Protocol::Https);
        let proto: derec_proto::TransportProtocol = original.clone().into();
        let back: TransportProtocol = proto.try_into().unwrap();
        assert_eq!(original, back);
    }
}
