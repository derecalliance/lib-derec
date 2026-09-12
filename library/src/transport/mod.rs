// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Library-level transport endpoint type + validation.
//!
//! This is the canonical [`TransportProtocol`] for library callers.
//! It mirrors [`derec_proto::TransportProtocol`] (the protobuf wire
//! type) but holds the protocol enum as a typed value rather than
//! a raw `i32`, exposes [`TransportProtocol::validate`] as a method,
//! and is `TryFrom<&str>` / `TryFrom<String>` for the common case
//! where the caller just has a URI in hand and wants the protocol
//! discriminant derived from the URI scheme in a single validated
//! step.
//!
//! ## Validation rules
//!
//! [`TransportProtocol::validate`] enforces:
//!
//! 1. **Length cap** — URI ≤ [`MAX_TRANSPORT_URI_LEN`] bytes.
//! 2. **No control characters** — bytes `< 0x20` or `= 0x7F` are
//!    rejected (NUL, embedded newlines, terminal escape codes).
//! 3. **Scheme matches the protocol** — `Protocol::Https` ⇒ the URI
//!    must start with `https://` or `http://`; `Protocol::Grpc` ⇒ the
//!    URI must start with `grpcs://` or `grpc://`. Other schemes
//!    (`ws://`, `file://`, …) are always rejected.
//!
//! Whether plaintext `http://` or `grpc://` is *acceptable* is a separate
//! question, answered by [`TransportPolicy`] rather than here: it depends
//! on how the application is deployed, which a validator with no
//! configuration cannot know.
//!
//! # One endpoint per protocol
//!
//! The rules above judge endpoints one at a time. A *set* of them carries one
//! more: a device serves at most one address per protocol. The endpoint is
//! the address peers reach that protocol on, so a second entry for the same
//! protocol names no additional reachability — it contradicts the first, and
//! nothing says two peers would resolve the contradiction alike.
//!
//! A list of endpoints is therefore a preference order over *distinct*
//! protocols, not a pool of interchangeable addresses. The rule is enforced
//! at two different strengths:
//!
//! - **This device's own endpoints** — refused. See
//!   [`TransportPolicy::check_own_set`]. A duplicate here is a configuration
//!   mistake the application can fix, and silently dropping one would
//!   advertise something it never asked for.
//! - **A peer's advertised endpoints** — filtered, first entry wins. See
//!   [`TransportPolicy::admit_peer_endpoints`]. The advertisement is
//!   untrusted input, and failing a whole pairing over a contradiction that
//!   can be resolved would discard an otherwise usable endpoint.
//! 4. **Non-empty URI** — `EmptyUri` is the explicit error.
//!
//! Unknown `protocol` discriminants are caught at the *conversion*
//! boundary by [`TryFrom<derec_proto::TransportProtocol>`] (or by
//! [`TryFrom<&derec_proto::TransportProtocol>`]), so they never reach
//! the typed [`TransportProtocol`] in the first place.
//!
//! ## The deprecated singular `transportProtocol`
//!
//! Contacts and pair requests carry both a singular `transportProtocol`
//! and a `supportedTransports` list. The singular field predates the list
//! and is deprecated on the wire, but it is still written and still read:
//! a peer running an implementation that predates `supportedTransports`
//! finds an endpoint only there, and dropping it would make this library
//! unpairable with them.
//!
//! Every site that touches it therefore carries `#[allow(deprecated)]`.
//! Those are compatibility, not oversight — this is the explanation they
//! point at rather than each restating it. The singular field is always
//! derived from the first entry of the list, never set independently,
//! which is what keeps the two from disagreeing.

use derec_proto::Protocol;
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
use serde::{Deserialize, Serialize};

mod selection;

/// Maximum accepted transport URI length, in bytes.
///
/// Matches the de-facto 2048-byte limit most HTTP stacks enforce
/// for request URIs. Pairing payloads embed the URI verbatim, so
/// capping it also bounds the propagated blob size.
pub const MAX_TRANSPORT_URI_LEN: usize = 2048;

/// URI scheme prefixes that carry DeRec messages without transport-layer
/// confidentiality. Each has a TLS counterpart sharing its [`Protocol`]
/// discriminant (`https://` for `http://`, `grpcs://` for `grpc://`).
///
/// [`TransportPolicy`] gates every entry here identically, so adding a
/// transport means adding its plaintext spelling to this list and nothing
/// else.
const PLAINTEXT_SCHEMES: [&str; 2] = ["http://", "grpc://"];

/// Library-level transport endpoint.
///
/// Use this type in your `DeRecProtocolBuilder` / `set_own_transport`
/// calls; the library converts to the protobuf wire form internally
/// when it needs to encode messages. Construct it from a URI string
/// with [`TryFrom`] / [`TryInto`] (which parses the URI scheme,
/// derives the protocol discriminant, and validates in one step),
/// or directly with [`TransportProtocol::new`] when you already have
/// a typed [`Protocol`] in hand.
///
/// ## Plaintext `http://`
///
/// [`validate`](Self::validate) accepts both http-family schemes,
/// because both are structurally consistent with [`Protocol::Https`].
/// Whether plaintext may actually be *used* is decided by
/// [`TransportPolicy`], configured through
/// [`with_unsafe_connection`](crate::protocol::DeRecProtocolBuilder::with_unsafe_connection).
///
/// This was a Cargo feature until it became clear that a compile-time
/// switch is unreachable for the four SDKs that install a prebuilt
/// binary from a package manager — a .NET or Node developer has no
/// compilation step in which to enable it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(Serialize, Deserialize)
)]
pub struct TransportProtocol {
    pub uri: String,
    /// Serialized as the protobuf enum's `i32` discriminant so the
    /// wire shape stays compatible with [`derec_proto::TransportProtocol`]
    /// — important because every binding's JSON Channel marshaller
    /// round-trips this field via the proto-style `{uri, protocol: 0}`
    /// representation.
    #[cfg_attr(
        any(feature = "serde", target_arch = "wasm32"),
        serde(with = "protocol_as_i32")
    )]
    pub protocol: Protocol,
}

#[cfg(any(feature = "serde", target_arch = "wasm32"))]
mod protocol_as_i32 {
    use super::Protocol;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(p: &Protocol, ser: S) -> Result<S::Ok, S::Error> {
        i32::from(*p).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Protocol, D::Error> {
        let raw = i32::deserialize(de)?;
        Protocol::try_from(raw)
            .map_err(|_| serde::de::Error::custom(format!("unknown Protocol discriminant {raw}")))
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

    /// Validate the endpoint's **structure**: non-empty, within the length
    /// cap, no control characters, and a scheme consistent with the declared
    /// [`Protocol`] discriminant.
    ///
    /// # This does not decide `http` versus `https`
    ///
    /// Both are structurally consistent with [`Protocol::Https`], so both pass
    /// here. Whether plaintext is *acceptable* is deployment policy, and a
    /// function with no configuration cannot answer it — see
    /// [`TransportPolicy`], which the orchestrator applies at every point a
    /// transport endpoint enters it.
    ///
    /// A caller reaching past [`crate::protocol::DeRecProtocol`] to the
    /// primitives owns that decision itself: run
    /// [`TransportPolicy::check_peer`] on any endpoint decoded from a peer.
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
        match self.protocol {
            Protocol::Https => {
                // Both http-family schemes are structurally consistent with
                // this discriminant. Choosing between them is
                // `TransportPolicy`'s job, not this function's.
                if !self.uri.starts_with("https://") && !self.uri.starts_with("http://") {
                    return Err(TransportValidationError::SchemeMismatch {
                        expected: "https://",
                        protocol: self.protocol,
                    });
                }
            }
            Protocol::Grpc => {
                // Both gRPC schemes are structurally consistent with this
                // discriminant, exactly as the http family is for Https.
                // Choosing between them is `TransportPolicy`'s job.
                if !self.uri.starts_with("grpcs://") && !self.uri.starts_with("grpc://") {
                    return Err(TransportValidationError::SchemeMismatch {
                        expected: "grpcs://",
                        protocol: self.protocol,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Derive the transport protocol a URI scheme implies.
///
/// The plaintext and TLS spellings of one transport share a discriminant:
/// whether plaintext is *acceptable* is [`TransportPolicy`]'s decision, not
/// the parser's.
fn protocol_for_scheme(uri: &str) -> Option<Protocol> {
    match uri.split_once("://") {
        Some(("https" | "http", _)) => Some(Protocol::Https),
        Some(("grpcs" | "grpc", _)) => Some(Protocol::Grpc),
        _ => None,
    }
}

impl TryFrom<&str> for TransportProtocol {
    type Error = TransportValidationError;

    /// Build a validated [`TransportProtocol`] from a URI literal,
    /// deriving the [`Protocol`] discriminant from the URI scheme:
    ///
    /// - `https://…` / `http://…`   → [`Protocol::Https`] (`http://` is
    ///   development-only; emits a `tracing::warn!` under the `logging`
    ///   feature — see the struct-level docs)
    /// - `grpcs://…` / `grpc://…`   → [`Protocol::Grpc`]
    /// - any other scheme → [`TransportValidationError::UnknownScheme`]
    ///
    /// Also runs the full [`validate`](Self::validate) chain (length
    /// cap, control-character check, non-empty URI), so a successful
    /// result is a fully-checked endpoint ready to embed in a
    /// pairing payload.
    fn try_from(uri: &str) -> Result<Self, Self::Error> {
        Self::try_from(uri.to_owned())
    }
}

impl TryFrom<String> for TransportProtocol {
    type Error = TransportValidationError;

    /// Same as [`TryFrom<&str>`](Self#impl-TryFrom<%26str>-for-TransportProtocol),
    /// but takes ownership of the URI string instead of cloning it.
    fn try_from(uri: String) -> Result<Self, Self::Error> {
        let Some(protocol) = protocol_for_scheme(&uri) else {
            return Err(TransportValidationError::UnknownScheme { uri });
        };
        let tp = Self { uri, protocol };
        tp.validate()?;
        Ok(tp)
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
        let protocol = Protocol::try_from(p.protocol).map_err(|_| {
            TransportValidationError::UnsupportedProtocol {
                discriminant: p.protocol,
            }
        })?;
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
        let protocol = Protocol::try_from(p.protocol).map_err(|_| {
            TransportValidationError::UnsupportedProtocol {
                discriminant: p.protocol,
            }
        })?;
        let tp = Self {
            uri: p.uri.clone(),
            protocol,
        };
        tp.validate()?;
        Ok(tp)
    }
}

/// Conversion trait for the `with_own_transport` builder setter.
///
/// Lets callers pass either an already-typed [`TransportProtocol`] or
/// a URI string (`&str` / `String`) without having to construct the
/// typed value themselves. Implementations either yield an
/// already-valid endpoint or report a
/// [`TransportValidationError`]; the
/// [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder)
/// stashes the result and surfaces failures from `.build()` so the
/// setter chain stays infallible.
pub trait IntoOwnTransport {
    fn into_own_transport(self) -> Result<TransportProtocol, TransportValidationError>;
}

impl IntoOwnTransport for TransportProtocol {
    /// Re-runs [`validate`](TransportProtocol::validate) so a builder
    /// receiving a hand-crafted [`TransportProtocol::new`] with an
    /// invalid URI still fails at `.build()` time.
    fn into_own_transport(self) -> Result<TransportProtocol, TransportValidationError> {
        self.validate()?;
        Ok(self)
    }
}

impl IntoOwnTransport for &str {
    fn into_own_transport(self) -> Result<TransportProtocol, TransportValidationError> {
        TransportProtocol::try_from(self)
    }
}

impl IntoOwnTransport for String {
    fn into_own_transport(self) -> Result<TransportProtocol, TransportValidationError> {
        TransportProtocol::try_from(self)
    }
}

/// Structured error returned by [`TransportProtocol::validate`] and
/// by [`TryFrom`] conversions from the protobuf wire type. Surfaced
/// via [`crate::Error::Transport`] and from there into the FFI's
/// `DeRecError` and the WASM `{code, message}` shape.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportValidationError {
    #[error("transport uri is empty")]
    EmptyUri,

    #[error("transport uri length {got} exceeds cap {limit} bytes — refusing to propagate")]
    UriTooLong { got: usize, limit: usize },

    #[error("transport uri contains control characters (bytes < 0x20 or = 0x7F are not allowed)")]
    ControlCharacters,

    #[deprecated(
        since = "0.0.3",
        note = "use `UnsupportedProtocol { discriminant }`; removed at 0.0.5"
    )]
    #[error("unknown TransportProtocol.protocol discriminant: {0}")]
    UnknownProtocol(i32),

    /// The URI scheme matches no supported transport protocol.
    ///
    /// Distinct from [`Self::SchemeMismatch`], which reports a URI whose
    /// scheme is known but inconsistent with the *declared* protocol. This
    /// variant is for a scheme no protocol claims at all.
    #[error(
        "transport uri scheme in `{uri}` matches no supported transport protocol \
         (expected one of: https://, http://, grpcs://, grpc://)"
    )]
    UnknownScheme { uri: String },

    /// A protocol discriminant this build does not define — typically a
    /// value introduced by a newer revision of the DeRec protocol.
    ///
    /// Reported instead of a bare decode failure so an application can tell
    /// the user something actionable rather than surfacing a parse error.
    #[error(
        "transport protocol discriminant {discriminant} is not defined in this \
         version of the DeRec protocol"
    )]
    UnsupportedProtocol { discriminant: i32 },

    /// The same protocol appears twice in one advertisement.
    ///
    /// A device serves at most one endpoint per protocol: the endpoint *is*
    /// the address peers reach that protocol on, so a second one for the same
    /// protocol names no additional reachability, it contradicts the first.
    /// Peers would have no rule for choosing between them, and different
    /// peers could choose differently.
    ///
    /// Reported for endpoints this device advertises about *itself*, where a
    /// duplicate is a configuration mistake the application can fix. A
    /// duplicate arriving from a peer is filtered instead — see
    /// [`TransportPolicy::admit_peer_endpoints`].
    #[error(
        "transport protocol {protocol:?} is advertised more than once \
         (`{first}` and `{second}`) — a device serves at most one endpoint \
         per protocol"
    )]
    DuplicateProtocol {
        protocol: Protocol,
        first: String,
        second: String,
    },

    #[error(
        "transport uri must start with `{expected}` for protocol {protocol:?} \
         — rejecting plaintext / mismatched scheme"
    )]
    SchemeMismatch {
        expected: &'static str,
        protocol: Protocol,
    },

    /// Structurally fine, but plaintext where policy does not allow it.
    /// Distinct from [`Self::SchemeMismatch`] so an application can tell
    /// "this endpoint is malformed" from "this endpoint is plaintext and you
    /// have not opted in" — the second is fixed by configuration, the first
    /// is not.
    #[error(
        "plaintext transport endpoint refused ({uri}) — {reason}. \
         Enable `unsafe_connection` on the protocol builder to accept plaintext \
         during development; never enable it in production"
    )]
    PlaintextRefused { uri: String, reason: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_str_derives_https_and_validates() {
        let tp = TransportProtocol::try_from("https://owner.example.com").unwrap();
        assert_eq!(tp.uri, "https://owner.example.com");
        assert_eq!(tp.protocol, Protocol::Https);
    }

    #[test]
    fn try_from_string_takes_ownership_and_validates() {
        let uri = String::from("https://owner.example.com");
        let tp = TransportProtocol::try_from(uri).unwrap();
        assert_eq!(tp.protocol, Protocol::Https);
    }

    /// `TryFrom<&str>` is structural, so it accepts `http://` — deciding
    /// whether plaintext is *acceptable* moved to [`TransportPolicy`], which
    /// the builder applies once both the endpoint and the setting are known.
    /// Parsing a string cannot see configuration, which is exactly why the
    /// rule used to need a Cargo feature.
    #[test]
    fn try_from_str_is_structural_and_accepts_plaintext() {
        let tp = TransportProtocol::try_from("http://owner.example.com").unwrap();
        assert_eq!(tp.protocol, Protocol::Https);

        // The refusal lives in the policy, not the parse.
        let proto = derec_proto::TransportProtocol {
            uri: tp.uri.clone(),
            protocol: tp.protocol as i32,
        };
        assert!(matches!(
            TransportPolicy::new(false).check_own(&proto),
            Err(TransportValidationError::PlaintextRefused { .. })
        ));
    }

    #[test]
    fn validate_rejects_unsupported_scheme() {
        let tp = TransportProtocol::new("ws://owner.example.com", Protocol::Https);
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
        assert!(matches!(
            TransportProtocol::try_from(oversize),
            Err(TransportValidationError::UriTooLong { .. })
        ));
    }

    #[test]
    fn try_from_proto_also_runs_uri_validation() {
        // Known protocol enum, but the URI scheme doesn't match.
        // `TryFrom` should reject without needing a follow-up
        // `.validate()` call.
        let proto = derec_proto::TransportProtocol {
            uri: "ws://owner.example.com".to_owned(),
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

    #[test]
    fn into_own_transport_accepts_str_string_and_typed() {
        let from_str = IntoOwnTransport::into_own_transport("https://owner.example.com").unwrap();
        assert_eq!(from_str.uri, "https://owner.example.com");

        let from_string =
            IntoOwnTransport::into_own_transport(String::from("https://owner.example.com"))
                .unwrap();
        assert_eq!(from_string.uri, "https://owner.example.com");

        let typed = TransportProtocol::new("https://owner.example.com", Protocol::Https);
        let from_typed = IntoOwnTransport::into_own_transport(typed.clone()).unwrap();
        assert_eq!(from_typed, typed);
    }

    #[test]
    fn into_own_transport_revalidates_typed_value() {
        // A caller can hand-build a `TransportProtocol::new(...)` that
        // skips validation. `IntoOwnTransport` runs it through
        // `validate` so the setter still catches the bad URI.
        let malformed = TransportProtocol::new("ws://owner.example.com", Protocol::Https);
        assert!(matches!(
            IntoOwnTransport::into_own_transport(malformed),
            Err(TransportValidationError::SchemeMismatch { .. })
        ));
    }

    #[test]
    fn into_own_transport_rejects_unsupported_str_scheme() {
        assert!(matches!(
            IntoOwnTransport::into_own_transport("ws://owner.example.com"),
            Err(TransportValidationError::UnknownScheme { .. })
        ));
    }

    #[test]
    fn validate_accepts_both_grpc_schemes() {
        for uri in ["grpcs://helper.example.com:443", "grpc://localhost:50051"] {
            let tp = TransportProtocol::new(uri, Protocol::Grpc);
            assert!(tp.validate().is_ok(), "{uri} should validate under Grpc");
        }
    }

    #[test]
    fn validate_rejects_cross_scheme_pairings() {
        let https_under_grpc = TransportProtocol::new("https://x.example.com", Protocol::Grpc);
        assert!(matches!(
            https_under_grpc.validate(),
            Err(TransportValidationError::SchemeMismatch {
                expected: "grpcs://",
                protocol: Protocol::Grpc,
            })
        ));

        let grpc_under_https = TransportProtocol::new("grpc://x.example.com", Protocol::Https);
        assert!(matches!(
            grpc_under_https.validate(),
            Err(TransportValidationError::SchemeMismatch {
                expected: "https://",
                protocol: Protocol::Https,
            })
        ));
    }

    #[test]
    fn try_from_str_dispatches_on_scheme() {
        for (uri, expected) in [
            ("https://x.example.com", Protocol::Https),
            ("http://x.example.com", Protocol::Https),
            ("grpcs://x.example.com:443", Protocol::Grpc),
            ("grpc://localhost:50051", Protocol::Grpc),
        ] {
            let tp = TransportProtocol::try_from(uri).expect("should parse");
            assert_eq!(tp.protocol, expected, "{uri}");
            assert_eq!(tp.uri, uri);
        }
    }

    #[test]
    fn try_from_str_reports_unknown_scheme() {
        assert!(matches!(
            TransportProtocol::try_from("ws://x.example.com"),
            Err(TransportValidationError::UnknownScheme { .. })
        ));
    }

    /// The scheme is the whole component before `://`, never a prefix of it.
    /// A URI whose scheme merely *starts with* a known one names a different
    /// protocol and must not be classified as that one — this feeds
    /// [`TransportPolicy`], so a misread here would apply the wrong plaintext
    /// rule.
    #[test]
    fn scheme_matching_is_exact_not_prefixed() {
        for uri in [
            "httpsx://x.example.com",
            "grpcx://x.example.com",
            "xhttps://x.example.com",
            "https:/x.example.com",
            "https",
            "://x.example.com",
            "",
        ] {
            assert_eq!(
                protocol_for_scheme(uri),
                None,
                "{uri} must not resolve to a protocol"
            );
        }

        // A second `://` later in the URI belongs to the path, not the scheme.
        assert_eq!(
            protocol_for_scheme("https://a://b"),
            Some(Protocol::Https),
            "only the first `://` delimits the scheme"
        );
    }

    #[test]
    fn try_from_proto_reports_unsupported_discriminant() {
        let proto = derec_proto::TransportProtocol {
            uri: "grpcs://x.example.com".to_owned(),
            protocol: 9999,
        };
        let res: Result<TransportProtocol, _> = (&proto).try_into();
        assert!(matches!(
            res,
            Err(TransportValidationError::UnsupportedProtocol { discriminant: 9999 })
        ));
    }
}

/// Decides whether a transport endpoint's **scheme** is acceptable.
///
/// [`TransportProtocol::validate`] answers "is this endpoint well-formed";
/// this answers "may we use it", which depends on how the application is
/// deployed and so cannot live in a function without configuration. Every
/// place an endpoint enters
/// [`DeRecProtocol`](crate::protocol::DeRecProtocol) consults one of these
/// rather than repeating the rule, so the policy has exactly one definition.
///
/// # Scope — this is a guardrail, not an enforcement boundary
///
/// The SDK never opens a socket. Transport is the consuming application's
/// concern ([`DeRecTransport`](crate::protocol::DeRecTransport)), so nothing
/// here can stop an application sending plaintext. What it *can* do is refuse
/// to record a plaintext endpoint, refuse to propagate one to peers during
/// pairing, and refuse to hand one back as a reply address. Treat it as a
/// consistency check on the endpoints the protocol carries, not as transport
/// security.
///
/// # The rule
///
/// | Endpoint | `https` | plaintext loopback | plaintext, any other host |
/// |---|---|---|---|
/// | [`check_own`](Self::check_own) — this device's own | always | **always**, with a warning | needs `unsafe_connection` |
/// | [`check_peer`](Self::check_peer) — supplied by a peer | always | needs `unsafe_connection` | needs `unsafe_connection` |
///
/// Loopback is free for an own endpoint because it names a service on this
/// machine: the bytes never reach a network, so there is nothing for TLS to
/// protect. It is **not** free for a peer-supplied endpoint, because there
/// the loopback address is chosen by somebody else and names a service on
/// *your* machine — a peer should not be able to nominate your localhost as
/// a reply address without you having opted into plaintext at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TransportPolicy {
    /// Mirrors the resolved value of
    /// [`DeRecProtocolBuilder::with_unsafe_connection`](crate::protocol::DeRecProtocolBuilder::with_unsafe_connection)
    /// (or the deprecated
    /// [`with_unsafe_http`](crate::protocol::DeRecProtocolBuilder::with_unsafe_http),
    /// whichever was set — both set and disagreeing fails `build()`).
    allow_plaintext: bool,
}

impl TransportPolicy {
    /// Build a policy. `allow_plaintext` is the application's resolved
    /// `unsafe_connection` (or deprecated `unsafe_http`) setting; `false` is
    /// the production posture.
    pub const fn new(allow_plaintext: bool) -> Self {
        Self { allow_plaintext }
    }

    /// `true` when plaintext has been opted into for every host.
    pub fn allows_plaintext(&self) -> bool {
        self.allow_plaintext
    }

    /// Check that a set of endpoints this device advertises names each
    /// protocol at most once.
    ///
    /// A device serves one address per protocol, so the list peers receive in
    /// `supportedTransports` is a preference *order* over distinct protocols,
    /// not a pool of interchangeable addresses. Two HTTPS entries would leave
    /// a peer with no rule for choosing, and nothing says two peers would
    /// choose alike.
    ///
    /// Strict here — a duplicate is refused rather than filtered — because
    /// these are the application's own endpoints, where a duplicate is a
    /// configuration mistake it can fix and silently dropping one would
    /// advertise something it did not ask for. Peer-advertised duplicates are
    /// filtered instead; see [`Self::admit_peer_endpoints`].
    pub fn check_own_set(
        &self,
        own: &[derec_proto::TransportProtocol],
    ) -> Result<(), TransportValidationError> {
        for (i, endpoint) in own.iter().enumerate() {
            if let Some(first) = own[..i].iter().find(|e| e.protocol == endpoint.protocol) {
                return Err(TransportValidationError::DuplicateProtocol {
                    protocol: Protocol::try_from(endpoint.protocol).map_err(|_| {
                        TransportValidationError::UnsupportedProtocol {
                            discriminant: endpoint.protocol,
                        }
                    })?,
                    first: first.uri.clone(),
                    second: endpoint.uri.clone(),
                });
            }
        }
        Ok(())
    }

    /// Check an endpoint **this device configured for itself** — the value
    /// passed to
    /// [`with_own_transport`](crate::protocol::DeRecProtocolBuilder::with_own_transport),
    /// and the `reply_to` this device stamps on its own outbound requests.
    ///
    /// Plaintext loopback is accepted whatever the setting, so local
    /// development needs no configuration at all.
    pub fn check_own(
        &self,
        endpoint: &derec_proto::TransportProtocol,
    ) -> Result<(), TransportValidationError> {
        self.check(endpoint, true)
    }

    /// Check an endpoint **a peer supplied** — a contact's
    /// `transport_protocol`, an `UpdateChannelInfo` announcement, or a
    /// request's `reply_to`.
    ///
    /// Plaintext always requires `unsafe_connection`, loopback included.
    pub fn check_peer(
        &self,
        endpoint: &derec_proto::TransportProtocol,
    ) -> Result<(), TransportValidationError> {
        self.check(endpoint, false)
    }

    fn check(
        &self,
        endpoint: &derec_proto::TransportProtocol,
        loopback_is_free: bool,
    ) -> Result<(), TransportValidationError> {
        crate::extensions::transport_protocol::TransportProtocolExt::validate(endpoint)?;

        let Some(scheme) = PLAINTEXT_SCHEMES
            .iter()
            .find(|scheme| endpoint.uri.starts_with(*scheme))
        else {
            return Ok(());
        };
        if self.allow_plaintext {
            #[cfg(feature = "logging")]
            tracing::warn!(
                uri = %endpoint.uri,
                "accepting plaintext transport endpoint — `unsafe_connection` is \
                 enabled, so confidentiality and authenticity are NOT provided by \
                 the transport layer; never enable this in production",
            );
            return Ok(());
        }
        if loopback_is_free && is_loopback_uri_with_scheme(&endpoint.uri, scheme) {
            #[cfg(feature = "logging")]
            tracing::warn!(
                uri = %endpoint.uri,
                "accepting plaintext transport endpoint on loopback — this is \
                 development mode; a deployed peer cannot reach it",
            );
            return Ok(());
        }
        Err(TransportValidationError::PlaintextRefused {
            uri: endpoint.uri.clone(),
            reason: if loopback_is_free {
                "only loopback endpoints may be plaintext by default"
            } else {
                "a peer-supplied endpoint may never be plaintext by default"
            },
        })
    }
}

/// Whether a plaintext URI with the given `scheme` prefix names this
/// machine.
///
/// Deliberately literal: the host must be `localhost`, `127.0.0.1` or `::1`
/// exactly. No DNS resolution and no wider private-range classification —
/// both would need real URI parsing, and getting *that* wrong in a security
/// check is how `http://127.0.0.1@evil.com/` slips through. A closed set of
/// literals plus an explicit userinfo refusal cannot be spoofed that way, and
/// the wider case is what `unsafe_connection` is for.
fn is_loopback_uri_with_scheme(uri: &str, scheme: &str) -> bool {
    const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

    let Some(rest) = uri.strip_prefix(scheme) else {
        return false;
    };
    // Authority is everything before the first `/`, `?` or `#`.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];

    // Any userinfo means the host is not what a naive reader sees
    // (`http://127.0.0.1@evil.com/` resolves to `evil.com`). Refuse outright
    // rather than try to be clever about it.
    if authority.contains('@') {
        return false;
    }

    // IPv6 literals are bracketed, and their colons are not port separators.
    let host = if let Some(after_bracket) = authority.strip_prefix('[') {
        match after_bracket.split_once(']') {
            // Only a port may follow the bracket.
            Some((inner, tail)) if tail.is_empty() || tail.starts_with(':') => inner,
            _ => return false,
        }
    } else {
        authority.split(':').next().unwrap_or(authority)
    };

    LOOPBACK_HOSTS.contains(&host)
}

#[cfg(test)]
mod transport_policy_tests {
    use super::*;

    fn grpc(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Grpc as i32,
        }
    }

    // ---------------------------------------------------------------
    // One endpoint per protocol
    // ---------------------------------------------------------------

    /// This device's own advertisement is held strictly: a duplicate is a
    /// configuration mistake the application can fix, and dropping one
    /// silently would advertise something it did not ask for.
    #[test]
    fn own_set_refuses_a_repeated_protocol() {
        let err = STRICT
            .check_own_set(&[ep("https://a.example"), ep("https://b.example")])
            .expect_err("one protocol may name only one endpoint");
        assert!(
            matches!(err, TransportValidationError::DuplicateProtocol { .. }),
            "got {err:?}"
        );
    }

    /// Distinct protocols are exactly what the list is for.
    #[test]
    fn own_set_accepts_one_endpoint_per_protocol() {
        STRICT
            .check_own_set(&[ep("https://a.example"), grpc("grpcs://a.example:443")])
            .expect("distinct protocols are a valid advertisement");
    }

    /// A peer's duplicate is filtered, not refused. Its advertisement is
    /// untrusted input, and failing the whole exchange over a contradiction
    /// we can resolve would abort a pairing that has a usable endpoint in it.
    #[test]
    fn a_peers_repeated_protocol_is_filtered_to_the_first() {
        let first = ep("https://first.example");
        let second = ep("https://second.example");
        let kept = STRICT
            .admit_peer_endpoints(vec![&first, &second])
            .expect("the first entry is usable");
        assert_eq!(
            kept,
            vec![first],
            "the earlier entry wins — the list is the peer's own preference order"
        );
    }

    /// Filtering a duplicate must not cost the peer its other protocols.
    #[test]
    fn filtering_a_duplicate_keeps_the_other_protocols() {
        let https = ep("https://a.example");
        let dup = ep("https://b.example");
        let grpc = grpc("grpcs://a.example:443");
        let kept = STRICT
            .admit_peer_endpoints(vec![&https, &dup, &grpc])
            .expect("two usable protocols");
        assert_eq!(kept, vec![https, grpc]);
    }

    /// The scheme filter runs first, so a duplicate of a *dropped* entry is
    /// admitted rather than being suppressed by an endpoint that never
    /// survived. Refusing it would leave the peer unreachable over a
    /// protocol it does serve.
    #[test]
    fn a_duplicate_of_a_refused_endpoint_is_still_admitted() {
        let plaintext = ep("http://a.example");
        let secure = ep("https://b.example");
        let kept = STRICT
            .admit_peer_endpoints(vec![&plaintext, &secure])
            .expect("the secure entry survives");
        assert_eq!(kept, vec![secure]);
    }

    fn ep(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    const STRICT: TransportPolicy = TransportPolicy {
        allow_plaintext: false,
    };
    const UNSAFE: TransportPolicy = TransportPolicy {
        allow_plaintext: true,
    };

    /// Every spelling of "this machine" that the loopback allowance covers,
    /// with and without ports and paths.
    #[test]
    fn loopback_forms_are_recognised() {
        for uri in [
            "http://localhost",
            "http://localhost/",
            "http://localhost:8080",
            "http://localhost:8080/derec",
            "http://127.0.0.1",
            "http://127.0.0.1:3000/x?y=1",
            "http://[::1]",
            "http://[::1]:8080/path",
        ] {
            assert!(
                is_loopback_uri_with_scheme(uri, "http://"),
                "{uri} should be loopback"
            );
        }
    }

    /// The spoofs. Each of these *contains* a loopback literal but does not
    /// resolve to this machine — the userinfo trick is the classic one.
    #[test]
    fn loopback_lookalikes_are_rejected() {
        for uri in [
            "http://127.0.0.1@evil.com/",
            "http://localhost@evil.com/",
            "http://localhost:pw@evil.com/",
            "http://[::1]@evil.com/",
            "http://127.0.0.1.evil.com/",
            "http://notlocalhost/",
            "http://localhost.evil.com/",
            "http://127.0.0.2/",
            "http://10.0.0.1/",
            "http://192.168.1.42:8080/",
            // A bracketed authority that is not a well-formed IPv6 literal.
            "http://[::1/",
            "http://[::1]x/",
            "https://localhost",
        ] {
            assert!(
                !is_loopback_uri_with_scheme(uri, "http://"),
                "{uri} must not count as loopback"
            );
        }
    }

    /// `https` needs no permission from anyone, on either path.
    #[test]
    fn https_is_always_accepted() {
        for policy in [STRICT, UNSAFE] {
            assert!(policy.check_own(&ep("https://owner.example.com")).is_ok());
            assert!(policy.check_peer(&ep("https://helper.example.com")).is_ok());
        }
    }

    /// The default posture: an own loopback endpoint works with no
    /// configuration, which is what makes local development frictionless.
    #[test]
    fn own_loopback_plaintext_is_free() {
        assert!(STRICT.check_own(&ep("http://localhost:8080")).is_ok());
        assert!(STRICT.check_own(&ep("http://127.0.0.1:8080")).is_ok());
    }

    /// The asymmetry that matters. A peer must not be able to nominate this
    /// machine's loopback as a reply address while plaintext is switched off.
    #[test]
    fn peer_loopback_plaintext_is_refused_by_default() {
        let err = STRICT
            .check_peer(&ep("http://127.0.0.1:9999"))
            .expect_err("a peer-supplied loopback endpoint must be refused");
        assert!(matches!(
            err,
            TransportValidationError::PlaintextRefused { .. }
        ));
    }

    /// Own endpoints get loopback for free, but nothing wider.
    #[test]
    fn own_non_loopback_plaintext_is_refused_by_default() {
        for uri in ["http://192.168.1.42:8080", "http://helper.example.com"] {
            assert!(
                matches!(
                    STRICT.check_own(&ep(uri)),
                    Err(TransportValidationError::PlaintextRefused { .. })
                ),
                "{uri} must be refused without unsafe_http"
            );
        }
    }

    /// With the opt-in, both paths accept plaintext anywhere — including the
    /// LAN case the flag exists for, and including public hosts, which is
    /// why the setting is named the way it is.
    #[test]
    fn unsafe_http_opens_both_paths_everywhere() {
        for uri in [
            "http://localhost:8080",
            "http://192.168.1.42:8080",
            "http://10.0.0.7:8080",
            "http://helper.example.com",
        ] {
            assert!(UNSAFE.check_own(&ep(uri)).is_ok(), "own {uri}");
            assert!(UNSAFE.check_peer(&ep(uri)).is_ok(), "peer {uri}");
        }
    }

    /// Policy runs *after* structure, so a malformed endpoint reports as
    /// malformed rather than as a plaintext refusal — the two are fixed
    /// differently.
    #[test]
    fn structural_failures_are_reported_as_such() {
        assert!(matches!(
            UNSAFE.check_own(&ep("")),
            Err(TransportValidationError::EmptyUri)
        ));
        assert!(matches!(
            UNSAFE.check_own(&ep("ftp://host/")),
            Err(TransportValidationError::SchemeMismatch { .. })
        ));
    }

    /// `validate` itself no longer takes a view on plaintext — that moved to
    /// the policy. Both http-family schemes are structurally sound.
    #[test]
    fn validate_is_structural_only() {
        assert!(
            crate::extensions::transport_protocol::TransportProtocolExt::validate(&ep(
                "http://anything.example.com"
            ))
            .is_ok()
        );
        assert!(
            crate::extensions::transport_protocol::TransportProtocolExt::validate(&ep(
                "https://anything.example.com"
            ))
            .is_ok()
        );
    }

    fn grpc_ep(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Grpc as i32,
        }
    }

    #[test]
    fn grpcs_is_always_accepted() {
        for policy in [STRICT, UNSAFE] {
            assert!(
                policy
                    .check_own(&grpc_ep("grpcs://owner.example.com"))
                    .is_ok()
            );
            assert!(
                policy
                    .check_peer(&grpc_ep("grpcs://helper.example.com"))
                    .is_ok()
            );
        }
    }

    #[test]
    fn own_grpc_loopback_plaintext_is_free() {
        assert!(STRICT.check_own(&grpc_ep("grpc://localhost:50051")).is_ok());
        assert!(STRICT.check_own(&grpc_ep("grpc://127.0.0.1:50051")).is_ok());
        assert!(STRICT.check_own(&grpc_ep("grpc://[::1]:50051")).is_ok());
    }

    #[test]
    fn peer_grpc_loopback_plaintext_is_refused_by_default() {
        assert!(matches!(
            STRICT.check_peer(&grpc_ep("grpc://127.0.0.1:50052")),
            Err(TransportValidationError::PlaintextRefused { .. })
        ));
    }

    #[test]
    fn own_non_loopback_grpc_plaintext_is_refused_by_default() {
        for uri in ["grpc://192.168.1.42:50051", "grpc://helper.example.com"] {
            assert!(
                matches!(
                    STRICT.check_own(&grpc_ep(uri)),
                    Err(TransportValidationError::PlaintextRefused { .. })
                ),
                "{uri} must be refused without the plaintext opt-in"
            );
        }
    }

    #[test]
    fn unsafe_opens_grpc_plaintext_everywhere() {
        for uri in ["grpc://localhost:50051", "grpc://192.168.1.42:50051"] {
            assert!(UNSAFE.check_own(&grpc_ep(uri)).is_ok(), "own {uri}");
            assert!(UNSAFE.check_peer(&grpc_ep(uri)).is_ok(), "peer {uri}");
        }
    }

    /// The spoof set is scheme-independent: every lookalike that fails for
    /// `http://` must fail identically for `grpc://`.
    #[test]
    fn grpc_loopback_lookalikes_are_rejected() {
        for uri in [
            "grpc://127.0.0.1@evil.com/",
            "grpc://localhost@evil.com/",
            "grpc://[::1]@evil.com/",
            "grpc://127.0.0.1.evil.com/",
            "grpc://localhost.evil.com/",
            "grpc://[::1/",
            "grpc://[::1]x/",
        ] {
            assert!(
                !is_loopback_uri_with_scheme(uri, "grpc://"),
                "{uri} must not count as loopback"
            );
        }
    }
}
