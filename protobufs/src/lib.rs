// SPDX-License-Identifier: Apache-2.0

//! # Protobuf Bindings
//!
//! This module exposes the Rust types generated from the DeRec protocol
//! protobuf definitions.
//!
//! The types are generated at build time using `prost` from the protocol
//! `.proto` files and correspond directly to the message definitions used
//! by the DeRec protocol.
//!
//! These structures are used internally by the library to:
//!
//! - serialize protocol messages before transmission
//! - deserialize received messages
//! - provide a strongly-typed representation of protocol data
//!
//! The generated code mirrors the protobuf schema and therefore follows the
//! naming and structure defined in the protocol specification rather than
//! typical Rust conventions.
//!
//! ## Important
//!
//! The contents of this module are **generated code** and should not be edited
//! manually. Any changes must be performed in the protobuf definitions and the
//! bindings regenerated.
//!
//! Most users of the library should interact with the higher-level APIs
//! provided by the protocol flow modules (`pairing`, `sharing`, `verification`,
//! and `recovery`) rather than manipulating protobuf messages directly.

mod derec_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/org.derecalliance.derec.protobuf.rs"
    ));
}

pub use derec_proto::*;
use prost::DecodeError;

const TYPE_URL_PREFIX: &str = "type.derec.org/";

/// Carries a reference to an inner DeRec protocol message together with its [`MessageType`]
/// discriminant.
///
/// Pass a `MessageBody` variant to [`DeRecMessageBuilder::message_body`] so that the builder
/// can encode the inner message *and* set the correct `message_type` field on the outer
/// [`DeRecMessage`] envelope in a single call.
///
/// # Example
///
/// ```rust,ignore
/// use derec_proto::{MessageBody, VerifyShareRequestMessage};
///
/// let inner = VerifyShareRequestMessage { /* … */ };
/// let envelope = DeRecMessageBuilder::channel()
///     .channel_id(channel_id)
///     .timestamp(ts)
///     .message_body(MessageBody::VerifyShareRequest(&inner))
///     .encrypt(&shared_key)?
///     .build()?;
/// ```
#[derive(Debug)]
pub enum MessageBody {
    PairRequest(PairRequestMessage),
    PairResponse(PairResponseMessage),
    UnpairRequest(UnpairRequestMessage),
    UnpairResponse(UnpairResponseMessage),
    StoreShareRequest(StoreShareRequestMessage),
    StoreShareResponse(StoreShareResponseMessage),
    VerifyShareRequest(VerifyShareRequestMessage),
    VerifyShareResponse(VerifyShareResponseMessage),
    GetSecretIdsVersionsRequest(GetSecretIdsVersionsRequestMessage),
    GetSecretIdsVersionsResponse(GetSecretIdsVersionsResponseMessage),
    GetShareRequest(GetShareRequestMessage),
    GetShareResponse(GetShareResponseMessage),
    ErrorResponse(ErrorResponseMessage),
    UpdateChannelInfoRequest(UpdateChannelInfoRequestMessage),
    UpdateChannelInfoResponse(UpdateChannelInfoResponseMessage),
    PrePairRequest(PrePairRequestMessage),
    PrePairResponse(PrePairResponseMessage),
}

impl MessageBody {
    /// Serializes the inner message to protobuf bytes using `prost`.
    pub fn encode_to_vec(&self) -> Vec<u8> {
        use prost::Message;
        use prost_types::Any;

        let (type_name, value) = match self {
            MessageBody::PairRequest(m) => ("PairRequestMessage", m.encode_to_vec()),
            MessageBody::PairResponse(m) => ("PairResponseMessage", m.encode_to_vec()),
            MessageBody::UnpairRequest(m) => ("UnpairRequestMessage", m.encode_to_vec()),
            MessageBody::UnpairResponse(m) => ("UnpairResponseMessage", m.encode_to_vec()),
            MessageBody::StoreShareRequest(m) => ("StoreShareRequestMessage", m.encode_to_vec()),
            MessageBody::StoreShareResponse(m) => ("StoreShareResponseMessage", m.encode_to_vec()),
            MessageBody::VerifyShareRequest(m) => ("VerifyShareRequestMessage", m.encode_to_vec()),
            MessageBody::VerifyShareResponse(m) => {
                ("VerifyShareResponseMessage", m.encode_to_vec())
            }
            MessageBody::GetSecretIdsVersionsRequest(m) => {
                ("GetSecretIdsVersionsRequestMessage", m.encode_to_vec())
            }
            MessageBody::GetSecretIdsVersionsResponse(m) => {
                ("GetSecretIdsVersionsResponseMessage", m.encode_to_vec())
            }
            MessageBody::GetShareRequest(m) => ("GetShareRequestMessage", m.encode_to_vec()),
            MessageBody::GetShareResponse(m) => ("GetShareResponseMessage", m.encode_to_vec()),
            MessageBody::ErrorResponse(m) => ("ErrorResponseMessage", m.encode_to_vec()),
            MessageBody::UpdateChannelInfoRequest(m) => {
                ("UpdateChannelInfoRequestMessage", m.encode_to_vec())
            }
            MessageBody::UpdateChannelInfoResponse(m) => {
                ("UpdateChannelInfoResponseMessage", m.encode_to_vec())
            }
            MessageBody::PrePairRequest(m) => ("PrePairRequestMessage", m.encode_to_vec()),
            MessageBody::PrePairResponse(m) => ("PrePairResponseMessage", m.encode_to_vec()),
        };

        let any = Any {
            type_url: format!("{}{}", TYPE_URL_PREFIX, type_name),
            value,
        };

        any.encode_to_vec()
    }

    /// Decodes a [`MessageBody`] from a [`prost_types::Any`]-wrapped
    /// protobuf payload.
    ///
    /// # Wire format
    ///
    /// The expected form is exactly what [`encode_to_vec`](Self::encode_to_vec)
    /// emits: an `Any` whose `type_url` is `type.derec.org/<MessageName>`
    /// (e.g. `type.derec.org/PairRequestMessage`) and whose `value` is the
    /// inner message's proto bytes. The `type.derec.org/` prefix is part
    /// of the canonical wire format and is enforced strictly.
    ///
    /// # Errors
    ///
    /// Returns [`prost::DecodeError`] in three cases:
    ///
    /// 1. The bytes don't decode as a valid `Any`.
    /// 2. **The `type_url` is missing the `type.derec.org/` prefix** —
    ///    this includes both the bare-name form (e.g. `PairRequestMessage`
    ///    with no namespace) AND any foreign-namespace form (e.g.
    ///    `type.example.com/PairRequestMessage` or `googleapis.com/...`).
    ///    Only the DeRec namespace is accepted; anything else is refused
    ///    so the type-domain binding the prefix provides cannot be
    ///    spoofed.
    /// 3. The bare message name after the prefix is unknown, or the
    ///    inner `value` bytes don't decode as that message type.
    ///
    /// Strict prefix matching is what stops a peer from shipping two
    /// byte-distinct encodings of the same logical message — a
    /// canonicalization gap downstream byte-level dedup or cross-
    /// implementation comparisons could otherwise be tricked by.
    pub fn decode_from_vec(message_bytes: &[u8]) -> Result<MessageBody, prost::DecodeError> {
        use prost::Message;
        use prost_types::Any;

        let any = Any::decode(message_bytes)?;

        let type_name = any.type_url.strip_prefix(TYPE_URL_PREFIX).ok_or_else(|| {
            #[allow(deprecated)]
            DecodeError::new(format!(
                "type_url `{}` is missing the required `{TYPE_URL_PREFIX}` namespace prefix",
                any.type_url
            ))
        })?;

        let body = match type_name {
            "PairRequestMessage" => {
                MessageBody::PairRequest(PairRequestMessage::decode(any.value.as_slice())?)
            }
            "PairResponseMessage" => {
                MessageBody::PairResponse(PairResponseMessage::decode(any.value.as_slice())?)
            }
            "UnpairRequestMessage" => {
                MessageBody::UnpairRequest(UnpairRequestMessage::decode(any.value.as_slice())?)
            }
            "UnpairResponseMessage" => {
                MessageBody::UnpairResponse(UnpairResponseMessage::decode(any.value.as_slice())?)
            }
            "StoreShareRequestMessage" => MessageBody::StoreShareRequest(
                StoreShareRequestMessage::decode(any.value.as_slice())?,
            ),
            "StoreShareResponseMessage" => MessageBody::StoreShareResponse(
                StoreShareResponseMessage::decode(any.value.as_slice())?,
            ),
            "VerifyShareRequestMessage" => MessageBody::VerifyShareRequest(
                VerifyShareRequestMessage::decode(any.value.as_slice())?,
            ),
            "VerifyShareResponseMessage" => MessageBody::VerifyShareResponse(
                VerifyShareResponseMessage::decode(any.value.as_slice())?,
            ),
            "GetSecretIdsVersionsRequestMessage" => MessageBody::GetSecretIdsVersionsRequest(
                GetSecretIdsVersionsRequestMessage::decode(any.value.as_slice())?,
            ),
            "GetSecretIdsVersionsResponseMessage" => MessageBody::GetSecretIdsVersionsResponse(
                GetSecretIdsVersionsResponseMessage::decode(any.value.as_slice())?,
            ),
            "GetShareRequestMessage" => {
                MessageBody::GetShareRequest(GetShareRequestMessage::decode(any.value.as_slice())?)
            }
            "GetShareResponseMessage" => MessageBody::GetShareResponse(
                GetShareResponseMessage::decode(any.value.as_slice())?,
            ),
            "ErrorResponseMessage" => {
                MessageBody::ErrorResponse(ErrorResponseMessage::decode(any.value.as_slice())?)
            }
            "UpdateChannelInfoRequestMessage" => MessageBody::UpdateChannelInfoRequest(
                UpdateChannelInfoRequestMessage::decode(any.value.as_slice())?,
            ),
            "UpdateChannelInfoResponseMessage" => MessageBody::UpdateChannelInfoResponse(
                UpdateChannelInfoResponseMessage::decode(any.value.as_slice())?,
            ),
            "PrePairRequestMessage" => {
                MessageBody::PrePairRequest(PrePairRequestMessage::decode(any.value.as_slice())?)
            }
            "PrePairResponseMessage" => MessageBody::PrePairResponse(
                PrePairResponseMessage::decode(any.value.as_slice())?,
            ),
            #[allow(deprecated)]
            unknown => return Err(DecodeError::new(unknown.to_string())),
        };

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use prost_types::Any;

    fn unpair_request_bytes() -> Vec<u8> {
        UnpairRequestMessage {
            memo: "bye".to_owned(),
            timestamp: None,
            reply_to: None,
        }
        .encode_to_vec()
    }

    /// The canonical wire form (`type.derec.org/<MessageName>`) emitted by
    /// `encode_to_vec` must round-trip through `decode_from_vec`.
    #[test]
    fn decode_accepts_canonical_prefixed_type_url() {
        let body = MessageBody::UnpairRequest(UnpairRequestMessage {
            memo: "bye".to_owned(),
            timestamp: None,
            reply_to: None,
        });
        let bytes = body.encode_to_vec();
        let round_tripped =
            MessageBody::decode_from_vec(&bytes).expect("canonical encoding must decode");
        assert!(matches!(round_tripped, MessageBody::UnpairRequest(_)));
    }

    /// A bare `<MessageName>` without the `type.derec.org/` prefix must be
    /// rejected — accepting it would create a second wire encoding for the
    /// same logical message and erase the type-domain binding the prefix
    /// provides.
    #[test]
    fn decode_rejects_unprefixed_type_url() {
        let any = Any {
            type_url: "UnpairRequestMessage".to_owned(),
            value: unpair_request_bytes(),
        };
        let err = MessageBody::decode_from_vec(&any.encode_to_vec())
            .expect_err("unprefixed type_url must be rejected");
        assert!(
            err.to_string()
                .contains("is missing the required `type.derec.org/` namespace prefix"),
            "unexpected error: {err}"
        );
    }

    /// A foreign-namespace prefix (e.g. another protocol's domain) must be
    /// rejected. Strict prefix matching is what enforces that the `Any`
    /// payload belongs to the DeRec type domain.
    #[test]
    fn decode_rejects_foreign_namespace_prefix() {
        let any = Any {
            type_url: "type.example.com/UnpairRequestMessage".to_owned(),
            value: unpair_request_bytes(),
        };
        let err = MessageBody::decode_from_vec(&any.encode_to_vec())
            .expect_err("foreign-namespace type_url must be rejected");
        assert!(
            err.to_string()
                .contains("is missing the required `type.derec.org/` namespace prefix"),
            "unexpected error: {err}"
        );
    }
}
