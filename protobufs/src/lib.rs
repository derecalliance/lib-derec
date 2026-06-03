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

    pub fn decode_from_vec(message_bytes: &[u8]) -> Result<MessageBody, prost::DecodeError> {
        use prost::Message;
        use prost_types::Any;

        let any = Any::decode(message_bytes)?;

        let type_name = any
            .type_url
            .strip_prefix(TYPE_URL_PREFIX)
            .unwrap_or(&any.type_url);

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
