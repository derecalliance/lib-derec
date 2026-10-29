// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Serialization of [`PendingAction`] to/from opaque bytes for the WASM boundary.
//!
//! The JS side treats the bytes as an opaque `Uint8Array` — it passes them
//! back to `accept()` or `reject()` without inspecting them.
//!
//! Wire format:
//! - 1 byte: discriminant (0, 7..14)
//! - 8 bytes: channel_id (big-endian u64)
//! - 8 bytes: trace_id (u64 BE) — echoed verbatim on the response
//! - For channel message types and RespondToFailure: 32 bytes, the action's
//!   seal (an HMAC-SHA256 under a key derived from the answering channel's
//!   shared key; see `events::seal`). Pairing and PrePair carry none.
//! - For Pairing:
//!   - 4 bytes: my_kind (i32 BE)
//!   - 4 bytes: request_len (u32 BE)
//!   - N bytes: protobuf-encoded PairRequestMessage
//! - For channel message types (StoreShare, VerifyShare, Discovery,
//!   GetShare, Unpair, UpdateChannelInfo):
//!   - remaining: protobuf-encoded request message
//! - For PrePair (initiator side, before any key material exists):
//!   - remaining: protobuf-encoded PrePairRequestMessage
//! - For RespondToFailure:
//!   - 8 bytes: reply channel_id (u64 BE)
//!   - 4 bytes: endpoint count (u32 BE), then for each endpoint:
//!     - 4 bytes: endpoint_len (u32 BE)
//!     - N bytes: protobuf-encoded TransportProtocol
//!   - 1 byte: failed-request discriminant (0..6)
//!   - remaining: protobuf-encoded request message, empty for `Undecodable`
//!
//! No token carries key material, and none can be altered undetected: the
//! seal covers everything after it, so `accept` and `reject` refuse a token
//! that was edited, built by hand, or moved to another channel. A channel message is answered under the
//! channel's shared key, and RespondToFailure under the reply channel's,
//! each loaded from the secret store when the response is sent. Pairing and
//! PrePair load `PairingSecret` from the secret store at accept time. The
//! secret store is the single source of truth for every key.
//!
//! Tokens issued by v0.0.10, whose channel messages used discriminants 1..6
//! and carried the shared key, are refused.

use crate::protocol::events::seal::{SEAL_LEN, Seal};
use crate::protocol::{Action, ChannelRequest, FailedRequest, PendingAction, ReplyTarget};
use crate::types::ChannelId;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    PrePairRequestMessage, SenderKind, StoreShareRequestMessage, TransportProtocol,
    UnpairRequestMessage, UpdateChannelInfoRequestMessage, VerifyShareRequestMessage,
};
use prost::Message;

const TAG_PAIRING: u8 = 0;
const TAG_PRE_PAIR: u8 = 7;
const TAG_RESPOND_TO_FAILURE: u8 = 8;
const TAG_STORE_SHARE: u8 = 9;
const TAG_VERIFY_SHARE: u8 = 10;
const TAG_DISCOVERY: u8 = 11;
const TAG_GET_SHARE: u8 = 12;
const TAG_UNPAIR: u8 = 13;
const TAG_UPDATE_CHANNEL_INFO: u8 = 14;

/// The highest channel-message discriminant of a v0.0.10 token, which carried
/// the shared key; discriminants 1 up to it are refused.
const V0_0_10_LAST_CHANNEL_TAG: u8 = 6;

const FAILED_STORE_SHARE: u8 = 0;
const FAILED_VERIFY_SHARE: u8 = 1;
const FAILED_GET_SECRET_IDS_VERSIONS: u8 = 2;
const FAILED_GET_SHARE: u8 = 3;
const FAILED_UNPAIR: u8 = 4;
const FAILED_UPDATE_CHANNEL_INFO: u8 = 5;
const FAILED_UNDECODABLE: u8 = 6;

pub fn serialize(action: PendingAction) -> Result<Vec<u8>, String> {
    let seal = action.seal().map(|seal| *seal.as_bytes());
    let (channel_id, trace_id, action) = action.into_parts();
    let (tag, body) = match action {
        Action::Pairing { request, kind, .. } => {
            let mut body = (kind as i32).to_be_bytes().to_vec();
            let request_bytes = request.encode_to_vec();
            body.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
            body.extend_from_slice(&request_bytes);
            (TAG_PAIRING, body)
        }
        Action::PrePair(request) => (TAG_PRE_PAIR, request.encode_to_vec()),
        Action::Request(request) => match request {
            ChannelRequest::StoreShare(r) => (TAG_STORE_SHARE, r.encode_to_vec()),
            ChannelRequest::VerifyShare(r) => (TAG_VERIFY_SHARE, r.encode_to_vec()),
            ChannelRequest::Discovery(r) => (TAG_DISCOVERY, r.encode_to_vec()),
            ChannelRequest::GetShare(r) => (TAG_GET_SHARE, r.encode_to_vec()),
            ChannelRequest::Unpair(r) => (TAG_UNPAIR, r.encode_to_vec()),
            ChannelRequest::UpdateChannelInfo(r) => (TAG_UPDATE_CHANNEL_INFO, r.encode_to_vec()),
        },
        Action::RespondToFailure { reply, request } => {
            let mut body = reply.channel_id.0.to_be_bytes().to_vec();
            let count = u32::try_from(reply.endpoints.len())
                .map_err(|_| "too many reply endpoints".to_owned())?;
            body.extend_from_slice(&count.to_be_bytes());
            for endpoint in &reply.endpoints {
                let endpoint_bytes = endpoint.encode_to_vec();
                let len = u32::try_from(endpoint_bytes.len())
                    .map_err(|_| "reply endpoint too large".to_owned())?;
                body.extend_from_slice(&len.to_be_bytes());
                body.extend_from_slice(&endpoint_bytes);
            }
            let (request_tag, request_bytes) = match request {
                FailedRequest::StoreShare(r) => (FAILED_STORE_SHARE, r.encode_to_vec()),
                FailedRequest::VerifyShare(r) => (FAILED_VERIFY_SHARE, r.encode_to_vec()),
                FailedRequest::GetSecretIdsVersions(r) => {
                    (FAILED_GET_SECRET_IDS_VERSIONS, r.encode_to_vec())
                }
                FailedRequest::GetShare(r) => (FAILED_GET_SHARE, r.encode_to_vec()),
                FailedRequest::Unpair(r) => (FAILED_UNPAIR, r.encode_to_vec()),
                FailedRequest::UpdateChannelInfo(r) => {
                    (FAILED_UPDATE_CHANNEL_INFO, r.encode_to_vec())
                }
                FailedRequest::Undecodable => (FAILED_UNDECODABLE, Vec::new()),
            };
            body.push(request_tag);
            body.extend_from_slice(&request_bytes);
            (TAG_RESPOND_TO_FAILURE, body)
        }
    };

    match (is_sealed(tag), seal) {
        (true, None) => return Err("a sealed action carries no seal".to_owned()),
        (false, Some(_)) => return Err("a pairing action carries a seal".to_owned()),
        _ => {}
    }

    let mut buf = Vec::with_capacity(1 + 8 + 8 + SEAL_LEN + body.len());
    buf.push(tag);
    buf.extend_from_slice(&channel_id.0.to_be_bytes());
    buf.extend_from_slice(&trace_id.to_be_bytes());
    if let Some(seal) = seal {
        buf.extend_from_slice(&seal);
    }
    buf.extend_from_slice(&body);
    Ok(buf)
}

pub fn deserialize(bytes: &[u8]) -> Result<PendingAction, String> {
    let Some((&tag, rest)) = bytes.split_first() else {
        return Err("empty action bytes".to_owned());
    };
    if (1..=V0_0_10_LAST_CHANNEL_TAG).contains(&tag) {
        return Err(
            "action issued by v0.0.10, which carried the shared key, is not accepted".to_owned(),
        );
    }
    if rest.len() < 16 {
        return Err("action bytes too short for channel_id and trace_id".to_owned());
    }
    let channel_id = ChannelId(u64::from_be_bytes(rest[..8].try_into().unwrap()));
    let trace_id = u64::from_be_bytes(rest[8..16].try_into().unwrap());
    let (seal, body) = if is_sealed(tag) {
        let Some(seal) = rest.get(16..16 + SEAL_LEN) else {
            return Err("action bytes too short for the seal".to_owned());
        };
        (
            Some(Seal::from_bytes(seal.try_into().unwrap())),
            &rest[16 + SEAL_LEN..],
        )
    } else {
        (None, &rest[16..])
    };

    let action = match tag {
        TAG_PAIRING => {
            if body.len() < 8 {
                return Err("pairing action bytes too short".to_owned());
            }
            let kind_i32 = i32::from_be_bytes(body[..4].try_into().unwrap());
            let request_len = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
            let body = &body[8..];
            if body.len() < request_len {
                return Err("pairing action bytes truncated (request)".to_owned());
            }
            let request = PairRequestMessage::decode(&body[..request_len])
                .map_err(|e| format!("failed to decode PairRequestMessage: {e}"))?;
            Action::Pairing {
                request,
                kind: i32_to_sender_kind(kind_i32)?,
                peer_communication_info: std::collections::HashMap::new(),
            }
        }
        TAG_PRE_PAIR => Action::PrePair(
            PrePairRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode PrePairRequestMessage: {e}"))?,
        ),
        TAG_STORE_SHARE => Action::Request(ChannelRequest::StoreShare(
            StoreShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode StoreShareRequestMessage: {e}"))?,
        )),
        TAG_VERIFY_SHARE => Action::Request(ChannelRequest::VerifyShare(
            VerifyShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode VerifyShareRequestMessage: {e}"))?,
        )),
        TAG_DISCOVERY => Action::Request(ChannelRequest::Discovery(
            GetSecretIdsVersionsRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode GetSecretIdsVersionsRequestMessage: {e}"))?,
        )),
        TAG_GET_SHARE => Action::Request(ChannelRequest::GetShare(
            GetShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode GetShareRequestMessage: {e}"))?,
        )),
        TAG_UNPAIR => Action::Request(ChannelRequest::Unpair(
            UnpairRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode UnpairRequestMessage: {e}"))?,
        )),
        TAG_UPDATE_CHANNEL_INFO => Action::Request(ChannelRequest::UpdateChannelInfo(
            UpdateChannelInfoRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode UpdateChannelInfoRequestMessage: {e}"))?,
        )),
        TAG_RESPOND_TO_FAILURE => {
            let (reply, body) = split_reply_target(body)?;
            Action::RespondToFailure {
                reply,
                request: decode_failed_request(body)?,
            }
        }
        _ => return Err(format!("unknown action tag: {tag}")),
    };
    Ok(PendingAction::from_parts(
        channel_id, trace_id, seal, action,
    ))
}

/// Whether a token with `tag` carries a seal: every action answered under a
/// channel key does.
fn is_sealed(tag: u8) -> bool {
    !matches!(tag, TAG_PAIRING | TAG_PRE_PAIR)
}

fn split_reply_target(bytes: &[u8]) -> Result<(ReplyTarget, &[u8]), String> {
    if bytes.len() < 12 {
        return Err("RespondToFailure action bytes too short for reply target".to_owned());
    }
    let channel_id = ChannelId(u64::from_be_bytes(bytes[..8].try_into().unwrap()));
    let count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
    let mut rest = &bytes[12..];
    let mut endpoints = Vec::new();
    for _ in 0..count {
        if rest.len() < 4 {
            return Err("RespondToFailure action bytes truncated (endpoint length)".to_owned());
        }
        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
        rest = &rest[4..];
        if rest.len() < len {
            return Err("RespondToFailure action bytes truncated (endpoint)".to_owned());
        }
        let endpoint = TransportProtocol::decode(&rest[..len])
            .map_err(|e| format!("failed to decode TransportProtocol: {e}"))?;
        endpoints.push(endpoint);
        rest = &rest[len..];
    }
    Ok((
        ReplyTarget {
            channel_id,
            endpoints,
        },
        rest,
    ))
}

fn decode_failed_request(bytes: &[u8]) -> Result<FailedRequest, String> {
    let Some((&tag, body)) = bytes.split_first() else {
        return Err("RespondToFailure action bytes too short for request".to_owned());
    };
    Ok(match tag {
        FAILED_STORE_SHARE => FailedRequest::StoreShare(
            StoreShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode StoreShareRequestMessage: {e}"))?,
        ),
        FAILED_VERIFY_SHARE => FailedRequest::VerifyShare(
            VerifyShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode VerifyShareRequestMessage: {e}"))?,
        ),
        FAILED_GET_SECRET_IDS_VERSIONS => FailedRequest::GetSecretIdsVersions(
            GetSecretIdsVersionsRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode GetSecretIdsVersionsRequestMessage: {e}"))?,
        ),
        FAILED_GET_SHARE => FailedRequest::GetShare(
            GetShareRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode GetShareRequestMessage: {e}"))?,
        ),
        FAILED_UNPAIR => FailedRequest::Unpair(
            UnpairRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode UnpairRequestMessage: {e}"))?,
        ),
        FAILED_UPDATE_CHANNEL_INFO => FailedRequest::UpdateChannelInfo(
            UpdateChannelInfoRequestMessage::decode(body)
                .map_err(|e| format!("failed to decode UpdateChannelInfoRequestMessage: {e}"))?,
        ),
        FAILED_UNDECODABLE if body.is_empty() => FailedRequest::Undecodable,
        FAILED_UNDECODABLE => {
            return Err("Undecodable failed request carries unexpected bytes".to_owned());
        }
        _ => return Err(format!("unknown failed-request tag: {tag}")),
    })
}

fn i32_to_sender_kind(val: i32) -> Result<SenderKind, String> {
    match val {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        _ => Err(format!("invalid SenderKind: {val}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FailedRequest, ReplyTarget};
    use derec_proto::{Protocol, TransportProtocol};

    fn reply() -> ReplyTarget {
        ReplyTarget {
            channel_id: ChannelId(u64::MAX - 1),
            endpoints: vec![
                TransportProtocol {
                    uri: "https://owner.example/derec".to_owned(),
                    protocol: Protocol::Https as i32,
                },
                TransportProtocol {
                    uri: "grpcs://owner.example:443".to_owned(),
                    protocol: Protocol::Grpc as i32,
                },
            ],
        }
    }

    fn every_failed_request() -> Vec<FailedRequest> {
        vec![
            FailedRequest::StoreShare(StoreShareRequestMessage {
                share: vec![0xAB; 64],
                secret_id: 42,
                version: 3,
                replica_id: Some(7),
                ..Default::default()
            }),
            FailedRequest::VerifyShare(VerifyShareRequestMessage {
                secret_id: 42,
                version: 3,
                nonce: 0xABCD,
                ..Default::default()
            }),
            FailedRequest::GetSecretIdsVersions(GetSecretIdsVersionsRequestMessage {
                replica_id: Some(7),
                ..Default::default()
            }),
            FailedRequest::GetShare(GetShareRequestMessage {
                secret_id: 42,
                version: 5,
                ..Default::default()
            }),
            FailedRequest::Unpair(UnpairRequestMessage {
                memo: "moving devices".to_owned(),
                ..Default::default()
            }),
            FailedRequest::UpdateChannelInfo(UpdateChannelInfoRequestMessage {
                supported_transports: vec![TransportProtocol {
                    uri: "https://new.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                ..Default::default()
            }),
            FailedRequest::Undecodable,
        ]
    }

    /// A token handed to an SDK comes back as the same token, whatever request
    /// it answers, so `reject` builds the response for the right request type
    /// and sends it to the right place.
    #[test]
    fn respond_to_failure_round_trips_every_failed_request() {
        for request in every_failed_request() {
            let bytes = serialize(
                PendingAction::failure(ChannelId(u64::MAX), 0xDEAD_BEEF, reply(), request.clone())
                    .sealed_with(&crate::types::SharedKey::new([0; 32])),
            )
            .unwrap_or_else(|e| panic!("{request:?} serializes: {e}"));

            let decoded =
                deserialize(&bytes).unwrap_or_else(|e| panic!("{request:?} decodes: {e}"));
            assert_eq!(decoded.channel_id(), ChannelId(u64::MAX));
            assert_eq!(decoded.trace_id(), 0xDEAD_BEEF);
            match decoded.action() {
                Action::RespondToFailure {
                    reply: decoded_reply,
                    request: decoded_request,
                } => {
                    assert_eq!(*decoded_reply, reply());
                    assert_eq!(*decoded_request, request, "{request:?}");
                }
                _ => panic!("{request:?} decoded as {decoded:?}"),
            }
        }
    }

    /// A target with no endpoints is a valid target: the response then goes
    /// to the channel's recorded endpoints.
    #[test]
    fn respond_to_failure_round_trips_an_empty_endpoint_list() {
        let target = ReplyTarget {
            channel_id: ChannelId(3),
            endpoints: Vec::new(),
        };
        let bytes = serialize(
            PendingAction::failure(ChannelId(3), 1, target.clone(), FailedRequest::Undecodable)
                .sealed_with(&crate::types::SharedKey::new([0; 32])),
        )
        .expect("serializes");
        let decoded = deserialize(&bytes).expect("decodes");
        let Action::RespondToFailure { reply, .. } = decoded.action() else {
            panic!("wrong variant");
        };
        assert_eq!(*reply, target);
    }

    /// A token issued by v0.0.10, which carried the channel key, is refused
    /// whatever request it holds.
    #[test]
    fn a_v0_0_10_token_is_refused() {
        let request = StoreShareRequestMessage {
            share: vec![0xCD; 8],
            version: 2,
            ..Default::default()
        };
        for tag in 1..=V0_0_10_LAST_CHANNEL_TAG {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(&9u64.to_be_bytes());
            bytes.extend_from_slice(&11u64.to_be_bytes());
            bytes.extend_from_slice(&[0x5A; 32]);
            bytes.extend_from_slice(&request.encode_to_vec());

            assert!(deserialize(&bytes).is_err(), "tag {tag}");
        }
    }

    /// A channel message's token is its tag, ids, seal and request: the key
    /// it is sealed under is not in it.
    #[test]
    fn a_channel_message_token_carries_no_key() {
        let key = crate::types::SharedKey::new([0x5A; 32]);
        let request = UnpairRequestMessage {
            memo: "moving devices".to_owned(),
            ..Default::default()
        };
        let bytes = serialize(
            PendingAction::request(ChannelId(9), 11, ChannelRequest::Unpair(request.clone()))
                .sealed_with(&key),
        )
        .expect("serializes");

        assert_eq!(
            bytes.len(),
            1 + 8 + 8 + SEAL_LEN + request.encode_to_vec().len()
        );
        assert!(
            !bytes.windows(32).any(|window| window == key.as_bytes()),
            "the token holds no copy of the key"
        );
        let decoded = deserialize(&bytes).expect("decodes");
        assert_eq!(decoded.channel_id(), ChannelId(9));
        assert_eq!(decoded.trace_id(), 11);
        assert!(matches!(
            decoded.action(),
            Action::Request(ChannelRequest::Unpair(decoded)) if *decoded == request
        ));
    }

    /// Truncated or corrupted token bytes are refused with an error, never a
    /// panic.
    #[test]
    fn truncated_respond_to_failure_bytes_are_refused() {
        let bytes = serialize(
            PendingAction::failure(
                ChannelId(1),
                2,
                reply(),
                FailedRequest::Unpair(UnpairRequestMessage::default()),
            )
            .sealed_with(&crate::types::SharedKey::new([0; 32])),
        )
        .expect("serializes");
        for len in 1..bytes.len() - 1 {
            let _ = deserialize(&bytes[..len]);
        }
        let mut bad_request_tag = bytes.clone();
        let tag_at = bytes.len() - 1 - UnpairRequestMessage::default().encode_to_vec().len();
        bad_request_tag[tag_at] = 0xFF;
        assert!(deserialize(&bad_request_tag).is_err());
    }
}
