// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Serialization of [`PendingAction`] to/from opaque bytes for the WASM boundary.
//!
//! The JS side treats the bytes as an opaque `Uint8Array` — it passes them
//! back to `accept()` or `reject()` without inspecting them.
//!
//! Wire format:
//! - 1 byte: discriminant (0..8)
//! - 8 bytes: channel_id (big-endian u64)
//! - 8 bytes: trace_id (u64 BE) — echoed verbatim on the response
//! - For Pairing:
//!   - 4 bytes: my_kind (i32 BE)
//!   - 4 bytes: request_len (u32 BE)
//!   - N bytes: protobuf-encoded PairRequestMessage
//! - For channel message types (StoreShare, VerifyShare, Discovery,
//!   GetShare, Unpair, UpdateChannelInfo):
//!   - 32 bytes: shared_key
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
//! RespondToFailure carries no shared key: the response is encrypted under
//! the reply channel's key, loaded when it is sent.
//!
//! No pairing secret is carried for Pairing or PrePair — both accept
//! handlers load `PairingSecret` from the secret store at accept time
//! (single source of truth), so the token never holds private key material.

use crate::protocol::{FailedRequest, PendingAction, ReplyTarget};
use crate::types::ChannelId;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    PrePairRequestMessage, SenderKind, StoreShareRequestMessage, TransportProtocol,
    UnpairRequestMessage, UpdateChannelInfoRequestMessage, VerifyShareRequestMessage,
};
use prost::Message;

const TAG_PAIRING: u8 = 0;
const TAG_STORE_SHARE: u8 = 1;
const TAG_VERIFY_SHARE: u8 = 2;
const TAG_DISCOVERY: u8 = 3;
const TAG_GET_SHARE: u8 = 4;
const TAG_UNPAIR: u8 = 5;
const TAG_UPDATE_CHANNEL_INFO: u8 = 6;
const TAG_PRE_PAIR: u8 = 7;
const TAG_RESPOND_TO_FAILURE: u8 = 8;

const FAILED_STORE_SHARE: u8 = 0;
const FAILED_VERIFY_SHARE: u8 = 1;
const FAILED_GET_SECRET_IDS_VERSIONS: u8 = 2;
const FAILED_GET_SHARE: u8 = 3;
const FAILED_UNPAIR: u8 = 4;
const FAILED_UPDATE_CHANNEL_INFO: u8 = 5;
const FAILED_UNDECODABLE: u8 = 6;

pub fn serialize(action: PendingAction) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();

    match action {
        PendingAction::Pairing {
            channel_id,
            request,
            kind,
            trace_id,
            ..
        } => {
            buf.push(TAG_PAIRING);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&(kind as i32).to_be_bytes());
            let request_bytes = request.encode_to_vec();
            buf.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&request_bytes);
        }
        PendingAction::StoreShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_STORE_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::VerifyShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_VERIFY_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::Discovery {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_DISCOVERY);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::GetShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_GET_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::Unpair {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_UNPAIR);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::UpdateChannelInfo {
            channel_id,
            request,
            shared_key,
            trace_id,
        } => {
            buf.push(TAG_UPDATE_CHANNEL_INFO);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::PrePair {
            channel_id,
            request,
            trace_id,
        } => {
            buf.push(TAG_PRE_PAIR);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::RespondToFailure {
            channel_id,
            trace_id,
            reply,
            request,
        } => {
            buf.push(TAG_RESPOND_TO_FAILURE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&trace_id.to_be_bytes());
            buf.extend_from_slice(&reply.channel_id.0.to_be_bytes());
            let count = u32::try_from(reply.endpoints.len())
                .map_err(|_| "too many reply endpoints".to_owned())?;
            buf.extend_from_slice(&count.to_be_bytes());
            for endpoint in &reply.endpoints {
                let endpoint_bytes = endpoint.encode_to_vec();
                let len = u32::try_from(endpoint_bytes.len())
                    .map_err(|_| "reply endpoint too large".to_owned())?;
                buf.extend_from_slice(&len.to_be_bytes());
                buf.extend_from_slice(&endpoint_bytes);
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
            buf.push(request_tag);
            buf.extend_from_slice(&request_bytes);
        }
    }

    Ok(buf)
}

pub fn deserialize(bytes: &[u8]) -> Result<PendingAction, String> {
    if bytes.is_empty() {
        return Err("empty action bytes".to_owned());
    }

    let tag = bytes[0];
    let rest = &bytes[1..];

    if rest.len() < 8 {
        return Err("action bytes too short for channel_id".to_owned());
    }
    let channel_id = ChannelId(u64::from_be_bytes(rest[..8].try_into().unwrap()));
    let rest = &rest[8..];

    match tag {
        TAG_PAIRING => {
            if rest.len() < 16 {
                return Err("pairing action bytes too short".to_owned());
            }
            let trace_id = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let kind_i32 = i32::from_be_bytes(rest[8..12].try_into().unwrap());
            let request_len = u32::from_be_bytes(rest[12..16].try_into().unwrap()) as usize;
            let rest = &rest[16..];
            if rest.len() < request_len {
                return Err("pairing action bytes truncated (request)".to_owned());
            }
            let request = PairRequestMessage::decode(&rest[..request_len])
                .map_err(|e| format!("failed to decode PairRequestMessage: {e}"))?;

            let kind = i32_to_sender_kind(kind_i32)?;

            Ok(PendingAction::Pairing {
                channel_id,
                request,
                kind,
                peer_communication_info: std::collections::HashMap::new(),
                trace_id,
            })
        }
        TAG_STORE_SHARE => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = StoreShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode StoreShareRequestMessage: {e}"))?;
            Ok(PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_VERIFY_SHARE => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = VerifyShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode VerifyShareRequestMessage: {e}"))?;
            Ok(PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_DISCOVERY => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = GetSecretIdsVersionsRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode GetSecretIdsVersionsRequestMessage: {e}"))?;
            Ok(PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_GET_SHARE => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = GetShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode GetShareRequestMessage: {e}"))?;
            Ok(PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_UNPAIR => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = UnpairRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode UnpairRequestMessage: {e}"))?;
            Ok(PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_UPDATE_CHANNEL_INFO => {
            let (trace_id, shared_key, request_bytes) = split_trace_id_and_shared_key(rest)?;
            let request = UpdateChannelInfoRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode UpdateChannelInfoRequestMessage: {e}"))?;
            Ok(PendingAction::UpdateChannelInfo {
                channel_id,
                request,
                shared_key,
                trace_id,
            })
        }
        TAG_PRE_PAIR => {
            if rest.len() < 8 {
                return Err("PrePair action bytes too short for trace_id".to_owned());
            }
            let trace_id = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let request = PrePairRequestMessage::decode(&rest[8..])
                .map_err(|e| format!("failed to decode PrePairRequestMessage: {e}"))?;
            Ok(PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            })
        }
        TAG_RESPOND_TO_FAILURE => {
            if rest.len() < 8 {
                return Err("RespondToFailure action bytes too short for trace_id".to_owned());
            }
            let trace_id = u64::from_be_bytes(rest[..8].try_into().unwrap());
            let (reply, rest) = split_reply_target(&rest[8..])?;
            let request = decode_failed_request(rest)?;
            Ok(PendingAction::RespondToFailure {
                channel_id,
                trace_id,
                reply,
                request,
            })
        }
        _ => Err(format!("unknown action tag: {tag}")),
    }
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

fn split_shared_key(bytes: &[u8]) -> Result<([u8; 32], &[u8]), String> {
    if bytes.len() < 32 {
        return Err("action bytes too short for shared_key".to_owned());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok((key, &bytes[32..]))
}

fn split_trace_id_and_shared_key(bytes: &[u8]) -> Result<(u64, [u8; 32], &[u8]), String> {
    if bytes.len() < 8 {
        return Err("action bytes too short for trace_id".to_owned());
    }
    let trace_id = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let (shared_key, rest) = split_shared_key(&bytes[8..])?;
    Ok((trace_id, shared_key, rest))
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
            let bytes = serialize(PendingAction::RespondToFailure {
                channel_id: ChannelId(u64::MAX),
                trace_id: 0xDEAD_BEEF,
                reply: reply(),
                request: request.clone(),
            })
            .unwrap_or_else(|e| panic!("{request:?} serializes: {e}"));

            match deserialize(&bytes).unwrap_or_else(|e| panic!("{request:?} decodes: {e}")) {
                PendingAction::RespondToFailure {
                    channel_id,
                    trace_id,
                    reply: decoded_reply,
                    request: decoded_request,
                } => {
                    assert_eq!(channel_id, ChannelId(u64::MAX));
                    assert_eq!(trace_id, 0xDEAD_BEEF);
                    assert_eq!(decoded_reply, reply());
                    assert_eq!(decoded_request, request, "{request:?}");
                }
                other => panic!("{request:?} decoded as {other:?}"),
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
        let bytes = serialize(PendingAction::RespondToFailure {
            channel_id: ChannelId(3),
            trace_id: 1,
            reply: target.clone(),
            request: FailedRequest::Undecodable,
        })
        .expect("serializes");
        let PendingAction::RespondToFailure { reply, .. } = deserialize(&bytes).expect("decodes")
        else {
            panic!("wrong variant");
        };
        assert_eq!(reply, target);
    }

    /// Bytes an SDK persisted before the new tag existed still decode to the
    /// same action.
    #[test]
    fn an_existing_tag_decodes_unchanged() {
        let request = StoreShareRequestMessage {
            share: vec![0xCD; 8],
            version: 2,
            ..Default::default()
        };
        let mut bytes = vec![TAG_STORE_SHARE];
        bytes.extend_from_slice(&9u64.to_be_bytes());
        bytes.extend_from_slice(&11u64.to_be_bytes());
        bytes.extend_from_slice(&[0x5A; 32]);
        bytes.extend_from_slice(&request.encode_to_vec());

        let PendingAction::StoreShare {
            channel_id,
            request: decoded,
            shared_key,
            trace_id,
        } = deserialize(&bytes).expect("decodes")
        else {
            panic!("wrong variant");
        };
        assert_eq!(channel_id, ChannelId(9));
        assert_eq!(trace_id, 11);
        assert_eq!(shared_key, [0x5A; 32]);
        assert_eq!(decoded, request);
    }

    /// Truncated or corrupted token bytes are refused with an error, never a
    /// panic.
    #[test]
    fn truncated_respond_to_failure_bytes_are_refused() {
        let bytes = serialize(PendingAction::RespondToFailure {
            channel_id: ChannelId(1),
            trace_id: 2,
            reply: reply(),
            request: FailedRequest::Unpair(UnpairRequestMessage::default()),
        })
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
