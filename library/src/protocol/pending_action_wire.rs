// SPDX-License-Identifier: Apache-2.0

//! Serialization of [`PendingAction`] to/from opaque bytes for the WASM boundary.
//!
//! The JS side treats the bytes as an opaque `Uint8Array` — it passes them
//! back to `accept()` or `reject()` without inspecting them.
//!
//! Wire format:
//! - 1 byte: discriminant (0..7)
//! - 8 bytes: channel_id (big-endian u64)
//! - 8 bytes: trace_id (u64 BE) — echoed verbatim on the response
//! - For Pairing:
//!   - 4 bytes: my_kind (i32 BE)
//!   - 4 bytes: request_len (u32 BE)
//!   - N bytes: protobuf-encoded PairRequestMessage
//!   - remaining: serialized PairingSecretKeyMaterial
//! - For channel message types (StoreShare, VerifyShare, Discovery,
//!   GetShare, Unpair, UpdateChannelInfo):
//!   - 32 bytes: shared_key
//!   - remaining: protobuf-encoded request message
//! - For PrePair (initiator side, before any key material exists):
//!   - remaining: protobuf-encoded PrePairRequestMessage
//!
//! No `shared_key` or `pairing_secret` is carried for PrePair — the leg is
//! plaintext and the handler loads `PairingSecret` from the secret store at
//! accept time (single source of truth).

use crate::protocol::PendingAction;
use crate::types::ChannelId;
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    PrePairRequestMessage, SenderKind, StoreShareRequestMessage, UnpairRequestMessage,
    UpdateChannelInfoRequestMessage, VerifyShareRequestMessage,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use prost::Message;

const TAG_PAIRING: u8 = 0;
const TAG_STORE_SHARE: u8 = 1;
const TAG_VERIFY_SHARE: u8 = 2;
const TAG_DISCOVERY: u8 = 3;
const TAG_GET_SHARE: u8 = 4;
const TAG_UNPAIR: u8 = 5;
const TAG_UPDATE_CHANNEL_INFO: u8 = 6;
const TAG_PRE_PAIR: u8 = 7;

pub fn serialize(action: PendingAction) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();

    match action {
        PendingAction::Pairing {
            channel_id,
            request,
            pairing_secret,
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
            // Serialize PairingSecretKeyMaterial
            let mut secret_buf = Vec::new();
            pairing_secret
                .serialize_uncompressed(&mut secret_buf)
                .map_err(|e| format!("failed to serialize pairing secret: {e}"))?;
            buf.extend_from_slice(&secret_buf);
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
    let channel_id = ChannelId(u64::from_be_bytes(
        rest[..8].try_into().unwrap(),
    ));
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
            let secret_bytes = &rest[request_len..];
            let pairing_secret =
                PairingSecretKeyMaterial::deserialize_uncompressed(&mut &secret_bytes[..])
                    .map_err(|e| format!("failed to deserialize pairing secret: {e}"))?;

            let kind = i32_to_sender_kind(kind_i32)?;

            Ok(PendingAction::Pairing {
                channel_id,
                request,
                pairing_secret,
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
        _ => Err(format!("unknown action tag: {tag}")),
    }
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

#[allow(dead_code)] // used by wasm only; kept for future ffi callers.
fn i32_to_sender_kind(val: i32) -> Result<SenderKind, String> {
    match val {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        _ => Err(format!("invalid SenderKind: {val}")),
    }
}
