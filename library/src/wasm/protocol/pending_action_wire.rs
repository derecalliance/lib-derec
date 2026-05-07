// SPDX-License-Identifier: Apache-2.0

//! Serialization of [`PendingAction`] to/from opaque bytes for the WASM boundary.
//!
//! The JS side treats the bytes as an opaque `Uint8Array` — it passes them
//! back to `accept()` or `reject()` without inspecting them.
//!
//! Wire format:
//! - 1 byte: discriminant (0..4)
//! - 8 bytes: channel_id (big-endian u64)
//! - For Pairing:
//!   - 4 bytes: my_kind (i32 BE)
//!   - 4 bytes: response_kind (i32 BE)
//!   - 4 bytes: request_len (u32 BE)
//!   - N bytes: protobuf-encoded PairRequestMessage
//!   - remaining: serialized PairingSecretKeyMaterial
//! - For channel message types (StoreShare, VerifyShare, Discovery, GetShare):
//!   - 32 bytes: shared_key
//!   - remaining: protobuf-encoded request message

use crate::protocol::PendingAction;
use crate::types::ChannelId;
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, PairRequestMessage,
    SenderKind, StoreShareRequestMessage, VerifyShareRequestMessage,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use prost::Message;

const TAG_PAIRING: u8 = 0;
const TAG_STORE_SHARE: u8 = 1;
const TAG_VERIFY_SHARE: u8 = 2;
const TAG_DISCOVERY: u8 = 3;
const TAG_GET_SHARE: u8 = 4;

pub fn serialize(action: PendingAction) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();

    match action {
        PendingAction::Pairing {
            channel_id,
            request,
            pairing_secret,
            kind,
            response_kind,
            ..
        } => {
            buf.push(TAG_PAIRING);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&(kind as i32).to_be_bytes());
            buf.extend_from_slice(&(response_kind as i32).to_be_bytes());
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
        } => {
            buf.push(TAG_STORE_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::VerifyShare {
            channel_id,
            request,
            shared_key,
        } => {
            buf.push(TAG_VERIFY_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::Discovery {
            channel_id,
            request,
            shared_key,
        } => {
            buf.push(TAG_DISCOVERY);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&shared_key);
            buf.extend_from_slice(&request.encode_to_vec());
        }
        PendingAction::GetShare {
            channel_id,
            request,
            shared_key,
        } => {
            buf.push(TAG_GET_SHARE);
            buf.extend_from_slice(&channel_id.0.to_be_bytes());
            buf.extend_from_slice(&shared_key);
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
            if rest.len() < 12 {
                return Err("pairing action bytes too short".to_owned());
            }
            let kind_i32 = i32::from_be_bytes(rest[..4].try_into().unwrap());
            let response_kind_i32 = i32::from_be_bytes(rest[4..8].try_into().unwrap());
            let request_len = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
            let rest = &rest[12..];
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
            let response_kind = i32_to_sender_kind(response_kind_i32)?;

            Ok(PendingAction::Pairing {
                channel_id,
                request,
                pairing_secret,
                kind,
                response_kind,
                peer_communication_info: std::collections::HashMap::new(),
            })
        }
        TAG_STORE_SHARE => {
            let (shared_key, request_bytes) = split_shared_key(rest)?;
            let request = StoreShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode StoreShareRequestMessage: {e}"))?;
            Ok(PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
            })
        }
        TAG_VERIFY_SHARE => {
            let (shared_key, request_bytes) = split_shared_key(rest)?;
            let request = VerifyShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode VerifyShareRequestMessage: {e}"))?;
            Ok(PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
            })
        }
        TAG_DISCOVERY => {
            let (shared_key, request_bytes) = split_shared_key(rest)?;
            let request = GetSecretIdsVersionsRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode GetSecretIdsVersionsRequestMessage: {e}"))?;
            Ok(PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
            })
        }
        TAG_GET_SHARE => {
            let (shared_key, request_bytes) = split_shared_key(rest)?;
            let request = GetShareRequestMessage::decode(request_bytes)
                .map_err(|e| format!("failed to decode GetShareRequestMessage: {e}"))?;
            Ok(PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
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

fn i32_to_sender_kind(val: i32) -> Result<SenderKind, String> {
    match val {
        0 => Ok(SenderKind::OwnerNonRecovery),
        1 => Ok(SenderKind::OwnerRecovery),
        2 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::Replica),
        _ => Err(format!("invalid SenderKind: {val}")),
    }
}
