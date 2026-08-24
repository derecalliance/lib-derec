// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_library::protocol::types::{
    ChannelRecord, HelperChannel, PairingKeyMaterial, ReplicaMember, UserSecret, UserSecrets,
};
use derec_library::protocol::{SecretKind, SecretValue};
use derec_proto::ContactMessage;
use prost::Message;

pub fn encode_channel(record: &ChannelRecord) -> Vec<u8> {
    serde_json::to_vec(record).expect("failed to JSON-encode ChannelRecord")
}

pub fn decode_channel(bytes: &[u8]) -> ChannelRecord {
    serde_json::from_slice(bytes).expect("failed to JSON-decode ChannelRecord")
}

/// Unwrap a stored record as a helper channel. The two record kinds live in
/// separate tables, so a mismatch means the row was written to the wrong one.
pub fn decode_helper(bytes: &[u8]) -> HelperChannel {
    match decode_channel(bytes) {
        ChannelRecord::Helper(h) => h,
        ChannelRecord::Replica(_) => panic!("replica member found in the helper channel table"),
    }
}

/// Unwrap a stored record as a replica-group member.
pub fn decode_member(bytes: &[u8]) -> ReplicaMember {
    match decode_channel(bytes) {
        ChannelRecord::Replica(m) => m,
        ChannelRecord::Helper(_) => panic!("helper channel found in the replica member table"),
    }
}

pub fn encode_secret_value(value: &SecretValue) -> Vec<u8> {
    let (tag, payload) = match value {
        SecretValue::SharedKey(key) => (SecretKind::SharedKey as u8, key.to_vec()),
        SecretValue::PairingSecret(material) => (
            SecretKind::PairingSecret as u8,
            material.as_bytes().to_vec(),
        ),
        SecretValue::PairingContact(contact) => {
            (SecretKind::PairingContact as u8, contact.encode_to_vec())
        }
    };
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(tag);
    out.extend_from_slice(&payload);
    out
}

pub fn decode_secret_value(bytes: &[u8]) -> SecretValue {
    let tag = bytes
        .first()
        .copied()
        .expect("SecretValue blob must carry the kind tag byte");
    let payload = &bytes[1..];
    match tag {
        t if t == SecretKind::SharedKey as u8 => {
            let key: [u8; 32] = payload
                .try_into()
                .expect("SharedKey blob must be 32 bytes after the tag byte");
            SecretValue::SharedKey(key)
        }
        t if t == SecretKind::PairingSecret as u8 => {
            SecretValue::PairingSecret(PairingKeyMaterial::from_bytes(payload.to_vec()))
        }
        t if t == SecretKind::PairingContact as u8 => {
            let contact =
                ContactMessage::decode(payload).expect("failed to prost-decode ContactMessage");
            SecretValue::PairingContact(contact)
        }
        other => panic!("unknown SecretValue tag byte: {other}"),
    }
}

pub fn secret_kind_tag(kind: SecretKind) -> i32 {
    kind as i32
}

#[derive(Clone, PartialEq, Message)]
struct UserSecretsPayload {
    #[prost(message, repeated, tag = "1")]
    pub secrets: Vec<UserSecret>,
}

pub fn encode_user_secrets_payload(secrets: &[UserSecret]) -> Vec<u8> {
    let wire = UserSecretsPayload {
        secrets: secrets.to_vec(),
    };
    wire.encode_to_vec()
}

pub fn decode_user_secrets_payload(bytes: &[u8]) -> Vec<UserSecret> {
    UserSecretsPayload::decode(bytes)
        .expect("failed to prost-decode UserSecrets payload")
        .secrets
}

pub fn assemble_user_secrets(
    version: u32,
    description: Option<String>,
    payload: Vec<u8>,
) -> UserSecrets {
    UserSecrets {
        version,
        description,
        secrets: decode_user_secrets_payload(&payload),
        replicas: None,
    }
}
