//! Encode/decode helpers for the typed values the protocol hands to
//! the store traits. SQLite has no native concept of `SecretValue` or
//! `UserSecrets`, so every store column that holds a structured Rust
//! value passes through one of these functions.
//!
//! The encodings are deliberately not cryptographic — they exist only
//! to get typed values across the SQLite byte boundary and back.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_library::protocol::types::{Channel, UserSecret, UserSecrets};
use derec_library::protocol::{SecretKind, SecretValue};
use derec_proto::ContactMessage;
use prost::Message;

/// Channel ↔ bytes. The library already derives serde
/// `Serialize`/`Deserialize` on `Channel` for the JSON-over-FFI
/// bridges, so we reuse that representation rather than rolling a new
/// one.
pub fn encode_channel(channel: &Channel) -> Vec<u8> {
    serde_json::to_vec(channel).expect("failed to JSON-encode Channel")
}

pub fn decode_channel(bytes: &[u8]) -> Channel {
    serde_json::from_slice(bytes).expect("failed to JSON-decode Channel")
}

/// `SecretValue` ↔ bytes. The encoding is `[kind_tag, payload..]`
/// where `kind_tag` is the `SecretKind` discriminant (so the store
/// also gets cheap typed lookups via the `kind` column without
/// decoding the payload).
pub fn encode_secret_value(value: &SecretValue) -> Vec<u8> {
    let (tag, payload) = match value {
        SecretValue::SharedKey(key) => (SecretKind::SharedKey as u8, key.to_vec()),
        SecretValue::PairingSecret(material) => {
            let mut buf = Vec::with_capacity(material.compressed_size());
            material
                .serialize_compressed(&mut buf)
                .expect("ark serialization of PairingSecretKeyMaterial cannot fail");
            (SecretKind::PairingSecret as u8, buf)
        }
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
            let material = PairingSecretKeyMaterial::deserialize_compressed(payload)
                .expect("failed to ark-decode PairingSecretKeyMaterial");
            SecretValue::PairingSecret(material)
        }
        t if t == SecretKind::PairingContact as u8 => {
            let contact = ContactMessage::decode(payload)
                .expect("failed to prost-decode ContactMessage");
            SecretValue::PairingContact(contact)
        }
        other => panic!("unknown SecretValue tag byte: {other}"),
    }
}

pub fn secret_kind_tag(kind: SecretKind) -> i64 {
    kind as i64
}

/// Prost wrapper used to serialize `UserSecrets.secrets` as a single
/// blob column. Library's `UserSecrets` does not implement serde, and
/// `UserSecret` is already a prost message — wrapping it lets us
/// round-trip the whole `Vec<UserSecret>` in one shot.
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

/// Assemble a `UserSecrets` from the three columns we store it in.
pub fn assemble_user_secrets(
    version: u32,
    description: Option<String>,
    payload: Vec<u8>,
) -> UserSecrets {
    UserSecrets {
        version,
        description,
        secrets: decode_user_secrets_payload(&payload),
    }
}

/// `u64` ↔ `i64` round-trip. SQLite's INTEGER is signed 64-bit; the
/// cast preserves the bit pattern in both directions, so values with
/// the high bit set come back identical.
pub fn u64_to_sql(value: u64) -> i64 {
    value as i64
}

pub fn sql_to_u64(value: i64) -> u64 {
    value as u64
}
