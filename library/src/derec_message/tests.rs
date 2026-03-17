use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::{
    derec_message::{
        DeRecMessageBuilder, DeRecMessageCodecError, DeRecMessageDecrypter, DeRecMessageEncrypter,
        DeRecMessageSigner, DeRecMessageVerifier, VerifiedPayload,
    },
    protocol_version::ProtocolVersion,
};
use derec_proto::{
    DeRecMessage, PairRequestMessage, PairResponseMessage, VerifyShareRequestMessage,
    de_rec_message::{HelperMessageBodies, SharerMessageBodies, message_bodies::Messages},
};
use prost_types::Timestamp;

fn sender_hash() -> Vec<u8> {
    vec![0x11; 48]
}

fn receiver_hash() -> Vec<u8> {
    vec![0x22; 48]
}

fn valid_secret_id() -> Vec<u8> {
    vec![1, 2, 3, 4]
}

fn owner_message() -> PairRequestMessage {
    PairRequestMessage::default()
}

fn helper_message() -> PairResponseMessage {
    PairResponseMessage::default()
}

#[derive(Clone)]
struct DummySigner {
    sender_key_hash: Vec<u8>,
    fail: bool,
}

impl DeRecMessageSigner for DummySigner {
    fn sender_key_hash(&self) -> &[u8] {
        &self.sender_key_hash
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        if self.fail {
            return Err(DeRecMessageCodecError::Signing(
                "dummy signer failure".to_string(),
            ));
        }

        let mut out = b"SIGNED:".to_vec();
        out.extend_from_slice(payload);
        Ok(out)
    }
}

#[derive(Clone)]
struct DummyVerifier {
    sender_key_hash: Vec<u8>,
    fail: bool,
}

impl DeRecMessageVerifier for DummyVerifier {
    fn verify(&self, signed_payload: &[u8]) -> Result<VerifiedPayload, DeRecMessageCodecError> {
        if self.fail {
            return Err(DeRecMessageCodecError::Verification(
                "dummy verifier failure".to_string(),
            ));
        }

        let payload = signed_payload.strip_prefix(b"SIGNED:").ok_or_else(|| {
            DeRecMessageCodecError::Verification("missing SIGNED prefix".to_string())
        })?;

        Ok(VerifiedPayload {
            payload: payload.to_vec(),
            signer_key_hash: self.sender_key_hash.clone(),
        })
    }
}

#[derive(Clone)]
struct DummyEncrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
    fail: bool,
}

impl DeRecMessageEncrypter for DummyEncrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn encrypt(&self, signed_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        if self.fail {
            return Err(DeRecMessageCodecError::Encryption(
                "dummy encrypter failure".to_string(),
            ));
        }

        let mut out = b"ENCRYPTED:".to_vec();
        out.extend_from_slice(signed_payload);
        Ok(out)
    }
}

#[derive(Clone)]
struct DummyDecrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
    fail: bool,
}

impl DeRecMessageDecrypter for DummyDecrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        if self.fail {
            return Err(DeRecMessageCodecError::Decryption(
                "dummy decrypter failure".to_string(),
            ));
        }

        let payload = encrypted_payload
            .strip_prefix(b"ENCRYPTED:")
            .ok_or_else(|| {
                DeRecMessageCodecError::Decryption("missing ENCRYPTED prefix".to_string())
            })?;

        Ok(payload.to_vec())
    }
}

fn dummy_signer() -> DummySigner {
    DummySigner {
        sender_key_hash: sender_hash(),
        fail: false,
    }
}

fn dummy_verifier() -> DummyVerifier {
    DummyVerifier {
        sender_key_hash: sender_hash(),
        fail: false,
    }
}

fn dummy_encrypter() -> DummyEncrypter {
    DummyEncrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_hash(),
        fail: false,
    }
}

fn dummy_decrypter() -> DummyDecrypter {
    DummyDecrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_hash(),
        fail: false,
    }
}

fn current_timestamp() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");

    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

fn build_owner_envelope() -> DeRecMessage {
    DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(owner_message())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap()
}

fn build_helper_envelope() -> DeRecMessage {
    DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(helper_message())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap()
}

#[test]
fn test_builder_new_sets_defaults() {
    let builder = DeRecMessageBuilder::new();

    assert!(builder.timestamp.is_none());
    assert!(builder.sender.is_none());
    assert!(builder.receiver.is_none());
    assert!(builder.secret_id.is_none());
    assert!(builder.side.is_none());
}

#[test]
fn test_builder_rejects_empty_secret_id() {
    let err = DeRecMessageBuilder::new()
        .secret_id(Vec::<u8>::new())
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::InvalidSecretIdLength(0));
}

#[test]
fn test_builder_rejects_secret_id_longer_than_16_bytes() {
    let err = DeRecMessageBuilder::new()
        .secret_id(vec![0u8; 17])
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::InvalidSecretIdLength(17));
}

#[test]
fn test_builder_accepts_valid_secret_id_lengths() {
    let _ = DeRecMessageBuilder::new().secret_id([1]).unwrap();
    let _ = DeRecMessageBuilder::new().secret_id([0u8; 16]).unwrap();
}

#[test]
fn test_builder_builds_owner_envelope() {
    let message = build_owner_envelope();

    let version = ProtocolVersion::current();

    assert_eq!(message.protocol_version_major, version.major);
    assert_eq!(message.protocol_version_minor, version.minor);
    assert_eq!(message.sender, sender_hash());
    assert_eq!(message.receiver, receiver_hash());
    assert_eq!(message.secret_id, valid_secret_id());
    assert!(message.timestamp.is_some());

    let bodies = message.message_bodies.expect("missing message bodies");
    match bodies.messages.expect("missing oneof") {
        Messages::SharerMessageBodies(SharerMessageBodies {
            sharer_message_body,
        }) => {
            assert_eq!(sharer_message_body.len(), 1);
        }
        _ => panic!("expected owner/sharer message bodies"),
    }
}

#[test]
fn test_builder_builds_helper_envelope() {
    let message = build_helper_envelope();

    let bodies = message.message_bodies.expect("missing message bodies");
    match bodies.messages.expect("missing oneof") {
        Messages::HelperMessageBodies(HelperMessageBodies {
            helper_message_body,
        }) => {
            assert_eq!(helper_message_body.len(), 1);
        }
        _ => panic!("expected helper message bodies"),
    }
}

#[test]
fn test_builder_supports_multiple_owner_messages() {
    let message = DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(PairRequestMessage::default())
        .unwrap()
        .message(VerifyShareRequestMessage::default())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap();

    let bodies = message.message_bodies.expect("missing message bodies");
    match bodies.messages.expect("missing oneof") {
        Messages::SharerMessageBodies(SharerMessageBodies {
            sharer_message_body,
        }) => {
            assert_eq!(sharer_message_body.len(), 2);
        }
        _ => panic!("expected owner/sharer message bodies"),
    }
}

#[test]
fn test_builder_rejects_mixed_message_sides() {
    let err = DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(PairRequestMessage::default())
        .unwrap()
        .timestamp(current_timestamp())
        .message(PairResponseMessage::default())
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::MixedMessageSides);
}

#[test]
fn test_builder_requires_sender() {
    let err = DeRecMessageBuilder::new()
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(owner_message())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::MissingSender);
}

#[test]
fn test_builder_requires_receiver() {
    let err = DeRecMessageBuilder::new()
        .sender(sender_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .message(owner_message())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::MissingReceiver);
}

#[test]
fn test_builder_requires_secret_id() {
    let err = DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .message(owner_message())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::MissingSecretId);
}

#[test]
fn test_builder_requires_message_bodies() {
    let err = DeRecMessageBuilder::new()
        .sender(sender_hash())
        .receiver(receiver_hash())
        .secret_id(valid_secret_id())
        .unwrap()
        .timestamp(current_timestamp())
        .build()
        .unwrap_err();

    assert_eq!(err, DeRecMessageBuilderError::MissingMessageBodies);
}

#[test]
fn test_wire_message_to_bytes_and_from_bytes_roundtrip() {
    let wire = WireMessage {
        recipient_key_id: 123,
        payload: vec![9, 8, 7, 6],
    };

    let encoded = wire.to_bytes();
    let decoded = WireMessage::from_bytes(&encoded).unwrap();

    assert_eq!(decoded, wire);
}

#[test]
fn test_wire_message_rejects_too_short_input() {
    let err = WireMessage::from_bytes(&[1, 2, 3]).unwrap_err();

    assert!(matches!(
        err,
        DeRecMessageCodecError::WireMessageTooShort(3)
    ));
}

#[test]
fn test_codec_encode_decode_roundtrip() {
    let message = build_owner_envelope();

    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    assert_eq!(wire.recipient_key_id, 7);
    assert!(!wire.payload.is_empty());

    let decoded = DeRecMessageCodec::decode(&wire, &dummy_decrypter(), &dummy_verifier()).unwrap();

    assert_eq!(decoded, message);
}

#[test]
fn test_codec_encode_to_bytes_and_decode_from_bytes_roundtrip() {
    let message = build_helper_envelope();

    let encoded =
        DeRecMessageCodec::encode_to_bytes(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let decoded =
        DeRecMessageCodec::decode_from_bytes(&encoded, &dummy_decrypter(), &dummy_verifier())
            .unwrap();

    assert_eq!(decoded, message);
}

#[test]
fn test_codec_encode_rejects_sender_hash_mismatch() {
    let mut message = build_owner_envelope();
    message.sender = vec![0x99; 48];

    let err = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap_err();

    assert!(matches!(err, DeRecMessageCodecError::SenderHashMismatch));
}

#[test]
fn test_codec_encode_rejects_receiver_hash_mismatch() {
    let mut message = build_owner_envelope();
    message.receiver = vec![0x88; 48];

    let err = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap_err();

    assert!(matches!(err, DeRecMessageCodecError::ReceiverHashMismatch));
}

#[test]
fn test_codec_decode_rejects_recipient_key_id_mismatch() {
    let message = build_owner_envelope();
    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let wrong_decrypter = DummyDecrypter {
        recipient_key_id: 999,
        recipient_key_hash: receiver_hash(),
        fail: false,
    };

    let err = DeRecMessageCodec::decode(&wire, &wrong_decrypter, &dummy_verifier()).unwrap_err();

    assert!(matches!(
        err,
        DeRecMessageCodecError::RecipientKeyIdMismatch {
            wire: 7,
            expected: 999
        }
    ));
}

#[test]
fn test_codec_decode_rejects_sender_hash_mismatch() {
    let message = build_owner_envelope();
    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let wrong_verifier = DummyVerifier {
        sender_key_hash: vec![0x77; 48],
        fail: false,
    };

    let err = DeRecMessageCodec::decode(&wire, &dummy_decrypter(), &wrong_verifier).unwrap_err();

    assert!(matches!(err, DeRecMessageCodecError::SenderHashMismatch));
}

#[test]
fn test_codec_decode_rejects_receiver_hash_mismatch() {
    let message = build_owner_envelope();
    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let wrong_decrypter = DummyDecrypter {
        recipient_key_id: 7,
        recipient_key_hash: vec![0x66; 48],
        fail: false,
    };

    let err = DeRecMessageCodec::decode(&wire, &wrong_decrypter, &dummy_verifier()).unwrap_err();

    assert!(matches!(err, DeRecMessageCodecError::ReceiverHashMismatch));
}

#[test]
fn test_codec_propagates_signing_failure() {
    let message = build_owner_envelope();

    let failing_signer = DummySigner {
        sender_key_hash: sender_hash(),
        fail: true,
    };

    let err = DeRecMessageCodec::encode(&message, &failing_signer, &dummy_encrypter()).unwrap_err();

    match err {
        DeRecMessageCodecError::Signing(msg) => {
            assert!(msg.contains("dummy signer failure"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn test_codec_propagates_encryption_failure() {
    let message = build_owner_envelope();

    let failing_encrypter = DummyEncrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_hash(),
        fail: true,
    };

    let err = DeRecMessageCodec::encode(&message, &dummy_signer(), &failing_encrypter).unwrap_err();

    match err {
        DeRecMessageCodecError::Encryption(msg) => {
            assert!(msg.contains("dummy encrypter failure"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn test_codec_propagates_decryption_failure() {
    let message = build_owner_envelope();
    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let failing_decrypter = DummyDecrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_hash(),
        fail: true,
    };

    let err = DeRecMessageCodec::decode(&wire, &failing_decrypter, &dummy_verifier()).unwrap_err();

    match err {
        DeRecMessageCodecError::Decryption(msg) => {
            assert!(msg.contains("dummy decrypter failure"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn test_codec_propagates_verification_failure() {
    let message = build_owner_envelope();
    let wire = DeRecMessageCodec::encode(&message, &dummy_signer(), &dummy_encrypter()).unwrap();

    let failing_verifier = DummyVerifier {
        sender_key_hash: sender_hash(),
        fail: true,
    };

    let err = DeRecMessageCodec::decode(&wire, &dummy_decrypter(), &failing_verifier).unwrap_err();

    match err {
        DeRecMessageCodecError::Verification(msg) => {
            assert!(msg.contains("dummy verifier failure"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
