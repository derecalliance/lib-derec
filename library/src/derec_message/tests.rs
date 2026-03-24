use super::*;
use crate::{
    derec_message::DeRecMessageBuilder, protocol_version::ProtocolVersion, types::ChannelId,
};
use derec_cryptography::pairing::pairing_ecies;
use derec_proto::PairRequestMessage;
use rand08::thread_rng;

const CHANNEL_ID: ChannelId = ChannelId(42);
const SEQUENCE: u32 = 7;
const SHARED_KEY: [u8; 32] = [0xAB; 32];

fn pairing_keypair() -> (Vec<u8>, Vec<u8>) {
    pairing_ecies::generate_key(&mut thread_rng()).unwrap()
}

fn sample_message() -> PairRequestMessage {
    PairRequestMessage::default()
}

#[test]
fn test_pairing_builder_new_sets_defaults() {
    let builder = DeRecMessageBuilder::pairing();

    assert!(builder.sequence.is_none());
    assert!(builder.channel_id.is_none());
    assert!(builder.timestamp.is_none());
    assert!(builder.message.is_empty());
}

#[test]
fn test_channel_builder_new_sets_defaults() {
    let builder = DeRecMessageBuilder::channel();

    assert!(builder.sequence.is_none());
    assert!(builder.channel_id.is_none());
    assert!(builder.timestamp.is_none());
    assert!(builder.message.is_empty());
}

#[test]
fn test_channel_id_sequence_timestamp_and_message_set_fields() {
    let inner = sample_message();
    let encoded = inner.encode_to_vec();
    let timestamp = current_timestamp();

    let builder = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .sequence(SEQUENCE)
        .timestamp(timestamp)
        .message(&inner);

    assert_eq!(builder.channel_id, Some(CHANNEL_ID));
    assert_eq!(builder.sequence, Some(SEQUENCE));
    assert_eq!(builder.timestamp, Some(timestamp));
    assert_eq!(builder.message, encoded);
}

#[test]
fn test_pairing_encrypt_rejects_missing_message() {
    let (_sk, pk) = pairing_keypair();

    let err = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(current_timestamp())
        .encrypt_pairing(&pk)
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingMessage));
}

#[test]
fn test_channel_encrypt_rejects_missing_message() {
    let err = DeRecMessageBuilder::channel()
        .channel_id(CHANNEL_ID)
        .timestamp(current_timestamp())
        .encrypt(&SHARED_KEY)
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingMessage));
}

#[test]
fn test_channel_encrypt_rejects_missing_channel_id() {
    let err = DeRecMessageBuilder::channel()
        .timestamp(current_timestamp())
        .message(&sample_message())
        .encrypt(&SHARED_KEY)
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingChannelId));
}

#[test]
fn test_pairing_build_rejects_missing_timestamp() {
    let (_sk, pk) = pairing_keypair();

    let err = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .message(&sample_message())
        .encrypt_pairing(&pk)
        .unwrap()
        .build()
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingTimestamp));
}

#[test]
fn test_pairing_build_rejects_missing_channel_id() {
    let (_sk, pk) = pairing_keypair();

    let err = DeRecMessageBuilder::pairing()
        .timestamp(current_timestamp())
        .message(&sample_message())
        .encrypt_pairing(&pk)
        .unwrap()
        .build()
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingChannelId));
}

#[test]
fn test_channel_build_rejects_missing_timestamp() {
    let err = DeRecMessageBuilder::channel()
        .channel_id(CHANNEL_ID)
        .message(&sample_message())
        .encrypt(&SHARED_KEY)
        .unwrap()
        .build()
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingTimestamp));
}

#[test]
fn test_channel_build_rejects_missing_channel_id_after_encrypt_is_impossible_but_checked_before() {
    let err = DeRecMessageBuilder::channel()
        .timestamp(current_timestamp())
        .message(&sample_message())
        .encrypt(&SHARED_KEY)
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingChannelId));
}

#[test]
fn test_pairing_encrypt_and_build_succeeds() {
    let (_sk, pk) = pairing_keypair();
    let inner = sample_message();
    let plaintext = inner.encode_to_vec();
    let timestamp = current_timestamp();

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .sequence(SEQUENCE)
        .timestamp(timestamp)
        .message(&inner)
        .encrypt_pairing(&pk)
        .unwrap()
        .build()
        .unwrap();

    let version = ProtocolVersion::current();

    assert_eq!(envelope.protocol_version_major, version.major);
    assert_eq!(envelope.protocol_version_minor, version.minor);
    assert_eq!(envelope.sequence, SEQUENCE);
    assert_eq!(envelope.channel_id, u64::from(CHANNEL_ID));
    assert_eq!(envelope.timestamp, Some(timestamp));
    assert!(!envelope.message.is_empty());
    assert_ne!(envelope.message, plaintext);
}

#[test]
fn test_channel_encrypt_and_build_succeeds() {
    let inner = sample_message();
    let plaintext = inner.encode_to_vec();
    let timestamp = current_timestamp();

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(CHANNEL_ID)
        .sequence(SEQUENCE)
        .timestamp(timestamp)
        .message(&inner)
        .encrypt(&SHARED_KEY)
        .unwrap()
        .build()
        .unwrap();

    let version = ProtocolVersion::current();

    assert_eq!(envelope.protocol_version_major, version.major);
    assert_eq!(envelope.protocol_version_minor, version.minor);
    assert_eq!(envelope.sequence, SEQUENCE);
    assert_eq!(envelope.channel_id, u64::from(CHANNEL_ID));
    assert_eq!(envelope.timestamp, Some(timestamp));
    assert!(!envelope.message.is_empty());
    assert_ne!(envelope.message, plaintext);
}

#[test]
fn test_build_defaults_sequence_to_zero_when_not_set() {
    let (_sk, pk) = pairing_keypair();

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(current_timestamp())
        .message(&sample_message())
        .encrypt_pairing(&pk)
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(envelope.sequence, 0);
}

#[test]
fn test_current_timestamp_returns_valid_range() {
    let ts = current_timestamp();

    assert!(ts.seconds >= 0);
    assert!((0..1_000_000_000).contains(&ts.nanos));
}

#[test]
fn test_message_overwrites_previous_payload() {
    let first = PairRequestMessage::default();
    let second = PairRequestMessage::default();

    let first_encoded = first.encode_to_vec();
    let second_encoded = second.encode_to_vec();

    let builder = DeRecMessageBuilder::pairing()
        .message(&first)
        .message(&second);

    assert_ne!(first_encoded.len(), 0);
    assert_eq!(builder.message, second_encoded);
}
