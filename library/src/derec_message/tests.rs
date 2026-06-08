use super::*;
use crate::{
    derec_message::DeRecMessageBuilder, protocol_version::ProtocolVersion, types::ChannelId,
};
use derec_cryptography::pairing::pairing_ecies;
use derec_proto::{MessageBody, PairRequestMessage};
use prost::Message;
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
    assert!(builder.message.is_none());
    assert!(builder.trace_id.is_none());
}

#[test]
fn test_channel_builder_new_sets_defaults() {
    let builder = DeRecMessageBuilder::channel();

    assert!(builder.sequence.is_none());
    assert!(builder.channel_id.is_none());
    assert!(builder.timestamp.is_none());
    assert!(builder.message.is_none());
    assert!(builder.trace_id.is_none());
}

#[test]
fn test_channel_id_sequence_timestamp_and_message_set_fields() {
    let inner = sample_message();
    let timestamp = current_timestamp();

    let builder = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .sequence(SEQUENCE)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(inner.clone()));

    assert_eq!(builder.channel_id, Some(CHANNEL_ID));
    assert_eq!(builder.sequence, Some(SEQUENCE));
    assert_eq!(builder.timestamp, Some(timestamp));
    assert!(
        matches!(builder.message, Some(MessageBody::PairRequest(inner_message)) if inner_message == inner),
    );
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
        .message_body(MessageBody::PairRequest(sample_message()))
        .encrypt(&SHARED_KEY)
        .unwrap_err();

    assert!(matches!(err, DeRecMessageBuilderError::MissingChannelId));
}

#[test]
fn test_pairing_build_rejects_missing_timestamp() {
    let (_sk, pk) = pairing_keypair();

    let err = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .message_body(MessageBody::PairRequest(sample_message()))
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
        .message_body(MessageBody::PairRequest(sample_message()))
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
        .message_body(MessageBody::PairRequest(sample_message()))
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
        .message_body(MessageBody::PairRequest(sample_message()))
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
        .message_body(MessageBody::PairRequest(inner))
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
        .message_body(MessageBody::PairRequest(inner))
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
        .message_body(MessageBody::PairRequest(sample_message()))
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
    let first = PairRequestMessage {
        nonce: 1,
        ..Default::default()
    };
    let second = PairRequestMessage {
        nonce: 2,
        ..Default::default()
    };

    let builder = DeRecMessageBuilder::pairing()
        .message_body(MessageBody::PairRequest(first))
        .message_body(MessageBody::PairRequest(second.clone()));

    assert!(
        matches!(builder.message, Some(MessageBody::PairRequest(inner_message)) if inner_message == second),
    );
}

#[test]
fn test_trace_id_is_propagated_through_pairing_build() {
    let (_sk, pk) = pairing_keypair();
    let timestamp = current_timestamp();

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(sample_message()))
        .trace_id(0xCAFEBABE_DEADBEEF)
        .encrypt_pairing(&pk)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed");

    assert_eq!(envelope.trace_id, 0xCAFEBABE_DEADBEEF);
}

#[test]
fn test_trace_id_is_propagated_through_channel_build() {
    let timestamp = current_timestamp();

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(CHANNEL_ID)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(sample_message()))
        .trace_id(0x0102_0304_0506_0708)
        .encrypt(&SHARED_KEY)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed");

    assert_eq!(envelope.trace_id, 0x0102_0304_0506_0708);
}

#[test]
fn test_auto_trace_id_produces_non_zero_value() {
    let timestamp = current_timestamp();
    let (_sk, pk) = pairing_keypair();

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(sample_message()))
        .auto_trace_id()
        .encrypt_pairing(&pk)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed");

    // The probability of `rand::rng().next_u64()` rolling exactly zero is
    // 2^-64; the test would have to be re-rolled on the order of the heat
    // death of the universe to legitimately observe it.
    assert_ne!(envelope.trace_id, 0);
}

#[test]
fn test_trace_id_defaults_to_zero_when_unset() {
    let (_sk, pk) = pairing_keypair();
    let timestamp = current_timestamp();

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(sample_message()))
        .encrypt_pairing(&pk)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed");

    assert_eq!(envelope.trace_id, 0);
}

#[test]
fn test_trace_id_round_trips_through_proto_encoding() {
    let (_sk, pk) = pairing_keypair();
    let timestamp = current_timestamp();

    let original = DeRecMessageBuilder::pairing()
        .channel_id(CHANNEL_ID)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(sample_message()))
        .trace_id(0xFEED_FACE_BAAD_F00D)
        .encrypt_pairing(&pk)
        .expect("encrypt should succeed")
        .build()
        .expect("build should succeed");

    let wire_bytes = original.encode_to_vec();
    let decoded = derec_proto::DeRecMessage::decode(wire_bytes.as_slice())
        .expect("envelope should decode");

    assert_eq!(decoded.trace_id, 0xFEED_FACE_BAAD_F00D);
}

#[test]
fn test_extract_inner_plaintext_message_round_trips() {
    let inner = sample_message();
    let encoded = MessageBody::PairRequest(inner.clone()).encode_to_vec();

    let decoded = extract_inner_plaintext_message(&encoded)
        .expect("extract_inner_plaintext_message should succeed");

    assert!(
        matches!(decoded, MessageBody::PairRequest(m) if m == inner),
        "plaintext extract must round-trip the inner MessageBody"
    );
}

#[test]
fn test_extract_inner_plaintext_message_rejects_garbage() {
    let err = extract_inner_plaintext_message(b"not a valid protobuf")
        .expect_err("garbage bytes must not decode as a MessageBody");

    assert!(matches!(err, crate::Error::ProtobufDecode(_)));
}
