// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::Error;
use crate::derec_message::current_timestamp;
use crate::primitives::pairing::PairingError;
use crate::primitives::pairing::{
    request::{
        CreateContactResult as CreateContactMessageResult,
        ExtractResult as ExtractPairingRequestResult, PrePairExtractResult, ProducePrePairResult,
        ProduceResult as ProducePairingRequestMessageResult,
        create_contact as create_contact_message, extract as extract_pairing_request,
        extract_pre_pair, produce as produce_pairing_request_message, produce_pre_pair_request,
    },
    response::{
        ExtractResult as ExtractPairingResponseResult,
        PrePairExtractResult as PrePairResponseExtractResult, ProcessPrePairResult,
        ProcessResult as ProcessPairingResponseMessageResult,
        ProducePrePairResult as ProducePrePairResponseResult,
        ProduceResult as ProducePairingResponseMessageResult, extract as extract_pairing_response,
        extract_pre_pair as extract_pre_pair_response, process as process_pairing_response_message,
        process_pre_pair, produce as produce_pairing_response_message, produce_pre_pair,
        produce_pre_pair_no_keys,
    },
};

fn test_policy() -> crate::transport::TransportPolicy {
    crate::transport::TransportPolicy::new(true)
}
use crate::types::ChannelId;
use derec_proto::{
    ContactMessage, ContactMode, DeRecMessage, DeRecResult, MessageBody, PairRequestMessage,
    PairResponseMessage, PrePairResponseMessage, Protocol, SenderKind, StatusEnum,
    TransportProtocol,
};
use prost::Message;

fn decode_outer_envelope(bytes: &[u8]) -> DeRecMessage {
    DeRecMessage::decode(bytes).expect("outer DeRecMessage should decode")
}

fn mismatch_envelope_timestamp(wire_bytes: &[u8]) -> Vec<u8> {
    let mut envelope = decode_outer_envelope(wire_bytes);
    let mut ts = envelope
        .timestamp
        .expect("envelope timestamp should be present");
    ts.seconds += 1;
    envelope.timestamp = Some(ts);
    envelope.encode_to_vec()
}

#[test]
fn test_create_contact_message_empty_transport_uri() {
    let result = create_contact_message(
        ChannelId(42),
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        }],
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_create_contact_message() {
    let channel_id = ChannelId(42);
    let transport_uri = "https://relay.example/alice";

    let CreateContactMessageResult {
        contact_message: contact_msg,
        ..
    } = create_contact_message(
        channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    assert_eq!(contact_msg.channel_id, u64::from(channel_id));

    let transport = contact_msg
        .transport_protocol
        .expect("transport protocol should be present");

    assert_eq!(transport.uri, transport_uri);
    assert_eq!(transport.protocol, Protocol::Https as i32);
    assert!(contact_msg.timestamp.is_some());
    assert!(
        contact_msg
            .mlkem_encapsulation_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        contact_msg
            .ecies_public_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_request_message_empty_mlkem_encapsulation_key() {
    let invalid_contact_msg = ContactMessage {
        channel_id: ChannelId(42).into(),
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        contact_mode: derec_proto::ContactMode::InlineKeys as i32,
        mlkem_encapsulation_key: Some(Vec::new()),
        ecies_public_key: Some(vec![1; 33]),
        contact_binding_hash: None,
        nonce: 1234,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &invalid_contact_msg,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "inline_keys contact missing mlkem_encapsulation_key"
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_request_message_empty_ecies_public_key() {
    let invalid_contact_msg = ContactMessage {
        channel_id: ChannelId(42).into(),
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        contact_mode: derec_proto::ContactMode::InlineKeys as i32,
        mlkem_encapsulation_key: Some(vec![1; 32]),
        ecies_public_key: Some(Vec::new()),
        contact_binding_hash: None,
        nonce: 1234,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &invalid_contact_msg,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "inline_keys contact missing ecies_public_key"
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_request_message_empty_transport_uri() {
    let invalid_contact_msg = ContactMessage {
        channel_id: ChannelId(42).into(),
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        contact_mode: derec_proto::ContactMode::InlineKeys as i32,
        contact_binding_hash: None,
        mlkem_encapsulation_key: Some(vec![1; 32]),
        ecies_public_key: Some(vec![1; 33]),
        nonce: 1234,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        }],
        &invalid_contact_msg,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_request_message() {
    let channel_id = ChannelId(42);
    let alice_transport_uri = "https://relay.example/alice";
    let bob_transport_uri = "https://relay.example/bob";

    let CreateContactMessageResult {
        contact_message,
        secret_key: alice_sk_state,
    } = create_contact_message(
        channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult { envelope, .. } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &contact_message,
        None,
        None,
    )
    .expect("failed to produce pairing request message");

    let ExtractPairingRequestResult {
        request: pair_request_message,
    } = extract_pairing_request(
        &envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let envelope_decoded = decode_outer_envelope(&envelope);
    assert_eq!(envelope_decoded.timestamp, pair_request_message.timestamp);
    assert_eq!(envelope_decoded.channel_id, u64::from(channel_id));
    assert_eq!(pair_request_message.nonce, contact_message.nonce);

    let transport = pair_request_message
        .transport_protocol
        .expect("transport protocol should be present");

    assert_eq!(transport.uri, bob_transport_uri);
    assert_eq!(transport.protocol, Protocol::Https as i32);
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_request_message_initiator_contact_message() {
    let alice_transport_uri = "https://relay.example/alice";

    let CreateContactMessageResult {
        contact_message, ..
    } = create_contact_message(
        ChannelId(42),
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        initiator_contact_message,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &contact_message,
        None,
        None,
    )
    .expect("failed to produce pairing request message");

    let tp = initiator_contact_message
        .transport_protocol
        .expect("transport protocol should be present");
    assert_eq!(tp.uri, alice_transport_uri);
    assert_eq!(tp.protocol, Protocol::Https as i32);
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_response_message_empty_mlkem_ciphertext() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: Vec::new(),
        ecies_public_key: vec![2; 33],
        nonce: 1234,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error)))
            if error == "mlkem_ciphertext is empty"
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_response_message_empty_ecies_public_key() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: Vec::new(),
        nonce: 1234,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error)))
            if error == "ecies_public_key is empty"
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_response_message_missing_transport_protocol() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        nonce: 1234,
        communication_info: None,
        parameter_range: None,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pairing_response_message_empty_transport_uri() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        nonce: 1234,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "   ".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_extract_pairing_request_rejects_envelope_timestamp_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult { envelope, .. } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let tampered_bytes = mismatch_envelope_timestamp(&envelope);

    let result = extract_pairing_request(
        &tampered_bytes,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    );

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_process_pairing_response_message_missing_result() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: None,
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairResponseMessage(error)))
            if error == "missing result"
    ));
}

#[test]
fn test_process_pairing_response_message_result_non_ok() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Fail as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::NonOkStatus { status, .. }))
            if status == StatusEnum::Fail as i32
    ));
}

#[test]
fn test_process_pairing_response_message_invalid_status() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: Some(DeRecResult {
            status: 15,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::NonOkStatus { status, .. }))
            if status == 15
    ));
}

#[test]
fn test_process_pairing_response_message_nonce_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce + 1,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::ProtocolViolation(error)))
            if error == "nonce mismatch"
    ));
}

#[test]
fn test_process_pairing_response_message_empty_mlkem_encapsulation_key() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.mlkem_encapsulation_key = Some(Vec::new());

    let result =
        process_pairing_response_message(&invalid_contact, &pair_response_msg, &bob_sk_state);

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "mlkem_encapsulation_key is empty"
    ));
}

#[test]
fn test_process_pairing_response_message_empty_ecies_public_key() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
        channel_id: 0,
    };

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.ecies_public_key = Some(Vec::new());

    let result =
        process_pairing_response_message(&invalid_contact, &pair_response_msg, &bob_sk_state);

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "ecies_public_key is empty"
    ));
}

#[test]
fn test_extract_pairing_response_rejects_envelope_timestamp_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: initiator_secret_key,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: request_envelope,
        secret_key: responder_secret_key,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce pairing request");

    let ExtractPairingRequestResult { request } = extract_pairing_request(
        &request_envelope,
        initiator_secret_key.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_pairing_response_message(
        ChannelId(42),
        &request,
        initiator_secret_key.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    )
    .expect("failed to produce pairing response");

    let tampered_bytes = mismatch_envelope_timestamp(&response_envelope);

    let result = extract_pairing_response(&tampered_bytes, responder_secret_key.ecies_secret_key());

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_alice_bob_pairing_flow() {
    let alice_channel_id = ChannelId(42);
    let alice_transport_uri = "https://relay.example/alice";
    let bob_transport_uri = "https://relay.example/bob";

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce pairing request");

    let contact_nonce = initiator_contact_message.nonce;

    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(
        &bob_pair_req_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        shared_key: alice_shared_key,
        peer_transports: bob_transport_protocol,
        channel_id: alice_new_channel_id,
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    )
    .expect("failed to produce pairing response");

    let ExtractPairingResponseResult {
        response: alice_pair_resp_msg,
    } = extract_pairing_response(&alice_pair_resp_envelope, bob_sk_state.ecies_secret_key())
        .expect("failed to extract pairing response");

    let ProcessPairingResponseMessageResult {
        shared_key: bob_shared_key,
        channel_id: bob_new_channel_id,
    } = process_pairing_response_message(
        &initiator_contact_message,
        &alice_pair_resp_msg,
        &bob_sk_state,
    )
    .expect("failed to process pairing response");

    assert_eq!(
        decode_outer_envelope(&bob_pair_req_envelope).timestamp,
        bob_pair_req_msg.timestamp
    );
    assert_eq!(
        decode_outer_envelope(&alice_pair_resp_envelope).timestamp,
        alice_pair_resp_msg.timestamp
    );
    assert_eq!(contact_nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_pair_resp_msg.nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_shared_key, bob_shared_key);
    assert_eq!(bob_transport_protocol[0].uri, bob_transport_uri);
    assert_eq!(bob_transport_protocol[0].protocol, Protocol::Https as i32);
    assert_eq!(alice_new_channel_id, bob_new_channel_id);
    assert_ne!(alice_new_channel_id, alice_channel_id);
    assert_eq!(
        alice_pair_resp_msg.channel_id,
        u64::from(alice_new_channel_id)
    );
}

#[test]
fn test_produce_pairing_response_returns_envelope_and_peer_transport() {
    let alice_channel_id = ChannelId(42);
    let bob_transport_uri = "https://relay.example/bob";

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        secret_key: bob_sk_state,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(
        &bob_request_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope,
        shared_key,
        peer_transports,
        channel_id: _,
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_request_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    )
    .expect("accept should succeed");

    assert!(!envelope.is_empty());
    assert_eq!(peer_transports[0].uri, bob_transport_uri);
    assert_eq!(peer_transports[0].protocol, Protocol::Https as i32);

    let ExtractPairingResponseResult { response } =
        extract_pairing_response(&envelope, bob_sk_state.ecies_secret_key())
            .expect("failed to extract pairing response");

    let result = response.result.expect("response should carry a result");
    assert_eq!(result.status, StatusEnum::Ok as i32);
    assert!(result.memo.is_empty());
    assert_eq!(response.nonce, bob_pair_request_msg.nonce);
    let _ = shared_key;
}

fn make_hashed_keys_contact(channel_id: ChannelId) -> ContactMessage {
    create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create HASHED_KEYS contact message")
    .contact_message
}

#[test]
fn test_create_contact_message_hashed_keys_omits_keys_and_carries_binding_hash() {
    let channel_id = ChannelId(42);
    let contact = make_hashed_keys_contact(channel_id);

    assert_eq!(contact.channel_id, u64::from(channel_id));
    assert_eq!(contact.contact_mode, ContactMode::HashedKeys as i32);

    assert!(contact.mlkem_encapsulation_key.is_none());
    assert!(contact.ecies_public_key.is_none());

    let hash = contact
        .contact_binding_hash
        .as_ref()
        .expect("contact_binding_hash should be present");
    assert_eq!(hash.len(), 48, "SHA-384 produces 48-byte digests");
}

#[test]
fn test_create_contact_message_hashed_keys_empty_transport_uri() {
    let result = create_contact_message(
        ChannelId(42),
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        }],
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_create_contact_message_hashed_keys_fresh_randomness_yields_distinct_hashes() {
    let a = make_hashed_keys_contact(ChannelId(42));
    let b = make_hashed_keys_contact(ChannelId(42));
    assert_ne!(a.contact_binding_hash, b.contact_binding_hash);
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pre_pair_request_emits_envelope_routed_to_contact_channel() {
    let channel_id = ChannelId(42);
    let alice_contact = make_hashed_keys_contact(channel_id);

    let bob_transport = TransportProtocol {
        uri: "https://relay.example/bob".to_owned(),
        protocol: Protocol::Https.into(),
    };

    let ProducePrePairResult { envelope } =
        produce_pre_pair_request(vec![bob_transport.clone()], &alice_contact)
            .expect("produce_pre_pair_request should succeed");

    let outer = decode_outer_envelope(&envelope);
    assert_eq!(outer.channel_id, u64::from(channel_id));
    let envelope_ts = outer.timestamp.expect("envelope timestamp must be present");

    let inner = match MessageBody::decode_from_vec(outer.message.as_slice())
        .expect("inner MessageBody should decode")
    {
        MessageBody::PrePairRequest(r) => r,
        other => panic!("expected PrePairRequest, got {other:?}"),
    };
    assert_eq!(inner.nonce, alice_contact.nonce);
    let inner_transport = inner
        .transport_protocol
        .as_ref()
        .expect("transport_protocol should be present");
    assert_eq!(inner_transport.uri, bob_transport.uri);
    assert_eq!(inner_transport.protocol, bob_transport.protocol);
    assert_eq!(inner.timestamp.as_ref(), Some(&envelope_ts));
}

#[test]
fn test_produce_pre_pair_request_rejects_inline_keys_contact() {
    let alice_contact = create_contact_message(
        ChannelId(42),
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message")
    .contact_message;

    let result = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(_)))
    ));
}

#[test]
fn test_produce_pre_pair_request_rejects_empty_transport_uri() {
    let alice_contact = make_hashed_keys_contact(ChannelId(42));

    let result = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "   ".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_extract_pre_pair_roundtrip() {
    let alice_contact = make_hashed_keys_contact(ChannelId(42));

    let bob_transport = TransportProtocol {
        uri: "https://relay.example/bob".to_owned(),
        protocol: Protocol::Https.into(),
    };

    let ProducePrePairResult { envelope } =
        produce_pre_pair_request(vec![bob_transport.clone()], &alice_contact)
            .expect("produce_pre_pair_request should succeed");

    let PrePairExtractResult { request } =
        extract_pre_pair(&envelope).expect("extract_pre_pair should succeed");

    assert_eq!(request.nonce, alice_contact.nonce);
    let transport = request
        .transport_protocol
        .as_ref()
        .expect("transport_protocol should be present");
    assert_eq!(transport.uri, bob_transport.uri);
    assert_eq!(transport.protocol, bob_transport.protocol);
    assert!(request.timestamp.is_some());
}

#[test]
fn test_extract_pre_pair_rejects_envelope_timestamp_mismatch() {
    let alice_contact = make_hashed_keys_contact(ChannelId(42));

    let ProducePrePairResult { envelope } = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    )
    .expect("produce_pre_pair_request should succeed");

    let tampered = mismatch_envelope_timestamp(&envelope);
    let result = extract_pre_pair(&tampered);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_extract_pre_pair_rejects_garbage_bytes() {
    let result = extract_pre_pair(&[0xff, 0xfe, 0xfd, 0xfc]);
    assert!(matches!(result, Err(Error::ProtobufDecode(_))));
}

#[test]
fn test_extract_pre_pair_rejects_wrong_inner_message_type() {
    let timestamp = current_timestamp();
    let body = MessageBody::PairResponse(PairResponseMessage::default()).encode_to_vec();
    let envelope = DeRecMessage {
        protocol_version_major: 0,
        protocol_version_minor: 0,
        sequence: 0,
        channel_id: 42,
        timestamp: Some(timestamp),
        message: body,
        trace_id: 0,
    }
    .encode_to_vec();

    let result = extract_pre_pair(&envelope);
    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_produce_pre_pair_emits_envelope_carrying_initiator_public_keys() {
    let channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create HASHED_KEYS contact");

    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    )
    .expect("produce_pre_pair_request should succeed");
    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair should succeed");

    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(
        channel_id,
        &pre_pair_request,
        alice_secret.as_ref().unwrap(),
    )
    .expect("produce_pre_pair should succeed");

    let outer = decode_outer_envelope(&response_envelope);
    assert_eq!(outer.channel_id, u64::from(channel_id));
    let envelope_ts = outer.timestamp.expect("envelope timestamp must be present");

    let inner = match MessageBody::decode_from_vec(outer.message.as_slice())
        .expect("inner MessageBody should decode")
    {
        MessageBody::PrePairResponse(r) => r,
        other => panic!("expected PrePairResponse, got {other:?}"),
    };
    let result = inner.result.as_ref().expect("result must be present");
    assert_eq!(result.status, StatusEnum::Ok as i32);
    assert!(result.memo.is_empty());
    assert_eq!(inner.nonce, pre_pair_request.nonce);
    assert_eq!(inner.timestamp.as_ref(), Some(&envelope_ts));
    assert!(
        inner
            .mlkem_encapsulation_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        inner
            .ecies_public_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pre_pair_rejects_responder_secret_key_material() {
    let channel_id = ChannelId(42);

    let alice_contact = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact")
    .contact_message;

    let ProducePairingRequestMessageResult {
        secret_key: bob_secret,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("produce_pairing_request_message should succeed");

    let dummy_request = derec_proto::PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 1234,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pre_pair(channel_id, &dummy_request, &bob_secret);

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::Invariant(_)))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
#[test]
fn test_produce_pre_pair_response_keys_match_initiator_contact_keys_in_inline_mode() {
    let channel_id = ChannelId(42);
    let CreateContactMessageResult {
        contact_message: inline_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact");

    let dummy_request = derec_proto::PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 7,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    let ProducePrePairResponseResult { envelope } =
        produce_pre_pair(channel_id, &dummy_request, alice_secret.as_ref().unwrap())
            .expect("produce_pre_pair should succeed");
    let outer = decode_outer_envelope(&envelope);
    let response: PrePairResponseMessage =
        match MessageBody::decode_from_vec(&outer.message).expect("decode inner") {
            MessageBody::PrePairResponse(r) => r,
            _ => panic!("expected PrePairResponse"),
        };

    assert_eq!(
        response.mlkem_encapsulation_key.as_ref(),
        inline_contact.mlkem_encapsulation_key.as_ref(),
        "republished ML-KEM key must equal the one in the inline contact"
    );
    assert_eq!(
        response.ecies_public_key.as_ref(),
        inline_contact.ecies_public_key.as_ref(),
        "republished ECIES key must equal the one in the inline contact"
    );
}

/// Convenience: run the full HASHED_KEYS PrePair leg and return the
/// envelope Bob sees on the wire from Alice along with the keys Alice
/// retained internally (so tests can cross-check what was republished).
fn build_pre_pair_response_envelope(
    channel_id: ChannelId,
) -> (Vec<u8>, ContactMessage, derec_proto::PrePairRequestMessage) {
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("create_contact (HASHED_KEYS) failed");

    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");

    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair (request) failed");

    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(
        channel_id,
        &pre_pair_request,
        alice_secret.as_ref().unwrap(),
    )
    .expect("produce_pre_pair failed");

    (response_envelope, alice_contact, pre_pair_request)
}

#[test]
fn test_extract_pre_pair_response_roundtrip() {
    let channel_id = ChannelId(42);
    let (response_envelope, _alice_contact, pre_pair_request) =
        build_pre_pair_response_envelope(channel_id);

    let PrePairResponseExtractResult { response } =
        extract_pre_pair_response(&response_envelope).expect("extract_pre_pair_response failed");

    let result = response
        .result
        .as_ref()
        .expect("PrePairResponse must carry a result");
    assert_eq!(result.status, StatusEnum::Ok as i32);
    assert!(result.memo.is_empty());

    assert_eq!(response.nonce, pre_pair_request.nonce);
    assert!(
        response
            .mlkem_encapsulation_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(
        response
            .ecies_public_key
            .as_ref()
            .is_some_and(|v| !v.is_empty())
    );
    assert!(response.timestamp.is_some());
}

#[test]
fn test_extract_pre_pair_response_rejects_envelope_timestamp_mismatch() {
    let (response_envelope, _, _) = build_pre_pair_response_envelope(ChannelId(42));

    let tampered = mismatch_envelope_timestamp(&response_envelope);
    let result = extract_pre_pair_response(&tampered);

    assert!(matches!(result, Err(Error::Invariant(_))));
}

#[test]
fn test_extract_pre_pair_response_rejects_garbage_bytes() {
    let result = extract_pre_pair_response(&[0xff, 0xfe, 0xfd, 0xfc]);
    assert!(matches!(result, Err(Error::ProtobufDecode(_))));
}

#[test]
fn test_extract_pre_pair_response_rejects_wrong_inner_message_type() {
    let timestamp = current_timestamp();
    let body = MessageBody::PairRequest(PairRequestMessage::default()).encode_to_vec();
    let envelope = DeRecMessage {
        protocol_version_major: 0,
        protocol_version_minor: 0,
        sequence: 0,
        channel_id: 42,
        timestamp: Some(timestamp),
        message: body,
        trace_id: 0,
    }
    .encode_to_vec();

    let result = extract_pre_pair_response(&envelope);
    assert!(matches!(result, Err(Error::Invariant(_))));
}

/// Convenience: run the full HASHED_KEYS PrePair leg and return the artifacts
/// the scanner side has to call `process_pre_pair` on.
fn run_pre_pair_leg(channel_id: ChannelId) -> (ContactMessage, PrePairResponseMessage) {
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("create_contact (HASHED_KEYS) failed");

    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");

    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair (request) failed");

    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(
        channel_id,
        &pre_pair_request,
        alice_secret.as_ref().unwrap(),
    )
    .expect("produce_pre_pair failed");

    let PrePairResponseExtractResult { response } =
        extract_pre_pair_response(&response_envelope).expect("extract_pre_pair_response failed");

    (alice_contact, response)
}

#[test]
fn test_process_pre_pair_returns_keys_and_nonce_on_valid_response() {
    let (contact, response) = run_pre_pair_leg(ChannelId(42));

    let ProcessPrePairResult {
        mlkem_encapsulation_key,
        ecies_public_key,
        nonce,
    } = process_pre_pair(&contact, &response).expect("process_pre_pair should succeed");

    assert_eq!(
        Some(&mlkem_encapsulation_key),
        response.mlkem_encapsulation_key.as_ref()
    );
    assert_eq!(Some(&ecies_public_key), response.ecies_public_key.as_ref());
    assert_eq!(nonce, contact.nonce);
}

#[test]
fn test_process_pre_pair_rejects_tampered_mlkem_key() {
    let (contact, mut response) = run_pre_pair_leg(ChannelId(42));

    let mut tampered = response.mlkem_encapsulation_key.clone().unwrap();
    tampered[0] ^= 0xff;
    response.mlkem_encapsulation_key = Some(tampered);

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::PrePairHashMismatch))
    ));
}

#[test]
fn test_process_pre_pair_rejects_tampered_ecies_key() {
    let (contact, mut response) = run_pre_pair_leg(ChannelId(42));

    let mut tampered = response.ecies_public_key.clone().unwrap();
    tampered[0] ^= 0xff;
    response.ecies_public_key = Some(tampered);

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::PrePairHashMismatch))
    ));
}

#[test]
fn test_process_pre_pair_rejects_non_ok_status() {
    let (contact, mut response) = run_pre_pair_leg(ChannelId(42));

    response.result = Some(DeRecResult {
        status: StatusEnum::Fail as i32,
        memo: "denied".to_owned(),
    });

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::NonOkStatus { .. }))
    ));
}

#[test]
fn test_process_pre_pair_rejects_inline_keys_contact() {
    let (mut contact, response) = run_pre_pair_leg(ChannelId(42));

    contact.contact_mode = ContactMode::InlineKeys as i32;

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(_)))
    ));
}

#[test]
fn test_process_pre_pair_rejects_contact_missing_binding_hash() {
    let (mut contact, response) = run_pre_pair_leg(ChannelId(42));

    contact.contact_binding_hash = None;

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(_)))
    ));
}

#[test]
fn test_process_pre_pair_rejects_response_missing_keys() {
    let (contact, mut response) = run_pre_pair_leg(ChannelId(42));

    response.mlkem_encapsulation_key = None;

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairResponseMessage(_)))
    ));
}

#[test]
fn test_process_pre_pair_rejects_response_nonce_mismatch() {
    let (contact, mut response) = run_pre_pair_leg(ChannelId(42));

    response.nonce = contact.nonce.wrapping_add(1);

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::ProtocolViolation(_)))
    ));
}

#[test]
fn test_process_pairing_response_rejects_tampered_channel_id_rekey() {
    let alice_channel_id = ChannelId(42);
    let alice_transport_uri = "https://relay.example/alice";
    let bob_transport_uri = "https://relay.example/bob";

    let CreateContactMessageResult {
        contact_message: initiator_contact_message,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("create_contact failed");

    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        secret_key: bob_sk_state,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &initiator_contact_message,
        None,
        None,
    )
    .expect("produce_pairing_request failed");

    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(
        &bob_pair_req_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("extract_pairing_request failed");

    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        ..
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    )
    .expect("produce_pairing_response failed");

    let ExtractPairingResponseResult {
        response: mut tampered_response,
    } = extract_pairing_response(&alice_pair_resp_envelope, bob_sk_state.ecies_secret_key())
        .expect("extract_pairing_response failed");

    tampered_response.channel_id = tampered_response.channel_id.wrapping_add(1);

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &tampered_response,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::ProtocolViolation(msg)))
            if msg == "channel_id rekey mismatch"
    ));
}

#[test]
fn test_pairing_rekey_also_fires_in_hashed_keys_mode() {
    let alice_channel_id = ChannelId(7);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("create_contact (HASHED_KEYS) failed");

    let ProducePrePairResult {
        envelope: pre_pair_req_envelope,
    } = produce_pre_pair_request(
        vec![TransportProtocol {
            uri: "https://relay.example/bob/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");
    let PrePairExtractResult {
        request: pre_pair_req,
    } = extract_pre_pair(&pre_pair_req_envelope).expect("extract_pre_pair failed");
    let ProducePrePairResponseResult {
        envelope: pre_pair_resp_envelope,
    } = produce_pre_pair(
        alice_channel_id,
        &pre_pair_req,
        alice_sk_state.as_ref().unwrap(),
    )
    .expect("produce_pre_pair failed");
    let PrePairResponseExtractResult {
        response: pre_pair_resp,
    } = extract_pre_pair_response(&pre_pair_resp_envelope)
        .expect("extract_pre_pair_response failed");
    let validated =
        process_pre_pair(&alice_contact, &pre_pair_resp).expect("process_pre_pair failed");

    let filled_in_contact = ContactMessage {
        mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
        ecies_public_key: Some(validated.ecies_public_key),
        contact_mode: ContactMode::InlineKeys as i32,
        contact_binding_hash: None,
        ..alice_contact.clone()
    };

    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &filled_in_contact,
        None,
        None,
    )
    .expect("produce_pairing_request_message failed");

    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(
        &bob_pair_req_envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    )
    .expect("extract_pairing_request failed");

    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        channel_id: alice_new_channel_id,
        ..
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        alice_sk_state.as_ref().unwrap(),
        None,
        None,
        test_policy(),
    )
    .expect("produce_pairing_response_message failed");

    let ExtractPairingResponseResult {
        response: alice_pair_resp_msg,
    } = extract_pairing_response(&alice_pair_resp_envelope, bob_sk_state.ecies_secret_key())
        .expect("extract_pairing_response failed");

    let ProcessPairingResponseMessageResult {
        channel_id: bob_new_channel_id,
        ..
    } = process_pairing_response_message(
        &initiator_contact_message,
        &alice_pair_resp_msg,
        &bob_sk_state,
    )
    .expect("process_pairing_response_message failed");

    assert_eq!(alice_new_channel_id, bob_new_channel_id);
    assert_ne!(alice_new_channel_id, alice_channel_id);
    assert_eq!(
        alice_pair_resp_msg.channel_id,
        u64::from(alice_new_channel_id)
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// Reference contact builders for the `validate_contact_for_mode` tests.
fn well_formed_inline_keys_contact() -> ContactMessage {
    ContactMessage {
        channel_id: 42,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        contact_mode: ContactMode::InlineKeys as i32,
        mlkem_encapsulation_key: Some(vec![1; 1184]),
        ecies_public_key: Some(vec![2; 33]),
        contact_binding_hash: None,
        nonce: 0xCAFE_BABE,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    }
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
fn well_formed_hashed_keys_contact() -> ContactMessage {
    ContactMessage {
        channel_id: 42,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        contact_mode: ContactMode::HashedKeys as i32,
        mlkem_encapsulation_key: None,
        ecies_public_key: None,
        contact_binding_hash: Some(vec![0xAB; 48]),
        nonce: 0xDEAD_BEEF,
        timestamp: Some(current_timestamp()),
        supported_transports: Vec::new(),
    }
}

#[test]
fn test_validate_contact_for_mode_accepts_well_formed_inline_keys() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let c = well_formed_inline_keys_contact();
    validate_contact_for_mode(&c, ContactMode::InlineKeys)
        .expect("well-formed inline_keys must pass");
}

#[test]
fn test_validate_contact_for_mode_accepts_well_formed_hashed_keys() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let c = well_formed_hashed_keys_contact();
    validate_contact_for_mode(&c, ContactMode::HashedKeys)
        .expect("well-formed hashed_keys must pass");
}

#[test]
fn test_validate_contact_for_mode_rejects_mode_mismatch() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let inline = well_formed_inline_keys_contact();
    let err = validate_contact_for_mode(&inline, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "expected HASHED_KEYS contact mode"
    ));

    let hashed = well_formed_hashed_keys_contact();
    let err = validate_contact_for_mode(&hashed, ContactMode::InlineKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "expected INLINE_KEYS contact mode"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_inline_missing_mlkem_key() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_inline_keys_contact();
    c.mlkem_encapsulation_key = Some(Vec::new());
    let err = validate_contact_for_mode(&c, ContactMode::InlineKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "inline_keys contact missing mlkem_encapsulation_key"
    ));

    let mut c = well_formed_inline_keys_contact();
    c.mlkem_encapsulation_key = None;
    let err = validate_contact_for_mode(&c, ContactMode::InlineKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "inline_keys contact missing mlkem_encapsulation_key"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_inline_missing_ecies_key() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_inline_keys_contact();
    c.ecies_public_key = None;
    let err = validate_contact_for_mode(&c, ContactMode::InlineKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "inline_keys contact missing ecies_public_key"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_inline_with_binding_hash() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_inline_keys_contact();
    c.contact_binding_hash = Some(vec![0xCD; 48]);
    let err = validate_contact_for_mode(&c, ContactMode::InlineKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "inline_keys contact must not carry contact_binding_hash"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_hashed_with_inline_keys() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_hashed_keys_contact();
    c.mlkem_encapsulation_key = Some(vec![1; 1184]);
    let err = validate_contact_for_mode(&c, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "hashed_keys contact must not carry inline keys"
    ));

    let mut c = well_formed_hashed_keys_contact();
    c.ecies_public_key = Some(vec![2; 33]);
    let err = validate_contact_for_mode(&c, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "hashed_keys contact must not carry inline keys"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_hashed_missing_binding_hash() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_hashed_keys_contact();
    c.contact_binding_hash = None;
    let err = validate_contact_for_mode(&c, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "hashed_keys contact missing contact_binding_hash"
    ));

    let mut c = well_formed_hashed_keys_contact();
    c.contact_binding_hash = Some(Vec::new());
    let err = validate_contact_for_mode(&c, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "hashed_keys contact missing contact_binding_hash"
    ));
}

#[test]
fn test_validate_contact_for_mode_rejects_hashed_wrong_hash_length() {
    use crate::primitives::pairing::validate_contact_for_mode;
    let mut c = well_formed_hashed_keys_contact();
    c.contact_binding_hash = Some(vec![0xAB; 32]);
    let err = validate_contact_for_mode(&c, ContactMode::HashedKeys).unwrap_err();
    assert!(matches!(
        err,
        Error::Pairing(PairingError::InvalidContactMessage(m))
            if m == "hashed_keys contact_binding_hash is not a SHA-384 digest"
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// A peer-supplied `PairRequestMessage.transport_protocol` declaring
/// `Protocol::Https` but carrying a URI with an unsupported scheme is
/// rejected on the initiator side at extract — the producer-side
/// `validate_inputs` catches well-behaved local builds, and this gate
/// catches a malicious responder that bypasses it. (`http://` is
/// intentionally accepted as a dev-mode affordance and is flagged via
/// `tracing::warn!`; see `crate::transport`.)
#[test]
fn test_extract_pairing_request_rejects_scheme_mismatched_transport_protocol() {
    use crate::derec_message::DeRecMessageBuilder;

    let alice_channel_id = ChannelId(91);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let malicious_transport = TransportProtocol {
        uri: "ws://attacker.example/inbox".to_owned(),
        protocol: Protocol::Https.into(),
    };
    let timestamp = current_timestamp();
    let request = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![0u8; 32],
        ecies_public_key: vec![0u8; 33],
        nonce: alice_contact.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(malicious_transport),
        timestamp: Some(timestamp),
        supported_transports: Vec::new(),
    };

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(alice_channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(request))
        .encrypt_pairing(
            alice_contact
                .ecies_public_key
                .as_ref()
                .expect("inline-keys contact carries ecies_public_key"),
        )
        .expect("encrypt pairing")
        .build()
        .expect("build envelope")
        .encode_to_vec();

    let result = extract_pairing_request(
        &envelope,
        alice_sk_state.as_ref().unwrap().ecies_secret_key(),
    );

    assert!(matches!(
        result,
        Err(Error::Transport(
            crate::transport::TransportValidationError::SchemeMismatch { .. }
        ))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// Same gate at the plaintext PrePair leg: a `PrePairRequestMessage`
/// advertising `Protocol::Https` with a URI carrying an unsupported
/// scheme is rejected at extract. (`http://` is intentionally accepted
/// as a dev-mode affordance and is flagged via `tracing::warn!`; see
/// `crate::transport`.)
#[test]
fn test_extract_pre_pair_rejects_scheme_mismatched_transport_protocol() {
    use crate::protocol_version::ProtocolVersion;
    use derec_proto::PrePairRequestMessage;

    let channel_id = ChannelId(92);

    let malicious_transport = TransportProtocol {
        uri: "ws://attacker.example/inbox".to_owned(),
        protocol: Protocol::Https.into(),
    };
    let timestamp = current_timestamp();
    let request = PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 0xDEAD_BEEF,
        transport_protocol: Some(malicious_transport),
        timestamp: Some(timestamp),
    };

    let version = ProtocolVersion::current();
    let envelope = DeRecMessage {
        protocol_version_major: version.major,
        protocol_version_minor: version.minor,
        sequence: 0,
        channel_id: channel_id.into(),
        timestamp: Some(timestamp),
        message: MessageBody::PrePairRequest(request).encode_to_vec(),
        trace_id: 0,
    }
    .encode_to_vec();

    let result = extract_pre_pair(&envelope);

    assert!(matches!(
        result,
        Err(Error::Transport(
            crate::transport::TransportValidationError::SchemeMismatch { .. }
        ))
    ));
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// Old peers read only the singular field, so a multi-transport contact
/// must still fill it. The first entry is what goes there: the order is
/// the application's stated preference and is never reinterpreted here.
#[test]
fn legacy_field_takes_the_first_entry() {
    let own = vec![
        TransportProtocol {
            uri: "grpcs://me.example.com:443".to_owned(),
            protocol: Protocol::Grpc as i32,
        },
        TransportProtocol {
            uri: "https://me.example.com/derec".to_owned(),
            protocol: Protocol::Https as i32,
        },
    ];
    let result = create_contact_message(ChannelId(1), ContactMode::InlineKeys, own, Some(42))
        .expect("creates");

    assert_eq!(
        result
            .contact_message
            .transport_protocol
            .as_ref()
            .expect("legacy field is always filled")
            .protocol,
        Protocol::Grpc as i32,
        "the legacy singular field must mirror the caller's first entry, \
         not a protocol the library picked on its own"
    );
}

/// An empty list has no entry to advertise, so contact creation fails
/// rather than panicking on an index.
#[test]
fn create_contact_rejects_an_empty_transport_list() {
    assert!(matches!(
        create_contact_message(ChannelId(1), ContactMode::InlineKeys, Vec::new(), Some(42)),
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn contact_carries_every_served_transport() {
    let own = vec![
        TransportProtocol {
            uri: "grpcs://me.example.com:443".to_owned(),
            protocol: Protocol::Grpc as i32,
        },
        TransportProtocol {
            uri: "https://me.example.com/derec".to_owned(),
            protocol: Protocol::Https as i32,
        },
    ];
    let result = create_contact_message(ChannelId(1), ContactMode::InlineKeys, own, Some(42))
        .expect("creates");

    assert_eq!(result.contact_message.supported_transports.len(), 2);
    assert_eq!(
        result.contact_message.supported_transports[0].protocol,
        Protocol::Grpc as i32,
        "the offer list must preserve the caller's order verbatim"
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// A responder builds its PrePair reply from a request a peer sent, so the
/// endpoint in that request is untrusted input. Validating it here rather
/// than only at `extract_pre_pair` matters because the FFI decodes straight
/// into this call, bypassing `extract` entirely.
#[test]
fn test_produce_pre_pair_rejects_scheme_mismatched_transport_protocol() {
    let channel_id = ChannelId(4301);
    let CreateContactMessageResult {
        secret_key: alice_secret,
        ..
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact");

    let request = derec_proto::PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 7,
        transport_protocol: Some(TransportProtocol {
            uri: "ws://attacker.example/inbox".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pre_pair(channel_id, &request, alice_secret.as_ref().unwrap());

    assert!(
        matches!(
            result,
            Err(Error::Transport(
                crate::transport::TransportValidationError::SchemeMismatch { .. }
            ))
        ),
        "a scheme-mismatched reply endpoint must be refused"
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// Same guard on the NoKeys leg, which generates key material before
/// replying and so must refuse before doing that work.
#[test]
fn test_produce_pre_pair_no_keys_rejects_scheme_mismatched_transport_protocol() {
    let request = derec_proto::PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 11,
        transport_protocol: Some(TransportProtocol {
            uri: "ws://attacker.example/inbox".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pre_pair_no_keys(ChannelId(4302), &request);

    assert!(
        matches!(
            result,
            Err(Error::Transport(
                crate::transport::TransportValidationError::SchemeMismatch { .. }
            ))
        ),
        "a scheme-mismatched reply endpoint must be refused"
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// An absent endpoint stays acceptable: the responder then routes to what
/// it already has on file. Locks in that adding validation did not turn
/// absence into an error.
#[test]
fn test_produce_pre_pair_no_keys_accepts_an_absent_transport_protocol() {
    let request = derec_proto::PrePairRequestMessage {
        supported_transports: Vec::new(),
        nonce: 13,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    produce_pre_pair_no_keys(ChannelId(4303), &request)
        .expect("an absent reply endpoint is not an error");
}

/// Builds a pairing envelope carrying `request`, encrypted to `contact`'s
/// ECIES public key. Lets a test hand a deliberately malformed body to
/// `extract` the way a hostile peer would.
fn pairing_envelope_carrying(
    channel_id: ChannelId,
    contact: &ContactMessage,
    request: PairRequestMessage,
    timestamp: prost_types::Timestamp,
) -> Vec<u8> {
    use crate::derec_message::DeRecMessageBuilder;

    DeRecMessageBuilder::pairing()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(request))
        .encrypt_pairing(
            contact
                .ecies_public_key
                .as_ref()
                .expect("inline-keys contact carries ecies_public_key"),
        )
        .expect("encrypt pairing")
        .build()
        .expect("build envelope")
        .encode_to_vec()
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// A malformed request is refused at the parse boundary rather than
/// travelling until something happens to read the missing field. The FFI
/// decodes through this call, so every SDK inherits the check.
#[test]
fn test_extract_pairing_request_rejects_missing_mlkem_ciphertext() {
    let channel_id = ChannelId(4401);
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk,
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let timestamp = current_timestamp();
    let envelope = pairing_envelope_carrying(
        channel_id,
        &alice_contact,
        PairRequestMessage {
            sender_kind: SenderKind::Helper.into(),
            mlkem_ciphertext: Vec::new(),
            ecies_public_key: vec![0u8; 33],
            nonce: alice_contact.nonce,
            communication_info: None,
            parameter_range: None,
            transport_protocol: Some(TransportProtocol {
                uri: "https://relay.example/bob".to_owned(),
                protocol: Protocol::Https.into(),
            }),
            timestamp: Some(timestamp),
            supported_transports: Vec::new(),
        },
        timestamp,
    );

    let result = extract_pairing_request(&envelope, alice_sk.as_ref().unwrap().ecies_secret_key());

    assert!(
        matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidPairRequestMessage(_)))
        ),
        "a request missing mlkem_ciphertext must be refused at extract"
    );
}

// Touches the deprecated singular `transportProtocol`: this is the
// compatibility path that keeps peers predating `supportedTransports`
// working, so the warning is expected here rather than a defect.
#[allow(deprecated)]
/// A request advertising no endpoint at all is refused here too: there
/// would be nowhere to send the response.
#[test]
fn test_extract_pairing_request_rejects_a_request_advertising_no_endpoint() {
    let channel_id = ChannelId(4402);
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk,
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let timestamp = current_timestamp();
    let envelope = pairing_envelope_carrying(
        channel_id,
        &alice_contact,
        PairRequestMessage {
            sender_kind: SenderKind::Helper.into(),
            mlkem_ciphertext: vec![0u8; 32],
            ecies_public_key: vec![0u8; 33],
            nonce: alice_contact.nonce,
            communication_info: None,
            parameter_range: None,
            transport_protocol: None,
            timestamp: Some(timestamp),
            supported_transports: Vec::new(),
        },
        timestamp,
    );

    let result = extract_pairing_request(&envelope, alice_sk.as_ref().unwrap().ecies_secret_key());

    assert!(
        matches!(result, Err(Error::Pairing(PairingError::EmptyTransportUri))),
        "a request advertising no endpoint must be refused at extract"
    );
}

/// A well-formed request still extracts: the boundary check rejects only
/// what it is meant to.
#[test]
fn test_extract_pairing_request_accepts_a_well_formed_request() {
    let channel_id = ChannelId(4403);
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk,
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult { envelope, .. } = produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("failed to produce valid pairing request");

    extract_pairing_request(&envelope, alice_sk.as_ref().unwrap().ecies_secret_key())
        .expect("a well-formed request extracts");
}

/// A contact that names no endpoint at all leaves the scanner nowhere to
/// send its pair request, so it is refused at validation rather than
/// failing later with a less obvious error.
#[test]
fn test_validate_rejects_a_contact_advertising_no_endpoint() {
    use crate::utils::ContactMessageExt as _;

    let contact = ContactMessage {
        channel_id: 5001,
        contact_mode: ContactMode::NoKeys as i32,
        nonce: 42,
        timestamp: Some(current_timestamp()),
        ..Default::default()
    };

    assert!(
        matches!(
            contact.validate(),
            Err(Error::Pairing(PairingError::EmptyTransportUri))
        ),
        "a contact naming no endpoint must be refused"
    );
}

/// The list alone satisfies the rule: a peer that has moved past the
/// deprecated singular field must not be refused for omitting it.
#[test]
fn test_validate_accepts_a_contact_carrying_only_the_list() {
    use crate::utils::ContactMessageExt as _;

    let contact = ContactMessage {
        channel_id: 5002,
        contact_mode: ContactMode::NoKeys as i32,
        nonce: 42,
        timestamp: Some(current_timestamp()),
        supported_transports: vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        ..Default::default()
    };

    contact
        .validate()
        .expect("a contact carrying only the list is valid");
}

/// And the whole pairing entry point accepts it, not just `validate`.
/// `validate_inputs` used to demand the singular field, which refused a
/// peer doing the modern thing.
#[test]
fn test_produce_accepts_a_contact_carrying_only_the_list() {
    let CreateContactMessageResult {
        contact_message: mut alice_contact,
        ..
    } = create_contact_message(
        ChannelId(5003),
        ContactMode::InlineKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    // Drop the deprecated singular field, leaving only the list.
    #[allow(deprecated)]
    {
        alice_contact.transport_protocol = None;
    }

    produce_pairing_request_message(
        SenderKind::Helper,
        vec![TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        &alice_contact,
        None,
        None,
    )
    .expect("a list-only contact must be accepted");
}

/// A PrePair request advertises the scanner's whole list, filling the
/// deprecated singular field from the first entry so peers predating the
/// list still know where to reply.
#[test]
fn test_produce_pre_pair_request_advertises_the_whole_list() {
    let channel_id = ChannelId(5004);
    let CreateContactMessageResult {
        contact_message: alice_contact,
        ..
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    let own = vec![
        TransportProtocol {
            uri: "grpcs://bob.example:443".to_owned(),
            protocol: Protocol::Grpc.into(),
        },
        TransportProtocol {
            uri: "https://bob.example/derec".to_owned(),
            protocol: Protocol::Https.into(),
        },
    ];

    let ProducePrePairResult { envelope } =
        produce_pre_pair_request(own.clone(), &alice_contact).expect("produce_pre_pair_request");

    let outer = decode_outer_envelope(&envelope);
    let request = match MessageBody::decode_from_vec(outer.message.as_slice())
        .expect("inner MessageBody should decode")
    {
        MessageBody::PrePairRequest(r) => r,
        other => panic!("expected PrePairRequest, got {other:?}"),
    };

    assert_eq!(
        request.supported_transports, own,
        "the whole list must travel in the sender's own order"
    );
    #[allow(deprecated)]
    {
        assert_eq!(
            request.transport_protocol.as_ref(),
            own.first(),
            "the first entry must fill the deprecated singular field"
        );
    }
}

/// An empty list is refused: the request would name nowhere to reply.
#[test]
fn test_produce_pre_pair_request_rejects_an_empty_transport_list() {
    let CreateContactMessageResult {
        contact_message: alice_contact,
        ..
    } = create_contact_message(
        ChannelId(5005),
        ContactMode::HashedKeys,
        vec![TransportProtocol {
            uri: "https://relay.example/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        }],
        None,
    )
    .expect("failed to create contact message");

    assert!(
        matches!(
            produce_pre_pair_request(Vec::new(), &alice_contact),
            Err(Error::Pairing(PairingError::EmptyTransportUri))
        ),
        "a PrePair request naming no endpoint must be refused"
    );
}
