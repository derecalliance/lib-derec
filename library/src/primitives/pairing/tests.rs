use crate::Error;
use crate::derec_message::current_timestamp;
use crate::primitives::pairing::PairingError;
use crate::primitives::pairing::{
    request::{
        CreateContactResult as CreateContactMessageResult,
        ExtractResult as ExtractPairingRequestResult, PrePairExtractResult,
        ProducePrePairResult, ProduceResult as ProducePairingRequestMessageResult,
        create_contact as create_contact_message, extract as extract_pairing_request,
        extract_pre_pair, produce as produce_pairing_request_message, produce_pre_pair_request,
    },
    response::{
        ExtractResult as ExtractPairingResponseResult,
        PrePairExtractResult as PrePairResponseExtractResult,
        ProcessPrePairResult, ProcessResult as ProcessPairingResponseMessageResult,
        ProducePrePairResult as ProducePrePairResponseResult,
        ProduceResult as ProducePairingResponseMessageResult,
        extract as extract_pairing_response, extract_pre_pair as extract_pre_pair_response,
        process as process_pairing_response_message, process_pre_pair,
        produce as produce_pairing_response_message, produce_pre_pair,
    },
};
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
        TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        },
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

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
        TransportProtocol {
            uri: transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &invalid_contact_msg,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "mlkem_encapsulation_key is empty"
    ));
}

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
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &invalid_contact_msg,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "ecies_public_key is empty"
    ));
}

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
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        },
        &invalid_contact_msg,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

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
        TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult { envelope, .. } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
        &contact_message,
        None,
    )
    .expect("failed to produce pairing request message");

    let ExtractPairingRequestResult {
        request: pair_request_message,
    } = extract_pairing_request(&envelope, alice_sk_state.ecies_secret_key())
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

#[test]
fn test_produce_pairing_request_message_initiator_contact_message() {
    let alice_transport_uri = "https://relay.example/alice";

    let CreateContactMessageResult {
        contact_message, ..
    } = create_contact_message(
        ChannelId(42),
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        initiator_contact_message,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &contact_message,
        None,
    )
    .expect("failed to produce pairing request message");

    let tp = initiator_contact_message
        .transport_protocol
        .expect("transport protocol should be present");
    assert_eq!(tp.uri, alice_transport_uri);
    assert_eq!(tp.protocol, Protocol::Https as i32);
}

#[test]
fn test_produce_pairing_response_message_empty_mlkem_ciphertext() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        &alice_sk_state,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error)))
            if error == "mlkem_ciphertext is empty"
    ));
}

#[test]
fn test_produce_pairing_response_message_empty_ecies_public_key() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        &alice_sk_state,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error)))
            if error == "ecies_public_key is empty"
    ));
}

#[test]
fn test_produce_pairing_response_message_missing_transport_protocol() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        &alice_sk_state,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_produce_pairing_response_message_empty_transport_uri() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        secret_key: alice_sk_state,
        ..
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    };

    let result = produce_pairing_response_message(
        ChannelId(42),
        &invalid_pair_request_msg,
        &alice_sk_state,
        None,
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult { envelope, .. } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let tampered_bytes = mismatch_envelope_timestamp(&envelope);

    let result = extract_pairing_request(&tampered_bytes, alice_sk_state.ecies_secret_key());

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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: request_envelope,
        secret_key: responder_secret_key,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce pairing request");

    let ExtractPairingRequestResult { request } =
        extract_pairing_request(&request_envelope, initiator_secret_key.ecies_secret_key())
            .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_pairing_response_message(
        ChannelId(42),
        &request,
        &initiator_secret_key,
        None,
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

    // Alice creates the contact message.
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    // Bob (responder) produces the pairing request envelope.
    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce pairing request");

    let contact_nonce = initiator_contact_message.nonce;

    // Alice (initiator) decrypts the request.
    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(&bob_pair_req_envelope, alice_sk_state.ecies_secret_key())
        .expect("failed to extract pairing request");

    // Alice produces the pairing response envelope.
    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        shared_key: alice_shared_key,
        peer_transport_protocol: bob_transport_protocol,
        channel_id: alice_new_channel_id,
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        &alice_sk_state,
        None,
    )
    .expect("failed to produce pairing response");

    // Bob (responder) decrypts the response.
    let ExtractPairingResponseResult {
        response: alice_pair_resp_msg,
    } = extract_pairing_response(&alice_pair_resp_envelope, bob_sk_state.ecies_secret_key())
        .expect("failed to extract pairing response");

    // Bob finalizes pairing.
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
    assert_eq!(bob_transport_protocol.uri, bob_transport_uri);
    assert_eq!(bob_transport_protocol.protocol, Protocol::Https as i32);
    // Both sides agree on the rekeyed channel id, derived from the
    // pre-rekey channel id and the freshly negotiated shared key.
    assert_eq!(alice_new_channel_id, bob_new_channel_id);
    assert_ne!(alice_new_channel_id, alice_channel_id);
    // The wire-level field on the encrypted inner response carries the
    // same value.
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        secret_key: bob_sk_state,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("failed to produce pairing request");

    let ExtractPairingRequestResult {
        request: bob_pair_request_msg,
    } = extract_pairing_request(&bob_request_envelope, alice_sk_state.ecies_secret_key())
        .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope,
        shared_key,
        peer_transport_protocol,
        channel_id: _,
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_request_msg,
        &alice_sk_state,
        None,
    )
    .expect("accept should succeed");

    assert!(!envelope.is_empty());
    assert_eq!(peer_transport_protocol.uri, bob_transport_uri);
    assert_eq!(peer_transport_protocol.protocol, Protocol::Https as i32);

    // The responder must be able to decrypt the envelope and observe an Ok status.
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
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

    // Keys MUST be absent in HASHED_KEYS mode (delivered later via PrePair).
    assert!(contact.mlkem_encapsulation_key.is_none());
    assert!(contact.ecies_public_key.is_none());

    // Binding hash MUST be present and SHA-384-sized (48 bytes).
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
        TransportProtocol {
            uri: String::new(),
            protocol: Protocol::Https.into(),
        },
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_create_contact_message_hashed_keys_fresh_randomness_yields_distinct_hashes() {
    // Two independent calls draw fresh ML-KEM/ECIES key material, so the
    // commitments MUST differ even with the same channel_id and transport.
    let a = make_hashed_keys_contact(ChannelId(42));
    let b = make_hashed_keys_contact(ChannelId(42));
    assert_ne!(a.contact_binding_hash, b.contact_binding_hash);
}

#[test]
fn test_produce_pre_pair_request_emits_envelope_routed_to_contact_channel() {
    let channel_id = ChannelId(42);
    let alice_contact = make_hashed_keys_contact(channel_id);

    let bob_transport = TransportProtocol {
        uri: "https://relay.example/bob".to_owned(),
        protocol: Protocol::Https.into(),
    };

    let ProducePrePairResult { envelope } =
        produce_pre_pair_request(bob_transport.clone(), &alice_contact)
            .expect("produce_pre_pair_request should succeed");

    // The outer envelope routes to the contact's channel and carries a timestamp.
    let outer = decode_outer_envelope(&envelope);
    assert_eq!(outer.channel_id, u64::from(channel_id));
    let envelope_ts = outer.timestamp.expect("envelope timestamp must be present");

    // Inner body decodes as a PrePairRequest carrying the contact nonce
    // and the requester's transport endpoint — and its timestamp matches
    // the envelope timestamp (the invariant `extract_pre_pair` enforces).
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact message")
    .contact_message;

    let result = produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    );

    // PrePair is only meaningful for HASHED_KEYS contacts — INLINE_KEYS
    // contacts already carry the keys and must use `produce` directly.
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(_)))
    ));
}

#[test]
fn test_produce_pre_pair_request_rejects_empty_transport_uri() {
    let alice_contact = make_hashed_keys_contact(ChannelId(42));

    let result = produce_pre_pair_request(
        TransportProtocol {
            uri: "   ".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_extract_pre_pair_roundtrip() {
    let alice_contact = make_hashed_keys_contact(ChannelId(42));

    let bob_transport = TransportProtocol {
        uri: "https://relay.example/bob".to_owned(),
        protocol: Protocol::Https.into(),
    };

    let ProducePrePairResult { envelope } =
        produce_pre_pair_request(bob_transport.clone(), &alice_contact)
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
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
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
    // Hand-craft an envelope that carries a non-PrePairRequest body. The
    // body is plaintext (same encoding as PrePair), so the envelope is
    // structurally valid — `extract_pre_pair` must still reject it.
    let timestamp = current_timestamp();
    let body =
        MessageBody::PairResponse(PairResponseMessage::default()).encode_to_vec();
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

    // Alice creates a HASHED_KEYS contact and keeps the secret material.
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create HASHED_KEYS contact");

    // Bob builds and Alice extracts the PrePair request so Alice has a
    // proper PrePairRequestMessage to echo the nonce from.
    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    )
    .expect("produce_pre_pair_request should succeed");
    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair should succeed");

    // Alice produces the PrePair response envelope.
    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(channel_id, &pre_pair_request, &alice_secret)
        .expect("produce_pre_pair should succeed");

    // Outer envelope routes back to the same channel and carries a timestamp.
    let outer = decode_outer_envelope(&response_envelope);
    assert_eq!(outer.channel_id, u64::from(channel_id));
    let envelope_ts = outer.timestamp.expect("envelope timestamp must be present");

    // Inner body is a PrePairResponse with Ok status, echoed nonce,
    // matching timestamp, and both public keys present and non-empty.
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

#[test]
fn test_produce_pre_pair_rejects_responder_secret_key_material() {
    let channel_id = ChannelId(42);

    // Alice's contact provides keys for Bob to encapsulate against.
    let alice_contact = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact")
    .contact_message;

    // Bob produces a PairRequest, which yields a Responder secret variant —
    // the kind that MUST NOT be allowed to serve a PrePair response.
    let ProducePairingRequestMessageResult {
        secret_key: bob_secret,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
        None,
    )
    .expect("produce_pairing_request_message should succeed");

    // A dummy request is fine — validation rejects on the secret variant
    // before nonce/timestamp are consulted.
    let dummy_request = derec_proto::PrePairRequestMessage {
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

#[test]
fn test_produce_pre_pair_response_keys_match_initiator_contact_keys_in_inline_mode() {
    // Sanity check: the keys we republish via PrePair MUST equal the ones a
    // peer would have received inline. We can't compare against a HASHED_KEYS
    // contact (it doesn't carry them), so we run create_contact in
    // INLINE_KEYS mode purely to surface the keys that ended up retained on
    // the secret material, and confirm they match.
    let channel_id = ChannelId(42);
    let CreateContactMessageResult {
        contact_message: inline_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("failed to create contact");

    let dummy_request = derec_proto::PrePairRequestMessage {
        nonce: 7,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    let ProducePrePairResponseResult { envelope } =
        produce_pre_pair(channel_id, &dummy_request, &alice_secret)
            .expect("produce_pre_pair should succeed");
    let outer = decode_outer_envelope(&envelope);
    let response: PrePairResponseMessage = match MessageBody::decode_from_vec(&outer.message)
        .expect("decode inner")
    {
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
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("create_contact (HASHED_KEYS) failed");

    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");

    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair (request) failed");

    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(channel_id, &pre_pair_request, &alice_secret)
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

    // Nonce echoed from the request, keys present and non-empty.
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
    // Hand-craft an envelope that carries a non-PrePairResponse body. The
    // body is plaintext, so the envelope is structurally valid —
    // `extract_pre_pair_response` must still reject it.
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
fn run_pre_pair_leg(
    channel_id: ChannelId,
) -> (ContactMessage, PrePairResponseMessage) {
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_secret,
    } = create_contact_message(
        channel_id,
        ContactMode::HashedKeys,
        TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("create_contact (HASHED_KEYS) failed");

    let ProducePrePairResult {
        envelope: request_envelope,
    } = produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");

    let PrePairExtractResult {
        request: pre_pair_request,
    } = extract_pre_pair(&request_envelope).expect("extract_pre_pair (request) failed");

    let ProducePrePairResponseResult {
        envelope: response_envelope,
    } = produce_pre_pair(channel_id, &pre_pair_request, &alice_secret)
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

    // Returned keys MUST equal the ones the response advertised — process
    // hands them back verbatim once the hash check has passed.
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

    // Flip a byte in the published ML-KEM key; the hash recomputation MUST
    // surface a binding-hash mismatch.
    let mut tampered = response.mlkem_encapsulation_key.clone().unwrap();
    tampered[0] ^= 0xff;
    response.mlkem_encapsulation_key = Some(tampered);

    let result = process_pre_pair(&contact, &response);
    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::ProtocolViolation(_)))
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
        Err(Error::Pairing(PairingError::ProtocolViolation(_)))
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

    // Pretend the contact was an INLINE_KEYS one — the PrePair leg makes
    // no sense in that mode and process must refuse.
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

    // Swap to a nonce that won't match the contact's. The hash recompute
    // would also catch this, but the explicit nonce check fires first
    // (matches the existing PairResponse process behavior).
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
        TransportProtocol {
            uri: alice_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("create_contact failed");

    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        secret_key: bob_sk_state,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: bob_transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        },
        &initiator_contact_message,
        None,
    )
    .expect("produce_pairing_request failed");

    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(&bob_pair_req_envelope, alice_sk_state.ecies_secret_key())
        .expect("extract_pairing_request failed");

    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        ..
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        &alice_sk_state,
        None,
    )
    .expect("produce_pairing_response failed");

    let ExtractPairingResponseResult {
        response: mut tampered_response,
    } = extract_pairing_response(&alice_pair_resp_envelope, bob_sk_state.ecies_secret_key())
        .expect("extract_pairing_response failed");

    // Flip the rekey id away from what process() will derive. The hash is
    // deterministic over (contact.channel_id, shared_key), so any value other
    // than the correct derivation must be rejected.
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
    // The channel-id rekey is part of every pairing handshake regardless
    // of `ContactMode`. This test runs the full HASHED_KEYS leg (PrePair
    // → Pair) and asserts the rekey happens on the synthesized contact
    // exactly like it does for INLINE_KEYS.

    let alice_channel_id = ChannelId(7);

    // Alice creates a HASHED_KEYS contact (no inline keys, only a hash).
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(
        alice_channel_id,
        ContactMode::HashedKeys,
        TransportProtocol {
            uri: "https://relay.example/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("create_contact (HASHED_KEYS) failed");

    // Bob runs the PrePair leg to fetch and validate Alice's keys.
    let ProducePrePairResult {
        envelope: pre_pair_req_envelope,
    } = produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/bob/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    )
    .expect("produce_pre_pair_request failed");
    let PrePairExtractResult {
        request: pre_pair_req,
    } = extract_pre_pair(&pre_pair_req_envelope).expect("extract_pre_pair failed");
    let ProducePrePairResponseResult {
        envelope: pre_pair_resp_envelope,
    } = produce_pre_pair(alice_channel_id, &pre_pair_req, &alice_sk_state)
        .expect("produce_pre_pair failed");
    let PrePairResponseExtractResult {
        response: pre_pair_resp,
    } = extract_pre_pair_response(&pre_pair_resp_envelope)
        .expect("extract_pre_pair_response failed");
    let validated = process_pre_pair(&alice_contact, &pre_pair_resp)
        .expect("process_pre_pair failed");

    // Bob synthesizes a filled-in contact and runs the regular Pair flow.
    let filled_in_contact = ContactMessage {
        mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
        ecies_public_key: Some(validated.ecies_public_key),
        ..alice_contact.clone()
    };

    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &filled_in_contact,
        None,
    )
    .expect("produce_pairing_request_message failed");

    let ExtractPairingRequestResult {
        request: bob_pair_req_msg,
    } = extract_pairing_request(&bob_pair_req_envelope, alice_sk_state.ecies_secret_key())
        .expect("extract_pairing_request failed");

    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        channel_id: alice_new_channel_id,
        ..
    } = produce_pairing_response_message(
        alice_channel_id,
        &bob_pair_req_msg,
        &alice_sk_state,
        None,
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

    // Both sides agree on the rekeyed id...
    assert_eq!(alice_new_channel_id, bob_new_channel_id);
    // ...and it differs from the original pre-rekey id.
    assert_ne!(alice_new_channel_id, alice_channel_id);
    // The wire-level field on the encrypted inner response carries it too.
    assert_eq!(
        alice_pair_resp_msg.channel_id,
        u64::from(alice_new_channel_id)
    );
}
