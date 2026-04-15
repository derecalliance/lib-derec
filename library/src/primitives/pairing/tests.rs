use crate::Error;
use crate::derec_message::current_timestamp;
use crate::primitives::pairing::PairingError;
use crate::primitives::pairing::{
    request::{
        CreateContactResult as CreateContactMessageResult,
        ExtractResult as ExtractPairingRequestResult,
        ProduceResult as ProducePairingRequestMessageResult,
        create_contact as create_contact_message,
        extract as extract_pairing_request,
        produce as produce_pairing_request_message,
    },
    response::{
        ExtractResult as ExtractPairingResponseResult,
        ProcessResult as ProcessPairingResponseMessageResult,
        ProduceResult as ProducePairingResponseMessageResult,
        extract as extract_pairing_response,
        process as process_pairing_response_message,
        produce as produce_pairing_response_message,
    },
};
use crate::types::ChannelId;
use derec_proto::{
    ContactMessage, DeRecMessage, DeRecResult, PairRequestMessage, PairResponseMessage, Protocol,
    SenderKind, StatusEnum, TransportProtocol,
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
    let result = create_contact_message(ChannelId(42), TransportProtocol {
        uri: String::new(),
        protocol: Protocol::Https.into(),
    });

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_create_contact_message() {
    let channel_id = ChannelId(42);
    let transport_uri = "https://relay.example/alice";

    let CreateContactMessageResult { contact_message: contact_msg, .. } =
        create_contact_message(channel_id, TransportProtocol {
            uri: transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        })
        .expect("failed to create contact message");

    assert_eq!(contact_msg.channel_id, u64::from(channel_id));

    let transport = contact_msg
        .transport_protocol
        .expect("transport protocol should be present");

    assert_eq!(transport.uri, transport_uri);
    assert_eq!(transport.protocol, Protocol::Https as i32);
    assert!(contact_msg.timestamp.is_some());
    assert!(!contact_msg.mlkem_encapsulation_key.is_empty());
    assert!(!contact_msg.ecies_public_key.is_empty());
}

#[test]
fn test_produce_pairing_request_message_empty_mlkem_encapsulation_key() {
    let invalid_contact_msg = ContactMessage {
        channel_id: ChannelId(42).into(),
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/alice".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        mlkem_encapsulation_key: Vec::new(),
        ecies_public_key: vec![1; 33],
        nonce: 1234,
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &invalid_contact_msg,
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
        mlkem_encapsulation_key: vec![1; 32],
        ecies_public_key: Vec::new(),
        nonce: 1234,
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &invalid_contact_msg,
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
        mlkem_encapsulation_key: vec![1; 32],
        ecies_public_key: vec![1; 33],
        nonce: 1234,
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: String::new(), protocol: Protocol::Https.into() },
        &invalid_contact_msg,
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
    } = create_contact_message(channel_id, TransportProtocol {
        uri: alice_transport_uri.to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: bob_transport_uri.to_owned(), protocol: Protocol::Https.into() },
        &contact_message,
    )
    .expect("failed to produce pairing request message");

    let ExtractPairingRequestResult { request: pair_request_message } =
        extract_pairing_request(&envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let envelope_decoded = decode_outer_envelope(&envelope);
    assert_eq!(envelope_decoded.timestamp, pair_request_message.timestamp);
    assert_eq!(pair_request_message.channel_id, u64::from(channel_id));
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
        contact_message,
        ..
    } = create_contact_message(ChannelId(42), TransportProtocol {
        uri: alice_transport_uri.to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        initiator_contact_message,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &contact_message,
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: Vec::new(),
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
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
        SenderKind::OwnerNonRecovery,
        &invalid_pair_request_msg,
        &alice_sk_state,
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: Vec::new(),
        channel_id: alice_channel_id.into(),
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
        SenderKind::OwnerNonRecovery,
        &invalid_pair_request_msg,
        &alice_sk_state,
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
        nonce: 1234,
        communication_info: None,
        parameter_range: None,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &invalid_pair_request_msg,
        &alice_sk_state,
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
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
        SenderKind::OwnerNonRecovery,
        &invalid_pair_request_msg,
        &alice_sk_state,
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let tampered_bytes = mismatch_envelope_timestamp(&envelope);

    let result = extract_pairing_request(&tampered_bytes, &alice_sk_state.ecies_secret_key());

    assert!(matches!(
        result,
        Err(Error::Invariant(error))
            if error == "Envelope timestamp does not match request timestamp"
    ));
}

#[test]
fn test_process_pairing_response_message_missing_result() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: None,
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Fail as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidPairResponseMessage(error)))
            if error == "response indicates non-ok status"
    ));
}

#[test]
fn test_process_pairing_response_message_invalid_status() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: Some(DeRecResult {
            status: 15,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
    };

    let result = process_pairing_response_message(
        &initiator_contact_message,
        &pair_response_msg,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::ProtocolViolation(error)))
            if error == "invalid status enum value"
    ));
}

#[test]
fn test_process_pairing_response_message_nonce_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce + 1,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
    };

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.mlkem_encapsulation_key.clear();

    let result = process_pairing_response_message(
        &invalid_contact,
        &pair_response_msg,
        &bob_sk_state,
    );

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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: bob_request_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce valid pairing request");

    let ExtractPairingRequestResult { request: bob_pair_request_msg } =
        extract_pairing_request(&bob_request_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
    };

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.ecies_public_key.clear();

    let result = process_pairing_response_message(
        &invalid_contact,
        &pair_response_msg,
        &bob_sk_state,
    );

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
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        envelope: request_envelope,
        secret_key: responder_secret_key,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce pairing request");

    let ExtractPairingRequestResult { request } =
        extract_pairing_request(&request_envelope, &initiator_secret_key.ecies_secret_key())
            .expect("failed to extract pairing request");

    let ProducePairingResponseMessageResult {
        envelope: response_envelope,
        ..
    } = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &request,
        &initiator_secret_key,
    )
    .expect("failed to produce pairing response");

    let tampered_bytes = mismatch_envelope_timestamp(&response_envelope);

    let result = extract_pairing_response(&tampered_bytes, &responder_secret_key.ecies_secret_key());

    assert!(matches!(
        result,
        Err(Error::Invariant(error))
            if error == "Envelope timestamp does not match response timestamp"
    ));
}

#[test]
fn test_alice_bob_pairing_flow() {
    let alice_channel_id = ChannelId(42);
    let alice_kind = SenderKind::OwnerNonRecovery;
    let alice_transport_uri = "https://relay.example/alice";
    let bob_transport_uri = "https://relay.example/bob";

    // Alice creates the contact message.
    let CreateContactMessageResult {
        contact_message: alice_contact,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: alice_transport_uri.to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("failed to create contact message");

    // Bob (responder) produces the pairing request envelope.
    let ProducePairingRequestMessageResult {
        envelope: bob_pair_req_envelope,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: bob_transport_uri.to_owned(), protocol: Protocol::Https.into() },
        &alice_contact,
    )
    .expect("failed to produce pairing request");

    let contact_nonce = initiator_contact_message.nonce;

    // Alice (initiator) decrypts the request.
    let ExtractPairingRequestResult { request: bob_pair_req_msg } =
        extract_pairing_request(&bob_pair_req_envelope, &alice_sk_state.ecies_secret_key())
            .expect("failed to extract pairing request");

    // Alice produces the pairing response envelope.
    let ProducePairingResponseMessageResult {
        envelope: alice_pair_resp_envelope,
        shared_key: alice_shared_key,
        responder_transport_protocol: bob_transport_protocol,
    } = produce_pairing_response_message(alice_kind, &bob_pair_req_msg, &alice_sk_state)
        .expect("failed to produce pairing response");

    // Bob (responder) decrypts the response.
    let ExtractPairingResponseResult { response: alice_pair_resp_msg } =
        extract_pairing_response(&alice_pair_resp_envelope, &bob_sk_state.ecies_secret_key())
            .expect("failed to extract pairing response");

    // Bob finalizes pairing.
    let ProcessPairingResponseMessageResult {
        shared_key: bob_shared_key,
    } = process_pairing_response_message(
        &initiator_contact_message,
        &alice_pair_resp_msg,
        &bob_sk_state,
    )
    .expect("failed to process pairing response");

    assert_eq!(decode_outer_envelope(&bob_pair_req_envelope).timestamp, bob_pair_req_msg.timestamp);
    assert_eq!(decode_outer_envelope(&alice_pair_resp_envelope).timestamp, alice_pair_resp_msg.timestamp);
    assert_eq!(contact_nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_pair_resp_msg.nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_shared_key, bob_shared_key);
    assert_eq!(bob_transport_protocol.uri, bob_transport_uri);
    assert_eq!(bob_transport_protocol.protocol, Protocol::Https as i32);
}
