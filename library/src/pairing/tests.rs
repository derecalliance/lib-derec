use crate::Error;
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::pairing::{
    CreateContactMessageResult, PairingError, ProcessPairingResponseMessageResult,
    ProducePairingRequestMessageResult, ProducePairingResponseMessageResult,
    create_contact_message, process_pairing_response_message, produce_pairing_request_message,
    produce_pairing_response_message,
};
use crate::types::ChannelId;
use derec_proto::{
    ContactMessage, DeRecMessage, DeRecResult, PairRequestMessage, PairResponseMessage, Protocol,
    SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;

fn decode_contact_message(bytes: &[u8]) -> ContactMessage {
    ContactMessage::decode(bytes).expect("contact message should decode")
}

fn decode_outer_envelope(bytes: &[u8]) -> DeRecMessage {
    DeRecMessage::decode(bytes).expect("outer DeRecMessage should decode")
}

fn decode_inner_pair_request(
    wire_bytes: &[u8],
    receiver_secret_key: &[u8],
) -> (DeRecMessage, PairRequestMessage) {
    let envelope = decode_outer_envelope(wire_bytes);

    let plaintext =
        derec_cryptography::pairing::envelope::decrypt(&envelope.message, receiver_secret_key)
            .expect("pair request decryption should succeed");

    let pair_request =
        PairRequestMessage::decode(plaintext.as_slice()).expect("pair request should decode");

    (envelope, pair_request)
}

fn decode_inner_pair_response(
    wire_bytes: &[u8],
    receiver_secret_key: &[u8],
) -> (DeRecMessage, PairResponseMessage) {
    let envelope = decode_outer_envelope(wire_bytes);

    let plaintext =
        derec_cryptography::pairing::envelope::decrypt(&envelope.message, receiver_secret_key)
            .expect("pair response decryption should succeed");

    let pair_response =
        PairResponseMessage::decode(plaintext.as_slice()).expect("pair response should decode");

    (envelope, pair_response)
}

fn make_pair_request_wire_bytes(
    channel_id: ChannelId,
    recipient_public_key: &[u8],
    pair_request_message: &PairRequestMessage,
) -> Vec<u8> {
    let timestamp = pair_request_message
        .timestamp
        .expect("pair request timestamp should be present");

    DeRecMessageBuilder::pairing()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(pair_request_message)
        .encrypt_pairing(recipient_public_key)
        .expect("pair request inner encryption should succeed")
        .build()
        .expect("outer DeRecMessage should build")
        .encode_to_vec()
}

fn make_pair_response_wire_bytes(
    channel_id: ChannelId,
    recipient_public_key: &[u8],
    pair_response_message: &PairResponseMessage,
) -> Vec<u8> {
    let timestamp = pair_response_message
        .timestamp
        .expect("pair response timestamp should be present");

    DeRecMessageBuilder::pairing()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(pair_response_message)
        .encrypt_pairing(recipient_public_key)
        .expect("pair response inner encryption should succeed")
        .build()
        .expect("outer DeRecMessage should build")
        .encode_to_vec()
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

    let CreateContactMessageResult { wire_bytes, .. } =
        create_contact_message(channel_id, TransportProtocol {
            uri: transport_uri.to_owned(),
            protocol: Protocol::Https.into(),
        })
        .expect("failed to create contact message");

    let contact_msg = decode_contact_message(&wire_bytes);

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
        &invalid_contact_msg.encode_to_vec(),
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
        &invalid_contact_msg.encode_to_vec(),
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
        &invalid_contact_msg.encode_to_vec(),
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
        wire_bytes: contact_message_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(channel_id, TransportProtocol {
        uri: alice_transport_uri.to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("failed to create contact message");

    let contact_message = decode_contact_message(&contact_message_bytes);

    let ProducePairingRequestMessageResult {
        wire_bytes: pair_request_wire_bytes,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: bob_transport_uri.to_owned(), protocol: Protocol::Https.into() },
        &contact_message_bytes,
    )
    .expect("failed to produce pairing request message");

    let (outer, pair_request_message) =
        decode_inner_pair_request(&pair_request_wire_bytes, &alice_sk_state.ecies_secret_key);

    assert_eq!(outer.timestamp, pair_request_message.timestamp);
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
        wire_bytes: contact_message_bytes,
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
        &contact_message_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let alice_contact = decode_contact_message(&alice_contact_bytes);

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: Vec::new(),
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
        nonce: alice_contact.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
    };

    let pair_request_wire_bytes = make_pair_request_wire_bytes(
        alice_channel_id,
        &alice_contact.ecies_public_key,
        &invalid_pair_request_msg,
    );

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &pair_request_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let alice_contact = decode_contact_message(&alice_contact_bytes);

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: Vec::new(),
        channel_id: alice_channel_id.into(),
        nonce: alice_contact.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "https://relay.example/bob".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
    };

    let pair_request_wire_bytes = make_pair_request_wire_bytes(
        alice_channel_id,
        &alice_contact.ecies_public_key,
        &invalid_pair_request_msg,
    );

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &pair_request_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let alice_contact = decode_contact_message(&alice_contact_bytes);

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
        nonce: alice_contact.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: None,
        timestamp: Some(current_timestamp()),
    };

    let pair_request_wire_bytes = make_pair_request_wire_bytes(
        alice_channel_id,
        &alice_contact.ecies_public_key,
        &invalid_pair_request_msg,
    );

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &pair_request_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let alice_contact = decode_contact_message(&alice_contact_bytes);

    let invalid_pair_request_msg = PairRequestMessage {
        sender_kind: SenderKind::Helper.into(),
        mlkem_ciphertext: vec![1; 32],
        ecies_public_key: vec![2; 33],
        channel_id: alice_channel_id.into(),
        nonce: alice_contact.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(TransportProtocol {
            uri: "   ".to_owned(),
            protocol: Protocol::Https.into(),
        }),
        timestamp: Some(current_timestamp()),
    };

    let pair_request_wire_bytes = make_pair_request_wire_bytes(
        alice_channel_id,
        &alice_contact.ecies_public_key,
        &invalid_pair_request_msg,
    );

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &pair_request_wire_bytes,
        &alice_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::EmptyTransportUri))
    ));
}

#[test]
fn test_produce_pairing_response_message_rejects_envelope_timestamp_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: pair_request_wire_bytes,
        ..
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let tampered_wire_bytes = mismatch_envelope_timestamp(&pair_request_wire_bytes);

    let result = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &tampered_wire_bytes,
        &alice_sk_state,
    );

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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

    let pair_response_msg = PairResponseMessage {
        sender_kind: SenderKind::OwnerNonRecovery.into(),
        result: None,
        nonce: bob_pair_request_msg.nonce,
        communication_info: None,
        parameter_range: None,
        timestamp: Some(current_timestamp()),
    };

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let result = process_pairing_response_message(
        initiator_contact_message,
        &pair_response_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

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

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let result = process_pairing_response_message(
        initiator_contact_message,
        &pair_response_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

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

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let result = process_pairing_response_message(
        initiator_contact_message,
        &pair_response_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

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

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let result = process_pairing_response_message(
        initiator_contact_message,
        &pair_response_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

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

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.mlkem_encapsulation_key.clear();

    let result = process_pairing_response_message(
        invalid_contact,
        &pair_response_wire_bytes,
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
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_request_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce valid pairing request");

    let (_outer, bob_pair_request_msg) =
        decode_inner_pair_request(&bob_request_bytes, &alice_sk_state.ecies_secret_key);

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

    let pair_response_wire_bytes = make_pair_response_wire_bytes(
        bob_pair_request_msg.channel_id.into(),
        &bob_pair_request_msg.ecies_public_key,
        &pair_response_msg,
    );

    let mut invalid_contact = initiator_contact_message;
    invalid_contact.ecies_public_key.clear();

    let result = process_pairing_response_message(
        invalid_contact,
        &pair_response_wire_bytes,
        &bob_sk_state,
    );

    assert!(matches!(
        result,
        Err(Error::Pairing(PairingError::InvalidContactMessage(error)))
            if error == "ecies_public_key is empty"
    ));
}

#[test]
fn test_process_pairing_response_message_rejects_envelope_timestamp_mismatch() {
    let alice_channel_id = ChannelId(42);

    let CreateContactMessageResult {
        wire_bytes: alice_contact_bytes,
        secret_key: initiator_secret_key,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: "https://relay.example/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
        .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: request_bytes,
        initiator_contact_message,
        secret_key: responder_secret_key,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: "https://relay.example/bob".to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce pairing request");

    let ProducePairingResponseMessageResult {
        wire_bytes: response_bytes,
        ..
    } = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &request_bytes,
        &initiator_secret_key,
    )
    .expect("failed to produce pairing response");

    let tampered_wire_bytes = mismatch_envelope_timestamp(&response_bytes);

    let result = process_pairing_response_message(
        initiator_contact_message,
        &tampered_wire_bytes,
        &responder_secret_key,
    );

    assert!(matches!(
        result,
        Err(Error::Invariant(error))
            if error == "Envelope timestamp does not match request timestamp"
    ));
}

#[test]
fn test_alice_bob_pairing_flow() {
    let alice_channel_id = ChannelId(42);
    let alice_kind = SenderKind::OwnerNonRecovery;
    let alice_transport_uri = "https://relay.example/alice";
    let bob_transport_uri = "https://relay.example/bob";

    let CreateContactMessageResult {
        wire_bytes: alice_contact_bytes,
        secret_key: alice_sk_state,
    } = create_contact_message(alice_channel_id, TransportProtocol {
        uri: alice_transport_uri.to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("failed to create contact message");

    let ProducePairingRequestMessageResult {
        wire_bytes: bob_pair_req_bytes,
        initiator_contact_message,
        secret_key: bob_sk_state,
    } = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol { uri: bob_transport_uri.to_owned(), protocol: Protocol::Https.into() },
        &alice_contact_bytes,
    )
    .expect("failed to produce pairing request");

    let (outer_req, bob_pair_req_msg) =
        decode_inner_pair_request(&bob_pair_req_bytes, &alice_sk_state.ecies_secret_key);

    let contact_nonce = initiator_contact_message.nonce;

    let ProducePairingResponseMessageResult {
        wire_bytes: alice_pair_resp_bytes,
        shared_key: alice_shared_key,
        responder_transport_protocol: bob_transport_protocol,
    } = produce_pairing_response_message(alice_kind, &bob_pair_req_bytes, &alice_sk_state)
        .expect("failed to produce pairing response");

    let ProcessPairingResponseMessageResult {
        shared_key: bob_shared_key,
    } = process_pairing_response_message(
        initiator_contact_message,
        &alice_pair_resp_bytes,
        &bob_sk_state,
    )
    .expect("failed to process pairing response");

    let (outer_resp, alice_pair_resp_msg) =
        decode_inner_pair_response(&alice_pair_resp_bytes, &bob_sk_state.ecies_secret_key);

    assert_eq!(outer_req.timestamp, bob_pair_req_msg.timestamp);
    assert_eq!(outer_resp.timestamp, alice_pair_resp_msg.timestamp);
    assert_eq!(contact_nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_pair_resp_msg.nonce, bob_pair_req_msg.nonce);
    assert_eq!(alice_shared_key, bob_shared_key);
    assert_eq!(bob_transport_protocol.uri, bob_transport_uri);
    assert_eq!(bob_transport_protocol.protocol, Protocol::Https as i32);
}
