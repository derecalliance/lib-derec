#[cfg(test)]
mod tests {
    use derec_cryptography::pairing::PairingSecretKeyMaterial;

    use crate::Error;
    use crate::pairing::PairingError;
    use crate::pairing::pairing::{
        create_contact_message, process_pairing_response_message, produce_pairing_request_message,
        produce_pairing_response_message,
    };
    use crate::protos::derec_proto;

    #[test]
    fn test_create_contact_message_empty_transport_uri() {
        let alice_channel_id = 42u64;
        let empty_transport_uri = "";

        let result = create_contact_message(alice_channel_id, empty_transport_uri);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::EmptyTransportUri))
        ))
    }

    #[test]
    fn test_produce_pairing_request_message_empty_mlkem_encapsulation_key() {
        let channel_id = 99u64;
        let transport_uri = "alice://transport";
        let kind = derec_proto::SenderKind::Helper;

        let invalid_contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: transport_uri.to_owned(),
            mlkem_encapsulation_key: Vec::new(),
            ecies_public_key: vec![0u8; 32],
            nonce: 1234,
            message_encoding_type: 0,
        };

        let result = produce_pairing_request_message(channel_id, kind, &invalid_contact_msg);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidContactMessage(error))) if error == "mlkem_encapsulation_key is empty"
        ))
    }

    #[test]
    fn test_produce_pairing_request_message_empty_ecies_public_key() {
        let channel_id = 99u64;
        let transport_uri = "alice://transport";
        let kind = derec_proto::SenderKind::Helper;

        let invalid_contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: transport_uri.to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: Vec::new(),
            nonce: 1234,
            message_encoding_type: 0,
        };

        let result = produce_pairing_request_message(channel_id, kind, &invalid_contact_msg);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidContactMessage(error))) if error == "ecies_public_key is empty"
        ))
    }

    #[test]
    fn test_produce_pairing_response_message_empty_mlkem_ciphertext() {
        let channel_id = 99u64;
        let kind = derec_proto::SenderKind::Helper;
        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let invalid_pair_request_msg = derec_proto::PairRequestMessage {
            sender_kind: kind.into(),
            mlkem_ciphertext: Vec::new(),
            ecies_public_key: vec![0u8; 32],
            public_key_id: channel_id,
            nonce: 1234,
            communication_info: None,
            parameter_range: None,
        };

        let result = produce_pairing_response_message(kind, &invalid_pair_request_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error))) if error == "mlkem_ciphertext is empty"
        ))
    }

    #[test]
    fn test_produce_pairing_response_message_empty_ecies_public_key() {
        let channel_id = 99u64;
        let kind = derec_proto::SenderKind::Helper;
        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let invalid_pair_request_msg = derec_proto::PairRequestMessage {
            sender_kind: kind.into(),
            mlkem_ciphertext: vec![0u8; 32],
            ecies_public_key: Vec::new(),
            public_key_id: channel_id,
            nonce: 1234,
            communication_info: None,
            parameter_range: None,
        };

        let result = produce_pairing_response_message(kind, &invalid_pair_request_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidPairRequestMessage(error))) if error == "ecies_public_key is empty"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_no_result() {
        let channel_id = 99u64;
        let nonce = 1234;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: vec![0u8; 32],
            nonce,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: None,
            nonce,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidPairResponseMessage(error))) if error == "missing result"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_result_no_ok() {
        let channel_id = 99u64;
        let nonce = 1234;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: vec![0u8; 32],
            nonce,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: Some(derec_proto::Result {
                status: derec_proto::StatusEnum::Fail as i32,
                memo: String::new(),
            }),
            nonce,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidPairResponseMessage(error))) if error == "response indicates non-ok status"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_invalid_status() {
        let channel_id = 99u64;
        let nonce = 1234;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: vec![0u8; 32],
            nonce,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: Some(derec_proto::Result {
                status: 15_i32,
                memo: String::new(),
            }),
            nonce,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::ProtocolViolation(error))) if error == "invalid status enum value"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_nonce_mismatch() {
        let channel_id = 99u64;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: vec![0u8; 32],
            nonce: 1234,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: Some(derec_proto::Result {
                status: derec_proto::StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            nonce: 4321,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::ProtocolViolation(error))) if error == "nonce mismatch"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_empty_mlkem_encapsulation_key() {
        let channel_id = 99u64;
        let nonce = 1234;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: Vec::new(),
            ecies_public_key: vec![0u8; 32],
            nonce,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: Some(derec_proto::Result {
                status: derec_proto::StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            nonce,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidContactMessage(error))) if error == "mlkem_encapsulation_key is empty"
        ))
    }

    #[test]
    fn test_process_pairing_response_message_empty_ecies_public_key() {
        let channel_id = 99u64;
        let nonce = 1234;
        let contact_msg = derec_proto::ContactMessage {
            public_key_id: channel_id,
            transport_uri: "alice://transport".to_owned(),
            mlkem_encapsulation_key: vec![0u8; 32],
            ecies_public_key: Vec::new(),
            nonce,
            message_encoding_type: 0,
        };

        let sk_state = PairingSecretKeyMaterial {
            mlkem_decapsulation_key: None,
            mlkem_shared_secret: None,
            ecies_secret_key: vec![0u8; 32],
        };

        let pair_response_msg = derec_proto::PairResponseMessage {
            sender_kind: derec_proto::SenderKind::Helper.into(),
            result: Some(derec_proto::Result {
                status: derec_proto::StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            nonce,
            communication_info: None,
            parameter_range: None,
        };

        let result = process_pairing_response_message(&contact_msg, &pair_response_msg, &sk_state);

        assert!(matches!(
            result,
            Err(Error::Pairing(PairingError::InvalidContactMessage(error))) if error == "ecies_public_key is empty"
        ))
    }

    #[test]
    fn test_alice_bob_pairing_flow() {
        // Alice creates a contact message
        let alice_channel_id = 42u64;
        let alice_kind = derec_proto::SenderKind::SharerNonRecovery;
        let alice_transport_uri = String::from("alice://transport");
        let (alice_contact_msg, alice_sk_state) =
            create_contact_message(alice_channel_id, &alice_transport_uri)
                .expect("Failed to create contract message");

        // Bob produces a pairing request message using Alice's contact message
        let bob_channel_id = 99u64;
        let bob_kind = derec_proto::SenderKind::Helper;
        let (bob_pair_req_msg, bob_sk_state) =
            produce_pairing_request_message(bob_channel_id, bob_kind, &alice_contact_msg)
                .expect("Failed to create contract message");

        let (alice_pair_resp_msg, alice_shared_key) =
            produce_pairing_response_message(alice_kind, &bob_pair_req_msg, &alice_sk_state)
                .expect("Failed to create contract message");

        let bob_shared_key = process_pairing_response_message(
            &alice_contact_msg,
            &alice_pair_resp_msg,
            &bob_sk_state,
        )
        .expect("Failed to create contract message");

        // check nonces match
        assert_eq!(alice_contact_msg.nonce, bob_pair_req_msg.nonce);
        assert_eq!(alice_pair_resp_msg.nonce, bob_pair_req_msg.nonce);

        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    fn test_create_contact_message() {
        let channel_id = 123u64;
        let transport_uri = String::from("test://transport");

        let (contact_msg, _sk) = create_contact_message(channel_id, &transport_uri)
            .expect("Failed to create contract message");

        assert_eq!(contact_msg.public_key_id, channel_id);
        assert_eq!(contact_msg.transport_uri, transport_uri);
        assert_eq!(contact_msg.message_encoding_type, 0);
    }

    #[test]
    fn test_produce_pairing_request_message() {
        let channel_id = 123u64;
        let transport_uri = String::from("test://transport");
        let (contact_msg, _) = create_contact_message(channel_id, &transport_uri)
            .expect("Failed to create contract message");

        let (request_msg, _) = produce_pairing_request_message(
            channel_id,
            derec_proto::SenderKind::SharerNonRecovery,
            &contact_msg,
        )
        .expect("Failed to create contract message");

        assert_eq!(request_msg.public_key_id, channel_id);
        assert_eq!(request_msg.nonce, contact_msg.nonce);
    }
}
