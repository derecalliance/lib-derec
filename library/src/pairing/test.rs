#[cfg(test)]
mod tests {
    use crate::pairing::pairing::{
        create_contact_message,
        produce_pairing_request_message,
        produce_pairing_response_message,
        process_pairing_response_message
    };
    use crate::protos::derec_proto;

    #[test]
    fn test_alice_bob_pairing_flow() {
        // Alice creates a contact message
        let alice_channel_id = 42u64;
        let alice_kind = derec_proto::SenderKind::SharerNonRecovery;
        let alice_transport_uri = String::from("alice://transport");
        let (alice_contact_msg, alice_sk_state) = create_contact_message(
            alice_channel_id,
            &alice_transport_uri
        );

        // Bob produces a pairing request message using Alice's contact message
        let bob_channel_id = 99u64;
        let bob_kind = derec_proto::SenderKind::Helper;
        let (bob_pair_req_msg, bob_sk_state) = produce_pairing_request_message(
            bob_channel_id,
            bob_kind,
            &alice_contact_msg,
        );

        let (alice_pair_resp_msg, alice_shared_key) = produce_pairing_response_message(
            alice_kind,
            &bob_pair_req_msg,
            &alice_sk_state
        );

        let bob_shared_key = process_pairing_response_message(
            &alice_contact_msg,
            &alice_pair_resp_msg,
            &bob_sk_state
        );

        // check nonces match
        assert_eq!(alice_contact_msg.nonce, bob_pair_req_msg.nonce);
        assert_eq!(alice_pair_resp_msg.nonce, bob_pair_req_msg.nonce);

        assert_eq!(alice_shared_key, bob_shared_key);
    }

    #[test]
    fn test_create_contact_message() {
        let channel_id = 123u64;
        let transport_uri = String::from("test://transport");
        
        let (contact_msg, _sk) = create_contact_message(channel_id, &transport_uri);
        
        assert_eq!(contact_msg.public_key_id, channel_id);
        assert_eq!(contact_msg.transport_uri, transport_uri);
        assert_eq!(contact_msg.message_encoding_type, 0);
    }

    #[test]
    fn test_produce_pairing_request_message() {
        let channel_id = 123u64;
        let transport_uri = String::from("test://transport");
        let (contact_msg, _) = create_contact_message(channel_id, &transport_uri);
        
        let (request_msg, _) = produce_pairing_request_message(
            channel_id,
            derec_proto::SenderKind::SharerNonRecovery,
            &contact_msg
        );
        
        assert_eq!(request_msg.public_key_id, channel_id);
        assert_eq!(request_msg.nonce, contact_msg.nonce);
    }
} 