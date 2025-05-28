use rand::RngCore;
use derec_cryptography::pairing;

pub mod derec_proto {
    // OUT_DIR is where the generated code is stored during compilation
    include!(concat!(env!("OUT_DIR"), "/org.derecalliance.derec.protobuf.rs")); // filename matches proto
}

pub fn create_contact_message(
    channel_id: u64,
    transport_uri: &String
) -> (derec_proto::ContactMessage, pairing::PairingSecretKeyMaterial) {
    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, sk) = pairing::contact_message(seed)
        .expect("Failed to generate contact message");

    let contact_msg = derec_proto::ContactMessage {
        public_key_id: channel_id,
        transport_uri: transport_uri.clone(),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        message_encoding_type: 0,
    };

    (contact_msg, sk)
}

pub fn produce_pairing_request_message(
    channel_id: u64,
    kind: derec_proto::SenderKind,
    contact_message: &derec_proto::ContactMessage
) -> (derec_proto::PairRequestMessage, pairing::PairingSecretKeyMaterial) {
    // extract the PairingContactMessageMaterial from the contact message
    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, sk) = pairing::pairing_request_message(seed, &pk)
        .expect("Failed to generate pairing request message");

    let request_msg = derec_proto::PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: pk.mlkem_ciphertext,
        ecies_public_key: pk.ecies_public_key,
        public_key_id: channel_id,
        nonce: contact_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    (request_msg, sk)
}

pub fn produce_pairing_response_message(
    kind: derec_proto::SenderKind,
    pair_request_message: &derec_proto::PairRequestMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial
) -> (derec_proto::PairResponseMessage, pairing::PairingSharedKey) {
    // extract the PairingContactMessageMaterial from the contact message
    let pairing_request = pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: pair_request_message.mlkem_ciphertext.clone(),
        ecies_public_key: pair_request_message.ecies_public_key.clone(),
    };

    let response_msg = derec_proto::PairResponseMessage {
        sender_kind: kind.into(),
        result: Some(derec_proto::Result { status: 0, memo: String::new() }),
        nonce: pair_request_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    // generate the shared key material
    let sk = pairing::finish_pairing_contactor(
        &pairing_secret_key_material,
        &pairing_request
    ).expect("Failed to finish pairing contactor");

    (response_msg, sk)
}

pub fn process_pairing_response_message(
    contact_message: &derec_proto::ContactMessage,
    _pair_response_message: &derec_proto::PairResponseMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial
) -> pairing::PairingSharedKey {
    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let sk = pairing::finish_pairing_requestor(
        &pairing_secret_key_material,
        &pk
    ).expect("Failed to finish pairing helper");

    sk
}

#[cfg(test)]
mod tests {
    use super::*;

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

}