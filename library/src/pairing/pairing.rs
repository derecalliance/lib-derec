use rand::RngCore;
use derec_cryptography::pairing;
use crate::protos::derec_proto;


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