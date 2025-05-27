use rand::RngCore;
use derec_cryptography::pairing;

pub mod derec_proto {
    // OUT_DIR is where the generated code is stored during compilation
    include!(concat!(env!("OUT_DIR"), "/org.derecalliance.derec.protobuf.rs")); // filename matches proto
}

pub fn create_contact_message(
    channel_id: u64,
    transport_uri: &String
) -> derec_proto::ContactMessage {
    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, _sk) = pairing::contact_message(seed)
        .expect("Failed to generate contact message");

    derec_proto::ContactMessage {
        public_key_id: channel_id,
        transport_uri: transport_uri.clone(),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        message_encoding_type: 0,
    }
}

pub fn produce_pairing_request_message(
    channel_id: u64,
    kind: derec_proto::SenderKind,
    contact_message: &derec_proto::ContactMessage
) -> derec_proto::PairRequestMessage {
    // extract the PairingContactMessageMaterial from the contact message
    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, _sk) = pairing::pairing_request_message(seed, &pk)
        .expect("Failed to generate pairing request message");

    derec_proto::PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: pk.mlkem_ciphertext,
        ecies_public_key: pk.ecies_public_key,
        public_key_id: channel_id,
        nonce: contact_message.nonce,
        communication_info: None,
        parameter_range: None,
    }
}