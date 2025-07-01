use rand::RngCore;
use derec_cryptography::pairing;

#[derive(uniffi::Record)]
pub struct ContactMessageWrapper {
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
    pub public_key_id: u64,
    pub nonce: u64,
    pub transport_uri: String,
    pub message_encoding_type: i32,
}

#[derive(uniffi::Record)]
pub struct PairingSecretKeyMaterialWrapper {
    pub mlkem_decapsulation_key: Option<Vec<u8>>,
    pub mlkem_shared_secret: Option<Vec<u8>>,
    pub ecies_secret_key: Vec<u8>,
}


#[derive(uniffi::Record)]
pub struct ContactMessageResult {
    pub contact_message: ContactMessageWrapper,
    pub secret_key_material: PairingSecretKeyMaterialWrapper,
}


#[derive(uniffi::Record)]
pub struct PairRequestMessageWrapper {
    pub sender_kind: i32,
    pub mlkem_ciphertext: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
    pub public_key_id: u64,
    pub nonce: u64,
}


#[derive(uniffi::Record)]
pub struct PairResponseMessageWrapper {
    pub sender_kind: i32,
    pub result_status: i32,
    pub result_memo: String,
    pub nonce: u64,
}


#[derive(uniffi::Record)]
pub struct PairingRequestResult {
    pub request_message: PairRequestMessageWrapper,
    pub secret_key_material: PairingSecretKeyMaterialWrapper,
}


#[derive(uniffi::Record)]
pub struct PairingResponseResult {
    pub response_message: PairResponseMessageWrapper,
    pub shared_key: Vec<u8>,
}


fn convert_secret_key_material(sk: pairing::PairingSecretKeyMaterial) -> PairingSecretKeyMaterialWrapper {
    PairingSecretKeyMaterialWrapper {
        mlkem_decapsulation_key: sk.mlkem_decapsulation_key,
        mlkem_shared_secret: sk.mlkem_shared_secret.map(|s| s.to_vec()),
        ecies_secret_key: sk.ecies_secret_key,
    }
}


fn convert_contact_message_to_material(contact_msg: &ContactMessageWrapper) -> pairing::PairingContactMessageMaterial {
    pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_msg.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_msg.ecies_public_key.clone(),
    }
}

fn convert_wrapper_to_secret_key_material(wrapper: &PairingSecretKeyMaterialWrapper) -> pairing::PairingSecretKeyMaterial {
    pairing::PairingSecretKeyMaterial {
        mlkem_decapsulation_key: wrapper.mlkem_decapsulation_key.clone(),
        mlkem_shared_secret: wrapper.mlkem_shared_secret.as_ref().map(|s| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&s[..32]);
            arr
        }),
        ecies_secret_key: wrapper.ecies_secret_key.clone(),
    }
}

#[uniffi::export]
pub fn create_contact_message(
    channel_id: u64,
    transport_uri: &String
) -> ContactMessageResult {
    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, sk) = pairing::contact_message(seed)
        .expect("Failed to generate contact message");

    let contact_msg = ContactMessageWrapper {
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        public_key_id: channel_id,
        transport_uri: transport_uri.clone(),
        nonce: rng.next_u64(),
        message_encoding_type: 0,
    };

    let secret_wrapper = convert_secret_key_material(sk);

    ContactMessageResult {
        contact_message: contact_msg,
        secret_key_material: secret_wrapper,
    }
}

#[uniffi::export]
pub fn produce_pairing_request_message(
    channel_id: u64,
    kind: i32,
    contact_message: &ContactMessageWrapper
) -> PairingRequestResult {
    // extract the PairingContactMessageMaterial from the contact message
    let pk = convert_contact_message_to_material(contact_message);

    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let (pk, sk) = pairing::pairing_request_message(seed, &pk)
        .expect("Failed to generate pairing request message");

    let request_msg = PairRequestMessageWrapper {
        sender_kind: kind,
        mlkem_ciphertext: pk.mlkem_ciphertext,
        ecies_public_key: pk.ecies_public_key,
        public_key_id: channel_id,
        nonce: contact_message.nonce,
    };

    let secret_wrapper = convert_secret_key_material(sk);

    PairingRequestResult {
        request_message: request_msg,
        secret_key_material: secret_wrapper,
    }
}

#[uniffi::export]
pub fn produce_pairing_response_message(
    kind: i32,
    pair_request_message: &PairRequestMessageWrapper,
    pairing_secret_key_material: &PairingSecretKeyMaterialWrapper
) -> PairingResponseResult {
    // extract the PairingContactMessageMaterial from the contact message
    let pairing_request = pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: pair_request_message.mlkem_ciphertext.clone(),
        ecies_public_key: pair_request_message.ecies_public_key.clone(),
    };

    let response_msg = PairResponseMessageWrapper {
        sender_kind: kind,
        result_status: 0,
        result_memo: String::new(),
        nonce: pair_request_message.nonce,
    };

    // generate the shared key material
    let sk = pairing::finish_pairing_contactor(
        &convert_wrapper_to_secret_key_material(pairing_secret_key_material),
        &pairing_request
    ).expect("Failed to finish pairing contactor");

    PairingResponseResult {
        response_message: response_msg,
        shared_key: sk.to_vec(),
    }
}

#[uniffi::export]
pub fn process_pairing_response_message(
    contact_message: &ContactMessageWrapper,
    _pair_response_message: &PairResponseMessageWrapper,
    pairing_secret_key_material: &PairingSecretKeyMaterialWrapper
) -> Vec<u8> {
    let pk = convert_contact_message_to_material(contact_message);

    let sk = pairing::finish_pairing_requestor(
        &convert_wrapper_to_secret_key_material(pairing_secret_key_material),
        &pk
    ).expect("Failed to finish pairing helper");

    sk.to_vec()
}