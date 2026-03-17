use derec_library::derec_message::DeRecMessageBuilder;
use derec_library::derec_message::{
    DeRecMessageCodec, DeRecMessageCodecError, DeRecMessageDecrypter, DeRecMessageEncrypter,
    DeRecMessageSigner, DeRecMessageVerifier, VerifiedPayload,
};
use derec_library::pairing::{
    create_contact_message, process_pairing_response_message, produce_pairing_request_message,
    produce_pairing_response_message,
};
use derec_library::protocol_version::ProtocolVersion;
use derec_library::recovery::{
    generate_share_request, generate_share_response, recover_from_share_responses,
};
use derec_library::sharing::protect_secret;
use derec_library::types::ChannelId;
use derec_library::verification::{
    generate_verification_request, generate_verification_response, verify_share_response,
};
use derec_proto::{DeRecMessage, GetShareResponseMessage, PairRequestMessage, SenderKind};
use prost::Message;
use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    run_protocol_version_test();
    let pair_request_message = run_pairing_flow_test();
    run_sharing_flow_test();
    run_verification_flow_test();
    run_recovery_flow_test();
    run_derec_message_builder_test(pair_request_message);

    println!("All smoke tests passed.");
}

fn run_protocol_version_test() {
    println!("=== Protocol version test ===");

    let version = ProtocolVersion::current();

    println!("protocol version = {}", version);
    println!("major = {}", version.major);
    println!("minor = {}", version.minor);

    if version.major < 0 || version.minor < 0 {
        panic!("Protocol version test failed.");
    }

    println!("Protocol version test passed.");
}

fn run_pairing_flow_test() -> PairRequestMessage {
    println!("=== Pairing flow test ===");

    let channel_id = ChannelId(1);

    let contact = create_contact_message(channel_id, "https://example.com/alice")
        .expect("Pairing test failed: create_contact_message failed.");

    println!(
        "contact.transport_uri = {}",
        contact.contact_message.transport_uri
    );
    println!(
        "contact.public_key_id = {}",
        contact.contact_message.public_key_id
    );
    println!("contact.nonce = {}", contact.contact_message.nonce);
    println!(
        "contact.transport_protocol = {:?}",
        contact.contact_message.transport_protocol
    );
    println!(
        "contact.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&contact.secret_key)
    );

    if contact.contact_message.transport_uri != "https://example.com/alice" {
        panic!("Pairing test failed: unexpected transport URI.");
    }

    if serialize_pairing_secret_key_material_len(&contact.secret_key) == 0 {
        panic!("Pairing test failed: empty contact secret key material.");
    }

    let pair_request =
        produce_pairing_request_message(channel_id, SenderKind::Helper, &contact.contact_message)
            .expect("Pairing test failed: produce_pairing_request_message failed.");

    println!(
        "pair_request.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&pair_request.secret_key)
    );
    println!(
        "pair_request_message = {:?}",
        pair_request.pair_request_message
    );

    if serialize_pairing_secret_key_material_len(&pair_request.secret_key) == 0 {
        panic!("Pairing test failed: empty pair request secret key material.");
    }

    let pair_response = produce_pairing_response_message(
        SenderKind::SharerNonRecovery,
        &pair_request.pair_request_message,
        &contact.secret_key,
    )
    .expect("Pairing test failed: produce_pairing_response_message failed.");

    println!(
        "pair_response.shared_key bytes = {}",
        pair_response.shared_key.len()
    );
    println!(
        "pair_response_message = {:?}",
        pair_response.pair_response_message
    );

    if pair_response.shared_key.is_empty() {
        panic!("Pairing test failed: empty pair response shared key.");
    }

    let processed = process_pairing_response_message(
        &contact.contact_message,
        &pair_response.pair_response_message,
        &pair_request.secret_key,
    )
    .expect("Pairing test failed: process_pairing_response_message failed.");

    println!(
        "processed.shared_key bytes = {}",
        processed.shared_key.len()
    );

    if processed.shared_key.is_empty() {
        panic!("Pairing test failed: empty processed shared key.");
    }

    let shared_keys_equal = pair_response.shared_key == processed.shared_key;

    println!("shared keys equal = {}", shared_keys_equal);

    if !shared_keys_equal {
        panic!("Pairing test failed: shared keys do not match.");
    }

    println!("Pairing flow test passed.");

    pair_request.pair_request_message
}

fn run_sharing_flow_test() {
    println!("=== Sharing flow test ===");

    let secret_id = [1_u8, 2, 3, 4, 255];
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version = 1_i32;

    let keep_list = [1_i32, 2, 3];

    let result = protect_secret(
        secret_id,
        secret_data,
        &channels,
        threshold,
        version,
        Some(&keep_list),
        Some("v1 initial distribution"),
    )
    .expect("Sharing test failed: protect_secret failed.");

    println!("shares count = {}", result.shares.len());

    if result.shares.len() != channels.len() {
        panic!(
            "Sharing test failed: expected {} shares but got {}.",
            channels.len(),
            result.shares.len()
        );
    }

    for channel in &channels {
        if !result.shares.contains_key(channel) {
            panic!(
                "Sharing test failed: missing share for channel {:?}.",
                channel
            );
        }
    }

    for (channel, message) in &result.shares {
        println!("channel = {:?}", channel);
        println!("store_share_request = {:?}", message);
    }

    println!("Sharing flow test passed.");
}

fn run_verification_flow_test() {
    println!("=== Verification flow test ===");

    let secret_id = [1_u8, 2, 3, 4, 255];
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version = 1_i32;

    let keep_list = [1_i32, 2, 3];

    let sharing = protect_secret(
        secret_id,
        secret_data,
        &channels,
        threshold,
        version,
        Some(&keep_list),
        Some("v1 initial distribution"),
    )
    .expect("Verification test failed: protect_secret failed.");

    let share_message = sharing
        .shares
        .get(&ChannelId(1))
        .expect("Verification test failed: missing share for channel 1.");

    let share_content = share_message.share.clone();

    let request = generate_verification_request(secret_id, version)
        .expect("Verification test failed: generate_verification_request failed.");
    println!("verification_request = {:?}", request);

    let response =
        generate_verification_response(secret_id, ChannelId(1), &share_content, &request)
            .expect("Verification test failed: generate_verification_response failed.");
    println!("verification_response = {:?}", response);

    let valid = verify_share_response(secret_id, ChannelId(1), &share_content, &response)
        .expect("Verification test failed: verify_share_response failed for valid case.");

    println!("verification valid = {}", valid);

    if !valid {
        panic!("Verification test failed: expected valid response.");
    }

    let wrong_share_message = sharing
        .shares
        .get(&ChannelId(2))
        .expect("Verification test failed: missing share for channel 2.");

    let wrong_share_content = wrong_share_message.share.clone();

    let invalid = verify_share_response(secret_id, ChannelId(1), &wrong_share_content, &response)
        .expect("Verification test failed: verify_share_response failed for invalid case.");

    println!("verification invalid case = {}", invalid);

    if invalid {
        panic!("Verification test failed: expected invalid response for wrong share.");
    }

    println!("Verification flow test passed.");
}

fn run_recovery_flow_test() {
    println!("=== Recovery flow test ===");

    let secret_id = [1_u8, 2, 3, 4, 255];
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version = 1_i32;

    let keep_list = [1_i32, 2, 3];

    let sharing = protect_secret(
        secret_id,
        secret_data,
        &channels,
        threshold,
        version,
        Some(&keep_list),
        Some("v1 initial distribution"),
    )
    .expect("Recovery test failed: protect_secret failed.");

    let share_request = generate_share_request(ChannelId(1), secret_id, version)
        .expect("Recovery test failed: generate_share_request failed.");
    println!("share_request = {:?}", share_request);

    let mut responses: Vec<GetShareResponseMessage> = Vec::new();

    for channel in &channels {
        let store_share_request = sharing.shares.get(channel).unwrap_or_else(|| {
            panic!(
                "Recovery test failed: missing share for channel {:?}.",
                channel
            )
        });

        let share_response =
            generate_share_response(*channel, secret_id, &share_request, store_share_request)
                .unwrap_or_else(|_| {
                    panic!(
                        "Recovery test failed: generate_share_response failed for channel {:?}.",
                        channel
                    )
                });

        println!("share_response[{channel:?}] = {:?}", share_response);
        responses.push(share_response);
    }

    let recovered = recover_from_share_responses(&responses, secret_id, version)
        .expect("Recovery test failed: recover_from_share_responses failed.");

    println!("recovered bytes = {}", recovered.len());
    println!(
        "recovered matches original = {}",
        recovered.as_slice() == secret_data
    );

    if recovered.as_slice() != secret_data {
        panic!("Recovery test failed: recovered secret does not match original.");
    }

    println!("Recovery flow test passed.");
}

fn run_derec_message_builder_test(pair_request: PairRequestMessage) {
    println!("=== DeRecMessage builder/codec test ===");

    let sender = vec![0x11; 48];
    let receiver = vec![0x22; 48];
    let secret_id = vec![1_u8, 2, 3, 4];
    let timestamp = current_timestamp();

    let derec_message = DeRecMessageBuilder::new()
        .sender(&sender)
        .receiver(&receiver)
        .secret_id(&secret_id)
        .expect("DeRecMessage builder test failed: secret_id rejected.")
        .timestamp(timestamp)
        .message(pair_request)
        .expect("DeRecMessage builder test failed: message rejected.")
        .build()
        .expect("DeRecMessage builder test failed: build failed.");

    if derec_message.protocol_version_major < 0 || derec_message.protocol_version_minor < 0 {
        panic!("DeRecMessage builder test failed: invalid protocol version.");
    }

    if derec_message.sender.len() != 48 {
        panic!("DeRecMessage builder test failed: invalid sender length.");
    }

    if derec_message.receiver.len() != 48 {
        panic!("DeRecMessage builder test failed: invalid receiver length.");
    }

    if derec_message.secret_id.len() != 4 {
        panic!("DeRecMessage builder test failed: invalid secret_id length.");
    }

    if derec_message.timestamp.is_none() {
        panic!("DeRecMessage builder test failed: missing timestamp.");
    }

    let message_bodies = derec_message
        .message_bodies
        .as_ref()
        .expect("DeRecMessage builder test failed: missing message bodies.");

    match &message_bodies.messages {
        Some(derec_proto::de_rec_message::message_bodies::Messages::SharerMessageBodies(
            bodies,
        )) => {
            if bodies.sharer_message_body.len() != 1 {
                panic!("DeRecMessage builder test failed: expected exactly one message body.");
            }
        }
        _ => panic!("DeRecMessage builder test failed: expected owner/sharer message bodies."),
    }

    println!("DeRecMessage built successfully.");

    let serialized = derec_message.encode_to_vec();
    println!("Serialized size = {}", serialized.len());

    let deserialized = DeRecMessage::decode(serialized.as_slice())
        .expect("DeRecMessage codec test failed: deserialization failed.");

    if derec_message != deserialized {
        panic!("DeRecMessage codec test failed: deserialize(serialize(x)) != x.");
    }

    println!("Serialize/deserialize roundtrip OK.");

    let signer = DummySigner::new(sender.clone());
    let verifier = DummyVerifier::new(sender.clone());
    let encrypter = DummyEncrypter::new(42, receiver.clone());
    let decrypter = DummyDecrypter::new(42, receiver.clone());

    let wire_bytes = DeRecMessageCodec::encode_to_bytes(&derec_message, &signer, &encrypter)
        .expect("DeRecMessage codec test failed: encode_to_bytes failed.");

    println!("Wire size = {}", wire_bytes.len());

    let decoded = DeRecMessageCodec::decode_from_bytes(&wire_bytes, &decrypter, &verifier)
        .expect("DeRecMessage codec test failed: decode_from_bytes failed.");

    if derec_message != decoded {
        panic!("DeRecMessage codec test failed: decode(encode(x)) != x.");
    }

    println!("Encode/decode roundtrip OK.");
    println!("DeRecMessage builder/codec test passed.");
}

fn current_timestamp() -> Timestamp {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards");

    Timestamp {
        seconds: now.as_secs() as i64,
        nanos: now.subsec_nanos() as i32,
    }
}

fn serialize_pairing_secret_key_material_len(
    sk: &derec_cryptography::pairing::PairingSecretKeyMaterial,
) -> usize {
    let mut len = 0_usize;

    len += 1;
    if let Some(v) = sk.mlkem_decapsulation_key.as_ref() {
        len += 4 + v.len();
    }

    len += 1;
    if sk.mlkem_shared_secret.is_some() {
        len += 4 + 32;
    }

    len += 4 + sk.ecies_secret_key.len();

    len
}

struct DummySigner {
    sender_key_hash: Vec<u8>,
}

impl DummySigner {
    fn new(sender_key_hash: Vec<u8>) -> Self {
        Self { sender_key_hash }
    }
}

impl DeRecMessageSigner for DummySigner {
    fn sender_key_hash(&self) -> &[u8] {
        &self.sender_key_hash
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        let mut output = vec![9, 9, 9];
        output.extend_from_slice(payload);
        Ok(output)
    }
}

struct DummyVerifier {
    sender_key_hash: Vec<u8>,
}

impl DummyVerifier {
    fn new(sender_key_hash: Vec<u8>) -> Self {
        Self { sender_key_hash }
    }
}

impl DeRecMessageVerifier for DummyVerifier {
    fn verify(&self, signed_payload: &[u8]) -> Result<VerifiedPayload, DeRecMessageCodecError> {
        if signed_payload.len() < 3 {
            return Err(DeRecMessageCodecError::Verification(
                "dummy verifier failed: signed payload too short".to_string(),
            ));
        }

        Ok(VerifiedPayload {
            payload: signed_payload[3..].to_vec(),
            signer_key_hash: self.sender_key_hash.clone(),
        })
    }
}

struct DummyEncrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
}

impl DummyEncrypter {
    fn new(recipient_key_id: i32, recipient_key_hash: Vec<u8>) -> Self {
        Self {
            recipient_key_id,
            recipient_key_hash,
        }
    }
}

impl DeRecMessageEncrypter for DummyEncrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn encrypt(&self, signed_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        let mut copy = signed_payload.to_vec();
        copy.reverse();
        Ok(copy)
    }
}

struct DummyDecrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
}

impl DummyDecrypter {
    fn new(recipient_key_id: i32, recipient_key_hash: Vec<u8>) -> Self {
        Self {
            recipient_key_id,
            recipient_key_hash,
        }
    }
}

impl DeRecMessageDecrypter for DummyDecrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        let mut copy = encrypted_payload.to_vec();
        copy.reverse();
        Ok(copy)
    }
}
