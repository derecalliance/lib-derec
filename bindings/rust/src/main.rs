use derec_library::pairing::{
    create_contact_message, process_pairing_response_message, produce_pairing_request_message,
    produce_pairing_response_message,
};
use derec_library::protocol_version::ProtocolVersion;
use derec_library::recovery::{
    RecoveryResponseInput, generate_share_request, generate_share_response,
    recover_from_share_responses,
};
use derec_library::sharing::protect_secret;
use derec_library::types::ChannelId;
use derec_library::verification::{
    generate_verification_request, generate_verification_response, verify_share_response,
};
use derec_proto::{ContactMessage, Protocol, SenderKind, TransportProtocol};
use prost::Message;
use std::collections::HashMap;

fn main() {
    run_protocol_version_test();
    run_pairing_flow_test();
    run_sharing_flow_test();
    run_verification_flow_test();
    run_recovery_flow_test();

    println!("All smoke tests passed.");
}

fn run_protocol_version_test() {
    println!("=== Protocol version test ===");

    let version = ProtocolVersion::current();

    println!("protocol version = {}", version);
    println!("major = {}", version.major);
    println!("minor = {}", version.minor);

    println!("Protocol version test passed.");
}

fn run_pairing_flow_test() {
    println!("=== Pairing flow test ===");

    let channel_id = ChannelId(1);

    let contact = create_contact_message(channel_id, TransportProtocol {
        uri: "https://example.com/alice".to_owned(),
        protocol: Protocol::Https.into(),
    })
    .expect("Pairing test failed: create_contact_message failed.");

    println!("contact.wire_bytes = {}", contact.wire_bytes.len());
    println!(
        "contact.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&contact.secret_key)
    );

    if contact.wire_bytes.is_empty() {
        panic!("Pairing test failed: empty contact wire bytes.");
    }

    if serialize_pairing_secret_key_material_len(&contact.secret_key) == 0 {
        panic!("Pairing test failed: empty contact secret key material.");
    }

    let decoded_contact = ContactMessage::decode(contact.wire_bytes.as_slice())
        .expect("Pairing test failed: failed to decode contact wire bytes.");

    let transport = decoded_contact
        .transport_protocol
        .as_ref()
        .expect("Pairing test failed: contact missing transport_protocol.");

    println!("contact.channel_id = {}", decoded_contact.channel_id);
    println!("contact.nonce = {}", decoded_contact.nonce);
    println!("contact.transport_protocol.uri = {}", transport.uri);
    println!(
        "contact.transport_protocol.protocol = {:?}",
        transport.protocol()
    );

    if transport.uri != "https://example.com/alice" {
        panic!("Pairing test failed: unexpected transport URI.");
    }

    if transport.protocol() != Protocol::Https {
        panic!("Pairing test failed: unexpected transport protocol.");
    }

    let pair_request = produce_pairing_request_message(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://example.com/helper".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &contact.wire_bytes,
    )
    .expect("Pairing test failed: produce_pairing_request_message failed.");

    let initiator_tp = pair_request
        .initiator_contact_message
        .transport_protocol
        .as_ref()
        .expect("initiator_contact_message should have transport_protocol");

    println!(
        "pair_request.wire_bytes = {}",
        pair_request.wire_bytes.len()
    );
    println!(
        "pair_request.initiator_contact_message.transport_protocol.uri = {}",
        initiator_tp.uri
    );
    println!(
        "pair_request.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&pair_request.secret_key)
    );

    if pair_request.wire_bytes.is_empty() {
        panic!("Pairing test failed: empty pair request wire bytes.");
    }

    if initiator_tp.uri != "https://example.com/alice" {
        panic!("Pairing test failed: initiator_contact_message URI does not match contact message.");
    }

    if initiator_tp.protocol() != Protocol::Https {
        panic!("Pairing test failed: initiator_contact_message protocol does not match contact message.");
    }

    if serialize_pairing_secret_key_material_len(&pair_request.secret_key) == 0 {
        panic!("Pairing test failed: empty pair request secret key material.");
    }

    let pair_response = produce_pairing_response_message(
        SenderKind::OwnerNonRecovery,
        &pair_request.wire_bytes,
        &contact.secret_key,
    )
    .expect("Pairing test failed: produce_pairing_response_message failed.");

    println!(
        "pair_response.wire_bytes = {}",
        pair_response.wire_bytes.len()
    );
    println!(
        "pair_response.shared_key bytes = {}",
        pair_response.shared_key.len()
    );
    println!(
        "pair_response.responder_transport_protocol = {:?}",
        pair_response.responder_transport_protocol
    );

    if pair_response.wire_bytes.is_empty() {
        panic!("Pairing test failed: empty pair response wire bytes.");
    }

    if pair_response.shared_key.is_empty() {
        panic!("Pairing test failed: empty pair response shared key.");
    }

    let processed = process_pairing_response_message(
        pair_request.initiator_contact_message,
        &pair_response.wire_bytes,
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
}

fn run_sharing_flow_test() {
    println!("=== Sharing flow test ===");

    let secret_id = [1_u8, 2, 3, 4, 255];
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version = 1_i32;

    let keep_list = [1_i32, 2, 3];
    let shared_keys = make_shared_keys(&channels);

    let result = protect_secret(
        secret_id,
        secret_data,
        &shared_keys,
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

    for (channel, bytes) in &result.shares {
        println!("channel = {:?}", channel);
        println!("share wire bytes = {}", bytes.len());

        if bytes.is_empty() {
            panic!(
                "Sharing test failed: empty share bytes for channel {:?}.",
                channel
            );
        }
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
    let shared_keys = make_shared_keys(&channels);

    let sharing = protect_secret(
        secret_id,
        secret_data,
        &shared_keys,
        threshold,
        version,
        Some(&keep_list),
        Some("v1 initial distribution"),
    )
    .expect("Verification test failed: protect_secret failed.");

    let channel_1 = ChannelId(1);
    let channel_2 = ChannelId(2);

    let stored_share_request_wire_bytes_1 = sharing
        .shares
        .get(&channel_1)
        .expect("Verification test failed: missing share for channel 1.");

    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("Verification test failed: missing shared key for channel 1.");

    let request = generate_verification_request(secret_id, channel_1, version, shared_key_1)
        .expect("Verification test failed: generate_verification_request failed.");
    println!(
        "verification_request wire bytes = {}",
        request.wire_bytes.len()
    );

    let response = generate_verification_response(
        secret_id,
        channel_1,
        shared_key_1,
        stored_share_request_wire_bytes_1,
        &request.wire_bytes,
    )
    .expect("Verification test failed: generate_verification_response failed.");
    println!(
        "verification_response wire bytes = {}",
        response.wire_bytes.len()
    );

    let valid = verify_share_response(
        secret_id,
        channel_1,
        shared_key_1,
        stored_share_request_wire_bytes_1,
        &response.wire_bytes,
    )
    .expect("Verification test failed: verify_share_response failed for valid case.");

    println!("verification valid = {}", valid);

    if !valid {
        panic!("Verification test failed: expected valid response.");
    }

    let stored_share_request_wire_bytes_2 = sharing
        .shares
        .get(&channel_2)
        .expect("Verification test failed: missing share for channel 2.");

    let invalid = verify_share_response(
        secret_id,
        channel_1,
        shared_key_1,
        stored_share_request_wire_bytes_2,
        &response.wire_bytes,
    )
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
    let shared_keys = make_shared_keys(&channels);

    let sharing = protect_secret(
        secret_id,
        secret_data,
        &shared_keys,
        threshold,
        version,
        Some(&keep_list),
        Some("v1 initial distribution"),
    )
    .expect("Recovery test failed: protect_secret failed.");

    let channel_1 = ChannelId(1);
    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("Recovery test failed: missing shared key for channel 1.");

    let stored_share_request_wire_bytes_1 = sharing
        .shares
        .get(&channel_1)
        .unwrap_or_else(|| panic!("Recovery test failed: missing share for channel 1."));

    let share_request_1 = generate_share_request(channel_1, &secret_id, version, shared_key_1)
        .expect("Recovery test failed: generate_share_request failed for channel 1.");
    println!(
        "share_request[1] wire bytes = {}",
        share_request_1.wire_bytes.len()
    );

    let share_response_1 = generate_share_response(
        channel_1,
        &secret_id,
        &share_request_1.wire_bytes,
        stored_share_request_wire_bytes_1,
        shared_key_1,
    )
    .unwrap_or_else(|_| {
        panic!("Recovery test failed: generate_share_response failed for channel 1.",)
    });

    println!(
        "share_response[1] wire bytes = {}",
        share_response_1.wire_bytes.len()
    );

    let channel_2 = ChannelId(2);
    let shared_key_2 = shared_keys
        .get(&channel_2)
        .expect("Recovery test failed: missing shared key for channel 2.");

    let stored_share_request_wire_bytes_2 = sharing
        .shares
        .get(&channel_2)
        .unwrap_or_else(|| panic!("Recovery test failed: missing share for channel 2.",));

    let share_request_2 = generate_share_request(channel_2, &secret_id, version, shared_key_2)
        .expect("Recovery test failed: generate_share_request failed for channel 2.");
    println!(
        "share_request[2] wire bytes = {}",
        share_request_2.wire_bytes.len()
    );

    let share_response_2 = generate_share_response(
        channel_2,
        &secret_id,
        &share_request_2.wire_bytes,
        stored_share_request_wire_bytes_2,
        shared_key_2,
    )
    .unwrap_or_else(|_| {
        panic!("Recovery test failed: generate_share_response failed for channel 2.",)
    });

    println!(
        "share_response[2] wire bytes = {}",
        share_response_2.wire_bytes.len()
    );

    let response_wire_bytes = vec![
        RecoveryResponseInput {
            bytes: &share_response_1.wire_bytes,
            shared_key: shared_key_1,
        },
        RecoveryResponseInput {
            bytes: &share_response_2.wire_bytes,
            shared_key: shared_key_2,
        },
    ];

    //

    let recovered = recover_from_share_responses(&secret_id, version, &response_wire_bytes)
        .expect("Recovery test failed: recover_from_share_responses failed.");

    println!("recovered bytes = {}", recovered.secret_data.len());
    println!(
        "recovered matches original = {}",
        recovered.secret_data.as_slice() == secret_data
    );

    if recovered.secret_data.as_slice() != secret_data {
        panic!("Recovery test failed: recovered secret does not match original.");
    }

    println!("Recovery flow test passed.");
}

fn make_shared_keys(channels: &[ChannelId]) -> HashMap<ChannelId, [u8; 32]> {
    let mut out = HashMap::with_capacity(channels.len());

    for (i, channel) in channels.iter().enumerate() {
        let mut key = [0u8; 32];
        key.fill((i + 1) as u8);
        out.insert(*channel, key);
    }

    out
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
