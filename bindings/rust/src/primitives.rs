use derec_library::primitives::pairing::{request as pair_request, response as pair_response};
use derec_library::primitives::recovery::{
    request as rec_request,
    response::{self as rec_response, RecoveryResponseInput},
};
use derec_library::primitives::sharing::{request as share_request, response as share_response};
use derec_library::primitives::verification::{request as verif_request, response as verif_response};
use derec_library::types::ChannelId;
use derec_proto::{Protocol, SenderKind, TransportProtocol};
use prost::Message;
use std::collections::HashMap;

pub fn run_all() {
    run_protocol_version_test();
    run_pairing_flow_test();
    run_sharing_flow_test();
    run_verification_flow_test();
    run_recovery_flow_test();
}

fn run_protocol_version_test() {
    println!("=== Protocol version test ===");

    let version = derec_library::protocol_version::ProtocolVersion::current();

    println!("protocol version = {}", version);
    println!("major = {}", version.major);
    println!("minor = {}", version.minor);

    println!("Protocol version test passed.");
}

fn run_pairing_flow_test() {
    println!("=== Pairing flow test ===");

    let channel_id = ChannelId(1);

    let contact_result = pair_request::create_contact(
        channel_id,
        TransportProtocol {
            uri: "https://example.com/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("Pairing test failed: pair_request::create_contact failed.");

    let contact_wire_bytes = contact_result.contact_message.encode_to_vec();

    println!("contact.wire_bytes = {}", contact_wire_bytes.len());
    println!(
        "contact.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&contact_result.secret_key)
    );

    if contact_wire_bytes.is_empty() {
        panic!("Pairing test failed: empty contact wire bytes.");
    }

    if serialize_pairing_secret_key_material_len(&contact_result.secret_key) == 0 {
        panic!("Pairing test failed: empty contact secret key material.");
    }

    let decoded_contact = contact_result.contact_message.clone();

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

    let pair_req = pair_request::produce(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://example.com/helper".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &decoded_contact,
    )
    .expect("Pairing test failed: pair_request::produce failed.");

    let pair_request_wire_bytes = pair_req.envelope.clone();

    let initiator_tp = pair_req
        .initiator_contact_message
        .transport_protocol
        .as_ref()
        .expect("initiator_contact_message should have transport_protocol");

    println!(
        "pair_request.wire_bytes = {}",
        pair_request_wire_bytes.len()
    );
    println!(
        "pair_request.initiator_contact_message.transport_protocol.uri = {}",
        initiator_tp.uri
    );
    println!(
        "pair_request.secret_key_material bytes = {}",
        serialize_pairing_secret_key_material_len(&pair_req.secret_key)
    );

    if pair_request_wire_bytes.is_empty() {
        panic!("Pairing test failed: empty pair request wire bytes.");
    }

    if initiator_tp.uri != "https://example.com/alice" {
        panic!(
            "Pairing test failed: initiator_contact_message URI does not match contact message."
        );
    }

    if initiator_tp.protocol() != Protocol::Https {
        panic!(
            "Pairing test failed: initiator_contact_message protocol does not match contact message."
        );
    }

    if serialize_pairing_secret_key_material_len(&pair_req.secret_key) == 0 {
        panic!("Pairing test failed: empty pair request secret key material.");
    }

    let extracted_request =
        pair_request::extract(&pair_req.envelope, contact_result.secret_key.ecies_secret_key())
            .expect("Pairing test failed: pair_request::extract failed.");

    let pair_resp = pair_response::produce(
        SenderKind::OwnerNonRecovery,
        &extracted_request.request,
        &contact_result.secret_key,
    )
    .expect("Pairing test failed: pair_response::produce failed.");

    let pair_response_wire_bytes = pair_resp.envelope.clone();

    println!(
        "pair_response.wire_bytes = {}",
        pair_response_wire_bytes.len()
    );
    println!(
        "pair_response.shared_key bytes = {}",
        pair_resp.shared_key.len()
    );
    println!(
        "pair_response.responder_transport_protocol = {:?}",
        pair_resp.responder_transport_protocol
    );

    if pair_response_wire_bytes.is_empty() {
        panic!("Pairing test failed: empty pair response wire bytes.");
    }

    if pair_resp.shared_key.is_empty() {
        panic!("Pairing test failed: empty pair response shared key.");
    }

    let extracted_response = pair_response::extract(
        &pair_resp.envelope,
        pair_req.secret_key.ecies_secret_key(),
    )
    .expect("Pairing test failed: pair_response::extract failed.");

    let processed = pair_response::process(
        &pair_req.initiator_contact_message,
        &extracted_response.response,
        &pair_req.secret_key,
    )
    .expect("Pairing test failed: pair_response::process failed.");

    println!(
        "processed.shared_key bytes = {}",
        processed.shared_key.len()
    );

    if processed.shared_key.is_empty() {
        panic!("Pairing test failed: empty processed shared key.");
    }

    let shared_keys_equal = pair_resp.shared_key == processed.shared_key;

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

    let split_result = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("Sharing test failed: share_request::split failed.");

    println!("shares count = {}", split_result.shares.len());

    if split_result.shares.len() != channels.len() {
        panic!(
            "Sharing test failed: expected {} shares but got {}.",
            channels.len(),
            split_result.shares.len()
        );
    }

    for channel in &channels {
        if !split_result.shares.contains_key(channel) {
            panic!(
                "Sharing test failed: missing share for channel {:?}.",
                channel
            );
        }
    }

    let shared_key = [42u8; 32];

    for (channel, share) in &split_result.shares {
        println!("channel = {:?}", channel);
        println!("  commitment bytes = {}", share.commitment.len());
        println!("  merkle_path nodes = {}", share.merkle_path.len());

        if let Ok(de_rec_share) = derec_proto::DeRecShare::decode(share.de_rec_share.as_slice()) {
            println!("  de_rec_share.version = {}", de_rec_share.version);
            println!("  de_rec_share.secret_id bytes = {}", de_rec_share.secret_id.len());
            println!("  de_rec_share.x bytes = {}", de_rec_share.x.len());
            println!("  de_rec_share.y bytes = {}", de_rec_share.y.len());
            println!("  de_rec_share.encrypted_secret bytes = {}", de_rec_share.encrypted_secret.len());
        }

        for (i, node) in share.merkle_path.iter().enumerate() {
            println!("  merkle_path[{}] is_left={} hash_bytes={}", i, node.is_left, node.hash.len());
        }

        if share.commitment.is_empty() {
            panic!(
                "Sharing test failed: empty commitment for channel {:?}.",
                channel
            );
        }

        let store_result = share_request::produce(
            *channel,
            version,
            &secret_id,
            share,
            &[],
            "",
            &shared_key,
        )
        .unwrap_or_else(|_| {
            panic!(
                "Sharing test failed: share_request::produce failed for channel {:?}.",
                channel
            )
        });

        let store_request_wire_bytes = store_result.envelope.clone();
        println!(
            "store_share_request wire bytes = {}",
            store_request_wire_bytes.len()
        );

        if store_request_wire_bytes.is_empty() {
            panic!(
                "Sharing test failed: empty store share request wire bytes for channel {:?}.",
                channel
            );
        }

        let extracted_req = share_request::extract(&store_request_wire_bytes, &shared_key)
            .unwrap_or_else(|e| {
                panic!(
                    "Sharing test failed: share_request::extract failed for channel {:?}: {}",
                    channel, e
                )
            });

        let processed = share_response::produce(*channel, &extracted_req.request, &shared_key)
            .unwrap_or_else(|_| {
                panic!(
                    "Sharing test failed: share_response::produce failed for channel {:?}.",
                    channel
                )
            });

        let response_wire_bytes = processed.envelope.clone();
        println!(
            "store_share_response wire bytes = {}",
            response_wire_bytes.len()
        );
        println!(
            "  stored committed_share: commitment_bytes={} merkle_path_nodes={}",
            processed.committed_share.commitment.len(),
            processed.committed_share.merkle_path.len()
        );
        if let Ok(stored_de_rec_share) =
            derec_proto::DeRecShare::decode(processed.committed_share.de_rec_share.as_slice())
        {
            println!(
                "  stored de_rec_share: version={} x_bytes={} y_bytes={}",
                stored_de_rec_share.version,
                stored_de_rec_share.x.len(),
                stored_de_rec_share.y.len()
            );
        }
        println!("secret_id bytes = {}", processed.secret_id.len());
        println!("version = {}", processed.version);

        if response_wire_bytes.is_empty() {
            panic!(
                "Sharing test failed: empty response wire bytes for channel {:?}.",
                channel
            );
        }

        if processed.committed_share.commitment.is_empty() {
            panic!(
                "Sharing test failed: empty committed_share commitment for channel {:?}.",
                channel
            );
        }

        if processed.secret_id.is_empty() {
            panic!(
                "Sharing test failed: empty secret_id for channel {:?}.",
                channel
            );
        }

        if processed.version != version {
            panic!(
                "Sharing test failed: version mismatch for channel {:?}: expected {}, got {}.",
                channel, version, processed.version
            );
        }

        let extracted_resp = share_response::extract(&response_wire_bytes, &shared_key)
            .unwrap_or_else(|e| {
                panic!(
                    "Sharing test failed: share_response::extract failed for channel {:?}: {}",
                    channel, e
                )
            });

        share_response::process(version, &extracted_resp.response)
            .unwrap_or_else(|e| {
                panic!(
                    "Sharing test failed: share_response::process failed for channel {:?}: {}",
                    channel, e
                )
            });

        println!("store_share_response validated ok");
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

    let shared_keys = make_shared_keys(&channels);

    let sharing = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("Verification test failed: share_request::split failed.");

    let channel_1 = ChannelId(1);
    let channel_2 = ChannelId(2);

    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("Verification test failed: missing shared key for channel 1.");

    let stored_wire_1 = share_request::produce(
        channel_1,
        version,
        &secret_id,
        &sharing.shares[&channel_1],
        &[],
        "",
        shared_key_1,
    )
    .expect("Verification test failed: share_request::produce failed for channel 1.")
    .envelope;

    let stored_wire_2 = share_request::produce(
        channel_2,
        version,
        &secret_id,
        &sharing.shares[&channel_2],
        &[],
        "",
        shared_key_1,
    )
    .expect("Verification test failed: share_request::produce failed for channel 2.")
    .envelope;

    let share_bytes_1 = share_request::extract(&stored_wire_1, shared_key_1)
        .expect("Verification test failed: failed to extract stored share 1.")
        .request
        .share;

    let share_bytes_2 = share_request::extract(&stored_wire_2, shared_key_1)
        .expect("Verification test failed: failed to extract stored share 2.")
        .request
        .share;

    let produced = verif_request::produce(channel_1, &secret_id, version, shared_key_1)
        .expect("Verification test failed: verif_request::produce failed.");

    println!("verification_request wire bytes = {}", produced.envelope.len());

    let request_envelope = derec_proto::DeRecMessage::decode(produced.envelope.as_slice())
        .expect("Verification test failed: failed to decode request envelope.");
    println!("request_envelope.channel_id = {}", request_envelope.channel_id);

    if request_envelope.channel_id != u64::from(channel_1) {
        panic!(
            "Verification test failed: expected channel_id {:?}, got {}.",
            channel_1, request_envelope.channel_id
        );
    }

    let req_result = verif_request::extract(&produced.envelope, shared_key_1)
        .expect("Verification test failed: verif_request::extract failed.");
    println!("req_result.request.secret_id bytes = {}", req_result.request.secret_id.len());
    println!("req_result.request.version = {}", req_result.request.version);
    println!("req_result.request.nonce = {}", req_result.request.nonce);

    if req_result.request.secret_id != secret_id {
        panic!("Verification test failed: secret_id does not match.");
    }
    if req_result.request.version != version {
        panic!(
            "Verification test failed: expected version {}, got {}.",
            version, req_result.request.version
        );
    }
    if req_result.request.nonce == 0 {
        panic!("Verification test failed: nonce must not be zero.");
    }

    let resp_produced = verif_response::produce(
        channel_1,
        &req_result.request,
        shared_key_1,
        &share_bytes_1,
    )
    .expect("Verification test failed: verif_response::produce failed.");

    println!("verification_response wire bytes = {}", resp_produced.envelope.len());

    let response_envelope = derec_proto::DeRecMessage::decode(resp_produced.envelope.as_slice())
        .expect("Verification test failed: failed to decode response envelope.");
    println!("response_envelope.channel_id = {}", response_envelope.channel_id);

    if response_envelope.channel_id != u64::from(channel_1) {
        panic!(
            "Verification test failed: expected channel_id {:?} in response, got {}.",
            channel_1, response_envelope.channel_id
        );
    }

    let resp_result = verif_response::extract(&resp_produced.envelope, shared_key_1)
        .expect("Verification test failed: verif_response::extract failed.");

    let valid = verif_response::process(&resp_result.response, &share_bytes_1)
        .expect("Verification test failed: verif_response::process failed for valid case.");

    println!("verification valid = {}", valid);

    if !valid {
        panic!("Verification test failed: expected valid response.");
    }

    let resp_produced_2 = verif_response::produce(
        channel_1,
        &req_result.request,
        shared_key_1,
        &share_bytes_1,
    )
    .expect("Verification test failed: second verif_response::produce failed.");

    let resp_result_2 = verif_response::extract(&resp_produced_2.envelope, shared_key_1)
        .expect("Verification test failed: second verif_response::extract failed.");

    let valid_2 = verif_response::process(&resp_result_2.response, &share_bytes_2)
        .expect("Verification test failed: verif_response::process failed for invalid case.");

    println!("verification invalid case = {}", valid_2);

    if valid_2 {
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

    let shared_keys = make_shared_keys(&channels);

    let sharing = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("Recovery test failed: share_request::split failed.");

    let channel_1 = ChannelId(1);
    let channel_2 = ChannelId(2);

    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("Recovery test failed: missing shared key for channel 1.");

    let shared_key_2 = shared_keys
        .get(&channel_2)
        .expect("Recovery test failed: missing shared key for channel 2.");

    let stored_envelope_1 = share_request::produce(
        channel_1,
        version,
        &secret_id,
        &sharing.shares[&channel_1],
        &[],
        "",
        shared_key_1,
    )
    .expect("Recovery test failed: share_request::produce failed for channel 1.")
    .envelope;

    let stored_envelope_2 = share_request::produce(
        channel_2,
        version,
        &secret_id,
        &sharing.shares[&channel_2],
        &[],
        "",
        shared_key_2,
    )
    .expect("Recovery test failed: share_request::produce failed for channel 2.")
    .envelope;

    let stored_request_1 = share_request::extract(&stored_envelope_1, shared_key_1)
        .expect("Recovery test failed: share_request::extract failed for channel 1.")
        .request;

    let stored_request_2 = share_request::extract(&stored_envelope_2, shared_key_2)
        .expect("Recovery test failed: share_request::extract failed for channel 2.")
        .request;

    let share_req_1 = rec_request::produce(channel_1, &secret_id, version, shared_key_1)
        .expect("Recovery test failed: rec_request::produce failed for channel 1.");
    println!("share_request[1] wire bytes = {}", share_req_1.envelope.len());

    let get_request_1 = rec_request::extract(&share_req_1.envelope, shared_key_1)
        .expect("Recovery test failed: rec_request::extract failed for channel 1.")
        .request;

    let share_resp_1 = rec_response::produce(
        channel_1,
        &secret_id,
        &get_request_1,
        &stored_request_1,
        shared_key_1,
    )
    .unwrap_or_else(|_| panic!("Recovery test failed: rec_response::produce failed for channel 1."));

    println!("share_response[1] wire bytes = {}", share_resp_1.envelope.len());

    let get_response_1 = rec_response::extract(&share_resp_1.envelope, shared_key_1)
        .expect("Recovery test failed: rec_response::extract failed for channel 1.")
        .response;

    let share_req_2 = rec_request::produce(channel_2, &secret_id, version, shared_key_2)
        .expect("Recovery test failed: rec_request::produce failed for channel 2.");
    println!("share_request[2] wire bytes = {}", share_req_2.envelope.len());

    let get_request_2 = rec_request::extract(&share_req_2.envelope, shared_key_2)
        .expect("Recovery test failed: rec_request::extract failed for channel 2.")
        .request;

    let share_resp_2 = rec_response::produce(
        channel_2,
        &secret_id,
        &get_request_2,
        &stored_request_2,
        shared_key_2,
    )
    .unwrap_or_else(|_| panic!("Recovery test failed: rec_response::produce failed for channel 2."));

    println!("share_response[2] wire bytes = {}", share_resp_2.envelope.len());

    let get_response_2 = rec_response::extract(&share_resp_2.envelope, shared_key_2)
        .expect("Recovery test failed: rec_response::extract failed for channel 2.")
        .response;

    let inputs = vec![
        RecoveryResponseInput {
            share_response: &get_response_1,
        },
        RecoveryResponseInput {
            share_response: &get_response_2,
        },
    ];

    let recovered = rec_response::recover(&secret_id, version, &inputs)
        .expect("Recovery test failed: rec_response::recover failed.");

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
    ark_serialize::CanonicalSerialize::uncompressed_size(sk)
}
