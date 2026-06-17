//! Primitive-level smoke tests for the current `derec_library::primitives` API.
//!
//! Exercises each flow's `produce` / `extract` / `process` round-trip directly
//! (no `DeRecProtocol` orchestrator). Signatures here track the post-refactor
//! API: numeric `secret_id: u64`, `version: u32`, pairing responses via
//! `response::produce`, and recovery driven by re-using the Helper's stored
//! `StoreShareRequestMessage`.

use derec_library::primitives::discovery::{
    request as disc_request,
    response::{self as disc_response, SecretVersionEntry, VersionEntry},
};
use derec_library::primitives::pairing::{request as pair_request, response as pair_response};
use derec_library::primitives::recovery::{
    request as rec_request, response as rec_response,
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
    run_pairing_flow_hashed_keys_test();
    run_sharing_flow_test();
    run_verification_flow_test();
    run_recovery_flow_test();
    run_discovery_flow_test();
    run_envelope_trace_id_test();
    run_request_reply_to_test();
}

fn run_protocol_version_test() {
    println!("=== Protocol version test ===");

    let version = derec_library::protocol_version::ProtocolVersion::current();

    println!("protocol version = {version}");
    println!("major = {}", version.major);
    println!("minor = {}", version.minor);

    println!("Protocol version test passed.");
}

fn run_pairing_flow_test() {
    println!("=== Pairing flow test ===");

    let channel_id = ChannelId(1);

    // Initiator creates an out-of-band contact.
    let contact_result = pair_request::create_contact(
        channel_id,
        derec_proto::ContactMode::InlineKeys,
        TransportProtocol {
            uri: "https://example.com/alice".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("pair_request::create_contact failed");

    let contact_wire_bytes = contact_result.contact_message.encode_to_vec();
    assert!(
        !contact_wire_bytes.is_empty(),
        "contact wire bytes must not be empty"
    );

    let decoded_contact = contact_result.contact_message.clone();
    let transport = decoded_contact
        .transport_protocol
        .as_ref()
        .expect("contact missing transport_protocol");
    assert_eq!(transport.uri, "https://example.com/alice");
    assert_eq!(transport.protocol(), Protocol::Https);

    // Responder produces a pairing request from the contact. The current API
    // takes an optional `CommunicationInfo` as the final argument.
    let pair_req = pair_request::produce(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://example.com/helper".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &decoded_contact,
        None,
    )
    .expect("pair_request::produce failed");

    assert!(
        !pair_req.envelope.is_empty(),
        "pair request envelope must not be empty"
    );

    let initiator_tp = pair_req
        .initiator_contact_message
        .transport_protocol
        .as_ref()
        .expect("initiator_contact_message should have transport_protocol");
    assert_eq!(initiator_tp.uri, "https://example.com/alice");
    assert_eq!(initiator_tp.protocol(), Protocol::Https);

    // Initiator extracts the request using its ECIES secret key.
    let extracted_request =
        pair_request::extract(&pair_req.envelope, contact_result.secret_key.ecies_secret_key())
            .expect("pair_request::extract failed");

    // Initiator produces the pairing response and derives its shared key.
    let pair_resp = pair_response::produce(
        channel_id,
        &extracted_request.request,
        &contact_result.secret_key,
        None,
    )
    .expect("pair_response::produce failed");

    assert!(
        !pair_resp.envelope.is_empty(),
        "pair response envelope must not be empty"
    );
    assert!(
        !pair_resp.shared_key.is_empty(),
        "initiator shared key must not be empty"
    );

    // Responder extracts and processes the response, deriving its shared key.
    let extracted_response =
        pair_response::extract(&pair_resp.envelope, pair_req.secret_key.ecies_secret_key())
            .expect("pair_response::extract failed");

    let processed = pair_response::process(
        &pair_req.initiator_contact_message,
        &extracted_response.response,
        &pair_req.secret_key,
    )
    .expect("pair_response::process failed");

    assert!(
        !processed.shared_key.is_empty(),
        "responder shared key must not be empty"
    );
    assert_eq!(
        pair_resp.shared_key, processed.shared_key,
        "shared keys derived by both sides must match"
    );
    assert_eq!(
        pair_resp.channel_id, processed.channel_id,
        "both sides must derive the same rekeyed channel id"
    );
    assert_ne!(
        pair_resp.channel_id, channel_id,
        "rekeyed channel id must differ from the pre-rekey id"
    );

    println!("Pairing flow test passed.");
}

fn run_pairing_flow_hashed_keys_test() {
    println!("=== Pairing flow test (HASHED_KEYS + PrePair) ===");

    let channel_id = ChannelId(2);

    // Alice creates a HASHED_KEYS contact. The contact carries only a
    // SHA-384 commitment to her public keys, not the keys themselves —
    // it is small enough for a QR code, and Bob will fetch the keys
    // over the wire via the PrePair leg.
    let alice_contact_result = pair_request::create_contact(
        channel_id,
        derec_proto::ContactMode::HashedKeys,
        TransportProtocol {
            uri: "https://example.com/alice/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        },
    )
    .expect("pair_request::create_contact (HASHED_KEYS) failed");

    let alice_contact = alice_contact_result.contact_message.clone();
    let alice_secret = alice_contact_result.secret_key;

    assert_eq!(
        alice_contact.contact_mode,
        derec_proto::ContactMode::HashedKeys as i32,
        "contact must advertise HASHED_KEYS mode"
    );
    assert!(
        alice_contact.mlkem_encapsulation_key.is_none(),
        "HASHED_KEYS contact must NOT carry the ML-KEM key inline"
    );
    assert!(
        alice_contact.ecies_public_key.is_none(),
        "HASHED_KEYS contact must NOT carry the ECIES key inline"
    );
    let binding_hash = alice_contact
        .contact_binding_hash
        .clone()
        .expect("HASHED_KEYS contact must carry contact_binding_hash");
    assert_eq!(
        binding_hash.len(),
        48,
        "contact_binding_hash must be a SHA-384 digest (48 bytes)"
    );


    // Bob (the scanner) sends a PrePair request asking for the actual keys.
    // The envelope is plaintext (no shared key exists yet) and routes to
    // the channel_id from the contact.
    let bob_prepair_req = pair_request::produce_pre_pair_request(
        TransportProtocol {
            uri: "https://example.com/helper/ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &alice_contact,
    )
    .expect("pair_request::produce_pre_pair_request failed");

    // Alice decodes the inbound plaintext request.
    let extracted_prepair_req = pair_request::extract_pre_pair(&bob_prepair_req.envelope)
        .expect("pair_request::extract_pre_pair failed");
    assert_eq!(
        extracted_prepair_req.request.nonce, alice_contact.nonce,
        "PrePair request must echo the contact's nonce"
    );

    // Alice publishes the public keys back to Bob (plaintext envelope).
    let alice_prepair_resp = pair_response::produce_pre_pair(
        channel_id,
        &extracted_prepair_req.request,
        &alice_secret,
    )
    .expect("pair_response::produce_pre_pair failed");

    // Bob decodes the inbound plaintext response.
    let extracted_prepair_resp = pair_response::extract_pre_pair(&alice_prepair_resp.envelope)
        .expect("pair_response::extract_pre_pair failed");

    // Bob recomputes the SHA-384 binding hash and validates it against the
    // commitment from the original contact. Any tampering on the plaintext
    // PrePair leg surfaces here.
    let processed_prepair = pair_response::process_pre_pair(
        &alice_contact,
        &extracted_prepair_resp.response,
    )
    .expect("pair_response::process_pre_pair failed");

    assert!(
        !processed_prepair.mlkem_encapsulation_key.is_empty(),
        "PrePair must return Alice's ML-KEM encapsulation key"
    );
    assert!(
        !processed_prepair.ecies_public_key.is_empty(),
        "PrePair must return Alice's ECIES public key"
    );
    assert_eq!(processed_prepair.nonce, alice_contact.nonce);

    // Bob synthesizes a "filled-in" contact by copying the validated keys
    // into a clone of the original (HASHED_KEYS) contact. From here on the
    // flow is identical to the INLINE_KEYS path — `pair_request::produce`
    // and the rest of the chain do not need to know PrePair happened.

    // Synthesize a "filled-in" contact for the downstream PairRequest flow.
    // After PrePair, the contact is logically `InlineKeys` — keys are
    // present locally — so normalize the shape: drop the binding hash and
    // flip the mode. `pair_request::produce` enforces the InlineKeys
    // invariant via `validate_contact_for_mode`, which rejects any contact
    // that still claims `HashedKeys`.
    let mut filled_in_contact = alice_contact.clone();
    filled_in_contact.mlkem_encapsulation_key =
        Some(processed_prepair.mlkem_encapsulation_key.clone());
    filled_in_contact.ecies_public_key = Some(processed_prepair.ecies_public_key.clone());
    filled_in_contact.contact_mode = derec_proto::ContactMode::InlineKeys as i32;
    filled_in_contact.contact_binding_hash = None;

    let pair_req = pair_request::produce(
        SenderKind::Helper,
        TransportProtocol {
            uri: "https://example.com/helper".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &filled_in_contact,
        None,
    )
    .expect("pair_request::produce failed");

    let extracted_request = pair_request::extract(&pair_req.envelope, alice_secret.ecies_secret_key())
        .expect("pair_request::extract failed");

    let pair_resp = pair_response::produce(
        channel_id,
        &extracted_request.request,
        &alice_secret,
        None,
    )
    .expect("pair_response::produce failed");

    let extracted_response =
        pair_response::extract(&pair_resp.envelope, pair_req.secret_key.ecies_secret_key())
            .expect("pair_response::extract failed");

    let processed = pair_response::process(
        &pair_req.initiator_contact_message,
        &extracted_response.response,
        &pair_req.secret_key,
    )
    .expect("pair_response::process failed");

    assert_eq!(
        pair_resp.shared_key, processed.shared_key,
        "shared keys derived by both sides must match (HASHED_KEYS path)"
    );
    assert_eq!(
        pair_resp.channel_id, processed.channel_id,
        "both sides must derive the same rekeyed channel id (HASHED_KEYS path)"
    );
    assert_ne!(
        pair_resp.channel_id, channel_id,
        "rekeyed channel id must differ from the pre-rekey id (HASHED_KEYS path)"
    );

    println!("Pairing flow test (HASHED_KEYS + PrePair) passed.");
}

fn run_sharing_flow_test() {
    println!("=== Sharing flow test ===");

    let secret_id: u64 = 0x0102_0304_05ff;
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version: u32 = 1;

    let split_result = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("share_request::split failed");

    assert_eq!(
        split_result.shares.len(),
        channels.len(),
        "expected one share per channel"
    );
    for channel in &channels {
        assert!(
            split_result.shares.contains_key(channel),
            "missing share for channel {channel:?}"
        );
    }

    let shared_key = [42u8; 32];

    for (channel, share) in &split_result.shares {
        assert!(
            !share.commitment.is_empty(),
            "empty commitment for channel {channel:?}"
        );

        let store_result = share_request::produce(
            *channel,
            version,
            secret_id,
            share,
            &[],
            "",
            &shared_key,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("share_request::produce failed for {channel:?}: {e}"));

        assert!(
            !store_result.envelope.is_empty(),
            "empty store share request envelope for {channel:?}"
        );

        let extracted_req = share_request::extract(&store_result.envelope, &shared_key)
            .unwrap_or_else(|e| panic!("share_request::extract failed for {channel:?}: {e}"));

        let processed = share_response::produce(*channel, &extracted_req.request, &shared_key)
            .unwrap_or_else(|e| panic!("share_response::produce failed for {channel:?}: {e}"));

        assert!(
            !processed.envelope.is_empty(),
            "empty store share response envelope for {channel:?}"
        );
        assert!(
            !processed.committed_share.commitment.is_empty(),
            "empty committed_share commitment for {channel:?}"
        );
        assert_eq!(
            processed.secret_id, secret_id,
            "secret_id mismatch for {channel:?}"
        );
        assert_eq!(
            processed.version, version,
            "version mismatch for {channel:?}"
        );

        let extracted_resp = share_response::extract(&processed.envelope, &shared_key)
            .unwrap_or_else(|e| panic!("share_response::extract failed for {channel:?}: {e}"));

        share_response::process(version, &extracted_resp.response)
            .unwrap_or_else(|e| panic!("share_response::process failed for {channel:?}: {e}"));
    }

    println!("Sharing flow test passed.");
}

fn run_verification_flow_test() {
    println!("=== Verification flow test ===");

    let secret_id: u64 = 0x0102_0304_05ff;
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version: u32 = 1;

    let shared_keys = make_shared_keys(&channels);

    let sharing = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("share_request::split failed");

    let channel_1 = ChannelId(1);
    let channel_2 = ChannelId(2);

    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("missing shared key for channel 1");

    let stored_wire_1 = share_request::produce(
        channel_1,
        version,
        secret_id,
        &sharing.shares[&channel_1],
        &[],
        "",
        shared_key_1,
        None,
        None,
    )
    .expect("share_request::produce failed for channel 1")
    .envelope;

    let stored_wire_2 = share_request::produce(
        channel_2,
        version,
        secret_id,
        &sharing.shares[&channel_2],
        &[],
        "",
        shared_key_1,
        None,
        None,
    )
    .expect("share_request::produce failed for channel 2")
    .envelope;

    let share_bytes_1 = share_request::extract(&stored_wire_1, shared_key_1)
        .expect("failed to extract stored share 1")
        .request
        .share;

    let share_bytes_2 = share_request::extract(&stored_wire_2, shared_key_1)
        .expect("failed to extract stored share 2")
        .request
        .share;

    let produced = verif_request::produce(channel_1, secret_id, version, shared_key_1, None)
        .expect("verif_request::produce failed");

    let request_envelope = derec_proto::DeRecMessage::decode(produced.envelope.as_slice())
        .expect("failed to decode request envelope");
    assert_eq!(
        request_envelope.channel_id,
        u64::from(channel_1),
        "unexpected channel_id in verification request envelope"
    );

    let req_result = verif_request::extract(&produced.envelope, shared_key_1)
        .expect("verif_request::extract failed");
    assert_eq!(
        req_result.request.secret_id, secret_id,
        "secret_id mismatch in verification request"
    );
    assert_eq!(
        req_result.request.version, version,
        "version mismatch in verification request"
    );
    assert_ne!(req_result.request.nonce, 0, "nonce must not be zero");

    let resp_produced =
        verif_response::produce(channel_1, &req_result.request, shared_key_1, &share_bytes_1)
            .expect("verif_response::produce failed");

    let resp_result = verif_response::extract(&resp_produced.envelope, shared_key_1)
        .expect("verif_response::extract failed");

    let valid = verif_response::process(&req_result.request, &resp_result.response, &share_bytes_1)
        .expect("verif_response::process failed (valid case)");
    assert!(valid, "expected a valid verification response");

    // The same proof must not validate against a different share.
    let resp_produced_2 =
        verif_response::produce(channel_1, &req_result.request, shared_key_1, &share_bytes_1)
            .expect("second verif_response::produce failed");
    let resp_result_2 = verif_response::extract(&resp_produced_2.envelope, shared_key_1)
        .expect("second verif_response::extract failed");
    let valid_2 = verif_response::process(
        &req_result.request,
        &resp_result_2.response,
        &share_bytes_2,
    )
    .expect("verif_response::process failed (invalid case)");
    assert!(
        !valid_2,
        "expected an invalid verification response for the wrong share"
    );

    println!("Verification flow test passed.");
}

fn run_recovery_flow_test() {
    println!("=== Recovery flow test ===");

    let secret_id: u64 = 0x0102_0304_05ff;
    let secret_data = [5_u8, 6, 7, 8, 255];
    let channels = vec![ChannelId(1), ChannelId(2), ChannelId(3)];
    let threshold = 2_usize;
    let version: u32 = 1;

    let shared_keys = make_shared_keys(&channels);

    let sharing = share_request::split(&channels, secret_id, version, secret_data, threshold)
        .expect("share_request::split failed");

    let channel_1 = ChannelId(1);
    let channel_2 = ChannelId(2);

    let shared_key_1 = shared_keys
        .get(&channel_1)
        .expect("missing shared key for channel 1");
    let shared_key_2 = shared_keys
        .get(&channel_2)
        .expect("missing shared key for channel 2");

    // Reproduce what a Helper persists during sharing: the decrypted
    // `StoreShareRequestMessage`.
    let stored_request_1 = share_request::extract(
        &share_request::produce(
            channel_1,
            version,
            secret_id,
            &sharing.shares[&channel_1],
            &[],
            "",
            shared_key_1,
            None,
            None,
        )
        .expect("share_request::produce failed for channel 1")
        .envelope,
        shared_key_1,
    )
    .expect("share_request::extract failed for channel 1")
    .request;

    let stored_request_2 = share_request::extract(
        &share_request::produce(
            channel_2,
            version,
            secret_id,
            &sharing.shares[&channel_2],
            &[],
            "",
            shared_key_2,
            None,
            None,
        )
        .expect("share_request::produce failed for channel 2")
        .envelope,
        shared_key_2,
    )
    .expect("share_request::extract failed for channel 2")
    .request;

    // Channel 1 recovery round-trip.
    let share_req_1 = rec_request::produce(channel_1, secret_id, version, shared_key_1, None)
        .expect("rec_request::produce failed for channel 1");
    let get_request_1 = rec_request::extract(&share_req_1.envelope, shared_key_1)
        .expect("rec_request::extract failed for channel 1")
        .request;
    let share_resp_1 = rec_response::produce(
        channel_1,
        &get_request_1,
        &stored_request_1,
        shared_key_1,
    )
    .expect("rec_response::produce failed for channel 1");
    let get_response_1 = rec_response::extract(&share_resp_1.envelope, shared_key_1)
        .expect("rec_response::extract failed for channel 1")
        .response;

    // Channel 2 recovery round-trip.
    let share_req_2 = rec_request::produce(channel_2, secret_id, version, shared_key_2, None)
        .expect("rec_request::produce failed for channel 2");
    let get_request_2 = rec_request::extract(&share_req_2.envelope, shared_key_2)
        .expect("rec_request::extract failed for channel 2")
        .request;
    let share_resp_2 = rec_response::produce(
        channel_2,
        &get_request_2,
        &stored_request_2,
        shared_key_2,
    )
    .expect("rec_response::produce failed for channel 2");
    let get_response_2 = rec_response::extract(&share_resp_2.envelope, shared_key_2)
        .expect("rec_response::extract failed for channel 2")
        .response;

    let inputs = vec![&get_response_1, &get_response_2];

    let recovered =
        rec_response::recover(secret_id, version, &inputs).expect("rec_response::recover failed");

    assert_eq!(
        recovered.secret_data.as_slice(),
        secret_data,
        "recovered secret does not match the original"
    );

    println!("Recovery flow test passed.");
}

fn run_discovery_flow_test() {
    println!("=== Discovery flow test ===");

    let channel_id = ChannelId(7);
    let shared_key = [11u8; 32];

    let request = disc_request::produce(channel_id, &shared_key, None)
        .expect("disc_request::produce failed");
    assert!(
        !request.envelope.is_empty(),
        "discovery request envelope must not be empty"
    );

    let extracted_req = disc_request::extract(&request.envelope, &shared_key)
        .expect("disc_request::extract failed");
    let _ = extracted_req.request;

    let secret_list = vec![SecretVersionEntry {
        secret_id: 0xABCD,
        versions: vec![
            VersionEntry {
                version: 1,
                description: "wallet seed".to_owned(),
                replica_id: None,
            },
            VersionEntry {
                version: 2,
                description: "wallet seed v2".to_owned(),
                replica_id: None,
            },
        ],
    }];

    let response = disc_response::produce(channel_id, &secret_list, &shared_key)
        .expect("disc_response::produce failed");

    let extracted_resp = disc_response::extract(&response.envelope, &shared_key)
        .expect("disc_response::extract failed");

    let processed = disc_response::process(&extracted_resp.response)
        .expect("disc_response::process failed");

    assert_eq!(
        processed.secret_list, secret_list,
        "discovery secret list must round-trip unchanged"
    );

    println!("Discovery flow test passed.");
}

fn run_envelope_trace_id_test() {
    println!("=== Envelope trace_id helpers test ===");

    let channel_id = ChannelId(42);
    let shared_key = [9u8; 32];

    // Primitive `produce` emits envelopes with trace_id = 0 (the protobuf
    // default). Consumers driving the protocol through primitives use
    // `apply_trace_id` to stamp a correlation token.
    let result = disc_request::produce(channel_id, &shared_key, None)
        .expect("disc_request::produce failed");

    let trace_before =
        derec_library::derec_message::read_trace_id(&result.envelope).expect("read failed");
    assert_eq!(trace_before, 0, "primitive default trace_id must be 0");

    let stamped =
        derec_library::derec_message::apply_trace_id(&result.envelope, 0xDEAD_BEEF_F00D_CAFE)
            .expect("apply failed");
    let trace_after = derec_library::derec_message::read_trace_id(&stamped).expect("read failed");
    assert_eq!(
        trace_after, 0xDEAD_BEEF_F00D_CAFE,
        "trace_id must round-trip through apply + read"
    );

    // The encrypted inner payload is untouched — extract still succeeds.
    let extracted = disc_request::extract(&stamped, &shared_key)
        .expect("extract on re-stamped envelope failed");
    assert!(extracted.request.timestamp.is_some());

    println!("Envelope trace_id helpers test passed.");
}

fn run_request_reply_to_test() {
    println!("=== Request reply_to round-trip test ===");

    let channel_id = ChannelId(7);
    let shared_key = [11u8; 32];

    let reply_to = TransportProtocol {
        uri: "https://replica-a.example.com/derec".to_owned(),
        protocol: Protocol::Https as i32,
    };

    let result = disc_request::produce(channel_id, &shared_key, Some(reply_to.clone()))
        .expect("disc_request::produce failed");

    let extracted = disc_request::extract(&result.envelope, &shared_key)
        .expect("disc_request::extract failed");
    assert_eq!(
        extracted.request.reply_to,
        Some(reply_to),
        "reply_to must round-trip on the inner request"
    );

    // Without it, the field is absent — the default behavior.
    let plain = disc_request::produce(channel_id, &shared_key, None)
        .expect("disc_request::produce (no reply_to) failed");
    let plain_extracted = disc_request::extract(&plain.envelope, &shared_key)
        .expect("disc_request::extract failed");
    assert!(
        plain_extracted.request.reply_to.is_none(),
        "absent reply_to must decode as None"
    );

    println!("Request reply_to round-trip test passed.");
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
