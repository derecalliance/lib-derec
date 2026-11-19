// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Wire compatibility with the releases a peer may still run.
//!
//! Every exchange runs twice: once with the released version producing and
//! this build consuming, once the other way round. Only bytes cross between
//! the two, exactly as on the wire; each side builds its inputs with its own
//! types. A message this build cannot open from an older peer, or one an older
//! peer cannot open from this build, fails here.

#[path = "../../library/tests/support/protocol_doubles.rs"]
mod protocol_doubles;

use std::collections::HashMap;

use derec_library::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
use derec_library::protocol::{
    DeRecChannelStore as _, DeRecEvent, DeRecProtocolBuilder, DeRecSecretStore as _, IgnoreReason,
    SecretValue,
};
use derec_library::protocol_version::ProtocolVersion;
use prost::Message as _;
use protocol_doubles::{
    InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore, InMemUserSecretStore,
    RecordingTransport, run_async,
};

const SECRET_ID: u64 = 0x5EC2E7;
const VERSION: u32 = 3;
const KEY: [u8; 32] = [0x5A; 32];
const CHANNEL: u64 = 4242;

/// Store-share, verification, recovery, discovery and unpair: `$a` sends
/// each request, `$b` answers it, and `$a` reads the answer.
macro_rules! channel_exchanges {
    ($a:ident, $ap:ident, $b:ident, $bp:ident) => {{
        let a_channel = $a::types::ChannelId(CHANNEL);
        let b_channel = $b::types::ChannelId(CHANNEL);
        let a_endpoint = vec![$ap::TransportProtocol {
            uri: "https://a.example/derec".to_owned(),
            protocol: $ap::Protocol::Https.into(),
        }];

        let split = $a::primitives::sharing::request::split(
            &[(a_channel, 1), ($a::types::ChannelId(CHANNEL + 1), 1)],
            SECRET_ID,
            VERSION,
            b"the secret",
            2,
        )
        .expect("split");
        let share = split.shares.get(&a_channel).expect("share").clone();

        let store = $a::primitives::sharing::request::produce(
            a_channel,
            VERSION,
            SECRET_ID,
            &share,
            0,
            "round",
            &KEY,
            &a_endpoint,
        )
        .expect("store-share request");
        let stored = $b::primitives::sharing::request::extract(&store.envelope, &KEY)
            .expect("store-share request opens")
            .request;
        assert_eq!((stored.secret_id, stored.version), (SECRET_ID, VERSION));
        let answer = $b::primitives::sharing::response::produce(b_channel, &stored, &KEY)
            .expect("store-share response");
        let answered = $a::primitives::sharing::response::extract(&answer.envelope, &KEY)
            .expect("store-share response opens")
            .response;
        $a::primitives::sharing::response::process(VERSION, &answered)
            .expect("store-share response accepted");

        let verify = $a::primitives::verification::request::produce(
            a_channel,
            SECRET_ID,
            VERSION,
            &KEY,
            &a_endpoint,
        )
        .expect("verify request");
        let challenge = $b::primitives::verification::request::extract(&verify.envelope, &KEY)
            .expect("verify request opens")
            .request;
        let proof = $b::primitives::verification::response::produce(
            b_channel,
            &challenge,
            &KEY,
            &stored.share,
        )
        .expect("verify response");
        $a::primitives::verification::response::extract(&proof.envelope, &KEY)
            .expect("verify response opens");

        let get = $a::primitives::recovery::request::produce(
            a_channel,
            SECRET_ID,
            VERSION,
            &KEY,
            &a_endpoint,
        )
        .expect("get-share request");
        let asked = $b::primitives::recovery::request::extract(&get.envelope, &KEY)
            .expect("get-share request opens")
            .request;
        let served = $b::primitives::recovery::response::produce(b_channel, &asked, &stored, &KEY)
            .expect("get-share response");
        $a::primitives::recovery::response::extract(&served.envelope, &KEY)
            .expect("get-share response opens");

        let discover = $a::primitives::discovery::request::produce(a_channel, &KEY, &a_endpoint)
            .expect("discovery request");
        $b::primitives::discovery::request::extract(&discover.envelope, &KEY)
            .expect("discovery request opens");
        let listed = $b::primitives::discovery::response::produce(b_channel, &[], &KEY)
            .expect("discovery response");
        $a::primitives::discovery::response::extract(&listed.envelope, &KEY)
            .expect("discovery response opens");

        let unpair =
            $a::primitives::unpairing::request::produce(a_channel, "bye", &KEY, &a_endpoint, None)
                .expect("unpair request");
        $b::primitives::unpairing::request::extract(&unpair.envelope, &KEY)
            .expect("unpair request opens");
        let unpaired =
            $b::primitives::unpairing::response::produce(b_channel, &KEY).expect("unpair response");
        $a::primitives::unpairing::response::extract(&unpaired.envelope, &KEY)
            .expect("unpair response opens");
    }};
}

/// Channel messages with no primitive of their own, sealed by `$a`'s
/// envelope builder and opened by `$b`.
macro_rules! builder_exchanges {
    ($a:ident, $ap:ident, $b:ident, $bp:ident) => {{
        let bodies = vec![
            $ap::MessageBody::ErrorResponse($ap::ErrorResponseMessage {
                timestamp: Some($a::derec_message::current_timestamp()),
                ..Default::default()
            }),
            $ap::MessageBody::UpdateChannelInfoRequest($ap::UpdateChannelInfoRequestMessage {
                timestamp: Some($a::derec_message::current_timestamp()),
                ..Default::default()
            }),
            $ap::MessageBody::UpdateChannelInfoResponse($ap::UpdateChannelInfoResponseMessage {
                timestamp: Some($a::derec_message::current_timestamp()),
                ..Default::default()
            }),
        ];
        for body in bodies {
            let kind = format!("{body:?}");
            let envelope = $a::derec_message::DeRecMessageBuilder::channel()
                .channel_id($a::types::ChannelId(CHANNEL))
                .timestamp($a::derec_message::current_timestamp())
                .message_body(body)
                .encrypt(&KEY)
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec();
            let decoded = $bp::DeRecMessage::decode(envelope.as_slice()).expect("envelope decodes");
            $b::derec_message::extract_inner_message(&decoded.message, &KEY)
                .unwrap_or_else(|e| panic!("{kind} does not open: {e:?}"));
        }
    }};
}

/// Every pairing leg. `$a` creates the contact and answers; `$b` scans it.
macro_rules! pairing_exchanges {
    ($a:ident, $ap:ident, $b:ident, $bp:ident) => {{
        let a_channel = $a::types::ChannelId(CHANNEL);
        let a_endpoint = vec![$ap::TransportProtocol {
            uri: "https://a.example/derec".to_owned(),
            protocol: $ap::Protocol::Https.into(),
        }];
        let b_endpoint = vec![$bp::TransportProtocol {
            uri: "https://b.example/derec".to_owned(),
            protocol: $bp::Protocol::Https.into(),
        }];

        // InlineKeys: PairRequest and PairResponse, both ECIES.
        let created = $a::primitives::pairing::request::create_contact(
            a_channel,
            $ap::ContactMode::InlineKeys,
            a_endpoint.clone(),
            None,
        )
        .expect("contact");
        let a_secret = created.secret_key.expect("inline contact carries keys");
        let contact_bytes =
            $a::primitives::pairing::request::encode_contact(&created.contact_message)
                .expect("encode contact");
        let contact = $b::primitives::pairing::request::decode_contact(&contact_bytes)
            .expect("decode contact");
        let request = $b::primitives::pairing::request::produce(
            $bp::SenderKind::Helper,
            b_endpoint.clone(),
            &contact,
            None,
            None,
        )
        .expect("pair request");
        let received = $a::primitives::pairing::request::extract(
            &request.envelope,
            a_secret.ecies_secret_key(),
            None,
        )
        .expect("pair request opens")
        .request;
        let response = $a::primitives::pairing::response::produce(
            a_channel,
            &received,
            &a_secret,
            None,
            None,
            $a::transport::TransportPolicy::default(),
        )
        .expect("pair response");
        let answered = $b::primitives::pairing::response::extract(
            &response.envelope,
            request.secret_key.ecies_secret_key(),
        )
        .expect("pair response opens")
        .response;
        let paired = $b::primitives::pairing::response::process(
            &request.initiator_contact_message,
            &answered,
            &request.secret_key,
            None,
        )
        .expect("pair response accepted");
        assert_eq!(
            paired.shared_key, response.shared_key,
            "both sides derive one key"
        );

        // HashedKeys: the plaintext PrePair request and response.
        let hashed = $a::primitives::pairing::request::create_contact(
            a_channel,
            $ap::ContactMode::HashedKeys,
            a_endpoint.clone(),
            None,
        )
        .expect("hashed contact");
        let hashed_secret = hashed.secret_key.expect("hashed contact keeps its keys");
        let hashed_bytes =
            $a::primitives::pairing::request::encode_contact(&hashed.contact_message)
                .expect("encode contact");
        let hashed_contact = $b::primitives::pairing::request::decode_contact(&hashed_bytes)
            .expect("decode contact");
        let pre = $b::primitives::pairing::request::produce_pre_pair_request(
            b_endpoint.clone(),
            &hashed_contact,
        )
        .expect("pre-pair request");
        let pre_received = $a::primitives::pairing::request::extract_pre_pair(&pre.envelope)
            .expect("pre-pair request opens")
            .request;
        let pre_answer = $a::primitives::pairing::response::produce_pre_pair(
            a_channel,
            &pre_received,
            &hashed_secret,
        )
        .expect("pre-pair response");
        let pre_answered =
            $b::primitives::pairing::response::extract_pre_pair(&pre_answer.envelope)
                .expect("pre-pair response opens")
                .response;
        $b::primitives::pairing::response::process_pre_pair(&hashed_contact, &pre_answered)
            .expect("pre-pair response matches the contact's binding");

        // NoKeys: the PrePair response carries freshly generated keys.
        let no_keys = $a::primitives::pairing::request::create_contact(
            a_channel,
            $ap::ContactMode::NoKeys,
            a_endpoint,
            None,
        )
        .expect("no-keys contact");
        let no_keys_bytes =
            $a::primitives::pairing::request::encode_contact(&no_keys.contact_message)
                .expect("encode contact");
        let no_keys_contact = $b::primitives::pairing::request::decode_contact(&no_keys_bytes)
            .expect("decode contact");
        let ask = $b::primitives::pairing::request::produce_pre_pair_request(
            b_endpoint,
            &no_keys_contact,
        )
        .expect("pre-pair request");
        let asked = $a::primitives::pairing::request::extract_pre_pair(&ask.envelope)
            .expect("pre-pair request opens")
            .request;
        let keys = $a::primitives::pairing::response::produce_pre_pair_no_keys(a_channel, &asked)
            .expect("no-keys pre-pair response");
        let got = $b::primitives::pairing::response::extract_pre_pair(&keys.envelope)
            .expect("no-keys pre-pair response opens")
            .response;
        $b::primitives::pairing::response::process_pre_pair_no_keys(&no_keys_contact, &got)
            .expect("no-keys pre-pair response accepted");
    }};
}

/// What this build reports for one inbound message on a channel paired with
/// an Owner, accepting messages from protocol `floor` on.
fn process_as_helper(envelope: &[u8], floor: ProtocolVersion) -> Vec<DeRecEvent> {
    let mut events = Vec::new();
    run_async(async {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: derec_library::types::ChannelId(CHANNEL),
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://a.example/derec".to_owned(),
                        protocol: derec_proto::Protocol::Https.into(),
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    peer_role: derec_proto::SenderKind::Owner,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        secrets
            .save(
                SECRET_ID,
                derec_library::types::ChannelId(CHANNEL),
                SecretValue::SharedKey(KEY),
            )
            .await
            .expect("seed key");
        let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://b.example/derec"])
            .with_min_protocol_version(floor)
            .build()
            .expect("protocol builds");
        events = protocol.process(envelope).await.expect("processed");
    });
    events
}

fn ignored_as_too_old(events: &[DeRecEvent]) -> bool {
    matches!(
        events,
        [DeRecEvent::MessageIgnored {
            reason: IgnoreReason::ProtocolVersionTooOld,
            ..
        }]
    )
}

macro_rules! compat_with {
    ($module:ident, $old_crate:ident, $old_proto_crate:ident) => {
        mod $module {
            use super::*;
            use derec_library as current;
            use derec_proto as current_proto;
            use $old_crate as old;
            use $old_proto_crate as old_proto;

            #[test]
            fn channel_messages_from_the_release_open_here() {
                channel_exchanges!(old, old_proto, current, current_proto);
            }

            #[test]
            fn channel_messages_from_here_open_in_the_release() {
                channel_exchanges!(current, current_proto, old, old_proto);
            }

            #[test]
            fn builder_sealed_messages_from_the_release_open_here() {
                builder_exchanges!(old, old_proto, current, current_proto);
            }

            #[test]
            fn builder_sealed_messages_from_here_open_in_the_release() {
                builder_exchanges!(current, current_proto, old, old_proto);
            }

            #[test]
            fn a_device_on_the_release_pairs_with_a_contact_from_here() {
                pairing_exchanges!(current, current_proto, old, old_proto);
            }

            #[test]
            fn a_device_here_pairs_with_a_contact_from_the_release() {
                pairing_exchanges!(old, old_proto, current, current_proto);
            }

            /// A request from the release reaches the protocol while the
            /// floor admits it; raised to 0.1 it is ignored unread.
            #[test]
            fn the_release_is_accepted_until_the_floor_is_raised() {
                let share = old::primitives::sharing::request::split(
                    &[
                        (old::types::ChannelId(CHANNEL), 1),
                        (old::types::ChannelId(CHANNEL + 1), 1),
                    ],
                    SECRET_ID,
                    VERSION,
                    b"the secret",
                    2,
                )
                .expect("split")
                .shares
                .remove(&old::types::ChannelId(CHANNEL))
                .expect("share");
                let request = old::primitives::sharing::request::produce(
                    old::types::ChannelId(CHANNEL),
                    VERSION,
                    SECRET_ID,
                    &share,
                    0,
                    "round",
                    &KEY,
                    &[],
                )
                .expect("store-share request")
                .envelope;

                let accepted = process_as_helper(&request, ProtocolVersion { major: 0, minor: 0 });
                assert!(
                    !accepted.is_empty()
                        && !accepted
                            .iter()
                            .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
                    "{accepted:?}"
                );
                assert!(ignored_as_too_old(&process_as_helper(
                    &request,
                    ProtocolVersion { major: 0, minor: 1 }
                )));
            }
        }
    };
}

compat_with!(v0_0_10, derec_library_0_0_10, derec_proto_0_0_10);
compat_with!(v0_0_11, derec_library_0_0_11, derec_proto_0_0_11);
