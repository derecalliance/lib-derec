// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::*;
use crate::protocol::builder::DeRecProtocolBuilder;
use crate::protocol::tests::{
    InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore, InMemUserSecretStore,
    NoopTransport, run_async,
};
use crate::protocol::types::SecretValue;
use crate::types::ChannelId;

const SECRET_ID: u64 = 0xF2;
const CHANNEL: ChannelId = ChannelId(4242);
const NONCE: u64 = 0xABCD;

/// A NoKeys contact is the cheapest way into `pre_pair::accept`: it needs
/// only a stored `PairingContact` whose nonce the request echoes.
async fn seed_no_keys_contact(secrets: &mut InMemSecretStore) {
    secrets
        .save(
            SECRET_ID,
            CHANNEL,
            SecretValue::PairingContact(derec_proto::ContactMessage {
                channel_id: CHANNEL.0,
                contact_mode: derec_proto::ContactMode::NoKeys as i32,
                nonce: NONCE,
                ..Default::default()
            }),
        )
        .await
        .expect("seed NoKeys pairing contact");
}

fn request_answering_on(uri: &str, protocol: derec_proto::Protocol) -> PendingAction {
    PendingAction::pre_pair(
        CHANNEL,
        0,
        derec_proto::PrePairRequestMessage {
            nonce: NONCE,
            supported_transports: vec![derec_proto::TransportProtocol {
                uri: uri.to_owned(),
                protocol: protocol as i32,
            }],
            timestamp: None,
        },
    )
}

fn build(
    secrets: InMemSecretStore,
    unsafe_connection: bool,
) -> DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemStateStore,
    NoopTransport,
> {
    DeRecProtocolBuilder::new(SECRET_ID)
        .with_channel_store(InMemChannelStore::default())
        .with_share_store(InMemShareStore::default())
        .with_secret_store(secrets)
        .with_user_secret_store(InMemUserSecretStore::default())
        .with_transport(NoopTransport)
        .with_state_store(InMemStateStore)
        .with_own_transports(["https://owner.example.com"])
        .with_threshold(2)
        .with_unsafe_connection(unsafe_connection)
        .build()
        .expect("test protocol builds")
}

/// The gap this guards: a peer asking to be answered over LAN plaintext
/// was dialled regardless of `unsafe_connection`, because this path
/// validated the endpoint's *structure* and never applied the policy.
#[test]
fn lan_plaintext_reply_endpoint_is_refused() {
    run_async(async {
        let secrets = InMemSecretStore::default();
        let mut seeded = secrets.clone();
        seed_no_keys_contact(&mut seeded).await;

        let mut protocol = build(secrets, false);
        let err = protocol
            .accept(request_answering_on(
                "http://192.168.1.42:8080",
                derec_proto::Protocol::Https,
            ))
            .await
            .expect_err("LAN plaintext must not be dialled without the flag");

        // Endpoints are filtered rather than fail-fasted, so a request
        // whose *every* endpoint is refused reports that none was usable.
        // The guarantee is unchanged: plaintext is not dialled.
        assert!(
            matches!(err, crate::Error::NoUsableEndpoint { offered: 1 }),
            "expected a no-usable-endpoint refusal, got {err:?}"
        );
    });
}

/// Same request succeeds once plaintext is opted into, proving the
/// refusal above comes from the policy rather than from the fixture.
#[test]
fn lan_plaintext_reply_endpoint_is_accepted_with_the_flag() {
    run_async(async {
        let secrets = InMemSecretStore::default();
        let mut seeded = secrets.clone();
        seed_no_keys_contact(&mut seeded).await;

        let mut protocol = build(secrets, true);
        protocol
            .accept(request_answering_on(
                "http://192.168.1.42:8080",
                derec_proto::Protocol::Https,
            ))
            .await
            .expect("plaintext is dialled once unsafe_connection is set");
    });
}

/// A requester offering both is answered over the secure one rather than
/// refused outright — one bad endpoint does not sink the request.
#[test]
fn a_plaintext_entry_is_skipped_when_a_secure_one_is_offered() {
    run_async(async {
        let secrets = InMemSecretStore::default();
        let mut seeded = secrets.clone();
        seed_no_keys_contact(&mut seeded).await;

        let mut protocol = build(secrets, false);
        protocol
            .accept(PendingAction::pre_pair(
                CHANNEL,
                0,
                derec_proto::PrePairRequestMessage {
                    nonce: NONCE,
                    supported_transports: vec![
                        derec_proto::TransportProtocol {
                            uri: "http://192.168.1.42:8080".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        },
                        derec_proto::TransportProtocol {
                            uri: "https://helper.example.com".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        },
                    ],
                    timestamp: None,
                },
            ))
            .await
            .expect("the secure entry survives the plaintext one");
    });
}

/// A failed request has no success to send, so the token can only be
/// rejected.
#[test]
fn accepting_a_failed_request_is_refused() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::SharedKey(crate::types::SharedKey::new([0; 32])),
            )
            .await
            .expect("seed the reply channel's key");
        let mut protocol = build(secrets, false);
        let err = protocol
            .accept(
                PendingAction::failure(
                    CHANNEL,
                    1,
                    crate::protocol::ReplyTarget {
                        channel_id: CHANNEL,
                        endpoints: Vec::new(),
                    },
                    crate::protocol::FailedRequest::Undecodable,
                )
                .sealed_with(&crate::types::SharedKey::new([0; 32])),
            )
            .await
            .expect_err("a failed request cannot be accepted");
        assert!(
            matches!(
                err,
                crate::Error::InvalidInput("a failed request can only be rejected")
            ),
            "expected InvalidInput, got {err:?}"
        );
    });
}

/// The ordinary case stays working: a secure endpoint needs no flag.
#[test]
fn secure_reply_endpoint_needs_no_flag() {
    run_async(async {
        let secrets = InMemSecretStore::default();
        let mut seeded = secrets.clone();
        seed_no_keys_contact(&mut seeded).await;

        let mut protocol = build(secrets, false);
        protocol
            .accept(request_answering_on(
                "https://helper.example.com",
                derec_proto::Protocol::Https,
            ))
            .await
            .expect("a secure reply endpoint is dialled by default");
    });
}
