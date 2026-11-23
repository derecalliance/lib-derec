// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! An inbound channel message is opened under the key of the epoch its
//! envelope's `sequence` names. A newer epoch within the forward limit is
//! followed once its message decrypts; an epoch with no usable key is ignored.

#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use std::collections::HashMap;

use derec_library::derec_message::{DeRecMessageBuilder, current_timestamp};
use derec_library::protocol::types::{
    ChannelRecord, ChannelStatus, HelperChannel, SecretValue, Share, Target,
};
use derec_library::protocol::{
    AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecFlow, DeRecProtocol,
    DeRecProtocolBuilder, DeRecSecretStore as _, DeRecShareStore as _, IgnoreReason, KeyRing,
    SecretKind,
};
use derec_library::types::{ChannelId, ChannelKey, SharedKey};
use derec_proto::{DeRecMessage, MessageBody, SenderKind, TransportProtocol};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message as _;
use protocol_doubles::{
    InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
    InMemUserSecretStore, RecordingTransport, run_async,
};
use sha2::Sha256;

const SECRET_ID: u64 = 0x0_F011;
const CHANNEL: ChannelId = ChannelId(8080);
const OWNER_URI: &str = "https://owner.example.com/derec";
const LIMIT: u32 = 512;

type Proto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

fn k0() -> SharedKey {
    SharedKey::new([0x5A; 32])
}

/// K(epoch) from K(from), by the channel key chain.
fn derive(key: &SharedKey, from: u32, to: u32) -> SharedKey {
    let mut key = key.clone();
    for epoch in from + 1..=to {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
        mac.update(b"derec channel key v1");
        mac.update(&epoch.to_be_bytes());
        key = SharedKey::new(mac.finalize().into_bytes().into());
    }
    key
}

/// A ring at `epoch` holding `key`, with `old` as `(version, epoch, key)`
/// pins and the keys they name.
fn ring(epoch: u32, key: &SharedKey, old: &[(u32, u32, SharedKey)]) -> KeyRing {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&(old.len() as u16).to_be_bytes());
    for (version, pinned, _) in old {
        bytes.extend_from_slice(&version.to_be_bytes());
        bytes.extend_from_slice(&pinned.to_be_bytes());
    }
    bytes.extend_from_slice(&(old.len() as u16).to_be_bytes());
    for (_, pinned, k) in old {
        bytes.extend_from_slice(&pinned.to_be_bytes());
        bytes.extend_from_slice(k.as_bytes());
    }
    KeyRing::from_bytes(&bytes).expect("a well-formed ring decodes")
}

#[derive(Clone, Default)]
struct Rig {
    channels: InMemChannelStore,
    shares: InMemShareStore,
    secrets: InMemSecretStore,
    user_secrets: InMemUserSecretStore,
    state: InMemPersistedStateStore,
    transport: RecordingTransport,
}

impl Rig {
    fn build(&self) -> Proto {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(self.channels.clone())
            .with_share_store(self.shares.clone())
            .with_secret_store(self.secrets.clone())
            .with_user_secret_store(self.user_secrets.clone())
            .with_transport(self.transport.clone())
            .with_state_store(self.state.clone())
            .with_own_transports(["https://self.example.com/derec"])
            .with_threshold(2)
            .with_auto_respond_on_failure(true)
            .with_auto_accept(AutoAcceptPolicy {
                verify_share: true,
                ..Default::default()
            })
            .build()
            .expect("test protocol builds")
    }

    /// A paired channel whose `SharedKey` row holds K0, optionally with a
    /// ring row, and a stored share for version 1.
    async fn seed(&self, peer_role: SenderKind, ring: Option<KeyRing>) {
        let mut channels = self.channels.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![TransportProtocol {
                        uri: OWNER_URI.to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    communication_info: HashMap::new(),
                    peer_role,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        let mut secrets = self.secrets.clone();
        if let Some(ring) = ring {
            secrets
                .save(SECRET_ID, CHANNEL, SecretValue::KeyRing(ring))
                .await
                .expect("seed ring");
        }
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey(k0()))
            .await
            .expect("seed key");
        let stored = derec_proto::StoreShareRequestMessage {
            secret_id: SECRET_ID,
            version: 1,
            share: b"a committed share".to_vec(),
            ..Default::default()
        };
        let mut shares = self.shares.clone();
        shares
            .save(
                SECRET_ID,
                CHANNEL,
                Share {
                    secret_id: SECRET_ID,
                    version: 1,
                    bytes: stored.encode_to_vec(),
                    subshares: Some(1),
                    threshold: Some(2),
                },
            )
            .await
            .expect("seed share");
    }

    /// The stored ring's encoding, or `None` when no ring row is stored.
    fn ring_bytes(&self) -> Option<Vec<u8>> {
        match self.secrets.data.lock().unwrap().get(&(
            SECRET_ID,
            CHANNEL.0,
            SecretKind::KeyRing as u8,
        )) {
            Some(SecretValue::KeyRing(r)) => Some(r.as_bytes().expect("a stored ring encodes")),
            _ => None,
        }
    }

    fn epoch(&self) -> u32 {
        match self.secrets.data.lock().unwrap().get(&(
            SECRET_ID,
            CHANNEL.0,
            SecretKind::KeyRing as u8,
        )) {
            Some(SecretValue::KeyRing(r)) => r.epoch(),
            _ => 0,
        }
    }

    fn sent_sequences(&self) -> Vec<u32> {
        self.transport
            .sent_envelopes()
            .iter()
            .map(|b| {
                DeRecMessage::decode(b.as_slice())
                    .expect("envelope")
                    .sequence
            })
            .collect()
    }
}

fn verify_request() -> MessageBody {
    MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
        secret_id: SECRET_ID,
        version: 1,
        nonce: 7,
        ..Default::default()
    })
}

fn envelope(sequence: u32, key: &SharedKey, mut body: MessageBody) -> DeRecMessage {
    let timestamp = current_timestamp();
    if let MessageBody::VerifyShareRequest(m) = &mut body {
        m.timestamp = Some(timestamp);
    }
    DeRecMessageBuilder::channel()
        .channel_id(CHANNEL)
        .timestamp(timestamp)
        .trace_id(9)
        .message_body(body)
        .encrypt(&ChannelKey::new(sequence, key.clone()))
        .expect("encrypt")
        .build()
        .expect("build")
}

fn wire(message: &DeRecMessage) -> Vec<u8> {
    message.encode_to_vec()
}

fn ignored(events: &[DeRecEvent], reason: IgnoreReason) -> bool {
    events.len() == 1
        && matches!(&events[0], DeRecEvent::MessageIgnored { reason: r, .. } if *r == reason)
}

#[test]
fn a_helper_follows_the_owner_to_a_newer_epoch() {
    run_async(async {
        let owner_rig = Rig::default();
        owner_rig
            .seed(SenderKind::Helper, Some(ring(1, &derive(&k0(), 0, 1), &[])))
            .await;
        let helper_rig = Rig::default();
        helper_rig.seed(SenderKind::Owner, None).await;

        let mut owner = owner_rig.build();
        owner
            .start(DeRecFlow::VerifyShares {
                secret_id: SECRET_ID,
                version: 1,
                target: Target::All,
            })
            .await
            .expect("verify starts");
        let request = owner_rig.transport.sent_envelopes().remove(0);

        helper_rig
            .build()
            .process(&request)
            .await
            .expect("the helper processes the request");

        assert_eq!(helper_rig.sent_sequences(), vec![1]);
        assert_eq!(helper_rig.epoch(), 1);
    });
}

#[test]
fn a_helper_answers_an_older_epoch_it_can_derive() {
    run_async(async {
        let k1 = derive(&k0(), 0, 1);
        let held = ring(16, &derive(&k1, 1, 16), &[(1, 1, k1.clone())]);
        let helper_rig = Rig::default();
        // The sender is not the owner, so the request is refused and the
        // refusal is the response, sent under the key the request opened with.
        helper_rig.seed(SenderKind::Helper, Some(held)).await;
        let before = helper_rig.ring_bytes();

        let request = envelope(2, &derive(&k1, 1, 2), verify_request());
        helper_rig
            .build()
            .process(&wire(&request))
            .await
            .expect("processes");

        assert_eq!(helper_rig.sent_sequences(), vec![2]);
        assert_eq!(helper_rig.ring_bytes(), before);
    });
}

#[test]
fn a_forged_far_ahead_sequence_is_ignored() {
    for sequence in [3 + LIMIT + 1, u32::MAX] {
        run_async(async {
            let helper_rig = Rig::default();
            helper_rig
                .seed(SenderKind::Owner, Some(ring(3, &derive(&k0(), 0, 3), &[])))
                .await;
            let before = helper_rig.ring_bytes();

            let mut forged = envelope(3, &derive(&k0(), 0, 3), verify_request());
            forged.sequence = sequence;
            let events = helper_rig
                .build()
                .process(&wire(&forged))
                .await
                .expect("an unusable epoch is not an error");

            assert!(ignored(&events, IgnoreReason::KeyUnavailable), "{events:?}");
            assert_eq!(helper_rig.ring_bytes(), before);
            assert!(helper_rig.sent_sequences().is_empty());
        });
    }
}

#[test]
fn a_sequence_below_every_held_key_is_ignored() {
    run_async(async {
        let helper_rig = Rig::default();
        helper_rig
            .seed(SenderKind::Owner, Some(ring(5, &derive(&k0(), 0, 5), &[])))
            .await;
        let before = helper_rig.ring_bytes();

        let request = envelope(2, &derive(&k0(), 0, 2), verify_request());
        let events = helper_rig
            .build()
            .process(&wire(&request))
            .await
            .expect("an unusable epoch is not an error");

        assert!(ignored(&events, IgnoreReason::KeyUnavailable), "{events:?}");
        assert_eq!(helper_rig.ring_bytes(), before);
        assert!(helper_rig.sent_sequences().is_empty());
    });
}

#[test]
fn a_follow_forward_is_kept_even_when_handling_fails() {
    run_async(async {
        let helper_rig = Rig::default();
        helper_rig.seed(SenderKind::Owner, None).await;

        // Version 9 has no stored share, so handling the request fails.
        let body = MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
            secret_id: SECRET_ID,
            version: 9,
            nonce: 7,
            ..Default::default()
        });
        let request = envelope(1, &derive(&k0(), 0, 1), body);
        let _ = helper_rig.build().process(&wire(&request)).await;

        assert_eq!(helper_rig.epoch(), 1);
    });
}

#[test]
fn a_failed_forward_save_is_retried_by_processing_again() {
    run_async(async {
        let helper_rig = Rig::default();
        helper_rig.seed(SenderKind::Owner, None).await;
        let request = wire(&envelope(1, &derive(&k0(), 0, 1), verify_request()));

        helper_rig.secrets.set_fail_save(Some(SecretKind::KeyRing));
        let mut helper = helper_rig.build();
        let first = helper.process(&request).await;
        assert!(first.is_err(), "a save failure is reported: {first:?}");
        assert_eq!(helper_rig.epoch(), 0);
        assert!(
            helper_rig.sent_sequences().is_empty(),
            "nothing was handled"
        );

        helper_rig.secrets.set_fail_save(None);
        helper
            .process(&request)
            .await
            .expect("the same bytes are processed on retry");
        assert_eq!(helper_rig.epoch(), 1);
        assert_eq!(helper_rig.sent_sequences(), vec![1]);
    });
}

#[test]
fn a_message_that_fails_to_decrypt_moves_nothing() {
    run_async(async {
        let helper_rig = Rig::default();
        helper_rig.seed(SenderKind::Owner, None).await;

        let wrong = SharedKey::new([0x01; 32]);
        let request = envelope(1, &wrong, verify_request());
        let result = helper_rig.build().process(&wire(&request)).await;

        assert!(result.is_err(), "{result:?}");
        assert_eq!(helper_rig.epoch(), 0);
        assert!(helper_rig.ring_bytes().is_none());
        assert!(helper_rig.sent_sequences().is_empty());
    });
}
