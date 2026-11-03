// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Every envelope the owner sends on a channel carries, in `sequence`, the
//! epoch of the key its payload is encrypted under. A channel with no key
//! ring is at epoch 0.

#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use std::collections::HashMap;

use derec_library::protocol::types::{
    ChannelRecord, ChannelStatus, HelperChannel, SecretValue, Share, Target, UserSecret,
};
use derec_library::protocol::{
    DeRecChannelStore as _, DeRecFlow, DeRecProtocol, DeRecProtocolBuilder, DeRecSecretStore as _,
    DeRecShareStore as _, KeyRing, UnpairAck,
};
use derec_library::types::{ChannelId, SharedKey};
use derec_proto::{DeRecMessage, SenderKind, TransportProtocol};
use prost::Message as _;
use protocol_doubles::{
    InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
    InMemUserSecretStore, RecordingTransport, run_async,
};

const SECRET_ID: u64 = 0x0_E90C;
const A: ChannelId = ChannelId(7070);
const B: ChannelId = ChannelId(7071);
const EPOCH: u32 = 2;

type Proto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

fn key(channel_id: ChannelId) -> SharedKey {
    SharedKey::new([channel_id.0 as u8; 32])
}

fn ring_at(epoch: u32, key: &SharedKey) -> KeyRing {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    KeyRing::from_bytes(&bytes).expect("a ring with no pins decodes")
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
            .with_unpair_ack(UnpairAck::Required)
            .with_channel_store(self.channels.clone())
            .with_share_store(self.shares.clone())
            .with_secret_store(self.secrets.clone())
            .with_user_secret_store(self.user_secrets.clone())
            .with_transport(self.transport.clone())
            .with_state_store(self.state.clone())
            .with_own_transports(["https://owner.example.com/derec"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds")
    }

    /// A paired helper holding a proof for version 1. `epoch` of `None` leaves
    /// the channel with a `SharedKey` row and no ring row.
    async fn seed_helper(&self, channel_id: ChannelId, epoch: Option<u32>) {
        let mut channels = self.channels.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: vec![TransportProtocol {
                        uri: format!("https://helper-{}.example.com/derec", channel_id.0),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    communication_info: HashMap::new(),
                    peer_role: SenderKind::Helper,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper channel");
        let mut secrets = self.secrets.clone();
        if let Some(epoch) = epoch {
            secrets
                .save(
                    SECRET_ID,
                    channel_id,
                    SecretValue::KeyRing(ring_at(epoch, &key(channel_id))),
                )
                .await
                .expect("seed key ring");
        }
        secrets
            .save(
                SECRET_ID,
                channel_id,
                SecretValue::SharedKey(key(channel_id)),
            )
            .await
            .expect("seed channel key");
        let mut shares = self.shares.clone();
        shares
            .save(
                SECRET_ID,
                channel_id,
                Share {
                    secret_id: SECRET_ID,
                    version: 1,
                    bytes: Vec::new(),
                    subshares: Some(1),
                    threshold: Some(2),
                },
            )
            .await
            .expect("seed proof");
    }

    /// The sequence of every envelope sent so far, paired with the channel it
    /// was addressed to.
    fn sent(&self) -> Vec<(ChannelId, u32, DeRecMessage)> {
        self.transport
            .sent_envelopes()
            .iter()
            .map(|bytes| {
                let envelope = DeRecMessage::decode(bytes.as_slice()).expect("envelope decodes");
                (ChannelId(envelope.channel_id), envelope.sequence, envelope)
            })
            .collect()
    }
}

fn flows() -> Vec<(&'static str, DeRecFlow)> {
    vec![
        (
            "VerifyShares",
            DeRecFlow::VerifyShares {
                secret_id: SECRET_ID,
                version: 1,
                target: Target::All,
            },
        ),
        (
            "Discovery",
            DeRecFlow::Discovery {
                target: Target::All,
            },
        ),
        (
            "RecoverSecret",
            DeRecFlow::RecoverSecret {
                secret_id: SECRET_ID,
                version: 1,
            },
        ),
        (
            "UpdateChannelInfo",
            DeRecFlow::UpdateChannelInfo {
                target: Target::All,
                communication_info: Some(HashMap::from([("name".to_owned(), "owner".to_owned())])),
                own_transports: Vec::new(),
            },
        ),
        (
            "ProtectSecret",
            DeRecFlow::ProtectSecret {
                secrets: vec![UserSecret {
                    id: b"id".to_vec(),
                    name: "name".to_owned(),
                    data: b"a secret the owner protects".to_vec(),
                }],
                description: None,
                weights: HashMap::new(),
                threshold: None,
            },
        ),
        (
            "Unpair",
            DeRecFlow::Unpair {
                channel_id: A,
                memo: None,
            },
        ),
    ]
}

#[test]
fn every_owner_request_carries_the_channel_epoch() {
    for (name, flow) in flows() {
        run_async(async {
            let rig = Rig::default();
            rig.seed_helper(A, Some(EPOCH)).await;
            rig.seed_helper(B, Some(EPOCH)).await;
            let mut owner = rig.build();

            owner.start(flow).await.expect("the flow starts");

            let sent = rig.sent();
            assert!(!sent.is_empty(), "{name} sent nothing");
            for (channel_id, sequence, envelope) in sent {
                assert_eq!(
                    sequence, EPOCH,
                    "{name}: the envelope for {channel_id:?} carries the wrong epoch"
                );
                derec_library::derec_message::extract_inner_message(
                    &envelope.message,
                    &key(channel_id),
                )
                .unwrap_or_else(|e| panic!("{name}: the epoch key opens the envelope: {e:?}"));
            }
        });
    }
}

#[test]
fn a_channel_without_a_ring_sends_sequence_zero() {
    for (name, flow) in flows() {
        run_async(async {
            let rig = Rig::default();
            rig.seed_helper(A, None).await;
            rig.seed_helper(B, None).await;
            let mut owner = rig.build();

            owner.start(flow).await.expect("the flow starts");

            let sent = rig.sent();
            assert!(!sent.is_empty(), "{name} sent nothing");
            for (channel_id, sequence, _) in sent {
                assert_eq!(sequence, 0, "{name}: {channel_id:?} has no ring");
            }
        });
    }
}
