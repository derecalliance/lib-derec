// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! An owner's helper channel is `Unpairing` while its unpair awaits the
//! helper's answer.
//!
//! Under `UnpairAck::Required` the channel keeps its key until the helper
//! answers, so the answer can be read, but no flow may select it in the
//! meantime: a publish started in that window must not hand a share to a
//! helper that is about to delete it. `restore` unpairs its recovery channels
//! the same way, so the helpers' answers end those channels instead of
//! arriving on channels that no longer exist.

#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use std::collections::HashMap;

use derec_library::derec_message::{DeRecMessageBuilder, current_timestamp};
use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, HelperInfo, Secret, SecretValue,
    UserSecret,
};
use derec_library::protocol::{
    DeRecChannelStore as _, DeRecEvent, DeRecFlow, DeRecProtocol, DeRecProtocolBuilder,
    DeRecSecretStore as _,
};
use derec_library::types::{ChannelId, SharedKey};
use derec_proto::{
    DeRecResult, MessageBody, SenderKind, StatusEnum, TransportProtocol, UnpairResponseMessage,
};
use prost::Message as _;
use protocol_doubles::{
    InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
    InMemUserSecretStore, RecordingTransport, run_async,
};

const SECRET_ID: u64 = 0x0_A1B2;
const A: ChannelId = ChannelId(6060);
const B: ChannelId = ChannelId(6061);
const C: ChannelId = ChannelId(6062);
const TRACE: u64 = 0x7_ACE;

type Proto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

fn key(channel_id: ChannelId) -> SharedKey {
    [channel_id.0 as u8; 32]
}

fn endpoint(channel_id: ChannelId) -> TransportProtocol {
    TransportProtocol {
        uri: format!("https://helper-{}.example.com/derec", channel_id.0),
        protocol: derec_proto::Protocol::Https as i32,
    }
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
            .with_own_transports(["https://owner.example.com/derec"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds")
    }

    async fn seed_helper(&self, channel_id: ChannelId, status: ChannelStatus) {
        let mut channels = self.channels.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: vec![endpoint(channel_id)],
                    communication_info: HashMap::new(),
                    peer_role: SenderKind::Helper,
                    status,
                    created_at: now_secs(),
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper channel");
        let mut secrets = self.secrets.clone();
        secrets
            .save(
                SECRET_ID,
                channel_id,
                SecretValue::SharedKey(key(channel_id)),
            )
            .await
            .expect("seed channel key");
    }

    async fn status(&self, channel_id: ChannelId) -> Option<ChannelStatus> {
        self.channels
            .load(SECRET_ID, ChannelQuery::Helper { channel_id })
            .await
            .expect("load channel")
            .and_then(|record| record.as_helper().map(|helper| helper.status))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// The helper's answer to an unpair request, as it arrives on the wire.
fn unpair_answer(channel_id: ChannelId, status: StatusEnum) -> Vec<u8> {
    let timestamp = current_timestamp();
    DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .trace_id(TRACE)
        .message_body(MessageBody::UnpairResponse(UnpairResponseMessage {
            result: Some(DeRecResult {
                status: status as i32,
                memo: String::new(),
            }),
            timestamp: Some(timestamp),
        }))
        .encrypt(&key(channel_id))
        .expect("encrypt")
        .build()
        .expect("build")
        .encode_to_vec()
}

fn unpair(channel_id: ChannelId) -> DeRecFlow {
    DeRecFlow::Unpair {
        channel_id,
        memo: None,
    }
}

fn protect_secret() -> DeRecFlow {
    DeRecFlow::ProtectSecret {
        secrets: vec![UserSecret {
            id: b"id".to_vec(),
            name: "name".to_owned(),
            data: b"a secret the owner protects".to_vec(),
        }],
        description: None,
        weights: HashMap::new(),
        threshold: None,
    }
}

fn published_to(events: &[DeRecEvent]) -> Vec<ChannelId> {
    let mut channels: Vec<ChannelId> = events
        .iter()
        .filter_map(|event| match event {
            DeRecEvent::ProtectSecretStarted { channel_id, .. } => Some(*channel_id),
            _ => None,
        })
        .collect();
    channels.sort_by_key(|c| c.0);
    channels
}

#[test]
fn a_helper_is_unpairing_until_it_acknowledges() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper(A, ChannelStatus::Paired).await;
        let mut owner = rig.build();

        let events = owner.start(unpair(A)).await.expect("unpair starts");
        assert!(
            matches!(events.as_slice(), [DeRecEvent::UnpairStarted { channel_id, .. }] if *channel_id == A),
            "got {events:?}"
        );
        assert_eq!(rig.status(A).await, Some(ChannelStatus::Unpairing));

        let events = owner
            .process(&unpair_answer(A, StatusEnum::Ok))
            .await
            .expect("the answer lands on a channel that still exists");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == A)),
            "got {events:?}"
        );
        assert_eq!(rig.status(A).await, None, "the channel is gone");
    });
}

#[test]
fn a_rejected_unpair_returns_the_helper_to_paired() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper(A, ChannelStatus::Paired).await;
        let mut owner = rig.build();

        owner.start(unpair(A)).await.expect("unpair starts");
        let events = owner
            .process(&unpair_answer(A, StatusEnum::Rejected))
            .await
            .expect("a rejection is an event");

        assert!(
            events.iter().any(
                |e| matches!(e, DeRecEvent::UnpairRejected { channel_id, .. } if *channel_id == A)
            ),
            "got {events:?}"
        );
        assert_eq!(rig.status(A).await, Some(ChannelStatus::Paired));
    });
}

/// A `Pending` channel is already excluded from every flow, and a rejection
/// must not promote it, so the unpair leaves its status alone.
#[test]
fn unpairing_a_pending_helper_leaves_it_pending() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper(A, ChannelStatus::Pending).await;
        let mut owner = rig.build();

        owner.start(unpair(A)).await.expect("unpair starts");
        assert_eq!(rig.status(A).await, Some(ChannelStatus::Pending));

        owner
            .process(&unpair_answer(A, StatusEnum::Rejected))
            .await
            .expect("a rejection is an event");
        assert_eq!(rig.status(A).await, Some(ChannelStatus::Pending));
    });
}

#[test]
fn a_publish_skips_a_helper_being_unpaired() {
    run_async(async {
        let rig = Rig::default();
        for channel_id in [A, B, C] {
            rig.seed_helper(channel_id, ChannelStatus::Paired).await;
        }
        let mut owner = rig.build();

        owner.start(unpair(C)).await.expect("unpair starts");
        let events = owner.start(protect_secret()).await.expect("publish starts");

        assert_eq!(published_to(&events), vec![A, B], "got {events:?}");
    });
}

/// Restore unpairs its recovery channels like any other unpair, so the
/// recovery helpers' answers end those channels rather than failing
/// `process`, and the publish that follows restore reaches only the restored
/// helpers.
#[test]
fn the_recovery_helpers_answers_end_their_channels_after_restore() {
    run_async(async {
        let rig = Rig::default();
        rig.seed_helper(C, ChannelStatus::Paired).await;
        let mut owner = rig.build();

        let helper = |channel_id: ChannelId| HelperInfo {
            channel_id: channel_id.0,
            transports: vec![endpoint(channel_id)],
            shared_key: key(channel_id).to_vec(),
            communication_info: HashMap::new(),
            weight: 1,
        };
        let secret = Secret {
            helpers: vec![helper(A), helper(B)],
            secrets: Vec::new(),
            replicas: None,
            threshold: Some(2),
        };
        let events = owner.restore(&secret, 1).await.expect("restore succeeds");
        assert!(
            events.iter().any(
                |e| matches!(e, DeRecEvent::UnpairStarted { channel_id, .. } if *channel_id == C)
            ),
            "got {events:?}"
        );
        assert_eq!(rig.status(C).await, Some(ChannelStatus::Unpairing));

        let events = owner.start(protect_secret()).await.expect("publish starts");
        assert_eq!(published_to(&events), vec![A, B], "got {events:?}");

        let events = owner
            .process(&unpair_answer(C, StatusEnum::Ok))
            .await
            .expect("the recovery helper's answer is not an unknown channel");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == C)),
            "got {events:?}"
        );
        assert_eq!(rig.status(C).await, None);
    });
}
