// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Parties driven through the public API over a recording transport, routed
//! by URI, for the key-chain tests: owners and helpers on helper channels,
//! and a source with destinations on a replica group channel.
//!
//! A test crate including this module also includes `protocol_doubles` at its
//! root.

#![allow(dead_code)]

use std::collections::HashMap;

use derec_library::protocol::types::{
    ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, Secret, SecretValue,
    StateItem, UserSecret,
};
use derec_library::protocol::{
    AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecFlow, DeRecProtocol,
    DeRecProtocolBuilder, DeRecSecretStore as _, SecretKind,
};
use derec_library::types::{ChannelId, ReplicaId, SharedKey};
use derec_proto::{SenderKind, TransportProtocol};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message as _;
use sha2::Sha256;

use crate::protocol_doubles::{
    InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
    InMemUserSecretStore, RecordingTransport,
};

pub const SECRET_ID: u64 = 0x0_91E5;
pub const A: ChannelId = ChannelId(9001);
pub const B: ChannelId = ChannelId(9002);
pub const C: ChannelId = ChannelId(9003);
pub const GROUP: ChannelId = ChannelId(9100);
pub const EPHEMERAL: ChannelId = ChannelId(9200);
pub const SOURCE: u64 = 501;
pub const D1: u64 = 502;
pub const D2: u64 = 503;

pub const OWNER_URI: &str = "https://owner.example.com/derec";
pub const HELPER_A_URI: &str = "https://helper-a.example.com/derec";
pub const HELPER_B_URI: &str = "https://helper-b.example.com/derec";
pub const HELPER_C_URI: &str = "https://helper-c.example.com/derec";
pub const SOURCE_URI: &str = "https://source.example.com/derec";
pub const D1_URI: &str = "https://d1.example.com/derec";
pub const D2_URI: &str = "https://d2.example.com/derec";

pub type Proto = DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemPersistedStateStore,
    RecordingTransport,
>;

pub fn k0(channel_id: ChannelId) -> SharedKey {
    SharedKey::new([channel_id.0 as u8; 32])
}

/// K(to) from K(from), by the channel key chain.
pub fn derive(key: &SharedKey, from: u32, to: u32) -> SharedKey {
    let mut key = key.clone();
    for epoch in from + 1..=to {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
        mac.update(b"derec channel key v1");
        mac.update(&epoch.to_be_bytes());
        key = SharedKey::new(mac.finalize().into_bytes().into());
    }
    key
}

/// The key of `channel_id` at `epoch`, from the channel's pairing key.
pub fn key_at(channel_id: ChannelId, epoch: u32) -> [u8; 32] {
    *derive(&k0(channel_id), 0, epoch).as_bytes()
}

/// The contents of a stored ring, read from its encoding.
#[derive(Debug, PartialEq, Eq)]
pub struct RingView {
    pub epoch: u32,
    pub key: [u8; 32],
    pub pins: Vec<(u32, u32)>,
    pub old: Vec<(u32, [u8; 32])>,
}

impl RingView {
    pub fn decode(bytes: &[u8]) -> Self {
        let u32_at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        let u16_at = |at: usize| u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap());
        let key_at = |at: usize| -> [u8; 32] { bytes[at..at + 32].try_into().unwrap() };
        assert_eq!(bytes[0], 1, "ring encoding version");
        let epoch = u32_at(1);
        let key = key_at(5);
        let mut at = 37;
        let pin_count = u16_at(at);
        at += 2;
        let mut pins = Vec::new();
        for _ in 0..pin_count {
            pins.push((u32_at(at), u32_at(at + 4)));
            at += 8;
        }
        let old_count = u16_at(at);
        at += 2;
        let mut old = Vec::new();
        for _ in 0..old_count {
            old.push((u32_at(at), key_at(at + 4)));
            at += 36;
        }
        Self {
            epoch,
            key,
            pins,
            old,
        }
    }

    pub fn old_epochs(&self) -> Vec<u32> {
        self.old.iter().map(|(epoch, _)| *epoch).collect()
    }
}

pub fn endpoint(uri: &str) -> Vec<TransportProtocol> {
    vec![TransportProtocol {
        uri: uri.to_owned(),
        protocol: derec_proto::Protocol::Https as i32,
    }]
}

#[derive(Clone, Default)]
pub struct Party {
    pub channels: InMemChannelStore,
    pub shares: InMemShareStore,
    pub secrets: InMemSecretStore,
    pub user_secrets: InMemUserSecretStore,
    pub state: InMemPersistedStateStore,
    pub transport: RecordingTransport,
    pub uri: &'static str,
    pub replica_id: Option<u64>,
    /// Whether this party advances a channel's key on each new version.
    pub rotation: bool,
    /// The actions this party accepts without the application; `None`
    /// accepts StoreShare and VerifyShare.
    pub auto_accept: Option<AutoAcceptPolicy>,
    /// Whether this party answers a failed request itself.
    pub auto_respond: bool,
}

impl Party {
    pub fn new(uri: &'static str) -> Self {
        Self {
            uri,
            ..Default::default()
        }
    }

    pub fn rotating(uri: &'static str) -> Self {
        Self {
            uri,
            rotation: true,
            ..Default::default()
        }
    }

    pub fn build(&self) -> Proto {
        let mut builder = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(self.channels.clone())
            .with_share_store(self.shares.clone())
            .with_secret_store(self.secrets.clone())
            .with_user_secret_store(self.user_secrets.clone())
            .with_transport(self.transport.clone())
            .with_state_store(self.state.clone())
            .with_own_transports([self.uri])
            .with_threshold(2)
            .with_key_rotation(self.rotation)
            .with_auto_respond_on_failure(self.auto_respond)
            .with_auto_accept(self.auto_accept.unwrap_or(AutoAcceptPolicy {
                store_share: true,
                verify_share: true,
                ..Default::default()
            }));
        if let Some(replica_id) = self.replica_id {
            builder = builder.with_replica_id(replica_id);
        }
        builder.build().expect("test protocol builds")
    }

    pub async fn pair_helper(&self, channel_id: ChannelId, peer_role: SenderKind, uri: &str) {
        let mut channels = self.channels.clone();
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: endpoint(uri),
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
        secrets
            .save(
                SECRET_ID,
                channel_id,
                SecretValue::SharedKey(k0(channel_id)),
            )
            .await
            .expect("seed key");
    }

    /// Record `members` on `channel_id`, keyed with that channel's pairing
    /// key.
    pub async fn join_on(&self, channel_id: ChannelId, members: &[(u64, ReplicaRole, &str)]) {
        let mut channels = self.channels.clone();
        for (replica_id, role, uri) in members {
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id,
                        replica_id: ReplicaId(*replica_id),
                        transports: endpoint(uri),
                        communication_info: HashMap::new(),
                        role: *role,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed member");
        }
        let mut secrets = self.secrets.clone();
        secrets
            .save(
                SECRET_ID,
                channel_id,
                SecretValue::SharedKey(k0(channel_id)),
            )
            .await
            .expect("seed member key");
    }

    pub async fn join_group(&self, members: &[(u64, ReplicaRole, &str)]) {
        self.join_on(GROUP, members).await;
    }

    /// The stored ring of `channel_id`; a channel with no ring row is at
    /// epoch 0 under its shared key.
    pub fn ring(&self, channel_id: ChannelId) -> RingView {
        let data = self.secrets.data.lock().unwrap();
        match data.get(&(SECRET_ID, channel_id.0, SecretKind::KeyRing as u8)) {
            Some(SecretValue::KeyRing(ring)) => {
                RingView::decode(&ring.as_bytes().expect("a stored ring encodes"))
            }
            _ => match data.get(&(SECRET_ID, channel_id.0, SecretKind::SharedKey as u8)) {
                Some(SecretValue::SharedKey(key)) => RingView {
                    epoch: 0,
                    key: *key.as_bytes(),
                    pins: Vec::new(),
                    old: Vec::new(),
                },
                _ => panic!("{channel_id:?} has no key"),
            },
        }
    }

    pub fn keep(&self, keep: u32) {
        *self.shares.keep.lock().unwrap() = Some(keep);
    }

    pub fn stored_versions(&self, channel_id: ChannelId) -> Vec<u32> {
        let mut versions: Vec<u32> = self
            .shares
            .data
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, c, _)| *s == SECRET_ID && *c == channel_id.0)
            .map(|(_, _, v)| *v)
            .collect();
        versions.sort_unstable();
        versions
    }

    /// The committed share a helper stores for `version` on `channel_id`: a
    /// helper keeps the whole request it accepted.
    pub fn share_bytes(&self, channel_id: ChannelId, version: u32) -> Vec<u8> {
        let stored = self
            .shares
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, channel_id.0, version))
            .unwrap_or_else(|| panic!("no share of v{version} on {channel_id:?}"))
            .bytes
            .clone();
        derec_proto::StoreShareRequestMessage::decode(stored.as_slice())
            .expect("a helper stores the request")
            .share
    }

    pub async fn protect(&self) -> Vec<DeRecEvent> {
        self.build()
            .start(DeRecFlow::ProtectSecret {
                secrets: vec![UserSecret {
                    id: b"id".to_vec(),
                    name: "name".to_owned(),
                    data: b"a secret the owner protects".to_vec(),
                }],
                description: None,
                weights: HashMap::new(),
                threshold: None,
            })
            .await
            .expect("the round starts")
    }

    pub async fn verify(&self, version: u32) -> Vec<DeRecEvent> {
        self.build()
            .start(DeRecFlow::VerifyShares {
                secret_id: SECRET_ID,
                version,
                target: derec_library::protocol::types::Target::All,
            })
            .await
            .expect("verification starts")
    }

    /// Start every open sharing round's window at the epoch of the clock,
    /// so the next sweep times out whoever has not answered.
    pub fn age_rounds(&self) {
        for item in self.state.data.lock().unwrap().values_mut() {
            if let StateItem::SharingRound(round) = item {
                round.started_at = 0;
            }
        }
    }

    /// Run the timeout sweeps once.
    pub async fn tick(&self) -> Vec<DeRecEvent> {
        self.build().tick().await
    }

    /// Answer the ring query of `channel_id` with a value of another kind,
    /// as a store with a broken kind mapping would.
    pub fn misfile_ring(&self, channel_id: ChannelId) {
        self.secrets.data.lock().unwrap().insert(
            (SECRET_ID, channel_id.0, SecretKind::KeyRing as u8),
            SecretValue::SharedKey(k0(channel_id)),
        );
    }

    /// Take every envelope this party sent to `uri`, in send order.
    pub fn take_sent_to(&self, uri: &str) -> Vec<Vec<u8>> {
        let mut sent = self.transport.sent.lock().unwrap();
        let (taken, kept): (Vec<_>, Vec<_>) = sent
            .drain(..)
            .partition(|(endpoints, _)| endpoints[0].uri == uri);
        *sent = kept;
        taken.into_iter().map(|(_, bytes)| bytes).collect()
    }

    /// Drop everything this party has sent so far, as if it never arrived.
    pub fn drop_sent(&self) {
        self.transport.sent.lock().unwrap().clear();
    }
}

/// The `sequence` of an envelope.
pub fn sequence_of(envelope: &[u8]) -> u32 {
    derec_proto::DeRecMessage::decode(envelope)
        .expect("an envelope decodes")
        .sequence
}

/// Process at `to` every envelope `from` sent to it; the events of all of
/// them, and every result's error rendered.
pub async fn deliver(from: &Party, to: &Party) -> (Vec<DeRecEvent>, Vec<String>) {
    let mut events = Vec::new();
    let mut errors = Vec::new();
    for bytes in from.take_sent_to(to.uri) {
        match to.build().process(&bytes).await {
            Ok(e) => events.extend(e),
            Err(e) => errors.push(format!("{e:?}")),
        }
    }
    (events, errors)
}

/// Deliver from `from` to `to`, failing on any error or ignored message.
pub async fn deliver_clean(from: &Party, to: &Party) -> Vec<DeRecEvent> {
    let (events, errors) = deliver(from, to).await;
    assert!(errors.is_empty(), "{errors:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
        "{events:?}"
    );
    events
}

/// The secret of `version`, reconstructed from the shares `holders` store,
/// as a recovering owner reconstructs it.
pub fn recover(holders: &[(&Party, ChannelId)], version: u32) -> Secret {
    let responses: Vec<derec_proto::GetShareResponseMessage> = holders
        .iter()
        .map(|(party, channel_id)| derec_proto::GetShareResponseMessage {
            result: Some(derec_proto::DeRecResult {
                status: derec_proto::StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            committed_de_rec_share: party.share_bytes(*channel_id, version),
            ..Default::default()
        })
        .collect();
    let refs: Vec<&derec_proto::GetShareResponseMessage> = responses.iter().collect();
    let recovered =
        derec_library::primitives::recovery::response::recover(SECRET_ID, version, &refs)
            .expect("the shares reconstruct the secret");
    let wrapped = derec_proto::DeRecSecret::decode(recovered.secret_data.as_slice())
        .expect("the reconstruction is a DeRecSecret");
    Secret::decode(&wrapped.secret_data).expect("the secret decodes")
}
