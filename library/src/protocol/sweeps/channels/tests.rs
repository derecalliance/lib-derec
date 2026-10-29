// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::protocol::DeRecProtocol;
use crate::protocol::builder::DeRecProtocolBuilder;
use crate::protocol::tests::{
    InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore, InMemUserSecretStore,
    NoopTransport, run_async,
};
use crate::protocol::traits::{DeRecChannelStore, DeRecSecretStore};
use crate::protocol::types::SecretKind;
use crate::protocol::types::{
    ChannelRecord, ChannelStatus, ExpiredChannelCleanup, HelperChannel, ReplicaMember, ReplicaRole,
    SecretValue,
};
use crate::types::ChannelId;
use crate::utils::now_secs;

const SECRET_ID: u64 = 0xC1;

fn endpoint() -> derec_proto::TransportProtocol {
    derec_proto::TransportProtocol {
        uri: "https://peer.example.com".to_owned(),
        protocol: derec_proto::Protocol::Https as i32,
    }
}

/// Seed one channel whose `created_at` is `age_secs` in the past.
async fn seed(channels: &mut InMemChannelStore, cid: u64, status: ChannelStatus, age_secs: u64) {
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Helper(HelperChannel {
                channel_id: ChannelId(cid),
                transports: vec![endpoint()],
                communication_info: std::collections::HashMap::new(),
                status,
                created_at: now_secs().saturating_sub(age_secs),
                peer_role: derec_proto::SenderKind::Helper,
                weight: 1,
            }),
        )
        .await
        .expect("seed channel");
}

fn build(
    channels: InMemChannelStore,
    policy: ExpiredChannelCleanup,
    timeout_in_secs: u64,
) -> DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemStateStore,
    NoopTransport,
> {
    DeRecProtocolBuilder::new(SECRET_ID)
        .with_channel_store(channels)
        .with_share_store(InMemShareStore::default())
        .with_secret_store(InMemSecretStore::default())
        .with_user_secret_store(InMemUserSecretStore::default())
        .with_transport(NoopTransport)
        .with_state_store(InMemStateStore)
        .with_own_transports(["https://owner.example.com"])
        .with_threshold(2)
        .with_timeouts(crate::protocol::types::Timeouts {
            sharing_round: std::time::Duration::from_secs(timeout_in_secs),
            unpair_ack: std::time::Duration::from_secs(timeout_in_secs),
            inbound_message: std::time::Duration::from_secs(timeout_in_secs),
            expired_channels: policy,
        })
        .build()
        .expect("test protocol builds")
}

/// The manual sweep honours its own argument, not the configured
/// policy — `Disabled` means "I drive this myself", not "off".
#[test]
fn manual_sweep_works_under_disabled_policy() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
        let removed = protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert_eq!(removed, vec![ChannelId(1)]);
        assert!(channels.helper_rows.lock().unwrap().is_empty());
    });
}

/// Seed one replica member on the group channel.
async fn seed_member(
    channels: &mut InMemChannelStore,
    replica_id: u64,
    status: ChannelStatus,
    age_secs: u64,
) {
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Replica(ReplicaMember {
                channel_id: ChannelId(9000),
                replica_id: crate::types::ReplicaId(replica_id),
                transports: vec![endpoint()],
                communication_info: std::collections::HashMap::new(),
                role: ReplicaRole::Destination,
                status,
                created_at: now_secs().saturating_sub(age_secs),
            }),
        )
        .await
        .expect("seed member");
}

/// A replica pairing that never completed expires like any other, but
/// this device's own row is exempt: it is a roster entry, not a pending
/// handshake, and sweeping it would erase the group's self-reference.
#[test]
fn sweep_removes_expired_replica_members_but_never_this_device() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed_member(&mut seeded, 7, ChannelStatus::Pending, 600).await;
        seed_member(&mut seeded, 8, ChannelStatus::Paired, 600).await;
        seed_member(&mut seeded, 9, ChannelStatus::Pending, 600).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
        protocol.replica_id = Some(9);
        let removed = protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert_eq!(
            removed,
            vec![ChannelId(9000)],
            "members share one channel, so the group is reported once"
        );
        let rows = channels.member_rows.lock().unwrap();
        assert!(
            !rows.contains_key(&(SECRET_ID, 7)),
            "expired pending member"
        );
        assert!(rows.contains_key(&(SECRET_ID, 8)), "paired member survives");
        assert!(rows.contains_key(&(SECRET_ID, 9)), "own row is exempt");
    });
}

/// `Disabled` suppresses the automatic sweep inside `process()`, so an
/// over-age channel survives because nothing swept it.
#[test]
fn disabled_policy_leaves_channel_for_manual_sweep() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
        let _ = protocol.process(&[]).await;

        assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
    });
}

/// The policy's timeout governs the automatic sweep, not
/// `timeout_in_secs` — verified by setting them to different values
/// and choosing an age between the two.
#[test]
fn policy_timeout_governs_not_protocol_timeout() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 120).await;

        let mut protocol = build(
            channels.clone(),
            ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 60,
            },
            3600,
        );
        let _ = protocol.process(&[]).await;

        assert!(channels.helper_rows.lock().unwrap().is_empty());
    });
}

/// `Paired` channels are never swept, regardless of age.
#[test]
fn paired_channels_are_never_removed() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Paired, 99_999).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::default(), 300);
        let removed = protocol
            .remove_expired_channels(1)
            .await
            .expect("sweep succeeds");

        assert!(removed.is_empty());
        assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
    });
}

/// Removing a channel also drops its pairing material, so a stale
/// handshake leaves nothing behind in the secret store.
#[test]
fn removal_drops_pairing_material() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let secrets = InMemSecretStore::default();
        let mut seeded = channels.clone();
        let mut seeded_secrets = secrets.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 600).await;
        seeded_secrets
            .save(
                SECRET_ID,
                ChannelId(1),
                SecretValue::PairingContact(Default::default()),
            )
            .await
            .expect("seed pairing contact");

        let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets.clone())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_timeouts(crate::protocol::types::Timeouts {
                expired_channels: ExpiredChannelCleanup::Disabled,
                ..Default::default()
            })
            .build()
            .expect("test protocol builds");

        let removed = protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert_eq!(removed, vec![ChannelId(1)]);
        assert!(secrets.data.lock().unwrap().is_empty());
    });
}

/// An explicit zero is not clamped — the minimum-of-1 rule guards the
/// automatic sweep only. A `Pending` channel from an earlier second
/// goes; the `Paired` one stays.
#[test]
fn explicit_zero_sweeps_pending_from_earlier_seconds() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 1).await;
        seed(&mut seeded, 2, ChannelStatus::Paired, 1).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
        let removed = protocol
            .remove_expired_channels(0)
            .await
            .expect("sweep succeeds");

        assert_eq!(removed, vec![ChannelId(1)]);
        assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
    });
}

/// The comparison is strict, so a channel created within the current
/// second survives even the most aggressive threshold. This pins the
/// boundary the automatic sweep relies on to avoid deleting pairings
/// the instant they start.
#[test]
fn zero_age_channel_survives_zero_threshold() {
    run_async(async {
        let channels = InMemChannelStore::default();
        let mut seeded = channels.clone();
        seed(&mut seeded, 1, ChannelStatus::Pending, 0).await;

        let mut protocol = build(channels.clone(), ExpiredChannelCleanup::Disabled, 300);
        let removed = protocol
            .remove_expired_channels(0)
            .await
            .expect("sweep succeeds");

        assert!(removed.is_empty());
        assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
    });
}

fn build_with_secrets(
    channels: InMemChannelStore,
    secrets: InMemSecretStore,
) -> DeRecProtocol<
    InMemChannelStore,
    InMemShareStore,
    InMemSecretStore,
    InMemUserSecretStore,
    InMemStateStore,
    NoopTransport,
> {
    DeRecProtocolBuilder::new(SECRET_ID)
        .with_channel_store(channels)
        .with_share_store(InMemShareStore::default())
        .with_secret_store(secrets)
        .with_user_secret_store(InMemUserSecretStore::default())
        .with_transport(NoopTransport)
        .with_state_store(InMemStateStore)
        .with_own_transports(["https://owner.example.com"])
        .with_threshold(2)
        .with_timeouts(crate::protocol::types::Timeouts {
            expired_channels: ExpiredChannelCleanup::Disabled,
            ..Default::default()
        })
        .build()
        .expect("test protocol builds")
}

async fn seed_member_on(
    channels: &mut InMemChannelStore,
    channel_id: u64,
    replica_id: u64,
    status: ChannelStatus,
    age_secs: u64,
) {
    channels
        .save(
            SECRET_ID,
            ChannelRecord::Replica(ReplicaMember {
                channel_id: ChannelId(channel_id),
                replica_id: crate::types::ReplicaId(replica_id),
                transports: vec![endpoint()],
                communication_info: std::collections::HashMap::new(),
                role: ReplicaRole::Destination,
                status,
                created_at: now_secs().saturating_sub(age_secs),
            }),
        )
        .await
        .expect("seed member");
}

async fn seed_key(secrets: &mut InMemSecretStore, channel_id: u64) {
    secrets
        .save(
            SECRET_ID,
            ChannelId(channel_id),
            SecretValue::SharedKey(crate::types::SharedKey::new([3u8; 32])),
        )
        .await
        .expect("seed shared key");
}

fn has_key(secrets: &InMemSecretStore, channel_id: u64) -> bool {
    secrets
        .data
        .lock()
        .unwrap()
        .contains_key(&(SECRET_ID, channel_id, SecretKind::SharedKey as u8))
}

/// A pairing that expired unconfirmed leaves no channel key: with the
/// record gone, a retained key would decrypt the peer's messages again.
#[test]
fn an_expired_helper_pairing_loses_its_channel_key() {
    run_async(async {
        let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
        let (mut c, mut s) = (channels.clone(), secrets.clone());
        seed(&mut c, 1, ChannelStatus::Pending, 600).await;
        seed_key(&mut s, 1).await;

        let mut protocol = build_with_secrets(channels, secrets.clone());
        protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert!(!has_key(&secrets, 1));
    });
}

/// A replica pairing whose only peer expired leaves no channel key.
#[test]
fn an_expired_replica_pairing_loses_its_channel_key() {
    run_async(async {
        let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
        let (mut c, mut s) = (channels.clone(), secrets.clone());
        seed_member_on(&mut c, 9100, 7, ChannelStatus::Pending, 600).await;
        seed_key(&mut s, 9100).await;

        let mut protocol = build_with_secrets(channels, secrets.clone());
        protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert!(!has_key(&secrets, 9100));
    });
}

/// Members of a group share one channel and one key, so an expired
/// member does not take the key the remaining members still use.
#[test]
fn an_expired_member_leaves_the_key_of_a_channel_still_in_use() {
    run_async(async {
        let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
        let (mut c, mut s) = (channels.clone(), secrets.clone());
        seed_member_on(&mut c, 9000, 7, ChannelStatus::Pending, 600).await;
        seed_member_on(&mut c, 9000, 8, ChannelStatus::Paired, 600).await;
        seed_key(&mut s, 9000).await;

        let mut protocol = build_with_secrets(channels.clone(), secrets.clone());
        protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert!(has_key(&secrets, 9000));
        assert!(
            channels
                .member_rows
                .lock()
                .unwrap()
                .contains_key(&(SECRET_ID, 8))
        );
    });
}

/// This device's own `Pending` row belongs to the pairing, not to a
/// group: once no peer remains on its channel and it has expired, it goes
/// with the key.
#[test]
fn an_expired_own_row_with_no_peer_left_goes_with_the_key() {
    run_async(async {
        let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
        let (mut c, mut s) = (channels.clone(), secrets.clone());
        seed_member_on(&mut c, 9100, 7, ChannelStatus::Pending, 600).await;
        seed_member_on(&mut c, 9100, 9, ChannelStatus::Pending, 600).await;
        seed_key(&mut s, 9100).await;

        let mut protocol = build_with_secrets(channels.clone(), secrets.clone());
        protocol.replica_id = Some(9);
        protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert!(channels.member_rows.lock().unwrap().is_empty());
        assert!(!has_key(&secrets, 9100));
    });
}

/// An initiator waiting for its peer holds only its own `Pending` row; a
/// pairing that has not expired is not swept.
#[test]
fn a_fresh_own_row_awaiting_its_peer_survives() {
    run_async(async {
        let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
        let mut c = channels.clone();
        seed_member_on(&mut c, 9100, 9, ChannelStatus::Pending, 0).await;

        let mut protocol = build_with_secrets(channels.clone(), secrets);
        protocol.replica_id = Some(9);
        protocol
            .remove_expired_channels(60)
            .await
            .expect("sweep succeeds");

        assert!(
            channels
                .member_rows
                .lock()
                .unwrap()
                .contains_key(&(SECRET_ID, 9))
        );
    });
}

/// An unpair started on a channel that is still `Pending` leaves a state row
/// under that channel; the sweep that removes the channel removes the row
/// too, and leaves the row of a channel it keeps.
#[test]
fn an_expired_channel_takes_its_unpair_state_with_it() {
    use crate::protocol::tests::InMemPersistedStateStore;
    use crate::protocol::traits::DeRecStateStore;
    use crate::protocol::types::{StateItem, StateKey};

    run_async(async {
        let mut channels = InMemChannelStore::default();
        seed(&mut channels, 1, ChannelStatus::Pending, 600).await;
        seed(&mut channels, 2, ChannelStatus::Paired, 600).await;
        let mut state = InMemPersistedStateStore::default();
        for cid in [1, 2] {
            state
                .save(
                    SECRET_ID,
                    StateItem::PendingUnpair {
                        channel_id: ChannelId(cid),
                        started_at: now_secs(),
                    },
                )
                .await
                .expect("seed unpair state");
        }

        let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(state.clone())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds");
        let removed = protocol
            .remove_expired_channels(300)
            .await
            .expect("sweep succeeds");

        assert_eq!(removed, vec![ChannelId(1)]);
        let rows = state.data.lock().unwrap();
        assert!(!rows.contains_key(&(
            SECRET_ID,
            StateKey::PendingUnpair {
                channel_id: ChannelId(1)
            }
        )));
        assert!(rows.contains_key(&(
            SECRET_ID,
            StateKey::PendingUnpair {
                channel_id: ChannelId(2)
            }
        )));
    });
}

/// A secret store whose removals fail; everything else is in memory.
#[derive(Clone, Default)]
struct RefusingRemoveSecretStore(InMemSecretStore);

impl DeRecSecretStore for RefusingRemoveSecretStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> crate::protocol::SecretStoreFuture<'_, Option<SecretValue>> {
        self.0.load(secret_id, channel_id, kind)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: crate::protocol::types::MissingPolicy,
    ) -> crate::protocol::SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        self.0
            .load_many(secret_id, channel_ids, kind, missing_policy)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> crate::protocol::SecretStoreFuture<'_, ()> {
        self.0.save(secret_id, channel_id, value)
    }
    fn remove(
        &mut self,
        _: u64,
        _: ChannelId,
        _: SecretKind,
    ) -> crate::protocol::SecretStoreFuture<'_, ()> {
        refused()
    }
    fn remove_many(
        &mut self,
        _: u64,
        _: &[(ChannelId, SecretKind)],
    ) -> crate::protocol::SecretStoreFuture<'_, ()> {
        refused()
    }
}

fn refused() -> crate::protocol::SecretStoreFuture<'static, ()> {
    Box::pin(std::future::ready(Err(
        crate::protocol::error::SecretStoreError::Backend("secret store unavailable".into()),
    )))
}

/// When the channel key cannot be removed, the sweep fails before it removes
/// the record, so the next sweep finds the channel and retries instead of
/// leaving a key nothing points at.
#[test]
fn a_failed_key_removal_keeps_the_record_for_the_next_sweep() {
    run_async(async {
        let mut channels = InMemChannelStore::default();
        seed(&mut channels, 1, ChannelStatus::Pending, 600).await;
        let mut secrets = RefusingRemoveSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                ChannelId(1),
                SecretValue::SharedKey(crate::types::SharedKey::new([7; 32])),
            )
            .await
            .expect("seed key");

        let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets.clone())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds");

        assert!(protocol.remove_expired_channels(300).await.is_err());
        assert_eq!(channels.helper_rows.lock().unwrap().len(), 1);
        assert!(has_key(&secrets.0, 1));
    });
}
