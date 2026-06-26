// SPDX-License-Identifier: Apache-2.0

//! Post-recovery rebuild handler.
//!
//! Takes a [`Secret`] handed up by a
//! [`DeRecEvent::SecretRecovered`](super::super::DeRecEvent::SecretRecovered)
//! event and reseats the protocol's `secret_id` namespace from it:
//! writes canonical helper / replica channel records, commits the
//! user-secret snapshot, then unpairs every other channel under the
//! `secret_id` (the recovery-mode channels minted to drive
//! `start(RecoverSecret)` — scrap after restore commits).
//!
//! Two preconditions are reported as [`RestoreError`] (wrapped in
//! [`crate::Error::Restore`]) **before any store mutation** — a
//! precondition error is exactly equivalent to never having called
//! restore:
//!
//! - [`RestoreError::AlreadyRestored`] — a user-secret snapshot
//!   already exists for this `secret_id`.
//! - [`RestoreError::Conflict`] — a channel already lives at one of
//!   the canonical helper / replica ids carried by the recovered
//!   `Secret`.
//!
//! Store I/O failures mid-restore propagate as their underlying
//! [`crate::Error`] variant (`ShareStore`, `ChannelStore`,
//! `SecretStore`). The snapshot write is the commit point — nothing
//! is removed before it succeeds, so any mid-flight failure leaves
//! state the next `restore` call can detect as one of the
//! preconditions above.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, PendingUnpair, SecretValue, UnpairAck,
    types::{Channel, ChannelStatus, HelperInfo, Replicas, Secret, Share, Target, UserSecrets},
};
use crate::{
    Result,
    types::{ChannelId, SharedKey},
};
use std::collections::HashSet;

#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
#[cfg(target_arch = "wasm32")]
use crate::wasm::now_secs;

/// Restore-specific failure modes surfaced via [`crate::Error::Restore`].
/// Every variant is reported **before any store mutation** — a
/// precondition error is exactly equivalent to never having called
/// restore. Store I/O failures mid-restore propagate as their
/// underlying [`crate::Error`] variant instead.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    /// A user-secret snapshot already exists for the protocol's
    /// `secret_id`. The application must clear it before retrying.
    #[error("user-secret snapshot already exists for secret_id")]
    AlreadyRestored,

    /// One or more channels already live at canonical helper or
    /// replica ids carried by the recovered `Secret`. The contained
    /// list enumerates the collisions; the application clears them
    /// through its own store wrappers and retries.
    #[error("restore blocked by pre-existing channels at canonical ids")]
    Conflict(Vec<ChannelId>),

    /// The recovered [`Secret`] is internally inconsistent. Only
    /// reachable when a `Secret` was hand-crafted — library-produced
    /// ones always satisfy the invariants (see
    /// [`super::sharing::build_secret`]).
    #[error("recovered Secret is internally inconsistent: {0}")]
    Invariant(&'static str),
}

/// Run the restore flow. On success: canonical helper channels are
/// persisted with `SharedKey` + owner-side tracking shares at
/// `recovered_version`; canonical replica channels are persisted with
/// the group key from `secret.replicas.shared_key`; the user-secret
/// snapshot is committed at `recovered_version`; `local_replica_id`
/// adopts `secret.owner_replica_id` if previously unset; every
/// recovery-mode channel under `secret_id` is unpaired
/// (`UnpairAck::NotRequired`). The returned events come from the
/// recovery-channel wipe and should be drained into the protocol's
/// `pending_start_events`.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn restore<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    pending_unpair: &mut PendingUnpair,
    local_replica_id: &mut Option<u64>,
    secret_id: u64,
    secret: &Secret,
    recovered_version: u32,
) -> Result<Vec<DeRecEvent>> {
    let (canonical_ids, existing_channels) =
        check_preconditions(user_secret_store, channel_store, secret_id, secret).await?;

    write_helper_channels(
        channel_store,
        share_store,
        secret_store,
        secret_id,
        &secret.helpers,
        recovered_version,
    )
    .await?;

    // TODO: move this logic into write_replica_channels so this code looks cleaner
    if let Some(group) = secret.replicas.as_ref().filter(|g| !g.replicas.is_empty()) {
        write_replica_channels(channel_store, secret_store, secret_id, group).await?;
    }

    commit_snapshot(user_secret_store, secret_id, secret, recovered_version).await?;

    adopt_owner_replica_id(local_replica_id, secret.owner_replica_id);

    let events = unpair_recovery_channels(
        channel_store,
        share_store,
        secret_store,
        transport,
        pending_unpair,
        secret_id,
        &existing_channels,
        &canonical_ids,
    )
    .await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        helpers_restored = secret.helpers.len(),
        replicas_restored = secret.replicas.as_ref().map_or(0, |g| g.replicas.len()),
        user_secrets_restored = secret.secrets.len(),
        "DeRecProtocol restored from recovered Secret"
    );

    Ok(events)
}

/// Validate that the protocol is in a state where restore can run AND
/// collect the data the rest of the flow needs (canonical id set +
/// the current channel list, reused for the recovery-channel wipe).
///
/// Surfaces [`RestoreError::AlreadyRestored`] when a snapshot is
/// already committed, [`RestoreError::Invariant`] when
/// `secret.replicas.shared_key` is mis-sized, and
/// [`RestoreError::Conflict`] when an existing channel sits at a
/// canonical helper / replica id. All three are reported before any
/// store mutation.
async fn check_preconditions<Ch: DeRecChannelStore, Us: DeRecUserSecretStore>(
    user_secret_store: &Us,
    channel_store: &Ch,
    secret_id: u64,
    secret: &Secret,
) -> Result<(HashSet<u64>, Vec<Channel>)> {
    if user_secret_store.load_latest(secret_id).await?.is_some() {
        return Err(RestoreError::AlreadyRestored.into());
    }

    if let Some(group) = &secret.replicas {
        if !group.replicas.is_empty() && group.shared_key.len() != 32 {
            return Err(RestoreError::Invariant(
                "recovered Secret carries replicas but replicas.shared_key is missing or wrong size",
            )
            .into());
        }
    }

    // Channels not at canonical ids are recovery channels — wiped
    // after the commit, not flagged as collisions.
    let canonical_ids: HashSet<u64> = secret
        .helpers
        .iter()
        .map(|h| h.channel_id)
        .chain(
            secret
                .replicas
                .as_ref()
                .into_iter()
                .flat_map(|g| g.replicas.iter().map(|r| r.channel_id)),
        )
        .collect();
    let existing_channels = channel_store.channels(secret_id).await?;
    let collisions: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| canonical_ids.contains(&c.id.0))
        .map(|c| c.id)
        .collect();
    if !collisions.is_empty() {
        return Err(RestoreError::Conflict(collisions).into());
    }

    Ok((canonical_ids, existing_channels))
}

/// Persist each helper's canonical channel record, its `SharedKey`,
/// and an empty owner-side tracking [`Share`] at `recovered_version`.
async fn write_helper_channels<Ch: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    secret_id: u64,
    helpers: &[HelperInfo],
    recovered_version: u32,
) -> Result<()> {
    for h in helpers {
        let cid = ChannelId(h.channel_id);
        let shared_key: SharedKey = h
            .shared_key
            .as_slice()
            .try_into()
            .map_err(|_| RestoreError::Invariant("helper.shared_key must be 32 bytes"))?;
        channel_store
            .save(
                secret_id,
                Channel {
                    id: cid,
                    transport: derec_proto::TransportProtocol {
                        uri: h.transport_uri.clone(),
                        protocol: derec_proto::Protocol::Https as i32,
                    },
                    communication_info: h.communication_info.clone(),
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    role: derec_proto::SenderKind::Owner,
                    replica_id: None,
                },
            )
            .await?;
        secret_store
            .save(secret_id, cid, SecretValue::SharedKey(shared_key))
            .await?;
        share_store
            .save(
                secret_id,
                cid,
                Share {
                    secret_id,
                    version: recovered_version,
                    replica_id: None,
                    bytes: Vec::new(),
                },
            )
            .await?;
    }
    Ok(())
}

/// Persist each replica destination's canonical channel record
/// (with the group key as its `SharedKey`). The local role on each
/// restored channel is the inverse of the peer's `sender_kind`
/// carried in the recovered `Secret`.
///
/// Caller guarantees `group.replicas` is non-empty.
async fn write_replica_channels<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    secret_id: u64,
    group: &Replicas,
) -> Result<()> {
    let group_key: SharedKey = group.shared_key.as_slice().try_into().map_err(|_| {
        RestoreError::Invariant("replicas.shared_key must be 32 bytes when replicas is non-empty")
    })?;
    for r in &group.replicas {
        let peer_kind = derec_proto::SenderKind::try_from(r.sender_kind)
            .map_err(|_| RestoreError::Invariant("replica.sender_kind invalid"))?;
        let local_role = super::pairing::derive_peer_kind(peer_kind);
        let cid = ChannelId(r.channel_id);
        channel_store
            .save(
                secret_id,
                Channel {
                    id: cid,
                    transport: derec_proto::TransportProtocol {
                        uri: r.transport_uri.clone(),
                        protocol: derec_proto::Protocol::Https as i32,
                    },
                    communication_info: r.communication_info.clone(),
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    role: local_role,
                    replica_id: Some(r.replica_id),
                },
            )
            .await?;
        secret_store
            .save(secret_id, cid, SecretValue::SharedKey(group_key))
            .await?;
    }
    Ok(())
}

/// Commit the user-secret snapshot at `recovered_version`. This write
/// is the commit point — nothing is removed before it succeeds, so any
/// earlier failure is fully retryable.
async fn commit_snapshot<Us: DeRecUserSecretStore>(
    user_secret_store: &mut Us,
    secret_id: u64,
    secret: &Secret,
    recovered_version: u32,
) -> Result<()> {
    user_secret_store
        .save_latest(
            secret_id,
            UserSecrets {
                version: recovered_version,
                secrets: secret.secrets.clone(),
                description: None,
                replicas: secret.replicas.clone(),
            },
        )
        .await?;
    Ok(())
}

/// Adopt `owner_replica_id` from the recovered `Secret` when the
/// builder left the local replica id unset. Zero is the "no replica
/// id" sentinel — don't adopt it.
fn adopt_owner_replica_id(local_replica_id: &mut Option<u64>, owner_replica_id: u64) {
    if local_replica_id.is_none() && owner_replica_id != 0 {
        *local_replica_id = Some(owner_replica_id);
    }
}

/// Send unpair requests to every channel that isn't at a canonical id
/// (i.e. the recovery-mode channels minted to drive
/// `start(RecoverSecret)`) and drop local state. Forces
/// `UnpairAck::NotRequired` so the wipe is synchronous regardless of
/// the protocol's configured ack mode.
#[allow(clippy::too_many_arguments)]
async fn unpair_recovery_channels<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    pending_unpair: &mut PendingUnpair,
    secret_id: u64,
    existing_channels: &[Channel],
    canonical_ids: &HashSet<u64>,
) -> Result<Vec<DeRecEvent>> {
    let recovery_ids: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| !canonical_ids.contains(&c.id.0))
        .map(|c| c.id)
        .collect();
    if recovery_ids.is_empty() {
        return Ok(Vec::new());
    }
    super::unpairing::start(
        channel_store,
        share_store,
        secret_store,
        transport,
        pending_unpair,
        secret_id,
        Target::Many(recovery_ids),
        None,
        UnpairAck::NotRequired,
        now_secs(),
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DeRecProtocolBuilder;
    use crate::protocol::traits::{
        ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
        DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture, TransportFuture,
    };
    use crate::protocol::types::{
        Channel, ChannelStatus, HelperInfo, MissingPolicy, ReplicaInfo, Replicas, Secret,
        SecretKind, SecretValue, Share, UserSecret, UserSecrets,
    };
    use derec_proto::{SenderKind, TransportProtocol};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    // ---- In-memory store impls, shared across both test paths ----------
    //
    // `Arc<Mutex<...>>` so we can pre-seed the inner data BEFORE building
    // the protocol (the protocol owns the impl, so the only mutation
    // path post-construction is through the trait).

    #[derive(Default, Clone)]
    struct InMemChannelStore {
        data: Arc<Mutex<HashMap<(u64, u64), Channel>>>,
    }
    impl DeRecChannelStore for InMemChannelStore {
        fn load(&self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
            let v = self.data.lock().unwrap().get(&(sid, cid.0)).cloned();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn save(&mut self, sid: u64, c: Channel) -> ChannelStoreFuture<'_, ()> {
            self.data.lock().unwrap().insert((sid, c.id.0), c);
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove(&mut self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, bool> {
            let removed = self.data.lock().unwrap().remove(&(sid, cid.0)).is_some();
            Box::pin(std::future::ready(Ok(removed)))
        }
        fn channels(&self, sid: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
            let v: Vec<Channel> = self
                .data
                .lock()
                .unwrap()
                .iter()
                .filter(|((s, _), _)| *s == sid)
                .map(|(_, c)| c.clone())
                .collect();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn link_channel(
            &mut self,
            _: u64,
            _: ChannelId,
            _: ChannelId,
        ) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn linked_channels(
            &self,
            _: u64,
            cid: ChannelId,
        ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
            Box::pin(std::future::ready(Ok(vec![cid])))
        }
    }

    #[derive(Default, Clone)]
    struct InMemSecretStore {
        data: Arc<Mutex<HashMap<(u64, u64, u8), SecretValue>>>,
    }
    impl DeRecSecretStore for InMemSecretStore {
        fn load(
            &self,
            sid: u64,
            cid: ChannelId,
            kind: SecretKind,
        ) -> SecretStoreFuture<'_, Option<SecretValue>> {
            let v = self
                .data
                .lock()
                .unwrap()
                .get(&(sid, cid.0, kind as u8))
                .cloned();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn load_many(
            &self,
            sid: u64,
            cids: &[ChannelId],
            kind: SecretKind,
            _: MissingPolicy,
        ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
            let mut out = Vec::new();
            for c in cids {
                if let Some(v) = self.data.lock().unwrap().get(&(sid, c.0, kind as u8)) {
                    out.push((*c, v.clone()));
                }
            }
            Box::pin(std::future::ready(Ok(out)))
        }
        fn save(
            &mut self,
            sid: u64,
            cid: ChannelId,
            value: SecretValue,
        ) -> SecretStoreFuture<'_, ()> {
            let k = match &value {
                SecretValue::SharedKey(_) => SecretKind::SharedKey as u8,
                SecretValue::PairingSecret(_) => SecretKind::PairingSecret as u8,
                SecretValue::PairingContact(_) => SecretKind::PairingContact as u8,
            };
            self.data.lock().unwrap().insert((sid, cid.0, k), value);
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove(
            &mut self,
            sid: u64,
            cid: ChannelId,
            kind: SecretKind,
        ) -> SecretStoreFuture<'_, ()> {
            self.data.lock().unwrap().remove(&(sid, cid.0, kind as u8));
            Box::pin(std::future::ready(Ok(())))
        }
    }

    #[derive(Default, Clone)]
    struct InMemShareStore {
        data: Arc<Mutex<HashMap<(u64, u64, u32), Share>>>,
    }
    impl DeRecShareStore for InMemShareStore {
        fn load(
            &self,
            sid: u64,
            cid: ChannelId,
            versions: &[u32],
        ) -> ShareStoreFuture<'_, Vec<Share>> {
            let lock = self.data.lock().unwrap();
            let out: Vec<Share> = lock
                .iter()
                .filter(|((s, c, v), _)| {
                    *s == sid && *c == cid.0 && (versions.is_empty() || versions.contains(v))
                })
                .map(|(_, s)| s.clone())
                .collect();
            Box::pin(std::future::ready(Ok(out)))
        }
        fn load_many(
            &self,
            _: u64,
            _: &[ChannelId],
            _: &[u32],
        ) -> ShareStoreFuture<'_, Vec<Share>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
        fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
        fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
            Box::pin(std::future::ready(Ok(None)))
        }
        fn save(&mut self, sid: u64, cid: ChannelId, share: Share) -> ShareStoreFuture<'_, ()> {
            let v = share.version;
            self.data.lock().unwrap().insert((sid, cid.0, v), share);
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
    }

    #[derive(Default, Clone)]
    struct InMemUserSecretStore {
        data: Arc<Mutex<HashMap<u64, UserSecrets>>>,
    }
    impl DeRecUserSecretStore for InMemUserSecretStore {
        fn load_latest(&self, sid: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
            let v = self.data.lock().unwrap().get(&sid).cloned();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn save_latest(&mut self, sid: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
            self.data.lock().unwrap().insert(sid, value);
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove(&mut self, sid: u64) -> ShareStoreFuture<'_, ()> {
            self.data.lock().unwrap().remove(&sid);
            Box::pin(std::future::ready(Ok(())))
        }
    }

    #[derive(Default, Clone)]
    struct NoopTransport;
    impl DeRecTransport for NoopTransport {
        fn send(&self, _: &TransportProtocol, _: Vec<u8>) -> TransportFuture<'_> {
            Box::pin(std::future::ready(Ok(())))
        }
    }

    type TestProto = crate::protocol::DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        NoopTransport,
    >;

    /// Test bundle — keeps clone handles to every store so the test
    /// can both pre-seed before construction AND inspect after the
    /// restore call.
    struct TestRig {
        protocol: TestProto,
        channel_store: InMemChannelStore,
        secret_store: InMemSecretStore,
        share_store: InMemShareStore,
        user_secret_store: InMemUserSecretStore,
    }

    fn build_rig(secret_id: u64) -> TestRig {
        let channel_store = InMemChannelStore::default();
        let secret_store = InMemSecretStore::default();
        let share_store = InMemShareStore::default();
        let user_secret_store = InMemUserSecretStore::default();
        let protocol = DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(channel_store.clone())
            .with_share_store(share_store.clone())
            .with_secret_store(secret_store.clone())
            .with_user_secret_store(user_secret_store.clone())
            .with_transport(NoopTransport)
            .with_own_transport("https://owner.example.com")
            .with_threshold(2)
            .build()
            .expect("test rig builds");
        TestRig {
            protocol,
            channel_store,
            secret_store,
            share_store,
            user_secret_store,
        }
    }

    fn fixture_secret() -> Secret {
        Secret {
            helpers: vec![
                HelperInfo {
                    channel_id: 11,
                    transport_uri: "https://helper-a.example".to_owned(),
                    shared_key: vec![0xAA; 32],
                    communication_info: HashMap::from([("name".to_owned(), "HelperA".to_owned())]),
                },
                HelperInfo {
                    channel_id: 12,
                    transport_uri: "https://helper-b.example".to_owned(),
                    shared_key: vec![0xBB; 32],
                    communication_info: HashMap::new(),
                },
            ],
            secrets: vec![
                UserSecret {
                    id: vec![0x01],
                    name: "wallet".to_owned(),
                    data: b"correct horse battery staple".to_vec(),
                },
                UserSecret {
                    id: vec![0x02],
                    name: "api token".to_owned(),
                    data: b"hunter2".to_vec(),
                },
            ],
            replicas: Some(Replicas {
                replicas: vec![ReplicaInfo {
                    channel_id: 21,
                    transport_uri: "https://replica.example".to_owned(),
                    communication_info: HashMap::new(),
                    replica_id: 0xCAFE,
                    sender_kind: SenderKind::ReplicaDestination as i32,
                }],
                shared_key: vec![0xCC; 32],
            }),
            owner_replica_id: 0xBEEF,
        }
    }

    fn run_async<F: std::future::Future<Output = ()>>(f: F) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    // ---------------- Happy path ----------------

    #[test]
    fn restore_happy_path_persists_canonical_state() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            rig.protocol
                .restore(&fixture_secret(), 7)
                .await
                .expect("happy path must succeed");

            // Helper channels: status=Paired, role=Owner, no replica_id.
            for hid in [11_u64, 12] {
                let ch = rig
                    .channel_store
                    .load(secret_id, ChannelId(hid))
                    .await
                    .unwrap()
                    .expect("helper channel must be persisted");
                assert_eq!(ch.status, ChannelStatus::Paired);
                assert_eq!(ch.role, SenderKind::Owner);
                assert!(ch.replica_id.is_none());
                let sk = rig
                    .secret_store
                    .load(secret_id, ChannelId(hid), SecretKind::SharedKey)
                    .await
                    .unwrap()
                    .expect("helper SharedKey must be persisted");
                assert!(matches!(sk, SecretValue::SharedKey(_)));
                let shares = rig
                    .share_store
                    .load(secret_id, ChannelId(hid), &[])
                    .await
                    .unwrap();
                assert_eq!(shares.len(), 1);
                assert_eq!(shares[0].version, 7);
            }

            // Replica channel: role inverted from peer's sender_kind,
            // group key persisted.
            let rep = rig
                .channel_store
                .load(secret_id, ChannelId(21))
                .await
                .unwrap()
                .expect("replica channel must be persisted");
            assert_eq!(rep.status, ChannelStatus::Paired);
            assert_eq!(rep.role, SenderKind::ReplicaSource);
            assert_eq!(rep.replica_id, Some(0xCAFE));
            let rep_sk = rig
                .secret_store
                .load(secret_id, ChannelId(21), SecretKind::SharedKey)
                .await
                .unwrap()
                .expect("replica group key must be persisted");
            match rep_sk {
                SecretValue::SharedKey(k) => assert_eq!(k.to_vec(), vec![0xCC; 32]),
                _ => panic!("expected SharedKey"),
            }

            // User-secret snapshot at recovered version.
            let snapshot = rig
                .user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .expect("snapshot must exist");
            assert_eq!(snapshot.version, 7);
            assert_eq!(snapshot.secrets.len(), 2);
            assert_eq!(snapshot.secrets[0].name, "wallet");
            assert_eq!(snapshot.secrets[0].data, b"correct horse battery staple");
            assert_eq!(snapshot.secrets[1].name, "api token");

            // replica_id adopted (builder default was None).
            assert_eq!(rig.protocol.replica_id(), Some(0xBEEF));
        });
    }

    // ---------------- Recovery-channel wipe ----------------

    #[test]
    fn restore_unpairs_pre_existing_recovery_channels() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            // Two recovery channels at ids that don't collide with any
            // canonical helper or replica id from `fixture_secret`.
            // Each needs a SharedKey in `secret_store` so the unpair
            // handler can build the encrypted request envelope.
            for rcid in [99_u64, 100] {
                rig.channel_store.data.lock().unwrap().insert(
                    (secret_id, rcid),
                    Channel {
                        id: ChannelId(rcid),
                        transport: TransportProtocol {
                            uri: format!("https://recovery-{rcid}.example"),
                            protocol: 0,
                        },
                        communication_info: HashMap::new(),
                        status: ChannelStatus::Paired,
                        created_at: 1,
                        role: SenderKind::Owner,
                        replica_id: None,
                    },
                );
                rig.secret_store.data.lock().unwrap().insert(
                    (secret_id, rcid, SecretKind::SharedKey as u8),
                    SecretValue::SharedKey([0x77; 32]),
                );
            }

            rig.protocol
                .restore(&fixture_secret(), 7)
                .await
                .expect("restore must succeed despite recovery channels");

            // Recovery channels and their SharedKeys are gone.
            for rcid in [99_u64, 100] {
                assert!(
                    rig.channel_store
                        .load(secret_id, ChannelId(rcid))
                        .await
                        .unwrap()
                        .is_none(),
                    "recovery channel {rcid} must be unpaired"
                );
                assert!(
                    rig.secret_store
                        .load(secret_id, ChannelId(rcid), SecretKind::SharedKey)
                        .await
                        .unwrap()
                        .is_none()
                );
            }

            // Canonical state is in place.
            assert!(
                rig.channel_store
                    .load(secret_id, ChannelId(11))
                    .await
                    .unwrap()
                    .is_some()
            );
        });
    }

    // ---------------- Preconditions ----------------

    #[test]
    fn restore_returns_already_restored_when_snapshot_exists() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);
            rig.user_secret_store.data.lock().unwrap().insert(
                secret_id,
                UserSecrets {
                    version: 1,
                    secrets: Vec::new(),
                    description: None,
                    replicas: None,
                },
            );

            let err = rig
                .protocol
                .restore(&fixture_secret(), 7)
                .await
                .unwrap_err();
            assert!(matches!(
                err,
                crate::Error::Restore(RestoreError::AlreadyRestored)
            ));

            // No mutation: no canonical channel written.
            assert!(
                rig.channel_store
                    .load(secret_id, ChannelId(11))
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn restore_returns_conflict_on_canonical_id_collision() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);
            // Pre-seed a channel sitting at canonical helper id 11.
            rig.channel_store.data.lock().unwrap().insert(
                (secret_id, 11),
                Channel {
                    id: ChannelId(11),
                    transport: TransportProtocol {
                        uri: "https://collision.example".to_owned(),
                        protocol: 0,
                    },
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 1,
                    role: SenderKind::Owner,
                    replica_id: None,
                },
            );

            let err = rig
                .protocol
                .restore(&fixture_secret(), 7)
                .await
                .unwrap_err();
            let crate::Error::Restore(RestoreError::Conflict(ids)) = err else {
                panic!("expected Restore(Conflict), got {err:?}");
            };
            assert_eq!(ids, vec![ChannelId(11)]);

            // No mutation beyond the pre-seed.
            assert!(
                rig.user_secret_store
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn restore_invariant_error_when_replicas_present_but_group_key_missing() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);
            let mut secret = fixture_secret();
            if let Some(group) = secret.replicas.as_mut() {
                group.shared_key = Vec::new();
            }

            let err = rig.protocol.restore(&secret, 7).await.unwrap_err();
            assert!(matches!(
                err,
                crate::Error::Restore(RestoreError::Invariant(_))
            ));

            // No mutation.
            assert!(
                rig.channel_store
                    .load(secret_id, ChannelId(11))
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    // ---------------- Explicit replica_id corner ----------------

    #[test]
    fn restore_does_not_overwrite_explicit_replica_id() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            // Builder configured WITH a replica id — restore must
            // leave it alone even though the Secret carries a
            // non-zero owner_replica_id.
            let mut protocol = DeRecProtocolBuilder::new(secret_id)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_own_transport("https://owner.example.com")
                .with_threshold(2)
                .with_replica_id(0x1234)
                .build()
                .expect("build");

            protocol.restore(&fixture_secret(), 7).await.unwrap();
            assert_eq!(protocol.replica_id(), Some(0x1234));
        });
    }
}
