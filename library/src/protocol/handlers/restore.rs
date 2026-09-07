// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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
//! A third, [`crate::Error::Transport`], joins them: the roster stores each
//! peer as a bare `transport_uri`, so its protocol is derived from the URI
//! scheme on the way back in, and a scheme this library serves no transport
//! for cannot become a channel record. Checked with the other preconditions,
//! so it too costs no partial write.
//!
//! Store I/O failures mid-restore propagate as their underlying
//! [`crate::Error`] variant (`ShareStore`, `ChannelStore`,
//! `SecretStore`). The snapshot write is the commit point — nothing
//! is removed before it succeeds, so any mid-flight failure leaves
//! state the next `restore` call can detect as one of the
//! preconditions above.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, DeRecUserSecretStore, SecretValue, UnpairAck,
    types::{
        ChannelRecord, ChannelStatus, HelperChannel, HelperInfo, ReplicaMember, ReplicaRole,
        Replicas, Secret, Share, UserSecrets,
    },
};
use crate::{
    Result,
    types::{ChannelId, SharedKey},
};
use std::collections::HashSet;

#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

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
    /// ones always satisfy the invariants (rebuilt inside the sharing
    /// handler during a `start(ProtectSecret)` round).
    #[error("recovered Secret is internally inconsistent: {0}")]
    Invariant(&'static str),
}

/// Run the restore flow. On success: canonical helper channels are
/// persisted with `SharedKey` + owner-side tracking shares at
/// `recovered_version`; canonical replica channels are persisted with
/// the group key from `secret.replicas.shared_key`; the user-secret
/// snapshot is committed at `recovered_version`; every
/// recovery-mode channel under `secret_id` is unpaired
/// (`UnpairAck::NotRequired`). The returned events come from the
/// recovery-channel wipe and should be drained into the protocol's
/// `pending_start_events`.
///
/// # Sequence
///
/// 1. **Preconditions.** Validate the protocol can restore and collect
///    what the rest of the flow needs (the canonical id set plus the
///    current channel list, reused for the wipe).
///    [`RestoreError::AlreadyRestored`] when a snapshot is already
///    committed, [`RestoreError::Invariant`] when
///    `secret.replicas.shared_key` is mis-sized, and
///    [`RestoreError::Conflict`] when an existing channel sits at a
///    canonical helper / replica id, and [`crate::Error::Transport`] when
///    a roster entry names a URI scheme this library serves no transport
///    for. All four are reported before any store mutation. Channels *not*
///    at canonical ids are recovery channels — wiped in step 5, never
///    flagged as collisions.
/// 2. **Helper channels.** Persist each helper's canonical channel
///    record, its `SharedKey`, and an empty owner-side tracking
///    [`Share`] at `recovered_version`.
/// 3. **Replica members.** Persist every member of the roster against the
///    one group channel, with the group key as that channel's `SharedKey`.
///    Each member's `role` is taken verbatim from the roster: it is a
///    property of the group, not of the reader.
///
///    The device's own `replica_id` is **not** adopted from the recovered
///    `Secret`. The roster names its source, but a recovering device
///    claiming that identity is a takeover, which is a separate decision
///    with its own convergence rules. A device that was built without a
///    `replica_id` still has none after restore and cannot publish as a
///    replica until the application configures one.
/// 4. **Commit.** Write the user-secret snapshot at
///    `recovered_version`. This write is the commit point — nothing is
///    removed before it succeeds, so any earlier failure is fully
///    retryable.
/// 5. **Wipe.** Send unpair requests to every channel not at a
///    canonical id — the recovery-mode channels minted to drive
///    `start(RecoverSecret)` — and drop their local state.
///
///    `UnpairAck::NotRequired` is forced here, deliberately, and does
///    not follow the protocol's configured ack mode. Waiting on an
///    acknowledgement would keep the ephemeral channels alive for up to
///    the unpair timeout, and those channels are indistinguishable from
///    the canonical ones to
///    [`sharing`](super::sharing) — which selects purely on
///    `peer_role == Helper && status == Paired` — so a subsequent
///    `ProtectSecret` would double-send to every helper. The ephemeral
///    channels must be gone by the time this call returns.
///
///    For the same reason the wipe cannot fail the restore. An old
///    helper that has gone away is the expected condition during
///    recovery, and the commit in step 4 has already happened —
///    returning `Err` here would strand the caller with committed
///    canonical state, un-torn-down ephemeral channels, and
///    [`RestoreError::AlreadyRestored`] blocking any retry. Instead each
///    undeliverable teardown surfaces as
///    [`DeRecEvent::UnpairFailed`] and local state is dropped anyway, so
///    every wiped channel still yields exactly one
///    [`DeRecEvent::Unpaired`].
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn restore<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    state_store: &mut St,
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

    if let Some(group) = secret.replicas.as_ref().filter(|g| !g.members.is_empty()) {
        write_replica_channels(channel_store, secret_store, secret_id, group).await?;
    }

    commit_snapshot(user_secret_store, secret_id, secret, recovered_version).await?;

    let events = unpair_recovery_channels(
        channel_store,
        share_store,
        secret_store,
        transport,
        state_store,
        secret_id,
        &existing_channels,
        &canonical_ids,
    )
    .await;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        helpers_restored = secret.helpers.len(),
        replicas_restored = secret.replicas.as_ref().map_or(0, |g| g.members.len()),
        user_secrets_restored = secret.secrets.len(),
        "DeRecProtocol restored from recovered Secret"
    );

    Ok(events)
}

async fn check_preconditions<Ch: DeRecChannelStore, Us: DeRecUserSecretStore>(
    user_secret_store: &Us,
    channel_store: &Ch,
    secret_id: u64,
    secret: &Secret,
) -> Result<(HashSet<u64>, Vec<HelperChannel>)> {
    if user_secret_store.load_latest(secret_id).await?.is_some() {
        return Err(RestoreError::AlreadyRestored.into());
    }

    if let Some(group) = &secret.replicas
        && !group.members.is_empty()
        && group.shared_key.len() != 32
    {
        return Err(RestoreError::Invariant(
            "recovered Secret carries replicas but replicas.shared_key is missing or wrong size",
        )
        .into());
    }

    // Rehydrating an endpoint derives its protocol from the URI scheme, so a
    // roster naming a scheme this library does not serve cannot be turned into
    // channel records at all. Checked here, alongside the other preconditions,
    // so the refusal costs no partial write.
    // A roster entry with no endpoint cannot be restored into a usable
    // channel — there would be nothing to send to. Checked here, alongside
    // the other preconditions, so the refusal costs no partial write.
    //
    // The endpoints themselves need no re-derivation: a v3 roster stores each
    // one with its protocol discriminant, and a v2 roster had its single URI
    // resolved during decode.
    let rosters_have_endpoints = secret
        .helpers
        .iter()
        .map(|h| &h.transports)
        .chain(
            secret
                .replicas
                .iter()
                .flat_map(|g| g.members.iter().map(|m| &m.transports)),
        )
        .all(|endpoints| !endpoints.is_empty());

    if !rosters_have_endpoints {
        return Err(crate::Error::InvalidInput(
            "recovered roster has an entry with no transport endpoint",
        ));
    }

    // Every member shares the group channel, so the roster contributes one id
    // rather than one per member.
    let canonical_ids: HashSet<u64> = secret
        .helpers
        .iter()
        .map(|h| h.channel_id)
        .chain(secret.replicas.as_ref().map(|g| g.channel_id))
        .collect();
    let existing_channels = channel_store.helpers(secret_id).await?;
    let collisions: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| canonical_ids.contains(&c.channel_id.0))
        .map(|c| c.channel_id)
        .collect();
    if !collisions.is_empty() {
        return Err(RestoreError::Conflict(collisions).into());
    }

    Ok((canonical_ids, existing_channels))
}

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
                ChannelRecord::Helper(HelperChannel {
                    channel_id: cid,
                    transports: h.transports.clone(),
                    communication_info: h.communication_info.clone(),
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    peer_role: derec_proto::SenderKind::Helper,
                }),
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
                    bytes: Vec::new(),
                },
            )
            .await?;
    }
    Ok(())
}

async fn write_replica_channels<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    secret_id: u64,
    group: &Replicas,
) -> Result<()> {
    let group_key: SharedKey = group.shared_key.as_slice().try_into().map_err(|_| {
        RestoreError::Invariant("replicas.shared_key must be 32 bytes when replicas is non-empty")
    })?;
    let cid = ChannelId(group.channel_id);
    for r in &group.members {
        channel_store
            .save(
                secret_id,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: cid,
                    replica_id: crate::types::ReplicaId::try_from(r.replica_id)?,
                    transports: r.transports.clone(),
                    communication_info: r.communication_info.clone(),
                    role: ReplicaRole::from_i32(r.role).ok_or(RestoreError::Invariant(
                        "roster member carries an unknown role",
                    ))?,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
    }
    // One key at the one channel every member is addressed on.
    secret_store
        .save(secret_id, cid, SecretValue::SharedKey(group_key))
        .await?;
    Ok(())
}

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

#[allow(clippy::too_many_arguments)]
async fn unpair_recovery_channels<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    state_store: &mut St,
    secret_id: u64,
    existing_channels: &[HelperChannel],
    canonical_ids: &HashSet<u64>,
) -> Vec<DeRecEvent> {
    let recovery_ids: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| !canonical_ids.contains(&c.channel_id.0))
        .map(|c| c.channel_id)
        .collect();
    if recovery_ids.is_empty() {
        return Vec::new();
    }
    let now = now_secs();
    let mut events = Vec::new();
    for channel_id in recovery_ids {
        match super::unpairing::start(
            channel_store,
            share_store,
            secret_store,
            transport,
            state_store,
            secret_id,
            channel_id,
            None,
            UnpairAck::NotRequired,
            now,
            &[],
        )
        .await
        {
            Ok(mut per_channel) => events.append(&mut per_channel),
            Err(e) => {
                events.push(DeRecEvent::UnpairFailed {
                    channel_id,
                    error: e.to_string(),
                });
                if super::unpairing::drop_channel_state(
                    channel_store,
                    share_store,
                    secret_store,
                    secret_id,
                    channel_id,
                )
                .await
                .is_ok()
                {
                    events.push(DeRecEvent::Unpaired { channel_id });
                }
            }
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DeRecProtocolBuilder;
    use crate::protocol::traits::{
        DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecUserSecretStore,
    };
    use crate::protocol::types::{
        ChannelQuery, ChannelRecord, ChannelStatus, HelperInfo, ReplicaInfo, ReplicaRole, Replicas,
        Secret, SecretKind, SecretValue, UserSecret, UserSecrets,
    };
    use derec_proto::{SenderKind, TransportProtocol};
    use std::collections::HashMap;

    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };

    type TestProto = crate::protocol::DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
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
            .with_state_store(InMemStateStore)
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
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://helper-a.example".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    shared_key: vec![0xAA; 32],
                    communication_info: HashMap::from([("name".to_owned(), "HelperA".to_owned())]),
                },
                HelperInfo {
                    channel_id: 12,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://helper-b.example".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
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
                channel_id: 21,
                members: vec![
                    ReplicaInfo {
                        replica_id: 0xBEEF,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://owner.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        role: ReplicaRole::Source as i32,
                        communication_info: HashMap::new(),
                    },
                    ReplicaInfo {
                        replica_id: 0xCAFE,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://replica.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        role: ReplicaRole::Destination as i32,
                        communication_info: HashMap::new(),
                    },
                ],
                shared_key: vec![0xCC; 32],
            }),
        }
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
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(hid),
                        },
                    )
                    .await
                    .unwrap()
                    .expect("helper channel must be persisted");
                let ChannelRecord::Helper(ch) = ch else {
                    panic!("a helper query must never return a replica record");
                };
                assert_eq!(ch.status, ChannelStatus::Paired);
                assert_eq!(ch.peer_role, SenderKind::Helper);
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

            // Replica member: the roster records each member's own role
            // verbatim — it is absolute, not relative to the reader.
            let rep = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Replica {
                        channel_id: ChannelId(21),
                        replica_id: crate::types::ReplicaId(0xCAFE),
                    },
                )
                .await
                .unwrap()
                .expect("replica member must be persisted");
            let ChannelRecord::Replica(rep) = rep else {
                panic!("a replica query must never return a helper record");
            };
            assert_eq!(rep.status, ChannelStatus::Paired);
            assert_eq!(rep.role, ReplicaRole::Destination);
            assert_eq!(rep.replica_id.0, 0xCAFE);
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

            // The device does not take the source's identity. The roster
            // names its source, but adopting that id is a takeover — a
            // separate decision with its own convergence rules — so a device
            // built without a replica_id still has none after restore.
            assert_eq!(
                rig.protocol.replica_id(),
                None,
                "restore must not adopt the roster source's replica_id"
            );
        });
    }

    // ---------------- Endpoint rehydration ----------------

    /// The roster stores a bare `transport_uri` and no protocol discriminant,
    /// so restore has to derive one. Pairing it with a fixed `Https` made every
    /// gRPC-paired peer come back as `{grpcs://…, Https}` — a combination
    /// `TransportProtocol::validate` rejects outright, which breaks the first
    /// send after every recovery.
    #[test]
    fn a_grpc_peer_is_rehydrated_as_grpc() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.helpers[0].transports = vec![derec_proto::TransportProtocol {
                uri: "grpcs://helper-a.example:443".to_owned(),
                protocol: derec_proto::Protocol::Grpc as i32,
            }];
            let members = &mut secret
                .replicas
                .as_mut()
                .expect("fixture has a roster")
                .members;
            members[1].transports = vec![derec_proto::TransportProtocol {
                uri: "grpcs://replica.example:443".to_owned(),
                protocol: derec_proto::Protocol::Grpc as i32,
            }];

            rig.protocol
                .restore(&secret, 7)
                .await
                .expect("a grpc roster must restore");

            let helper = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(11),
                    },
                )
                .await
                .unwrap()
                .expect("helper channel must be persisted");
            let ChannelRecord::Helper(helper) = helper else {
                panic!("a helper query must never return a replica record");
            };
            assert_eq!(helper.transports[0].uri, "grpcs://helper-a.example:443");
            assert_eq!(
                helper.transports[0].protocol,
                derec_proto::Protocol::Grpc as i32,
                "a grpcs:// helper must come back as Grpc, not the historical \
                 hardcoded Https"
            );
            for endpoint in &helper.transports {
                crate::transport::TransportProtocol::try_from(endpoint)
                    .expect("every rehydrated endpoint must be self-consistent");
            }

            let member = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Replica {
                        channel_id: ChannelId(21),
                        replica_id: crate::types::ReplicaId(0xCAFE),
                    },
                )
                .await
                .unwrap()
                .expect("replica member must be persisted");
            let ChannelRecord::Replica(member) = member else {
                panic!("a replica query must never return a helper record");
            };
            assert_eq!(member.transports[0].uri, "grpcs://replica.example:443");
            assert_eq!(
                member.transports[0].protocol,
                derec_proto::Protocol::Grpc as i32,
                "a grpcs:// group member must come back as Grpc"
            );

            // The https:// entries in the same roster are unaffected — the
            // discriminant follows each URI, not the roster as a whole.
            let other = rig
                .channel_store
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: ChannelId(12),
                    },
                )
                .await
                .unwrap()
                .expect("helper channel must be persisted");
            let ChannelRecord::Helper(other) = other else {
                panic!("a helper query must never return a replica record");
            };
            assert_eq!(
                other.transports[0].protocol,
                derec_proto::Protocol::Https as i32
            );
        });
    }

    /// A roster entry that names no endpoint cannot become a usable channel
    /// — there would be nothing to send to. Refused with the rest of the
    /// preconditions, so nothing is written and the call stays retryable.
    #[test]
    fn a_roster_entry_without_an_endpoint_is_refused_before_any_write() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.helpers[1].transports = Vec::new();

            let err = rig
                .protocol
                .restore(&secret, 7)
                .await
                .expect_err("a peer with no endpoint must not restore silently");
            assert!(
                matches!(err, crate::Error::InvalidInput(_)),
                "expected the precondition refusal, got {err:?}"
            );

            assert!(
                rig.channel_store
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(11)
                        }
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "a precondition failure must leave the stores untouched"
            );
            assert!(
                rig.user_secret_store
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_none(),
                "a precondition failure must not commit a snapshot"
            );
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
                rig.channel_store.helper_rows.lock().unwrap().insert(
                    (secret_id, rcid),
                    HelperChannel {
                        channel_id: ChannelId(rcid),
                        transports: vec![TransportProtocol {
                            uri: format!("https://recovery-{rcid}.example"),
                            protocol: 0,
                        }],
                        communication_info: HashMap::new(),
                        status: ChannelStatus::Paired,
                        created_at: 1,
                        peer_role: SenderKind::Helper,
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
                        .load(
                            secret_id,
                            ChannelQuery::Helper {
                                channel_id: ChannelId(rcid),
                            },
                        )
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
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(11),
                        },
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        });
    }

    /// An old helper that has gone away is the *expected* condition
    /// during recovery, so a failed teardown must not undo a committed
    /// restore.
    #[test]
    fn restore_succeeds_when_recovery_channel_unpair_cannot_be_delivered() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let channel_store = InMemChannelStore::default();
            let secret_store = InMemSecretStore::default();
            let share_store = InMemShareStore::default();
            let user_secret_store = InMemUserSecretStore::default();
            let mut protocol = DeRecProtocolBuilder::new(secret_id)
                .with_channel_store(channel_store.clone())
                .with_share_store(share_store.clone())
                .with_secret_store(secret_store.clone())
                .with_user_secret_store(user_secret_store.clone())
                .with_transport(crate::protocol::test::FailingTransport)
                .with_state_store(InMemStateStore)
                .with_own_transport("https://owner.example.com")
                .with_threshold(2)
                .build()
                .expect("test rig builds");

            channel_store.helper_rows.lock().unwrap().insert(
                (secret_id, 99),
                HelperChannel {
                    channel_id: ChannelId(99),
                    transports: vec![TransportProtocol {
                        uri: "https://gone.example".to_owned(),
                        protocol: 0,
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 1,
                    peer_role: SenderKind::Helper,
                },
            );
            secret_store.data.lock().unwrap().insert(
                (secret_id, 99, SecretKind::SharedKey as u8),
                SecretValue::SharedKey([0x77; 32]),
            );

            let events = protocol
                .restore(&fixture_secret(), 7)
                .await
                .expect("an unreachable peer must not fail the restore");

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::UnpairFailed { channel_id, .. } if *channel_id == ChannelId(99)
                )),
                "the undeliverable teardown must be reported, got {events:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::Unpaired { channel_id } if *channel_id == ChannelId(99))),
                "local state is dropped regardless, so Unpaired still fires"
            );

            assert!(
                channel_store
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(99),
                        },
                    )
                    .await
                    .unwrap()
                    .is_none(),
                "the ephemeral channel must not survive a failed send"
            );
            assert!(
                user_secret_store
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_some(),
                "the recovered snapshot stays committed"
            );
            assert!(
                channel_store
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(11),
                        },
                    )
                    .await
                    .unwrap()
                    .is_some(),
                "canonical helper channels stay in place"
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
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(11),
                        },
                    )
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
            rig.channel_store.helper_rows.lock().unwrap().insert(
                (secret_id, 11),
                HelperChannel {
                    channel_id: ChannelId(11),
                    transports: vec![TransportProtocol {
                        uri: "https://collision.example".to_owned(),
                        protocol: 0,
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 1,
                    peer_role: SenderKind::Helper,
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
                    .load(
                        secret_id,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(11),
                        },
                    )
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
            // Builder configured WITH a replica id — restore must leave it
            // alone even though the recovered Secret names a source member.
            let mut protocol = DeRecProtocolBuilder::new(secret_id)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_state_store(InMemStateStore)
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
