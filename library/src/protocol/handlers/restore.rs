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
//!   the canonical helper / replica ids restore is about to write.
//!
//! A roster entry with no transport endpoint is not an error: a channel to
//! it would have nothing to send to, so restore writes none and reports the
//! entry as [`DeRecEvent::PeerNotRestored`] instead. Every other entry is
//! restored as usual.
//!
//! Store I/O failures mid-restore propagate as their underlying
//! [`crate::Error`] variant (`ChannelStore`, `SecretStore`, and
//! `ShareStore` — which the user-secret store reuses for the snapshot
//! write, restore having no share writes of its own). The snapshot
//! write is the commit point — nothing
//! is removed before it succeeds, so any mid-flight failure leaves
//! state the next `restore` call can detect as one of the
//! preconditions above.
//!
//! Restore writes no owner-side tracking shares, so the recovered
//! version is not verifiable on this device; publishing once restores
//! that. See [`restore`] for why, and for the replica-identity
//! precondition on that publish.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecUserSecretStore, NotRestoredReason,
    SecretValue, UnpairAck,
    types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, Secret,
        UserSecrets,
    },
};
use crate::protocol::context::Local;
use crate::protocol::stores::{StoreSet, Stores};
use crate::{
    Result,
    types::{ChannelId, SharedKey},
};
use std::collections::HashSet;

use crate::extensions::channel_store::ChannelStoreExt as _;
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
/// persisted with their `SharedKey`; canonical replica channels are
/// persisted with the group key from `secret.replicas.shared_key`; the
/// user-secret snapshot is committed at `recovered_version`; every
/// recovery-mode channel under `secret_id` is unpaired
/// (`UnpairAck::NotRequired`). The returned events are one
/// [`DeRecEvent::PeerNotRestored`] per roster entry that got no channel,
/// followed by those of the recovery-channel wipe, and should be drained
/// into the protocol's `pending_start_events`.
///
/// # Verification after a restore
///
/// No owner-side tracking [`crate::protocol::types::Share`] is written,
/// so `start(VerifyShares)` at `recovered_version` reports
/// [`crate::Error::InvalidInput`] — this device holds no reference bytes
/// for that version and cannot check a proof against it. That is a
/// property of recovery, not a defect: a `VerifyShare` proof is
/// `SHA-384(share ‖ nonce)` over the *exact* bytes a Helper holds, and
/// recovery cannot attribute a collected share to a canonical Helper
/// channel — the VSS x-coordinate is a random field element and
/// `GetShareResponseMessage` carries no channel id.
///
/// The way back to a verifiable state is to publish:
/// `start(ProtectSecret)` derives `recovered_version + 1` from the
/// snapshot committed here, writes real tracking shares as it
/// distributes, and `start(VerifyShares)` at that version behaves
/// exactly as it does for an owner that never recovered.
///
/// A restored device whose roster carries a replica group cannot
/// publish until the application configures a `replica_id` that the
/// roster names — see step 3 on why restore does not adopt one itself.
///
/// # Peers without an endpoint
///
/// A helper or replica member whose `transports` is empty gets no channel:
/// it would be a channel with nothing to send to. Restore skips it, reports
/// it as [`DeRecEvent::PeerNotRestored`] with
/// [`NotRestoredReason::NoTransports`], and restores the rest of the roster.
/// A legacy roster whose single URI had a scheme this library does not serve
/// decodes to exactly such an entry.
///
/// A skipped entry is still validated — its key length, `replica_id` and
/// role are part of the recovered `Secret`, and an inconsistent `Secret` is
/// refused whole whether or not every entry is reachable. What the skip
/// changes is which ids restore claims. A skipped helper's `channel_id` is
/// not written, so a channel already sitting there is not a conflict; it
/// is a roster id, so it is not a recovery channel either, and the wipe
/// leaves it alone rather than send an unpair to a peer that holds a share.
/// The replica group's channel is written only when at least one member is
/// restored; with every member skipped, neither the group key nor any
/// member record is written and the group's id is treated like a skipped
/// helper's.
///
/// # Sequence
///
/// 1. **Preconditions.** Validate the protocol can restore and plan
///    every write the rest of the flow makes.
///    [`RestoreError::AlreadyRestored`] when a snapshot is already
///    committed, [`RestoreError::Invariant`] when a key is mis-sized or a
///    member's role is unknown, [`crate::Error::InvalidInput`] when a
///    member's `replica_id` is the reserved `0`, and
///    [`RestoreError::Conflict`] when an existing channel sits at an id
///    restore is about to write. All are reported before any store
///    mutation. Channels at no roster id are recovery channels — wiped in
///    step 5, never flagged as collisions.
/// 2. **Helper channels.** Persist each reachable helper's canonical
///    channel record and its `SharedKey`. No tracking share — see
///    *Verification after a restore* above.
/// 3. **Replica members.** Persist every reachable member of the roster
///    against the one group channel, with the group key as that channel's
///    `SharedKey`. Each member's `role` is taken verbatim from the roster:
///    it is a property of the group, not of the reader.
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
/// 5. **Wipe.** Send unpair requests to every channel at no roster id —
///    the recovery-mode channels minted to drive `start(RecoverSecret)` —
///    and drop their local state.
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
pub(in crate::protocol) async fn restore<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secret: &Secret,
    recovered_version: u32,
) -> Result<Vec<DeRecEvent>> {
    let plan = plan_restore(secret)?;
    let existing_channels = check_preconditions(stores, local, &plan).await?;

    write_helper_channels(stores, local, &plan.helpers).await?;

    if let Some(group) = &plan.replicas {
        write_replica_channels(stores, local, group).await?;
    }

    commit_snapshot(stores, local, secret, recovered_version).await?;

    let mut events = plan.not_restored;
    events.extend(
        unpair_recovery_channels(stores, local, &existing_channels, &plan.roster_ids).await,
    );

    #[cfg(feature = "logging")]
    tracing::info!(
        local.secret_id,
        helpers_restored = plan.helpers.len(),
        replicas_restored = plan.replicas.as_ref().map_or(0, |g| g.members.len()),
        user_secrets_restored = secret.secrets.len(),
        "DeRecProtocol restored from recovered Secret"
    );

    Ok(events)
}

/// Every write restore makes, derived from the recovered [`Secret`] alone
/// and fully validated before any store is touched.
struct RestorePlan {
    helpers: Vec<(HelperChannel, SharedKey)>,
    replicas: Option<GroupPlan>,
    /// One [`DeRecEvent::PeerNotRestored`] per roster entry that gets no
    /// channel, in roster order.
    not_restored: Vec<DeRecEvent>,
    /// Ids restore writes. A pre-existing channel at one of these is a
    /// conflict.
    written_ids: HashSet<u64>,
    /// Every id the roster names, written or not. A channel at none of them
    /// is a recovery channel.
    roster_ids: HashSet<u64>,
}

struct GroupPlan {
    channel_id: ChannelId,
    members: Vec<ReplicaMember>,
    group_key: SharedKey,
}

fn plan_restore(secret: &Secret) -> Result<RestorePlan> {
    let mut not_restored = Vec::new();
    let mut helpers = Vec::new();
    let mut written_ids = HashSet::new();
    let mut roster_ids = HashSet::new();

    for h in &secret.helpers {
        let shared_key: SharedKey = h
            .shared_key
            .as_slice()
            .try_into()
            .map_err(|_| RestoreError::Invariant("helper.shared_key must be 32 bytes"))?;
        let channel_id = ChannelId(h.channel_id);
        roster_ids.insert(h.channel_id);
        if h.transports.is_empty() {
            not_restored.push(DeRecEvent::PeerNotRestored {
                channel_id,
                replica_id: None,
                reason: NotRestoredReason::NoTransports,
            });
            continue;
        }
        written_ids.insert(h.channel_id);
        helpers.push((
            HelperChannel {
                channel_id,
                transports: h.transports.clone(),
                communication_info: h.communication_info.clone(),
                status: ChannelStatus::Paired,
                created_at: now_secs(),
                peer_role: derec_proto::SenderKind::Helper,
            },
            shared_key,
        ));
    }

    let replicas = match &secret.replicas {
        Some(group) if !group.members.is_empty() => {
            let group_key: SharedKey = group.shared_key.as_slice().try_into().map_err(|_| {
                RestoreError::Invariant(
                    "recovered Secret carries replicas but replicas.shared_key is missing or wrong size",
                )
            })?;
            let channel_id = ChannelId(group.channel_id);
            roster_ids.insert(group.channel_id);
            let mut members = Vec::new();
            for r in &group.members {
                let replica_id = crate::types::ReplicaId::try_from(r.replica_id)?;
                let role = ReplicaRole::from_i32(r.role).ok_or(RestoreError::Invariant(
                    "roster member carries an unknown role",
                ))?;
                if r.transports.is_empty() {
                    not_restored.push(DeRecEvent::PeerNotRestored {
                        channel_id,
                        replica_id: Some(r.replica_id),
                        reason: NotRestoredReason::NoTransports,
                    });
                    continue;
                }
                members.push(ReplicaMember {
                    channel_id,
                    replica_id,
                    transports: r.transports.clone(),
                    communication_info: r.communication_info.clone(),
                    role,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                });
            }
            if members.is_empty() {
                None
            } else {
                written_ids.insert(group.channel_id);
                Some(GroupPlan {
                    channel_id,
                    members,
                    group_key,
                })
            }
        }
        Some(group) => {
            roster_ids.insert(group.channel_id);
            None
        }
        None => None,
    };

    Ok(RestorePlan {
        helpers,
        replicas,
        not_restored,
        written_ids,
        roster_ids,
    })
}

async fn check_preconditions<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    plan: &RestorePlan,
) -> Result<Vec<HelperChannel>> {
    if stores
        .user_secrets
        .load_latest(local.secret_id)
        .await?
        .is_some()
    {
        return Err(RestoreError::AlreadyRestored.into());
    }

    // Unfiltered deliberately: the caller unpairs every channel at no roster
    // id while this function rejects the ones at ids restore writes.
    // Narrowing either way loses the other half.
    let existing_channels = stores
        .channels
        .helpers_matching(
            local.secret_id,
            crate::protocol::types::HelperFilter::default(),
        )
        .await?;
    let collisions: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| plan.written_ids.contains(&c.channel_id.0))
        .map(|c| c.channel_id)
        .collect();
    if !collisions.is_empty() {
        return Err(RestoreError::Conflict(collisions).into());
    }

    Ok(existing_channels)
}

async fn write_helper_channels<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    helpers: &[(HelperChannel, SharedKey)],
) -> Result<()> {
    let secret_id = local.secret_id;
    for (channel, shared_key) in helpers {
        let cid = channel.channel_id;
        stores
            .channels
            .save(secret_id, ChannelRecord::Helper(channel.clone()))
            .await?;
        stores
            .secrets
            .save(secret_id, cid, SecretValue::SharedKey(*shared_key))
            .await?;
    }
    Ok(())
}

async fn write_replica_channels<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    group: &GroupPlan,
) -> Result<()> {
    for member in &group.members {
        stores
            .channels
            .save(local.secret_id, ChannelRecord::Replica(member.clone()))
            .await?;
    }
    // One key at the one channel every member is addressed on.
    stores
        .secrets
        .save(
            local.secret_id,
            group.channel_id,
            SecretValue::SharedKey(group.group_key),
        )
        .await?;
    Ok(())
}

async fn commit_snapshot<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secret: &Secret,
    recovered_version: u32,
) -> Result<()> {
    stores
        .user_secrets
        .save_latest(
            local.secret_id,
            UserSecrets {
                version: recovered_version,
                secrets: secret.secrets.clone(),
                description: None,
                author_replica_id: None,
            },
        )
        .await?;
    Ok(())
}

async fn unpair_recovery_channels<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    existing_channels: &[HelperChannel],
    roster_ids: &HashSet<u64>,
) -> Vec<DeRecEvent> {
    let recovery_ids: Vec<ChannelId> = existing_channels
        .iter()
        .filter(|c| !roster_ids.contains(&c.channel_id.0))
        .map(|c| c.channel_id)
        .collect();
    if recovery_ids.is_empty() {
        return Vec::new();
    }
    let now = now_secs();
    let round = &crate::protocol::context::Round {
        reply_to: &[],
        trace_id: crate::derec_message::fresh_trace_id(),
    };
    let mut events = Vec::new();
    for channel_id in recovery_ids {
        match super::unpairing::start(
            stores,
            local,
            channel_id,
            None,
            UnpairAck::NotRequired,
            now,
            round,
        )
        .await
        {
            Ok(mut per_channel) => events.append(&mut per_channel),
            Err(e) => {
                events.push(DeRecEvent::UnpairFailed {
                    channel_id,
                    error: e.to_string(),
                });
                if super::unpairing::drop_channel_state(stores, local, channel_id)
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
        InMemUserSecretStore, NoopTransport, StoreRig, run_async,
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
        let rig = StoreRig::new();
        let protocol = DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(rig.channels.clone())
            .with_share_store(rig.shares.clone())
            .with_secret_store(rig.secrets.clone())
            .with_user_secret_store(rig.user_secrets.clone())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .build()
            .expect("test rig builds");
        TestRig {
            protocol,
            channel_store: rig.channels,
            secret_store: rig.secrets,
            share_store: rig.shares,
            user_secret_store: rig.user_secrets,
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
                // No tracking share. A fabricated one would hash to
                // something no Helper can produce, so verification would
                // report the Helper's data as corrupt rather than reporting
                // that this device has nothing to check against.
                let shares = rig
                    .share_store
                    .load(secret_id, ChannelId(hid), &[])
                    .await
                    .unwrap();
                assert!(
                    shares.is_empty(),
                    "restore must not invent tracking shares; got {shares:?}"
                );
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
                rig.protocol.replica_id, None,
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

    fn not_restored(events: &[DeRecEvent]) -> Vec<(ChannelId, Option<u64>, NotRestoredReason)> {
        events
            .iter()
            .filter_map(|e| match e {
                DeRecEvent::PeerNotRestored {
                    channel_id,
                    replica_id,
                    reason,
                } => Some((*channel_id, *replica_id, *reason)),
                _ => None,
            })
            .collect()
    }

    async fn helper_record(rig: &TestRig, secret_id: u64, id: u64) -> Option<ChannelRecord> {
        rig.channel_store
            .load(
                secret_id,
                ChannelQuery::Helper {
                    channel_id: ChannelId(id),
                },
            )
            .await
            .unwrap()
    }

    async fn member_record(
        rig: &TestRig,
        secret_id: u64,
        channel_id: u64,
        replica_id: u64,
    ) -> Option<ChannelRecord> {
        rig.channel_store
            .load(
                secret_id,
                ChannelQuery::Replica {
                    channel_id: ChannelId(channel_id),
                    replica_id: crate::types::ReplicaId(replica_id),
                },
            )
            .await
            .unwrap()
    }

    async fn shared_key_at(rig: &TestRig, secret_id: u64, id: u64) -> Option<SecretValue> {
        rig.secret_store
            .load(secret_id, ChannelId(id), SecretKind::SharedKey)
            .await
            .unwrap()
    }

    // ---------------- Peers without an endpoint ----------------

    /// A helper that names no endpoint would be a channel with nothing to
    /// send to. It is skipped and reported; the reachable helper and the
    /// snapshot are restored exactly as they would be without it.
    #[test]
    fn a_helper_without_an_endpoint_is_skipped_and_reported() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.helpers[1].transports = Vec::new();

            let events = rig
                .protocol
                .restore(&secret, 7)
                .await
                .expect("an unreachable helper must not block the restore");

            assert_eq!(
                not_restored(&events),
                vec![(ChannelId(12), None, NotRestoredReason::NoTransports)],
                "exactly the unreachable helper is reported, got {events:?}"
            );

            assert!(helper_record(&rig, secret_id, 11).await.is_some());
            assert!(shared_key_at(&rig, secret_id, 11).await.is_some());
            assert!(
                helper_record(&rig, secret_id, 12).await.is_none(),
                "no channel is written for a helper with no endpoint"
            );
            assert!(
                shared_key_at(&rig, secret_id, 12).await.is_none(),
                "no key is written for a helper that has no channel"
            );

            assert!(member_record(&rig, secret_id, 21, 0xBEEF).await.is_some());
            assert!(member_record(&rig, secret_id, 21, 0xCAFE).await.is_some());
            let snapshot = rig
                .user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .expect("the snapshot is committed");
            assert_eq!(snapshot.version, 7);
            assert_eq!(snapshot.secrets.len(), 2);
        });
    }

    /// A member with no endpoint is skipped the same way. The group channel
    /// and its key are still written for the members that remain.
    #[test]
    fn a_replica_member_without_an_endpoint_is_skipped_and_reported() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.replicas.as_mut().unwrap().members[0].transports = Vec::new();

            let events = rig
                .protocol
                .restore(&secret, 7)
                .await
                .expect("an unreachable member must not block the restore");

            assert_eq!(
                not_restored(&events),
                vec![(ChannelId(21), Some(0xBEEF), NotRestoredReason::NoTransports)],
                "exactly the unreachable member is reported, got {events:?}"
            );
            assert!(
                member_record(&rig, secret_id, 21, 0xBEEF).await.is_none(),
                "no record is written for a member with no endpoint"
            );
            assert!(member_record(&rig, secret_id, 21, 0xCAFE).await.is_some());
            assert!(
                matches!(
                    shared_key_at(&rig, secret_id, 21).await,
                    Some(SecretValue::SharedKey(k)) if k == [0xCC; 32]
                ),
                "the group key is written for the members that remain"
            );
            assert!(helper_record(&rig, secret_id, 11).await.is_some());
            assert!(helper_record(&rig, secret_id, 12).await.is_some());
        });
    }

    /// With no reachable member there is no group to address, so neither the
    /// group key nor any member record is written.
    #[test]
    fn a_group_with_no_reachable_member_writes_nothing() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            for m in &mut secret.replicas.as_mut().unwrap().members {
                m.transports = Vec::new();
            }

            let events = rig.protocol.restore(&secret, 7).await.expect("restores");

            assert_eq!(
                not_restored(&events),
                vec![
                    (ChannelId(21), Some(0xBEEF), NotRestoredReason::NoTransports),
                    (ChannelId(21), Some(0xCAFE), NotRestoredReason::NoTransports),
                ],
            );
            assert!(member_record(&rig, secret_id, 21, 0xBEEF).await.is_none());
            assert!(member_record(&rig, secret_id, 21, 0xCAFE).await.is_none());
            assert!(
                shared_key_at(&rig, secret_id, 21).await.is_none(),
                "a group key with no member to use it is not written"
            );
            assert!(helper_record(&rig, secret_id, 11).await.is_some());
        });
    }

    /// Restore claims only the ids it writes. A channel already at a skipped
    /// helper's id is not overwritten, so it is no conflict; and it sits at a
    /// roster id, so it is no recovery channel either — the wipe must not
    /// send an unpair to a peer that holds a share.
    #[test]
    fn a_channel_at_a_skipped_helpers_id_is_neither_a_conflict_nor_wiped() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);
            rig.channel_store.helper_rows.lock().unwrap().insert(
                (secret_id, 12),
                HelperChannel {
                    channel_id: ChannelId(12),
                    transports: vec![TransportProtocol {
                        uri: "https://repaired.example".to_owned(),
                        protocol: 0,
                    }],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 1,
                    peer_role: SenderKind::Helper,
                },
            );
            rig.secret_store.data.lock().unwrap().insert(
                (secret_id, 12, SecretKind::SharedKey as u8),
                SecretValue::SharedKey([0x77; 32]),
            );

            let mut secret = fixture_secret();
            secret.helpers[1].transports = Vec::new();

            let events = rig
                .protocol
                .restore(&secret, 7)
                .await
                .expect("a skipped helper's id must not be reported as a conflict");

            assert_eq!(
                not_restored(&events),
                vec![(ChannelId(12), None, NotRestoredReason::NoTransports)]
            );
            assert!(
                !events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::Unpaired { channel_id }
                        | DeRecEvent::UnpairStarted { channel_id, .. }
                        | DeRecEvent::UnpairFailed { channel_id, .. }
                        if *channel_id == ChannelId(12)
                )),
                "the channel at a roster id is not a recovery channel, got {events:?}"
            );
            let Some(ChannelRecord::Helper(kept)) = helper_record(&rig, secret_id, 12).await else {
                panic!("the pre-existing channel must survive");
            };
            assert_eq!(kept.transports[0].uri, "https://repaired.example");
            assert!(
                matches!(
                    shared_key_at(&rig, secret_id, 12).await,
                    Some(SecretValue::SharedKey(k)) if k == [0x77; 32]
                ),
                "its key is left as it was"
            );
        });
    }

    /// Skipping is about reachability, not validity: a skipped entry that
    /// makes the `Secret` inconsistent still refuses the whole restore.
    #[test]
    fn a_skipped_helper_with_a_malformed_key_still_refuses_the_restore() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.helpers[1].transports = Vec::new();
            secret.helpers[1].shared_key = vec![0xBB; 31];

            let err = rig.protocol.restore(&secret, 7).await.unwrap_err();
            assert!(
                matches!(err, crate::Error::Restore(RestoreError::Invariant(_))),
                "got {err:?}"
            );
            assert!(
                helper_record(&rig, secret_id, 11).await.is_none(),
                "an invariant failure is reported before any write"
            );
            assert!(
                rig.user_secret_store
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    /// A malformed key on a later entry used to be found mid-write, after the
    /// earlier helpers were already persisted. It is now part of the plan.
    #[test]
    fn a_malformed_helper_key_is_refused_before_any_write() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let mut secret = fixture_secret();
            secret.helpers[1].shared_key = vec![0xBB; 31];

            let err = rig.protocol.restore(&secret, 7).await.unwrap_err();
            assert!(matches!(
                err,
                crate::Error::Restore(RestoreError::Invariant(_))
            ));
            assert!(helper_record(&rig, secret_id, 11).await.is_none());
            assert!(shared_key_at(&rig, secret_id, 11).await.is_none());
        });
    }

    /// End to end from the bytes a pre-0.0.3 owner protected: a v2 roster
    /// whose helper URI names a scheme this library does not serve decodes
    /// with no endpoint, and restore skips that helper instead of refusing
    /// the whole secret.
    #[test]
    fn a_legacy_roster_with_an_unserved_scheme_restores_the_rest() {
        use std::io::Write as _;
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);

            let json = r#"{
                "helpers": [
                    {
                        "channel_id": "11",
                        "transport_uri": "ws://helper-a.example",
                        "shared_key": "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
                    },
                    {
                        "channel_id": "12",
                        "transport_uri": "https://helper-b.example",
                        "shared_key": "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s="
                    }
                ],
                "secrets": [{"id": "AQ==", "name": "wallet", "data": "c2VjcmV0"}],
                "replicas": {
                    "channel_id": "21",
                    "shared_key": "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=",
                    "members": [{
                        "replica_id": "48879",
                        "transport_uri": "https://owner.example",
                        "role": "Source"
                    }]
                }
            }"#;
            let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            gz.write_all(json.as_bytes()).unwrap();
            let mut bytes = vec![2_u8];
            bytes.extend(gz.finish().unwrap());

            let secret = Secret::decode(&bytes).expect("a v2 secret still decodes");
            assert!(secret.helpers[0].transports.is_empty());

            let events = rig
                .protocol
                .restore(&secret, 3)
                .await
                .expect("one unusable URI must not refuse the whole secret");

            assert_eq!(
                not_restored(&events),
                vec![(ChannelId(11), None, NotRestoredReason::NoTransports)]
            );
            assert!(helper_record(&rig, secret_id, 11).await.is_none());
            assert!(helper_record(&rig, secret_id, 12).await.is_some());
            assert!(member_record(&rig, secret_id, 21, 0xBEEF).await.is_some());
            let snapshot = rig
                .user_secret_store
                .load_latest(secret_id)
                .await
                .unwrap()
                .expect("the snapshot is committed");
            assert_eq!(snapshot.version, 3);
            assert_eq!(snapshot.secrets[0].data, b"secret");
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
            let rig = StoreRig::new();
            let mut protocol = DeRecProtocolBuilder::new(secret_id)
                .with_channel_store(rig.channels.clone())
                .with_share_store(rig.shares.clone())
                .with_secret_store(rig.secrets.clone())
                .with_user_secret_store(rig.user_secrets.clone())
                .with_transport(crate::protocol::test::FailingTransport)
                .with_state_store(InMemStateStore)
                .with_own_transports(["https://owner.example.com"])
                .with_threshold(2)
                .build()
                .expect("test rig builds");

            rig.channels.helper_rows.lock().unwrap().insert(
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
            rig.secrets.data.lock().unwrap().insert(
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
                rig.channels
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
                rig.user_secrets
                    .load_latest(secret_id)
                    .await
                    .unwrap()
                    .is_some(),
                "the recovered snapshot stays committed"
            );
            assert!(
                rig.channels
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

    /// Restore leaves the recovered version unverifiable, and one publish is
    /// what buys verification back.
    ///
    /// This is the sequence the restore docs point applications at, so it is
    /// asserted rather than described: the snapshot committed at
    /// `recovered_version` is what the next round derives `+ 1` from, and that
    /// round writes tracking shares carrying the bytes it actually sent.
    /// Without this, removing the fabricated share would look like a lost
    /// capability instead of a relocated one.
    #[test]
    fn a_publish_after_restore_writes_real_tracking_shares() {
        run_async(async {
            let secret_id: u64 = 0xDE_2EC;
            let mut rig = build_rig(secret_id);
            // Helpers only. A roster carrying a replica group cannot publish
            // until the application configures a `replica_id` the roster
            // names, which is a separate decision restore declines to make.
            let secret = Secret {
                replicas: None,
                ..fixture_secret()
            };

            rig.protocol
                .restore(&secret, 4)
                .await
                .expect("restore must succeed");

            let events = rig
                .protocol
                .start(crate::protocol::DeRecFlow::ProtectSecret {
                    secrets: secret.secrets.clone(),
                    description: None,
                })
                .await
                .expect("a restored owner must be able to publish again");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ProtectSecretStarted { version: 5, .. })),
                "the round after a restore at 4 must be 5; got {events:?}"
            );

            for hid in [11_u64, 12] {
                let rows = rig
                    .share_store
                    .load(secret_id, ChannelId(hid), &[])
                    .await
                    .unwrap();
                let versions: Vec<u32> = rows.iter().map(|r| r.version).collect();
                assert_eq!(
                    versions,
                    vec![5],
                    "helper {hid} must hold exactly the published version, \
                     with nothing left over from the restore"
                );
                assert!(
                    !rows[0].bytes.is_empty(),
                    "helper {hid}'s tracking share must carry the committed \
                     bytes that were sent, or verification has nothing to hash"
                );
            }
        });
    }

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
                    author_replica_id: None,
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
                .with_own_transports(["https://owner.example.com"])
                .with_threshold(2)
                .with_replica_id(0x1234)
                .build()
                .expect("build");

            protocol.restore(&fixture_secret(), 7).await.unwrap();
            assert_eq!(protocol.replica_id, Some(0x1234));
        });
    }
}
