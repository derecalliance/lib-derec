// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Removing a member from a replica group, voluntarily or by eviction.
//!
//! This is **not** helper unpair. A helper channel serves exactly one peer, so
//! tearing it down deletes the channel record. Every member of a group shares
//! **one** channel, so deleting it would sever the whole group. Removal is a
//! member-row edit; only the departing device drops anything wider.
//!
//! # The safety rule
//!
//! > A member tears down only when it has been **told to leave** *and*
//! > **subsequently observes a newer roster excluding it**. Neither condition
//! > alone is sufficient.
//!
//! Absence from a roster must never on its own instruct a member to destroy
//! its copy of the secret. A publisher that silently omitted a member is a bug
//! this design already guards against elsewhere; if bare absence triggered
//! teardown, that bug would escalate from *member forgotten* to *member
//! destroys the secret*. The "told to leave" flag — [`ChannelStatus::Unpairing`]
//! on the member row — is what keeps an omission non-destructive.
//!
//! The flag is persisted rather than held in memory because the notice and the
//! completing publish are separate rounds that may straddle a restart.
//!
//! # The two flavours
//!
//! Both begin by telling **every** member, and differ only in who is named:
//!
//! - **Voluntary** — the departing device names itself. After publishing a
//!   roster without itself, it drops its whole `secret_id` partition.
//! - **Eviction** — the evictor names the member to remove. That member sees
//!   its own id, flags itself, and tears down when the completing version
//!   arrives — **after** acknowledging it, so the publisher's round records a
//!   success rather than failing against a member that behaved correctly.
//!
//! `UnpairRequestMessage.replica_id` names the member **being removed**, not
//! the sender: a recipient compares it against its own id to learn which of
//! the two flavours it is in.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, SecretKind,
};
use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole};
use crate::types::{ChannelId, ReplicaId};
use crate::{Error, Result};
use derec_proto::UnpairRequestMessage;

/// Tell every member that `target` is leaving, and flag it locally.
///
/// Returns the members notified. The caller publishes the new roster: the flag
/// keeps `target` out of it while leaving it on the distribution list, which is
/// how an evicted member learns it may finally tear down.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id)))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    secret_id: u64,
    target: u64,
    memo: Option<String>,
    local_replica_id: Option<u64>,
) -> Result<Vec<DeRecEvent>> {
    let own = local_replica_id.ok_or(Error::ReplicaIdNotConfigured)?;
    let target = ReplicaId::try_from(target)?;

    let roster = channel_store.replicas(secret_id).await?;
    let member = roster
        .iter()
        .find(|m| m.replica_id == target)
        .ok_or(Error::InvalidInput("no such member in this replica group"))?
        .clone();

    // Removing the source leaves the group without one, so a successor is
    // chosen here and published in the roster that completes the removal.
    // Exactly one device runs this flow, so exactly one device decides; every
    // other member reads the outcome from `ReplicaInfo.role` rather than
    // deriving it, which is what keeps the group from disagreeing mid-handover.
    //
    // The pick is the first remaining member in store order. That order is the
    // application's to define — see [`DeRecChannelStore::replicas`] — which is
    // how an application steers the succession without the protocol having to
    // model a policy. A sole source leaves no successor and the group dissolves.
    let successor = if member.role == ReplicaRole::Source {
        roster
            .iter()
            .find(|m| m.replica_id != target && m.status != ChannelStatus::Unpairing)
            .cloned()
    } else {
        None
    };

    let group_channel = member.channel_id;
    let key = match secret_store
        .load(secret_id, group_channel, SecretKind::SharedKey)
        .await?
    {
        Some(crate::protocol::types::SecretValue::SharedKey(k)) => k,
        _ => {
            return Err(Error::InvalidInput(
                "channel has no shared key — not yet paired",
            ));
        }
    };

    // Every member is told, the departing one included. The remaining members
    // need the flag to satisfy the safety rule when the new roster arrives;
    // without it they would be acting on absence alone.
    let memo = memo.unwrap_or_default();
    let mut notified = Vec::new();
    for peer in roster.iter().filter(|m| m.replica_id.0 != own) {
        let request = crate::primitives::unpairing::request::produce(
            peer.channel_id,
            &memo,
            &key,
            &[],
            Some(target.0),
        )?;
        let envelope = super::apply_trace_id(request.envelope, super::fresh_trace_id())?;
        if transport.send(&peer.transports, envelope).await.is_ok() {
            notified.push(peer.replica_id);
        }
    }

    flag_unpairing(channel_store, secret_id, &member).await?;

    // Promoted before the roster is built, so the completing publish carries the
    // new source. The flagged row and the promoted row are distinct members, so
    // the two writes cannot collide.
    let mut events = Vec::new();
    if let Some(successor) = successor {
        channel_store
            .save(
                secret_id,
                ChannelRecord::Replica(ReplicaMember {
                    role: ReplicaRole::Source,
                    ..successor.clone()
                }),
            )
            .await?;
        events.push(DeRecEvent::ReplicaSourceChanged {
            replica_id: successor.replica_id.0,
        });
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        target = target.0,
        voluntary = target.0 == own,
        notified = notified.len(),
        "replica removal announced"
    );

    Ok(events)
}

/// Handle an inbound `UnpairRequest` that names a group member.
///
/// Flags the row and nothing more. Teardown waits for the completing roster —
/// the second half of the safety rule.
pub(in crate::protocol) async fn handle_request<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    request: &UnpairRequestMessage,
    target: u64,
) -> Result<Vec<DeRecEvent>> {
    let _ = request;
    let target = ReplicaId::try_from(target)?;
    let member = channel_store
        .replicas(secret_id)
        .await?
        .into_iter()
        .find(|m| m.replica_id == target)
        .ok_or(Error::InvalidInput(
            "unpair names a member that is not in the group",
        ))?;

    flag_unpairing(channel_store, secret_id, &member).await?;

    // No event yet: nothing has been removed. The row is flagged, and the
    // removal is reported when the completing roster arrives.
    Ok(vec![DeRecEvent::NoOp])
}

/// Mark a member as told-to-leave, preserving everything else about the row.
async fn flag_unpairing<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    member: &ReplicaMember,
) -> Result<()> {
    channel_store
        .save(
            secret_id,
            ChannelRecord::Replica(ReplicaMember {
                status: ChannelStatus::Unpairing,
                ..member.clone()
            }),
        )
        .await?;
    Ok(())
}

/// What an arriving roster means for members already flagged as leaving.
pub(in crate::protocol) enum RemovalOutcome {
    /// Nothing was flagged, or nothing flagged is yet absent.
    Nothing,
    /// These members completed their departure; their rows were removed.
    Removed(Vec<u64>),
    /// This device completed its own departure. The caller must acknowledge
    /// **before** tearing down: dropping the group key first would leave it
    /// unable to encrypt the acknowledgement, failing the publisher's round
    /// against a member that did exactly the right thing.
    SelfRemoved,
}

/// Apply the second half of the safety rule against a freshly arrived roster.
///
/// A flagged member that is *still present* has not completed anything — a
/// removal can be announced and then superseded by a roster that keeps the
/// member, and that must leave no trace.
pub(in crate::protocol) async fn reconcile<Ch: DeRecChannelStore>(
    channel_store: &mut Ch,
    secret_id: u64,
    roster_ids: &[u64],
    local_replica_id: Option<u64>,
) -> Result<RemovalOutcome> {
    let stored = channel_store.replicas(secret_id).await?;

    let mut removed = Vec::new();
    let mut self_removed = false;
    for member in stored
        .iter()
        .filter(|m| m.status == ChannelStatus::Unpairing)
    {
        if roster_ids.contains(&member.replica_id.0) {
            continue;
        }
        if Some(member.replica_id.0) == local_replica_id {
            self_removed = true;
            continue;
        }
        channel_store
            .remove(
                secret_id,
                crate::protocol::types::ChannelQuery::Replica {
                    channel_id: member.channel_id,
                    replica_id: member.replica_id,
                },
            )
            .await?;
        removed.push(member.replica_id.0);
    }

    if self_removed {
        return Ok(RemovalOutcome::SelfRemoved);
    }
    if removed.is_empty() {
        Ok(RemovalOutcome::Nothing)
    } else {
        Ok(RemovalOutcome::Removed(removed))
    }
}

/// Drop this device's entire `secret_id` partition.
///
/// Wider than a remaining member's single-row edit: a departing device keeps
/// nothing. Called only after the acknowledgement has been sent.
pub(in crate::protocol) async fn tear_down<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    secret_id: u64,
) -> Result<()> {
    for helper in channel_store.helpers(secret_id).await? {
        drop_channel(
            channel_store,
            share_store,
            secret_store,
            secret_id,
            helper.channel_id,
            crate::protocol::types::ChannelQuery::Helper {
                channel_id: helper.channel_id,
            },
        )
        .await?;
    }

    for member in channel_store.replicas(secret_id).await? {
        drop_channel(
            channel_store,
            share_store,
            secret_store,
            secret_id,
            member.channel_id,
            crate::protocol::types::ChannelQuery::Replica {
                channel_id: member.channel_id,
                replica_id: member.replica_id,
            },
        )
        .await?;
    }

    user_secret_store.remove(secret_id).await?;
    Ok(())
}

async fn drop_channel<Ch: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    secret_id: u64,
    channel_id: ChannelId,
    query: crate::protocol::types::ChannelQuery,
) -> Result<()> {
    let _ = share_store.remove_channel(secret_id, channel_id).await;
    for kind in [
        SecretKind::SharedKey,
        SecretKind::PairingSecret,
        SecretKind::PairingContact,
    ] {
        let _ = secret_store.remove(secret_id, channel_id, kind).await;
    }
    channel_store.remove(secret_id, query).await?;
    Ok(())
}

/// U1–U12 of the replica-removal spec, concentrated on the safety rule: a
/// member tears down only when it was told to leave **and** has since seen a
/// roster excluding it.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemUserSecretStore, run_async,
    };
    use crate::protocol::types::{HelperChannel, SecretValue, UserSecrets};
    use crate::protocol::{DeRecSecretStore, DeRecUserSecretStore};

    const SECRET_ID: u64 = 0xDE9A27;
    const GROUP: ChannelId = ChannelId(5001);

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    async fn seed_member(
        channels: &mut InMemChannelStore,
        id: u64,
        role: ReplicaRole,
        status: ChannelStatus,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(id),
                    transports: vec![endpoint("https://peer.example")],
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed member");
    }

    /// U5 — the omission guard. A member absent from a newer roster but never
    /// told to leave keeps its row. This is the half that stops a publisher
    /// bug from escalating into destroyed state.
    #[test]
    fn absence_alone_removes_nothing() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            // A roster that simply forgot 1002.
            let outcome = super::reconcile(&mut channels, SECRET_ID, &[1001], Some(1001))
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Nothing));
            assert_eq!(
                channels.replicas(SECRET_ID).await.expect("roster").len(),
                2,
                "a member never told to leave survives being omitted"
            );
        });
    }

    /// U6 — the other half. A member told to leave, but still present in the
    /// newest roster, has completed nothing: an announced removal can be
    /// superseded, and that must leave no trace.
    #[test]
    fn being_flagged_alone_removes_nothing() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;

            let outcome = super::reconcile(&mut channels, SECRET_ID, &[1001, 1002], Some(1001))
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Nothing));
            assert_eq!(
                channels.replicas(SECRET_ID).await.expect("roster").len(),
                2,
                "a flagged member still in the roster keeps its row"
            );
        });
    }

    /// U3 / U10 — both halves hold: the row goes, and the group channel and
    /// every helper channel survive for the members that remain.
    #[test]
    fn both_halves_remove_the_row_and_nothing_else() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(9001),
                        transports: vec![endpoint("https://helper.example")],
                        communication_info: std::collections::HashMap::new(),
                        peer_role: derec_proto::SenderKind::Helper,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed helper");

            let outcome = super::reconcile(&mut channels, SECRET_ID, &[1001], Some(1001))
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Removed(ref ids) if ids == &[1002]));
            let roster = channels.replicas(SECRET_ID).await.expect("roster");
            assert_eq!(roster.len(), 1, "only the departing row goes");
            assert_eq!(
                roster[0].channel_id, GROUP,
                "the shared group channel is untouched"
            );
            assert_eq!(
                channels.helpers(SECRET_ID).await.expect("helpers").len(),
                1,
                "a remaining member keeps every helper channel"
            );
        });
    }

    /// The departing device reports itself rather than deleting its own row in
    /// place — the caller must acknowledge first, then tear down.
    #[test]
    fn a_departing_device_defers_to_its_caller() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;

            let outcome = super::reconcile(&mut channels, SECRET_ID, &[1001], Some(1002))
                .await
                .expect("reconcile");

            assert!(
                matches!(outcome, RemovalOutcome::SelfRemoved),
                "the device being removed is reported, not silently torn down"
            );
            assert_eq!(
                channels.replicas(SECRET_ID).await.expect("roster").len(),
                2,
                "nothing is dropped before the acknowledgement is sent"
            );
        });
    }

    /// U4 / U8 — teardown is the whole partition, not one row.
    #[test]
    fn tear_down_drops_the_whole_partition() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut shares = InMemShareStore::default();
            let mut secrets = InMemSecretStore::default();
            let mut user_secrets = InMemUserSecretStore::default();

            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(9001),
                        transports: vec![endpoint("https://helper.example")],
                        communication_info: std::collections::HashMap::new(),
                        peer_role: derec_proto::SenderKind::Helper,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed helper");
            secrets
                .save(SECRET_ID, GROUP, SecretValue::SharedKey([0x33; 32]))
                .await
                .expect("seed key");
            user_secrets
                .save_latest(
                    SECRET_ID,
                    UserSecrets {
                        version: 4,
                        secrets: Vec::new(),
                        description: None,
                        replicas: None,
                    },
                )
                .await
                .expect("seed snapshot");

            super::tear_down(
                &mut channels,
                &mut shares,
                &mut secrets,
                &mut user_secrets,
                SECRET_ID,
            )
            .await
            .expect("tear down");

            assert!(
                channels
                    .replicas(SECRET_ID)
                    .await
                    .expect("roster")
                    .is_empty()
            );
            assert!(
                channels
                    .helpers(SECRET_ID)
                    .await
                    .expect("helpers")
                    .is_empty()
            );
            assert!(
                secrets
                    .load(SECRET_ID, GROUP, SecretKind::SharedKey)
                    .await
                    .expect("load")
                    .is_none(),
                "the group key goes with everything else"
            );
            assert!(
                user_secrets
                    .load_latest(SECRET_ID)
                    .await
                    .expect("load")
                    .is_none(),
                "a departing device keeps no copy of the secret"
            );
        });
    }

    async fn seed_group_key(secrets: &mut InMemSecretStore) {
        secrets
            .save(SECRET_ID, GROUP, SecretValue::SharedKey([7u8; 32]))
            .await
            .expect("seed group key");
    }

    async fn role_of(channels: &InMemChannelStore, id: u64) -> ReplicaRole {
        channels
            .replicas(SECRET_ID)
            .await
            .expect("roster")
            .into_iter()
            .find(|m| m.replica_id.0 == id)
            .expect("member present")
            .role
    }

    /// R1 — removing the source promotes a remaining member, and the departing
    /// source is never its own successor.
    #[test]
    fn removing_the_source_promotes_a_remaining_member() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let transport = crate::protocol::test::NoopTransport;
            seed_group_key(&mut secrets).await;
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(
                &mut channels,
                &mut secrets,
                &transport,
                SECRET_ID,
                1001,
                None,
                Some(1002),
            )
            .await
            .expect("removing the source succeeds once a successor is chosen");

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSourceChanged { replica_id } if *replica_id == 1002
                )),
                "the chosen successor is reported to the application"
            );
            assert_eq!(role_of(&channels, 1002).await, ReplicaRole::Source);
            assert_eq!(
                role_of(&channels, 1001).await,
                ReplicaRole::Source,
                "the departing row is untouched; its absence from the next roster is what removes it"
            );
        });
    }

    /// R1 — a member already told to leave cannot be crowned on its way out.
    #[test]
    fn a_departing_member_is_not_eligible_to_succeed() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let transport = crate::protocol::test::NoopTransport;
            seed_group_key(&mut secrets).await;
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            seed_member(
                &mut channels,
                1003,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            super::start(
                &mut channels,
                &mut secrets,
                &transport,
                SECRET_ID,
                1001,
                None,
                Some(1003),
            )
            .await
            .expect("start");

            assert_eq!(role_of(&channels, 1003).await, ReplicaRole::Source);
            assert_eq!(role_of(&channels, 1002).await, ReplicaRole::Destination);
        });
    }

    /// R1 — a sole source leaves no successor. The group dissolves with it
    /// rather than the removal failing.
    #[test]
    fn a_sole_source_leaves_no_successor() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let transport = crate::protocol::test::NoopTransport;
            seed_group_key(&mut secrets).await;
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(
                &mut channels,
                &mut secrets,
                &transport,
                SECRET_ID,
                1001,
                None,
                Some(1001),
            )
            .await
            .expect("a sole source may still leave");

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSourceChanged { .. })),
                "no successor exists to report"
            );
        });
    }

    /// R1 — removing a destination changes nobody's role.
    #[test]
    fn removing_a_destination_promotes_nobody() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let transport = crate::protocol::test::NoopTransport;
            seed_group_key(&mut secrets).await;
            seed_member(
                &mut channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(
                &mut channels,
                &mut secrets,
                &transport,
                SECRET_ID,
                1002,
                None,
                Some(1001),
            )
            .await
            .expect("start");

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSourceChanged { .. })),
                "the source is unaffected by a destination leaving"
            );
            assert_eq!(role_of(&channels, 1001).await, ReplicaRole::Source);
        });
    }
}
