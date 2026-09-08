// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica side of unpairing — removing a member from the group.
//!
//! An `UnpairRequest` naming a group member is a roster removal, not a helper
//! channel teardown. The owner↔helper side lives in
//! [`handlers::unpairing`](super::super::unpairing), which routes here when
//! the payload names an author.
//!
//! Both directions live here. [`start`] announces a removal — the message the
//! application asks for as [`DeRecFlow::UnpairReplica`](crate::protocol::DeRecFlow)
//! — and [`handle`] is what a peer does with it.
//!
//! Removal completes in two halves, and the safety rule spans both: a member
//! is flagged when the departure is announced, and only removed once a roster
//! arrives that both omits it and post-dates the flag. [`reconcile`] and
//! [`tear_down`] are the second half, driven from the sharing flow as each new
//! roster lands.
use super::flag_unpairing;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::protocol::context::Local;
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{
    ChannelRecord, ChannelStatus, ReplicaFilter, ReplicaMember, ReplicaRole,
};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, SecretKind,
};
use crate::types::{ChannelId, ReplicaId};
use crate::{Error, Result};
use derec_proto::{MessageBody, UnpairRequestMessage};

/// Handle an unpairing message that names a group member.
///
/// Unlike the other flows here, the `replica_id` on an `UnpairRequest` names
/// the member being **removed**, not the member that sent it — a removal is
/// announced to every peer, so the target is the only thing they all agree
/// on. There is no replica reading of `UnpairResponse`: a removal is
/// completed by the roster that omits the member, not by an acknowledgement.
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    target: u64,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UnpairRequest(request) => on_request(stores, local, &request, target).await,
        _ => Err(Error::Invariant(
            "replica identity on a message that is not an unpair request",
        )),
    }
}

/// Tell every member that `target` is leaving, and flag it locally.
///
/// Returns the members notified. The caller publishes the new roster: the flag
/// keeps `target` out of it while leaving it on the distribution list, which is
/// how an evicted member learns it may finally tear down.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = trace_id, local.secret_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    target: u64,
    memo: Option<String>,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let own = local.replica_id.ok_or(Error::ReplicaIdNotConfigured)?;
    let target = ReplicaId::try_from(target)?;

    // Unfiltered deliberately: this flow reads the whole roster three ways —
    // the member being removed, the successor that replaces it, and the
    // notification list, which is every member. Narrowing any one of them
    // would cost a second listing to recover the rest.
    let roster = stores
        .channels
        .replicas_matching(secret_id, ReplicaFilter::default())
        .await?;
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
    let key = match stores
        .secrets
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
        let envelope = crate::derec_message::apply_trace_id(&request.envelope, trace_id)?;
        if stores
            .transport
            .send(&peer.transports, envelope)
            .await
            .is_ok()
        {
            notified.push(peer.replica_id);
        }
    }

    flag_unpairing(stores, local, &member).await?;

    // Promoted before the roster is built, so the completing publish carries the
    // new source. The flagged row and the promoted row are distinct members, so
    // the two writes cannot collide.
    let mut events = Vec::new();
    if let Some(successor) = successor {
        stores
            .channels
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
pub(in crate::protocol) async fn reconcile<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    roster_ids: &[u64],
) -> Result<RemovalOutcome> {
    let stored = stores
        .channels
        .replicas_matching(
            local.secret_id,
            ReplicaFilter {
                status: vec![ChannelStatus::Unpairing],
                ..Default::default()
            },
        )
        .await?;

    let mut removed = Vec::new();
    let mut self_removed = false;
    for member in stored.iter() {
        if roster_ids.contains(&member.replica_id.0) {
            continue;
        }
        if Some(member.replica_id.0) == local.replica_id {
            self_removed = true;
            continue;
        }
        stores
            .channels
            .remove(
                local.secret_id,
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
pub(in crate::protocol) async fn tear_down<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
) -> Result<()> {
    let secret_id = local.secret_id;
    for helper in stores
        .channels
        .helpers_matching(secret_id, crate::protocol::types::HelperFilter::default())
        .await?
    {
        drop_channel(
            stores,
            local,
            helper.channel_id,
            crate::protocol::types::ChannelQuery::Helper {
                channel_id: helper.channel_id,
            },
        )
        .await?;
    }

    for member in stores
        .channels
        .replicas_matching(secret_id, ReplicaFilter::default())
        .await?
    {
        drop_channel(
            stores,
            local,
            member.channel_id,
            crate::protocol::types::ChannelQuery::Replica {
                channel_id: member.channel_id,
                replica_id: member.replica_id,
            },
        )
        .await?;
    }

    stores.user_secrets.remove(secret_id).await?;
    Ok(())
}

async fn drop_channel<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    query: crate::protocol::types::ChannelQuery,
) -> Result<()> {
    let secret_id = local.secret_id;
    // The share and secret rows may or may not exist — a member removed
    // before it ever received a share has neither. Removal is idempotent and
    // their absence is not an error, so only the channel row below is
    // required to succeed; that one is what makes the teardown observable.
    let _ = stores.shares.remove_channel(secret_id, channel_id).await;
    for kind in [
        SecretKind::SharedKey,
        SecretKind::PairingSecret,
        SecretKind::PairingContact,
    ] {
        let _ = stores.secrets.remove(secret_id, channel_id, kind).await;
    }
    stores.channels.remove(secret_id, query).await?;
    Ok(())
}

/// Handle an inbound `UnpairRequest` that names a group member.
///
/// Flags the row and nothing more. Teardown waits for the completing roster —
/// the second half of the safety rule.
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    request: &UnpairRequestMessage,
    target: u64,
) -> Result<Vec<DeRecEvent>> {
    // The request body carries only a `memo` — the human-readable reason the
    // publisher gave for the removal. Nothing on the replica path can surface
    // it: this leg raises no `ActionRequired` (a roster removal is not the
    // application's to confirm), and `ReplicaRemoved`, emitted later by
    // `reconcile`, carries no memo field. The owner↔helper leg does surface
    // it, by handing the whole request to `PendingAction::Unpair`.
    let _ = request;
    let target = ReplicaId::try_from(target)?;
    let member = stores
        .channels
        .replicas_matching(
            local.secret_id,
            ReplicaFilter {
                ids: vec![target],
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        // Re-checked against the id we asked for. `replicas_matching` already
        // guarantees this, but the consequence of being wrong here is flagging
        // the wrong member for eviction, so the site states its own invariant.
        .find(|m| m.replica_id == target)
        .ok_or(Error::InvalidInput(
            "unpair names a member that is not in the group",
        ))?;

    flag_unpairing(stores, local, &member).await?;

    // No event yet: nothing has been removed. The row is flagged, and the
    // removal is reported when the completing roster arrives.
    Ok(vec![DeRecEvent::NoOp])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::{InMemChannelStore, InMemSecretStore, StoreRig, run_async};
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

    /// A fixed round token, so a test can assert what reaches the wire.
    const TRACE_ID: u64 = 0x7ACE;

    /// U5 — the omission guard. A member absent from a newer roster but never
    /// told to leave keeps its row. This is the half that stops a publisher
    /// bug from escalating into destroyed state.
    #[test]
    fn absence_alone_removes_nothing() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            // A roster that simply forgot 1002.
            let outcome = super::reconcile(&mut rig.stores(), &lf.local(), &[1001])
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Nothing));
            assert_eq!(
                rig.channels
                    .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                    .await
                    .expect("roster")
                    .len(),
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;

            let outcome = super::reconcile(&mut rig.stores(), &lf.local(), &[1001, 1002])
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Nothing));
            assert_eq!(
                rig.channels
                    .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                    .await
                    .expect("roster")
                    .len(),
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            rig.channels
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

            let outcome = super::reconcile(&mut rig.stores(), &lf.local(), &[1001])
                .await
                .expect("reconcile");

            assert!(matches!(outcome, RemovalOutcome::Removed(ref ids) if ids == &[1002]));
            let roster = rig
                .channels
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                .await
                .expect("roster");
            assert_eq!(roster.len(), 1, "only the departing row goes");
            assert_eq!(
                roster[0].channel_id, GROUP,
                "the shared group channel is untouched"
            );
            assert_eq!(
                rig.channels
                    .helpers(SECRET_ID, crate::protocol::types::HelperFilter::default())
                    .await
                    .expect("helpers")
                    .len(),
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;

            let outcome = super::reconcile(&mut rig.stores(), &lf.local(), &[1001])
                .await
                .expect("reconcile");

            assert!(
                matches!(outcome, RemovalOutcome::SelfRemoved),
                "the device being removed is reported, not silently torn down"
            );
            assert_eq!(
                rig.channels
                    .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                    .await
                    .expect("roster")
                    .len(),
                2,
                "nothing is dropped before the acknowledgement is sent"
            );
        });
    }

    /// U4 / U8 — teardown is the whole partition, not one row.
    #[test]
    fn tear_down_drops_the_whole_partition() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            let mut rig = StoreRig::new();

            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            rig.channels
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
            rig.secrets
                .save(SECRET_ID, GROUP, SecretValue::SharedKey([0x33; 32]))
                .await
                .expect("seed key");
            rig.user_secrets
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

            super::tear_down(&mut rig.stores(), &lf.local())
                .await
                .expect("tear down");

            assert!(
                rig.channels
                    .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                    .await
                    .expect("roster")
                    .is_empty()
            );
            assert!(
                rig.channels
                    .helpers(SECRET_ID, crate::protocol::types::HelperFilter::default())
                    .await
                    .expect("helpers")
                    .is_empty()
            );
            assert!(
                rig.secrets
                    .load(SECRET_ID, GROUP, SecretKind::SharedKey)
                    .await
                    .expect("load")
                    .is_none(),
                "the group key goes with everything else"
            );
            assert!(
                rig.user_secrets
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
            .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::with_transport(crate::protocol::test::NoopTransport);
            seed_group_key(&mut rig.secrets).await;
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(&mut rig.stores(), &lf.local(), 1001, None, TRACE_ID)
                .await
                .expect("removing the source succeeds once a successor is chosen");

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSourceChanged { replica_id } if *replica_id == 1002
                )),
                "the chosen successor is reported to the application"
            );
            assert_eq!(role_of(&rig.channels, 1002).await, ReplicaRole::Source);
            assert_eq!(
                role_of(&rig.channels, 1001).await,
                ReplicaRole::Source,
                "the departing row is untouched; its absence from the next roster is what removes it"
            );
        });
    }

    /// R1 — a member already told to leave cannot be crowned on its way out.
    #[test]
    fn a_departing_member_is_not_eligible_to_succeed() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1003);
            let mut rig = StoreRig::with_transport(crate::protocol::test::NoopTransport);
            seed_group_key(&mut rig.secrets).await;
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Unpairing,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1003,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            super::start(&mut rig.stores(), &lf.local(), 1001, None, TRACE_ID)
                .await
                .expect("start");

            assert_eq!(role_of(&rig.channels, 1003).await, ReplicaRole::Source);
            assert_eq!(role_of(&rig.channels, 1002).await, ReplicaRole::Destination);
        });
    }

    /// R1 — a sole source leaves no successor. The group dissolves with it
    /// rather than the removal failing.
    #[test]
    fn a_sole_source_leaves_no_successor() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::with_transport(crate::protocol::test::NoopTransport);
            seed_group_key(&mut rig.secrets).await;
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(&mut rig.stores(), &lf.local(), 1001, None, TRACE_ID)
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::with_transport(crate::protocol::test::NoopTransport);
            seed_group_key(&mut rig.secrets).await;
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                ChannelStatus::Paired,
            )
            .await;

            let events = super::start(&mut rig.stores(), &lf.local(), 1002, None, TRACE_ID)
                .await
                .expect("start");

            assert!(
                !events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ReplicaSourceChanged { .. })),
                "the source is unaffected by a destination leaving"
            );
            assert_eq!(role_of(&rig.channels, 1001).await, ReplicaRole::Source);
        });
    }
}
