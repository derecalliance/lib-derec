// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue, Share,
};
use crate::derec_message::DeRecMessageBuilder;
use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::sharing::{
        request::{produce as produce_store_share_request_message, split},
        response::{self as sharing_response},
    },
    protocol::types::{HelperInfo, Secret, UserSecret},
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, DeRecSecret, MessageBody, SenderKind, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage,
};
use prost::Message;

#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) fn handle(
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::StoreShareRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::StoreShareResponse(response) => on_response(channel_id, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in sharing handler",
        )),
    }
}

/// Inbound `StoreShareRequest` on a **replica** channel. The payload
/// is the full secret — the sender used `share_algorithm =
/// REPLICA_SECRET`. We decode the typed
/// [`crate::protocol::types::ReplicaSecretPayload`] from `request.share`,
/// auto-ack with `StoreShareResponse(Ok)`, and surface a
/// [`DeRecEvent::ReplicaSecretReceived`] carrying the decoded
/// [`crate::protocol::types::Secret`] + [`Vec<crate::protocol::types::ChannelShare>`]
/// for the application's secret-install logic.
///
/// # Group-key handover
///
/// If the payload carries a non-empty `shared_key` (32 bytes), the
/// sender is asking us to adopt the replica-group key for this
/// `secret_id`. We persist it as this channel's new `SharedKey` in
/// [`crate::protocol::DeRecSecretStore`] **before** encrypting the ack
/// — so the ack travels under the group key, matching the sender's
/// secret store after its own swap. From this round forward, this
/// channel's traffic uses the group key.
///
/// The embedded `shared_key` is delivered inside an already-decrypted
/// authenticated envelope (the pair-handshake key authenticated the
/// outer message), so the receiver does not need an additional binding
/// check.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn handle_replica_request<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: crate::protocol::DeRecUserSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    channel: &crate::protocol::types::ReplicaMember,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
    local_replica_id: Option<u64>,
) -> Result<Vec<DeRecEvent>> {
    // The author is whoever wrote this message, which is not necessarily
    // the channel's counterparty: a member admitted by a third party
    // receives updates from every other member over the same channel.
    // The payload is authoritative; the channel record is the fallback
    // for writers that predate the field.
    let from_replica_id = request.replica_id.unwrap_or(channel.replica_id.0);
    let secret_id = request.secret_id;
    let version = request.version;

    let composite = crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "replica secret payload missing `secret` field",
    ))?;
    let shares = composite.shares;

    // Whether this is the first time this device has held the secret is
    // decided before hydration writes the snapshot that would erase the
    // distinction.
    let is_install = user_secret_store.load_latest(secret_id).await?.is_none();

    // The roster is the single source of truth for the group key. The
    // payload's own `shared_key` predates that and is now only a
    // cross-check: two disagreeing copies of a key is a defect worth
    // catching at the boundary rather than a value to choose between.
    if !composite.shared_key.is_empty() {
        let roster_key = secret.replicas.as_ref().map(|g| g.shared_key.as_slice());
        if roster_key != Some(composite.shared_key.as_slice()) {
            return Err(crate::Error::InvalidInput(
                "replica payload's shared_key disagrees with the roster's group key",
            ));
        }
    }

    // Read before hydration overwrites it: a roster that removes the previous
    // source promotes another member, and this device may be the one promoted.
    let was_source =
        match local_replica_id {
            Some(id) => channel_store.replicas(secret_id).await?.iter().any(|m| {
                m.replica_id.0 == id && m.role == crate::protocol::types::ReplicaRole::Source
            }),
            None => false,
        };

    let hydrated = hydrate(
        channel_store,
        secret_store,
        user_secret_store,
        secret_id,
        version,
        &secret,
        request.version_description.clone(),
    )
    .await?;

    // Second half of the removal safety rule: a member flagged as leaving and
    // now absent from the roster has completed its departure.
    let roster_ids: Vec<u64> = secret
        .replicas
        .as_ref()
        .map(|g| g.members.iter().map(|m| m.replica_id).collect())
        .unwrap_or_default();
    let removal =
        super::remove_replica::reconcile(channel_store, secret_id, &roster_ids, local_replica_id)
            .await?;

    let promotion = promotion_event(local_replica_id, was_source, &secret);

    // Every member answers on the group channel under the group key. Before
    // the first sync a joiner has neither, so it answers where the request
    // arrived.
    let (ack_channel, ack_key) = hydrated.unwrap_or((channel.channel_id, shared_key));

    let timestamp = current_timestamp();
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version,
        timestamp: Some(timestamp),
        secret_id,
        // Replica-bound acknowledgement: announce which member answered,
        // since every member replies on the same group channel.
        replica_id: local_replica_id,
    };
    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(ack_channel)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareResponse(response))
        .encrypt(&ack_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope_bytes, inbound_trace_id)?;
    let endpoint = request.reply_to.clone();
    let endpoint = if endpoint.is_empty() {
        channel.transports.clone()
    } else {
        endpoint
    };
    transport.send(&endpoint, envelope).await?;

    // Admission handover: the sync arrived on the ephemeral channel minted
    // by the pairing with the admitter. Hydration has already moved every
    // member onto the group channel, so the only thing left at the ephemeral
    // id is its key. The admitter drops its side when this ack lands.
    if ack_channel != channel.channel_id {
        let _ = secret_store
            .remove(secret_id, channel.channel_id, SecretKind::SharedKey)
            .await;

        #[cfg(feature = "logging")]
        tracing::info!(
            ephemeral_channel_id = channel.channel_id.0,
            group_channel_id = ack_channel.0,
            secret_id,
            "admission handover complete; ephemeral channel dropped"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel.channel_id.0,
        from_replica_id,
        secret_id,
        version,
        is_install,
        helpers_in_secret = secret.helpers.len(),
        members_in_secret = secret.replicas.as_ref().map_or(0, |g| g.members.len()),
        secrets_in_secret = secret.secrets.len(),
        shares_count = shares.len(),
        "replica secret hydrated; ack sent"
    );

    // Teardown happens strictly after the acknowledgement above: dropping the
    // group key first would leave this device unable to encrypt its reply, so
    // the publisher's round would record a failure against a member that had
    // behaved correctly.
    match removal {
        super::remove_replica::RemovalOutcome::SelfRemoved => {
            super::remove_replica::tear_down(
                channel_store,
                share_store,
                secret_store,
                user_secret_store,
                secret_id,
            )
            .await?;

            #[cfg(feature = "logging")]
            tracing::info!(
                secret_id,
                version,
                "left the replica group; partition dropped"
            );

            return Ok(vec![DeRecEvent::SelfRemovedFromGroup { version }]);
        }
        super::remove_replica::RemovalOutcome::Removed(ids) => {
            let mut events: Vec<DeRecEvent> = ids
                .into_iter()
                .map(|replica_id| DeRecEvent::ReplicaRemoved { replica_id })
                .collect();
            events.extend(promotion);
            events.push(if is_install {
                DeRecEvent::ReplicaSecretInstalled {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            } else {
                DeRecEvent::ReplicaSecretReceived {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            });
            return Ok(events);
        }
        super::remove_replica::RemovalOutcome::Nothing => {}
    }

    let event = if is_install {
        DeRecEvent::ReplicaSecretInstalled {
            channel_id: channel.channel_id,
            from_replica_id,
            secret_id,
            version,
            secret,
            shares,
        }
    } else {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: channel.channel_id,
            from_replica_id,
            secret_id,
            version,
            secret,
            shares,
        }
    };
    let mut events: Vec<DeRecEvent> = promotion.into_iter().collect();
    events.push(event);
    Ok(events)
}

/// Report this device being promoted to the group's source by an arriving
/// roster, which happens when the previous source is removed.
///
/// Only the transition is reported: a device that was already the source and
/// still is has nothing to learn from a roster restating it. `was_source` must
/// be read before hydration, which overwrites the stored role.
fn promotion_event(
    local_replica_id: Option<u64>,
    was_source: bool,
    secret: &Secret,
) -> Option<DeRecEvent> {
    if was_source {
        return None;
    }
    let id = local_replica_id?;
    let now_source = secret.replicas.as_ref().is_some_and(|g| {
        g.members.iter().any(|m| {
            m.replica_id == id && m.role == crate::protocol::types::ReplicaRole::Source as i32
        })
    });
    now_source.then_some(DeRecEvent::ReplicaSourceChanged { replica_id: id })
}

/// Write an inbound roster into this device's stores.
///
/// The payload is self-contained by construction, so hydration is a straight
/// decomposition: helper channels and their keys, every group member against
/// the one group channel, the group key, and the user-secret snapshot. After
/// it, a destination holds the same state as the source and can publish.
///
/// Materialising the helper channels grants no capability the payload had not
/// already granted — it ships each helper's `shared_key`, which is what
/// authenticating as the source toward that helper requires.
///
/// Returns the group channel and its key when the payload carried a roster,
/// so the caller can acknowledge there.
async fn hydrate<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: crate::protocol::DeRecUserSecretStore,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    secret_id: u64,
    version: u32,
    secret: &Secret,
    description: String,
) -> Result<Option<(ChannelId, SharedKey)>> {
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, UserSecrets,
    };

    for helper in &secret.helpers {
        let channel_id = ChannelId(helper.channel_id);
        let key: SharedKey =
            helper.shared_key.as_slice().try_into().map_err(|_| {
                crate::Error::InvalidInput("roster helper shared_key must be 32 bytes")
            })?;
        channel_store
            .save(
                secret_id,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: helper.transports.clone(),
                    communication_info: helper.communication_info.clone(),
                    peer_role: SenderKind::Helper,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
        secret_store
            .save(secret_id, channel_id, SecretValue::SharedKey(key))
            .await?;
    }

    let group = match secret.replicas.as_ref().filter(|g| !g.members.is_empty()) {
        Some(group) => group,
        None => return Ok(None),
    };

    let group_channel = ChannelId(group.channel_id);
    let group_key: SharedKey = group
        .shared_key
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::InvalidInput("roster group shared_key must be 32 bytes"))?;

    for member in &group.members {
        channel_store
            .save(
                secret_id,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: group_channel,
                    replica_id: crate::types::ReplicaId::try_from(member.replica_id)?,
                    transports: member.transports.clone(),
                    communication_info: member.communication_info.clone(),
                    // The roster is authoritative, including for this device's
                    // own row: a joiner's provisional role from pairing is
                    // corrected here.
                    role: ReplicaRole::from_i32(member.role).ok_or(crate::Error::InvalidInput(
                        "roster member carries an unknown role",
                    ))?,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
    }

    secret_store
        .save(secret_id, group_channel, SecretValue::SharedKey(group_key))
        .await?;

    // Members present in this roster are up to date. Anything flagged as
    // leaving and now absent has completed its departure — reconciled by the
    // caller, which must acknowledge before tearing itself down.
    user_secret_store
        .save_latest(
            secret_id,
            UserSecrets {
                version,
                secrets: secret.secrets.clone(),
                description: Some(description).filter(|d| !d.is_empty()),
                replicas: secret.replicas.clone(),
            },
        )
        .await?;

    Ok(Some((group_channel, group_key)))
}

/// Inbound `StoreShareResponse` on a **replica** channel — the source's
/// follow-up to a secret sync. Surface the peer's ack as
/// [`DeRecEvent::ReplicaSecretAcked`] so the app can decide whether to
/// retry / rebroadcast / report.
/// Surface a Destination's acknowledgement of a secret sync.
///
/// A `StoreShareResponse` missing its `result` is itself a protocol
/// violation, so a distinct out-of-range sentinel is reported rather
/// than `StatusEnum::Ok`, which would mislead the application into
/// believing the sync succeeded.
pub(in crate::protocol) async fn handle_replica_response<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    secret_id: u64,
    arrived_on: ChannelId,
    channel: &crate::protocol::types::ReplicaMember,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // Every member answers on the same channel, so the responder names
    // itself in the payload. Fall back to the channel's counterparty for
    // responders that predate the field.
    let from_replica_id = response.replica_id.unwrap_or(channel.replica_id.0);
    let (status, memo) = response
        .result
        .as_ref()
        .map(|r| (r.status, r.memo.clone()))
        .unwrap_or((-1, "response missing `result` field".to_owned()));

    // Admission handover, admitter side. A member this device admitted was
    // recorded against the ephemeral pairing channel; answering on the group
    // channel is its proof of having hydrated, since the reply decrypted
    // under the group key. Move the row and drop the ephemeral key.
    //
    // The row is *moved*, never removed and re-added: a member is keyed by
    // `replica_id` alone, so removing it at the old channel would delete the
    // member itself rather than the stale address.
    if status == StatusEnum::Ok as i32 && channel.channel_id != arrived_on {
        let ephemeral = channel.channel_id;
        channel_store
            .save(
                secret_id,
                crate::protocol::types::ChannelRecord::Replica(
                    crate::protocol::types::ReplicaMember {
                        channel_id: arrived_on,
                        ..channel.clone()
                    },
                ),
            )
            .await?;
        let _ = secret_store
            .remove(secret_id, ephemeral, SecretKind::SharedKey)
            .await;

        #[cfg(feature = "logging")]
        tracing::info!(
            ephemeral_channel_id = ephemeral.0,
            group_channel_id = arrived_on.0,
            from_replica_id,
            "admitted member moved onto the group channel"
        );
    }

    // Acceptance and refusal are different events, mirroring the helper leg's
    // ShareConfirmed / ShareRejected split: the round accumulator moves a
    // member to `synced` on one and to `behind` on the other, and a
    // VERSION_CONFLICT here fails the round.
    if status == StatusEnum::Ok as i32 {
        Ok(vec![DeRecEvent::ReplicaSecretAcked {
            channel_id: arrived_on,
            from_replica_id,
            secret_id: response.secret_id,
            version: response.version,
            status,
            memo,
        }])
    } else {
        Ok(vec![DeRecEvent::ReplicaSyncRejected {
            replica_id: from_replica_id,
            secret_id: response.secret_id,
            version: response.version,
            status,
            memo,
        }])
    }
}

/// Run one `ProtectSecret` round: VSS-split the secret to every paired
/// Helper and ship the full secret to every paired Replica Destination.
///
/// Returns `Ok(None)` when no peer is paired — the secret has nowhere to
/// land, and callers treat it as a no-op so the auto-publish-on-pair
/// hook can fire safely before any peer exists.
///
/// Version progression is anchored to `user_secret_store`, so it bumps
/// on every round — including roster-only auto-publishes to Destinations
/// that never write to `share_store`. The snapshot written at the end of
/// this function is the source of truth the next round reads.
///
/// The split runs once and feeds both the helper-distribution path and
/// the Destination composite. Below `threshold` no split runs at all:
/// Helpers receive nothing this round and any paired Replicas receive a
/// secret-only composite carrying no share material.
///
/// The snapshot is persisted only *after* distribution attempts
/// complete, so an interrupted round never leaves the version ahead of
/// what peers actually received. Per-channel failures surface as
/// `ProtectSecretFailed` and do not block the snapshot — the round stays
/// addressable and failed peers retry on the next one.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: crate::protocol::DeRecUserSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    transport: &T,
    secrets: Vec<UserSecret>,
    description: Option<String>,
    threshold: usize,
    keep_versions_count: usize,
    secret_id: u64,
    own_transport: &derec_proto::TransportProtocol,
    reply_to: &[derec_proto::TransportProtocol],
    local_replica_id: Option<u64>,
) -> Result<Option<SharingRoundResult>> {
    let (helpers, replicas) =
        load_all_paired_targets(channel_store, secret_store, secret_id, local_replica_id).await?;

    if helpers.is_empty() && replicas.is_empty() {
        return Ok(None);
    }

    let snapshot_secrets = secrets.clone();
    let snapshot_description = description.clone();

    // The roster names every member, including this device — a group whose
    // members cannot name themselves is not reconstructible from the payload.
    // The dispatch list above is the same set minus self.
    let roster = channel_store.replicas(secret_id).await?;
    let group_channel = group_channel_of(&roster, local_replica_id)?;
    let group_key = match group_channel {
        Some(channel_id) => match secret_store
            .load(secret_id, channel_id, SecretKind::SharedKey)
            .await?
        {
            Some(SecretValue::SharedKey(key)) => Some(key),
            _ => {
                return Err(Error::Invariant(
                    "replica group channel has no key in the secret store",
                ));
            }
        },
        None => None,
    };
    let secret = build_secret(&helpers, &roster, secrets, group_channel, group_key)?;

    // A helper holds exactly one endpoint: the one it paired with. Every other
    // member of the group is invisible to it, so a publish from a group must
    // carry `reply_to` on the helper leg or the acknowledgement is routed to
    // whoever paired — which for a member that joined later is the wrong
    // device entirely. Decided here, where the roster is known, rather than
    // left to the application's `auto_reply_to` setting.
    let helper_reply_to: Vec<derec_proto::TransportProtocol> = if roster.is_empty() {
        reply_to.to_vec()
    } else {
        vec![own_transport.clone()]
    };
    let derec_secret_bytes = wrap_for_helper_split(&secret, threshold);

    let version = user_secret_store
        .load_latest(secret_id)
        .await?
        .map(|s| s.version + 1)
        .unwrap_or(1);
    let description = description.as_deref().unwrap_or("").to_owned();

    let helper_channel_ids: Vec<ChannelId> = helpers.iter().map(|(ch, _)| ch.channel_id).collect();
    let split_result = if helpers.len() >= threshold {
        Some(split(
            &helper_channel_ids,
            secret_id,
            version,
            &derec_secret_bytes,
            threshold,
        )?)
    } else {
        None
    };

    let mut outcomes: Vec<(ChannelId, Result<()>)> = Vec::new();
    let mut replica_outcomes: Vec<(crate::types::ReplicaId, Result<()>)> = Vec::new();

    if let Some(ref result) = split_result {
        let helper_outcomes = distribute_shares(
            share_store,
            transport,
            &helpers,
            result,
            keep_versions_count,
            secret_id,
            version,
            &description,
            &helper_reply_to,
        )
        .await;
        outcomes.extend(helper_outcomes);
    }

    if !replicas.is_empty() {
        let composite = build_replica_composite(&secret, split_result.as_ref());
        let k_group = group_key;
        let replica_results = distribute_composite_to_destinations(
            secret_store,
            transport,
            &replicas,
            &composite,
            k_group,
            secret_id,
            version,
            &description,
            reply_to,
            local_replica_id,
        )
        .await;
        replica_outcomes.extend(replica_results);
    }

    user_secret_store
        .save_latest(
            secret_id,
            crate::protocol::types::UserSecrets {
                version,
                secrets: snapshot_secrets,
                description: snapshot_description,
                replicas: secret.replicas.clone(),
            },
        )
        .await?;

    Ok(Some(SharingRoundResult {
        version,
        outcomes,
        replica_outcomes,
    }))
}

/// The output of [`start`] on a round with at least one targeted peer.
///
/// `outcomes` carries one `(ChannelId, Result<()>)` per targeted
/// helper / replica — `Ok(())` on successful dispatch, `Err` on
/// per-channel transport / store failure. The orchestrator maps each
/// entry to `ProtectSecretStarted` / `ProtectSecretFailed`.
pub(in crate::protocol) struct SharingRoundResult {
    pub(in crate::protocol) version: u32,
    /// One entry per helper written to, keyed by its channel.
    pub(in crate::protocol) outcomes: Vec<(ChannelId, Result<()>)>,
    /// One entry per group member written to, keyed by its `ReplicaId`.
    ///
    /// Separate from `outcomes` because members share one channel: keying
    /// them by `ChannelId` would collapse the whole group into a single
    /// entry, and the first answer would settle the round for all of them.
    pub(in crate::protocol) replica_outcomes: Vec<(crate::types::ReplicaId, Result<()>)>,
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
    local_replica_id: Option<u64>,
) -> Result<Vec<DeRecEvent>> {
    let version = request.version;
    let replica_id = request.replica_id;
    let encoded_request = request.encode_to_vec();

    // A version has exactly one writer, so an existing entry at this
    // version is either that writer re-sending the identical envelope —
    // an idempotent retry, acknowledged without rewriting — or a second
    // writer publishing concurrently, which is a conflict only the
    // application can resolve.
    //
    // A single writer derives `version` as `latest + 1` and so can never
    // rewrite a version with different content; differing bytes at the
    // same version therefore imply a second writer.
    //
    // Enforced here rather than delegated to store implementations so
    // every binding inherits one rule.
    let already_stored = share_store
        .load(secret_id, channel_id, &[version])
        .await?
        .into_iter()
        .find(|stored| stored.version == version);

    match already_stored {
        Some(stored) if stored.bytes != encoded_request => {
            reject(
                channel_store,
                transport,
                secret_id,
                channel_id,
                request,
                shared_key,
                StatusEnum::VersionConflict,
                "a different share is already stored at this version",
                trace_id,
                local_replica_id,
            )
            .await?;

            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id = secret_id,
                version = version,
                "version conflict — refused a second writer at an existing version"
            );

            return Ok(vec![DeRecEvent::NoOp]);
        }
        Some(_) => {
            // Byte-identical re-send: acknowledge without rewriting.
            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id = secret_id,
                version = version,
                "idempotent re-send of an already-stored share"
            );
        }
        None => {
            share_store
                .save(
                    secret_id,
                    channel_id,
                    Share {
                        secret_id: request.secret_id,
                        version,
                        bytes: encoded_request,
                    },
                )
                .await?;
        }
    }

    let resp = sharing_response::produce(channel_id, request, shared_key)?;
    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint =
        super::resolve_response_endpoints(channel_store, secret_id, channel_id, &request.reply_to)
            .await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = secret_id,
        version = version,
        "share stored and acknowledged"
    );

    Ok(vec![DeRecEvent::ShareStored {
        channel_id,
        version,
        replica_id,
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
    local_replica_id: Option<u64>,
) -> Result<()> {
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        timestamp: Some(current_timestamp()),
        // Mirror the request's audience: only a replica-bound request is
        // rejected by a replica, and only then is a writer identity due.
        replica_id: request.replica_id.and(local_replica_id),
    };
    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::StoreShareResponse(response),
        shared_key,
        trace_id,
        &request.reply_to,
    )
    .await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        status = status as i32,
        "share rejection sent"
    );

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(
    channel_id: ChannelId,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::StoreShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version
        )
    )
)]
fn on_response(
    channel_id: ChannelId,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let version = response.version;
    match sharing_response::process(version, response) {
        Ok(()) => {
            #[cfg(feature = "logging")]
            tracing::info!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = version,
                "share confirmed by helper"
            );

            Ok(vec![DeRecEvent::ShareConfirmed {
                channel_id,
                version,
            }])
        }
        Err(err) => {
            if let Some((status, memo)) = err.as_non_ok_status() {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    secret_id = response.secret_id,
                    version = version,
                    status,
                    memo,
                    "share rejected by helper"
                );

                Ok(vec![DeRecEvent::ShareRejected {
                    channel_id,
                    version,
                    status,
                    memo: memo.to_owned(),
                }])
            } else {
                Err(err)
            }
        }
    }
}

async fn load_all_paired_targets<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    secret_id: u64,
    local_replica_id: Option<u64>,
) -> Result<(
    Vec<(crate::protocol::types::HelperChannel, SharedKey)>,
    Vec<(crate::protocol::types::ReplicaMember, SharedKey)>,
)> {
    use crate::protocol::types::ChannelStatus;

    let helper_rows: Vec<_> = channel_store
        .helpers(secret_id)
        .await?
        .into_iter()
        .filter(|c| c.peer_role == SenderKind::Helper && c.status == ChannelStatus::Paired)
        .collect();

    // Every member is a target except this device itself. `replicas()`
    // deliberately includes our own row so the roster is reconstructible from
    // stores alone, so the exclusion happens here.
    let member_rows: Vec<_> = channel_store
        .replicas(secret_id)
        .await?
        .into_iter()
        // `Unpairing` members stay on the distribution list even though the
        // roster below drops them: receiving the version that excludes them is
        // exactly how they learn their departure is complete.
        .filter(|m| {
            matches!(m.status, ChannelStatus::Paired | ChannelStatus::Unpairing)
                && Some(m.replica_id.0) != local_replica_id
        })
        .collect();

    if helper_rows.is_empty() && member_rows.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    // Every key lives at the channel its record names. Members of one group
    // converge on a single channel and therefore a single key, but resolving
    // per record keeps this correct while a group spans several pairings.
    let mut key_ids: Vec<ChannelId> = helper_rows.iter().map(|c| c.channel_id).collect();
    for m in &member_rows {
        if !key_ids.contains(&m.channel_id) {
            key_ids.push(m.channel_id);
        }
    }

    let keys: std::collections::HashMap<ChannelId, SharedKey> = secret_store
        .load_many(
            secret_id,
            &key_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?
        .into_iter()
        .filter_map(|(cid, v)| match v {
            SecretValue::SharedKey(k) => Some((cid, k)),
            _ => None,
        })
        .collect();

    let helpers: Vec<(crate::protocol::types::HelperChannel, SharedKey)> = helper_rows
        .into_iter()
        .map(|c| {
            let key = *keys
                .get(&c.channel_id)
                .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");
            (c, key)
        })
        .collect();

    let replicas: Vec<(crate::protocol::types::ReplicaMember, SharedKey)> = member_rows
        .into_iter()
        .map(|m| {
            let key = *keys
                .get(&m.channel_id)
                .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");
            (m, key)
        })
        .collect();

    Ok((helpers, replicas))
}

/// Assemble the payload from the stores.
///
/// `roster` is every member of the group including this device — the dispatch
/// list is the same set minus self, and during an admission handover also
/// differs by channel, since a joiner sits on its ephemeral pairing channel
/// until it hydrates.
fn build_secret(
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    roster: &[crate::protocol::types::ReplicaMember],
    secrets: Vec<UserSecret>,
    group_channel: Option<ChannelId>,
    group_key: Option<SharedKey>,
) -> Result<Secret> {
    let helper_infos: Vec<HelperInfo> = paired_helpers
        .iter()
        .map(|(channel, shared_key)| HelperInfo {
            channel_id: channel.channel_id.0,
            transports: channel.transports.clone(),
            shared_key: shared_key.to_vec(),
            communication_info: channel.communication_info.clone(),
        })
        .collect();

    Ok(Secret {
        helpers: helper_infos,
        secrets,
        replicas: build_replicas(roster, group_channel, group_key)?,
    })
}

/// The group's channel: the one on this device's **own** member row.
///
/// A joiner admitted since the last round is still on its ephemeral pairing
/// channel, so the group's id cannot be read off an arbitrary row — and
/// publishing an ephemeral id as the group's would strand every other member.
/// This device's own row always names the group: it is written once, at the
/// first replica pairing, and never moved.
///
/// `Ok(None)` when there is no group at all.
fn group_channel_of(
    roster: &[crate::protocol::types::ReplicaMember],
    local_replica_id: Option<u64>,
) -> Result<Option<ChannelId>> {
    if roster.is_empty() {
        return Ok(None);
    }
    let own = local_replica_id.ok_or(Error::ReplicaIdNotConfigured)?;
    roster
        .iter()
        .find(|m| m.replica_id.0 == own)
        .map(|m| Some(m.channel_id))
        .ok_or(Error::Invariant(
            "replica group has members but this device holds no row of its own",
        ))
}

/// Project the group onto the wire roster.
fn build_replicas(
    roster: &[crate::protocol::types::ReplicaMember],
    group_channel: Option<ChannelId>,
    group_key: Option<SharedKey>,
) -> Result<Option<crate::protocol::types::Replicas>> {
    let (Some(group_channel), Some(group_key)) = (group_channel, group_key) else {
        return Ok(None);
    };

    let members: Vec<crate::protocol::types::ReplicaInfo> = roster
        .iter()
        // A member told to leave is already out of the group as far as the
        // published roster is concerned. Its absence here is what completes
        // the removal on every recipient.
        .filter(|member| member.status != crate::protocol::types::ChannelStatus::Unpairing)
        .map(|member| crate::protocol::types::ReplicaInfo {
            replica_id: member.replica_id.0,
            transports: member.transports.clone(),
            role: member.role as i32,
            communication_info: member.communication_info.clone(),
        })
        .collect();

    Ok(Some(crate::protocol::types::Replicas {
        channel_id: group_channel.0,
        members,
        shared_key: group_key.to_vec(),
    }))
}

fn build_replica_composite(
    secret: &Secret,
    split_result: Option<&crate::primitives::sharing::request::SplitResult>,
) -> crate::protocol::types::ReplicaSecretPayload {
    let shares: Vec<crate::protocol::types::ChannelShare> = split_result
        .map(|r| {
            r.shares
                .iter()
                .map(|(ch_id, committed)| crate::protocol::types::ChannelShare {
                    channel_id: ch_id.0,
                    committed_share: committed.encode_to_vec(),
                })
                .collect()
        })
        .unwrap_or_default();

    crate::protocol::types::ReplicaSecretPayload {
        secret: Some(secret.clone()),
        shares,
        shared_key: Vec::new(),
    }
}

fn wrap_for_helper_split(secret: &Secret, threshold: usize) -> Vec<u8> {
    let derec_secret = DeRecSecret {
        secret_data: secret.encode(),
        creation_time: None,
        helper_threshold_for_recovery: threshold as i64,
        helper_threshold_for_confirming_share_receipt: threshold as i64,
        helpers: Vec::new(),
    };
    derec_secret.encode_to_vec()
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_shares<Sh: DeRecShareStore, T: DeRecTransport>(
    share_store: &mut Sh,
    transport: &T,
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    split_result: &crate::primitives::sharing::request::SplitResult,
    keep_versions_count: usize,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: &[derec_proto::TransportProtocol],
) -> Vec<(ChannelId, Result<()>)> {
    let keep_list: Vec<u32> = {
        let start = version
            .saturating_sub(keep_versions_count as u32 - 1)
            .max(1);
        (start..=version).collect()
    };

    let mut results: Vec<(ChannelId, Result<()>)> = Vec::with_capacity(paired_helpers.len());
    for (channel, shared_key) in paired_helpers {
        let Some(committed_share) = split_result.shares.get(&channel.channel_id) else {
            continue;
        };

        let outcome = dispatch_share_to_helper(
            share_store,
            transport,
            channel,
            shared_key,
            committed_share,
            &keep_list,
            secret_id,
            version,
            description,
            reply_to,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.channel_id.0,
                secret_id = secret_id,
                version = version,
                "share envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.channel_id.0,
                secret_id = secret_id,
                version = version,
                error = %e,
                "share envelope dispatch failed"
            ),
        }

        results.push((channel.channel_id, outcome));
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        "secret distributed to helpers"
    );

    results
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_share_to_helper<Sh: DeRecShareStore, T: DeRecTransport>(
    share_store: &mut Sh,
    transport: &T,
    channel: &crate::protocol::types::HelperChannel,
    shared_key: &SharedKey,
    committed_share: &derec_proto::CommittedDeRecShare,
    keep_list: &[u32],
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: &[derec_proto::TransportProtocol],
) -> Result<()> {
    let msg = produce_store_share_request_message(
        channel.channel_id,
        version,
        secret_id,
        committed_share,
        keep_list,
        description,
        shared_key,
        reply_to,
    )?;
    let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
    transport.send(&channel.transports, envelope).await?;

    share_store
        .save(
            secret_id,
            channel.channel_id,
            Share {
                secret_id,
                version,
                bytes: committed_share.encode_to_vec(),
            },
        )
        .await?;
    Ok(())
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_composite_to_destinations<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    replicas: &[(crate::protocol::types::ReplicaMember, SharedKey)],
    composite: &crate::protocol::types::ReplicaSecretPayload,
    k_group: Option<SharedKey>,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: &[derec_proto::TransportProtocol],
    local_replica_id: Option<u64>,
) -> Vec<(crate::types::ReplicaId, Result<()>)> {
    let mut results: Vec<(crate::types::ReplicaId, Result<()>)> =
        Vec::with_capacity(replicas.len());
    for (channel, channel_key) in replicas {
        let outcome = dispatch_composite_to_destination(
            secret_store,
            transport,
            channel,
            channel_key,
            composite,
            k_group.as_ref(),
            secret_id,
            version,
            description,
            reply_to,
            local_replica_id,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.channel_id.0,
                secret_id = secret_id,
                version = version,
                "replica secret envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.channel_id.0,
                secret_id = secret_id,
                version = version,
                error = %e,
                "replica secret envelope dispatch failed"
            ),
        }

        results.push((channel.replica_id, outcome));
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        count = replicas.len(),
        "secret distributed to replicas"
    );

    results
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_composite_to_destination<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    channel: &crate::protocol::types::ReplicaMember,
    channel_key: &SharedKey,
    composite: &crate::protocol::types::ReplicaSecretPayload,
    k_group: Option<&SharedKey>,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: &[derec_proto::TransportProtocol],
    local_replica_id: Option<u64>,
) -> Result<()> {
    let needs_handover = match k_group {
        Some(g) => channel_key != g,
        None => false,
    };

    let mut per_channel = composite.clone();
    if needs_handover {
        per_channel.shared_key = k_group.expect("handover implies k_group set").to_vec();
    }
    let composite_bytes = per_channel.encode_to_vec();

    let timestamp = current_timestamp();
    let msg = StoreShareRequestMessage {
        share: composite_bytes,
        share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
        version,
        keep_list: Vec::new(),
        version_description: description.to_owned(),
        timestamp: Some(timestamp),
        secret_id,
        reply_to: reply_to.to_vec(),
        replica_id: local_replica_id,
    };

    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareRequest(msg))
        .encrypt(channel_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope_bytes, super::fresh_trace_id())?;
    transport.send(&channel.transports, envelope).await?;

    if needs_handover {
        let new_key = k_group.expect("handover implies k_group set");
        secret_store
            .save(
                secret_id,
                channel.channel_id,
                SecretValue::SharedKey(*new_key),
            )
            .await
            .map_err(crate::Error::SecretStore)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::primitives::sharing::request;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, NoopTransport, run_async,
    };
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{Protocol, TransportProtocol};
    use prost::Message as _;

    /// A Helper stores each incoming share partitioned under *its own*
    /// `secret_id`, but the persisted `Share` record must carry the
    /// *Owner's* `secret_id` (from the wire request). Discovery groups a
    /// Helper's shares by `Share::secret_id` to report which Owner secrets
    /// it holds; recording the Helper's own partition id instead would
    /// mislabel every held share as belonging to the Helper. The two ids
    /// are only distinguishable when they differ — so this test drives
    /// `accept` with an Owner id that is not the Helper's.
    #[test]
    fn accept_records_owner_secret_id_not_helper_partition() {
        run_async(async {
            const OWNER_SECRET_ID: u64 = 0xA11CE;
            const HELPER_SECRET_ID: u64 = 0xB0B;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = [42u8; 32];

            // Owner: split a secret across two channels and build the
            // store-share request bound to OWNER_SECRET_ID.
            let split = request::split(
                &[channel_id, ChannelId(12)],
                OWNER_SECRET_ID,
                1,
                b"correct horse battery staple",
                2,
            )
            .expect("split secret");
            let committed = split.shares.get(&channel_id).expect("share for channel");
            let produced = request::produce(
                channel_id,
                1,
                OWNER_SECRET_ID,
                committed,
                &[],
                "",
                &shared_key,
                std::slice::from_ref(&TransportProtocol {
                    uri: "https://owner.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }),
            )
            .expect("produce store-share request");

            // Helper: recover the request and confirm it carries the
            // Owner's id, then run the accept handler under the Helper's
            // own (different) partition id.
            let request = request::extract(&produced.envelope, &shared_key)
                .expect("extract request")
                .request;
            assert_eq!(request.secret_id, OWNER_SECRET_ID);

            let mut channel_store = InMemChannelStore::default();
            let mut share_store = InMemShareStore::default();
            let transport = NoopTransport;
            super::accept(
                &mut channel_store,
                &mut share_store,
                &transport,
                HELPER_SECRET_ID,
                channel_id,
                &request,
                &shared_key,
                1,
                None,
            )
            .await
            .expect("accept stores share");

            // The record is keyed under the Helper's partition id, but the
            // `secret_id` field Discovery groups by must be the Owner's.
            let stored = share_store
                .data
                .lock()
                .unwrap()
                .get(&(HELPER_SECRET_ID, channel_id.0, 1))
                .cloned()
                .expect("share persisted under helper partition");
            assert_eq!(
                stored.secret_id, OWNER_SECRET_ID,
                "Discovery groups shares by Share.secret_id; it must be the owner's id"
            );
        });
    }

    /// A Destination hydrating a roster uses each stored endpoint verbatim.
    ///
    /// The roster carries the protocol discriminant alongside the URI, so
    /// nothing is inferred here. That is the point: a roster that stored only
    /// a URI forced the discriminant to be reconstructed on every hydration,
    /// and the historical reconstruction hardcoded `Https` — producing
    /// `{grpcs://…, Https}` and silently unaddressing every gRPC peer.
    #[test]
    fn hydrate_uses_each_stored_endpoint_verbatim() {
        run_async(async {
            use crate::protocol::test::InMemUserSecretStore;
            use crate::protocol::traits::DeRecChannelStore;
            use crate::protocol::types::{
                ChannelQuery, ChannelRecord, HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret,
            };

            const SECRET_ID: u64 = 0xD3_57;

            let secret = Secret {
                helpers: vec![
                    HelperInfo {
                        channel_id: 11,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "grpcs://helper.example:443".to_owned(),
                            protocol: derec_proto::Protocol::Grpc as i32,
                        }],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                    },
                    HelperInfo {
                        channel_id: 12,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://helper-b.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        shared_key: vec![0xAB; 32],
                        communication_info: std::collections::HashMap::new(),
                    },
                ],
                secrets: Vec::new(),
                replicas: Some(Replicas {
                    channel_id: 21,
                    members: vec![ReplicaInfo {
                        replica_id: 0xCAFE,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "grpcs://replica.example:443".to_owned(),
                            protocol: derec_proto::Protocol::Grpc as i32,
                        }],
                        role: ReplicaRole::Destination as i32,
                        communication_info: std::collections::HashMap::new(),
                    }],
                    shared_key: vec![0xCC; 32],
                }),
            };

            let mut channel_store = InMemChannelStore::default();
            let mut secret_store = InMemSecretStore::default();
            let mut user_secret_store = InMemUserSecretStore::default();

            super::hydrate(
                &mut channel_store,
                &mut secret_store,
                &mut user_secret_store,
                SECRET_ID,
                4,
                &secret,
                String::new(),
            )
            .await
            .expect("a grpc roster must hydrate");

            let expected = [(11_u64, Protocol::Grpc), (12, Protocol::Https)];
            for (channel_id, protocol) in expected {
                let record = channel_store
                    .load(
                        SECRET_ID,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(channel_id),
                        },
                    )
                    .await
                    .unwrap()
                    .expect("helper channel must be persisted");
                let ChannelRecord::Helper(record) = record else {
                    panic!("a helper query must never return a replica record");
                };
                assert_eq!(
                    record.transports[0].protocol, protocol as i32,
                    "helper {channel_id} must carry the protocol its URI scheme names"
                );
                for endpoint in &record.transports {
                    crate::transport::TransportProtocol::try_from(endpoint)
                        .expect("every rehydrated endpoint must be self-consistent");
                }
            }

            let member = channel_store
                .load(
                    SECRET_ID,
                    ChannelQuery::Replica {
                        channel_id: ChannelId(21),
                        replica_id: crate::types::ReplicaId(0xCAFE),
                    },
                )
                .await
                .unwrap()
                .expect("group member must be persisted");
            let ChannelRecord::Replica(member) = member else {
                panic!("a replica query must never return a helper record");
            };
            assert_eq!(member.transports[0].protocol, Protocol::Grpc as i32);
        });
    }

    /// A version has exactly one writer. Re-sending the *identical*
    /// envelope is an idempotent retry — the recipient acknowledges it
    /// and leaves the stored bytes untouched, so a lost ack costs
    /// nothing.
    #[test]
    fn accept_treats_an_identical_resend_as_an_idempotent_retry() {
        run_async(async {
            const SECRET_ID: u64 = 0xA11CE;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = [42u8; 32];

            let split = request::split(
                &[channel_id, ChannelId(12)],
                SECRET_ID,
                1,
                b"correct horse battery staple",
                2,
            )
            .expect("split secret");
            let committed = split.shares.get(&channel_id).expect("share for channel");
            let produced = request::produce(
                channel_id,
                1,
                SECRET_ID,
                committed,
                &[],
                "",
                &shared_key,
                &[],
            )
            .expect("produce request");
            let request = request::extract(&produced.envelope, &shared_key)
                .expect("extract request")
                .request;

            let mut channel_store = InMemChannelStore::default();
            let mut share_store = InMemShareStore::default();
            let transport = NoopTransport;
            seed_owner_channel(&mut channel_store, SECRET_ID, channel_id).await;

            for _ in 0..2 {
                let events = super::accept(
                    &mut channel_store,
                    &mut share_store,
                    &transport,
                    SECRET_ID,
                    channel_id,
                    &request,
                    &shared_key,
                    1,
                    None,
                )
                .await
                .expect("identical re-send is accepted");
                assert!(
                    matches!(
                        events.as_slice(),
                        [crate::protocol::DeRecEvent::ShareStored { .. }]
                    ),
                    "an idempotent retry is still acknowledged as stored"
                );
            }

            assert_eq!(
                share_store.data.lock().unwrap().len(),
                1,
                "the retry must not create a second entry"
            );
        });
    }

    /// A second writer publishing different content at a version that is
    /// already taken is refused. A single writer derives `version` as
    /// `latest + 1` and so can never reach this path, which is what makes
    /// differing bytes at one version a reliable signal of concurrent
    /// publishers.
    #[test]
    fn accept_refuses_a_second_writer_at_an_existing_version() {
        run_async(async {
            const SECRET_ID: u64 = 0xA11CE;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = [42u8; 32];

            let build = |payload: &[u8]| {
                let split = request::split(&[channel_id, ChannelId(12)], SECRET_ID, 1, payload, 2)
                    .expect("split secret");
                let committed = split.shares.get(&channel_id).expect("share").clone();
                let produced = request::produce(
                    channel_id,
                    1,
                    SECRET_ID,
                    &committed,
                    &[],
                    "",
                    &shared_key,
                    &[],
                )
                .expect("produce request");
                request::extract(&produced.envelope, &shared_key)
                    .expect("extract request")
                    .request
            };

            let first = build(b"written by alice");
            let second = build(b"written by alice-2");
            assert_ne!(
                first.share, second.share,
                "the two writers must differ for this to be a conflict"
            );

            let mut channel_store = InMemChannelStore::default();
            let mut share_store = InMemShareStore::default();
            let transport = NoopTransport;
            seed_owner_channel(&mut channel_store, SECRET_ID, channel_id).await;

            super::accept(
                &mut channel_store,
                &mut share_store,
                &transport,
                SECRET_ID,
                channel_id,
                &first,
                &shared_key,
                1,
                None,
            )
            .await
            .expect("first writer stores");

            let events = super::accept(
                &mut channel_store,
                &mut share_store,
                &transport,
                SECRET_ID,
                channel_id,
                &second,
                &shared_key,
                1,
                None,
            )
            .await
            .expect("the conflict is reported to the peer, not raised locally");

            assert!(
                matches!(events.as_slice(), [crate::protocol::DeRecEvent::NoOp]),
                "a refused write stores nothing and reports no ShareStored"
            );

            let stored = share_store
                .data
                .lock()
                .unwrap()
                .get(&(SECRET_ID, channel_id.0, 1))
                .cloned()
                .expect("the first writer's share survives");
            assert_eq!(
                stored.bytes,
                first.encode_to_vec(),
                "the first writer wins; the second never overwrites"
            );
        });
    }

    /// Author attribution must come from the payload, not from whoever
    /// established the channel. Once a member admitted by a third party
    /// receives updates from every other member over one group channel,
    /// `channel.replica_id` names the admitter — not the writer — so
    /// reading it would misattribute every forwarded update.
    #[test]
    fn replica_ack_attributes_the_responder_from_the_payload() {
        run_async(async {
            const SECRET_ID: u64 = 0xA11CE;
            const CHANNEL_PEER: u64 = 1002;
            const ACTUAL_RESPONDER: u64 = 1003;

            let channel = crate::protocol::types::ReplicaMember {
                channel_id: ChannelId(5001),
                // The member row the response arrived against is Alice-2 …
                replica_id: crate::types::ReplicaId(CHANNEL_PEER),
                transports: vec![TransportProtocol {
                    uri: "https://alice-2.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                communication_info: std::collections::HashMap::new(),
                status: crate::protocol::types::ChannelStatus::Paired,
                created_at: 0,
                role: crate::protocol::types::ReplicaRole::Destination,
            };

            let response = derec_proto::StoreShareResponseMessage {
                result: Some(derec_proto::DeRecResult {
                    status: derec_proto::StatusEnum::Ok as i32,
                    memo: String::new(),
                }),
                secret_id: SECRET_ID,
                version: 3,
                timestamp: None,
                // … but Alice-3 is the one answering.
                replica_id: Some(ACTUAL_RESPONDER),
            };

            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let events = super::handle_replica_response(
                &mut channels,
                &mut secrets,
                SECRET_ID,
                channel.channel_id,
                &channel,
                &response,
            )
            .await
            .expect("ack is handled");

            match events.as_slice() {
                [
                    crate::protocol::DeRecEvent::ReplicaSecretAcked {
                        from_replica_id, ..
                    },
                ] => assert_eq!(
                    *from_replica_id, ACTUAL_RESPONDER,
                    "the responder names itself; the channel's counterparty is not the author"
                ),
                other => panic!("expected a single ReplicaSecretAcked, got {other:?}"),
            }
        });
    }

    /// Both conflict tests need a channel record so `accept` can resolve
    /// a response endpoint.
    async fn seed_owner_channel(
        channels: &mut InMemChannelStore,
        secret_id: u64,
        channel_id: ChannelId,
    ) {
        use crate::protocol::DeRecChannelStore;
        channels
            .save(
                secret_id,
                crate::protocol::types::ChannelRecord::Helper(
                    crate::protocol::types::HelperChannel {
                        channel_id,
                        transports: vec![TransportProtocol {
                            uri: "https://owner.example".to_owned(),
                            protocol: Protocol::Https as i32,
                        }],
                        communication_info: std::collections::HashMap::new(),
                        status: crate::protocol::types::ChannelStatus::Paired,
                        created_at: 0,
                        peer_role: derec_proto::SenderKind::Owner,
                    },
                ),
            )
            .await
            .expect("seed channel");
    }
}

/// Group-model conformance checks (T1–T3, T6 of the replica-group spec).
///
/// These pin the properties that a shared group channel makes easy to get
/// wrong: who a publish addresses, which channel the group is on, and what a
/// non-source member is allowed to do.
#[cfg(test)]
mod group_conformance_tests {
    use crate::protocol::DeRecChannelStore;
    use crate::protocol::test::{InMemChannelStore, InMemSecretStore, run_async};
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole, SecretValue,
    };
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{Protocol, TransportProtocol};

    const SECRET_ID: u64 = 0xC0FFEE;
    const GROUP_CHANNEL: ChannelId = ChannelId(5001);

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    async fn seed_member(
        channels: &mut InMemChannelStore,
        replica_id: u64,
        role: ReplicaRole,
        uri: &str,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP_CHANNEL,
                    replica_id: ReplicaId(replica_id),
                    transports: vec![endpoint(uri)],
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed member");
    }

    async fn seed_group_key(secrets: &mut InMemSecretStore) {
        use crate::protocol::DeRecSecretStore;
        secrets
            .save(SECRET_ID, GROUP_CHANNEL, SecretValue::SharedKey([0x42; 32]))
            .await
            .expect("seed group key");
    }

    /// T1 — a member never addresses itself.
    ///
    /// The roster deliberately includes this device, so the exclusion has to
    /// happen when the dispatch list is built. A self-addressed target would
    /// have the device encrypt a payload to its own endpoint and wait for an
    /// acknowledgement that can never arrive.
    #[test]
    fn a_member_is_never_a_target_of_its_own_publish() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            seed_member(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed_member(
                &mut channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_group_key(&mut secrets).await;

            let (_, targets) =
                super::load_all_paired_targets(&mut channels, &mut secrets, SECRET_ID, Some(1002))
                    .await
                    .expect("targets load");

            let ids: Vec<u64> = targets.iter().map(|(m, _)| m.replica_id.0).collect();
            assert_eq!(
                ids.len(),
                2,
                "the roster has three members; the writer is not one of its own targets"
            );
            assert!(
                !ids.contains(&1002),
                "a member must never address itself, got {ids:?}"
            );
        });
    }

    /// T2 — three members on one channel are three distinct targets.
    ///
    /// The case that exposed the original collision: keyed by `channel_id`
    /// they would collapse into a single target, because the group shares one
    /// channel.
    #[test]
    fn three_members_on_one_channel_are_three_targets() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            for (id, role) in [
                (1001, ReplicaRole::Source),
                (1002, ReplicaRole::Destination),
                (1003, ReplicaRole::Destination),
                (1004, ReplicaRole::Destination),
            ] {
                seed_member(&mut channels, id, role, "https://peer").await;
            }
            seed_group_key(&mut secrets).await;

            let (_, targets) =
                super::load_all_paired_targets(&mut channels, &mut secrets, SECRET_ID, Some(1001))
                    .await
                    .expect("targets load");

            assert_eq!(targets.len(), 3, "one target per member, not per channel");
            let channels_used: std::collections::HashSet<ChannelId> =
                targets.iter().map(|(m, _)| m.channel_id).collect();
            assert_eq!(
                channels_used.len(),
                1,
                "all three sit on the one group channel"
            );
        });
    }

    /// T3 — a destination can publish.
    ///
    /// After hydrating, a destination holds the same state as the source and
    /// must be able to build a payload. Nothing in the roster projection may
    /// gate on the writer being the `Source`.
    #[test]
    fn a_destination_can_build_the_roster() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            seed_member(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed_group_key(&mut secrets).await;

            // Publishing as the destination, not the source.
            let roster = channels.replicas(SECRET_ID).await.expect("roster");
            let group_channel =
                super::group_channel_of(&roster, Some(1002)).expect("group channel resolves");
            assert_eq!(group_channel, Some(GROUP_CHANNEL));

            let secret =
                super::build_secret(&[], &roster, Vec::new(), group_channel, Some([0x42; 32]))
                    .expect("a destination must be able to build the payload");

            let group = secret.replicas.expect("roster is present");
            assert_eq!(group.members.len(), 2, "the roster still names everyone");
            let sources: Vec<u64> = group
                .members
                .iter()
                .filter(|m| m.role == ReplicaRole::Source as i32)
                .map(|m| m.replica_id)
                .collect();
            assert_eq!(
                sources,
                vec![1001],
                "the source is unchanged by who published"
            );
        });
    }

    /// Build a roster in which `source_id` holds the source role.
    async fn roster_with_source(source_id: u64) -> crate::protocol::types::Secret {
        let mut channels = InMemChannelStore::default();
        for id in [1001u64, 1002] {
            let role = if id == source_id {
                ReplicaRole::Source
            } else {
                ReplicaRole::Destination
            };
            seed_member(&mut channels, id, role, "https://peer").await;
        }
        let roster = channels.replicas(SECRET_ID).await.expect("roster");
        super::build_secret(
            &[],
            &roster,
            Vec::new(),
            Some(GROUP_CHANNEL),
            Some([0x42; 32]),
        )
        .expect("build secret")
    }

    /// R1 — the successor learns of its promotion from the roster that carries
    /// it, without deriving anything locally.
    #[test]
    fn a_roster_that_promotes_this_device_reports_it() {
        run_async(async {
            let secret = roster_with_source(1002).await;

            let event = super::promotion_event(Some(1002), false, &secret);

            assert!(
                matches!(
                    event,
                    Some(super::DeRecEvent::ReplicaSourceChanged { replica_id })
                        if replica_id == 1002
                ),
                "got {event:?}"
            );
        });
    }

    /// R1 — a roster restating an unchanged source is not a promotion.
    #[test]
    fn an_unchanged_source_is_not_reported_again() {
        run_async(async {
            let secret = roster_with_source(1002).await;

            assert!(
                super::promotion_event(Some(1002), true, &secret).is_none(),
                "only the transition is an event"
            );
        });
    }

    /// R1 — a member the roster leaves as a destination is unaffected. It
    /// learns the new source from the roster like any other field.
    #[test]
    fn a_destination_is_not_promoted() {
        run_async(async {
            let secret = roster_with_source(1001).await;

            assert!(super::promotion_event(Some(1002), false, &secret).is_none());
        });
    }

    /// T6 — a joiner mid-handover does not redefine the group channel.
    ///
    /// The admitter's own row names the group; a member still on its ephemeral
    /// pairing channel must not drag the group id onto that channel, which
    /// would strand every other member.
    #[test]
    fn a_joiner_on_an_ephemeral_channel_does_not_move_the_group() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            seed_member(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed_member(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            // A joiner admitted since the last round, still on C₂.
            channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id: ChannelId(7001),
                        replica_id: ReplicaId(1003),
                        transports: vec![endpoint("https://alice-3")],
                        communication_info: std::collections::HashMap::new(),
                        role: ReplicaRole::Destination,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed joiner");

            let roster = channels.replicas(SECRET_ID).await.expect("roster");
            let group_channel = super::group_channel_of(&roster, Some(1002))
                .expect("group channel resolves")
                .expect("a group exists");
            assert_eq!(
                group_channel, GROUP_CHANNEL,
                "the group id comes from this device's own row, not the joiner's"
            );
        });
    }
}

/// Build the payload a catch-up request is answered with.
///
/// The same composite a publish sends — whole secret, whole roster — so the
/// asker's hydration path is identical whether the state arrived unsolicited
/// or was pulled. `None` when this device holds no snapshot and therefore has
/// nothing to serve.
pub(in crate::protocol) async fn build_catch_up_payload<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: crate::protocol::DeRecUserSecretStore,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &Us,
    secret_id: u64,
    local_replica_id: Option<u64>,
) -> Result<Option<crate::protocol::types::ReplicaSecretPayload>> {
    let Some(snapshot) = user_secret_store.load_latest(secret_id).await? else {
        return Ok(None);
    };

    let (helpers, _) =
        load_all_paired_targets(channel_store, secret_store, secret_id, local_replica_id).await?;
    let roster = channel_store.replicas(secret_id).await?;
    let group_channel = group_channel_of(&roster, local_replica_id)?;
    let group_key = match group_channel {
        Some(channel_id) => match secret_store
            .load(secret_id, channel_id, SecretKind::SharedKey)
            .await?
        {
            Some(SecretValue::SharedKey(key)) => Some(key),
            _ => None,
        },
        None => None,
    };

    let secret = build_secret(
        &helpers,
        &roster,
        snapshot.secrets,
        group_channel,
        group_key,
    )?;

    // No share map: shares are derived per publishing round from the helper
    // set, and a member does not persist them. A catch-up carries the secret,
    // which is what the asker needs to become current.
    Ok(Some(crate::protocol::types::ReplicaSecretPayload {
        secret: Some(secret),
        shares: Vec::new(),
        shared_key: Vec::new(),
    }))
}

/// Hydrate a payload pulled by a catch-up, reporting install or update.
pub(in crate::protocol) async fn hydrate_catch_up<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: crate::protocol::DeRecUserSecretStore,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    secret_id: u64,
    from_replica_id: u64,
    version: u32,
    payload: &[u8],
) -> Result<Vec<DeRecEvent>> {
    let composite = crate::protocol::types::ReplicaSecretPayload::decode(payload)
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "catch-up payload missing `secret` field",
    ))?;

    let is_install = user_secret_store.load_latest(secret_id).await?.is_none();

    hydrate(
        channel_store,
        secret_store,
        user_secret_store,
        secret_id,
        version,
        &secret,
        String::new(),
    )
    .await?;

    let event = if is_install {
        DeRecEvent::ReplicaSecretInstalled {
            channel_id: ChannelId(secret.replicas.as_ref().map_or(0, |g| g.channel_id)),
            from_replica_id,
            secret_id,
            version,
            secret,
            shares: composite.shares,
        }
    } else {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: ChannelId(secret.replicas.as_ref().map_or(0, |g| g.channel_id)),
            from_replica_id,
            secret_id,
            version,
            secret,
            shares: composite.shares,
        }
    };
    Ok(vec![event])
}
