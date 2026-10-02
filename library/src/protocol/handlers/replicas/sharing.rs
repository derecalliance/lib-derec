// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica side of sharing.
//!
//! `StoreShare` serves both relationships. Against a helper it carries one
//! share of a secret; against another group member it carries the whole
//! secret and the whole roster. The owner↔helper side lives in
//! [`handlers::sharing`](super::super::sharing), which routes here when the
//! payload names an author.
use crate::derec_message::DeRecMessageBuilder;
use crate::extensions::channel_store::ChannelStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::DeRecUserSecretStore;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport, SecretKind,
    SecretValue,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    protocol::types::Secret,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, MessageBody, SenderKind, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage,
};
use prost::Message;

/// How an incoming copy of the secret relates to the one this device holds.
pub(in crate::protocol) enum Arrival {
    /// Newer than what is held, or nothing is held: hydrate it.
    Apply { is_install: bool },
    /// The held version, from the same author: a re-send. Nothing to write.
    Resend,
    /// The held version from a different author, or from an unknown one: two
    /// members published the same version.
    Conflict { held_author_replica_id: Option<u64> },
    /// Older than what is held.
    Stale,
}

/// Classify an incoming copy against this device's snapshot.
///
/// A version is identified by who published it, not by its bytes: the same
/// author re-sending a version may carry a roster that has since changed.
/// When either author is unknown the two copies cannot be told apart, and
/// they are reported as a conflict rather than silently merged.
pub(in crate::protocol) async fn arrival<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    incoming_author_replica_id: Option<u64>,
) -> Result<Arrival> {
    let Some(held) = stores.user_secrets.load_latest(local.secret_id).await? else {
        return Ok(Arrival::Apply { is_install: true });
    };
    Ok(match version.cmp(&held.version) {
        std::cmp::Ordering::Greater => Arrival::Apply { is_install: false },
        std::cmp::Ordering::Less => Arrival::Stale,
        std::cmp::Ordering::Equal
            if held.author_replica_id.is_some()
                && held.author_replica_id == incoming_author_replica_id =>
        {
            Arrival::Resend
        }
        std::cmp::Ordering::Equal => Arrival::Conflict {
            held_author_replica_id: held.author_replica_id,
        },
    })
}

/// Handle a store-share message a group member authored.
///
/// Every member of the group answers on the one group channel, so the author
/// in the payload — not the channel's counterparty — is what says which
/// member the message concerns. Resolving it is this module's job rather than
/// the dispatcher's.
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    author: u64,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    let member = stores
        .channels
        .load_replica_member(local.secret_id, exchange.channel_id, author)
        .await?;
    match inner {
        MessageBody::StoreShareRequest(request) => {
            on_request(
                stores,
                local,
                &member,
                request,
                *exchange.shared_key,
                exchange.trace_id,
            )
            .await
        }
        MessageBody::StoreShareResponse(response) => {
            on_response(stores, local, exchange.channel_id, &member, &response).await
        }
        _ => Err(Error::Invariant(
            "replica identity on a message that is not a store-share exchange",
        )),
    }
}

/// Write an inbound roster into this device's stores.
///
/// The payload is self-contained by construction, so hydration is a straight
/// decomposition: helper channels and their keys, the per-helper share map,
/// every group member against the one group channel, the group key, and the
/// user-secret snapshot. After it, a destination holds the same state as the
/// source and can publish.
///
/// Materialising the helper channels grants no capability the payload had not
/// already granted — it ships each helper's `shared_key`, which is what
/// authenticating as the source toward that helper requires.
///
/// # Why the share map is stored
///
/// `shares` becomes this device's owner-side tracking shares, at the same
/// `(channel_id, version)` keys the source wrote them under. That is what
/// makes verification possible here: a `VerifyShare` proof is
/// `SHA-384(share ‖ nonce)` over the exact bytes the Helper holds, and
/// [`verification`](super::super::verification) reads those bytes back from
/// the share store when a response arrives. A destination that hydrated the
/// roster but not the map can challenge its Helpers and receive their
/// answers, yet has nothing to check them against — it holds a secret it can
/// read and recover from but cannot verify.
///
/// An empty map is not a defect. A round below `threshold` runs no split, so
/// the source distributed no share and tracked none either; a catch-up served
/// by a member that never held the map carries none. In both cases the
/// versions simply stay unverifiable on both sides, consistently.
///
/// Returns the group channel and its key when the payload carried a roster,
/// so the caller can acknowledge there.
pub(in crate::protocol) async fn hydrate<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    secret: &Secret,
    shares: &[crate::protocol::types::ChannelShare],
    description: String,
    author_replica_id: Option<u64>,
) -> Result<Option<(ChannelId, SharedKey)>> {
    let secret_id = local.secret_id;
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, UserSecrets,
    };

    for helper in &secret.helpers {
        let channel_id = ChannelId(helper.channel_id);
        let key: SharedKey =
            helper.shared_key.as_slice().try_into().map_err(|_| {
                crate::Error::InvalidInput("roster helper shared_key must be 32 bytes")
            })?;
        stores
            .channels
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
        stores
            .secrets
            .save(secret_id, channel_id, SecretValue::SharedKey(key))
            .await?;
    }

    // Owner-side tracking shares, keyed exactly as the source keyed them so
    // the two devices agree on what each Helper was given. `secret_id` is the
    // local partition, not the sender's: the wire id names the secret, the
    // partition names the store this device reads back from.
    for share in shares {
        let channel_id = ChannelId(share.channel_id);
        // A share naming a channel the roster does not list would be filed
        // against a Helper this device has no record of, unreachable and
        // unverifiable. The roster is authoritative, so the disagreement is
        // the payload's.
        if !secret
            .helpers
            .iter()
            .any(|h| h.channel_id == share.channel_id)
        {
            return Err(crate::Error::InvalidInput(
                "share map names a channel absent from the roster's helpers",
            ));
        }
        stores
            .shares
            .save(
                secret_id,
                channel_id,
                crate::protocol::types::Share {
                    secret_id,
                    version,
                    bytes: share.committed_share.clone(),
                },
            )
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
        stores
            .channels
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

    stores
        .secrets
        .save(secret_id, group_channel, SecretValue::SharedKey(group_key))
        .await?;

    // Members present in this roster are up to date. Anything flagged as
    // leaving and now absent has completed its departure — reconciled by the
    // caller, which must acknowledge before tearing itself down.
    stores
        .user_secrets
        .save_latest(
            secret_id,
            UserSecrets {
                version,
                secrets: secret.secrets.clone(),
                description: Some(description).filter(|d| !d.is_empty()),
                author_replica_id,
            },
        )
        .await?;

    Ok(Some((group_channel, group_key)))
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
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::ReplicaMember,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    // The author is whoever wrote this message, which is not necessarily
    // the channel's counterparty: a member admitted by a third party
    // receives updates from every other member over the same channel.
    // The payload is authoritative; the channel record is the fallback
    // for writers that predate the field.
    let from_replica_id = request.replica_id.unwrap_or(channel.replica_id.0);
    // Two ids, deliberately distinct. `secret_id` names the secret **on the
    // wire** — the sender's — and is echoed back in the acknowledgement and in
    // the events this returns. Every *store* access uses `local.secret_id`,
    // the partition this instance owns and the one `hydrate` writes to. A
    // destination is not required to have been configured with the sender's
    // id, so reading a store under the wire id finds nothing this device ever
    // wrote.
    let secret_id = request.secret_id;
    let partition = local.secret_id;
    let version = request.version;

    let composite = crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "replica secret payload missing `secret` field",
    ))?;
    let shares = composite.shares;

    // On a push the two carriers of the version are the same round and the
    // sender writes both. Disagreement means the payload and the envelope
    // describe different versions, and there is no way to tell which one the
    // share map belongs to — so it is refused rather than guessed. (A sender
    // predating the payload field sends 0, which is not a disagreement.)
    if composite.version != 0 && composite.version != version {
        return Err(crate::Error::InvalidInput(
            "replica payload's version disagrees with the request's version",
        ));
    }

    // On a push the sender is the publisher, so it stands in for a writer
    // that does not name the author in the payload.
    let author_replica_id = composite.author_replica_id.or(Some(from_replica_id));

    // Decided before hydration writes the snapshot that would erase the
    // distinction between install, update and conflict.
    let is_install = match arrival(stores, local, version, author_replica_id).await? {
        Arrival::Apply { is_install } => is_install,
        Arrival::Resend => {
            answer(
                stores,
                local,
                channel,
                &request,
                (channel.channel_id, shared_key),
                StatusEnum::Ok,
                "",
                inbound_trace_id,
            )
            .await?;
            return Ok(vec![DeRecEvent::NoOp]);
        }
        Arrival::Conflict {
            held_author_replica_id,
        } => {
            answer(
                stores,
                local,
                channel,
                &request,
                (channel.channel_id, shared_key),
                StatusEnum::VersionConflict,
                "a different copy of this version is already held",
                inbound_trace_id,
            )
            .await?;
            return Ok(vec![DeRecEvent::ReplicaVersionConflict {
                channel_id: channel.channel_id,
                from_replica_id,
                secret_id,
                version,
                held_author_replica_id,
                incoming_author_replica_id: author_replica_id,
                secret,
            }]);
        }
        Arrival::Stale => {
            answer(
                stores,
                local,
                channel,
                &request,
                (channel.channel_id, shared_key),
                StatusEnum::VersionConflict,
                "a newer version is already held",
                inbound_trace_id,
            )
            .await?;
            return Ok(vec![DeRecEvent::NoOp]);
        }
    };

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
    let was_source = match local.replica_id {
        Some(id) => stores
            .channels
            .load(
                partition,
                crate::protocol::types::ChannelQuery::Replica {
                    channel_id: channel.channel_id,
                    replica_id: crate::types::ReplicaId(id),
                },
            )
            .await?
            .and_then(|r| r.as_replica().cloned())
            .is_some_and(|m| m.role == crate::protocol::types::ReplicaRole::Source),
        None => false,
    };

    let hydrated = hydrate(
        stores,
        local,
        version,
        &secret,
        &shares,
        request.version_description.clone(),
        author_replica_id,
    )
    .await?;

    // Second half of the removal safety rule: a member flagged as leaving and
    // now absent from the roster has completed its departure.
    let roster_ids: Vec<u64> = secret
        .replicas
        .as_ref()
        .map(|g| g.members.iter().map(|m| m.replica_id).collect())
        .unwrap_or_default();
    let removal = super::unpairing::reconcile(stores, local, &roster_ids).await?;

    let promotion = promotion_event(local, was_source, &secret);

    // Every member answers on the group channel under the group key. Before
    // the first sync a joiner has neither, so it answers where the request
    // arrived.
    let (ack_channel, ack_key) = hydrated.unwrap_or((channel.channel_id, shared_key));
    answer(
        stores,
        local,
        channel,
        &request,
        (ack_channel, ack_key),
        StatusEnum::Ok,
        "",
        inbound_trace_id,
    )
    .await?;

    // Admission handover: the sync arrived on the ephemeral channel minted
    // by the pairing with the admitter. Hydration has already moved every
    // member onto the group channel, so the only thing left at the ephemeral
    // id is its key. The admitter drops its side when this ack lands.
    if ack_channel != channel.channel_id {
        let _ = stores
            .secrets
            .remove(partition, channel.channel_id, SecretKind::SharedKey)
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
        super::unpairing::RemovalOutcome::SelfRemoved => {
            super::unpairing::tear_down(stores, local).await?;

            #[cfg(feature = "logging")]
            tracing::info!(
                secret_id,
                version,
                "left the replica group; partition dropped"
            );

            return Ok(vec![DeRecEvent::SelfRemovedFromGroup { version }]);
        }
        super::unpairing::RemovalOutcome::Removed(ids) => {
            let mut events: Vec<DeRecEvent> = ids
                .into_iter()
                .map(|replica_id| DeRecEvent::ReplicaRemoved { replica_id })
                .collect();
            events.extend(promotion);
            events.push(if is_install {
                DeRecEvent::ReplicaSecretInstalled {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    author_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            } else {
                DeRecEvent::ReplicaSecretReceived {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    author_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            });
            return Ok(events);
        }
        super::unpairing::RemovalOutcome::Nothing => {}
    }

    let event = if is_install {
        DeRecEvent::ReplicaSecretInstalled {
            channel_id: channel.channel_id,
            from_replica_id,
            author_replica_id,
            secret_id,
            version,
            secret,
            shares,
        }
    } else {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: channel.channel_id,
            from_replica_id,
            author_replica_id,
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

/// Answer a member's sync on `(channel, key)` with `status`.
///
/// Every member answers on the same group channel, so the response names
/// which member answered.
#[allow(clippy::too_many_arguments)]
async fn answer<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::ReplicaMember,
    request: &StoreShareRequestMessage,
    (ack_channel, ack_key): (ChannelId, SharedKey),
    status: StatusEnum,
    memo: &str,
    inbound_trace_id: u64,
) -> Result<()> {
    let timestamp = current_timestamp();
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        version: request.version,
        timestamp: Some(timestamp),
        secret_id: request.secret_id,
        replica_id: local.replica_id,
    };
    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(ack_channel)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareResponse(response))
        .encrypt(&ack_key)?
        .build()?
        .encode_to_vec();
    let envelope = crate::derec_message::apply_trace_id(&envelope_bytes, inbound_trace_id)?;
    let endpoint = crate::extensions::advertised_endpoints::reply_to_owned(request);
    let endpoint = if endpoint.is_empty() {
        channel.transports.clone()
    } else {
        endpoint
    };
    stores.transport.send(&endpoint, envelope).await?;
    Ok(())
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
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    arrived_on: ChannelId,
    channel: &crate::protocol::types::ReplicaMember,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
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
        stores
            .channels
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
        let _ = stores
            .secrets
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

/// Report this device being promoted to the group's source by an arriving
/// roster, which happens when the previous source is removed.
///
/// Only the transition is reported: a device that was already the source and
/// still is has nothing to learn from a roster restating it. `was_source` must
/// be read before hydration, which overwrites the stored role.
fn promotion_event(local: &Local<'_>, was_source: bool, secret: &Secret) -> Option<DeRecEvent> {
    if was_source {
        return None;
    }
    let id = local.replica_id?;
    let now_source = secret.replicas.as_ref().is_some_and(|g| {
        g.members.iter().any(|m| {
            m.replica_id == id && m.role == crate::protocol::types::ReplicaRole::Source as i32
        })
    });
    now_source.then_some(DeRecEvent::ReplicaSourceChanged { replica_id: id })
}

#[cfg(test)]
mod tests {
    use crate::extensions::derec_result::DeRecResultExt as _;
    use crate::protocol::DeRecChannelStore;
    use crate::protocol::test::{InMemChannelStore, LocalFixture, StoreRig, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole};
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{Protocol, TransportProtocol};

    const SECRET_ID: u64 = 0xB0B;
    const GROUP_CHANNEL: ChannelId = ChannelId(9001);

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
            let lf = LocalFixture::new(SECRET_ID);
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

            let mut rig = StoreRig::new();

            super::hydrate(
                &mut rig.stores(),
                &lf.local(),
                4,
                &secret,
                &[],
                String::new(),
                None,
            )
            .await
            .expect("a grpc roster must hydrate");

            let expected = [(11_u64, Protocol::Grpc), (12, Protocol::Https)];
            for (channel_id, protocol) in expected {
                let record = rig
                    .channels
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

            let member = rig
                .channels
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

    /// Author attribution must come from the payload, not from whoever
    /// established the channel. Once a member admitted by a third party
    /// receives updates from every other member over one group channel,
    /// `channel.replica_id` names the admitter — not the writer — so
    /// reading it would misattribute every forwarded update.
    #[test]
    fn replica_ack_attributes_the_responder_from_the_payload() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
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
                result: Some(derec_proto::DeRecResult::ok()),
                secret_id: SECRET_ID,
                version: 3,
                timestamp: None,
                // … but Alice-3 is the one answering.
                replica_id: Some(ACTUAL_RESPONDER),
            };

            let mut rig = StoreRig::new();
            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
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

    /// A second roster on a device that already holds the secret reports
    /// `ReplicaSecretReceived`, not `ReplicaSecretInstalled`.
    ///
    /// The distinction is the application's cue to run its first-install logic
    /// exactly once. It is decided by whether a user-secret snapshot exists,
    /// so it only holds if the answer is read from the partition the snapshot
    /// was written to.
    ///
    /// The destination here runs under a **different `secret_id` than the
    /// sender**, which is the arrangement that broke this: a destination is
    /// not required to have been configured with the owner's id, and reading
    /// the store under the wire id found nothing this device ever wrote, so
    /// every round reported a first install.
    #[test]
    fn a_second_roster_reports_received_not_installed() {
        run_async(async {
            use crate::protocol::types::{ReplicaInfo, Replicas, Secret};

            const OWNER: u64 = 1001;
            const SELF_ID: u64 = 1002;
            /// The sender's `secret_id`, deliberately not this device's.
            const WIRE_SECRET_ID: u64 = 0xC0FFEE;

            let lf = LocalFixture::with_replica(SECRET_ID, SELF_ID);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                OWNER,
                ReplicaRole::Source,
                "https://owner",
            )
            .await;
            seed_member(
                &mut rig.channels,
                SELF_ID,
                ReplicaRole::Destination,
                "https://self",
            )
            .await;

            let channel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(OWNER),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("seeded member");

            let roster = || Secret {
                helpers: Vec::new(),
                secrets: Vec::new(),
                replicas: Some(Replicas {
                    channel_id: GROUP_CHANNEL.0,
                    members: vec![
                        ReplicaInfo {
                            replica_id: OWNER,
                            transports: vec![endpoint("https://owner")],
                            role: ReplicaRole::Source as i32,
                            communication_info: std::collections::HashMap::new(),
                        },
                        ReplicaInfo {
                            replica_id: SELF_ID,
                            transports: vec![endpoint("https://self")],
                            role: ReplicaRole::Destination as i32,
                            communication_info: std::collections::HashMap::new(),
                        },
                    ],
                    shared_key: vec![0x42; 32],
                }),
            };

            let request = |version: u32| {
                let payload = crate::protocol::types::ReplicaSecretPayload {
                    secret: Some(roster()),
                    shares: Vec::new(),
                    shared_key: Vec::new(),
                    version,
                    author_replica_id: None,
                };
                derec_proto::StoreShareRequestMessage {
                    secret_id: WIRE_SECRET_ID,
                    share: prost::Message::encode_to_vec(&payload),
                    version,
                    version_description: String::new(),
                    share_algorithm: 0,
                    keep_list: Vec::new(),
                    replica_id: Some(OWNER),
                    reply_to_transports: Vec::new(),
                    timestamp: None,
                }
            };

            let first = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request(1),
                [0x11; 32],
                7,
            )
            .await
            .expect("first roster");
            assert!(
                first.iter().any(|e| matches!(
                    e,
                    crate::protocol::DeRecEvent::ReplicaSecretInstalled { .. }
                )),
                "the first roster installs; got {first:?}"
            );

            let second = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request(2),
                [0x11; 32],
                8,
            )
            .await
            .expect("second roster");
            assert!(
                second.iter().any(|e| matches!(
                    e,
                    crate::protocol::DeRecEvent::ReplicaSecretReceived { .. }
                )),
                "a device that already holds the secret receives rather than installs; got {second:?}"
            );

            // The events still echo the sender's id, which is what names the
            // secret on the wire — only store access moved to the local one.
            let echoed = second.iter().find_map(|e| match e {
                crate::protocol::DeRecEvent::ReplicaSecretReceived { secret_id, .. } => {
                    Some(*secret_id)
                }
                _ => None,
            });
            assert_eq!(
                echoed,
                Some(WIRE_SECRET_ID),
                "the event echoes the inbound secret_id, not the local partition"
            );
        });
    }

    /// Replica A holds a version written by B; C writes the same version.
    mod author_tests {
        use super::*;
        use crate::extensions::channel_store::ChannelStoreExt as _;
        use crate::protocol::types::{
            ReplicaInfo, ReplicaSecretPayload, Replicas, Secret, UserSecret,
        };
        use crate::protocol::{DeRecEvent, DeRecUserSecretStore};
        use derec_proto::{DeRecMessage, MessageBody, StatusEnum, StoreShareRequestMessage};
        use prost::Message as _;

        const B: u64 = 1001;
        const A: u64 = 1002;
        const C: u64 = 1003;
        const GROUP_KEY: [u8; 32] = [0x42; 32];

        fn state(label: &str) -> Secret {
            let member = |replica_id, role: ReplicaRole| ReplicaInfo {
                replica_id,
                transports: vec![endpoint(&format!("https://m{replica_id}"))],
                role: role as i32,
                communication_info: std::collections::HashMap::new(),
            };
            Secret {
                helpers: Vec::new(),
                secrets: vec![UserSecret {
                    id: vec![1],
                    name: label.to_owned(),
                    data: label.as_bytes().to_vec(),
                }],
                replicas: Some(Replicas {
                    channel_id: GROUP_CHANNEL.0,
                    members: vec![
                        member(B, ReplicaRole::Source),
                        member(A, ReplicaRole::Destination),
                        member(C, ReplicaRole::Destination),
                    ],
                    shared_key: GROUP_KEY.to_vec(),
                }),
            }
        }

        fn payload(version: u32, author: Option<u64>, label: &str) -> ReplicaSecretPayload {
            ReplicaSecretPayload {
                secret: Some(state(label)),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version,
                author_replica_id: author,
            }
        }

        fn push(sender: u64, payload: &ReplicaSecretPayload) -> StoreShareRequestMessage {
            StoreShareRequestMessage {
                secret_id: SECRET_ID,
                share: payload.encode_to_vec(),
                version: payload.version,
                version_description: String::new(),
                share_algorithm: 0,
                keep_list: Vec::new(),
                replica_id: Some(sender),
                reply_to_transports: Vec::new(),
                timestamp: None,
            }
        }

        async fn rig_holding_b_v2() -> (LocalFixture, StoreRig) {
            let lf = LocalFixture::with_replica(SECRET_ID, A);
            let mut rig = StoreRig::new();
            for (id, role) in [
                (B, ReplicaRole::Source),
                (A, ReplicaRole::Destination),
                (C, ReplicaRole::Destination),
            ] {
                seed_member(&mut rig.channels, id, role, &format!("https://m{id}")).await;
            }
            let events = deliver(&mut rig, &lf, B, push(B, &payload(2, Some(B), "b"))).await;
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::ReplicaSecretInstalled { .. }]
                ),
                "{events:?}"
            );
            (lf, rig)
        }

        async fn deliver(
            rig: &mut StoreRig,
            lf: &LocalFixture,
            sender: u64,
            request: StoreShareRequestMessage,
        ) -> Vec<DeRecEvent> {
            let channel = rig
                .channels
                .load_replica_member(SECRET_ID, GROUP_CHANNEL, sender)
                .await
                .expect("seeded member");
            super::super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request,
                GROUP_KEY,
                0,
            )
            .await
            .expect("a sync is handled")
        }

        fn last_answer(rig: &StoreRig) -> (i32, u32) {
            let envelope = rig
                .transport
                .sent_envelopes()
                .pop()
                .expect("an answer was sent");
            let msg = DeRecMessage::decode(envelope.as_slice()).expect("envelope decodes");
            match crate::derec_message::extract_inner_message(&msg.message, &GROUP_KEY)
                .expect("answer decrypts")
            {
                MessageBody::StoreShareResponse(r) => (r.result.expect("result").status, r.version),
                other => panic!("expected a StoreShareResponse, got {other:?}"),
            }
        }

        async fn held(rig: &StoreRig) -> (u32, Option<u64>, String) {
            let snapshot = rig
                .user_secrets
                .load_latest(SECRET_ID)
                .await
                .expect("load")
                .expect("a snapshot is held");
            (
                snapshot.version,
                snapshot.author_replica_id,
                snapshot.secrets[0].name.clone(),
            )
        }

        #[test]
        fn a_rival_copy_of_the_held_version_is_a_conflict_and_writes_nothing() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = deliver(&mut rig, &lf, C, push(C, &payload(2, Some(C), "c"))).await;

                match events.as_slice() {
                    [
                        DeRecEvent::ReplicaVersionConflict {
                            from_replica_id,
                            version,
                            held_author_replica_id,
                            incoming_author_replica_id,
                            secret,
                            ..
                        },
                    ] => {
                        assert_eq!(*from_replica_id, C);
                        assert_eq!(*version, 2);
                        assert_eq!(*held_author_replica_id, Some(B));
                        assert_eq!(*incoming_author_replica_id, Some(C));
                        assert_eq!(secret.secrets[0].name, "c", "the incoming state");
                    }
                    other => panic!("expected one ReplicaVersionConflict, got {other:?}"),
                }
                assert_eq!(
                    last_answer(&rig),
                    (StatusEnum::VersionConflict as i32, 2),
                    "the publisher is told its copy was refused"
                );
                assert_eq!(held(&rig).await, (2, Some(B), "b".to_owned()));
            });
        }

        #[test]
        fn the_same_author_resending_its_version_is_acknowledged_without_rewriting() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events =
                    deliver(&mut rig, &lf, B, push(B, &payload(2, Some(B), "b-again"))).await;

                assert!(
                    matches!(events.as_slice(), [DeRecEvent::NoOp]),
                    "{events:?}"
                );
                assert_eq!(last_answer(&rig), (StatusEnum::Ok as i32, 2));
                assert_eq!(held(&rig).await, (2, Some(B), "b".to_owned()));
            });
        }

        #[test]
        fn an_older_version_is_refused_and_writes_nothing() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = deliver(&mut rig, &lf, C, push(C, &payload(1, Some(C), "old"))).await;

                assert!(
                    matches!(events.as_slice(), [DeRecEvent::NoOp]),
                    "{events:?}"
                );
                assert_eq!(last_answer(&rig), (StatusEnum::VersionConflict as i32, 1));
                assert_eq!(held(&rig).await, (2, Some(B), "b".to_owned()));
            });
        }

        #[test]
        fn a_newer_version_is_applied_and_its_author_stored() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = deliver(&mut rig, &lf, C, push(C, &payload(3, Some(C), "c3"))).await;

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretReceived {
                            from_replica_id: C,
                            author_replica_id: Some(C),
                            version: 3,
                            ..
                        }]
                    ),
                    "{events:?}"
                );
                assert_eq!(held(&rig).await, (3, Some(C), "c3".to_owned()));
            });
        }

        #[test]
        fn a_push_that_does_not_name_its_author_is_attributed_to_its_sender() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = deliver(&mut rig, &lf, C, push(C, &payload(3, None, "c3"))).await;

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretReceived {
                            author_replica_id: Some(C),
                            ..
                        }]
                    ),
                    "{events:?}"
                );
                assert_eq!(held(&rig).await.1, Some(C));
            });
        }

        /// A catch-up is answered by whichever member is asked, so the
        /// responder is not the author. The payload is what names it.
        #[test]
        fn a_pulled_copy_keeps_its_original_author() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = crate::protocol::handlers::sharing::hydrate_catch_up(
                    &mut rig.stores(),
                    &lf.local(),
                    C,
                    SECRET_ID,
                    3,
                    &payload(3, Some(B), "b3").encode_to_vec(),
                )
                .await
                .expect("catch-up hydrates");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretReceived {
                            from_replica_id: C,
                            author_replica_id: Some(B),
                            ..
                        }]
                    ),
                    "{events:?}"
                );
                assert_eq!(held(&rig).await, (3, Some(B), "b3".to_owned()));
            });
        }

        #[test]
        fn a_pulled_rival_copy_is_a_conflict_and_writes_nothing() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let events = crate::protocol::handlers::sharing::hydrate_catch_up(
                    &mut rig.stores(),
                    &lf.local(),
                    B,
                    SECRET_ID,
                    2,
                    &payload(2, Some(C), "c").encode_to_vec(),
                )
                .await
                .expect("catch-up is handled");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaVersionConflict {
                            held_author_replica_id: Some(B),
                            incoming_author_replica_id: Some(C),
                            ..
                        }]
                    ),
                    "{events:?}"
                );
                assert_eq!(held(&rig).await, (2, Some(B), "b".to_owned()));
            });
        }

        /// A member serving a catch-up names the author it stored, not
        /// itself, so the asker records who actually wrote the version.
        #[test]
        fn a_catch_up_answer_names_the_stored_author() {
            run_async(async {
                let (lf, mut rig) = rig_holding_b_v2().await;

                let payload = crate::protocol::handlers::sharing::build_catch_up_payload(
                    &mut rig.stores(),
                    &lf.local(),
                )
                .await
                .expect("payload builds")
                .expect("a snapshot is held");

                assert_eq!(payload.version, 2);
                assert_eq!(payload.author_replica_id, Some(B));
            });
        }
    }

    /// A Destination that receives the per-helper share map must keep it as
    /// owner-side tracking shares, or it can never verify what those helpers
    /// hold: `on_response` in the verification handler reads the committed
    /// share for `(channel_id, version)` and has nothing to hash against.
    #[test]
    fn a_received_share_map_is_stored_for_verification() {
        run_async(async {
            use crate::protocol::DeRecShareStore as _;
            use crate::protocol::types::{
                ChannelShare, HelperInfo, ReplicaInfo, ReplicaSecretPayload, Replicas, Secret,
            };

            const OWNER: u64 = 1001;
            const SELF_ID: u64 = 1002;
            const HELPER_CHANNEL: u64 = 77;
            const VERSION: u32 = 3;

            let committed = prost::Message::encode_to_vec(&derec_proto::CommittedDeRecShare {
                de_rec_share: vec![0x01, 0x02, 0x03],
                commitment: Vec::new(),
                merkle_path: Vec::new(),
            });

            let lf = LocalFixture::with_replica(SECRET_ID, SELF_ID);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                OWNER,
                ReplicaRole::Source,
                "https://owner",
            )
            .await;
            seed_member(
                &mut rig.channels,
                SELF_ID,
                ReplicaRole::Destination,
                "https://self",
            )
            .await;

            let channel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(OWNER),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("seeded member");

            let payload = ReplicaSecretPayload {
                secret: Some(Secret {
                    helpers: vec![HelperInfo {
                        channel_id: HELPER_CHANNEL,
                        transports: vec![endpoint("https://helper")],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                    }],
                    secrets: Vec::new(),
                    replicas: Some(Replicas {
                        channel_id: GROUP_CHANNEL.0,
                        members: vec![
                            ReplicaInfo {
                                replica_id: OWNER,
                                transports: vec![endpoint("https://owner")],
                                role: ReplicaRole::Source as i32,
                                communication_info: std::collections::HashMap::new(),
                            },
                            ReplicaInfo {
                                replica_id: SELF_ID,
                                transports: vec![endpoint("https://self")],
                                role: ReplicaRole::Destination as i32,
                                communication_info: std::collections::HashMap::new(),
                            },
                        ],
                        shared_key: vec![0x42; 32],
                    }),
                }),
                shares: vec![ChannelShare {
                    channel_id: HELPER_CHANNEL,
                    committed_share: committed.clone(),
                }],
                shared_key: Vec::new(),
                version: VERSION,
                author_replica_id: None,
            };

            let request = derec_proto::StoreShareRequestMessage {
                secret_id: SECRET_ID,
                share: prost::Message::encode_to_vec(&payload),
                version: VERSION,
                version_description: String::new(),
                share_algorithm: 0,
                keep_list: Vec::new(),
                replica_id: Some(OWNER),
                reply_to_transports: Vec::new(),
                timestamp: None,
            };

            super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request,
                [0x11; 32],
                7,
            )
            .await
            .expect("the sync must be accepted");

            let stored = rig
                .shares
                .load(SECRET_ID, ChannelId(HELPER_CHANNEL), &[VERSION])
                .await
                .expect("share store must answer");

            assert_eq!(
                stored.len(),
                1,
                "the mirrored share map must land in the share store, or verification \
                 of this helper has nothing to check against"
            );
            assert_eq!(
                stored[0].bytes, committed,
                "the tracked bytes must be the same CommittedDeRecShare the helper \
                 received, since that is what the helper hashes"
            );
        });
    }

    /// A share naming a channel the roster does not list is refused.
    ///
    /// Storing it would file a tracking share against a Helper this device has
    /// no channel or key for — unreachable, unverifiable, and indistinguishable
    /// afterwards from a Helper that simply went quiet. The roster is
    /// authoritative, so the disagreement belongs to the payload.
    #[test]
    fn a_share_map_naming_an_unknown_channel_is_refused() {
        run_async(async {
            use crate::protocol::types::{
                ChannelShare, HelperInfo, ReplicaInfo, ReplicaSecretPayload, Replicas, Secret,
            };

            const OWNER: u64 = 1001;
            const SELF_ID: u64 = 1002;

            let lf = LocalFixture::with_replica(SECRET_ID, SELF_ID);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                OWNER,
                ReplicaRole::Source,
                "https://owner",
            )
            .await;
            let channel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(OWNER),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("seeded member");

            let payload = ReplicaSecretPayload {
                secret: Some(Secret {
                    helpers: vec![HelperInfo {
                        channel_id: 77,
                        transports: vec![endpoint("https://helper")],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                    }],
                    secrets: Vec::new(),
                    replicas: Some(Replicas {
                        channel_id: GROUP_CHANNEL.0,
                        members: vec![ReplicaInfo {
                            replica_id: OWNER,
                            transports: vec![endpoint("https://owner")],
                            role: ReplicaRole::Source as i32,
                            communication_info: std::collections::HashMap::new(),
                        }],
                        shared_key: vec![0x42; 32],
                    }),
                }),
                // 78 is in nobody's roster.
                shares: vec![ChannelShare {
                    channel_id: 78,
                    committed_share: vec![0x01],
                }],
                shared_key: Vec::new(),
                version: 1,
                author_replica_id: None,
            };

            let err = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                derec_proto::StoreShareRequestMessage {
                    secret_id: SECRET_ID,
                    share: prost::Message::encode_to_vec(&payload),
                    version: 1,
                    version_description: String::new(),
                    share_algorithm: 0,
                    keep_list: Vec::new(),
                    replica_id: Some(OWNER),
                    reply_to_transports: Vec::new(),
                    timestamp: None,
                },
                [0x11; 32],
                7,
            )
            .await
            .expect_err("a share for an unlisted channel must be refused");
            assert!(
                matches!(err, crate::Error::InvalidInput(m) if m.contains("absent from the roster")),
                "got {err:?}"
            );
        });
    }

    /// A payload whose own version contradicts the request's is refused.
    ///
    /// On a push the sender writes both, so a disagreement leaves no way to
    /// say which version the share map belongs to. Filing it under either
    /// guess would key a Helper's share to a version it may never have held.
    #[test]
    fn a_payload_version_disagreeing_with_the_request_is_refused() {
        run_async(async {
            use crate::protocol::types::{ReplicaInfo, ReplicaSecretPayload, Replicas, Secret};

            const OWNER: u64 = 1001;
            const SELF_ID: u64 = 1002;

            let lf = LocalFixture::with_replica(SECRET_ID, SELF_ID);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                OWNER,
                ReplicaRole::Source,
                "https://owner",
            )
            .await;
            let channel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(OWNER),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("seeded member");

            let payload = ReplicaSecretPayload {
                secret: Some(Secret {
                    helpers: Vec::new(),
                    secrets: Vec::new(),
                    replicas: Some(Replicas {
                        channel_id: GROUP_CHANNEL.0,
                        members: vec![ReplicaInfo {
                            replica_id: OWNER,
                            transports: vec![endpoint("https://owner")],
                            role: ReplicaRole::Source as i32,
                            communication_info: std::collections::HashMap::new(),
                        }],
                        shared_key: vec![0x42; 32],
                    }),
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                // The envelope says 5.
                version: 4,
                author_replica_id: None,
            };

            let err = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                derec_proto::StoreShareRequestMessage {
                    secret_id: SECRET_ID,
                    share: prost::Message::encode_to_vec(&payload),
                    version: 5,
                    version_description: String::new(),
                    share_algorithm: 0,
                    keep_list: Vec::new(),
                    replica_id: Some(OWNER),
                    reply_to_transports: Vec::new(),
                    timestamp: None,
                },
                [0x11; 32],
                7,
            )
            .await
            .expect_err("contradicting versions must be refused");
            assert!(
                matches!(err, crate::Error::InvalidInput(m) if m.contains("version disagrees")),
                "got {err:?}"
            );
        });
    }

    /// Build a roster in which `source_id` holds the source role.
    async fn roster_with_source(source_id: u64) -> crate::protocol::types::Secret {
        let mut rig = StoreRig::new();
        for id in [1001u64, 1002] {
            let role = if id == source_id {
                ReplicaRole::Source
            } else {
                ReplicaRole::Destination
            };
            seed_member(&mut rig.channels, id, role, "https://peer").await;
        }
        let roster = rig
            .channels
            .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
            .await
            .expect("roster");
        crate::protocol::handlers::sharing::build_secret(
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
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1002).await;

            let event = super::promotion_event(&lf.local(), false, &secret);

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
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1002).await;

            assert!(
                super::promotion_event(&lf.local(), true, &secret).is_none(),
                "only the transition is an event"
            );
        });
    }

    /// R1 — a member the roster leaves as a destination is unaffected. It
    /// learns the new source from the roster like any other field.
    #[test]
    fn a_destination_is_not_promoted() {
        run_async(async {
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1001).await;

            assert!(super::promotion_event(&lf.local(), false, &secret).is_none());
        });
    }
}
