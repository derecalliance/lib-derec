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
use crate::protocol::obligation::{Obligation, attempted, deliver, refused, reported};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, SecretKind, SecretValue,
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
    /// The held version, re-sent: nothing to write.
    Resend,
    /// The held version with different contents: two members published the
    /// same version.
    Conflict { held_author_replica_id: Option<u64> },
    /// Older than what is held.
    Stale,
}

/// Classify an incoming copy against this device's snapshot.
///
/// A version is identified by who published it, not by its bytes: the same
/// author re-sending a version may carry a roster that has since changed.
/// A held version with no recorded author — one restored from recovery, or
/// published before the device had a replica id — is identified by its user
/// secrets instead: the same secrets are a re-send, different ones a
/// conflict.
pub(in crate::protocol) async fn arrival<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    incoming_author_replica_id: Option<u64>,
    incoming_secrets: &[crate::protocol::types::UserSecret],
) -> Result<Arrival> {
    let Some(held) = stores.user_secrets.load_latest(local.secret_id).await? else {
        return Ok(Arrival::Apply { is_install: true });
    };
    Ok(match version.cmp(&held.version) {
        std::cmp::Ordering::Greater => Arrival::Apply { is_install: false },
        std::cmp::Ordering::Less => Arrival::Stale,
        std::cmp::Ordering::Equal
            if match held.author_replica_id {
                Some(author) => Some(author) == incoming_author_replica_id,
                None => held.secrets == incoming_secrets,
            } =>
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
            if let Some(obligation) = exchange.obligation {
                obligation.answer_at(&member.transports);
            }
            on_request(
                stores,
                local,
                &member,
                request,
                *exchange.shared_key,
                exchange.trace_id,
                exchange.obligation,
            )
            .await
        }
        MessageBody::StoreShareResponse(response) => {
            on_response(exchange.channel_id, &member, &response)
        }
        _ => Err(Error::Invariant(
            "replica identity on a message that is not a store-share exchange",
        )),
    }
}

/// Why this device refuses a group member's copy of the secret: the status
/// and memo the publisher is answered with.
#[derive(Debug, Clone, Copy)]
pub(in crate::protocol) struct PayloadFault {
    /// `FORMAT_ERROR` for a payload that does not decode or is not
    /// self-consistent, `VERIFICATION_FAILED` for a share map entry that does
    /// not verify against its commitment.
    pub(in crate::protocol) status: StatusEnum,
    /// Human-readable reason sent to the publisher.
    pub(in crate::protocol) memo: &'static str,
}

impl PayloadFault {
    pub(in crate::protocol) const fn format(memo: &'static str) -> Self {
        Self {
            status: StatusEnum::FormatError,
            memo,
        }
    }
}

/// A copy of the secret checked in full and ready for [`hydrate`].
///
/// Holding one is the proof that every write hydration makes will be of a
/// well-formed value, so a payload is either applied whole or not at all.
pub(in crate::protocol) struct Checked<'a> {
    secret: &'a Secret,
    shares: &'a [crate::protocol::types::ChannelShare],
    /// One key per entry of `secret.helpers`, in order.
    helper_keys: Vec<SharedKey>,
    group: Option<CheckedGroup>,
}

struct CheckedGroup {
    channel_id: ChannelId,
    key: SharedKey,
    /// One `(id, role)` per entry of the roster's members, in order.
    members: Vec<(crate::types::ReplicaId, crate::protocol::types::ReplicaRole)>,
}

/// Check every part of an inbound copy of the secret that hydration writes.
///
/// - A recorded threshold is at least `2`.
/// - Each helper's `shared_key` and the group's are 32 bytes.
/// - Each member carries a non-reserved id and a known role.
/// - Each share map entry names a Helper the roster lists — the roster is
///   authoritative, and a share filed against a Helper this device has no
///   channel or key for is unreachable and unverifiable — and is a
///   committed share that passes the rule set a Helper applies before
///   storing one
///   ([`validate_committed_share`](crate::primitives::sharing::response::validate_committed_share)).
///   A tracking share that does not verify would make every later
///   verification of that Helper fail.
pub(in crate::protocol) fn check<'a>(
    secret: &'a Secret,
    shares: &'a [crate::protocol::types::ChannelShare],
) -> std::result::Result<Checked<'a>, PayloadFault> {
    use crate::protocol::types::ReplicaRole;

    if secret.threshold.is_some_and(|t| t < 2) {
        return Err(PayloadFault::format("roster threshold must be at least 2"));
    }

    let helper_keys = secret
        .helpers
        .iter()
        .map(|helper| {
            helper
                .shared_key
                .as_slice()
                .try_into()
                .map_err(|_| PayloadFault::format("roster helper shared_key must be 32 bytes"))
        })
        .collect::<std::result::Result<Vec<SharedKey>, _>>()?;

    for share in shares {
        if !secret
            .helpers
            .iter()
            .any(|h| h.channel_id == share.channel_id)
        {
            return Err(PayloadFault::format(
                "share map names a channel absent from the roster's helpers",
            ));
        }
        crate::primitives::sharing::response::validate_committed_share(&share.committed_share)
            .map_err(|fault| PayloadFault {
                status: fault.status,
                memo: fault.memo,
            })?;
    }

    let group = match secret.replicas.as_ref().filter(|g| !g.members.is_empty()) {
        None => None,
        Some(group) => {
            let key: SharedKey =
                group.shared_key.as_slice().try_into().map_err(|_| {
                    PayloadFault::format("roster group shared_key must be 32 bytes")
                })?;
            let members = group
                .members
                .iter()
                .map(|member| {
                    let id =
                        crate::types::ReplicaId::try_from(member.replica_id).map_err(|_| {
                            PayloadFault::format("roster member carries the reserved replica_id 0")
                        })?;
                    let role = ReplicaRole::from_i32(member.role).ok_or(PayloadFault::format(
                        "roster member carries an unknown role",
                    ))?;
                    Ok((id, role))
                })
                .collect::<std::result::Result<Vec<_>, PayloadFault>>()?;
            Some(CheckedGroup {
                channel_id: ChannelId(group.channel_id),
                key,
                members,
            })
        }
    };

    Ok(Checked {
        secret,
        shares,
        helper_keys,
        group,
    })
}

/// Write an inbound roster into this device's stores.
///
/// The payload is self-contained by construction, so hydration is a straight
/// decomposition: helper channels and their keys, the per-helper share map,
/// every group member against the one group channel, the group key, and the
/// user-secret snapshot. After it, a destination holds the same state as the
/// source and can publish.
///
/// The roster's threshold
/// ([`Secret::threshold`](crate::protocol::types::Secret::threshold)) is
/// written to the snapshot and to every mirrored share, so this device's
/// next publish splits at the same `t`, and verifying a mirrored version
/// reports the `t` it was split with.
///
/// It takes a [`Checked`] payload, so nothing it writes can be refused
/// partway: the only failures left are the stores' own.
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
/// # Proof retention
///
/// A destination keeps every proof it receives: hydration adds the map's
/// proofs and never deletes one, so freeing that storage is the application's
/// concern. The map is what the source sent, not what the Helpers kept. The
/// source later drops its proofs for a Helper that refuses or fails a round,
/// and for versions a confirmed `keepList` had the Helper remove; a
/// destination sees neither answer. Verifying such a version here therefore
/// challenges the Helper, which answers `ShareVerifyRejected`
/// (`UNKNOWN_SHARE_VERSION`), where the source reports
/// [`VerifyFailureReason::NoProof`](crate::protocol::VerifyFailureReason::NoProof)
/// without asking. The application may delete such rows; verifying a version
/// whose rows are gone reports
/// [`VerifySharesFailed`](crate::protocol::DeRecEvent::VerifySharesFailed)
/// with `NoProof`.
///
/// Returns the group channel and its key when the payload carried a roster,
/// so the caller can acknowledge there.
pub(in crate::protocol) async fn hydrate<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    checked: &Checked<'_>,
    description: String,
    author_replica_id: Option<u64>,
) -> Result<Option<(ChannelId, SharedKey)>> {
    let secret_id = local.secret_id;
    let secret = checked.secret;
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, UserSecrets,
    };

    for (helper, key) in secret.helpers.iter().zip(&checked.helper_keys) {
        let channel_id = ChannelId(helper.channel_id);
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
                    weight: helper.effective_weight(),
                }),
            )
            .await?;
        stores
            .secrets
            .save(secret_id, channel_id, SecretValue::SharedKey(*key))
            .await?;
    }

    // Owner-side tracking shares, keyed exactly as the source keyed them so
    // the two devices agree on what each Helper was given. `secret_id` is the
    // local partition, not the sender's: the wire id names the secret, the
    // partition names the store this device reads back from.
    for share in checked.shares {
        stores
            .shares
            .save(
                secret_id,
                ChannelId(share.channel_id),
                crate::protocol::types::Share {
                    secret_id,
                    version,
                    bytes: share.committed_share.clone(),
                    subshares: derec_proto::CommittedDeRecShare::decode(
                        share.committed_share.as_slice(),
                    )
                    .ok()
                    .as_ref()
                    .and_then(crate::protocol::handlers::sharing::subshare_count),
                    threshold: secret.threshold,
                },
            )
            .await?;
    }

    let (Some(group), Some(roster)) = (checked.group.as_ref(), secret.replicas.as_ref()) else {
        return Ok(None);
    };

    for (member, (replica_id, role)) in roster.members.iter().zip(&group.members) {
        stores
            .channels
            .save(
                secret_id,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: group.channel_id,
                    replica_id: *replica_id,
                    transports: member.transports.clone(),
                    communication_info: member.communication_info.clone(),
                    // The roster is authoritative, including for this device's
                    // own row: a joiner's provisional role from pairing is
                    // corrected here.
                    role: *role,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
    }

    stores
        .secrets
        .save(
            secret_id,
            group.channel_id,
            SecretValue::SharedKey(group.key),
        )
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
                threshold: secret.threshold,
            },
        )
        .await?;

    Ok(Some((group.channel_id, group.key)))
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
/// # Refusal
///
/// A payload that does not decode, disagrees with the request, or fails
/// [`check`] is answered with the fault's status on the channel it arrived on
/// and reported as [`DeRecEvent::ReplicaSecretRefused`]. Nothing is written.
///
/// # Proof retention
///
/// An applied copy adds the proofs of its share map and deletes none, so this
/// device keeps every proof it has received (see [`hydrate`]).
///
/// # Group-key handover
///
/// If the payload carries a non-empty `shared_key` (32 bytes), the
/// sender is asking us to adopt the replica-group key for this
/// `secret_id`. Hydration saves it as the group channel's key and moves
/// every member onto the group channel, and the ack travels there under
/// the group key. The ephemeral pairing channel the request arrived on is
/// then dropped: the sender moved this device onto the group channel when
/// it sent the request, so all later traffic arrives there.
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
    obligation: Option<&Obligation>,
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

    // A copy this device will not apply is answered whatever
    // `auto_respond_on_failure` says: the request was authenticated and the
    // refusal is a protocol outcome, so a publisher left without it would
    // only learn of it by timing out. It goes to `reply`, which starts as the
    // channel the request arrived on and moves to the group channel once the
    // payload shows an admission handover.
    let mut reply = (channel.channel_id, shared_key);
    macro_rules! refuse {
        ($fault:expr) => {{
            let fault: PayloadFault = $fault;
            let sent = answer(
                stores,
                local,
                channel,
                &request,
                reply,
                fault.status,
                fault.memo,
                inbound_trace_id,
                obligation,
            )
            .await;
            return refused(
                obligation,
                DeRecEvent::ReplicaSecretRefused {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    status: fault.status as i32,
                    memo: fault.memo.to_owned(),
                },
                fault.status,
                fault.memo,
                sent,
            );
        }};
    }

    let Ok(composite) =
        crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
    else {
        refuse!(PayloadFault::format(
            "replica secret payload is not a valid ReplicaSecretPayload"
        ));
    };
    let Some(secret) = composite.secret else {
        refuse!(PayloadFault::format(
            "replica secret payload missing `secret` field"
        ));
    };
    let shares = composite.shares;

    // An admission handover carries the group key: the admitter dropped the
    // ephemeral key when it sent this copy, so a refusal under that key
    // could never be read. The admitter holds the key it sent, and the
    // roster names the group channel, so the refusal goes there. A handover
    // whose key is not 32 bytes or whose roster names no group leaves no
    // channel the admitter can read, and neither does one that does not
    // decode: those refusals are sent where the request arrived and the
    // admitter learns of them only by timing out.
    if let (Ok(group_key), Some(group)) = (
        <SharedKey>::try_from(composite.shared_key.as_slice()),
        secret.replicas.as_ref(),
    ) {
        reply = (ChannelId(group.channel_id), group_key);
        if let Some(obligation) = obligation {
            obligation.encrypt_for(reply.0, reply.1);
        }
    }

    // On a push the two carriers of the version are the same round and the
    // sender writes both. Disagreement means the payload and the envelope
    // describe different versions, and there is no way to tell which one the
    // share map belongs to — so it is refused rather than guessed. (A sender
    // predating the payload field sends 0, which is not a disagreement.)
    if composite.version != 0 && composite.version != version {
        refuse!(PayloadFault::format(
            "replica payload's version disagrees with the request's version"
        ));
    }

    // The roster is the single source of truth for the group key. The
    // payload's own `shared_key` predates that and is now only a
    // cross-check: two disagreeing copies of a key is a defect worth
    // catching at the boundary rather than a value to choose between.
    if !composite.shared_key.is_empty() {
        let roster_key = secret.replicas.as_ref().map(|g| g.shared_key.as_slice());
        if roster_key != Some(composite.shared_key.as_slice()) {
            refuse!(PayloadFault::format(
                "replica payload's shared_key disagrees with the roster's group key"
            ));
        }
    }

    // Checked whole before anything below writes, so a copy is applied in
    // full or not at all.
    let checked = match check(&secret, &shares) {
        Ok(checked) => checked,
        Err(fault) => refuse!(fault),
    };

    // On a push the sender is the publisher, so it stands in for a writer
    // that does not name the author in the payload.
    let author_replica_id = composite.author_replica_id.or(Some(from_replica_id));

    // Decided before hydration writes the snapshot that would erase the
    // distinction between install, update and conflict.
    let is_install =
        match arrival(stores, local, version, author_replica_id, &secret.secrets).await? {
            Arrival::Apply { is_install } => is_install,
            Arrival::Resend => {
                let sent = answer(
                    stores,
                    local,
                    channel,
                    &request,
                    (channel.channel_id, shared_key),
                    StatusEnum::Ok,
                    "",
                    inbound_trace_id,
                    obligation,
                )
                .await;
                return reported(obligation, vec![DeRecEvent::NoOp], sent);
            }
            Arrival::Conflict {
                held_author_replica_id,
            } => {
                let sent = answer(
                    stores,
                    local,
                    channel,
                    &request,
                    (channel.channel_id, shared_key),
                    StatusEnum::VersionConflict,
                    "a different copy of this version is already held",
                    inbound_trace_id,
                    obligation,
                )
                .await;
                return refused(
                    obligation,
                    DeRecEvent::ReplicaVersionConflict {
                        channel_id: channel.channel_id,
                        from_replica_id,
                        secret_id,
                        version,
                        held_author_replica_id,
                        incoming_author_replica_id: author_replica_id,
                        secret,
                    },
                    StatusEnum::VersionConflict,
                    "a different copy of this version is already held",
                    sent,
                );
            }
            Arrival::Stale => {
                let sent = answer(
                    stores,
                    local,
                    channel,
                    &request,
                    (channel.channel_id, shared_key),
                    StatusEnum::VersionConflict,
                    "a newer version is already held",
                    inbound_trace_id,
                    obligation,
                )
                .await;
                return refused(
                    obligation,
                    DeRecEvent::NoOp,
                    StatusEnum::VersionConflict,
                    "a newer version is already held",
                    sent,
                );
            }
        };

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
        &checked,
        request.version_description.clone(),
        author_replica_id,
    )
    .await?;

    // Every member answers on the group channel under the group key. Before
    // the first sync a joiner has neither, so it answers where the request
    // arrived.
    let (ack_channel, ack_key) = hydrated.unwrap_or((channel.channel_id, shared_key));
    if let Some(obligation) = obligation {
        obligation.encrypt_for(ack_channel, ack_key);
    }

    // Second half of the removal safety rule: a member flagged as leaving and
    // now absent from the roster has completed its departure.
    let roster_ids: Vec<u64> = secret
        .replicas
        .as_ref()
        .map(|g| g.members.iter().map(|m| m.replica_id).collect())
        .unwrap_or_default();
    let removal = super::unpairing::reconcile(stores, local, &roster_ids).await?;

    let promotion = promotion_event(local, was_source, &secret);

    let sent = answer(
        stores,
        local,
        channel,
        &request,
        (ack_channel, ack_key),
        StatusEnum::Ok,
        "",
        inbound_trace_id,
        obligation,
    )
    .await;
    if sent.is_err() && !attempted(obligation) {
        return sent.map(|()| Vec::new());
    }

    // From here the copy is hydrated and the acknowledgement attempted, so
    // what follows completes the committed state; a failure in it is
    // reported after that state's events, never answered a second time.

    // Admission handover: the sync arrived on the ephemeral channel minted
    // by the pairing with the admitter. Hydration has already moved every
    // member onto the group channel, so the only thing left at the ephemeral
    // id is its key. The admitter dropped its side when it sent the sync.
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

    let installed = if is_install {
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

    // Teardown happens strictly after the acknowledgement above: dropping the
    // group key first would leave this device unable to encrypt its reply, so
    // the publisher's round would record a failure against a member that had
    // behaved correctly.
    match removal {
        super::unpairing::RemovalOutcome::SelfRemoved => {
            let torn_down = super::unpairing::tear_down(stores, local).await;

            #[cfg(feature = "logging")]
            tracing::info!(
                secret_id,
                version,
                "left the replica group; partition dropped"
            );

            reported(
                obligation,
                vec![DeRecEvent::SelfRemovedFromGroup { version }],
                sent.and(torn_down),
            )
        }
        super::unpairing::RemovalOutcome::Removed(ids) => {
            let mut events: Vec<DeRecEvent> = ids
                .into_iter()
                .map(|replica_id| DeRecEvent::ReplicaRemoved { replica_id })
                .collect();
            events.extend(promotion);
            events.push(installed);
            reported(obligation, events, sent)
        }
        super::unpairing::RemovalOutcome::Nothing => {
            let mut events: Vec<DeRecEvent> = promotion.into_iter().collect();
            events.push(installed);
            reported(obligation, events, sent)
        }
    }
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
    obligation: Option<&Obligation>,
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
    // A reply-to is filtered through the transport policy before it stands
    // in for the member's recorded endpoint, the same rule every other
    // peer-supplied endpoint is held to; an offer with nothing left after
    // that is treated as no reply-to at all.
    let reply_to = crate::extensions::channel_store::filter_reply_to(
        local.policy,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
    );
    let endpoint = if reply_to.is_empty() {
        channel.transports.clone()
    } else {
        reply_to
    };
    deliver(
        obligation,
        stores.transport,
        &endpoint,
        envelope,
        status,
        memo,
    )
    .await
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
fn on_response(
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
    use crate::protocol::tests::{InMemChannelStore, LocalFixture, StoreRig, run_async};
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
                        weight: 1,
                    },
                    HelperInfo {
                        channel_id: 12,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://helper-b.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        shared_key: vec![0xAB; 32],
                        communication_info: std::collections::HashMap::new(),
                        weight: 1,
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
                threshold: None,
            };

            let mut rig = StoreRig::new();

            super::hydrate(
                &mut rig.stores(),
                &lf.local(),
                4,
                &super::check(&secret, &[]).expect("a well-formed roster"),
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

    /// Hydration writes each Helper's roster weight into its channel, so a
    /// successor's publish gives it the same number of subshares. The
    /// protobuf default `0` comes from a sender that predates the field and
    /// reads as `1`.
    #[test]
    fn hydrate_writes_each_roster_weight_into_the_helper_channel() {
        run_async(async {
            use crate::protocol::types::{ChannelQuery, HelperInfo, Secret};
            let lf = LocalFixture::new(SECRET_ID);
            let helper = |channel_id, weight| HelperInfo {
                channel_id,
                transports: vec![endpoint("https://helper.example")],
                shared_key: vec![channel_id as u8; 32],
                communication_info: std::collections::HashMap::new(),
                weight,
            };
            let secret = Secret {
                helpers: vec![helper(11, 2), helper(12, 0)],
                secrets: Vec::new(),
                replicas: None,
                threshold: None,
            };
            let mut rig = StoreRig::new();

            super::hydrate(
                &mut rig.stores(),
                &lf.local(),
                4,
                &super::check(&secret, &[]).expect("a well-formed roster"),
                String::new(),
                None,
            )
            .await
            .expect("hydrates");

            for (channel_id, expected) in [(11_u64, 2_u32), (12, 1)] {
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
                    .and_then(|r| r.as_helper().cloned())
                    .expect("helper channel persisted");
                assert_eq!(record.weight, expected, "helper {channel_id}");
            }
        });
    }

    /// The tracking shares a Destination mirrors carry the subshare count of
    /// each share, as the Source's own copies do.
    #[test]
    fn hydrate_records_the_subshare_count_of_each_mirrored_share() {
        run_async(async {
            use crate::protocol::types::{ChannelShare, HelperInfo, Secret};
            use prost::Message as _;
            let lf = LocalFixture::new(SECRET_ID);
            let helper = |channel_id, weight| HelperInfo {
                channel_id,
                transports: vec![endpoint("https://helper.example")],
                shared_key: vec![channel_id as u8; 32],
                communication_info: std::collections::HashMap::new(),
                weight,
            };
            // The roster weights deliberately differ from the split weights
            // below: if `hydrate` read the subshare count off
            // `HelperInfo.weight` instead of the mirrored share's own bytes,
            // this would record 1 for both channels instead of 2 and 1.
            let secret = Secret {
                helpers: vec![helper(11, 1), helper(12, 1)],
                secrets: Vec::new(),
                replicas: None,
                threshold: None,
            };
            let split = crate::primitives::sharing::request::split(
                &[(ChannelId(11), 2), (ChannelId(12), 1)],
                SECRET_ID,
                4,
                b"mirrored secret",
                3,
            )
            .expect("weighted split");
            let shares: Vec<ChannelShare> = split
                .shares
                .iter()
                .map(|(channel_id, committed)| ChannelShare {
                    channel_id: channel_id.0,
                    committed_share: committed.encode_to_vec(),
                })
                .collect();
            let mut rig = StoreRig::new();

            super::hydrate(
                &mut rig.stores(),
                &lf.local(),
                4,
                &super::check(&secret, &shares).expect("a well-formed roster"),
                String::new(),
                None,
            )
            .await
            .expect("hydrates");

            for (channel_id, expected) in [(11_u64, 2_u32), (12, 1)] {
                let stored = rig
                    .shares
                    .data
                    .lock()
                    .unwrap()
                    .get(&(SECRET_ID, channel_id, 4))
                    .cloned()
                    .expect("mirrored tracking share");
                assert_eq!(stored.subshares, Some(expected), "helper {channel_id}");
            }
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
                result: Some(derec_proto::DeRecResult::ok()),
                secret_id: SECRET_ID,
                version: 3,
                timestamp: None,
                // … but Alice-3 is the one answering.
                replica_id: Some(ACTUAL_RESPONDER),
            };

            let events = super::on_response(channel.channel_id, &channel, &response)
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
                threshold: None,
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
                None,
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
                None,
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
                threshold: None,
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
                None,
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

        /// A device holding `v2` with no recorded author, as after a restore,
        /// installed through a catch-up whose payload names no author.
        async fn rig_holding_authorless_v2() -> (LocalFixture, StoreRig) {
            let lf = LocalFixture::with_replica(SECRET_ID, A);
            let mut rig = StoreRig::new();
            for (id, role) in [
                (B, ReplicaRole::Source),
                (A, ReplicaRole::Destination),
                (C, ReplicaRole::Destination),
            ] {
                seed_member(&mut rig.channels, id, role, &format!("https://m{id}")).await;
            }
            let events = catch_up(&mut rig, &lf, &payload(2, None, "b")).await;
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::ReplicaSecretInstalled { .. }]
                ),
                "{events:?}"
            );
            assert_eq!(held(&rig).await, (2, None, "b".to_owned()));
            (lf, rig)
        }

        async fn catch_up(
            rig: &mut StoreRig,
            lf: &LocalFixture,
            payload: &ReplicaSecretPayload,
        ) -> Vec<DeRecEvent> {
            crate::protocol::handlers::sharing::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
                GROUP_CHANNEL,
                B,
                SECRET_ID,
                payload.version,
                &payload.encode_to_vec(),
            )
            .await
            .expect("a catch-up is handled")
        }

        /// A held version with no recorded author is identified by its user
        /// secrets: the same secrets pushed again are a re-send.
        #[test]
        fn the_same_secrets_resent_over_an_authorless_version_are_acknowledged() {
            run_async(async {
                let (lf, mut rig) = rig_holding_authorless_v2().await;

                let events = deliver(&mut rig, &lf, B, push(B, &payload(2, Some(B), "b"))).await;

                assert!(
                    matches!(events.as_slice(), [DeRecEvent::NoOp]),
                    "{events:?}"
                );
                assert_eq!(last_answer(&rig), (StatusEnum::Ok as i32, 2));
                assert_eq!(held(&rig).await, (2, None, "b".to_owned()));
            });
        }

        /// The same authorless catch-up answered twice is one version, not two.
        #[test]
        fn a_repeated_authorless_catch_up_is_not_a_conflict() {
            run_async(async {
                let (lf, mut rig) = rig_holding_authorless_v2().await;

                let events = catch_up(&mut rig, &lf, &payload(2, None, "b")).await;

                assert!(
                    matches!(events.as_slice(), [DeRecEvent::NoOp]),
                    "{events:?}"
                );
                assert_eq!(held(&rig).await, (2, None, "b".to_owned()));
            });
        }

        /// Different secrets at an authorless held version are still a rival
        /// copy, reported and not written.
        #[test]
        fn different_secrets_over_an_authorless_version_are_a_conflict() {
            run_async(async {
                let (lf, mut rig) = rig_holding_authorless_v2().await;

                let events = deliver(&mut rig, &lf, C, push(C, &payload(2, Some(C), "c"))).await;

                match events.as_slice() {
                    [
                        DeRecEvent::ReplicaVersionConflict {
                            held_author_replica_id,
                            incoming_author_replica_id,
                            ..
                        },
                    ] => {
                        assert_eq!(*held_author_replica_id, None);
                        assert_eq!(*incoming_author_replica_id, Some(C));
                    }
                    other => panic!("expected one ReplicaVersionConflict, got {other:?}"),
                }
                assert_eq!(last_answer(&rig), (StatusEnum::VersionConflict as i32, 2));
                assert_eq!(held(&rig).await, (2, None, "b".to_owned()));
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
                    GROUP_CHANNEL,
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
                    GROUP_CHANNEL,
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

            let split = crate::primitives::sharing::request::split(
                &[
                    (ChannelId(HELPER_CHANNEL), 1),
                    (ChannelId(HELPER_CHANNEL + 1), 1),
                ],
                SECRET_ID,
                VERSION,
                b"the secret",
                2,
            )
            .expect("split secret");
            let committed = prost::Message::encode_to_vec(
                split
                    .shares
                    .get(&ChannelId(HELPER_CHANNEL))
                    .expect("share for helper"),
            );

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
                        weight: 1,
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
                    threshold: None,
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
                None,
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
                        weight: 1,
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
                    threshold: None,
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

            let events = super::on_request(
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
                None,
            )
            .await
            .expect("a refusal is an outcome, not an error");
            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ReplicaSecretRefused { status, memo, .. }]
                        if *status == derec_proto::StatusEnum::FormatError as i32
                            && memo.contains("absent from the roster")
                ),
                "got {events:?}"
            );
            assert!(
                rig.channels.helper_rows.lock().unwrap().is_empty(),
                "the roster's helpers are not written either"
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
                    threshold: None,
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                // The envelope says 5.
                version: 4,
                author_replica_id: None,
            };

            let events = super::on_request(
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
                None,
            )
            .await
            .expect("a refusal is an outcome, not an error");
            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ReplicaSecretRefused { status, memo, .. }]
                        if *status == derec_proto::StatusEnum::FormatError as i32
                            && memo.contains("version disagrees")
                ),
                "got {events:?}"
            );
        });
    }

    /// A destination refusing a group member's copy of the secret.
    ///
    /// Driven through `process()` so the refusal is checked against both
    /// settings of `auto_respond_on_failure`: the answer must not depend on
    /// it, and the batch's events must not be lost to an error.
    mod refused_payload_tests {
        use super::*;
        use crate::derec_message::DeRecMessageBuilder;
        use crate::primitives::sharing::request;
        use crate::protocol::builder::DeRecProtocolBuilder;
        use crate::protocol::tests::{
            InMemSecretStore, InMemShareStore, InMemStateStore, InMemUserSecretStore,
            RecordingTransport,
        };
        use crate::protocol::types::{
            ChannelShare, HelperInfo, ReplicaInfo, ReplicaSecretPayload, Replicas, Secret,
        };
        use crate::protocol::{DeRecEvent, DeRecProtocol, DeRecSecretStore as _, SecretValue};
        use derec_proto::{CommittedDeRecShare, DeRecMessage, MessageBody, StatusEnum};
        use prost::Message as _;

        const SOURCE: u64 = 1001;
        const SELF_ID: u64 = 1002;
        const GROUP_KEY: [u8; 32] = [0x42; 32];
        const HELPER_CHANNEL: u64 = 77;
        const VERSION: u32 = 1;

        type Destination = DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemStateStore,
            RecordingTransport,
        >;

        struct Rig {
            protocol: Destination,
            channels: InMemChannelStore,
            shares: InMemShareStore,
            secrets: InMemSecretStore,
            user_secrets: InMemUserSecretStore,
            transport: RecordingTransport,
        }

        async fn destination(auto_respond: bool) -> Rig {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            seed_member(&mut channels, SOURCE, ReplicaRole::Source, "https://source").await;
            seed_member(
                &mut channels,
                SELF_ID,
                ReplicaRole::Destination,
                "https://self",
            )
            .await;
            secrets
                .save(SECRET_ID, GROUP_CHANNEL, SecretValue::SharedKey(GROUP_KEY))
                .await
                .expect("seed group key");
            let shares = InMemShareStore::default();
            let user_secrets = InMemUserSecretStore::default();
            let transport = RecordingTransport::default();
            let protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels.clone())
                .with_share_store(shares.clone())
                .with_secret_store(secrets.clone())
                .with_user_secret_store(user_secrets.clone())
                .with_transport(transport.clone())
                .with_state_store(InMemStateStore)
                .with_own_transports(["https://self"])
                .with_threshold(2)
                .with_replica_id(SELF_ID)
                .with_auto_respond_on_failure(auto_respond)
                .build()
                .expect("test protocol builds");
            Rig {
                protocol,
                channels,
                shares,
                secrets,
                user_secrets,
                transport,
            }
        }

        fn roster(helper_channels: &[u64]) -> Secret {
            let member = |replica_id, role: ReplicaRole, uri: &str| ReplicaInfo {
                replica_id,
                transports: vec![endpoint(uri)],
                role: role as i32,
                communication_info: std::collections::HashMap::new(),
            };
            Secret {
                helpers: helper_channels
                    .iter()
                    .map(|&channel_id| HelperInfo {
                        channel_id,
                        transports: vec![endpoint("https://helper")],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                        weight: 1,
                    })
                    .collect(),
                secrets: Vec::new(),
                replicas: Some(Replicas {
                    channel_id: GROUP_CHANNEL.0,
                    members: vec![
                        member(SOURCE, ReplicaRole::Source, "https://source"),
                        member(SELF_ID, ReplicaRole::Destination, "https://self"),
                    ],
                    shared_key: GROUP_KEY.to_vec(),
                }),
                threshold: None,
            }
        }

        /// The committed share a Helper on [`HELPER_CHANNEL`] was given.
        fn committed_share() -> CommittedDeRecShare {
            let split = request::split(
                &[
                    (ChannelId(HELPER_CHANNEL), 1),
                    (ChannelId(HELPER_CHANNEL + 1), 1),
                ],
                SECRET_ID,
                VERSION,
                b"the secret",
                2,
            )
            .expect("split secret");
            split
                .shares
                .get(&ChannelId(HELPER_CHANNEL))
                .expect("share for helper")
                .clone()
        }

        fn payload(helper_channels: &[u64], shares: Vec<ChannelShare>) -> Vec<u8> {
            ReplicaSecretPayload {
                secret: Some(roster(helper_channels)),
                shares,
                shared_key: Vec::new(),
                version: VERSION,
                author_replica_id: Some(SOURCE),
            }
            .encode_to_vec()
        }

        fn push(share: Vec<u8>) -> Vec<u8> {
            let timestamp = crate::derec_message::current_timestamp();
            DeRecMessageBuilder::channel()
                .channel_id(GROUP_CHANNEL)
                .timestamp(timestamp)
                .message_body(MessageBody::StoreShareRequest(
                    derec_proto::StoreShareRequestMessage {
                        secret_id: SECRET_ID,
                        share,
                        version: VERSION,
                        replica_id: Some(SOURCE),
                        timestamp: Some(timestamp),
                        ..Default::default()
                    },
                ))
                .encrypt(&GROUP_KEY)
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec()
        }

        /// Bytes that are not a `ReplicaSecretPayload`.
        fn undecodable() -> Vec<u8> {
            b"not a payload".to_vec()
        }

        /// A share map naming a Helper the roster does not list.
        fn unknown_channel() -> Vec<u8> {
            payload(
                &[HELPER_CHANNEL],
                vec![ChannelShare {
                    channel_id: HELPER_CHANNEL + 1,
                    committed_share: committed_share().encode_to_vec(),
                }],
            )
        }

        /// A committed share whose Merkle path does not lead to its
        /// commitment.
        fn unverifiable_share() -> Vec<u8> {
            let mut share = committed_share();
            share.merkle_path[0].hash[0] ^= 0xFF;
            payload(
                &[HELPER_CHANNEL],
                vec![ChannelShare {
                    channel_id: HELPER_CHANNEL,
                    committed_share: share.encode_to_vec(),
                }],
            )
        }

        /// The one answer sent, decrypted.
        fn answer(rig: &Rig) -> derec_proto::StoreShareResponseMessage {
            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one answer is sent to the publisher");
            let msg = DeRecMessage::decode(sent[0].as_slice()).expect("envelope decodes");
            match crate::derec_message::extract_inner_message(&msg.message, &GROUP_KEY)
                .expect("answer decrypts")
            {
                MessageBody::StoreShareResponse(r) => r,
                other => panic!("expected a StoreShareResponse, got {other:?}"),
            }
        }

        async fn assert_refused(share: Vec<u8>, expected: StatusEnum) {
            for auto_respond in [true, false] {
                let mut rig = destination(auto_respond).await;
                let secrets_before = rig.secrets.data.lock().unwrap().len();

                let events = rig
                    .protocol
                    .process(&push(share.clone()))
                    .await
                    .expect("a refused copy is an outcome, not an error");

                let memo = match events.as_slice() {
                    [
                        DeRecEvent::ReplicaSecretRefused {
                            channel_id,
                            from_replica_id,
                            secret_id,
                            version,
                            status,
                            memo,
                        },
                    ] => {
                        assert_eq!(*channel_id, GROUP_CHANNEL);
                        assert_eq!(*from_replica_id, SOURCE);
                        assert_eq!(*secret_id, SECRET_ID);
                        assert_eq!(*version, VERSION);
                        assert_eq!(*status, expected as i32, "auto_respond={auto_respond}");
                        assert!(!memo.is_empty());
                        memo.clone()
                    }
                    other => panic!(
                        "expected one ReplicaSecretRefused (auto_respond={auto_respond}), \
                         got {other:?}"
                    ),
                };

                let response = answer(&rig);
                let result = response.result.clone().expect("result");
                assert_eq!(
                    result.status, expected as i32,
                    "auto_respond={auto_respond}"
                );
                assert_eq!(result.memo, memo, "the publisher is told the same reason");
                assert_eq!(response.version, VERSION);

                assert!(
                    rig.channels.helper_rows.lock().unwrap().is_empty(),
                    "no helper channel is written"
                );
                assert_eq!(
                    rig.channels.member_rows.lock().unwrap().len(),
                    2,
                    "no member is written"
                );
                assert_eq!(
                    rig.secrets.data.lock().unwrap().len(),
                    secrets_before,
                    "no key is written"
                );
                assert!(
                    rig.shares.data.lock().unwrap().is_empty(),
                    "no tracking share is written"
                );
                assert!(
                    rig.user_secrets.data.lock().unwrap().is_empty(),
                    "no snapshot is written"
                );

                // The publisher reads the answer as a refusal of its sync.
                let responder = ReplicaMember {
                    channel_id: GROUP_CHANNEL,
                    replica_id: ReplicaId(SELF_ID),
                    transports: vec![endpoint("https://self")],
                    communication_info: std::collections::HashMap::new(),
                    role: ReplicaRole::Destination,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                };
                let seen = super::super::on_response(GROUP_CHANNEL, &responder, &response)
                    .expect("the answer is handled");
                assert!(
                    matches!(
                        seen.as_slice(),
                        [DeRecEvent::ReplicaSyncRejected { replica_id: SELF_ID, version: VERSION, status, .. }]
                            if *status == expected as i32
                    ),
                    "got {seen:?}"
                );
            }
        }

        #[test]
        fn an_undecodable_payload_is_refused_as_a_format_error() {
            run_async(assert_refused(undecodable(), StatusEnum::FormatError));
        }

        #[test]
        fn a_share_map_naming_an_unlisted_helper_is_refused_before_anything_is_written() {
            run_async(assert_refused(unknown_channel(), StatusEnum::FormatError));
        }

        #[test]
        fn a_share_that_does_not_verify_is_refused_before_anything_is_written() {
            run_async(assert_refused(
                unverifiable_share(),
                StatusEnum::VerificationFailed,
            ));
        }

        /// A roster whose threshold is below 2 is malformed.
        #[test]
        fn a_roster_threshold_below_two_is_refused_as_a_format_error() {
            let mut secret = roster(&[HELPER_CHANNEL]);
            secret.threshold = Some(1);
            let share = ReplicaSecretPayload {
                secret: Some(secret),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version: VERSION,
                author_replica_id: Some(SOURCE),
            }
            .encode_to_vec();
            run_async(assert_refused(share, StatusEnum::FormatError));
        }

        /// Hydration stores the roster's threshold on the snapshot and on each
        /// mirrored share, and this device's next publish splits at it rather
        /// than at its builder's 2.
        #[test]
        fn a_hydrated_threshold_is_stored_and_the_next_publish_uses_it() {
            run_async(async {
                let mut rig = destination(false).await;
                let helpers = [HELPER_CHANNEL, HELPER_CHANNEL + 1, HELPER_CHANNEL + 2];
                let mut secret = roster(&helpers);
                secret.threshold = Some(3);
                let share = ReplicaSecretPayload {
                    secret: Some(secret),
                    shares: vec![ChannelShare {
                        channel_id: HELPER_CHANNEL,
                        committed_share: committed_share().encode_to_vec(),
                    }],
                    shared_key: Vec::new(),
                    version: VERSION,
                    author_replica_id: Some(SOURCE),
                }
                .encode_to_vec();

                rig.protocol.process(&push(share)).await.expect("hydrates");

                use crate::protocol::DeRecUserSecretStore as _;
                let snapshot = rig
                    .user_secrets
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .expect("snapshot hydrated");
                assert_eq!(snapshot.threshold, Some(3));
                let mirrored = rig
                    .shares
                    .data
                    .lock()
                    .unwrap()
                    .get(&(SECRET_ID, HELPER_CHANNEL, VERSION))
                    .cloned()
                    .expect("mirrored tracking share");
                assert_eq!(mirrored.threshold, Some(3));

                rig.protocol
                    .start(crate::protocol::DeRecFlow::ProtectSecret {
                        secrets: Vec::new(),
                        description: None,
                        weights: std::collections::HashMap::new(),
                        threshold: None,
                    })
                    .await
                    .expect("the hydrated device publishes");
                for channel in helpers {
                    let row = rig
                        .shares
                        .data
                        .lock()
                        .unwrap()
                        .get(&(SECRET_ID, channel, VERSION + 1))
                        .cloned()
                        .expect("tracking share of the next version");
                    assert_eq!(row.threshold, Some(3), "helper {channel}");
                }
            });
        }

        const ADMITTER: u64 = SOURCE;
        const EPHEMERAL: ChannelId = ChannelId(4242);
        const EPHEMERAL_KEY: [u8; 32] = [0x11; 32];

        /// A joiner still on the ephemeral channel of its pairing with the
        /// admitter, holding only that channel's key.
        async fn joiner() -> Rig {
            let channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            for (replica_id, role, uri) in [
                (ADMITTER, ReplicaRole::Source, "https://source"),
                (SELF_ID, ReplicaRole::Destination, "https://self"),
            ] {
                channels
                    .clone()
                    .save(
                        SECRET_ID,
                        ChannelRecord::Replica(ReplicaMember {
                            channel_id: EPHEMERAL,
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
            secrets
                .save(SECRET_ID, EPHEMERAL, SecretValue::SharedKey(EPHEMERAL_KEY))
                .await
                .expect("seed ephemeral key");
            rig_with(channels, secrets, SELF_ID)
        }

        /// The admitter after sending the handover: the joiner is recorded on
        /// the group channel and only the group key is held.
        async fn admitter() -> Rig {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            seed_member(
                &mut channels,
                ADMITTER,
                ReplicaRole::Source,
                "https://source",
            )
            .await;
            seed_member(
                &mut channels,
                SELF_ID,
                ReplicaRole::Destination,
                "https://self",
            )
            .await;
            secrets
                .save(SECRET_ID, GROUP_CHANNEL, SecretValue::SharedKey(GROUP_KEY))
                .await
                .expect("seed group key");
            rig_with(channels, secrets, ADMITTER)
        }

        fn rig_with(
            channels: InMemChannelStore,
            secrets: InMemSecretStore,
            replica_id: u64,
        ) -> Rig {
            let shares = InMemShareStore::default();
            let user_secrets = InMemUserSecretStore::default();
            let transport = RecordingTransport::default();
            let protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels.clone())
                .with_share_store(shares.clone())
                .with_secret_store(secrets.clone())
                .with_user_secret_store(user_secrets.clone())
                .with_transport(transport.clone())
                .with_state_store(InMemStateStore)
                .with_own_transports(["https://self"])
                .with_threshold(2)
                .with_replica_id(replica_id)
                .build()
                .expect("test protocol builds");
            Rig {
                protocol,
                channels,
                shares,
                secrets,
                user_secrets,
                transport,
            }
        }

        /// A joiner refusing its admission handover answers where the
        /// admitter can still read it: on the group channel, under the group
        /// key the handover carried.
        #[test]
        fn a_refused_handover_is_answered_on_the_group_channel() {
            run_async(async {
                let mut joiner = joiner().await;
                let mut share = committed_share();
                share.merkle_path[0].hash[0] ^= 0xFF;
                let handover = ReplicaSecretPayload {
                    secret: Some(roster(&[HELPER_CHANNEL])),
                    shares: vec![ChannelShare {
                        channel_id: HELPER_CHANNEL,
                        committed_share: share.encode_to_vec(),
                    }],
                    shared_key: GROUP_KEY.to_vec(),
                    version: VERSION,
                    author_replica_id: Some(ADMITTER),
                };
                let timestamp = crate::derec_message::current_timestamp();
                let request = DeRecMessageBuilder::channel()
                    .channel_id(EPHEMERAL)
                    .timestamp(timestamp)
                    .message_body(MessageBody::StoreShareRequest(
                        derec_proto::StoreShareRequestMessage {
                            secret_id: SECRET_ID,
                            share: handover.encode_to_vec(),
                            version: VERSION,
                            replica_id: Some(ADMITTER),
                            timestamp: Some(timestamp),
                            ..Default::default()
                        },
                    ))
                    .encrypt(&EPHEMERAL_KEY)
                    .expect("encrypt")
                    .build()
                    .expect("build")
                    .encode_to_vec();
                let secrets_before = joiner.secrets.data.lock().unwrap().len();

                let events = joiner
                    .protocol
                    .process(&request)
                    .await
                    .expect("a refused handover is an outcome, not an error");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretRefused { channel_id: EPHEMERAL, status, .. }]
                            if *status == StatusEnum::VerificationFailed as i32
                    ),
                    "{events:?}"
                );
                assert!(joiner.channels.helper_rows.lock().unwrap().is_empty());
                assert_eq!(joiner.channels.member_rows.lock().unwrap().len(), 2);
                assert_eq!(joiner.secrets.data.lock().unwrap().len(), secrets_before);
                assert!(joiner.shares.data.lock().unwrap().is_empty());
                assert!(joiner.user_secrets.data.lock().unwrap().is_empty());

                let sent = joiner.transport.sent_envelopes();
                assert_eq!(sent.len(), 1, "the refusal is sent");

                let mut admitter = admitter().await;
                let seen = admitter
                    .protocol
                    .process(&sent[0])
                    .await
                    .expect("the admitter reads the refusal");
                assert!(
                    matches!(
                        seen.as_slice(),
                        [DeRecEvent::ReplicaSyncRejected { replica_id: SELF_ID, version: VERSION, status, memo, .. }]
                            if *status == StatusEnum::VerificationFailed as i32
                                && memo == "CommittedDeRecShare Merkle proof verification failed"
                    ),
                    "{seen:?}"
                );
            });
        }

        /// A copy served by a catch-up that does not verify is reported and
        /// not written. Nothing is answered: the copy is itself an answer.
        #[test]
        fn a_refused_catch_up_copy_is_reported_and_writes_nothing() {
            run_async(async {
                let mut rig = destination(false).await;
                let secrets_before = rig.secrets.data.lock().unwrap().len();
                let timestamp = crate::derec_message::current_timestamp();
                let response = DeRecMessageBuilder::channel()
                    .channel_id(GROUP_CHANNEL)
                    .timestamp(timestamp)
                    .message_body(MessageBody::GetShareResponse(
                        derec_proto::GetShareResponseMessage {
                            result: Some(derec_proto::DeRecResult {
                                status: StatusEnum::Ok as i32,
                                memo: String::new(),
                            }),
                            committed_de_rec_share: unverifiable_share(),
                            share_algorithm:
                                crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET,
                            timestamp: Some(timestamp),
                            secret_id: SECRET_ID,
                            version: VERSION,
                            replica_id: Some(SOURCE),
                        },
                    ))
                    .encrypt(&GROUP_KEY)
                    .expect("encrypt")
                    .build()
                    .expect("build")
                    .encode_to_vec();

                let events = rig
                    .protocol
                    .process(&response)
                    .await
                    .expect("a refused copy is an outcome, not an error");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretRefused {
                            channel_id: GROUP_CHANNEL,
                            from_replica_id: SOURCE,
                            secret_id: SECRET_ID,
                            version: VERSION,
                            status,
                            memo,
                        }] if *status == StatusEnum::VerificationFailed as i32
                            && memo == "CommittedDeRecShare Merkle proof verification failed"
                    ),
                    "{events:?}"
                );
                assert!(
                    rig.transport.sent_envelopes().is_empty(),
                    "nothing is answered"
                );
                assert!(rig.channels.helper_rows.lock().unwrap().is_empty());
                assert_eq!(rig.channels.member_rows.lock().unwrap().len(), 2);
                assert_eq!(rig.secrets.data.lock().unwrap().len(), secrets_before);
                assert!(rig.shares.data.lock().unwrap().is_empty());
                assert!(rig.user_secrets.data.lock().unwrap().is_empty());
            });
        }

        #[test]
        fn a_valid_payload_hydrates_in_full() {
            run_async(async {
                let mut rig = destination(false).await;
                let committed = committed_share().encode_to_vec();
                let share = payload(
                    &[HELPER_CHANNEL],
                    vec![ChannelShare {
                        channel_id: HELPER_CHANNEL,
                        committed_share: committed.clone(),
                    }],
                );

                let events = rig.protocol.process(&push(share)).await.expect("hydrates");

                assert!(
                    matches!(
                        events.as_slice(),
                        [DeRecEvent::ReplicaSecretInstalled { .. }]
                    ),
                    "{events:?}"
                );
                assert_eq!(
                    answer(&rig).result.expect("result").status,
                    StatusEnum::Ok as i32
                );
                assert_eq!(rig.channels.helper_rows.lock().unwrap().len(), 1);
                let stored: Vec<Vec<u8>> = rig
                    .shares
                    .data
                    .lock()
                    .unwrap()
                    .values()
                    .map(|s| s.bytes.clone())
                    .collect();
                assert_eq!(stored, vec![committed]);
                assert_eq!(rig.user_secrets.data.lock().unwrap().len(), 1);
            });
        }
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
            None,
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
