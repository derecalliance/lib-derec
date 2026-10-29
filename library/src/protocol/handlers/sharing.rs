// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    ChannelRequest, DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore,
    DeRecTransport, MissingPolicy, PendingAction, SecretKind, SecretValue, Share, ShareStoreError,
};
use super::replicas::sharing as replica;
use crate::derec_message::DeRecMessageBuilder;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
use crate::protocol::DeRecUserSecretStore;
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::obligation::{deliver, refused, reported};
use crate::protocol::stores::{StoreSet, Stores};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::sharing::{
        request::{
            produce as produce_store_share_request_message, split, total_subshares, validate_weight,
        },
        response::{self as sharing_response},
    },
    protocol::types::{HelperInfo, Secret, UserSecret},
    types::{ChannelId, SharedKey, WeightedChannel},
};
use derec_proto::{
    DeRecResult, DeRecSecret, MessageBody, SenderKind, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage,
};
use prost::Message;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    match (inner.route(), &inner) {
        (Route::Replica(author), _) => {
            replica::handle(stores, local, exchange, author, inner).await
        }
        (Route::Helper, _) => {
            let channel = stores
                .channels
                .load_helper(local.secret_id, channel_id)
                .await?
                .ok_or(Error::InvalidInput(
                    "channel id not present in channel store",
                ))?;
            match (channel.peer_role, inner) {
                (SenderKind::Owner, MessageBody::StoreShareRequest(request)) => {
                    on_request(stores, local, exchange, request).await
                }
                (SenderKind::Helper, MessageBody::StoreShareResponse(response)) => {
                    on_response(channel_id, &response)
                }
                (actual, _) => Err(Error::RoleMismatch {
                    channel_id,
                    expected: SenderKind::Owner,
                    actual,
                }),
            }
        }
    }
}

/// Run one `ProtectSecret` round: VSS-split the secret to every paired
/// Helper and ship the full secret to every paired Replica Destination.
///
/// Returns `Ok(None)` when no peer is paired — the secret has nowhere to
/// land, and callers treat it as a no-op so the auto-publish-on-pair
/// hook can fire safely before any peer exists.
///
/// Version progression is anchored to `stores.user_secrets`, so it bumps
/// on every round — including roster-only auto-publishes to Destinations
/// that never write to `stores.shares`. The snapshot written at the end of
/// this function is the source of truth the next round reads.
///
/// `weights` decides how many subshares each paired Helper receives. An
/// explicit map is the full assignment: a Helper it names gets its entry and
/// every other paired Helper gets `1`, so an empty map resets every Helper to
/// `1`. `None` — a publish the library starts on its own — reuses the weight
/// stored on each Helper's channel. A key that is not a paired Helper channel
/// (a replica channel included) fails the call with
/// [`crate::Error::Sharing`].
///
/// The round's threshold is `threshold` when given, otherwise the one stored
/// on the latest [`UserSecrets`](crate::protocol::types::UserSecrets)
/// snapshot, otherwise `default_threshold` (the builder's). It must be at
/// least `2`, failing with
/// [`SharingError::InvalidThreshold`](crate::primitives::sharing::SharingError::InvalidThreshold),
/// and no greater than `max_subshares`, failing with [`Error::InvalidInput`].
///
/// Every resolved weight, stored ones included, must be in `1..threshold`; a
/// weight recorded under a higher threshold fails the round the same way.
/// These checks run before a version is chosen: nothing is written or sent,
/// no version is consumed and no snapshot is written, even when the round
/// would not have split. Once they pass, the resolved weights are written to
/// each Helper's channel before anything is sent, so a round that later fails
/// still leaves them recorded for the next one. The threshold is stored only
/// on the round's own snapshot, saved at the end, and on the owner's copies
/// of the shares it sends: a snapshot never records a threshold its version
/// was not split with, so a round that fails before its snapshot is saved
/// leaves the previous threshold in place.
///
/// `max_subshares`, when set, bounds the round's total subshares. It is
/// checked right after the weights, with the same guarantees: a total above
/// it fails the call with
/// [`SharingError::TooManySubshares`](crate::primitives::sharing::SharingError::TooManySubshares)
/// before a version is chosen or anything is sent.
///
/// The split runs once and feeds both the helper-distribution path and
/// the Destination composite. Below the round's threshold in total
/// subshares (the sum of every paired Helper's weight) no split runs at all:
/// Helpers receive nothing this round and any paired Replicas receive a
/// secret-only composite carrying no share material.
///
/// The snapshot is persisted only *after* distribution attempts
/// complete, so an interrupted round never leaves the version ahead of
/// what peers actually received. Per-channel failures surface as
/// `ProtectSecretFailed` and do not block the snapshot — the round stays
/// addressable and failed peers retry on the next one.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secrets: Vec<UserSecret>,
    description: Option<String>,
    weights: Option<&std::collections::HashMap<ChannelId, u32>>,
    threshold: Option<u32>,
    default_threshold: usize,
    max_subshares: Option<u64>,
    round: &Round<'_>,
) -> Result<Option<SharingRoundResult>> {
    let secret_id = local.secret_id;
    let (mut helpers, replicas) = load_all_paired_targets(stores, local).await?;

    let previous = stores.user_secrets.load_latest(secret_id).await?;
    let round_threshold = threshold
        .or(previous.as_ref().and_then(|s| s.threshold))
        .map_or(default_threshold, |t| t as usize);
    validate_threshold(&helpers, round_threshold, max_subshares)?;
    let weighted_channels = resolve_weights(&helpers, weights, round_threshold)?;
    let subshares = total_subshares(&weighted_channels);
    if let Some(max) = max_subshares
        && subshares > max
    {
        return Err(
            crate::primitives::sharing::SharingError::TooManySubshares { subshares, max }.into(),
        );
    }
    let threshold = round_threshold;
    let recorded_threshold = u32::try_from(threshold).ok();

    if helpers.is_empty() && replicas.is_empty() {
        return Ok(None);
    }

    for ((channel, _), &(_, weight)) in helpers.iter_mut().zip(&weighted_channels) {
        if channel.weight != weight {
            channel.weight = weight;
            stores
                .channels
                .save(
                    secret_id,
                    crate::protocol::types::ChannelRecord::Helper(channel.clone()),
                )
                .await?;
        }
    }

    let snapshot_secrets = secrets.clone();
    let snapshot_description = description.clone();

    // The roster names every member, including this device — a group whose
    // members cannot name themselves is not reconstructible from the payload.
    // The dispatch list above is the same set minus self.
    let mut roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
    stamp_own_row(local, &mut roster);
    let group_channel = group_channel_of(local, &roster)?;
    let group_key = match group_channel {
        Some(channel_id) => Some(
            stores
                .secrets
                .shared_key(secret_id, channel_id)
                .await?
                .ok_or(Error::Invariant(
                    "replica group channel has no key in the secret store",
                ))?,
        ),
        None => None,
    };
    let secret = build_secret(
        &helpers,
        &roster,
        secrets,
        group_channel,
        group_key.as_ref(),
        recorded_threshold,
    )?;

    // A helper holds exactly one endpoint: the one it paired with. Every other
    // member of the group is invisible to it, so a publish from a group must
    // carry `round.reply_to` on the helper leg or the acknowledgement is routed to
    // whoever paired — which for a member that joined later is the wrong
    // device entirely. Decided here, where the roster is known, rather than
    // left to the application's `auto_reply_to` setting.
    let helper_reply_to: Vec<derec_proto::TransportProtocol> = if roster.is_empty() {
        round.reply_to.to_vec()
    } else {
        vec![local.primary().clone()]
    };
    let derec_secret_bytes = wrap_for_helper_split(&secret, threshold);

    let version = previous.as_ref().map(|s| s.version + 1).unwrap_or(1);
    let description = description.as_deref().unwrap_or("").to_owned();

    let split_result = if subshares >= threshold as u64 {
        Some(split(
            &weighted_channels,
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
    let mut keep_version = None;

    if let Some(ref result) = split_result {
        let resolved = resolve_keep_version(stores, secret_id, version).await?;
        keep_version = Some(resolved);
        let helper_outcomes = distribute_shares(
            stores,
            local,
            &helpers,
            result,
            resolved,
            version,
            recorded_threshold,
            &description,
            &Round {
                reply_to: &helper_reply_to,
                trace_id: round.trace_id,
            },
        )
        .await;
        outcomes.extend(helper_outcomes);
    }

    if !replicas.is_empty() {
        let composite =
            build_replica_composite(&secret, split_result.as_ref(), version, local.replica_id);
        let replica_results = distribute_composite_to_destinations(
            stores,
            local,
            &replicas,
            &composite,
            group_channel.zip(group_key),
            version,
            &description,
            round,
        )
        .await;
        replica_outcomes.extend(replica_results);
    }

    stores
        .user_secrets
        .save_latest(
            secret_id,
            crate::protocol::types::UserSecrets {
                version,
                secrets: snapshot_secrets,
                description: snapshot_description,
                author_replica_id: local.replica_id,
                threshold: recorded_threshold,
            },
        )
        .await?;

    Ok(Some(SharingRoundResult {
        version,
        threshold: recorded_threshold,
        weights: weighted_channels.into_iter().collect(),
        outcomes,
        replica_outcomes,
        keep_version,
    }))
}

/// Checks the round's threshold before any weight is judged against it.
///
/// A threshold below `2` admits no valid weight, so it is reported as
/// [`crate::primitives::sharing::SharingError::InvalidThreshold`]. A threshold
/// above the `max_subshares` cap could never be met by a round that splits.
fn validate_threshold(
    helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    threshold: usize,
    max_subshares: Option<u64>,
) -> Result<()> {
    if threshold < 2 || u32::try_from(threshold).is_err() {
        return Err(crate::primitives::sharing::SharingError::InvalidThreshold {
            threshold,
            channels: helpers.len(),
            subshares: helpers.iter().map(|(c, _)| u64::from(c.weight)).sum(),
        }
        .into());
    }
    if let Some(max) = max_subshares
        && max < threshold as u64
    {
        return Err(Error::InvalidInput(
            "max_subshares must be >= threshold; a lower cap fails every round that splits",
        ));
    }
    Ok(())
}

/// Pairs every paired Helper channel with the subshare weight this round
/// gives it, in `helpers` order.
///
/// With `weights` the map is the full assignment: a named Helper gets its
/// entry and every other one gets `1`. Every key must be a paired Helper
/// channel — a replica channel carries no subshares. Without it each Helper
/// keeps the weight stored on its channel.
///
/// Every resolved weight must be in `1..threshold`. Map entries are judged
/// first, then the resolved weights, each in ascending channel-ID order, so
/// the offending entry reported as
/// [`crate::primitives::sharing::SharingError::InvalidWeight`] does not depend
/// on the map's iteration order.
fn resolve_weights(
    helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    weights: Option<&std::collections::HashMap<ChannelId, u32>>,
    threshold: usize,
) -> Result<Vec<WeightedChannel>> {
    if let Some(weights) = weights {
        let mut entries: Vec<(ChannelId, u32)> = weights.iter().map(|(&c, &w)| (c, w)).collect();
        entries.sort_by_key(|&(channel_id, _)| channel_id);
        for (channel_id, weight) in entries {
            if !helpers.iter().any(|(ch, _)| ch.channel_id == channel_id) {
                return Err(crate::primitives::sharing::SharingError::InvalidWeight {
                    channel_id: channel_id.into(),
                    weight,
                }
                .into());
            }
            validate_weight(channel_id, weight, threshold)?;
        }
    }

    let resolved: Vec<WeightedChannel> = helpers
        .iter()
        .map(|(channel, _)| {
            let weight = match weights {
                Some(weights) => weights.get(&channel.channel_id).copied().unwrap_or(1),
                None => channel.weight,
            };
            (channel.channel_id, weight)
        })
        .collect();

    let mut ordered = resolved.clone();
    ordered.sort_by_key(|&(channel_id, _)| channel_id);
    for (channel_id, weight) in ordered {
        validate_weight(channel_id, weight, threshold)?;
    }
    Ok(resolved)
}

/// The output of [`start`] on a round with at least one targeted peer.
///
/// `outcomes` carries one `(ChannelId, Result<()>)` per targeted
/// helper / replica — `Ok(())` on successful dispatch, `Err` on
/// per-channel stores.transport / store failure. The orchestrator maps each
/// entry to `ProtectSecretStarted` / `ProtectSecretFailed`.
pub(in crate::protocol) struct SharingRoundResult {
    pub(in crate::protocol) version: u32,
    /// The threshold this round split at.
    pub(in crate::protocol) threshold: Option<u32>,
    /// The weight this round gave every paired Helper, by channel.
    pub(in crate::protocol) weights: std::collections::HashMap<ChannelId, u32>,
    /// One entry per helper written to, keyed by its channel.
    pub(in crate::protocol) outcomes: Vec<(ChannelId, Result<()>)>,
    /// One entry per group member written to, keyed by its `ReplicaId`.
    ///
    /// Separate from `outcomes` because members share one channel: keying
    /// them by `ChannelId` would collapse the whole group into a single
    /// entry, and the first answer would settle the round for all of them.
    pub(in crate::protocol) replica_outcomes: Vec<(crate::types::ReplicaId, Result<()>)>,
    /// The `keepVersion` every Helper in `outcomes` was sent; `None` when no
    /// share was sent.
    pub(in crate::protocol) keep_version: Option<u32>,
}

/// The memo sent with `SIZE_LIMIT_EXCEEDED` for a share outside this
/// device's configured size range.
const SIZE_OUTSIDE_RANGE: &str = "share size is outside the helper's accepted range";

/// Whether `request`'s share is outside this device's configured
/// `minShareSize`/`maxShareSize`. A bound of `0` is no bound.
fn outside_size_range(local: &Local<'_>, request: &StoreShareRequestMessage) -> bool {
    local.parameter_range.is_some_and(|range| {
        let len = request.share.len() as i64;
        let too_small = range.min_share_size > 0 && len < range.min_share_size;
        let too_large = range.max_share_size != 0 && len > range.max_share_size;
        too_small || too_large
    })
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
/// Helper side of a `StoreShareRequestMessage`: persist the incoming
/// share, apply the request's `keepVersion`, and acknowledge.
///
/// # Refusals
///
/// The share is validated first, with the same rules `on_request` applies
/// before raising `ActionRequired`. A share that does not decode
/// (`FORMAT_ERROR`) or does not verify (`VERIFICATION_FAILED`), or a
/// different share at an already-stored version (`VERSION_CONFLICT`), is
/// answered with that status and reported as [`DeRecEvent::ShareRefused`]:
/// nothing is stored and the `keepVersion` is not applied. A `keepVersion`
/// that is not below `version` (and not `0`) is refused as `FORMAT_ERROR`.
///
/// # Retention (`keepVersion`)
///
/// Once the incoming share is persisted, every version stored under
/// `(secret_id, channel_id)` other than the request's `version` and its
/// `keepVersion` is removed via
/// [`DeRecShareStore::remove_versions`](crate::protocol::DeRecShareStore::remove_versions).
/// `keepVersion = 0` keeps no other version.
///
/// A request whose `version` is older than the latest version already
/// stored on this channel has its `keepVersion` ignored, so a replayed or
/// delayed request can never delete newer shares.
///
/// "Latest" is scoped to this channel rather than to
/// [`DeRecShareStore::latest_version`](crate::protocol::DeRecShareStore::latest_version),
/// which spans every channel of the partition and would let one Owner's
/// newer version suppress another Owner's `keepVersion`.
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &StoreShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;
    let version = request.version;
    let keep_version = request.keep_version;

    // Validated before anything is loaded, stored or removed: an accepted
    // `PendingAction` may have been persisted, or built by hand, without
    // passing through `on_request`.
    if outside_size_range(local, request) {
        return refuse(
            stores,
            local,
            exchange,
            request,
            StatusEnum::SizeLimitExceeded,
            SIZE_OUTSIDE_RANGE,
        )
        .await;
    }
    if let Err(fault) = sharing_response::validate_share(request) {
        return refuse(stores, local, exchange, request, fault.status, fault.memo).await;
    }

    let encoded_request = request.encode_to_vec();

    // Applying `keepVersion` needs every version stored on the channel.
    let stored_on_channel = stores.shares.load(secret_id, channel_id, &[]).await?;

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
    let already_stored = stored_on_channel
        .iter()
        .find(|stored| stored.version == version);

    match already_stored {
        Some(stored) if stored.bytes != encoded_request => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id = secret_id,
                version = version,
                "version conflict — refused a second writer at an existing version"
            );

            return refuse(
                stores,
                local,
                exchange,
                request,
                StatusEnum::VersionConflict,
                "a different share is already stored at this version",
            )
            .await;
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
            let save_result = stores
                .shares
                .save(
                    secret_id,
                    channel_id,
                    Share {
                        secret_id: request.secret_id,
                        version,
                        bytes: encoded_request,
                        subshares: None,
                        threshold: None,
                    },
                )
                .await;
            match save_result {
                Ok(()) => {}
                Err(ShareStoreError::Refused(refusal)) => {
                    let sent = reject(
                        stores,
                        local,
                        exchange,
                        request,
                        refusal.status(),
                        refusal.memo(),
                    )
                    .await;

                    #[cfg(feature = "logging")]
                    tracing::info!(
                        channel_id = channel_id.0,
                        secret_id = secret_id,
                        version = version,
                        "share update refused by the application's share store"
                    );

                    return refused(
                        exchange.obligation,
                        DeRecEvent::NoOp,
                        refusal.status(),
                        refusal.memo(),
                        sent,
                    );
                }
                Err(other) => return Err(other.into()),
            }
        }
    }

    let is_latest = stored_on_channel
        .iter()
        .all(|stored| stored.version <= version);
    if is_latest {
        let stale: Vec<u32> = stored_on_channel
            .iter()
            .map(|stored| stored.version)
            .filter(|v| *v != version && *v != keep_version)
            .collect();
        if !stale.is_empty() {
            stores
                .shares
                .remove_versions(secret_id, channel_id, &stale)
                .await?;

            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id = secret_id,
                version = version,
                removed = ?stale,
                "share versions other than keepVersion removed"
            );
        }
    }

    let resp = sharing_response::produce(channel_id, request, exchange.shared_key)?;
    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(
            secret_id,
            channel_id,
            local.policy,
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
        .await?;
    let sent = deliver(
        exchange.obligation,
        stores.transport,
        &endpoint,
        envelope,
        StatusEnum::Ok,
        "",
    )
    .await;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = secret_id,
        version = version,
        "share stored and acknowledged"
    );

    reported(
        exchange.obligation,
        vec![DeRecEvent::ShareStored {
            channel_id,
            version,
        }],
        sent,
    )
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &StoreShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;
    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        secret_id,
        channel_id,
        failure_response(local, request, status, memo),
        exchange.shared_key,
        exchange.trace_id,
        local.policy,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
        exchange.obligation,
        status,
        memo,
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

/// The `StoreShareResponse` that answers `request` with a non-`Ok` `status`.
pub(in crate::protocol) fn failure_response(
    local: &Local<'_>,
    request: &StoreShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> MessageBody {
    MessageBody::StoreShareResponse(StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        timestamp: Some(current_timestamp()),
        // Mirror the request's audience: only a replica-bound request is
        // rejected by a replica, and only then is a writer identity due.
        replica_id: request.replica_id.and(local.replica_id),
    })
}

/// A refusal the library itself makes on a `StoreShareRequest`: answer the
/// Owner with `status` and `memo` and report
/// [`DeRecEvent::ShareRefused`] carrying the same values.
///
/// The answer is sent whatever `auto_respond_on_failure` says: the request
/// was authenticated and the refusal is a protocol outcome, not a failure,
/// so an Owner left without it would only learn of it by timing out.
///
/// `ShareRefused` is reported however the answer fares. A send failure after
/// the answer was handed to the transport is reported alongside it and never
/// answered again; one before that is answered by the router with this same
/// status and memo.
async fn refuse<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &StoreShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<Vec<DeRecEvent>> {
    let sent = reject(stores, local, exchange, request, status, memo).await;
    refused(
        exchange.obligation,
        DeRecEvent::ShareRefused {
            channel_id: exchange.channel_id,
            version: request.version,
            status: status as i32,
            memo: memo.to_owned(),
        },
        status,
        memo,
        sent,
    )
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
/// Helper side of an inbound `StoreShareRequestMessage`, before the
/// application decides on it.
///
/// A share outside the Helper's size range (`SIZE_LIMIT_EXCEEDED`), or one
/// that does not decode (`FORMAT_ERROR`) or verify (`VERIFICATION_FAILED`),
/// is answered with that status and reported as
/// [`DeRecEvent::ShareRefused`] instead of `ActionRequired`, so the
/// application is never asked to store it.
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: StoreShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    if outside_size_range(local, &request) {
        return refuse(
            stores,
            local,
            exchange,
            &request,
            StatusEnum::SizeLimitExceeded,
            SIZE_OUTSIDE_RANGE,
        )
        .await;
    }

    if let Err(fault) = sharing_response::validate_share(&request) {
        return refuse(stores, local, exchange, &request, fault.status, fault.memo).await;
    }

    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::request(
            exchange.channel_id,
            exchange.trace_id,
            ChannelRequest::StoreShare(request),
        )
        .sealed_with(exchange.shared_key),
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

async fn load_all_paired_targets<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
) -> Result<(
    Vec<(crate::protocol::types::HelperChannel, SharedKey)>,
    Vec<(crate::protocol::types::ReplicaMember, SharedKey)>,
)> {
    let secret_id = local.secret_id;
    use crate::protocol::types::ChannelStatus;

    let helper_rows: Vec<_> = stores
        .channels
        .helpers_matching(
            secret_id,
            crate::protocol::types::HelperFilter {
                status: vec![ChannelStatus::Paired],
                role: Some(SenderKind::Helper),
                ..Default::default()
            },
        )
        .await?;

    // Every member is a target except this device itself. `replicas()`
    // deliberately includes our own row so the roster is reconstructible from
    // stores alone, so the exclusion is asked for here.
    //
    // `Unpairing` members stay on the distribution list even though the roster
    // built below drops them: receiving the version that excludes them is
    // exactly how they learn their departure is complete.
    let member_rows: Vec<_> = stores
        .channels
        .replicas_matching(
            secret_id,
            crate::protocol::types::ReplicaFilter {
                status: vec![ChannelStatus::Paired, ChannelStatus::Unpairing],
                exclude: local.exclude_self(),
                ..Default::default()
            },
        )
        .await?;

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

    let keys: std::collections::HashMap<ChannelId, SharedKey> = stores
        .secrets
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
            let key = keys
                .get(&c.channel_id)
                .expect("load_many(MissingPolicy::Fail) guarantees an entry per id")
                .clone();
            (c, key)
        })
        .collect();

    let replicas: Vec<(crate::protocol::types::ReplicaMember, SharedKey)> = member_rows
        .into_iter()
        .map(|m| {
            let key = keys
                .get(&m.channel_id)
                .expect("load_many(MissingPolicy::Fail) guarantees an entry per id")
                .clone();
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
/// until its first copy is sent.
pub(in crate::protocol) fn build_secret(
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    roster: &[crate::protocol::types::ReplicaMember],
    secrets: Vec<UserSecret>,
    group_channel: Option<ChannelId>,
    group_key: Option<&SharedKey>,
    threshold: Option<u32>,
) -> Result<Secret> {
    let helper_infos: Vec<HelperInfo> = paired_helpers
        .iter()
        .map(|(channel, shared_key)| HelperInfo {
            channel_id: channel.channel_id.0,
            transports: channel.transports.clone(),
            shared_key: shared_key.as_bytes().to_vec(),
            communication_info: channel.communication_info.clone(),
            weight: channel.weight,
        })
        .collect();

    Ok(Secret {
        helpers: helper_infos,
        secrets,
        replicas: build_replicas(roster, group_channel, group_key)?,
        threshold,
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
    local: &Local<'_>,
    roster: &[crate::protocol::types::ReplicaMember],
) -> Result<Option<ChannelId>> {
    if roster.is_empty() {
        return Ok(None);
    }
    let own = local.replica_id.ok_or(Error::ReplicaIdNotConfigured)?;
    roster
        .iter()
        .find(|m| m.replica_id.0 == own)
        .map(|m| Some(m.channel_id))
        .ok_or(Error::Invariant(
            "replica group has members but this device holds no row of its own",
        ))
}

/// Publish this device's own row under what it advertises now.
///
/// A peer's row carries every endpoint and the `communication_info` that peer
/// advertised, but the stored own row only records what was current when it
/// was written. Stamping it here is what lets a roster name, and reach, the
/// device that published it.
fn stamp_own_row(local: &Local<'_>, roster: &mut [crate::protocol::types::ReplicaMember]) {
    let Some(own) = local.replica_id else {
        return;
    };
    if let Some(member) = roster.iter_mut().find(|m| m.replica_id.0 == own) {
        member.transports = local.own_transports.to_vec();
        member.communication_info = super::pairing::own_communication_info(local);
    }
}

/// Project the group onto the wire roster.
fn build_replicas(
    roster: &[crate::protocol::types::ReplicaMember],
    group_channel: Option<ChannelId>,
    group_key: Option<&SharedKey>,
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
        shared_key: group_key.as_bytes().to_vec(),
    }))
}

fn build_replica_composite(
    secret: &Secret,
    split_result: Option<&crate::primitives::sharing::request::SplitResult>,
    version: u32,
    author_replica_id: Option<u64>,
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
        version,
        author_replica_id,
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

/// The `keepVersion` every Helper receives in the round distributing
/// `version`: the share store's
/// [`keep_version`](crate::protocol::DeRecShareStore::keep_version), refused
/// with [`SharingError::InvalidKeepVersion`](crate::primitives::sharing::SharingError::InvalidKeepVersion)
/// when it is not below `version` and not `0`.
async fn resolve_keep_version<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
) -> Result<u32> {
    let keep_version = stores.shares.keep_version(secret_id, version).await?;
    crate::primitives::sharing::request::validate_keep_version(keep_version, version)
        .map_err(crate::Error::from)?;
    Ok(keep_version)
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_shares<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    split_result: &crate::primitives::sharing::request::SplitResult,
    keep_version: u32,
    version: u32,
    threshold: Option<u32>,
    description: &str,
    round: &Round<'_>,
) -> Vec<(ChannelId, Result<()>)> {
    let mut results: Vec<(ChannelId, Result<()>)> = Vec::with_capacity(paired_helpers.len());
    for (channel, shared_key) in paired_helpers {
        let Some(committed_share) = split_result.shares.get(&channel.channel_id) else {
            continue;
        };

        let outcome = dispatch_share_to_helper(
            stores,
            local,
            channel,
            shared_key,
            committed_share,
            keep_version,
            version,
            threshold,
            description,
            round,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.channel_id.0,
                secret_id = local.secret_id,
                version = version,
                "share envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.channel_id.0,
                secret_id = local.secret_id,
                version = version,
                error = %e,
                "share envelope dispatch failed"
            ),
        }

        results.push((channel.channel_id, outcome));
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = local.secret_id,
        version = version,
        "secret distributed to helpers"
    );

    results
}
/// How many subshares `committed` carries: the length of `subshares` in the
/// `DeRecShare` it wraps, or `None` when that share does not decode or
/// carries none — the proto requires at least one, so an empty list is a
/// malformed share, not a real count of zero.
pub(in crate::protocol) fn subshare_count(
    committed: &derec_proto::CommittedDeRecShare,
) -> Option<u32> {
    derec_proto::DeRecShare::decode(committed.de_rec_share.as_slice())
        .ok()
        .and_then(|share| u32::try_from(share.subshares.len()).ok())
        .filter(|&n| n > 0)
}

/// Send one Helper its share and save the owner's proof of what was sent.
///
/// The saved proof is retained only until the round settles that channel:
/// [`DeRecProtocol::tick`](crate::protocol::DeRecProtocol::tick) and
/// [`DeRecProtocol::process`](crate::protocol::DeRecProtocol::process) drop
/// it the moment the channel is marked failed, whether by an inbound
/// `ShareRejected` (any status) or by the round timing out. A stored proof
/// is therefore always either confirmed by its Helper or still part of an
/// open round — a late `ShareConfirmed` arriving after the failure is
/// recorded but never recreates it.
///
/// A confirmation also removes the proofs of older versions the Helper
/// dropped: a Helper that accepts this share removes every version it holds
/// on the channel other than this one and `keep_version`, so when it confirms, the
/// owner removes its proofs of those versions for that channel. A Helper
/// that refuses or never answers removes nothing, and neither does the
/// owner. Verifying a removed version reports
/// [`VerifyFailureReason::NoProof`](crate::protocol::VerifyFailureReason::NoProof)
/// without asking the Helper.
///
/// None of this reaches a replica Destination. It never sees the Helpers'
/// answers, and it keeps every proof the share map of a copy gives it: it
/// never deletes one on its own, and freeing that storage is the
/// application's concern. Verifying there a version that a Helper refused, or
/// later dropped under `keepVersion`, draws `ShareVerifyRejected`
/// (`UNKNOWN_SHARE_VERSION`) from that Helper, where this device reports
/// `NoProof`. Once the application deletes those rows, verifying the version
/// there reports
/// [`VerifySharesFailed`](crate::protocol::DeRecEvent::VerifySharesFailed)
/// with `NoProof`.
#[allow(clippy::too_many_arguments)]
async fn dispatch_share_to_helper<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::HelperChannel,
    shared_key: &SharedKey,
    committed_share: &derec_proto::CommittedDeRecShare,
    keep_version: u32,
    version: u32,
    threshold: Option<u32>,
    description: &str,
    round: &Round<'_>,
) -> Result<()> {
    let secret_id = local.secret_id;
    let msg = produce_store_share_request_message(
        channel.channel_id,
        version,
        secret_id,
        committed_share,
        keep_version,
        description,
        shared_key,
        round.reply_to,
    )?;
    let envelope = crate::derec_message::apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(&channel.transports, envelope).await?;

    stores
        .shares
        .save(
            secret_id,
            channel.channel_id,
            Share {
                secret_id,
                version,
                bytes: committed_share.encode_to_vec(),
                subshares: subshare_count(committed_share),
                threshold,
            },
        )
        .await?;
    Ok(())
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_composite_to_destinations<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    replicas: &[(crate::protocol::types::ReplicaMember, SharedKey)],
    composite: &crate::protocol::types::ReplicaSecretPayload,
    group: Option<(ChannelId, SharedKey)>,
    version: u32,
    description: &str,
    round: &Round<'_>,
) -> Vec<(crate::types::ReplicaId, Result<()>)> {
    let mut results: Vec<(crate::types::ReplicaId, Result<()>)> =
        Vec::with_capacity(replicas.len());
    for (channel, channel_key) in replicas {
        let outcome = dispatch_composite_to_destination(
            stores,
            local,
            channel,
            channel_key,
            composite,
            group.as_ref(),
            version,
            description,
            round,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.channel_id.0,
                secret_id = local.secret_id,
                version = version,
                "replica secret envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.channel_id.0,
                secret_id = local.secret_id,
                version = version,
                error = %e,
                "replica secret envelope dispatch failed"
            ),
        }

        results.push((channel.replica_id, outcome));
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = local.secret_id,
        version = version,
        count = replicas.len(),
        "secret distributed to replicas"
    );

    results
}
/// Send one member its copy of a publish.
///
/// # Admission handover
///
/// A member this device admitted since the last round is still recorded on
/// the ephemeral channel of that pairing, under the pairing key. Its copy
/// carries the group key, and the member moves onto the group channel as
/// soon as it is sent: the member hydrates onto the group channel and drops
/// the ephemeral one when it receives the copy, so every later message must
/// already use the group channel. Waiting for the member's acknowledgement
/// instead would strand it on a channel it no longer holds, for any publish
/// sent before that acknowledgement lands, and for good if it never does.
#[allow(clippy::too_many_arguments)]
async fn dispatch_composite_to_destination<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::ReplicaMember,
    channel_key: &SharedKey,
    composite: &crate::protocol::types::ReplicaSecretPayload,
    group: Option<&(ChannelId, SharedKey)>,
    version: u32,
    description: &str,
    round: &Round<'_>,
) -> Result<()> {
    let handover = group.filter(|(_, group_key)| channel_key != group_key);

    let mut per_channel = composite.clone();
    if let Some((_, group_key)) = handover {
        per_channel.shared_key = group_key.as_bytes().to_vec();
    }
    let composite_bytes = per_channel.encode_to_vec();

    let timestamp = current_timestamp();
    let reply_to_transports = round.reply_to.to_vec();
    let msg = StoreShareRequestMessage {
        share: composite_bytes,
        share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
        version,
        keep_version: 0,
        version_description: description.to_owned(),
        timestamp: Some(timestamp),
        secret_id: local.secret_id,
        reply_to_transports,
        replica_id: local.replica_id,
    };

    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareRequest(msg))
        .encrypt(channel_key)?
        .build()?
        .encode_to_vec();
    let envelope = crate::derec_message::apply_trace_id(&envelope_bytes, round.trace_id)?;
    stores.transport.send(&channel.transports, envelope).await?;

    if let Some((group_channel, _)) = handover {
        stores
            .channels
            .save(
                local.secret_id,
                crate::protocol::types::ChannelRecord::Replica(
                    crate::protocol::types::ReplicaMember {
                        channel_id: *group_channel,
                        ..channel.clone()
                    },
                ),
            )
            .await?;
        let _ = stores
            .secrets
            .remove(local.secret_id, channel.channel_id, SecretKind::SharedKey)
            .await;

        #[cfg(feature = "logging")]
        tracing::info!(
            ephemeral_channel_id = channel.channel_id.0,
            group_channel_id = group_channel.0,
            replica_id = channel.replica_id.0,
            "admitted member moved onto the group channel"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::primitives::sharing::request;
    use crate::protocol::context::Exchange;
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemUserSecretStore,
        NoopTransport, RecordingTransport, RefusingShareStore, StoreRig, run_async,
    };
    use crate::protocol::{Refusal, ShareStoreError};
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{ParameterRange, Protocol, StatusEnum, TransportProtocol};
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
            let lf = LocalFixture::new(HELPER_SECRET_ID);
            const OWNER_SECRET_ID: u64 = 0xA11CE;
            const HELPER_SECRET_ID: u64 = 0xB0B;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = crate::types::SharedKey::new([42u8; 32]);

            // Owner: split a secret across two channels and build the
            // store-share request bound to OWNER_SECRET_ID.
            let split = request::split(
                &[(channel_id, 1), (ChannelId(12), 1)],
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
                0,
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

            let mut rig = StoreRig::with_transport(NoopTransport);
            super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id,
                    shared_key: &shared_key,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("accept stores share");

            // The record is keyed under the Helper's partition id, but the
            // `secret_id` field Discovery groups by must be the Owner's.
            let stored = rig
                .shares
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

    /// A version has exactly one writer. Re-sending the *identical*
    /// envelope is an idempotent retry — the recipient acknowledges it
    /// and leaves the stored bytes untouched, so a lost ack costs
    /// nothing.
    #[test]
    fn accept_treats_an_identical_resend_as_an_idempotent_retry() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            const SECRET_ID: u64 = 0xA11CE;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = crate::types::SharedKey::new([42u8; 32]);

            let split = request::split(
                &[(channel_id, 1), (ChannelId(12), 1)],
                SECRET_ID,
                1,
                b"correct horse battery staple",
                2,
            )
            .expect("split secret");
            let committed = split.shares.get(&channel_id).expect("share for channel");
            let produced =
                request::produce(channel_id, 1, SECRET_ID, committed, 0, "", &shared_key, &[])
                    .expect("produce request");
            let request = request::extract(&produced.envelope, &shared_key)
                .expect("extract request")
                .request;

            let mut rig = StoreRig::with_transport(NoopTransport);
            seed_owner_channel(&mut rig.channels, SECRET_ID, channel_id).await;

            for _ in 0..2 {
                let events = super::accept(
                    &mut rig.stores(),
                    &lf.local(),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id: 1,
                        obligation: None,
                    },
                    &request,
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
                rig.shares.data.lock().unwrap().len(),
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
            let lf = LocalFixture::new(SECRET_ID);
            const SECRET_ID: u64 = 0xA11CE;
            let channel_id = ChannelId(11);
            let shared_key: SharedKey = crate::types::SharedKey::new([42u8; 32]);

            let build = |payload: &[u8]| {
                let split = request::split(
                    &[(channel_id, 1), (ChannelId(12), 1)],
                    SECRET_ID,
                    1,
                    payload,
                    2,
                )
                .expect("split secret");
                let committed = split.shares.get(&channel_id).expect("share").clone();
                let produced = request::produce(
                    channel_id,
                    1,
                    SECRET_ID,
                    &committed,
                    0,
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

            let mut rig = StoreRig::with_transport(NoopTransport);
            seed_owner_channel(&mut rig.channels, SECRET_ID, channel_id).await;

            super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id,
                    shared_key: &shared_key,
                    trace_id: 1,
                    obligation: None,
                },
                &first,
            )
            .await
            .expect("first writer stores");

            let events = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id,
                    shared_key: &shared_key,
                    trace_id: 1,
                    obligation: None,
                },
                &second,
            )
            .await
            .expect("the conflict is reported to the peer, not raised locally");

            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRefused { version: 1, status, .. }]
                        if *status == StatusEnum::VersionConflict as i32
                ),
                "a refused write stores nothing and reports ShareRefused, got {events:?}"
            );

            let stored = rig
                .shares
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

    const KEEP_SECRET_ID: u64 = 0xA11CE;
    const KEEP_CHANNEL: ChannelId = ChannelId(11);
    const KEEP_KEY: SharedKey = SharedKey::new([42u8; 32]);

    fn store_request(version: u32, keep_version: u32) -> derec_proto::StoreShareRequestMessage {
        let split = request::split(
            &[(KEEP_CHANNEL, 1), (ChannelId(12), 1)],
            KEEP_SECRET_ID,
            version,
            format!("secret at version {version}").as_bytes(),
            2,
        )
        .expect("split secret");
        let committed = split.shares.get(&KEEP_CHANNEL).expect("share");
        let produced = request::produce(
            KEEP_CHANNEL,
            version,
            KEEP_SECRET_ID,
            committed,
            keep_version,
            "",
            &KEEP_KEY,
            &[],
        )
        .expect("produce request");
        request::extract(&produced.envelope, &KEEP_KEY)
            .expect("extract request")
            .request
    }

    async fn accept_version(rig: &mut StoreRig, version: u32, keep_version: u32) {
        accept_request(rig, &store_request(version, keep_version)).await;
    }

    async fn accept_request(rig: &mut StoreRig, request: &derec_proto::StoreShareRequestMessage) {
        let lf = LocalFixture::new(KEEP_SECRET_ID);
        let events = super::accept(
            &mut rig.stores(),
            &lf.local(),
            &Exchange {
                channel_id: KEEP_CHANNEL,
                shared_key: &KEEP_KEY,
                trace_id: 1,
                obligation: None,
            },
            request,
        )
        .await
        .expect("accept stores share");
        assert!(
            matches!(
                events.as_slice(),
                [crate::protocol::DeRecEvent::ShareStored { .. }]
            ),
            "every request in these scenarios is acknowledged as stored"
        );
    }

    /// A rig whose Helper already holds `versions` on [`KEEP_CHANNEL`],
    /// stored directly so that no `keepVersion` prunes them on the way in.
    async fn keep_rig_with_versions(versions: &[u32]) -> StoreRig {
        use crate::protocol::DeRecShareStore;
        let mut rig = StoreRig::new();
        seed_owner_channel(&mut rig.channels, KEEP_SECRET_ID, KEEP_CHANNEL).await;
        for v in versions {
            rig.shares
                .save(
                    KEEP_SECRET_ID,
                    KEEP_CHANNEL,
                    crate::protocol::types::Share {
                        secret_id: KEEP_SECRET_ID,
                        version: *v,
                        bytes: store_request(*v, 0).encode_to_vec(),
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed held version");
        }
        rig
    }

    fn stored_versions(rig: &StoreRig) -> Vec<u32> {
        let mut versions: Vec<u32> = rig
            .shares
            .data
            .lock()
            .unwrap()
            .keys()
            .filter(|(s, c, _)| *s == KEEP_SECRET_ID && *c == KEEP_CHANNEL.0)
            .map(|(_, _, v)| *v)
            .collect();
        versions.sort_unstable();
        versions
    }

    /// A Helper stores no subshare count, even for a share carrying several.
    #[test]
    fn a_helper_records_no_subshare_count() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[]).await;
            let split = request::split(
                &[(KEEP_CHANNEL, 2), (ChannelId(12), 1)],
                KEEP_SECRET_ID,
                1,
                b"weighted secret",
                3,
            )
            .expect("split secret");
            let committed = split.shares.get(&KEEP_CHANNEL).expect("share");
            let produced = request::produce(
                KEEP_CHANNEL,
                1,
                KEEP_SECRET_ID,
                committed,
                0,
                "",
                &KEEP_KEY,
                &[],
            )
            .expect("produce request");
            let weighted = request::extract(&produced.envelope, &KEEP_KEY)
                .expect("extract request")
                .request;
            accept_request(&mut rig, &weighted).await;

            let stored = rig
                .shares
                .data
                .lock()
                .unwrap()
                .get(&(KEEP_SECRET_ID, KEEP_CHANNEL.0, 1))
                .cloned()
                .expect("the helper stored the share");
            assert_eq!(stored.subshares, None);
        });
    }

    /// A `DeRecShare` that decodes but carries no subshare must read back as
    /// `None`, not as a real count of `0`: the proto requires at least one
    /// subshare, so an empty list means the share is malformed, not that the
    /// helper holds zero of them.
    #[test]
    fn subshare_count_of_an_empty_subshare_list_is_none() {
        let malformed = derec_proto::DeRecShare {
            subshares: Vec::new(),
            ..Default::default()
        };
        let committed = derec_proto::CommittedDeRecShare {
            de_rec_share: malformed.encode_to_vec(),
            commitment: Vec::new(),
            merkle_path: Vec::new(),
        };
        assert_eq!(super::subshare_count(&committed), None);
    }

    /// Once the new share is stored, every version other than it and
    /// `keepVersion` is deleted.
    #[test]
    fn accept_keeps_only_the_incoming_version_and_the_keep_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            accept_version(&mut rig, 4, 2).await;
            assert_eq!(stored_versions(&rig), vec![2, 4]);
        });
    }

    /// `keepVersion = 0` keeps no version other than the incoming one.
    #[test]
    fn accept_with_keep_version_zero_keeps_only_the_incoming_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            accept_version(&mut rig, 4, 0).await;
            assert_eq!(stored_versions(&rig), vec![4]);
        });
    }

    /// A Helper that missed the round before keeps the last valid version
    /// it holds when that is the `keepVersion`, and one that answered both
    /// drops the version that never became valid.
    #[test]
    fn accept_keeps_the_last_valid_version_across_a_missed_round() {
        run_async(async {
            let mut missed = keep_rig_with_versions(&[1]).await;
            accept_version(&mut missed, 3, 1).await;
            assert_eq!(stored_versions(&missed), vec![1, 3]);

            let mut answered = keep_rig_with_versions(&[1, 2]).await;
            accept_version(&mut answered, 3, 1).await;
            assert_eq!(stored_versions(&answered), vec![1, 3]);
        });
    }

    /// A `keepVersion` the Helper does not hold keeps nothing else.
    #[test]
    fn accept_with_a_keep_version_not_held_keeps_only_the_incoming_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 3]).await;
            accept_version(&mut rig, 4, 2).await;
            assert_eq!(stored_versions(&rig), vec![4]);
        });
    }

    /// A request older than the latest stored version must have its
    /// `keepVersion` ignored, so a replay cannot delete newer shares.
    #[test]
    fn accept_ignores_the_keep_version_of_an_older_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 3, 4]).await;
            accept_version(&mut rig, 2, 0).await;
            assert_eq!(stored_versions(&rig), vec![1, 2, 3, 4]);
        });
    }

    /// The share carried by the request is kept on an idempotent re-send
    /// where that version is already stored.
    #[test]
    fn accept_never_deletes_the_incoming_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            let request = store_request(4, 3);
            accept_request(&mut rig, &request).await;
            assert_eq!(stored_versions(&rig), vec![3, 4]);
            accept_request(&mut rig, &request).await;
            assert_eq!(stored_versions(&rig), vec![3, 4]);
        });
    }

    /// The `keepVersion` only governs the channel it arrived on.
    #[test]
    fn accept_keep_version_leaves_other_channels_untouched() {
        run_async(async {
            use crate::protocol::DeRecShareStore;
            let mut rig = keep_rig_with_versions(&[1, 2]).await;
            let other = crate::protocol::types::Share {
                secret_id: KEEP_SECRET_ID,
                version: 1,
                bytes: vec![1, 2, 3],
                subshares: None,
                threshold: None,
            };
            rig.shares
                .save(KEEP_SECRET_ID, ChannelId(99), other)
                .await
                .expect("seed other channel");
            accept_version(&mut rig, 3, 0).await;
            assert_eq!(stored_versions(&rig), vec![3]);
            assert!(
                rig.shares
                    .data
                    .lock()
                    .unwrap()
                    .contains_key(&(KEEP_SECRET_ID, 99, 1)),
                "a share on another channel must survive"
            );
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
                        weight: 1,
                    },
                ),
            )
            .await
            .expect("seed channel");
    }

    const PARAM_SECRET_ID: u64 = 0xA11CE;
    const PARAM_CHANNEL: ChannelId = ChannelId(41);
    const PARAM_KEY: SharedKey = SharedKey::new([5u8; 32]);

    fn param_reply_to() -> TransportProtocol {
        TransportProtocol {
            uri: "https://owner.example".to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    /// A real `StoreShareRequestMessage` whose `share` field is a VSS
    /// committed-share encoding of `payload`, carrying an explicit
    /// `reply_to` so these tests need no seeded channel record to resolve
    /// a response endpoint.
    fn param_request(payload: &[u8]) -> derec_proto::StoreShareRequestMessage {
        let split = request::split(
            &[(PARAM_CHANNEL, 1), (ChannelId(42), 1)],
            PARAM_SECRET_ID,
            1,
            payload,
            2,
        )
        .expect("split secret");
        let committed = split.shares.get(&PARAM_CHANNEL).expect("share for channel");
        let produced = request::produce(
            PARAM_CHANNEL,
            1,
            PARAM_SECRET_ID,
            committed,
            0,
            "",
            &PARAM_KEY,
            std::slice::from_ref(&param_reply_to()),
        )
        .expect("produce request");
        request::extract(&produced.envelope, &PARAM_KEY)
            .expect("extract request")
            .request
    }

    /// Decode a `StoreShareResponseMessage` sent by a Helper, using the same
    /// decode path the orchestrator's `process()` uses
    /// (`extract_inner_message`) rather than reimplementing it, since these
    /// tests only inspect the response content.
    fn decode_store_share_response(
        envelope_bytes: &[u8],
        shared_key: &SharedKey,
    ) -> derec_proto::StoreShareResponseMessage {
        let envelope =
            derec_proto::DeRecMessage::decode(envelope_bytes).expect("decode response envelope");
        match crate::derec_message::extract_inner_message(&envelope.message, shared_key)
            .expect("decrypt response")
        {
            derec_proto::MessageBody::StoreShareResponse(resp) => resp,
            other => panic!("expected a StoreShareResponse, got {other:?}"),
        }
    }

    /// `accept` applies the size range again: an action whose share is
    /// outside it, however the action reached `accept`, stores nothing and is
    /// answered `SIZE_LIMIT_EXCEEDED`.
    #[test]
    fn accept_refuses_a_share_above_max_size() {
        run_async(async {
            let request = param_request(b"a plausible secret payload for the size gate tests");
            let share_len = request.share.len() as i64;
            let range = ParameterRange {
                max_share_size: share_len - 1,
                ..Default::default()
            };
            let lf = LocalFixture::with_parameter_range(PARAM_SECRET_ID, range);
            let mut rig = StoreRig::with_transport(RecordingTransport::default());

            let events = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("an oversized share is refused, not raised as an error");

            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRefused { status, .. }]
                        if *status == StatusEnum::SizeLimitExceeded as i32
                ),
                "got {events:?}"
            );
            assert!(
                rig.shares.data.lock().unwrap().is_empty(),
                "nothing is stored"
            );
            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one rejection is sent to the owner");
            let response = decode_store_share_response(&sent[0], &PARAM_KEY);
            assert_eq!(
                response.result.expect("result").status,
                StatusEnum::SizeLimitExceeded as i32
            );
        });
    }

    /// A share-size check refuses an oversized share before `ActionRequired`
    /// is ever raised, so the application is never asked about it.
    #[test]
    fn helper_refuses_a_share_above_max_size() {
        run_async(async {
            let request = param_request(b"a plausible secret payload for the size gate tests");
            let share_len = request.share.len() as i64;
            let range = ParameterRange {
                max_share_size: share_len - 1,
                ..Default::default()
            };
            let lf = LocalFixture::with_parameter_range(PARAM_SECRET_ID, range);
            let mut rig = StoreRig::with_transport(RecordingTransport::default());

            let events = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                request,
            )
            .await
            .expect("an oversized share is refused, not raised as an error");

            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRefused { channel_id, version: 1, status, .. }]
                        if *channel_id == PARAM_CHANNEL
                            && *status == StatusEnum::SizeLimitExceeded as i32
                ),
                "a refused share reports ShareRefused instead of ActionRequired, got {events:?}"
            );
            assert!(
                rig.shares.data.lock().unwrap().is_empty(),
                "nothing is stored once the size check refuses the share"
            );

            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one rejection is sent to the owner");
            let response = decode_store_share_response(&sent[0], &PARAM_KEY);
            let owner_events = super::on_response(PARAM_CHANNEL, &response)
                .expect("owner processes the rejection");
            assert!(
                matches!(
                    owner_events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRejected { status, .. }]
                        if *status == StatusEnum::SizeLimitExceeded as i32
                ),
                "the owner sees the mapped SIZE_LIMIT_EXCEEDED status"
            );
        });
    }

    /// Same gate, triggered from the other side of the range.
    #[test]
    fn helper_refuses_a_share_below_min_size() {
        run_async(async {
            let request = param_request(b"a plausible secret payload for the size gate tests");
            let share_len = request.share.len() as i64;
            let range = ParameterRange {
                min_share_size: share_len + 1,
                ..Default::default()
            };
            let lf = LocalFixture::with_parameter_range(PARAM_SECRET_ID, range);
            let mut rig = StoreRig::with_transport(RecordingTransport::default());

            let events = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                request,
            )
            .await
            .expect("an undersized share is refused, not raised as an error");

            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRefused { channel_id, version: 1, status, .. }]
                        if *channel_id == PARAM_CHANNEL
                            && *status == StatusEnum::SizeLimitExceeded as i32
                ),
                "a refused share reports ShareRefused instead of ActionRequired, got {events:?}"
            );
            assert!(
                rig.shares.data.lock().unwrap().is_empty(),
                "nothing is stored once the size check refuses the share"
            );

            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one rejection is sent to the owner");
            let response = decode_store_share_response(&sent[0], &PARAM_KEY);
            let owner_events = super::on_response(PARAM_CHANNEL, &response)
                .expect("owner processes the rejection");
            assert!(
                matches!(
                    owner_events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRejected { status, .. }]
                        if *status == StatusEnum::SizeLimitExceeded as i32
                ),
                "the owner sees the mapped SIZE_LIMIT_EXCEEDED status"
            );
        });
    }

    /// Inclusive bounds: a share exactly at `min == max` is accepted,
    /// stored, and acknowledged.
    #[test]
    fn helper_accepts_a_share_at_the_bounds() {
        run_async(async {
            let request = param_request(b"a payload whose encoded share sets the exact bound");
            let share_len = request.share.len() as i64;
            let range = ParameterRange {
                min_share_size: share_len,
                max_share_size: share_len,
                ..Default::default()
            };
            let lf = LocalFixture::with_parameter_range(PARAM_SECRET_ID, range);
            let mut rig = StoreRig::with_transport(RecordingTransport::default());

            let events = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                request.clone(),
            )
            .await
            .expect("a share exactly at the bounds is let through");
            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ActionRequired { action, .. }]
                        if action.kind() == crate::protocol::PendingActionKind::StoreShare
                ),
                "an in-bounds share raises ActionRequired like any other"
            );

            let accept_events = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("accept stores the in-bounds share");
            assert!(matches!(
                accept_events.as_slice(),
                [crate::protocol::DeRecEvent::ShareStored { .. }]
            ));

            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1);
            let response = decode_store_share_response(&sent[0], &PARAM_KEY);
            let owner_events =
                super::on_response(PARAM_CHANNEL, &response).expect("owner processes the ack");
            assert!(matches!(
                owner_events.as_slice(),
                [crate::protocol::DeRecEvent::ShareConfirmed { .. }]
            ));
        });
    }

    /// `max_share_size == 0` means unbounded, independent of `min`.
    #[test]
    fn helper_with_zero_max_accepts_any_size() {
        run_async(async {
            let request = param_request(b"a payload accepted under an explicit zero max bound");
            let range = ParameterRange::default();
            let lf = LocalFixture::with_parameter_range(PARAM_SECRET_ID, range);
            let mut rig = StoreRig::with_transport(NoopTransport);

            let events = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                request,
            )
            .await
            .expect("a zero max_share_size means unbounded");

            assert!(matches!(
                events.as_slice(),
                [crate::protocol::DeRecEvent::ActionRequired { .. }]
            ));
        });
    }

    type ParamRig = StoreRig<
        InMemChannelStore,
        RefusingShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        RecordingTransport,
    >;

    fn param_rig() -> ParamRig {
        StoreRig {
            channels: InMemChannelStore::default(),
            shares: RefusingShareStore::default(),
            secrets: InMemSecretStore::default(),
            user_secrets: InMemUserSecretStore::default(),
            state: InMemPersistedStateStore::default(),
            transport: RecordingTransport::default(),
        }
    }

    /// A `save` refusal is answered to the owner with the mapped status
    /// and memo, not raised as a local error.
    #[test]
    fn helper_save_refusal_answers_the_mapped_status() {
        run_async(async {
            let request = param_request(b"a share update the application's store refuses");
            let lf = LocalFixture::new(PARAM_SECRET_ID);
            let mut rig = param_rig();
            rig.shares.set_refusal(Some(Refusal::TooFrequent));

            let events = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("a store refusal is answered, not raised as an error");

            assert!(
                matches!(events.as_slice(), [crate::protocol::DeRecEvent::NoOp]),
                "the refusal is reported to the peer, not surfaced as a local ShareStored"
            );

            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 1);
            let response = decode_store_share_response(&sent[0], &PARAM_KEY);
            let owner_events =
                super::on_response(PARAM_CHANNEL, &response).expect("owner processes the refusal");
            assert!(
                matches!(
                    owner_events.as_slice(),
                    [crate::protocol::DeRecEvent::ShareRejected { status, memo, .. }]
                        if *status == StatusEnum::TooFrequent as i32
                            && memo == "refused by the helper: too frequent"
                ),
                "the owner sees the mapped TOO_FREQUENT status and memo"
            );
        });
    }

    /// An idempotent re-send of an already-stored version never calls
    /// `save`, so a store that has started refusing writes still
    /// acknowledges it.
    #[test]
    fn helper_save_refusal_is_not_reached_by_an_idempotent_resend() {
        run_async(async {
            let request =
                param_request(b"a payload re-sent identically after the store starts refusing");
            let lf = LocalFixture::new(PARAM_SECRET_ID);
            let mut rig = param_rig();

            let first = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("the first write stores the share");
            assert!(matches!(
                first.as_slice(),
                [crate::protocol::DeRecEvent::ShareStored { .. }]
            ));

            rig.shares.set_refusal(Some(Refusal::TooFrequent));

            let second = super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: PARAM_CHANNEL,
                    shared_key: &PARAM_KEY,
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("an identical resend never reaches save, so it cannot be refused");
            assert!(
                matches!(
                    second.as_slice(),
                    [crate::protocol::DeRecEvent::ShareStored { .. }]
                ),
                "the idempotent resend is still acknowledged as stored"
            );
        });
    }

    /// A non-refusal store failure is the router's to answer: `FAIL` with the
    /// generic memo when the library responds, or a token when it does not.
    /// Either way exactly one response leaves, and the store's error text
    /// stays local.
    #[test]
    fn helper_save_backend_error_is_answered_through_the_router() {
        for respond in [true, false] {
            run_async(async move {
                use crate::protocol::obligation::{GENERIC_FAILURE_MEMO, Obligation, settle};

                let request = param_request(b"a payload whose save backend fails outright");
                let lf = LocalFixture::new(PARAM_SECRET_ID);
                let mut rig = param_rig();
                rig.shares.set_backend_error(true);
                let action = crate::protocol::PendingAction::request(
                    PARAM_CHANNEL,
                    1,
                    crate::protocol::ChannelRequest::StoreShare(request.clone()),
                )
                .sealed_with(&PARAM_KEY);
                let obligation =
                    Obligation::for_action(&action, lf.local().policy).expect("a request");

                let outcome = super::accept(
                    &mut rig.stores(),
                    &lf.local(),
                    &Exchange {
                        channel_id: PARAM_CHANNEL,
                        shared_key: &PARAM_KEY,
                        trace_id: 1,
                        obligation: Some(&obligation),
                    },
                    &request,
                )
                .await;
                assert!(
                    matches!(
                        outcome,
                        Err(crate::Error::ShareStore(ShareStoreError::Backend(_)))
                    ),
                    "the flow itself leaves the failure to the router"
                );
                assert!(rig.transport.sent_envelopes().is_empty());

                // The paired channel's key is in the secret store. The token
                // carries none: `reject` reads it from there.
                crate::protocol::DeRecSecretStore::save(
                    &mut rig.secrets,
                    PARAM_SECRET_ID,
                    PARAM_CHANNEL,
                    crate::protocol::SecretValue::SharedKey(PARAM_KEY),
                )
                .await
                .expect("seed the channel key");
                let events = settle(
                    &mut rig.stores(),
                    &lf.local(),
                    &obligation,
                    respond,
                    outcome,
                )
                .await;
                let token = match events.as_slice() {
                    [
                        crate::protocol::DeRecEvent::RequestFailed {
                            responded, action, ..
                        },
                    ] => {
                        assert_eq!(*responded, respond);
                        action.clone()
                    }
                    other => panic!("expected one RequestFailed, got {other:?}"),
                };
                if let Some(token) = token {
                    assert!(rig.transport.sent_envelopes().is_empty());
                    let (
                        channel_id,
                        trace_id,
                        crate::protocol::Action::RespondToFailure { reply, request },
                    ) = token.into_parts()
                    else {
                        panic!("a RespondToFailure token");
                    };
                    let answer = Obligation::for_failure(
                        channel_id,
                        trace_id,
                        &reply,
                        request,
                        lf.local().policy,
                    );
                    crate::protocol::obligation::respond_to_failure(
                        &mut rig.stores(),
                        &lf.local(),
                        &answer,
                        StatusEnum::Fail,
                        GENERIC_FAILURE_MEMO,
                    )
                    .await
                    .expect("the token answers the request");
                }

                let sent = rig.transport.sent_envelopes();
                assert_eq!(sent.len(), 1, "exactly one response");
                let response = decode_store_share_response(&sent[0], &PARAM_KEY);
                let result = response.result.expect("a result");
                assert_eq!(result.status, StatusEnum::Fail as i32);
                assert_eq!(result.memo, GENERIC_FAILURE_MEMO);
            });
        }
    }
}

/// A Helper refuses a share that does not decode or does not verify before
/// anything is stored or removed, and answers the Owner whatever
/// `auto_respond_on_failure` says.
#[cfg(test)]
mod invalid_share_tests {
    use crate::derec_message::DeRecMessageBuilder;
    use crate::primitives::sharing::request;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::context::Exchange;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, LocalFixture, RecordingTransport, StoreRig, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue, Share};
    use crate::protocol::{
        AutoAcceptPolicy, DeRecChannelStore, DeRecEvent, DeRecProtocol, DeRecSecretStore,
        DeRecShareStore,
    };
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{
        CommittedDeRecShare, MessageBody, Protocol, SenderKind, StatusEnum,
        StoreShareRequestMessage, TransportProtocol,
    };
    use prost::Message as _;

    pub(super) const HELPER_SECRET_ID: u64 = 0x4E;
    const OWNER_SECRET_ID: u64 = 0xA11CE;
    pub(super) const CHANNEL: ChannelId = ChannelId(61);
    pub(super) const KEY: SharedKey = SharedKey::new([7u8; 32]);

    /// The version already held before the invalid request arrives.
    const HELD: u32 = 1;
    /// The version the invalid request claims; its `keepVersion` is `0`, so
    /// honouring it would remove [`HELD`].
    pub(super) const INCOMING: u32 = 2;

    pub(super) type Helper = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        RecordingTransport,
    >;

    pub(super) fn owner_endpoint() -> TransportProtocol {
        TransportProtocol {
            uri: "https://owner.example".to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    pub(super) fn valid_request(version: u32, keep_version: u32) -> StoreShareRequestMessage {
        let split = request::split(
            &[(CHANNEL, 1), (ChannelId(62), 1)],
            OWNER_SECRET_ID,
            version,
            format!("secret at version {version}").as_bytes(),
            2,
        )
        .expect("split secret");
        let committed = split.shares.get(&CHANNEL).expect("share for channel");
        let produced = request::produce(
            CHANNEL,
            version,
            OWNER_SECRET_ID,
            committed,
            keep_version,
            "",
            &KEY,
            std::slice::from_ref(&owner_endpoint()),
        )
        .expect("produce request");
        request::extract(&produced.envelope, &KEY)
            .expect("extract request")
            .request
    }

    /// `share` holds bytes that are not a `CommittedDeRecShare`.
    pub(super) fn not_a_share() -> StoreShareRequestMessage {
        let mut request = valid_request(INCOMING, 0);
        request.share = b"not a share".to_vec();
        request
    }

    /// A well-formed `CommittedDeRecShare` whose Merkle path does not lead
    /// to its commitment.
    fn broken_merkle_path() -> StoreShareRequestMessage {
        let mut request = valid_request(INCOMING, 0);
        let mut committed =
            CommittedDeRecShare::decode(request.share.as_slice()).expect("valid committed share");
        committed.merkle_path[0].hash[0] ^= 0xFF;
        request.share = committed.encode_to_vec();
        request
    }

    /// A valid share whose `keepVersion` names the version being shared.
    fn keep_version_not_below_version() -> StoreShareRequestMessage {
        let mut request = valid_request(INCOMING, 0);
        request.keep_version = INCOMING;
        request
    }

    pub(super) fn envelope(request: &StoreShareRequestMessage) -> Vec<u8> {
        DeRecMessageBuilder::channel()
            .channel_id(CHANNEL)
            .timestamp(request.timestamp.expect("request timestamp"))
            .message_body(MessageBody::StoreShareRequest(request.clone()))
            .encrypt(&KEY)
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    async fn seed(channels: &mut InMemChannelStore, shares: &mut InMemShareStore) {
        channels
            .save(
                HELPER_SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![owner_endpoint()],
                    communication_info: std::collections::HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: crate::utils::now_secs(),
                    peer_role: SenderKind::Owner,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        shares
            .save(
                HELPER_SECRET_ID,
                CHANNEL,
                Share {
                    secret_id: OWNER_SECRET_ID,
                    version: HELD,
                    bytes: valid_request(HELD, 0).encode_to_vec(),
                    subshares: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed held share");
    }

    pub(super) async fn helper(
        policy: AutoAcceptPolicy,
        auto_respond: bool,
    ) -> (Helper, InMemShareStore, RecordingTransport) {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        let mut shares = InMemShareStore::default();
        let transport = RecordingTransport::default();
        seed(&mut channels, &mut shares).await;
        secrets
            .save(HELPER_SECRET_ID, CHANNEL, SecretValue::SharedKey(KEY))
            .await
            .expect("seed shared key");

        let protocol = DeRecProtocolBuilder::new(HELPER_SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(shares.clone())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(transport.clone())
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://helper.example.com"])
            .with_threshold(2)
            .with_auto_accept(policy)
            .with_auto_respond_on_failure(auto_respond)
            .build()
            .expect("test protocol builds");
        (protocol, shares, transport)
    }

    fn refusals(events: &[DeRecEvent]) -> Vec<(ChannelId, u32, i32, String)> {
        events
            .iter()
            .filter_map(|e| match e {
                DeRecEvent::ShareRefused {
                    channel_id,
                    version,
                    status,
                    memo,
                } => Some((*channel_id, *version, *status, memo.clone())),
                _ => None,
            })
            .collect()
    }

    /// Nothing at [`INCOMING`] is stored, [`HELD`] survives, and exactly one
    /// response carrying `expected` reached the Owner, which reads it as
    /// `ShareRejected` with the refusal's status and memo.
    async fn assert_refused_without_side_effects(
        events: &[DeRecEvent],
        shares: &InMemShareStore,
        transport: &RecordingTransport,
        expected: StatusEnum,
    ) {
        let refused = refusals(events);
        assert_eq!(refused.len(), 1, "exactly one ShareRefused, got {events:?}");
        let (channel_id, version, status, memo) = refused[0].clone();
        assert_eq!(channel_id, CHANNEL);
        assert_eq!(version, INCOMING);
        assert_eq!(status, expected as i32, "got {events:?}");
        assert!(
            !events.iter().any(|e| matches!(
                e,
                DeRecEvent::ActionRequired { .. }
                    | DeRecEvent::AutoAccepted { .. }
                    | DeRecEvent::ShareStored { .. }
            )),
            "a refused share never reaches the application's decision, got {events:?}"
        );

        assert!(
            shares
                .load(HELPER_SECRET_ID, CHANNEL, &[INCOMING])
                .await
                .expect("load")
                .is_empty(),
            "the refused share is not stored"
        );
        let held: Vec<u32> = shares
            .load(HELPER_SECRET_ID, CHANNEL, &[])
            .await
            .expect("load")
            .iter()
            .map(|s| s.version)
            .collect();
        assert_eq!(held, vec![HELD], "the refused keepVersion prunes nothing");

        let sent = transport.sent_envelopes();
        assert_eq!(sent.len(), 1, "exactly one response is sent to the owner");
        let envelope = derec_proto::DeRecMessage::decode(sent[0].as_slice()).expect("envelope");
        let MessageBody::StoreShareResponse(response) =
            crate::derec_message::extract_inner_message(&envelope.message, &KEY).expect("decrypt")
        else {
            panic!("expected a StoreShareResponse");
        };
        let result = response.result.clone().expect("result");
        assert_eq!(result.status, expected as i32);
        assert_eq!(result.memo, memo);
        assert_eq!(response.version, INCOMING);

        let owner_events =
            super::on_response(CHANNEL, &response).expect("owner processes the rejection");
        assert!(
            matches!(
                owner_events.as_slice(),
                [DeRecEvent::ShareRejected { status, memo: owner_memo, .. }]
                    if *status == expected as i32 && *owner_memo == memo
            ),
            "the owner sees the same status and memo, got {owner_events:?}"
        );
    }

    async fn process_refuses(
        policy: AutoAcceptPolicy,
        auto_respond: bool,
        request: StoreShareRequestMessage,
        expected: StatusEnum,
    ) {
        let (mut protocol, shares, transport) = helper(policy, auto_respond).await;
        let events = protocol
            .process(&envelope(&request))
            .await
            .expect("an invalid share is refused, not raised as an error");
        assert_refused_without_side_effects(&events, &shares, &transport, expected).await;
    }

    #[test]
    fn auto_accepting_helper_refuses_bytes_that_are_not_a_share() {
        for auto_respond in [true, false] {
            run_async(process_refuses(
                AutoAcceptPolicy::all(),
                auto_respond,
                not_a_share(),
                StatusEnum::FormatError,
            ));
        }
    }

    #[test]
    fn auto_accepting_helper_refuses_a_broken_merkle_path() {
        for auto_respond in [true, false] {
            run_async(process_refuses(
                AutoAcceptPolicy::all(),
                auto_respond,
                broken_merkle_path(),
                StatusEnum::VerificationFailed,
            ));
        }
    }

    #[test]
    fn auto_accepting_helper_refuses_a_keep_version_not_below_version() {
        for auto_respond in [true, false] {
            run_async(process_refuses(
                AutoAcceptPolicy::all(),
                auto_respond,
                keep_version_not_below_version(),
                StatusEnum::FormatError,
            ));
        }
    }

    #[test]
    fn manual_helper_refuses_an_invalid_share_instead_of_asking() {
        for (request, expected) in [
            (not_a_share(), StatusEnum::FormatError),
            (broken_merkle_path(), StatusEnum::VerificationFailed),
            (keep_version_not_below_version(), StatusEnum::FormatError),
        ] {
            run_async(process_refuses(
                AutoAcceptPolicy::default(),
                false,
                request,
                expected,
            ));
        }
    }

    /// `accept` validates on its own, so a `ChannelRequest::StoreShare`
    /// carrying an invalid share cannot store it either.
    #[test]
    fn accept_refuses_an_invalid_share_without_storing() {
        for (request, expected) in [
            (not_a_share(), StatusEnum::FormatError),
            (broken_merkle_path(), StatusEnum::VerificationFailed),
            (keep_version_not_below_version(), StatusEnum::FormatError),
        ] {
            run_async(async {
                let mut rig = StoreRig::with_transport(RecordingTransport::default());
                seed(&mut rig.channels, &mut rig.shares).await;
                let lf = LocalFixture::new(HELPER_SECRET_ID);

                let events = super::accept(
                    &mut rig.stores(),
                    &lf.local(),
                    &Exchange {
                        channel_id: CHANNEL,
                        shared_key: &KEY,
                        trace_id: 1,
                        obligation: None,
                    },
                    &request,
                )
                .await
                .expect("an invalid share is refused, not raised as an error");

                assert_refused_without_side_effects(&events, &rig.shares, &rig.transport, expected)
                    .await;
            });
        }
    }
}

/// A [`PendingAction`](crate::protocol::PendingAction) carries no key: `accept`
/// and `reject` answer under the key the secret store holds for the action's
/// channel when they run.
#[cfg(test)]
mod action_key_tests {
    use super::invalid_share_tests::{
        CHANNEL, HELPER_SECRET_ID, INCOMING, KEY, envelope, helper, valid_request,
    };
    use crate::protocol::tests::run_async;
    use crate::protocol::{
        AutoAcceptPolicy, DeRecEvent, DeRecSecretStore as _, DeRecShareStore as _, PendingAction,
        SecretKind,
    };
    use derec_proto::{MessageBody, StatusEnum};
    use prost::Message as _;

    /// The `StoreShare` action the helper raises for a valid share.
    fn store_share_action(events: Vec<DeRecEvent>) -> PendingAction {
        events
            .into_iter()
            .find_map(|e| match e {
                DeRecEvent::ActionRequired { action, .. } => Some(action),
                _ => None,
            })
            .expect("a valid share raises ActionRequired")
    }

    /// An action is answered under the key stored for its channel.
    #[test]
    fn an_action_is_answered_under_the_stored_key() {
        run_async(async {
            let (mut protocol, _, transport) = helper(AutoAcceptPolicy::default(), false).await;
            let events = protocol
                .process(&envelope(&valid_request(INCOMING, 0)))
                .await
                .expect("the share is handled");
            let action = store_share_action(events);

            let events = protocol.accept(action).await.expect("accept runs");

            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
                "got {events:?}"
            );
            let sent = transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "one response is sent");
            let response = derec_proto::DeRecMessage::decode(sent[0].as_slice()).expect("envelope");
            assert!(matches!(
                crate::derec_message::extract_inner_message(&response.message, &KEY)
                    .expect("the response decrypts under the stored key"),
                MessageBody::StoreShareResponse(_)
            ));
        });
    }

    /// An action whose channel no longer has a key can be neither checked nor
    /// answered: `accept` and `reject` fail, and nothing is stored or sent.
    #[test]
    fn an_action_whose_channel_lost_its_key_is_not_answered() {
        run_async(async {
            let (mut protocol, shares, transport) = helper(AutoAcceptPolicy::default(), true).await;
            let events = protocol
                .process(&envelope(&valid_request(INCOMING, 0)))
                .await
                .expect("the share is handled");
            let action = store_share_action(events);
            protocol
                .secret_store
                .remove(HELPER_SECRET_ID, CHANNEL, SecretKind::SharedKey)
                .await
                .expect("remove the key");

            let accepted = protocol.accept(action.clone()).await;

            assert!(
                matches!(accepted, Err(crate::Error::InvalidInput(_))),
                "got {accepted:?}"
            );
            assert!(transport.sent_envelopes().is_empty(), "nothing is sent");
            assert!(
                shares
                    .load(HELPER_SECRET_ID, CHANNEL, &[INCOMING])
                    .await
                    .expect("load")
                    .is_empty(),
                "the share is not stored"
            );

            let rejected = protocol.reject(action, StatusEnum::Rejected, "no").await;
            assert!(rejected.is_err(), "got {rejected:?}");
            assert!(transport.sent_envelopes().is_empty(), "nothing is sent");
        });
    }
}

/// A token is refused unless it is the one `process` issued: edited,
/// extended, or moved to another channel, its seal no longer verifies, and
/// nothing is stored or sent.
#[cfg(all(test, feature = "ffi"))]
mod sealed_token_tests {
    use super::invalid_share_tests::{
        CHANNEL, HELPER_SECRET_ID, INCOMING, envelope, helper, valid_request,
    };
    use crate::protocol::events::seal::SEAL_LEN;
    use crate::protocol::tests::{InMemShareStore, RecordingTransport, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
    use crate::protocol::utils::pending_action_wire::{deserialize, serialize};
    use crate::protocol::{
        AutoAcceptPolicy, DeRecChannelStore as _, DeRecEvent, DeRecSecretStore as _,
        DeRecShareStore as _, SecretValue,
    };
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{StatusEnum, StoreShareRequestMessage};
    use prost::Message as _;

    /// The error a token whose seal does not verify is refused with.
    const ALTERED: &str = "the action was altered, or was not raised on this channel";

    /// Where a channel request's body starts: tag, channel id, trace id, seal.
    const BODY_AT: usize = 1 + 8 + 8 + SEAL_LEN;

    /// The token `process` issues for a valid share.
    async fn issued_token() -> (
        super::invalid_share_tests::Helper,
        InMemShareStore,
        RecordingTransport,
        Vec<u8>,
    ) {
        let (mut protocol, shares, transport) = helper(AutoAcceptPolicy::default(), false).await;
        let events = protocol
            .process(&envelope(&valid_request(INCOMING, 0)))
            .await
            .expect("the share is handled");
        let action = events
            .into_iter()
            .find_map(|e| match e {
                DeRecEvent::ActionRequired { action, .. } => Some(action),
                _ => None,
            })
            .expect("a valid share raises ActionRequired");
        let token = serialize(action).expect("the action serializes");
        (protocol, shares, transport, token)
    }

    /// The token with its request replaced by `edit` of it; the seal is kept.
    fn edited(token: &[u8], edit: impl FnOnce(&mut StoreShareRequestMessage)) -> Vec<u8> {
        let mut request =
            StoreShareRequestMessage::decode(&token[BODY_AT..]).expect("the token's request");
        edit(&mut request);
        let mut out = token[..BODY_AT].to_vec();
        out.extend_from_slice(&request.encode_to_vec());
        out
    }

    /// `accept` and `reject` refuse `token`, and nothing is stored or sent.
    async fn assert_refused(token: &[u8]) {
        let (mut protocol, shares, transport, _) = issued_token().await;
        let action = deserialize(token).expect("the bytes decode");

        let accepted = protocol.accept(action.clone()).await;
        assert!(
            matches!(accepted, Err(crate::Error::InvalidInput(ALTERED))),
            "got {accepted:?}"
        );
        let rejected = protocol.reject(action, StatusEnum::Rejected, "no").await;
        assert!(
            matches!(rejected, Err(crate::Error::InvalidInput(ALTERED))),
            "got {rejected:?}"
        );

        assert!(transport.sent_envelopes().is_empty(), "nothing is sent");
        assert!(
            shares
                .load(HELPER_SECRET_ID, CHANNEL, &[INCOMING])
                .await
                .expect("load")
                .is_empty(),
            "nothing is stored"
        );
    }

    /// The token `process` issued is accepted after a round trip through its
    /// bytes.
    #[test]
    fn an_issued_token_is_accepted() {
        run_async(async {
            let (mut protocol, _, transport, token) = issued_token().await;
            let events = protocol
                .accept(deserialize(&token).expect("the token decodes"))
                .await
                .expect("the issued token is accepted");
            assert!(
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
                "got {events:?}"
            );
            assert_eq!(transport.sent_envelopes().len(), 1);
        });
    }

    /// A request edited after `process`, here only its `keepVersion`, which
    /// decides what the helper deletes, is refused.
    #[test]
    fn an_edited_token_is_refused() {
        run_async(async {
            let (_, _, _, token) = issued_token().await;
            assert_refused(&edited(&token, |request| request.keep_version = 1)).await;
        });
    }

    /// Protobuf bytes appended to the request, which a decoder would read as
    /// an overriding `keepVersion`, are refused.
    #[test]
    fn an_extended_token_is_refused() {
        run_async(async {
            let (_, _, _, mut token) = issued_token().await;
            token.extend_from_slice(
                &StoreShareRequestMessage {
                    keep_version: 1,
                    ..Default::default()
                }
                .encode_to_vec(),
            );
            assert_refused(&token).await;
        });
    }

    /// A token moved to another paired channel is refused, though that
    /// channel would otherwise answer it.
    #[test]
    fn a_token_moved_to_another_channel_is_refused() {
        run_async(async {
            let (_, _, _, mut token) = issued_token().await;
            let other = ChannelId(62);
            token[1..9].copy_from_slice(&other.0.to_be_bytes());

            let (mut protocol, _, transport, _) = issued_token().await;
            protocol
                .channel_store
                .save(
                    HELPER_SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: other,
                        transports: vec![super::invalid_share_tests::owner_endpoint()],
                        communication_info: std::collections::HashMap::new(),
                        status: ChannelStatus::Paired,
                        created_at: crate::utils::now_secs(),
                        peer_role: derec_proto::SenderKind::Owner,
                        weight: 1,
                    }),
                )
                .await
                .expect("seed the other channel");
            protocol
                .secret_store
                .save(
                    HELPER_SECRET_ID,
                    other,
                    SecretValue::SharedKey(SharedKey::new([0x62; 32])),
                )
                .await
                .expect("seed the other channel's key");
            let accepted = protocol
                .accept(deserialize(&token).expect("the bytes decode"))
                .await;
            assert!(
                matches!(accepted, Err(crate::Error::InvalidInput(ALTERED))),
                "got {accepted:?}"
            );
            assert!(transport.sent_envelopes().is_empty(), "nothing is sent");
        });
    }
}

/// `reply_to` names where the courtesy failure response is sent, but it is
/// peer-supplied and must pass the same transport policy as any other
/// peer-supplied endpoint — including when it is the refusal itself that
/// triggers the response.
#[cfg(test)]
mod refused_reply_to_tests {
    use super::invalid_share_tests::{envelope, helper, not_a_share, owner_endpoint};
    use crate::protocol::AutoAcceptPolicy;
    use crate::protocol::tests::run_async;
    use derec_proto::{Protocol, StoreShareRequestMessage, TransportProtocol};

    /// A plaintext, non-loopback endpoint: refused by the default transport
    /// policy whether it is a peer's advertised endpoint or a one-shot
    /// `reply_to`.
    fn refused_reply_to() -> TransportProtocol {
        TransportProtocol {
            uri: "http://owner.example".to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    fn with_reply_to(
        mut request: StoreShareRequestMessage,
        reply_to: TransportProtocol,
    ) -> StoreShareRequestMessage {
        request.reply_to_transports = vec![reply_to];
        request
    }

    /// The refused `reply_to` must never receive the failure response; it
    /// is sent to the channel's recorded endpoint instead, exactly as if
    /// the peer had named no `reply_to` at all.
    #[test]
    fn refused_reply_to_falls_back_to_the_recorded_endpoint() {
        run_async(async {
            let request = with_reply_to(not_a_share(), refused_reply_to());
            let (mut protocol, _shares, transport) = helper(AutoAcceptPolicy::all(), true).await;

            let _ = protocol.process(&envelope(&request)).await;

            assert_eq!(
                transport.sent_uris(),
                vec![owner_endpoint().uri],
                "the refused reply_to must never be used as a destination"
            );
        });
    }

    /// A `reply_to` the policy accepts is still honoured: the fix must not
    /// stop answering a well-behaved peer at the address it asked for.
    #[test]
    fn accepted_reply_to_is_still_used() {
        run_async(async {
            let accepted_reply_to = TransportProtocol {
                uri: "https://owner-reply.example".to_owned(),
                protocol: Protocol::Https as i32,
            };
            let request = with_reply_to(not_a_share(), accepted_reply_to.clone());
            let (mut protocol, _shares, transport) = helper(AutoAcceptPolicy::all(), true).await;

            let _ = protocol.process(&envelope(&request)).await;

            assert_eq!(
                transport.sent_uris(),
                vec![accepted_reply_to.uri],
                "an accepted reply_to is used, not the recorded endpoint"
            );
        });
    }
}

/// The Owner side of `keepVersion`: which version the Helpers are told to
/// keep, and the end-to-end effect once they apply it.
#[cfg(test)]
mod owner_keep_version_tests {
    use crate::primitives::sharing::request;
    use crate::protocol::context::{Exchange, Round};
    use crate::protocol::tests::{LocalFixture, StoreRig, run_async};
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, SecretValue, UserSecret, UserSecrets,
    };
    use crate::protocol::{DeRecChannelStore, DeRecSecretStore, DeRecUserSecretStore};
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{Protocol, SenderKind, TransportProtocol};

    const OWNER_SECRET_ID: u64 = 0x0E;
    const HELPER_SECRET_ID: u64 = 0x4E;
    const HELPERS: [u64; 3] = [21, 22, 23];
    const THRESHOLD: usize = 2;

    fn endpoint(channel: u64) -> TransportProtocol {
        TransportProtocol {
            uri: format!("https://helper-{channel}.example"),
            protocol: Protocol::Https as i32,
        }
    }

    fn key_of(channel: u64) -> SharedKey {
        crate::types::SharedKey::new([channel as u8; 32])
    }

    fn channel_of(endpoints: &[TransportProtocol]) -> u64 {
        HELPERS
            .into_iter()
            .find(|c| endpoints[0] == endpoint(*c))
            .expect("every send goes to a seeded helper")
    }

    async fn owner_rig() -> StoreRig {
        let mut rig = StoreRig::new();
        for channel in HELPERS {
            rig.channels
                .save(
                    OWNER_SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(channel),
                        transports: vec![endpoint(channel)],
                        communication_info: std::collections::HashMap::new(),
                        status: ChannelStatus::Paired,
                        created_at: 0,
                        peer_role: SenderKind::Helper,
                        weight: 1,
                    }),
                )
                .await
                .expect("seed helper channel");
            rig.secrets
                .save(
                    OWNER_SECRET_ID,
                    ChannelId(channel),
                    SecretValue::SharedKey(key_of(channel)),
                )
                .await
                .expect("seed helper key");
        }
        rig
    }

    async fn seed_latest_version(rig: &mut StoreRig, version: u32) {
        rig.user_secrets
            .save_latest(
                OWNER_SECRET_ID,
                UserSecrets {
                    version,
                    secrets: Vec::new(),
                    description: None,
                    author_replica_id: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed snapshot");
    }

    async fn publish(rig: &mut StoreRig) -> u32 {
        try_publish(rig)
            .await
            .expect("sharing round runs")
            .expect("helpers are paired")
            .version
    }

    async fn try_publish(rig: &mut StoreRig) -> crate::Result<Option<super::SharingRoundResult>> {
        let lf = LocalFixture::new(OWNER_SECRET_ID);
        rig.transport.sent.lock().unwrap().clear();
        super::start(
            &mut rig.stores(),
            &lf.local(),
            vec![UserSecret {
                id: b"id".to_vec(),
                name: "name".to_owned(),
                data: b"data".to_vec(),
            }],
            None,
            Some(&std::collections::HashMap::new()),
            None,
            THRESHOLD,
            None,
            &Round {
                reply_to: &[],
                trace_id: 1,
            },
        )
        .await
    }

    fn sent_requests(rig: &StoreRig) -> Vec<(u64, derec_proto::StoreShareRequestMessage)> {
        rig.transport
            .sent
            .lock()
            .unwrap()
            .iter()
            .map(|(endpoints, envelope)| {
                let channel = channel_of(endpoints);
                let request = request::extract(envelope, &key_of(channel))
                    .expect("extract store-share request")
                    .request;
                (channel, request)
            })
            .collect()
    }

    fn sent_keep_versions(rig: &StoreRig) -> Vec<u32> {
        let requests = sent_requests(rig);
        assert_eq!(requests.len(), HELPERS.len(), "one request per helper");
        requests.into_iter().map(|(_, r)| r.keep_version).collect()
    }

    /// The application's `keepVersion` reaches every Helper in the round;
    /// the store is asked once, not once per Helper.
    #[test]
    fn the_app_keep_version_goes_to_every_helper() {
        run_async(async {
            let mut rig = owner_rig().await;
            seed_latest_version(&mut rig, 4).await;
            *rig.shares.keep.lock().unwrap() = Some(2);

            assert_eq!(publish(&mut rig).await, 5);

            assert_eq!(sent_keep_versions(&rig), vec![2; HELPERS.len()]);
            assert_eq!(
                *rig.shares.keep_version_calls.lock().unwrap(),
                vec![(OWNER_SECRET_ID, 5)]
            );
        });
    }

    /// `0` goes out as is: the Helpers keep only the version being sent.
    #[test]
    fn a_zero_keep_version_goes_to_every_helper() {
        run_async(async {
            let mut rig = owner_rig().await;
            seed_latest_version(&mut rig, 4).await;
            *rig.shares.keep.lock().unwrap() = Some(0);

            publish(&mut rig).await;

            assert_eq!(sent_keep_versions(&rig), vec![0; HELPERS.len()]);
        });
    }

    /// A `keepVersion` equal to or above the version being sent fails the
    /// round before any Helper is written to, and leaves the snapshot as it
    /// was.
    #[test]
    fn a_keep_version_not_below_the_new_version_fails_the_round() {
        for keep_version in [5, 6] {
            run_async(async {
                let mut rig = owner_rig().await;
                seed_latest_version(&mut rig, 4).await;
                *rig.shares.keep.lock().unwrap() = Some(keep_version);

                let err = try_publish(&mut rig)
                    .await
                    .err()
                    .expect("the round is refused");

                assert!(
                    matches!(
                        err,
                        crate::Error::Sharing(
                            crate::primitives::sharing::SharingError::InvalidKeepVersion {
                                keep_version: k,
                                version: 5,
                            }
                        ) if k == keep_version
                    ),
                    "{err:?}"
                );
                assert!(rig.transport.sent.lock().unwrap().is_empty());
                let snapshot = rig
                    .user_secrets
                    .load_latest(OWNER_SECRET_ID)
                    .await
                    .unwrap()
                    .expect("the seeded snapshot is kept");
                assert_eq!(snapshot.version, 4);
            });
        }
    }

    async fn helper_rig(channel: u64) -> StoreRig {
        let mut rig = StoreRig::new();
        rig.channels
            .save(
                HELPER_SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: ChannelId(channel),
                    transports: vec![TransportProtocol {
                        uri: "https://owner.example".to_owned(),
                        protocol: Protocol::Https as i32,
                    }],
                    communication_info: std::collections::HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    peer_role: SenderKind::Owner,
                    weight: 1,
                }),
            )
            .await
            .expect("seed owner channel");
        rig
    }

    async fn deliver(owner: &StoreRig, helpers: &mut [(u64, StoreRig)]) {
        deliver_to(owner, helpers, &HELPERS).await;
    }

    async fn deliver_to(owner: &StoreRig, helpers: &mut [(u64, StoreRig)], reached: &[u64]) {
        let lf = LocalFixture::new(HELPER_SECRET_ID);
        for (channel, request) in sent_requests(owner) {
            if !reached.contains(&channel) {
                continue;
            }
            let (_, rig) = helpers
                .iter_mut()
                .find(|(c, _)| *c == channel)
                .expect("helper rig");
            super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id: ChannelId(channel),
                    shared_key: &key_of(channel),
                    trace_id: 1,
                    obligation: None,
                },
                &request,
            )
            .await
            .expect("helper accepts the share");
        }
    }

    fn held_versions(rig: &StoreRig) -> Vec<u32> {
        let mut versions: Vec<u32> = rig
            .shares
            .data
            .lock()
            .unwrap()
            .keys()
            .map(|(_, _, v)| *v)
            .collect();
        versions.sort_unstable();
        versions
    }

    /// v2 reaches only one Helper and never commits, so the owner keeps v1
    /// when it sends v3. Once the v3 round lands, every Helper holds exactly
    /// v1 and v3: the one that took v2 drops it, and the others had nothing
    /// to drop.
    #[test]
    fn helpers_keep_the_new_version_and_the_last_valid_one() {
        run_async(async {
            let mut owner = owner_rig().await;
            let mut helpers = Vec::new();
            for channel in HELPERS {
                helpers.push((channel, helper_rig(channel).await));
            }

            *owner.shares.keep.lock().unwrap() = Some(0);
            assert_eq!(publish(&mut owner).await, 1);
            deliver(&owner, &mut helpers).await;

            *owner.shares.keep.lock().unwrap() = Some(1);
            assert_eq!(publish(&mut owner).await, 2);
            deliver_to(&owner, &mut helpers, &HELPERS[..1]).await;
            assert_eq!(held_versions(&helpers[0].1), vec![1, 2]);
            assert_eq!(held_versions(&helpers[1].1), vec![1]);

            assert_eq!(publish(&mut owner).await, 3);
            deliver(&owner, &mut helpers).await;

            for (channel, rig) in &helpers {
                assert_eq!(
                    held_versions(rig),
                    vec![1, 3],
                    "helper on channel {channel} must hold the new and the kept version"
                );
            }
        });
    }

    /// Whatever the owner answers, a Helper never holds more than two
    /// versions: five rounds that each keep the version before leave the
    /// last two.
    #[test]
    fn a_helper_holds_at_most_two_versions() {
        run_async(async {
            let mut owner = owner_rig().await;
            let mut helpers = Vec::new();
            for channel in HELPERS {
                helpers.push((channel, helper_rig(channel).await));
            }

            for _ in 0..5 {
                publish(&mut owner).await;
                deliver(&owner, &mut helpers).await;
            }

            for (channel, rig) in &helpers {
                assert_eq!(
                    held_versions(rig),
                    vec![4, 5],
                    "helper on channel {channel} must hold the last two versions"
                );
            }
        });
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
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::StoreRig;
    use crate::protocol::tests::{InMemChannelStore, InMemSecretStore, run_async};
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
            .save(
                SECRET_ID,
                GROUP_CHANNEL,
                SecretValue::SharedKey(crate::types::SharedKey::new([0x42; 32])),
            )
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed_member(
                &mut rig.channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_group_key(&mut rig.secrets).await;

            let (_, targets) = super::load_all_paired_targets(&mut rig.stores(), &lf.local())
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            for (id, role) in [
                (1001, ReplicaRole::Source),
                (1002, ReplicaRole::Destination),
                (1003, ReplicaRole::Destination),
                (1004, ReplicaRole::Destination),
            ] {
                seed_member(&mut rig.channels, id, role, "https://peer").await;
            }
            seed_group_key(&mut rig.secrets).await;

            let (_, targets) = super::load_all_paired_targets(&mut rig.stores(), &lf.local())
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
            let lf = LocalFixture::with_replica(0, 1002);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed_group_key(&mut rig.secrets).await;

            // Publishing as the destination, not the source.
            let roster = rig
                .channels
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                .await
                .expect("roster");
            let group_channel =
                super::group_channel_of(&lf.local(), &roster).expect("group channel resolves");
            assert_eq!(group_channel, Some(GROUP_CHANNEL));

            let secret = super::build_secret(
                &[],
                &roster,
                Vec::new(),
                group_channel,
                Some(&crate::types::SharedKey::new([0x42; 32])),
                None,
            )
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

    /// T6 — a joiner mid-handover does not redefine the group channel.
    ///
    /// The admitter's own row names the group; a member still on its ephemeral
    /// pairing channel must not drag the group id onto that channel, which
    /// would strand every other member.
    #[test]
    fn a_joiner_on_an_ephemeral_channel_does_not_move_the_group() {
        run_async(async {
            let lf = LocalFixture::with_replica(0, 1002);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed_member(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            // A joiner admitted since the last round, still on C₂.
            rig.channels
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

            let roster = rig
                .channels
                .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
                .await
                .expect("roster");
            let group_channel = super::group_channel_of(&lf.local(), &roster)
                .expect("group channel resolves")
                .expect("a group exists");
            assert_eq!(
                group_channel, GROUP_CHANNEL,
                "the group id comes from this device's own row, not the joiner's"
            );
        });
    }

    const HELPER_CHANNEL: ChannelId = ChannelId(7001);

    /// Seed one paired helper channel plus a snapshot, so a catch-up has
    /// something to serve.
    async fn seed_helper_and_snapshot(
        rig: &mut StoreRig,
        version: u32,
        tracked_bytes: Option<Vec<u8>>,
    ) {
        use crate::protocol::types::{HelperChannel, Share, UserSecrets};
        use crate::protocol::{DeRecSecretStore, DeRecShareStore, DeRecUserSecretStore};

        rig.channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: HELPER_CHANNEL,
                    transports: vec![endpoint("https://helper")],
                    communication_info: std::collections::HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    peer_role: derec_proto::SenderKind::Helper,
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper");
        rig.secrets
            .save(
                SECRET_ID,
                HELPER_CHANNEL,
                SecretValue::SharedKey(crate::types::SharedKey::new([0xAA; 32])),
            )
            .await
            .expect("seed helper key");
        if let Some(bytes) = tracked_bytes {
            rig.shares
                .save(
                    SECRET_ID,
                    HELPER_CHANNEL,
                    Share {
                        secret_id: SECRET_ID,
                        version,
                        bytes,
                        subshares: None,
                        threshold: None,
                    },
                )
                .await
                .expect("seed tracking share");
        }
        rig.user_secrets
            .save_latest(
                SECRET_ID,
                UserSecrets {
                    version,
                    secrets: Vec::new(),
                    description: None,
                    author_replica_id: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed snapshot");
    }

    /// The roster a catch-up payload carries. A payload always comes from a
    /// group member, so one is always present — and `hydrate` commits the
    /// snapshot only for a payload that names a group.
    fn payload_roster() -> crate::protocol::types::Replicas {
        crate::protocol::types::Replicas {
            channel_id: GROUP_CHANNEL.0,
            members: vec![crate::protocol::types::ReplicaInfo {
                replica_id: 1002,
                transports: vec![endpoint("https://self")],
                role: ReplicaRole::Destination as i32,
                communication_info: std::collections::HashMap::new(),
            }],
            shared_key: vec![0x42; 32],
        }
    }

    /// A catch-up answer carries the share map, so the asker ends up as able
    /// to verify as the answerer is.
    ///
    /// The map used to be withheld on the pulled path on the grounds that
    /// shares are derived per publishing round — which left a member that
    /// became current by pulling permanently unable to check its helpers,
    /// while one that received a push could.
    #[test]
    fn a_catch_up_answer_carries_the_tracked_share_map() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1002, ReplicaRole::Source, "https://self").await;
            seed_group_key(&mut rig.secrets).await;
            seed_helper_and_snapshot(&mut rig, 4, Some(vec![0xDE, 0xAD, 0xBE, 0xEF])).await;

            let payload = super::build_catch_up_payload(&mut rig.stores(), &lf.local())
                .await
                .expect("catch-up payload")
                .expect("a device holding a snapshot must serve one");

            assert_eq!(
                payload.version, 4,
                "the payload must name the version it actually carries"
            );
            assert_eq!(payload.shares.len(), 1, "got {:?}", payload.shares);
            assert_eq!(payload.shares[0].channel_id, HELPER_CHANNEL.0);
            assert_eq!(
                payload.shares[0].committed_share,
                vec![0xDE, 0xAD, 0xBE, 0xEF]
            );
        });
    }

    /// A published roster names, and can reach, every member — the writer
    /// included.
    ///
    /// The writer's stored row is seeded with one endpoint and no
    /// `communication_info`, as rows written before the own row carried them
    /// are: publishing stamps it from the instance, so such a group heals on
    /// its next round.
    #[test]
    fn a_published_roster_describes_every_member_including_the_writer() {
        run_async(async {
            let lf = crate::protocol::tests::LocalFixture {
                own_transports: vec![
                    endpoint("https://self"),
                    TransportProtocol {
                        uri: "grpcs://self:443".to_owned(),
                        protocol: Protocol::Grpc as i32,
                    },
                ],
                communication_info: std::collections::HashMap::from([(
                    "name".to_owned(),
                    "Alice-2".to_owned(),
                )]),
                ..LocalFixture::with_replica(SECRET_ID, 1002)
            };
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1002, ReplicaRole::Source, "https://self").await;
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(1003),
                        transports: vec![endpoint("https://alice-3")],
                        communication_info: std::collections::HashMap::from([(
                            "name".to_owned(),
                            "Alice-3".to_owned(),
                        )]),
                        role: ReplicaRole::Destination,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed peer");
            seed_group_key(&mut rig.secrets).await;
            seed_helper_and_snapshot(&mut rig, 4, None).await;

            let payload = super::build_catch_up_payload(&mut rig.stores(), &lf.local())
                .await
                .expect("catch-up payload")
                .expect("a device holding a snapshot must serve one");

            let members = payload
                .secret
                .and_then(|s| s.replicas)
                .expect("roster is present")
                .members;
            let mut described: Vec<(u64, Option<String>, Vec<String>)> = members
                .iter()
                .map(|m| {
                    (
                        m.replica_id,
                        m.communication_info.get("name").cloned(),
                        m.transports.iter().map(|t| t.uri.clone()).collect(),
                    )
                })
                .collect();
            described.sort();
            assert_eq!(
                described,
                vec![
                    (
                        1002,
                        Some("Alice-2".to_owned()),
                        vec!["https://self".to_owned(), "grpcs://self:443".to_owned()],
                    ),
                    (
                        1003,
                        Some("Alice-3".to_owned()),
                        vec!["https://alice-3".to_owned()],
                    ),
                ],
            );
        });
    }

    /// A member with no tracking rows serves a map-less answer rather than
    /// failing. Below-threshold rounds and recovered devices both land here.
    #[test]
    fn a_catch_up_answer_without_tracked_shares_is_still_served() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();
            seed_member(&mut rig.channels, 1002, ReplicaRole::Source, "https://self").await;
            seed_group_key(&mut rig.secrets).await;
            seed_helper_and_snapshot(&mut rig, 4, None).await;

            let payload = super::build_catch_up_payload(&mut rig.stores(), &lf.local())
                .await
                .expect("catch-up payload")
                .expect("a snapshot is still servable without a share map");

            assert!(payload.shares.is_empty());
            assert_eq!(payload.version, 4);
        });
    }

    /// The asker commits the payload's version, not the one it asked for.
    ///
    /// A catch-up asks for a version and is answered with whatever the peer
    /// holds, so the two routinely differ. Filing the share map under the
    /// requested version would key a helper's share to a version it never
    /// held, and verification would then hash the wrong bytes and report a
    /// healthy helper as corrupt.
    #[test]
    fn a_catch_up_commits_the_payload_version_not_the_requested_one() {
        run_async(async {
            use crate::protocol::DeRecShareStore;

            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            let payload = crate::protocol::types::ReplicaSecretPayload {
                secret: Some(crate::protocol::types::Secret {
                    helpers: vec![crate::protocol::types::HelperInfo {
                        channel_id: HELPER_CHANNEL.0,
                        transports: vec![endpoint("https://helper")],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                        weight: 1,
                    }],
                    secrets: Vec::new(),
                    replicas: Some(payload_roster()),
                    threshold: None,
                }),
                shares: vec![crate::protocol::types::ChannelShare {
                    channel_id: HELPER_CHANNEL.0,
                    committed_share: prost::Message::encode_to_vec(
                        crate::primitives::sharing::request::split(
                            &[(HELPER_CHANNEL, 1), (ChannelId(HELPER_CHANNEL.0 + 1), 1)],
                            SECRET_ID,
                            4,
                            b"the secret",
                            2,
                        )
                        .expect("split secret")
                        .shares
                        .get(&HELPER_CHANNEL)
                        .expect("share for helper"),
                    ),
                }],
                shared_key: Vec::new(),
                version: 4,
                author_replica_id: None,
            };

            // The asker requested 9; the answerer served 4.
            super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
                crate::types::ChannelId(5001),
                1001,
                SECRET_ID,
                9,
                &prost::Message::encode_to_vec(&payload),
            )
            .await
            .expect("catch-up must hydrate");

            let at_served = rig
                .shares
                .load(SECRET_ID, HELPER_CHANNEL, &[4])
                .await
                .expect("load");
            let at_requested = rig
                .shares
                .load(SECRET_ID, HELPER_CHANNEL, &[9])
                .await
                .expect("load");
            assert_eq!(
                at_served.len(),
                1,
                "the map belongs to the version the payload names"
            );
            assert!(
                at_requested.is_empty(),
                "nothing may be filed under the version the asker happened to request"
            );
        });
    }

    /// An answerer predating the payload version falls back to the enclosing
    /// message's version, which is what that writer meant.
    #[test]
    fn a_catch_up_from_an_older_writer_falls_back_to_the_response_version() {
        run_async(async {
            use crate::protocol::DeRecUserSecretStore;

            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            let payload = crate::protocol::types::ReplicaSecretPayload {
                secret: Some(crate::protocol::types::Secret {
                    helpers: Vec::new(),
                    secrets: Vec::new(),
                    replicas: Some(payload_roster()),
                    threshold: None,
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version: 0,
                author_replica_id: None,
            };

            super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
                crate::types::ChannelId(5001),
                1001,
                SECRET_ID,
                9,
                &prost::Message::encode_to_vec(&payload),
            )
            .await
            .expect("catch-up must hydrate");

            let snapshot = rig
                .user_secrets
                .load_latest(SECRET_ID)
                .await
                .expect("load")
                .expect("a snapshot must be committed");
            assert_eq!(
                snapshot.version, 9,
                "an absent payload version means the enclosing one governs"
            );
        });
    }

    #[test]
    fn a_pulled_copy_reports_the_senders_secret_id() {
        run_async(async {
            use crate::protocol::DeRecUserSecretStore;

            const SENDER_SECRET_ID: u64 = 0x5E_4DE4;
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();
            let payload = crate::protocol::types::ReplicaSecretPayload {
                secret: Some(crate::protocol::types::Secret {
                    helpers: Vec::new(),
                    secrets: Vec::new(),
                    replicas: Some(payload_roster()),
                    threshold: None,
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version: 3,
                author_replica_id: None,
            };

            let events = super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
                crate::types::ChannelId(5001),
                1001,
                SENDER_SECRET_ID,
                3,
                &prost::Message::encode_to_vec(&payload),
            )
            .await
            .expect("catch-up must hydrate");

            assert!(
                matches!(
                    events.as_slice(),
                    [crate::protocol::DeRecEvent::ReplicaSecretInstalled { secret_id, .. }] if *secret_id == SENDER_SECRET_ID
                ),
                "a pull must report the sender's secret id, as a push does: {events:?}"
            );
            assert!(
                rig.user_secrets
                    .load_latest(SECRET_ID)
                    .await
                    .expect("load")
                    .is_some(),
                "the copy is still stored under this device's own partition"
            );
        });
    }
}

/// Build the payload a catch-up request is answered with.
///
/// The same composite a publish sends — whole secret, whole roster, and the
/// per-helper share map — so the asker's hydration path is identical whether
/// the state arrived unsolicited or was pulled. `None` when this device holds
/// no snapshot and therefore has nothing to serve.
///
/// # The share map
///
/// Served from this device's own owner-side tracking shares at the snapshot's
/// version, one read per helper: [`crate::protocol::types::Share`] carries no
/// channel id, so a batched `load_many` could not say which helper each row
/// belongs to, and the whole point of the map is that pairing.
///
/// Whatever this device can verify, the asker can verify after hydrating —
/// which is the property that makes a pulled catch-up equivalent to a pushed
/// round. A member that holds no tracking rows (it recovered, or it predates
/// the map being stored) serves none and the asker is no worse off than the
/// answerer.
///
/// This is no wider a disclosure than a publish: the push path has always
/// carried the same share material to the same audience, and every member
/// already holds each helper's `shared_key` through the roster.
///
/// # Proof retention
///
/// The map covers the snapshot's version only, so an asker gains no proof of
/// an earlier version from it. Nor does it lose any: the asker keeps every
/// proof it already holds (see [`replica::hydrate`]).
pub(in crate::protocol) async fn build_catch_up_payload<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
) -> Result<Option<crate::protocol::types::ReplicaSecretPayload>> {
    let secret_id = local.secret_id;
    let Some(snapshot) = stores.user_secrets.load_latest(secret_id).await? else {
        return Ok(None);
    };

    let (helpers, _) = load_all_paired_targets(stores, local).await?;
    let mut roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
    stamp_own_row(local, &mut roster);
    let group_channel = group_channel_of(local, &roster)?;
    let group_key = match group_channel {
        Some(channel_id) => match stores
            .secrets
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
        group_key.as_ref(),
        snapshot.threshold,
    )?;

    let mut shares: Vec<crate::protocol::types::ChannelShare> = Vec::new();
    for (helper, _) in &helpers {
        if let Some(tracked) = stores
            .shares
            .load(secret_id, helper.channel_id, &[snapshot.version])
            .await?
            .into_iter()
            .next()
        {
            shares.push(crate::protocol::types::ChannelShare {
                channel_id: helper.channel_id.0,
                committed_share: tracked.bytes,
            });
        }
    }

    Ok(Some(crate::protocol::types::ReplicaSecretPayload {
        secret: Some(secret),
        shares,
        shared_key: Vec::new(),
        // The asker files the map under this, not under the version it
        // requested — see the field's docs.
        version: snapshot.version,
        author_replica_id: snapshot.author_replica_id,
    }))
}

/// Hydrate a payload pulled by a catch-up, reporting install or update.
///
/// # Which version this commits
///
/// `response_version` is what the enclosing `GetShareResponseMessage`
/// carried, which on this leg is the version the *asker* requested rather
/// than the one the answerer served. The payload's own
/// [`version`](crate::protocol::types::ReplicaSecretPayload::version) is
/// authoritative when present, so the snapshot and the share map are both
/// committed at the version the bytes actually belong to. `response_version`
/// is the fallback for an answerer that predates the field.
///
/// Filing the map under the requested version instead would key a helper's
/// share to a version it never held, and verification would then hash the
/// wrong bytes and report a healthy helper as corrupt.
///
/// # Proof retention
///
/// Hydration adds the proofs of the payload's share map and deletes none:
/// this device keeps every proof it has received, and freeing them is the
/// application's concern (see [`replica::hydrate`]).
///
/// # Refusal
///
/// A payload that does not decode, lacks its `secret`, or fails
/// [`replica::check`] is reported as
/// [`DeRecEvent::ReplicaSecretRefused`] on `arrived_on`, and nothing is
/// written. No answer is sent: this payload is itself the answer to this
/// device's request.
pub(in crate::protocol) async fn hydrate_catch_up<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    arrived_on: ChannelId,
    from_replica_id: u64,
    secret_id: u64,
    response_version: u32,
    payload: &[u8],
) -> Result<Vec<DeRecEvent>> {
    let refused = |version: u32, fault: replica::PayloadFault| {
        Ok(vec![DeRecEvent::ReplicaSecretRefused {
            channel_id: arrived_on,
            from_replica_id,
            secret_id,
            version,
            status: fault.status as i32,
            memo: fault.memo.to_owned(),
        }])
    };

    let Ok(composite) = crate::protocol::types::ReplicaSecretPayload::decode(payload) else {
        return refused(
            response_version,
            replica::PayloadFault::format("catch-up payload is not a valid ReplicaSecretPayload"),
        );
    };
    let version = if composite.version == 0 {
        response_version
    } else {
        composite.version
    };
    let Some(secret) = composite.secret else {
        return refused(
            version,
            replica::PayloadFault::format("catch-up payload missing `secret` field"),
        );
    };

    // A catch-up answer comes from whichever member answered, so only the
    // payload can name the author.
    let author_replica_id = composite.author_replica_id;
    let channel_id = ChannelId(secret.replicas.as_ref().map_or(0, |g| g.channel_id));

    // Checked whole before anything is written, so a served copy is applied
    // in full or not at all.
    let checked = match replica::check(&secret, &composite.shares) {
        Ok(checked) => checked,
        Err(fault) => return refused(version, fault),
    };

    let is_install =
        match replica::arrival(stores, local, version, author_replica_id, &secret.secrets).await? {
            replica::Arrival::Apply { is_install } => is_install,
            replica::Arrival::Resend | replica::Arrival::Stale => {
                return Ok(vec![DeRecEvent::NoOp]);
            }
            replica::Arrival::Conflict {
                held_author_replica_id,
            } => {
                return Ok(vec![DeRecEvent::ReplicaVersionConflict {
                    channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    held_author_replica_id,
                    incoming_author_replica_id: author_replica_id,
                    secret,
                }]);
            }
        };

    replica::hydrate(
        stores,
        local,
        version,
        &checked,
        String::new(),
        author_replica_id,
    )
    .await?;

    let event = if is_install {
        DeRecEvent::ReplicaSecretInstalled {
            channel_id,
            from_replica_id,
            author_replica_id,
            secret_id,
            version,
            secret,
            shares: composite.shares,
        }
    } else {
        DeRecEvent::ReplicaSecretReceived {
            channel_id,
            from_replica_id,
            author_replica_id,
            secret_id,
            version,
            secret,
            shares: composite.shares,
        }
    };
    Ok(vec![event])
}

/// `start(ProtectSecret)` with per-helper weights: validation, the gate, the
/// split, and the `weight` reported on each dispatch event.
#[cfg(test)]
mod weighted_round_tests {
    use crate::primitives::sharing::SharingError;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::context::Round;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, LocalFixture, RecordingTransport, StoreRig, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, SecretValue,
        UserSecret, UserSecrets,
    };
    use crate::protocol::{
        DeRecChannelStore, DeRecEvent, DeRecFlow, DeRecProtocol, DeRecSecretStore,
        DeRecUserSecretStore,
    };
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{Protocol, SenderKind, TransportProtocol};
    use prost::Message as _;
    use std::collections::HashMap;

    const SECRET_ID: u64 = 0x7E16;

    fn endpoint(channel: u64) -> TransportProtocol {
        TransportProtocol {
            uri: format!("https://helper-{channel}.example"),
            protocol: Protocol::Https as i32,
        }
    }

    async fn seed_helper(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        ch: u64,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: ChannelId(ch),
                    transports: vec![endpoint(ch)],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: 0,
                    peer_role: SenderKind::Helper,
                    weight: 1,
                }),
            )
            .await
            .expect("seed helper channel");
        secrets
            .save(
                SECRET_ID,
                ChannelId(ch),
                SecretValue::SharedKey(crate::types::SharedKey::new([ch as u8; 32])),
            )
            .await
            .expect("seed helper key");
    }

    fn secrets() -> Vec<UserSecret> {
        vec![UserSecret {
            id: b"id".to_vec(),
            name: "name".to_owned(),
            data: b"weighted data".to_vec(),
        }]
    }

    async fn seed_latest_version(rig: &mut StoreRig, version: u32) {
        rig.user_secrets
            .save_latest(
                SECRET_ID,
                UserSecrets {
                    version,
                    secrets: Vec::new(),
                    description: None,
                    author_replica_id: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed snapshot");
    }

    async fn latest_version(rig: &StoreRig) -> Option<u32> {
        rig.user_secrets
            .load_latest(SECRET_ID)
            .await
            .expect("load snapshot")
            .map(|s| s.version)
    }

    #[test]
    fn protect_secret_rejects_invalid_weights_even_below_threshold() {
        run_async(async {
            let mut rig = StoreRig::new();
            for ch in [41, 42] {
                seed_helper(&mut rig.channels, &mut rig.secrets, ch).await;
            }
            seed_latest_version(&mut rig, 4).await;
            let lf = LocalFixture::new(SECRET_ID);

            let result = super::start(
                &mut rig.stores(),
                &lf.local(),
                secrets(),
                None,
                Some(&HashMap::from([(ChannelId(999), 2)])),
                None,
                5,
                None,
                &Round {
                    reply_to: &[],
                    trace_id: 1,
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::InvalidWeight {
                        channel_id: 999,
                        weight: 2
                    }))
                ),
                "an unknown channel's weight fails the call, though 2 helpers never reach t = 5"
            );
            assert!(
                rig.transport.sent_envelopes().is_empty(),
                "nothing is dispatched"
            );
            assert_eq!(
                latest_version(&rig).await,
                Some(4),
                "no version is consumed"
            );
        });
    }

    #[test]
    fn protect_secret_rejects_a_replica_channel_weight() {
        run_async(async {
            const GROUP_CHANNEL: u64 = 5101;
            let mut rig = StoreRig::new();
            for ch in [41, 42] {
                seed_helper(&mut rig.channels, &mut rig.secrets, ch).await;
            }
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Replica(ReplicaMember {
                        channel_id: ChannelId(GROUP_CHANNEL),
                        replica_id: ReplicaId(1002),
                        transports: vec![endpoint(GROUP_CHANNEL)],
                        communication_info: HashMap::new(),
                        role: ReplicaRole::Destination,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed member");
            rig.secrets
                .save(
                    SECRET_ID,
                    ChannelId(GROUP_CHANNEL),
                    SecretValue::SharedKey(crate::types::SharedKey::new([0x42; 32])),
                )
                .await
                .expect("seed group key");
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);

            let result = super::start(
                &mut rig.stores(),
                &lf.local(),
                secrets(),
                None,
                Some(&HashMap::from([(ChannelId(GROUP_CHANNEL), 1)])),
                None,
                2,
                None,
                &Round {
                    reply_to: &[],
                    trace_id: 1,
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::InvalidWeight {
                        channel_id: GROUP_CHANNEL,
                        ..
                    }))
                ),
                "a replica channel carries no subshares and cannot be weighted"
            );
            assert!(rig.transport.sent_envelopes().is_empty());
        });
    }

    /// A paired Helper's weight outside `1..threshold` fails the call even
    /// when the round would not split, and entries are judged in ascending
    /// channel-ID order whichever rule they break.
    #[test]
    fn protect_secret_rejects_an_out_of_range_helper_weight_even_below_threshold() {
        run_async(async {
            let mut rig = StoreRig::new();
            for ch in [41, 42] {
                seed_helper(&mut rig.channels, &mut rig.secrets, ch).await;
            }
            seed_latest_version(&mut rig, 4).await;
            let lf = LocalFixture::new(SECRET_ID);

            let result = super::start(
                &mut rig.stores(),
                &lf.local(),
                secrets(),
                None,
                Some(&HashMap::from([(ChannelId(999), 2), (ChannelId(41), 0)])),
                None,
                5,
                None,
                &Round {
                    reply_to: &[],
                    trace_id: 1,
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::InvalidWeight {
                        channel_id: 41,
                        weight: 0
                    }))
                ),
                "the lowest offending channel is reported; got {:?}",
                result.as_ref().map(|_| ())
            );
            assert!(rig.transport.sent_envelopes().is_empty());
            assert_eq!(latest_version(&rig).await, Some(4));
        });
    }

    type TestProtocol = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        RecordingTransport,
    >;

    struct ProtocolRig {
        protocol: TestProtocol,
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
        shares: InMemShareStore,
        user_secrets: InMemUserSecretStore,
    }

    async fn protocol_rig(helpers: &[u64], threshold: usize) -> ProtocolRig {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        let shares = InMemShareStore::default();
        for &ch in helpers {
            seed_helper(&mut channels, &mut secrets, ch).await;
        }
        let user_secrets = InMemUserSecretStore::default();
        let protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(shares.clone())
            .with_secret_store(secrets.clone())
            .with_user_secret_store(user_secrets.clone())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds");
        ProtocolRig {
            protocol,
            channels,
            secrets,
            shares,
            user_secrets,
        }
    }

    /// The same owner restarted with a different threshold: every store is
    /// kept, so the weights recorded under the old threshold are still there.
    fn rebuild_with_threshold(rig: &mut ProtocolRig, threshold: usize) {
        rig.protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(rig.channels.clone())
            .with_share_store(rig.shares.clone())
            .with_secret_store(rig.secrets.clone())
            .with_user_secret_store(rig.user_secrets.clone())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .build()
            .expect("test protocol builds");
    }

    /// The snapshot as an owner upgrading from a build that did not record the
    /// threshold left it: the builder's threshold applies again.
    async fn forget_stored_threshold(rig: &mut ProtocolRig) {
        let mut snapshot = rig
            .user_secrets
            .load_latest(SECRET_ID)
            .await
            .unwrap()
            .expect("a snapshot is stored");
        snapshot.threshold = None;
        rig.user_secrets
            .save_latest(SECRET_ID, snapshot)
            .await
            .unwrap();
    }

    async fn stored_weight(channels: &InMemChannelStore, channel: u64) -> u32 {
        channels
            .load(
                SECRET_ID,
                crate::protocol::types::ChannelQuery::Helper {
                    channel_id: ChannelId(channel),
                },
            )
            .await
            .expect("load helper")
            .and_then(|r| r.as_helper().cloned())
            .expect("helper row present")
            .weight
    }

    fn paired(channel: u64) -> DeRecEvent {
        DeRecEvent::PairingCompleted {
            channel_id: ChannelId(channel),
            pairing_channel_id: ChannelId(channel),
            kind: SenderKind::Owner,
            peer_communication_info: HashMap::new(),
        }
    }

    async fn protect(rig: &mut ProtocolRig, weights: &[(u64, u32)]) -> Vec<DeRecEvent> {
        rig.protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: secrets(),
                description: None,
                weights: weights.iter().map(|&(c, w)| (ChannelId(c), w)).collect(),
                threshold: None,
            })
            .await
            .expect("protect secret")
    }

    /// `(channel, weight)` of every `ProtectSecretStarted`, sorted by channel.
    fn started_weights(events: &[DeRecEvent]) -> Vec<(u64, u32)> {
        let mut out: Vec<(u64, u32)> = events
            .iter()
            .filter_map(|e| match e {
                DeRecEvent::ProtectSecretStarted {
                    channel_id, weight, ..
                } => Some((channel_id.0, *weight)),
                _ => None,
            })
            .collect();
        out.sort_unstable();
        out
    }

    fn stored_subshares(shares: &InMemShareStore, channel: u64, version: u32) -> usize {
        let bytes = shares
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, channel, version))
            .expect("the owner keeps a tracking share per dispatched helper")
            .bytes
            .clone();
        let committed =
            derec_proto::CommittedDeRecShare::decode(bytes.as_slice()).expect("committed share");
        derec_proto::DeRecShare::decode(committed.de_rec_share.as_slice())
            .expect("derec share")
            .subshares
            .len()
    }

    /// The subshare count the library recorded on the owner's row.
    fn recorded_subshares(shares: &InMemShareStore, channel: u64, version: u32) -> Option<u32> {
        shares
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, channel, version))
            .expect("the owner keeps a tracking share per dispatched helper")
            .subshares
    }

    /// Answer the verification challenge sent to `channel` at `version` the
    /// way an honest Helper would, and hand the answer to the owner.
    async fn answer_verification(
        rig: &mut ProtocolRig,
        channel: u64,
        version: u32,
    ) -> Vec<DeRecEvent> {
        use crate::primitives::verification::{request, response};
        let key = crate::types::SharedKey::new([channel as u8; 32]);
        let challenge = rig
            .protocol
            .transport
            .sent_envelopes()
            .iter()
            .rev()
            .find_map(|env| request::extract(env, &key).ok())
            .expect("a challenge was sent to the channel")
            .request;
        let held = rig
            .shares
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, channel, version))
            .expect("the owner's proof")
            .bytes
            .clone();
        let answer =
            response::produce(ChannelId(channel), &challenge, &key, held).expect("answer produced");
        rig.protocol
            .process(&answer.envelope)
            .await
            .expect("the owner processes the answer")
    }

    /// The owner's row records how many subshares each Helper was sent.
    #[test]
    fn the_owner_row_records_each_helpers_subshare_count() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;

            assert_eq!(recorded_subshares(&rig.shares, 51, 1), Some(2));
            assert_eq!(recorded_subshares(&rig.shares, 52, 1), Some(1));
        });
    }

    /// Verifying an older version reports the counts of the round that
    /// published it, not the weights a later round recorded.
    #[test]
    fn verifying_an_older_version_reports_its_own_counts() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            protect(&mut rig, &[(52, 2)]).await;
            assert_eq!(recorded_subshares(&rig.shares, 51, 2), Some(1));
            assert_eq!(recorded_subshares(&rig.shares, 52, 2), Some(2));
            assert_eq!(stored_weight(&rig.channels, 51).await, 1);

            for (channel, expected) in [(51, 2), (52, 1)] {
                rig.protocol
                    .start(DeRecFlow::VerifyShares {
                        secret_id: SECRET_ID,
                        version: 1,
                        target: crate::protocol::types::Target::Single(ChannelId(channel)),
                    })
                    .await
                    .expect("verification starts");
                let events = answer_verification(&mut rig, channel, 1).await;
                let verified: Vec<_> = events
                    .iter()
                    .filter_map(|e| match e {
                        DeRecEvent::ShareVerified {
                            channel_id,
                            version,
                            subshares,
                            ..
                        } => Some((channel_id.0, *version, *subshares)),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    verified,
                    vec![(channel, 1, Some(expected))],
                    "got {events:?}"
                );
            }
        });
    }

    #[test]
    fn weighted_round_splits_with_fewer_helpers_than_threshold() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            let events = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2)]),
                    threshold: None,
                })
                .await
                .expect("a weighted round over 3 subshares meets t = 3");

            assert_eq!(started_weights(&events), vec![(51, 2), (52, 1)]);
            assert_eq!(stored_subshares(&rig.shares, 51, 1), 2);
            assert_eq!(stored_subshares(&rig.shares, 52, 1), 1);
        });
    }

    #[test]
    fn protect_secret_without_weights_is_unchanged() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            let events = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::new(),
                    threshold: None,
                })
                .await
                .expect("an unweighted round runs");

            assert_eq!(events.len(), 3, "one event per helper; got {events:?}");
            assert_eq!(started_weights(&events), vec![(51, 1), (52, 1), (53, 1)]);
            for ch in [51, 52, 53] {
                assert_eq!(stored_subshares(&rig.shares, ch, 1), 1);
            }
        });
    }

    #[test]
    fn unweighted_round_below_threshold_still_does_not_split() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            let events = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::new(),
                    threshold: None,
                })
                .await
                .expect("a round below threshold is not an error");

            assert!(started_weights(&events).is_empty(), "got {events:?}");
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
        });
    }

    #[test]
    fn a_failed_dispatch_reports_the_intended_weight() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets_store = InMemSecretStore::default();
            for ch in [51, 52] {
                seed_helper(&mut channels, &mut secrets_store, ch).await;
            }
            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets_store)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(crate::protocol::tests::FailingTransport)
                .with_state_store(InMemPersistedStateStore::default())
                .with_own_transports(["https://owner.example.com"])
                .with_threshold(3)
                .build()
                .expect("test protocol builds");

            let events = protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2)]),
                    threshold: None,
                })
                .await
                .expect("per-channel failures do not fail the round");

            let mut failed: Vec<(u64, u32)> = events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::ProtectSecretFailed {
                        channel_id, weight, ..
                    } => Some((channel_id.0, *weight)),
                    _ => None,
                })
                .collect();
            failed.sort_unstable();
            assert_eq!(failed, vec![(51, 2), (52, 1)]);
        });
    }

    /// Weights are recorded per Helper: a publish the library starts on its
    /// own reuses them, and a Helper paired since gets one subshare.
    #[test]
    fn a_pairing_publish_reuses_the_stored_weights() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            assert_eq!(stored_weight(&rig.channels, 51).await, 2);
            assert_eq!(stored_weight(&rig.channels, 52).await, 1);

            seed_helper(&mut rig.channels, &mut rig.secrets, 53).await;
            let events = rig
                .protocol
                .maybe_auto_publish(&[paired(53)], &std::collections::HashSet::new())
                .await
                .expect("auto-publish runs");

            assert_eq!(started_weights(&events), vec![(51, 2), (52, 1), (53, 1)]);
            assert_eq!(stored_subshares(&rig.shares, 51, 2), 2);
            assert_eq!(stored_subshares(&rig.shares, 52, 2), 1);
            assert_eq!(stored_subshares(&rig.shares, 53, 2), 1);
            assert_eq!(stored_weight(&rig.channels, 53).await, 1);
        });
    }

    async fn snapshot_version(rig: &ProtocolRig) -> Option<u32> {
        rig.user_secrets
            .load_latest(SECRET_ID)
            .await
            .unwrap()
            .map(|s| s.version)
    }

    async fn seed_pending_helper(rig: &mut ProtocolRig, channel: u64) {
        rig.channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: ChannelId(channel),
                    transports: vec![endpoint(channel)],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Pending,
                    created_at: 0,
                    peer_role: SenderKind::Helper,
                    weight: 1,
                }),
            )
            .await
            .expect("seed pending helper");
        rig.secrets
            .save(
                SECRET_ID,
                ChannelId(channel),
                SecretValue::SharedKey(crate::types::SharedKey::new([channel as u8; 32])),
            )
            .await
            .expect("seed helper key");
    }

    /// Pairing a Helper that leaves the Helpers below the threshold publishes
    /// nothing and consumes no version; the pairing that reaches it publishes
    /// the stored snapshot to every Helper.
    #[test]
    fn a_pairing_below_the_threshold_publishes_nothing() {
        run_async(async {
            let mut rig = protocol_rig(&[51], 3).await;
            protect(&mut rig, &[]).await;
            assert_eq!(snapshot_version(&rig).await, Some(1));

            seed_helper(&mut rig.channels, &mut rig.secrets, 52).await;
            let events = rig
                .protocol
                .maybe_auto_publish(&[paired(52)], &std::collections::HashSet::new())
                .await
                .expect("auto-publish runs");
            assert!(events.is_empty(), "got {events:?}");
            assert_eq!(snapshot_version(&rig).await, Some(1));

            seed_helper(&mut rig.channels, &mut rig.secrets, 53).await;
            let events = rig
                .protocol
                .maybe_auto_publish(&[paired(53)], &std::collections::HashSet::new())
                .await
                .expect("auto-publish runs");
            assert_eq!(started_weights(&events), vec![(51, 1), (52, 1), (53, 1)]);
            assert_eq!(snapshot_version(&rig).await, Some(2));
        });
    }

    /// The fingerprint promotion follows the same rule as pairing.
    #[test]
    fn a_fingerprint_promotion_below_the_threshold_publishes_nothing() {
        run_async(async {
            let mut rig = protocol_rig(&[51], 3).await;
            protect(&mut rig, &[]).await;

            seed_pending_helper(&mut rig, 52).await;
            let fingerprint = rig.protocol.get_fingerprint(ChannelId(52)).await.unwrap();
            rig.protocol
                .verify_fingerprint(ChannelId(52), &fingerprint)
                .await
                .expect("verify_fingerprint");
            assert_eq!(snapshot_version(&rig).await, Some(1));

            seed_pending_helper(&mut rig, 53).await;
            let fingerprint = rig.protocol.get_fingerprint(ChannelId(53)).await.unwrap();
            rig.protocol
                .verify_fingerprint(ChannelId(53), &fingerprint)
                .await
                .expect("verify_fingerprint");
            assert_eq!(snapshot_version(&rig).await, Some(2));
            for ch in [51, 52, 53] {
                assert_eq!(stored_subshares(&rig.shares, ch, 2), 1);
            }
        });
    }

    /// An explicit map is the full assignment: a Helper it does not name goes
    /// back to one subshare, and an empty map resets every Helper.
    #[test]
    fn an_explicit_map_replaces_every_stored_weight() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 3).await;
            protect(&mut rig, &[(51, 2), (52, 2)]).await;

            let events = protect(&mut rig, &[(52, 2)]).await;
            assert_eq!(started_weights(&events), vec![(51, 1), (52, 2), (53, 1)]);
            assert_eq!(stored_subshares(&rig.shares, 51, 2), 1);
            assert_eq!(stored_weight(&rig.channels, 51).await, 1);
            assert_eq!(stored_weight(&rig.channels, 52).await, 2);

            let events = protect(&mut rig, &[]).await;
            assert_eq!(started_weights(&events), vec![(51, 1), (52, 1), (53, 1)]);
            for ch in [51, 52, 53] {
                assert_eq!(stored_weight(&rig.channels, ch).await, 1);
                assert_eq!(stored_subshares(&rig.shares, ch, 3), 1);
            }
        });
    }

    fn assert_invalid_weight(result: crate::Result<Vec<DeRecEvent>>, channel_id: u64, weight: u32) {
        assert!(
            matches!(
                result,
                Err(crate::Error::Sharing(SharingError::InvalidWeight { channel_id: c, weight: w }))
                    if c == channel_id && w == weight
            ),
            "expected InvalidWeight {{ {channel_id}, {weight} }}; got {:?}",
            result.as_ref().map(|_| ())
        );
    }

    /// The owner passes back the weights it recorded with an explicit, lower
    /// threshold under which one of them would let a Helper recover alone.
    /// The round fails before anything is written or sent.
    #[test]
    fn an_explicit_weight_invalid_under_a_lowered_threshold_fails_the_round() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 3).await;
            protect(&mut rig, &[(51, 2), (52, 2)]).await;
            rig.protocol.transport.clear();

            let result = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2), (ChannelId(52), 2)]),
                    threshold: Some(2),
                })
                .await;

            assert_invalid_weight(result, 51, 2);
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
            assert_eq!(
                rig.protocol
                    .user_secret_store
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .map(|s| s.version),
                Some(1)
            );
            assert_eq!(
                stored_weight(&rig.channels, 51).await,
                2,
                "nothing is written"
            );
        });
    }

    /// The same lowered threshold fails a publish the library starts on its
    /// own: the stored weight is validated like an explicit one, and the
    /// error is what the pairing hook returns to `process` and `accept`.
    #[test]
    fn a_stored_weight_invalid_under_a_lowered_threshold_fails_the_pairing_publish() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            forget_stored_threshold(&mut rig).await;
            rebuild_with_threshold(&mut rig, 2);
            seed_helper(&mut rig.channels, &mut rig.secrets, 53).await;

            let result = rig
                .protocol
                .maybe_auto_publish(&[paired(53)], &std::collections::HashSet::new())
                .await;

            assert_invalid_weight(result, 51, 2);
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
            assert_eq!(
                rig.protocol
                    .user_secret_store
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .map(|s| s.version),
                Some(1)
            );
            assert_eq!(stored_weight(&rig.channels, 51).await, 2);
        });
    }

    /// The fingerprint hook fails the same way. The channel is already
    /// promoted when the publish runs, so the promotion stands and
    /// `verify_fingerprint` returns the publish's error.
    #[test]
    fn a_stored_weight_invalid_under_a_lowered_threshold_fails_the_fingerprint_publish() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            forget_stored_threshold(&mut rig).await;
            rebuild_with_threshold(&mut rig, 2);
            rig.channels
                .save(
                    SECRET_ID,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id: ChannelId(53),
                        transports: vec![endpoint(53)],
                        communication_info: HashMap::new(),
                        status: ChannelStatus::Pending,
                        created_at: 0,
                        peer_role: SenderKind::Helper,
                        weight: 1,
                    }),
                )
                .await
                .expect("seed pending helper");
            rig.secrets
                .save(
                    SECRET_ID,
                    ChannelId(53),
                    SecretValue::SharedKey(crate::types::SharedKey::new([53; 32])),
                )
                .await
                .expect("seed helper key");
            let fingerprint = rig
                .protocol
                .get_fingerprint(ChannelId(53))
                .await
                .expect("fingerprint");

            let result = rig
                .protocol
                .verify_fingerprint(ChannelId(53), &fingerprint)
                .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::InvalidWeight {
                        channel_id: 51,
                        weight: 2
                    }))
                ),
                "got {result:?}"
            );
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
            assert_eq!(
                rig.protocol
                    .user_secret_store
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .map(|s| s.version),
                Some(1)
            );
            let promoted = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Helper {
                        channel_id: ChannelId(53),
                    },
                )
                .await
                .expect("load helper")
                .and_then(|r| r.as_helper().cloned())
                .expect("helper row present");
            assert_eq!(
                promoted.status,
                ChannelStatus::Paired,
                "the promotion stands"
            );

            let retry = rig
                .protocol
                .verify_fingerprint(ChannelId(53), &fingerprint)
                .await;
            assert!(matches!(retry, Ok(())), "got {retry:?}");
            assert!(
                rig.protocol.transport.sent_envelopes().is_empty(),
                "a retry does not publish"
            );
        });
    }

    /// The pairing hook driven through `process`: the owner's PairResponse
    /// completes the pairing, and the publish after it fails on a stored
    /// weight the lowered threshold no longer allows. `process` returns the
    /// error together with the pairing's events, and nothing is sent.
    #[test]
    fn a_pair_response_whose_publish_fails_returns_its_events_with_the_error() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            forget_stored_threshold(&mut rig).await;
            rebuild_with_threshold(&mut rig, 2);

            let helper_transport = RecordingTransport::default();
            let mut helper = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(helper_transport.clone())
                .with_state_store(InMemPersistedStateStore::default())
                .with_own_transports(["https://helper-53.example"])
                .with_threshold(2)
                .with_auto_accept(crate::protocol::AutoAcceptPolicy {
                    pairing: true,
                    ..Default::default()
                })
                .build()
                .expect("helper builds");
            let contact = helper
                .create_contact(
                    Some(ChannelId(9393)),
                    derec_proto::ContactMode::InlineKeys,
                    None,
                )
                .await
                .expect("contact");
            rig.protocol
                .start(DeRecFlow::Pairing {
                    kind: SenderKind::Owner,
                    contact,
                    peer_communication_info: HashMap::new(),
                })
                .await
                .expect("pairing starts");
            let request = rig
                .protocol
                .transport
                .sent_envelopes()
                .pop()
                .expect("the pair request");
            helper.process(&request).await.expect("the helper answers");
            let response = helper_transport
                .sent_envelopes()
                .pop()
                .expect("the pair response");
            let sent_before = rig.protocol.transport.sent_envelopes().len();

            let err = rig
                .protocol
                .process(&response)
                .await
                .expect_err("the publish after pairing fails");

            assert!(
                matches!(
                    err.source,
                    crate::Error::Sharing(SharingError::InvalidWeight {
                        channel_id: 51,
                        weight: 2
                    })
                ),
                "got {:?}",
                err.source
            );
            assert!(
                err.events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::PairingCompleted { .. })),
                "the pairing is reported: {:?}",
                err.events
            );
            assert!(
                !err.events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::ProtectSecretStarted { .. })),
                "no publish is reported: {:?}",
                err.events
            );
            assert_eq!(
                rig.protocol.transport.sent_envelopes().len(),
                sent_before,
                "nothing is sent"
            );
            assert_eq!(
                rig.protocol
                    .user_secret_store
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .map(|s| s.version),
                Some(1),
                "no version is consumed"
            );
        });
    }

    /// Two devices of one replica group, and a third recovering from the
    /// roster: the weights the source chose travel in the roster, hydration
    /// and restore write them back into each device's channels, and the next
    /// publish each device starts on its own gives every Helper the same
    /// number of subshares the source did.
    #[test]
    fn hydration_and_restore_carry_the_weights_into_the_next_publish() {
        run_async(async {
            const GROUP: u64 = 5101;
            const SOURCE: u64 = 1001;
            const DESTINATION: u64 = 1002;
            const GROUP_KEY: crate::types::SharedKey = crate::types::SharedKey::new([0x42; 32]);

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
                            channel_id: ChannelId(GROUP),
                            replica_id: ReplicaId(replica_id),
                            transports: vec![TransportProtocol {
                                uri: uri.to_owned(),
                                protocol: Protocol::Https as i32,
                            }],
                            communication_info: HashMap::new(),
                            role,
                            status: ChannelStatus::Paired,
                            created_at: 0,
                        }),
                    )
                    .await
                    .expect("seed member");
            }

            struct Device {
                protocol: TestProtocol,
                channels: InMemChannelStore,
                secrets: InMemSecretStore,
                shares: InMemShareStore,
                transport: RecordingTransport,
            }

            async fn device(replica_id: Option<u64>, own_uri: &str) -> Device {
                let mut channels = InMemChannelStore::default();
                let mut secrets = InMemSecretStore::default();
                if replica_id.is_some() {
                    seed_member(&mut channels, SOURCE, ReplicaRole::Source, "https://source").await;
                    seed_member(
                        &mut channels,
                        DESTINATION,
                        ReplicaRole::Destination,
                        "https://destination",
                    )
                    .await;
                    secrets
                        .save(
                            SECRET_ID,
                            ChannelId(GROUP),
                            SecretValue::SharedKey(GROUP_KEY),
                        )
                        .await
                        .expect("seed group key");
                }
                let shares = InMemShareStore::default();
                let transport = RecordingTransport::default();
                let mut builder = DeRecProtocolBuilder::new(SECRET_ID)
                    .with_channel_store(channels.clone())
                    .with_share_store(shares.clone())
                    .with_secret_store(secrets.clone())
                    .with_user_secret_store(InMemUserSecretStore::default())
                    .with_transport(transport.clone())
                    .with_state_store(InMemPersistedStateStore::default())
                    .with_own_transports([own_uri])
                    .with_threshold(3);
                if let Some(id) = replica_id {
                    builder = builder.with_replica_id(id);
                }
                Device {
                    protocol: builder.build().expect("test protocol builds"),
                    channels,
                    secrets,
                    shares,
                    transport,
                }
            }

            let mut source = device(Some(SOURCE), "https://source").await;
            for ch in [51, 52, 53] {
                seed_helper(&mut source.channels, &mut source.secrets, ch).await;
            }
            source
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2)]),
                    threshold: None,
                })
                .await
                .expect("the source publishes");
            let source_counts: Vec<usize> = [51, 52, 53]
                .iter()
                .map(|&ch| stored_subshares(&source.shares, ch, 1))
                .collect();
            assert_eq!(source_counts, vec![2, 1, 1]);

            let push = source
                .transport
                .sent
                .lock()
                .unwrap()
                .iter()
                .find(|(to, _)| to.iter().any(|t| t.uri == "https://destination"))
                .map(|(_, envelope)| envelope.clone())
                .expect("the source pushes the roster to its destination");

            let mut destination = device(Some(DESTINATION), "https://destination").await;
            let events = destination
                .protocol
                .process(&push)
                .await
                .expect("the destination installs the roster");
            let roster = events
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ReplicaSecretInstalled { secret, .. } => Some(secret.clone()),
                    _ => None,
                })
                .expect("the roster is installed");
            assert_eq!(stored_weight(&destination.channels, 51).await, 2);

            seed_helper(&mut destination.channels, &mut destination.secrets, 54).await;
            let events = destination
                .protocol
                .maybe_auto_publish(&[paired(54)], &std::collections::HashSet::new())
                .await
                .expect("the destination publishes");
            assert_eq!(
                started_weights(&events),
                vec![(51, 2), (52, 1), (53, 1), (54, 1)]
            );
            let destination_counts: Vec<usize> = [51, 52, 53]
                .iter()
                .map(|&ch| stored_subshares(&destination.shares, ch, 2))
                .collect();
            assert_eq!(destination_counts, source_counts);

            // Restore reads the roster through its recoverable encoding, as a
            // recovered secret arrives.
            let mut recovered = crate::protocol::types::Secret::decode(&roster.encode())
                .expect("the roster decodes");
            recovered.replicas = None;
            let mut restored = device(None, "https://restored").await;
            restored
                .protocol
                .restore(&recovered, 1)
                .await
                .expect("restore succeeds");
            assert_eq!(stored_weight(&restored.channels, 51).await, 2);

            seed_helper(&mut restored.channels, &mut restored.secrets, 54).await;
            let events = restored
                .protocol
                .maybe_auto_publish(&[paired(54)], &std::collections::HashSet::new())
                .await
                .expect("the restored device publishes");
            assert_eq!(
                started_weights(&events),
                vec![(51, 2), (52, 1), (53, 1), (54, 1)]
            );
            let restored_counts: Vec<usize> = [51, 52, 53]
                .iter()
                .map(|&ch| stored_subshares(&restored.shares, ch, 2))
                .collect();
            assert_eq!(restored_counts, source_counts);
        });
    }

    /// The cap is checked against the round's total subshares before a version
    /// is chosen, so an over-cap round fails without dispatching anything or
    /// consuming a version.
    #[test]
    fn protect_secret_over_the_subshare_cap_fails_before_dispatch() {
        run_async(async {
            let mut rig = StoreRig::new();
            for ch in [41, 42] {
                seed_helper(&mut rig.channels, &mut rig.secrets, ch).await;
            }
            seed_latest_version(&mut rig, 4).await;
            let lf = LocalFixture::new(SECRET_ID);

            let result = super::start(
                &mut rig.stores(),
                &lf.local(),
                secrets(),
                None,
                Some(&HashMap::from([(ChannelId(41), 2), (ChannelId(42), 2)])),
                None,
                3,
                Some(3),
                &Round {
                    reply_to: &[],
                    trace_id: 1,
                },
            )
            .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::TooManySubshares {
                        subshares: 4,
                        max: 3
                    }))
                ),
                "4 subshares exceed a cap of 3; got {:?}",
                result.as_ref().map(|_| ())
            );
            assert!(
                rig.transport.sent_envelopes().is_empty(),
                "nothing is dispatched"
            );
            assert_eq!(
                latest_version(&rig).await,
                Some(4),
                "no version is consumed"
            );
        });
    }

    async fn protocol_rig_with_cap(
        helpers: &[u64],
        threshold: usize,
        max_subshares: u64,
    ) -> ProtocolRig {
        let mut channels = InMemChannelStore::default();
        let mut secrets = InMemSecretStore::default();
        let shares = InMemShareStore::default();
        for &ch in helpers {
            seed_helper(&mut channels, &mut secrets, ch).await;
        }
        let user_secrets = InMemUserSecretStore::default();
        let protocol = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels.clone())
            .with_share_store(shares.clone())
            .with_secret_store(secrets.clone())
            .with_user_secret_store(user_secrets.clone())
            .with_transport(RecordingTransport::default())
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(threshold)
            .with_max_subshares(max_subshares)
            .build()
            .expect("test protocol builds");
        ProtocolRig {
            protocol,
            channels,
            secrets,
            shares,
            user_secrets,
        }
    }

    #[test]
    fn protect_secret_at_the_subshare_cap_runs() {
        run_async(async {
            let mut rig = protocol_rig_with_cap(&[51, 52], 3, 3).await;
            let events = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2)]),
                    threshold: None,
                })
                .await
                .expect("3 subshares fit a cap of 3");

            assert_eq!(started_weights(&events), vec![(51, 2), (52, 1)]);
            assert_eq!(stored_subshares(&rig.shares, 51, 1), 2);
        });
    }

    #[test]
    fn protect_secret_over_the_subshare_cap_surfaces_from_start() {
        run_async(async {
            let mut rig = protocol_rig_with_cap(&[51, 52], 3, 3).await;
            let result = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2), (ChannelId(52), 2)]),
                    threshold: None,
                })
                .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::TooManySubshares {
                        subshares: 4,
                        max: 3
                    }))
                ),
                "got {:?}",
                result.as_ref().map(|_| ())
            );
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
        });
    }

    /// With no cap configured a round of any total runs as before.
    #[test]
    fn protect_secret_without_a_cap_accepts_any_total() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 3).await;
            let events = rig
                .protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::from([(ChannelId(51), 2), (ChannelId(52), 2)]),
                    threshold: None,
                })
                .await
                .expect("no cap is configured");

            assert_eq!(started_weights(&events), vec![(51, 2), (52, 2)]);
        });
    }

    /// A library-initiated publish totals the stored weights — here one per
    /// Helper — so pairing a third Helper exceeds the cap and the publish
    /// fails the same way `start` does, and nothing reaches any Helper.
    #[test]
    fn pair_completion_auto_publish_respects_the_subshare_cap() {
        run_async(async {
            let mut rig = protocol_rig_with_cap(&[51, 52], 2, 2).await;
            rig.protocol
                .start(DeRecFlow::ProtectSecret {
                    secrets: secrets(),
                    description: None,
                    weights: HashMap::new(),
                    threshold: None,
                })
                .await
                .expect("2 subshares fit a cap of 2");
            let sent_before = rig.protocol.transport.sent_envelopes().len();

            seed_helper(&mut rig.channels, &mut rig.secrets, 53).await;
            let result = rig
                .protocol
                .maybe_auto_publish(
                    &[DeRecEvent::PairingCompleted {
                        channel_id: ChannelId(53),
                        pairing_channel_id: ChannelId(53),
                        kind: SenderKind::Owner,
                        peer_communication_info: HashMap::new(),
                    }],
                    &std::collections::HashSet::new(),
                )
                .await;

            assert!(
                matches!(
                    result,
                    Err(crate::Error::Sharing(SharingError::TooManySubshares {
                        subshares: 3,
                        max: 2
                    }))
                ),
                "got {:?}",
                result.as_ref().map(|_| ())
            );
            assert_eq!(
                rig.protocol.transport.sent_envelopes().len(),
                sent_before,
                "nothing is dispatched"
            );
            assert_eq!(
                rig.protocol
                    .user_secret_store
                    .load_latest(SECRET_ID)
                    .await
                    .expect("load snapshot")
                    .map(|s| s.version),
                Some(1),
                "no version is consumed"
            );
        });
    }

    async fn stored_threshold(rig: &ProtocolRig) -> Option<u32> {
        rig.user_secrets
            .load_latest(SECRET_ID)
            .await
            .unwrap()
            .and_then(|s| s.threshold)
    }

    /// The threshold the library recorded on the owner's row.
    fn recorded_threshold(shares: &InMemShareStore, channel: u64, version: u32) -> Option<u32> {
        shares
            .data
            .lock()
            .unwrap()
            .get(&(SECRET_ID, channel, version))
            .expect("the owner keeps a tracking share per dispatched helper")
            .threshold
    }

    async fn round_threshold(rig: &ProtocolRig, version: u32) -> Option<u32> {
        use crate::protocol::DeRecStateStore as _;
        match rig
            .protocol
            .state_store
            .load(
                SECRET_ID,
                crate::protocol::types::StateKey::SharingRound { version },
            )
            .await
            .unwrap()
        {
            Some(crate::protocol::types::StateItem::SharingRound(round)) => round.threshold,
            other => panic!("no open round at v{version}: {other:?}"),
        }
    }

    async fn protect_at(
        rig: &mut ProtocolRig,
        weights: &[(u64, u32)],
        threshold: Option<u32>,
    ) -> crate::Result<Vec<DeRecEvent>> {
        rig.protocol
            .start(DeRecFlow::ProtectSecret {
                secrets: secrets(),
                description: None,
                weights: weights.iter().map(|&(c, w)| (ChannelId(c), w)).collect(),
                threshold,
            })
            .await
    }

    fn helper_dispatches(events: &[DeRecEvent]) -> usize {
        events
            .iter()
            .filter(|e| matches!(e, DeRecEvent::ProtectSecretStarted { .. }))
            .count()
    }

    /// With nothing stored, the builder's threshold is the round's, and it is
    /// recorded on the snapshot, the owner rows and the round.
    #[test]
    fn with_nothing_stored_the_builders_threshold_is_used_and_recorded() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            protect(&mut rig, &[]).await;

            assert_eq!(stored_threshold(&rig).await, Some(2));
            for ch in [51, 52, 53] {
                assert_eq!(recorded_threshold(&rig.shares, ch, 1), Some(2));
            }
            assert_eq!(round_threshold(&rig, 1).await, Some(2));
        });
    }

    /// An explicit threshold beats the builder's and becomes the stored one.
    /// A later publish passing none keeps it, and so does the publish the
    /// library starts after a pairing. A new explicit threshold replaces it.
    #[test]
    fn an_explicit_threshold_is_stored_and_reused_until_replaced() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            protect_at(&mut rig, &[], Some(3)).await.expect("v1");
            assert_eq!(stored_threshold(&rig).await, Some(3));
            assert_eq!(recorded_threshold(&rig.shares, 51, 1), Some(3));
            assert_eq!(round_threshold(&rig, 1).await, Some(3));

            protect(&mut rig, &[]).await;
            assert_eq!(recorded_threshold(&rig.shares, 51, 2), Some(3));

            seed_helper(&mut rig.channels, &mut rig.secrets, 54).await;
            rig.protocol
                .maybe_auto_publish(&[paired(54)], &std::collections::HashSet::new())
                .await
                .expect("the pairing publish runs");
            for ch in [51, 52, 53, 54] {
                assert_eq!(recorded_threshold(&rig.shares, ch, 3), Some(3));
            }
            assert_eq!(stored_threshold(&rig).await, Some(3));

            protect_at(&mut rig, &[], Some(4)).await.expect("v4");
            assert_eq!(stored_threshold(&rig).await, Some(4));
            for ch in [51, 52, 53, 54] {
                assert_eq!(recorded_threshold(&rig.shares, ch, 4), Some(4));
            }
        });
    }

    /// The split itself follows the stored threshold, not the builder's: three
    /// weight-1 Helpers reach a builder threshold of 2 but not a stored 4, so
    /// no share is sent until a fourth Helper pairs.
    #[test]
    fn the_split_follows_the_stored_threshold() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            let events = protect_at(&mut rig, &[], Some(4)).await.expect("v1");
            assert_eq!(helper_dispatches(&events), 0, "3 subshares miss t = 4");
            assert_eq!(stored_threshold(&rig).await, Some(4));

            let events = protect(&mut rig, &[]).await;
            assert_eq!(helper_dispatches(&events), 0, "the stored t = 4 applies");

            seed_helper(&mut rig.channels, &mut rig.secrets, 54).await;
            let events = rig
                .protocol
                .maybe_auto_publish(&[paired(54)], &std::collections::HashSet::new())
                .await
                .expect("the pairing publish runs");
            assert_eq!(helper_dispatches(&events), 4, "4 subshares reach t = 4");
            assert_eq!(recorded_threshold(&rig.shares, 54, 3), Some(4));
        });
    }

    /// A stored threshold survives a restart with a different builder value.
    #[test]
    fn a_stored_threshold_beats_the_builders() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 3).await;
            protect(&mut rig, &[]).await;
            rebuild_with_threshold(&mut rig, 2);

            protect(&mut rig, &[]).await;
            assert_eq!(recorded_threshold(&rig.shares, 51, 2), Some(3));
            assert_eq!(stored_threshold(&rig).await, Some(3));
        });
    }

    /// An explicit threshold that a passed weight is not below fails the
    /// round before anything is written or sent.
    #[test]
    fn an_explicit_threshold_at_or_below_a_weight_fails_with_nothing_written() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 3).await;
            protect(&mut rig, &[(51, 2)]).await;
            rig.protocol.transport.clear();

            let result = protect_at(&mut rig, &[(51, 2)], Some(2)).await;

            assert_invalid_weight(result, 51, 2);
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
            assert_eq!(stored_threshold(&rig).await, Some(3));
            assert_eq!(
                rig.user_secrets
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .map(|s| s.version),
                Some(1)
            );
            assert_eq!(stored_weight(&rig.channels, 51).await, 2);
        });
    }

    /// An explicit threshold above the subshare cap fails the round before
    /// anything is written or sent.
    #[test]
    fn an_explicit_threshold_above_the_subshare_cap_fails_with_nothing_written() {
        run_async(async {
            let mut rig = protocol_rig_with_cap(&[51, 52, 53], 2, 3).await;
            let result = protect_at(&mut rig, &[], Some(4)).await;

            assert!(
                matches!(result, Err(crate::Error::InvalidInput(_))),
                "got {:?}",
                result.as_ref().map(|_| ())
            );
            assert!(rig.protocol.transport.sent_envelopes().is_empty());
            assert!(
                rig.user_secrets
                    .load_latest(SECRET_ID)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    /// An explicit threshold below 2 fails the round before anything is
    /// written or sent.
    #[test]
    fn an_explicit_threshold_below_two_fails_with_nothing_written() {
        run_async(async {
            for t in [0, 1] {
                let mut rig = protocol_rig(&[51, 52, 53], 2).await;
                let result = protect_at(&mut rig, &[], Some(t)).await;

                assert!(
                    matches!(
                        result,
                        Err(crate::Error::Sharing(SharingError::InvalidThreshold { threshold, .. }))
                            if threshold == t as usize
                    ),
                    "t = {t}: got {:?}",
                    result.as_ref().map(|_| ())
                );
                assert!(rig.protocol.transport.sent_envelopes().is_empty());
                assert!(
                    rig.user_secrets
                        .load_latest(SECRET_ID)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
        });
    }

    /// A round that changes the threshold and fails after validation, before
    /// its own snapshot is saved, leaves the previous snapshot as it was: a
    /// snapshot never records a threshold its version was not split with.
    #[test]
    fn a_threshold_changing_round_that_fails_leaves_the_previous_snapshot_unchanged() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            protect_at(&mut rig, &[], Some(2)).await.expect("v1");
            *rig.shares.keep_version_error.lock().unwrap() = true;

            let result = protect_at(&mut rig, &[], Some(3)).await;

            assert!(result.is_err(), "the keep-version read fails the round");
            let snapshot = rig
                .user_secrets
                .load_latest(SECRET_ID)
                .await
                .unwrap()
                .expect("v1's snapshot is kept");
            assert_eq!(snapshot.version, 1);
            assert_eq!(snapshot.threshold, Some(2));
        });
    }

    /// The owner rows carry the threshold; the Helpers' rows carry none.
    /// Verifying v1 after v2 changed the threshold reports v1's.
    #[test]
    fn verifying_an_older_version_reports_its_own_threshold() {
        run_async(async {
            let mut rig = protocol_rig(&[51, 52, 53], 2).await;
            protect_at(&mut rig, &[], Some(3)).await.expect("v1");
            protect_at(&mut rig, &[], Some(2)).await.expect("v2");
            assert_eq!(recorded_threshold(&rig.shares, 51, 2), Some(2));

            rig.protocol
                .start(DeRecFlow::VerifyShares {
                    secret_id: SECRET_ID,
                    version: 1,
                    target: crate::protocol::types::Target::Single(ChannelId(51)),
                })
                .await
                .expect("verification starts");
            let events = answer_verification(&mut rig, 51, 1).await;
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ShareVerified {
                        version: 1,
                        threshold: Some(3),
                        ..
                    }
                )),
                "got {events:?}"
            );
        });
    }

    /// The sharing round at `version`, as stored.
    async fn stored_round(
        rig: &ProtocolRig,
        version: u32,
    ) -> Option<crate::protocol::types::SharingRoundState> {
        use crate::protocol::DeRecStateStore as _;
        use crate::protocol::types::{StateItem, StateKind};
        rig.protocol
            .state_store
            .load_all(SECRET_ID, StateKind::SharingRound)
            .await
            .expect("load rounds")
            .into_iter()
            .find_map(|item| match item {
                StateItem::SharingRound(round) if round.version == version => Some(*round),
                _ => None,
            })
    }

    /// A confirmation whose round cannot be saved fails `process`, and
    /// processing the same bytes once the store recovers records it.
    #[test]
    fn a_confirmation_the_round_cannot_record_is_recorded_on_retry() {
        use crate::primitives::sharing::{request, response};
        run_async(async {
            let mut rig = protocol_rig(&[51, 52], 2).await;
            let started = protect(&mut rig, &[]).await;
            let version = started
                .iter()
                .find_map(|e| match e {
                    DeRecEvent::ProtectSecretStarted { version, .. } => Some(*version),
                    _ => None,
                })
                .expect("a round starts");
            let key = crate::types::SharedKey::new([51u8; 32]);
            let sent = rig
                .protocol
                .transport
                .sent_envelopes()
                .iter()
                .find_map(|env| request::extract(env, &key).ok())
                .expect("a request was sent to 51")
                .request;
            let answer = response::produce(ChannelId(51), &sent, &key)
                .expect("the helper answers")
                .envelope;

            *rig.protocol.state_store.fail_writes.lock().unwrap() = true;
            let error = rig
                .protocol
                .process(&answer)
                .await
                .expect_err("the round cannot record the confirmation");

            assert_eq!(error.channel_id, Some(ChannelId(51)));
            assert!(
                error.events.iter().any(
                    |e| matches!(e, DeRecEvent::ShareConfirmed { channel_id, .. }
                        if *channel_id == ChannelId(51))
                ),
                "the message's events travel with the error; got {:?}",
                error.events
            );
            let round = stored_round(&rig, version)
                .await
                .expect("the round is open");
            assert!(round.pending.contains(&ChannelId(51)));

            *rig.protocol.state_store.fail_writes.lock().unwrap() = false;
            rig.protocol
                .process(&answer)
                .await
                .expect("the retry records the confirmation");

            let round = stored_round(&rig, version)
                .await
                .expect("52 is still pending");
            assert!(round.confirmed.contains(&ChannelId(51)));
            assert!(!round.pending.contains(&ChannelId(51)));
        });
    }
}
