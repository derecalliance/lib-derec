// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue, Share,
};
use super::replicas::sharing as replica;
use crate::derec_message::DeRecMessageBuilder;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
use crate::protocol::DeRecUserSecretStore;
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::ChannelQuery;
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
                .load(local.secret_id, ChannelQuery::Helper { channel_id })
                .await?
                .and_then(|r| r.as_helper().cloned())
                .ok_or(Error::InvalidInput(
                    "channel id not present in channel store",
                ))?;
            match (channel.peer_role, inner) {
                (SenderKind::Owner, MessageBody::StoreShareRequest(request)) => {
                    on_request(exchange, request)
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
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    secrets: Vec<UserSecret>,
    description: Option<String>,
    threshold: usize,
    round: &Round<'_>,
) -> Result<Option<SharingRoundResult>> {
    let secret_id = local.secret_id;
    let (helpers, replicas) = load_all_paired_targets(stores, local).await?;

    if helpers.is_empty() && replicas.is_empty() {
        return Ok(None);
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
        Some(channel_id) => match stores
            .secrets
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

    let version = stores
        .user_secrets
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
        let keep_list = resolve_keep_list(stores, secret_id, version).await?;
        let helper_outcomes = distribute_shares(
            stores,
            local,
            &helpers,
            result,
            &keep_list,
            version,
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
/// per-channel stores.transport / store failure. The orchestrator maps each
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
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
/// Helper side of a `StoreShareRequestMessage`: persist the incoming
/// share, apply the request's `keepList`, and acknowledge.
///
/// # Retention (`keepList`)
///
/// A non-empty `keepList` is the complete set of versions the Owner wants
/// retained on this channel; every other version stored under
/// `(secret_id, channel_id)` is removed via
/// [`DeRecShareStore::remove_versions`](crate::protocol::DeRecShareStore::remove_versions)
/// once the incoming share is persisted.
///
/// - An empty `keepList` retains every stored version plus the new one.
/// - A request whose `version` is older than the latest version already
///   stored on this channel has its `keepList` ignored, so a replayed or
///   delayed request can never delete newer shares.
/// - The version carried by the request is never removed, even when the
///   `keepList` omits it: deleting the share this very request stores
///   would acknowledge a share the Helper no longer holds.
///
/// "Latest" is scoped to this channel rather than to
/// [`DeRecShareStore::latest_version`](crate::protocol::DeRecShareStore::latest_version),
/// which spans every channel of the partition and would let one Owner's
/// newer version suppress another Owner's `keepList`.
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &StoreShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;
    let version = request.version;
    let keep_list = &request.keep_list;
    let encoded_request = request.encode_to_vec();

    // Applying a `keepList` needs every version stored on the channel;
    // otherwise only the incoming version is needed for the check below.
    let versions_to_load: &[u32] = if keep_list.is_empty() {
        std::slice::from_ref(&version)
    } else {
        &[]
    };
    let stored_on_channel = stores
        .shares
        .load(secret_id, channel_id, versions_to_load)
        .await?;

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
            reject(
                stores,
                local,
                exchange,
                request,
                StatusEnum::VersionConflict,
                "a different share is already stored at this version",
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
            stores
                .shares
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

    let is_latest = stored_on_channel
        .iter()
        .all(|stored| stored.version <= version);
    if !keep_list.is_empty() && is_latest {
        let stale: Vec<u32> = stored_on_channel
            .iter()
            .map(|stored| stored.version)
            .filter(|v| *v != version && !keep_list.contains(v))
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
                "share versions outside keepList removed"
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
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

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
    }])
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
        replica_id: request.replica_id.and(local.replica_id),
    };
    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        secret_id,
        channel_id,
        MessageBody::StoreShareResponse(response),
        exchange.shared_key,
        exchange.trace_id,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
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
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(
    exchange: &Exchange<'_>,
    request: StoreShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::StoreShare {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
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
/// until its first copy is sent.
pub(in crate::protocol) fn build_secret(
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

/// The `keepList` every Helper receives in the round distributing
/// `version`: the share store's [`keep_list`](crate::protocol::DeRecShareStore::keep_list)
/// plus `version`, deduplicated and ascending, or an empty list when the
/// store returns `None`, which tells every Helper to keep every version it
/// holds.
async fn resolve_keep_list<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    secret_id: u64,
    version: u32,
) -> Result<Vec<u32>> {
    let Some(mut keep_list) = stores.shares.keep_list(secret_id, version).await? else {
        return Ok(Vec::new());
    };
    keep_list.push(version);
    keep_list.sort_unstable();
    keep_list.dedup();
    Ok(keep_list)
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_shares<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    split_result: &crate::primitives::sharing::request::SplitResult,
    keep_list: &[u32],
    version: u32,
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
            keep_list,
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
#[allow(clippy::too_many_arguments)]
async fn dispatch_share_to_helper<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::HelperChannel,
    shared_key: &SharedKey,
    committed_share: &derec_proto::CommittedDeRecShare,
    keep_list: &[u32],
    version: u32,
    description: &str,
    round: &Round<'_>,
) -> Result<()> {
    let secret_id = local.secret_id;
    let msg = produce_store_share_request_message(
        channel.channel_id,
        version,
        secret_id,
        committed_share,
        keep_list,
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
        per_channel.shared_key = group_key.to_vec();
    }
    let composite_bytes = per_channel.encode_to_vec();

    let timestamp = current_timestamp();
    let reply_to_transports = round.reply_to.to_vec();
    let msg = StoreShareRequestMessage {
        share: composite_bytes,
        share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
        version,
        keep_list: Vec::new(),
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
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::{InMemChannelStore, NoopTransport, StoreRig, run_async};
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
            let lf = LocalFixture::new(HELPER_SECRET_ID);
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

            let mut rig = StoreRig::with_transport(NoopTransport);
            super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id,
                    shared_key: &shared_key,
                    trace_id: 1,
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

            let mut rig = StoreRig::with_transport(NoopTransport);
            seed_owner_channel(&mut rig.channels, SECRET_ID, channel_id).await;

            super::accept(
                &mut rig.stores(),
                &lf.local(),
                &Exchange {
                    channel_id,
                    shared_key: &shared_key,
                    trace_id: 1,
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
                },
                &second,
            )
            .await
            .expect("the conflict is reported to the peer, not raised locally");

            assert!(
                matches!(events.as_slice(), [crate::protocol::DeRecEvent::NoOp]),
                "a refused write stores nothing and reports no ShareStored"
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
    const KEEP_KEY: SharedKey = [42u8; 32];

    fn store_request(version: u32, keep_list: &[u32]) -> derec_proto::StoreShareRequestMessage {
        let split = request::split(
            &[KEEP_CHANNEL, ChannelId(12)],
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
            keep_list,
            "",
            &KEEP_KEY,
            &[],
        )
        .expect("produce request");
        request::extract(&produced.envelope, &KEEP_KEY)
            .expect("extract request")
            .request
    }

    async fn accept_version(rig: &mut StoreRig, version: u32, keep_list: &[u32]) {
        accept_request(rig, &store_request(version, keep_list)).await;
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

    async fn keep_rig_with_versions(versions: &[u32]) -> StoreRig {
        let mut rig = StoreRig::new();
        seed_owner_channel(&mut rig.channels, KEEP_SECRET_ID, KEEP_CHANNEL).await;
        for v in versions {
            accept_version(&mut rig, *v, &[]).await;
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

    /// `keepList` is the complete set of versions to retain: every stored
    /// version outside it is deleted once the new share is stored.
    #[test]
    fn accept_deletes_versions_outside_the_keep_list() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            accept_version(&mut rig, 4, &[3, 4]).await;
            assert_eq!(stored_versions(&rig), vec![3, 4]);
        });
    }

    /// An empty `keepList` retains every existing version plus the new one.
    #[test]
    fn accept_with_an_empty_keep_list_keeps_every_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            accept_version(&mut rig, 4, &[]).await;
            assert_eq!(stored_versions(&rig), vec![1, 2, 3, 4]);
        });
    }

    /// A request older than the latest stored version must have its
    /// `keepList` ignored, so a replay cannot delete newer shares.
    #[test]
    fn accept_ignores_the_keep_list_of_an_older_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 3, 4]).await;
            accept_version(&mut rig, 2, &[2]).await;
            assert_eq!(stored_versions(&rig), vec![1, 2, 3, 4]);
        });
    }

    /// The share carried by the request is kept even when its own version
    /// is missing from the `keepList`, including on an idempotent re-send
    /// where that version is already stored.
    #[test]
    fn accept_never_deletes_the_incoming_version() {
        run_async(async {
            let mut rig = keep_rig_with_versions(&[1, 2, 3]).await;
            let request = store_request(4, &[3]);
            accept_request(&mut rig, &request).await;
            assert_eq!(stored_versions(&rig), vec![3, 4]);
            accept_request(&mut rig, &request).await;
            assert_eq!(stored_versions(&rig), vec![3, 4]);
        });
    }

    /// The `keepList` only governs the channel it arrived on.
    #[test]
    fn accept_keep_list_leaves_other_channels_untouched() {
        run_async(async {
            use crate::protocol::DeRecShareStore;
            let mut rig = keep_rig_with_versions(&[1, 2]).await;
            let other = crate::protocol::types::Share {
                secret_id: KEEP_SECRET_ID,
                version: 1,
                bytes: vec![1, 2, 3],
            };
            rig.shares
                .save(KEEP_SECRET_ID, ChannelId(99), other)
                .await
                .expect("seed other channel");
            accept_version(&mut rig, 3, &[3]).await;
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
                    },
                ),
            )
            .await
            .expect("seed channel");
    }
}

/// The Owner side of `keepList`: which versions the Helpers are told to
/// keep, and the end-to-end effect once they apply it.
#[cfg(test)]
mod owner_keep_list_tests {
    use crate::primitives::sharing::request;
    use crate::protocol::context::{Exchange, Round};
    use crate::protocol::test::{LocalFixture, StoreRig, run_async};
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
        [channel as u8; 32]
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
                },
            )
            .await
            .expect("seed snapshot");
    }

    async fn publish(rig: &mut StoreRig) -> u32 {
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
            THRESHOLD,
            &Round {
                reply_to: &[],
                trace_id: 1,
            },
        )
        .await
        .expect("sharing round runs")
        .expect("helpers are paired")
        .version
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

    fn sent_keep_lists(rig: &StoreRig) -> Vec<Vec<u32>> {
        let requests = sent_requests(rig);
        assert_eq!(requests.len(), HELPERS.len(), "one request per helper");
        requests.into_iter().map(|(_, r)| r.keep_list).collect()
    }

    /// The application's list, plus the version being sent, reaches every
    /// Helper in the round; the store is asked once, not once per Helper.
    #[test]
    fn the_app_list_plus_the_new_version_goes_to_every_helper() {
        run_async(async {
            let mut rig = owner_rig().await;
            seed_latest_version(&mut rig, 4).await;
            *rig.shares.keep.lock().unwrap() = Some(vec![2]);

            assert_eq!(publish(&mut rig).await, 5);

            assert_eq!(sent_keep_lists(&rig), vec![vec![2, 5]; HELPERS.len()]);
            assert_eq!(
                *rig.shares.keep_list_calls.lock().unwrap(),
                vec![(OWNER_SECRET_ID, 5)]
            );
        });
    }

    /// The library normalizes the list: duplicates go, the order is
    /// ascending, and the version being sent appears once.
    #[test]
    fn the_app_list_is_deduplicated_and_sorted() {
        run_async(async {
            let mut rig = owner_rig().await;
            seed_latest_version(&mut rig, 4).await;
            *rig.shares.keep.lock().unwrap() = Some(vec![5, 3, 1, 3]);

            publish(&mut rig).await;

            assert_eq!(sent_keep_lists(&rig), vec![vec![1, 3, 5]; HELPERS.len()]);
        });
    }

    /// With no list from the application the owner sends an empty
    /// `keepList`, after asking: no window of recent versions is imposed.
    #[test]
    fn no_app_list_sends_an_empty_keep_list() {
        run_async(async {
            let mut rig = owner_rig().await;
            seed_latest_version(&mut rig, 4).await;

            publish(&mut rig).await;

            assert_eq!(
                sent_keep_lists(&rig),
                vec![Vec::<u32>::new(); HELPERS.len()]
            );
            assert_eq!(
                *rig.shares.keep_list_calls.lock().unwrap(),
                vec![(OWNER_SECRET_ID, 5)]
            );
        });
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
                }),
            )
            .await
            .expect("seed owner channel");
        rig
    }

    async fn deliver(owner: &StoreRig, helpers: &mut [(u64, StoreRig)]) {
        let lf = LocalFixture::new(HELPER_SECRET_ID);
        for (channel, request) in sent_requests(owner) {
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

    /// The application rolls back v2: it never committed, so the list it
    /// returns for v3 names only v1. Once the v3 round lands, every Helper
    /// holds exactly v1 and v3.
    #[test]
    fn helpers_keep_exactly_the_versions_the_owner_lists() {
        run_async(async {
            let mut owner = owner_rig().await;
            let mut helpers = Vec::new();
            for channel in HELPERS {
                helpers.push((channel, helper_rig(channel).await));
            }

            for _ in 0..2 {
                publish(&mut owner).await;
                deliver(&owner, &mut helpers).await;
            }
            for (_, rig) in &helpers {
                assert_eq!(held_versions(rig), vec![1, 2]);
            }

            *owner.shares.keep.lock().unwrap() = Some(vec![1]);
            assert_eq!(publish(&mut owner).await, 3);
            deliver(&owner, &mut helpers).await;

            for (channel, rig) in &helpers {
                assert_eq!(
                    held_versions(rig),
                    vec![1, 3],
                    "helper on channel {channel} must hold exactly the listed versions"
                );
            }
        });
    }

    /// With no list from the application, Helpers keep every version they
    /// were sent: five rounds leave all five versions on every Helper,
    /// which a capped window would have pruned.
    #[test]
    fn no_app_list_leaves_every_version_on_the_helpers() {
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
                    vec![1, 2, 3, 4, 5],
                    "helper on channel {channel} must keep every version"
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
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::StoreRig;
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
                }),
            )
            .await
            .expect("seed helper");
        rig.secrets
            .save(
                SECRET_ID,
                HELPER_CHANNEL,
                SecretValue::SharedKey([0xAA; 32]),
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
            let lf = crate::protocol::test::LocalFixture {
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
                    }],
                    secrets: Vec::new(),
                    replicas: Some(payload_roster()),
                }),
                shares: vec![crate::protocol::types::ChannelShare {
                    channel_id: HELPER_CHANNEL.0,
                    committed_share: vec![0x01, 0x02],
                }],
                shared_key: Vec::new(),
                version: 4,
                author_replica_id: None,
            };

            // The asker requested 9; the answerer served 4.
            super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
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
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version: 0,
                author_replica_id: None,
            };

            super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
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
                }),
                shares: Vec::new(),
                shared_key: Vec::new(),
                version: 3,
                author_replica_id: None,
            };

            let events = super::hydrate_catch_up(
                &mut rig.stores(),
                &lf.local(),
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
        group_key,
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
pub(in crate::protocol) async fn hydrate_catch_up<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    from_replica_id: u64,
    secret_id: u64,
    response_version: u32,
    payload: &[u8],
) -> Result<Vec<DeRecEvent>> {
    let composite = crate::protocol::types::ReplicaSecretPayload::decode(payload)
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "catch-up payload missing `secret` field",
    ))?;
    let version = if composite.version == 0 {
        response_version
    } else {
        composite.version
    };

    // A catch-up answer comes from whichever member answered, so only the
    // payload can name the author.
    let author_replica_id = composite.author_replica_id;
    let channel_id = ChannelId(secret.replicas.as_ref().map_or(0, |g| g.channel_id));

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
        &secret,
        &composite.shares,
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
