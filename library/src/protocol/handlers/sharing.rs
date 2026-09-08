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
    keep_versions_count: usize,
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
    let roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
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
        let helper_outcomes = distribute_shares(
            stores,
            local,
            &helpers,
            result,
            keep_versions_count,
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
        let composite = build_replica_composite(&secret, split_result.as_ref());
        let k_group = group_key;
        let replica_results = distribute_composite_to_destinations(
            stores,
            local,
            &replicas,
            &composite,
            k_group,
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
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &StoreShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;
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
    let already_stored = stores
        .shares
        .load(secret_id, channel_id, &[version])
        .await?
        .into_iter()
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

    let resp = sharing_response::produce(channel_id, request, exchange.shared_key)?;
    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(secret_id, channel_id, &request.reply_to)
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
        replica_id,
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
/// until it hydrates.
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

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id, secret_id = local.secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_shares<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    paired_helpers: &[(crate::protocol::types::HelperChannel, SharedKey)],
    split_result: &crate::primitives::sharing::request::SplitResult,
    keep_versions_count: usize,
    version: u32,
    description: &str,
    round: &Round<'_>,
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
            stores,
            local,
            channel,
            shared_key,
            committed_share,
            &keep_list,
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
    k_group: Option<SharedKey>,
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
            k_group.as_ref(),
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
#[allow(clippy::too_many_arguments)]
async fn dispatch_composite_to_destination<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::ReplicaMember,
    channel_key: &SharedKey,
    composite: &crate::protocol::types::ReplicaSecretPayload,
    k_group: Option<&SharedKey>,
    version: u32,
    description: &str,
    round: &Round<'_>,
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
        secret_id: local.secret_id,
        reply_to: round.reply_to.to_vec(),
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

    if needs_handover {
        let new_key = k_group.expect("handover implies k_group set");
        stores
            .secrets
            .save(
                local.secret_id,
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
}

/// Build the payload a catch-up request is answered with.
///
/// The same composite a publish sends — whole secret, whole roster — so the
/// asker's hydration path is identical whether the state arrived unsolicited
/// or was pulled. `None` when this device holds no snapshot and therefore has
/// nothing to serve.
pub(in crate::protocol) async fn build_catch_up_payload<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
) -> Result<Option<crate::protocol::types::ReplicaSecretPayload>> {
    let secret_id = local.secret_id;
    let Some(snapshot) = stores.user_secrets.load_latest(secret_id).await? else {
        return Ok(None);
    };

    let (helpers, _) = load_all_paired_targets(stores, local).await?;
    let roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
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
pub(in crate::protocol) async fn hydrate_catch_up<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    from_replica_id: u64,
    version: u32,
    payload: &[u8],
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let composite = crate::protocol::types::ReplicaSecretPayload::decode(payload)
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "catch-up payload missing `secret` field",
    ))?;

    let is_install = stores.user_secrets.load_latest(secret_id).await?.is_none();

    replica::hydrate(stores, local, version, &secret, String::new()).await?;

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
