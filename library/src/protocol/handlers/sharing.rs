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
pub(in crate::protocol) async fn handle_replica_request<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    channel: &crate::protocol::types::Channel,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let from_replica_id = channel.replica_id.ok_or(Error::Invariant(
        "replica channel missing peer replica_id (must be set at pair time)",
    ))?;
    let secret_id = request.secret_id;
    let version = request.version;

    let composite = crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "replica secret payload missing `secret` field",
    ))?;
    let shares = composite.shares;

    let ack_key: SharedKey = match composite.shared_key.len() {
        0 => shared_key,
        32 => {
            let k_group: SharedKey = composite
                .shared_key
                .as_slice()
                .try_into()
                .expect("len-checked above");
            secret_store
                .save(secret_id, channel.id, SecretValue::SharedKey(k_group))
                .await
                .map_err(crate::Error::SecretStore)?;
            k_group
        }
        _ => {
            return Err(crate::Error::InvalidInput(
                "replica_group_key must be empty or 32 bytes",
            ));
        }
    };

    let timestamp = current_timestamp();
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version,
        timestamp: Some(timestamp),
        secret_id,
    };
    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel.id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareResponse(response))
        .encrypt(&ack_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope_bytes, inbound_trace_id)?;
    let endpoint = request
        .reply_to
        .clone()
        .unwrap_or_else(|| channel.transport.clone());
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel.id.0,
        from_replica_id,
        secret_id,
        version,
        helpers_in_secret = secret.helpers.len(),
        replicas_in_secret = secret.replicas.as_ref().map_or(0, |g| g.replicas.len()),
        secrets_in_secret = secret.secrets.len(),
        shares_count = shares.len(),
        handover = !composite.shared_key.is_empty(),
        "replica secret received; ack sent"
    );

    Ok(vec![DeRecEvent::ReplicaSecretReceived {
        channel_id: channel.id,
        from_replica_id,
        secret_id,
        version,
        secret,
        shares,
    }])
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
pub(in crate::protocol) fn handle_replica_response(
    channel: &crate::protocol::types::Channel,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let from_replica_id = channel.replica_id.ok_or(Error::Invariant(
        "replica channel missing peer replica_id (must be set at pair time)",
    ))?;
    let (status, memo) = response
        .result
        .as_ref()
        .map(|r| (r.status, r.memo.clone()))
        .unwrap_or((-1, "response missing `result` field".to_owned()));

    Ok(vec![DeRecEvent::ReplicaSecretAcked {
        channel_id: channel.id,
        from_replica_id,
        secret_id: response.secret_id,
        version: response.version,
        status,
        memo,
    }])
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
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
) -> Result<Option<SharingRoundResult>> {
    let (helpers, replicas) =
        load_all_paired_targets(channel_store, secret_store, secret_id).await?;

    if helpers.is_empty() && replicas.is_empty() {
        return Ok(None);
    }

    let snapshot_secrets = secrets.clone();
    let snapshot_description = description.clone();

    let secret = build_secret(&helpers, &replicas, secrets, owner_replica_id.unwrap_or(0));
    let derec_secret_bytes = wrap_for_helper_split(&secret, threshold);

    let version = user_secret_store
        .load_latest(secret_id)
        .await?
        .map(|s| s.version + 1)
        .unwrap_or(1);
    let description = description.as_deref().unwrap_or("").to_owned();

    let helper_channel_ids: Vec<ChannelId> = helpers.iter().map(|(ch, _)| ch.id).collect();
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
            reply_to.clone(),
            owner_replica_id,
        )
        .await;
        outcomes.extend(helper_outcomes);
    }

    if !replicas.is_empty() {
        let composite = build_replica_composite(&secret, split_result.as_ref());
        let k_group = current_replica_group_key(&replicas);
        let replica_outcomes = distribute_composite_to_destinations(
            secret_store,
            transport,
            &replicas,
            &composite,
            k_group,
            secret_id,
            version,
            &description,
            reply_to,
            owner_replica_id,
        )
        .await;
        outcomes.extend(replica_outcomes);
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

    Ok(Some(SharingRoundResult { version, outcomes }))
}

/// The output of [`start`] on a round with at least one targeted peer.
///
/// `outcomes` carries one `(ChannelId, Result<()>)` per targeted
/// helper / replica — `Ok(())` on successful dispatch, `Err` on
/// per-channel transport / store failure. The orchestrator maps each
/// entry to `ProtectSecretStarted` / `ProtectSecretFailed`.
pub(in crate::protocol) struct SharingRoundResult {
    pub(in crate::protocol) version: u32,
    pub(in crate::protocol) outcomes: Vec<(ChannelId, Result<()>)>,
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
) -> Result<Vec<DeRecEvent>> {
    let version = request.version;
    let replica_id = request.replica_id;
    let encoded_request = request.encode_to_vec();
    let resp = sharing_response::produce(channel_id, request, shared_key)?;

    share_store
        .save(
            secret_id,
            channel_id,
            Share {
                secret_id: request.secret_id,
                version,
                replica_id,
                bytes: encoded_request,
            },
        )
        .await?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = super::resolve_response_endpoint(
        channel_store,
        secret_id,
        channel_id,
        request.reply_to.as_ref(),
    )
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
) -> Result<()> {
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        timestamp: Some(current_timestamp()),
    };
    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::StoreShareResponse(response),
        shared_key,
        trace_id,
        request.reply_to.as_ref(),
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
) -> Result<(
    Vec<(crate::protocol::types::Channel, SharedKey)>,
    Vec<(crate::protocol::types::Channel, SharedKey)>,
)> {
    let all_channels = channel_store.channels(secret_id).await?;
    let selected_channels: Vec<crate::protocol::types::Channel> = all_channels
        .into_iter()
        .filter(|c| {
            matches!(
                c.peer_role,
                SenderKind::Helper | SenderKind::ReplicaDestination
            ) && c.status == crate::protocol::types::ChannelStatus::Paired
        })
        .collect();

    if selected_channels.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }

    let selected_ids: Vec<ChannelId> = selected_channels.iter().map(|c| c.id).collect();

    let mut keys: std::collections::HashMap<ChannelId, SharedKey> = secret_store
        .load_many(
            secret_id,
            &selected_ids,
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

    let mut helpers: Vec<(crate::protocol::types::Channel, SharedKey)> = Vec::new();
    let mut replicas: Vec<(crate::protocol::types::Channel, SharedKey)> = Vec::new();
    for channel in selected_channels {
        let key = keys
            .remove(&channel.id)
            .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");
        match channel.peer_role {
            SenderKind::Helper => helpers.push((channel, key)),
            SenderKind::ReplicaDestination => replicas.push((channel, key)),
            _ => {}
        }
    }
    Ok((helpers, replicas))
}

fn build_secret(
    paired_helpers: &[(crate::protocol::types::Channel, SharedKey)],
    paired_replicas: &[(crate::protocol::types::Channel, SharedKey)],
    secrets: Vec<UserSecret>,
    owner_replica_id: u64,
) -> Secret {
    let helper_infos: Vec<HelperInfo> = paired_helpers
        .iter()
        .map(|(channel, shared_key)| HelperInfo {
            channel_id: channel.id.0,
            transport_uri: channel.transport.uri.to_owned(),
            shared_key: shared_key.to_vec(),
            communication_info: channel.communication_info.clone(),
        })
        .collect();

    Secret {
        helpers: helper_infos,
        secrets,
        replicas: build_replicas(paired_replicas),
        owner_replica_id,
    }
}

fn build_replicas(
    paired_replicas: &[(crate::protocol::types::Channel, SharedKey)],
) -> Option<crate::protocol::types::Replicas> {
    if paired_replicas.is_empty() {
        return None;
    }
    let replica_infos: Vec<crate::protocol::types::ReplicaInfo> = paired_replicas
        .iter()
        .map(
            |(channel, _shared_key)| crate::protocol::types::ReplicaInfo {
                channel_id: channel.id.0,
                transport_uri: channel.transport.uri.to_owned(),
                communication_info: channel.communication_info.clone(),
                replica_id: channel.replica_id.unwrap_or(0),
                sender_kind: channel.peer_role as i32,
            },
        )
        .collect();
    let shared_key = paired_replicas
        .first()
        .map(|(_, key)| key.to_vec())
        .unwrap_or_default();
    Some(crate::protocol::types::Replicas {
        replicas: replica_infos,
        shared_key,
    })
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

fn current_replica_group_key(
    replicas: &[(crate::protocol::types::Channel, SharedKey)],
) -> Option<SharedKey> {
    replicas
        .iter()
        .min_by_key(|(ch, _)| (ch.created_at, ch.id.0))
        .map(|(_, key)| *key)
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_shares<Sh: DeRecShareStore, T: DeRecTransport>(
    share_store: &mut Sh,
    transport: &T,
    paired_helpers: &[(crate::protocol::types::Channel, SharedKey)],
    split_result: &crate::primitives::sharing::request::SplitResult,
    keep_versions_count: usize,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
) -> Vec<(ChannelId, Result<()>)> {
    let keep_list: Vec<u32> = {
        let start = version
            .saturating_sub(keep_versions_count as u32 - 1)
            .max(1);
        (start..=version).collect()
    };

    let mut results: Vec<(ChannelId, Result<()>)> = Vec::with_capacity(paired_helpers.len());
    for (channel, shared_key) in paired_helpers {
        let Some(committed_share) = split_result.shares.get(&channel.id) else {
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
            reply_to.clone(),
            owner_replica_id,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.id.0,
                secret_id = secret_id,
                version = version,
                "share envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.id.0,
                secret_id = secret_id,
                version = version,
                error = %e,
                "share envelope dispatch failed"
            ),
        }

        results.push((channel.id, outcome));
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
    channel: &crate::protocol::types::Channel,
    shared_key: &SharedKey,
    committed_share: &derec_proto::CommittedDeRecShare,
    keep_list: &[u32],
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
) -> Result<()> {
    let msg = produce_store_share_request_message(
        channel.id,
        version,
        secret_id,
        committed_share,
        keep_list,
        description,
        shared_key,
        reply_to,
        owner_replica_id,
    )?;
    let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
    transport.send(&channel.transport, envelope).await?;

    share_store
        .save(
            secret_id,
            channel.id,
            Share {
                secret_id,
                version,
                replica_id: owner_replica_id,
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
    replicas: &[(crate::protocol::types::Channel, SharedKey)],
    composite: &crate::protocol::types::ReplicaSecretPayload,
    k_group: Option<SharedKey>,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
) -> Vec<(ChannelId, Result<()>)> {
    let mut results: Vec<(ChannelId, Result<()>)> = Vec::with_capacity(replicas.len());
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
            reply_to.clone(),
            owner_replica_id,
        )
        .await;

        #[cfg(feature = "logging")]
        match &outcome {
            Ok(()) => tracing::debug!(
                channel_id = channel.id.0,
                secret_id = secret_id,
                version = version,
                "replica secret envelope sent"
            ),
            Err(e) => tracing::warn!(
                channel_id = channel.id.0,
                secret_id = secret_id,
                version = version,
                error = %e,
                "replica secret envelope dispatch failed"
            ),
        }

        results.push((channel.id, outcome));
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
    channel: &crate::protocol::types::Channel,
    channel_key: &SharedKey,
    composite: &crate::protocol::types::ReplicaSecretPayload,
    k_group: Option<&SharedKey>,
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
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
        reply_to,
        replica_id: owner_replica_id,
    };

    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel.id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareRequest(msg))
        .encrypt(channel_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope_bytes, super::fresh_trace_id())?;
    transport.send(&channel.transport, envelope).await?;

    if needs_handover {
        let new_key = k_group.expect("handover implies k_group set");
        secret_store
            .save(secret_id, channel.id, SecretValue::SharedKey(*new_key))
            .await
            .map_err(crate::Error::SecretStore)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::primitives::sharing::request;
    use crate::protocol::test::{InMemChannelStore, InMemShareStore, NoopTransport, run_async};
    use crate::types::{ChannelId, SharedKey};
    use derec_proto::{Protocol, TransportProtocol};

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
                Some(TransportProtocol {
                    uri: "https://owner.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }),
                None,
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
}
