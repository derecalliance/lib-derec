// SPDX-License-Identifier: Apache-2.0

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
) -> Result<Option<(u32, Vec<ChannelId>)>> {
    let (helpers, replicas) =
        load_all_paired_targets(channel_store, secret_store, secret_id).await?;

    // No paired peers — the secret has nowhere to land. Callers treat
    // this as a no-op so the auto-publish-on-pair hook can fire safely
    // even when no helpers/replicas exist yet.
    if helpers.is_empty() && replicas.is_empty() {
        return Ok(None);
    }

    // Snapshot copies kept for the user_secret_store write at the end.
    // Both arguments get moved into secret construction below.
    let snapshot_secrets = secrets.clone();
    let snapshot_description = description.clone();

    let secret =
        build_secret(&helpers, &replicas, secrets, owner_replica_id.unwrap_or(0));
    let derec_secret_bytes = wrap_for_helper_split(&secret, threshold);

    // Version progression is anchored to `user_secret_store` so it
    // bumps on every round — including roster-only auto-publishes to
    // Replica Destinations, which never write to `share_store`. The
    // snapshot saved at the end of this function is the source of
    // truth that the next round reads.
    let version = user_secret_store
        .load_latest(secret_id)
        .await?
        .map(|s| s.version + 1)
        .unwrap_or(1);
    let description = description.as_deref().unwrap_or("").to_owned();

    // VSS-split the DeRecSecret bytes once. The helper-distribution path
    // and the Destination composite both consume the resulting share map.
    // Below the configured threshold, no split runs — Helpers receive
    // nothing this round and any paired Replicas receive a "secret-only"
    // composite (no share material).
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

    let mut sent_channels: Vec<ChannelId> = Vec::new();

    if let Some(ref result) = split_result {
        let helper_sent = distribute_shares(
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
        .await?;
        sent_channels.extend(helper_sent);
    }

    if !replicas.is_empty() {
        let composite_bytes = build_replica_composite_bytes(&secret, split_result.as_ref());
        let replica_sent = distribute_composite_to_destinations(
            transport,
            &replicas,
            &composite_bytes,
            secret_id,
            version,
            &description,
            reply_to,
            owner_replica_id,
        )
        .await?;
        sent_channels.extend(replica_sent);
    }

    // Persist the snapshot AFTER successful distribution so an
    // interrupted round does not leave the version field ahead of
    // what any peer actually received.
    user_secret_store
        .save_latest(
            secret_id,
            crate::protocol::types::UserSecrets {
                version,
                secrets: snapshot_secrets,
                description: snapshot_description,
            },
        )
        .await?;

    Ok(Some((version, sent_channels)))
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
                secret_id,
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

/// Resolve all currently-paired publish targets into `(helpers, replicas)`
/// keyed by channel role.
///
/// Both vectors carry `(Channel, SharedKey)` pairs ready for envelope
/// construction. The protocol publishes the secret to *every* paired
/// peer that can receive it — apps no longer subset the target — so
/// selection is driven entirely by channel state:
/// `role == Owner` (peer is a Helper) lands in `helpers`,
/// `role == ReplicaSource` (peer is a ReplicaDestination) lands in
/// `replicas`. Channels with any other `role` (e.g. `Helper` — we're the
/// helper on the channel) are ignored.
///
/// `ChannelStatus::Pending` channels (replicas awaiting fingerprint
/// verification) are excluded to prevent a MITM-leaning peer from
/// receiving secret material before the user confirms the fingerprint
/// out-of-band.
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
                c.role,
                SenderKind::Owner | SenderKind::ReplicaSource
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
        match channel.role {
            // Local kind == Owner, peer is the Helper. Classic share path.
            SenderKind::Owner => helpers.push((channel, key)),
            // Local kind == ReplicaSource, peer is a ReplicaDestination
            // ready to receive full secret payloads (secret-sync path).
            SenderKind::ReplicaSource => replicas.push((channel, key)),
            // Local kind == Helper — we're the helper on this channel, not
            // a legitimate ProtectSecret initiator. The orchestrator-level
            // role gate refuses these before we get here.
            _ => {}
        }
    }
    Ok((helpers, replicas))
}

/// Build the canonical [`Secret`] for this `ProtectSecret` round —
/// the inner payload that contains the full roster snapshot (helpers +
/// replicas + secrets) plus the owner's replica id.
///
/// Returns the [`Secret`] value (not its encoded bytes), so callers
/// can either wrap it in [`DeRecSecret`] for the helper VSS path
/// (via [`wrap_for_helper_split`]) or embed it directly in a
/// [`ReplicaSecretPayload`] for the Destination path (via
/// [`build_replica_composite_bytes`]).
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

    let replica_infos: Vec<crate::protocol::types::ReplicaInfo> = paired_replicas
        .iter()
        .map(
            |(channel, shared_key)| crate::protocol::types::ReplicaInfo {
                channel_id: channel.id.0,
                transport_uri: channel.transport.uri.to_owned(),
                shared_key: shared_key.to_vec(),
                communication_info: channel.communication_info.clone(),
                replica_id: channel.replica_id.unwrap_or(0),
                sender_kind: crate::protocol::handlers::pairing::derive_peer_kind(channel.role)
                    as i32,
            },
        )
        .collect();

    Secret {
        helpers: helper_infos,
        secrets,
        replicas: replica_infos,
        owner_replica_id,
    }
}

/// Wrap the [`Secret`] in a [`DeRecSecret`] envelope ready to be
/// VSS-split for helper distribution. The helper side reconstructs the
/// `DeRecSecret` from a `threshold`-sized subset of shares; the inner
/// `secret_data` then decodes back to the original [`Secret`].
fn wrap_for_helper_split(secret: &Secret, threshold: usize) -> Vec<u8> {
    let derec_secret = DeRecSecret {
        secret_data: secret.encode_to_vec(),
        creation_time: None,
        helper_threshold_for_recovery: threshold as i64,
        helper_threshold_for_confirming_share_receipt: threshold as i64,
        helpers: Vec::new(),
    };
    derec_secret.encode_to_vec()
}

/// Build the encoded [`ReplicaSecretPayload`] bytes sent to each
/// Destination on this round. Pairs the full [`Secret`] (so the
/// Destination has the entire payload) with the per-helper share map
/// (so the Destination can act as a recovery delegate by re-fetching
/// shares from each helper using `secret.helpers[i].shared_key`).
fn build_replica_composite_bytes(
    secret: &Secret,
    split_result: Option<&crate::primitives::sharing::request::SplitResult>,
) -> Vec<u8> {
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

    let composite = crate::protocol::types::ReplicaSecretPayload {
        secret: Some(secret.clone()),
        shares,
    };
    composite.encode_to_vec()
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
) -> Result<Vec<ChannelId>> {
    let keep_list: Vec<u32> = {
        let start = version
            .saturating_sub(keep_versions_count as u32 - 1)
            .max(1);
        (start..=version).collect()
    };

    let mut sent_channels: Vec<ChannelId> = Vec::new();
    for (channel, shared_key) in paired_helpers {
        let Some(committed_share) = split_result.shares.get(&channel.id) else {
            continue;
        };

        let msg = produce_store_share_request_message(
            channel.id,
            version,
            secret_id,
            committed_share,
            &keep_list,
            description,
            shared_key,
            reply_to.clone(),
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

        sent_channels.push(channel.id);

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel.id.0,
            secret_id = secret_id,
            version = version,
            "share envelope sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        "secret distributed to helpers"
    );

    Ok(sent_channels)
}

/// Inbound `StoreShareRequest` on a **replica** channel. The payload
/// is the full secret — the sender used `share_algorithm =
/// REPLICA_SECRET`. We decode the typed
/// [`crate::protocol::types::ReplicaSecretPayload`] from `request.share`,
/// auto-ack with `StoreShareResponse(Ok)`, and surface a
/// [`DeRecEvent::ReplicaSecretReceived`] carrying the decoded
/// [`crate::protocol::types::Secret`] + [`Vec<crate::protocol::types::ChannelShare>`]
/// for the application's secret-install logic.
pub(in crate::protocol) async fn handle_replica_request<T: DeRecTransport>(
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

    // Decode the typed `ReplicaSecretPayload` from the request's
    // `share` field. The sender's `distribute_composite_to_destinations`
    // wrote it; surfacing the decoded fields on the event matches
    // the existing `SecretsDiscovered` / `SecretRecovered` pattern of
    // handing typed structures to the application.
    let composite = crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "replica secret payload missing `secret` field",
    ))?;
    let shares = composite.shares;

    // Auto-ack with Ok. We never refuse a replica secret sync — the
    // payload is app territory, so any install failures are surfaced
    // out-of-band, not via this response cycle.
    //
    // The standard `sharing_response::produce` validates `share` as a
    // `CommittedDeRecShare` (helper share path); the replica payload is
    // a full secret instead, so we build the response envelope inline.
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
        .encrypt(&shared_key)?
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
        replicas_in_secret = secret.replicas.len(),
        secrets_in_secret = secret.secrets.len(),
        shares_count = shares.len(),
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
pub(in crate::protocol) fn handle_replica_response(
    channel: &crate::protocol::types::Channel,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let from_replica_id = channel.replica_id.ok_or(Error::Invariant(
        "replica channel missing peer replica_id (must be set at pair time)",
    ))?;
    // Missing `result` on a StoreShareResponse is itself a protocol
    // violation; fall back to a sentinel (StatusEnum::Ok would mislead
    // the app into thinking the sync succeeded, so use a distinct
    // out-of-range value).
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

/// Sender-side replica path for `ProtectSecret`.
///
/// Each replica target receives a `StoreShareRequestMessage` carrying the
/// **full `Secret` payload** (the same `DeRecSecret` bytes the helper
/// path derives its VSS shares from) in `share`, tagged with
/// [`SHARE_ALGORITHM_REPLICA_SECRET`] so the receiver knows the payload
/// is the whole secret rather than a single share fragment.
///
/// `version` is shared with the helper path; both sides write the same
/// version number on this round. `keep_list` semantics don't apply to
/// replicas (every replica holds every version), so it is left empty.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
#[allow(clippy::too_many_arguments)]
async fn distribute_composite_to_destinations<T: DeRecTransport>(
    transport: &T,
    replicas: &[(crate::protocol::types::Channel, SharedKey)],
    composite_bytes: &[u8],
    secret_id: u64,
    version: u32,
    description: &str,
    reply_to: Option<derec_proto::TransportProtocol>,
    owner_replica_id: Option<u64>,
) -> Result<Vec<ChannelId>> {
    let mut sent_channels: Vec<ChannelId> = Vec::with_capacity(replicas.len());

    for (channel, shared_key) in replicas {
        let timestamp = current_timestamp();
        let msg = StoreShareRequestMessage {
            share: composite_bytes.to_vec(),
            share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
            version,
            keep_list: Vec::new(),
            version_description: description.to_owned(),
            timestamp: Some(timestamp),
            secret_id,
            reply_to: reply_to.clone(),
            replica_id: owner_replica_id,
        };

        let envelope_bytes = DeRecMessageBuilder::channel()
            .channel_id(channel.id)
            .timestamp(timestamp)
            .message_body(MessageBody::StoreShareRequest(msg))
            .encrypt(shared_key)?
            .build()?
            .encode_to_vec();
        let envelope = super::apply_trace_id(envelope_bytes, super::fresh_trace_id())?;
        transport.send(&channel.transport, envelope).await?;

        sent_channels.push(channel.id);

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel.id.0,
            secret_id = secret_id,
            version = version,
            "replica secret envelope sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id = secret_id,
        version = version,
        count = replicas.len(),
        "secret bag distributed to replicas"
    );

    Ok(sent_channels)
}
