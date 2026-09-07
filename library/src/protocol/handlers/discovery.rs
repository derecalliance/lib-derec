// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoints;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::discovery::{
        request,
        response::{self, SecretVersionEntry, VersionEntry},
    },
    protocol::types::Target,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    MessageBody, StatusEnum, StoreShareRequestMessage,
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
        MessageBody::GetSecretIdsVersionsRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::GetSecretIdsVersionsResponse(response) => on_response(channel_id, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in discovery handler",
        )),
    }
}

/// Dispatch a discovery request to each targeted channel.
///
/// `Target::Single` / `Target::Many` are filtered down to channels this
/// `secret_id` actually holds — caller-supplied ids may name unpaired
/// channels, which would otherwise trip the shared-key invariant below.
///
/// Dispatch failure is isolated per channel and surfaced as
/// `DiscoveryFailed` rather than short-circuiting the fan-out, so one
/// unreachable helper cannot suppress the rest.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    secret_id: u64,
    target: Target,
    reply_to: &[derec_proto::TransportProtocol],
) -> Result<Vec<DeRecEvent>> {
    let known_channel_ids: std::collections::HashSet<ChannelId> = channel_store
        .helpers(secret_id)
        .await?
        .into_iter()
        .map(|ch| ch.channel_id)
        .collect();
    let channel_ids: Vec<ChannelId> = match target {
        Target::All => known_channel_ids.iter().copied().collect(),
        Target::Single(id) => {
            if known_channel_ids.contains(&id) {
                vec![id]
            } else {
                vec![]
            }
        }
        Target::Many(ids) => ids
            .into_iter()
            .filter(|id| known_channel_ids.contains(id))
            .collect(),
    };

    let keys = secret_store
        .load_many(
            secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    let mut events = Vec::with_capacity(keys.len());
    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            events.push(DeRecEvent::DiscoveryFailed {
                channel_id,
                error: "channel has no shared key".to_owned(),
            });
            continue;
        };

        match dispatch_one(
            channel_store,
            transport,
            secret_id,
            channel_id,
            &shared_key,
            reply_to,
        )
        .await
        {
            Ok(()) => {
                events.push(DeRecEvent::DiscoveryStarted { channel_id });
                #[cfg(feature = "logging")]
                tracing::debug!(channel_id = channel_id.0, "discovery request sent");
            }
            Err(e) => {
                events.push(DeRecEvent::DiscoveryFailed {
                    channel_id,
                    error: e.to_string(),
                });
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    error = %e,
                    "discovery request dispatch failed"
                );
            }
        }
    }

    #[cfg(feature = "logging")]
    tracing::info!("discovery requests dispatched");

    Ok(events)
}

/// Answer a peer's discovery request with the catalog of secrets held
/// for it across every linked channel.
///
/// Entries are grouped by `secret_id`, then keyed by `version`. A helper
/// holds exactly one share per `(secret_id, version)` — a second write
/// carrying different content is refused with `VERSION_CONFLICT` rather
/// than stored alongside — so a version identifies a share unambiguously
/// and needs no writer to disambiguate it.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
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
    request: &GetSecretIdsVersionsRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = channel_store.linked_channels(secret_id, channel_id).await?;
    let all_shares = share_store.load_all(secret_id, &linked_ids).await?;

    let mut secret_map: std::collections::HashMap<u64, std::collections::BTreeMap<u32, String>> =
        std::collections::HashMap::new();

    for share in all_shares {
        let description = StoreShareRequestMessage::decode(share.bytes.as_slice())
            .map(|msg| msg.version_description)
            .unwrap_or_default();
        secret_map
            .entry(share.secret_id)
            .or_default()
            .entry(share.version)
            .or_insert(description);
    }

    let secret_list: Vec<SecretVersionEntry> = secret_map
        .into_iter()
        .map(|(secret_id, versions)| SecretVersionEntry {
            secret_id,
            versions: versions
                .into_iter()
                .map(|(version, description)| VersionEntry {
                    version,
                    description,
                })
                .collect(),
        })
        .collect();

    let resp = response::produce(channel_id, &secret_list, shared_key)?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint =
        super::resolve_response_endpoints(channel_store, secret_id, channel_id, &request.reply_to)
            .await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery response sent");

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &GetSecretIdsVersionsRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
    local_replica_id: Option<u64>,
) -> Result<()> {
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_list: Vec::new(),
        timestamp: Some(current_timestamp()),
        // Answer on the path the request arrived on: a member asking gets a
        // member's answer, a helper exchange stays helper-bound.
        replica_id: local_replica_id.filter(|_| request.replica_id.is_some()),
    };

    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::GetSecretIdsVersionsResponse(response),
        shared_key,
        trace_id,
        &request.reply_to,
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: GetSecretIdsVersionsRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::Discovery {
            channel_id,
            request,
            shared_key,
            trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_response(
    channel_id: ChannelId,
    response: &GetSecretIdsVersionsResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let result = response::process(response)?;

    #[cfg(feature = "logging")]
    tracing::info!(
        secrets_count = result.secret_list.len(),
        "secrets discovered"
    );

    Ok(vec![DeRecEvent::SecretsDiscovered {
        channel_id,
        secrets: result.secret_list,
    }])
}

async fn dispatch_one<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    reply_to: &[derec_proto::TransportProtocol],
) -> Result<()> {
    let endpoint = peer_endpoints(channel_store, secret_id, channel_id).await?;
    let msg = request::produce(channel_id, shared_key, reply_to)?;
    let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;
    Ok(())
}
