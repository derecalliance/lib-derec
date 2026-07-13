// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoint;
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
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<Vec<DeRecEvent>> {
    // Filter Target::Single/Many to known channels; user input may include
    // unpaired ids and those would otherwise trip the invariant check below.
    let known_channel_ids: std::collections::HashSet<ChannelId> = channel_store
        .channels(secret_id)
        .await?
        .into_iter()
        .map(|ch| ch.id)
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
        .load_many(secret_id, &channel_ids, SecretKind::SharedKey, MissingPolicy::Fail)
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
            reply_to.clone(),
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

/// Send a single discovery request; failure isolated so
/// [`start`] can surface it as a per-channel `DiscoveryFailed` event
/// without short-circuiting the rest of the fan-out.
async fn dispatch_one<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<()> {
    let endpoint = peer_endpoint(channel_store, secret_id, channel_id).await?;
    let msg = request::produce(channel_id, shared_key, reply_to)?;
    let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;
    Ok(())
}

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

    // Group by secret_id across all linked channels. The inner key
    // pairs `version` with `replica_id` so two replicas writing the
    // same numeric version surface as two distinct entries in the
    // catalog — that's the conflict-visibility surface the App uses
    // to detect concurrent writes from multiple replicas.
    let mut secret_map: std::collections::HashMap<
        u64,
        std::collections::BTreeMap<(u32, Option<u64>), String>,
    > = std::collections::HashMap::new();

    for share in all_shares {
        let description = StoreShareRequestMessage::decode(share.bytes.as_slice())
            .map(|msg| msg.version_description)
            .unwrap_or_default();
        secret_map
            .entry(share.secret_id)
            .or_default()
            .entry((share.version, share.replica_id))
            .or_insert(description);
    }

    let secret_list: Vec<SecretVersionEntry> = secret_map
        .into_iter()
        .map(|(secret_id, versions)| SecretVersionEntry {
            secret_id,
            versions: versions
                .into_iter()
                .map(|((version, replica_id), description)| VersionEntry {
                    version,
                    description,
                    replica_id,
                })
                .collect(),
        })
        .collect();

    let resp = response::produce(channel_id, &secret_list, shared_key)?;

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
) -> Result<()> {
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_list: Vec::new(),
        timestamp: Some(current_timestamp()),
    };

    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::GetSecretIdsVersionsResponse(response),
        shared_key,
        trace_id,
        request.reply_to.as_ref(),
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
