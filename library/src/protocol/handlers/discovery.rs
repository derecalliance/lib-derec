// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::discovery::{
        request,
        response::{self, SecretVersionEntry, VersionEntry},
    },
    types::{ChannelId, SharedKey, Target},
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
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetSecretIdsVersionsRequest(request) => {
            on_request(channel_id, request, shared_key)
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
    target: Target,
) -> Result<()> {
    let channel_ids = match target {
        Target::All => {
            let channels = channel_store.channels().await?;
            channels.into_iter().map(|ch| ch.id).collect::<Vec<_>>()
        }
        Target::Single(id) => vec![id],
        Target::Many(ids) => ids,
    };

    for channel_id in channel_ids {
        let Some(SecretValue::SharedKey(shared_key)) =
            // TODO: add a new function load_many
            secret_store.load(channel_id, SecretKind::SharedKey).await?
        else {
            continue;
        };

        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        let msg = request::produce(channel_id, &shared_key)?;
        transport.send(&endpoint, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(channel_id = channel_id.0, "discovery request sent");
    }

    #[cfg(feature = "logging")]
    tracing::info!("discovery requests dispatched");

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    transport: &T,
    channel_id: ChannelId,
    _request: &GetSecretIdsVersionsRequestMessage,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = channel_store.linked_channels(channel_id).await?;
    let all_shares = share_store.load_all(&linked_ids).await?;

    // Group by secret_id across all linked channels, deduplicating by version.
    // Key: secret_id (u64) → version → description.
    // TODO: evaluate using a HashMap<(secret_id, version), String>
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

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery response sent");

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
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
        channel_id,
        MessageBody::GetSecretIdsVersionsResponse(response),
        shared_key,
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
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::Discovery {
            channel_id,
            request,
            shared_key,
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
