// SPDX-License-Identifier: Apache-2.0

//! Discovery (get-secret-ids-versions) flow handler.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::discovery::{
        request::produce as produce_discovery_request,
        response::{self as discovery_response, SecretVersionEntry, VersionEntry},
    },
    types::{ChannelId, SharedKey, Target},
};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    MessageBody, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

pub(in crate::protocol) fn handle(
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetSecretIdsVersionsRequest(request) => {
            Ok(on_request(channel_id, request, shared_key))
        }
        MessageBody::GetSecretIdsVersionsResponse(response) => on_response(channel_id, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in discovery handler",
        )),
    }
}

/// Accept a discovery request: enumerate stored secrets and send response.
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
    let all_shares = share_store.load(channel_id, &[]).await?;

    let secret_list = if all_shares.is_empty() {
        vec![]
    } else {
        let first_msg = StoreShareRequestMessage::decode(all_shares[0].1.as_slice())
            .map_err(Error::ProtobufDecode)?;
        let secret_id = first_msg.secret_id;

        let mut version_entries: Vec<VersionEntry> = Vec::with_capacity(all_shares.len());
        for (version, encoded) in &all_shares {
            let description = StoreShareRequestMessage::decode(encoded.as_slice())
                .map(|msg| msg.version_description)
                .unwrap_or_default();
            version_entries.push(VersionEntry {
                version: *version,
                description,
            });
        }

        vec![SecretVersionEntry {
            secret_id,
            versions: version_entries,
        }]
    };

    let resp = discovery_response::produce(channel_id, &secret_list, shared_key)?;

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery response sent");

    Ok(vec![DeRecEvent::NoOp])
}

/// Reject a discovery request: send FAIL response.
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    memo: &str,
) -> Result<()> {
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Fail as i32,
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

/// Send discovery requests to one or more paired helpers.
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
            secret_store.load(channel_id, SecretKind::SharedKey).await?
        else {
            continue;
        };

        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        let msg = produce_discovery_request(channel_id, &shared_key)?;
        transport.send(&endpoint, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(channel_id = channel_id.0, "discovery request sent");
    }

    #[cfg(feature = "logging")]
    tracing::info!("discovery requests dispatched");

    Ok(())
}

fn on_request(
    channel_id: ChannelId,
    request: GetSecretIdsVersionsRequestMessage,
    shared_key: SharedKey,
) -> Vec<DeRecEvent> {
    vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::Discovery {
            channel_id,
            request,
            shared_key,
        },
    }]
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_response(
    channel_id: ChannelId,
    response: &GetSecretIdsVersionsResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let result = discovery_response::process(response)?;

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
