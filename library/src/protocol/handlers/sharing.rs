// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    PendingAction, SecretKind, SecretValue,
};
use super::peer_endpoint;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::sharing::{
        request::{produce as produce_store_share_request_message, split},
        response::{self as sharing_response},
    },
    types::{ChannelId, HelperInfo, SecretContainer, SharedKey, UserSecret},
};
use derec_proto::{
    DeRecResult, DeRecSecret, MessageBody, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage,
};
use prost::Message;

pub(in crate::protocol) fn handle(
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::StoreShareRequest(request) => Ok(on_request(channel_id, request, shared_key)),
        MessageBody::StoreShareResponse(response) => on_response(channel_id, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in sharing handler",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.version))
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
    request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
) -> Result<Vec<DeRecEvent>> {
    let version = request.version;
    let encoded_request = request.encode_to_vec();
    let resp = sharing_response::produce(channel_id, request, shared_key)?;

    share_store
        .save(channel_id, version, encoded_request)
        .await?;

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, resp.envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("share stored and acknowledged");

    Ok(vec![DeRecEvent::ShareStored {
        channel_id,
        version,
    }])
}

pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_id: request.secret_id.clone(),
        version: request.version,
        timestamp: Some(current_timestamp()),
    };
    super::send_channel_message(
        channel_store,
        transport,
        channel_id,
        MessageBody::StoreShareResponse(response),
        shared_key,
    )
    .await
}

/// Split and distribute a secret to all paired helpers.
///
/// The version is automatically derived from the store: `latest_version + 1`
/// (or `1` if no shares exist yet).
#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    secret_store: &mut Ss,
    transport: &T,
    secrets: Vec<UserSecret>,
    description: Option<String>,
    threshold: usize,
    keep_versions_count: usize,
    secret_id: &[u8],
) -> Result<(i32, Vec<ChannelId>)> {
    let all_channels = channel_store.channels().await?;
    let mut paired_helpers: Vec<(crate::types::Channel, SharedKey)> = Vec::new();

    for channel in all_channels {
        let Some(SecretValue::SharedKey(shared_key)) =
            secret_store.load(channel.id, SecretKind::SharedKey).await?
        else {
            continue;
        };
        paired_helpers.push((channel, shared_key));
    }

    if paired_helpers.is_empty() {
        return Err(Error::InvalidInput("no paired helpers available"));
    }

    let helper_infos: Vec<HelperInfo> = paired_helpers
        .iter()
        .map(|(channel, shared_key)| HelperInfo {
            channel_id: channel.id.0,
            transport_uri: channel.transport.uri.to_owned(),
            name: channel.name.to_owned(),
            shared_key: shared_key.to_vec(),
        })
        .collect();

    let bag = SecretContainer {
        helpers: helper_infos,
        secrets,
    };
    let bag_bytes = bag.encode_to_vec();

    let derec_secret = DeRecSecret {
        secret_data: bag_bytes,
        creation_time: None,
        helper_threshold_for_recovery: threshold as i64,
        helper_threshold_for_confirming_share_receipt: threshold as i64,
        helpers: Vec::new(),
    };
    let secret_data = derec_secret.encode_to_vec();

    let version = share_store.latest_version().await?.map_or(1, |v| v + 1);

    let keep_list: Vec<i32> = {
        let start = (version - keep_versions_count as i32 + 1).max(1);
        (start..=version).collect()
    };

    let helper_channel_ids: Vec<ChannelId> = paired_helpers.iter().map(|(ch, _)| ch.id).collect();
    let result = split(
        &helper_channel_ids,
        secret_id,
        version,
        &secret_data,
        threshold,
    )?;

    let desc = description.as_deref().unwrap_or("");
    let mut sent_channels: Vec<ChannelId> = Vec::new();

    for (channel, shared_key) in &paired_helpers {
        let Some(committed_share) = result.shares.get(&channel.id) else {
            continue;
        };

        let msg = produce_store_share_request_message(
            channel.id,
            version,
            secret_id,
            committed_share,
            &keep_list,
            desc,
            shared_key,
        )?;
        transport.send(&channel.transport, msg.envelope).await?;

        share_store
            .save(channel.id, version, committed_share.encode_to_vec())
            .await?;

        sent_channels.push(channel.id);

        #[cfg(feature = "logging")]
        tracing::debug!(channel_id = channel.id.0, "share envelope sent");
    }

    #[cfg(feature = "logging")]
    tracing::info!(version = version, "secret bag distributed to helpers");

    Ok((version, sent_channels))
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = response.version))
)]
fn on_request(
    channel_id: ChannelId,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
) -> Vec<DeRecEvent> {
    vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::StoreShare {
            channel_id,
            request,
            shared_key,
        },
    }]
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = response.version))
)]
fn on_response(
    channel_id: ChannelId,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let version = response.version;
    match sharing_response::process(version, response) {
        Ok(()) => {
            #[cfg(feature = "logging")]
            tracing::info!("share confirmed by helper");

            Ok(vec![DeRecEvent::ShareConfirmed {
                channel_id,
                version,
            }])
        }
        Err(err) => {
            if let Some((status, memo)) = err.as_non_ok_status() {
                #[cfg(feature = "logging")]
                tracing::warn!(status, memo, "share rejected by helper");

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
