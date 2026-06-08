// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue, Share,
};
use super::{peer_endpoint, resolve_target};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::sharing::{
        request::{produce as produce_store_share_request_message, split},
        response::{self as sharing_response},
    },
    types::{ChannelId, HelperInfo, SecretContainer, SharedKey, Target, UserSecret},
};
use derec_proto::{
    DeRecResult, DeRecSecret, MessageBody, StatusEnum, StoreShareRequestMessage,
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
    secret_id: u64,
    target: Target,
) -> Result<(u32, Vec<ChannelId>)> {
    let paired_helpers = load_paired_helpers(channel_store, secret_store, target).await?;

    let secret_data = build_secret_container(&paired_helpers, secrets, threshold);

    distribute_shares(
        share_store,
        transport,
        &paired_helpers,
        &secret_data,
        threshold,
        keep_versions_count,
        secret_id,
        description.as_deref().unwrap_or(""),
    )
    .await
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
    channel_id: ChannelId,
    request: &StoreShareRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = request.secret_id;
    let version = request.version;
    let encoded_request = request.encode_to_vec();
    let resp = sharing_response::produce(channel_id, request, shared_key)?;

    share_store
        .save(
            channel_id,
            Share {
                secret_id,
                version,
                bytes: encoded_request,
            },
        )
        .await?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = peer_endpoint(channel_store, channel_id).await?;
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
        channel_id,
        MessageBody::StoreShareResponse(response),
        shared_key,
        trace_id,
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

async fn load_paired_helpers<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    target: Target,
) -> Result<Vec<(crate::types::Channel, SharedKey)>> {
    let selected_ids = resolve_target(channel_store, target).await?;
    if selected_ids.is_empty() {
        return Err(Error::InvalidInput("no paired helpers in target set"));
    }

    let all_channels = channel_store.channels().await?;
    let selected_channels: Vec<crate::types::Channel> = all_channels
        .into_iter()
        .filter(|c| selected_ids.contains(&c.id))
        .collect();

    let mut keys: std::collections::HashMap<ChannelId, SharedKey> = secret_store
        .load_many(&selected_ids, SecretKind::SharedKey, MissingPolicy::Fail)
        .await?
        .into_iter()
        .filter_map(|(cid, v)| match v {
            SecretValue::SharedKey(k) => Some((cid, k)),
            _ => None,
        })
        .collect();

    let paired_helpers = selected_channels
        .into_iter()
        .map(|channel| {
            let key = keys
                .remove(&channel.id)
                .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");
            (channel, key)
        })
        .collect();

    Ok(paired_helpers)
}

fn build_secret_container(
    paired_helpers: &[(crate::types::Channel, SharedKey)],
    secrets: Vec<UserSecret>,
    threshold: usize,
) -> Vec<u8> {
    let helper_infos: Vec<HelperInfo> = paired_helpers
        .iter()
        .map(|(channel, shared_key)| HelperInfo {
            channel_id: channel.id.0,
            transport_uri: channel.transport.uri.to_owned(),
            shared_key: shared_key.to_vec(),
            communication_info: channel.communication_info.clone(),
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
    derec_secret.encode_to_vec()
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id = secret_id)))]
async fn distribute_shares<Sh: DeRecShareStore, T: DeRecTransport>(
    share_store: &mut Sh,
    transport: &T,
    paired_helpers: &[(crate::types::Channel, SharedKey)],
    secret_data: &[u8],
    threshold: usize,
    keep_versions_count: usize,
    secret_id: u64,
    description: &str,
) -> Result<(u32, Vec<ChannelId>)> {
    let version = share_store.latest_version().await?.map_or(1, |v| v + 1);

    let keep_list: Vec<u32> = {
        let start = version
            .saturating_sub(keep_versions_count as u32 - 1)
            .max(1);
        (start..=version).collect()
    };

    let helper_channel_ids: Vec<ChannelId> = paired_helpers.iter().map(|(ch, _)| ch.id).collect();
    let result = split(
        &helper_channel_ids,
        secret_id,
        version,
        secret_data,
        threshold,
    )?;

    let mut sent_channels: Vec<ChannelId> = Vec::new();
    for (channel, shared_key) in paired_helpers {
        let Some(committed_share) = result.shares.get(&channel.id) else {
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
        )?;
        transport.send(&channel.transport, msg.envelope).await?;

        share_store
            .save(
                channel.id,
                Share {
                    secret_id,
                    version,
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
        "secret bag distributed to helpers"
    );

    Ok((version, sent_channels))
}
