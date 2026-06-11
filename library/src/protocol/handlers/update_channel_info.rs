// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, MissingPolicy, PendingAction,
    SecretKind, SecretValue,
};
use super::{peer_endpoint, resolve_target};
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::{
    Error, Result,
    protocol::types::Target,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    CommunicationInfo, DeRecResult, MessageBody, StatusEnum, TransportProtocol,
    UpdateChannelInfoRequestMessage, UpdateChannelInfoResponseMessage,
};
use prost::Message;
use std::collections::HashMap;

const EMPTY_UPDATE_ERROR: Error = Error::InvalidInput(
    "UpdateChannelInfo requires at least one of communication_info or transport_protocol",
);

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle(
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UpdateChannelInfoRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::UpdateChannelInfoResponse(response) => on_response(channel_id, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in update_channel_info handler",
        )),
    }
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    target: Target,
    communication_info: Option<HashMap<String, String>>,
    transport_protocol: Option<TransportProtocol>,
) -> Result<()> {
    if communication_info.is_none() && transport_protocol.is_none() {
        return Err(EMPTY_UPDATE_ERROR);
    }

    let channel_ids = resolve_target(channel_store, target).await?;
    if channel_ids.is_empty() {
        return Ok(());
    }

    let keys = secret_store
        .load_many(&channel_ids, SecretKind::SharedKey, MissingPolicy::Fail)
        .await?;

    let comm_info_proto = communication_info
        .as_ref()
        .map(build_communication_info_proto);

    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            continue;
        };

        let timestamp = current_timestamp();
        let request = UpdateChannelInfoRequestMessage {
            communication_info: comm_info_proto.clone(),
            transport_protocol: transport_protocol.clone(),
            timestamp: Some(timestamp),
        };
        let envelope = DeRecMessageBuilder::channel()
            .channel_id(channel_id)
            .timestamp(timestamp)
            .message_body(MessageBody::UpdateChannelInfoRequest(request))
            .auto_trace_id()
            .encrypt(&shared_key)?
            .build()?
            .encode_to_vec();

        let endpoint = peer_endpoint(channel_store, channel_id).await?;
        transport.send(&endpoint, envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            has_communication_info = comm_info_proto.is_some(),
            has_transport_protocol = transport_protocol.is_some(),
            "update_channel_info request sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!("update_channel_info requests dispatched");

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn accept<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    request: &UpdateChannelInfoRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    // Apply the update to the stored channel first, so the response we send
    // below is routed to the (possibly updated) transport endpoint.
    let mut channel = channel_store
        .load(channel_id)
        .await?
        .ok_or(Error::InvalidInput(
            "channel id not present in channel store",
        ))?;

    #[cfg(feature = "logging")]
    let communication_info_updated = request.communication_info.is_some();
    #[cfg(feature = "logging")]
    let transport_protocol_updated = request.transport_protocol.is_some();

    if let Some(ci) = request.communication_info.as_ref() {
        channel.communication_info = extract_communication_info(ci);
    }
    if let Some(tp) = request.transport_protocol.clone() {
        channel.transport = tp;
    }

    channel_store.save(channel).await?;

    let timestamp = current_timestamp();
    let response = UpdateChannelInfoResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UpdateChannelInfoResponse(response))
        .trace_id(trace_id)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        communication_info_updated,
        transport_protocol_updated,
        "update_channel_info applied; Ok response sent"
    );

    Ok(vec![DeRecEvent::ChannelInfoUpdated { channel_id }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, status = status as i32))
)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let timestamp = current_timestamp();
    let response = UpdateChannelInfoResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UpdateChannelInfoResponse(response))
        .trace_id(trace_id)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    let endpoint = peer_endpoint(channel_store, channel_id).await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("update_channel_info rejected");

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: UpdateChannelInfoRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    if request.communication_info.is_none() && request.transport_protocol.is_none() {
        return Err(EMPTY_UPDATE_ERROR);
    }

    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::UpdateChannelInfo {
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
    response: &UpdateChannelInfoResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let result = response.result.as_ref().ok_or(Error::Invariant(
        "update_channel_info response missing result",
    ))?;

    if result.status == StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::info!(
            channel_id = channel_id.0,
            "update_channel_info acknowledged"
        );
        Ok(vec![DeRecEvent::ChannelInfoUpdated { channel_id }])
    } else {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            status = result.status,
            memo = %result.memo,
            "update_channel_info rejected by peer"
        );
        Ok(vec![DeRecEvent::ChannelInfoUpdateRejected {
            channel_id,
            status: result.status,
            memo: result.memo.clone(),
        }])
    }
}

fn build_communication_info_proto(info: &HashMap<String, String>) -> CommunicationInfo {
    let entries: Vec<_> = info
        .iter()
        .map(|(k, v)| derec_proto::CommunicationInfoKeyValue {
            key: k.to_owned(),
            value: Some(
                derec_proto::communication_info_key_value::Value::StringValue(v.to_owned()),
            ),
        })
        .collect();
    CommunicationInfo {
        communication_info_entries: entries,
    }
}

fn extract_communication_info(info: &CommunicationInfo) -> HashMap<String, String> {
    info.communication_info_entries
        .iter()
        .filter_map(|e| {
            if let Some(derec_proto::communication_info_key_value::Value::StringValue(s)) = &e.value
            {
                Some((e.key.to_owned(), s.to_owned()))
            } else {
                None
            }
        })
        .collect()
}
