// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, MissingPolicy, PendingAction,
    SecretKind, SecretValue,
};
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::extensions::advertised_endpoints::AdvertisedEndpoints as _;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::communication_info::CommunicationInfoExt as _;
use crate::extensions::derec_result::DeRecResultExt as _;
use crate::extensions::transport_protocol::TransportProtocolExt as _;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::stores::{StoreSet, Stores};
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
    "UpdateChannelInfo requires at least one of communication_info or supported_transports",
);

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    _stores: &mut Stores<'_, S>,
    _local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UpdateChannelInfoRequest(request) => on_request(exchange, request),
        MessageBody::UpdateChannelInfoResponse(response) => on_response(exchange, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in update_channel_info handler",
        )),
    }
}

#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = trace_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    target: Target,
    communication_info: Option<HashMap<String, String>>,
    own_transports: Vec<TransportProtocol>,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    if communication_info.is_none() && own_transports.is_empty() {
        return Err(EMPTY_UPDATE_ERROR);
    }

    let channel_ids = stores
        .channels
        .resolve_target(local.secret_id, target)
        .await?;
    if channel_ids.is_empty() {
        return Ok(Vec::new());
    }

    let keys = stores
        .secrets
        .load_many(
            local.secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    let comm_info_proto = communication_info.as_ref().map(CommunicationInfo::from_map);

    let events = dispatch_all(
        stores,
        local,
        keys,
        comm_info_proto,
        own_transports,
        trace_id,
    )
    .await;

    #[cfg(feature = "logging")]
    tracing::info!("update_channel_info requests dispatched");

    Ok(events)
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &UpdateChannelInfoRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;
    let channel = stores
        .channels
        .load(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?
        .ok_or(Error::InvalidInput(
            "channel id not present in channel store",
        ))?;

    #[cfg(feature = "logging")]
    let communication_info_updated = request.communication_info.is_some();
    #[cfg(feature = "logging")]
    let transport_protocol_updated = !request.supported_transports.is_empty();

    let new_info = request
        .communication_info
        .as_ref()
        .map(CommunicationInfo::to_map);
    let advertised = request.advertised_endpoints();
    let new_transport = if advertised.is_empty() {
        // An update that changes only `communication_info` says nothing
        // about transports, so the stored set is left alone.
        None
    } else {
        Some(local.policy.admit_peer_endpoints(advertised)?)
    };

    // Either record kind can carry an endpoint change; the fields live on the
    // variants rather than the enum.
    let channel = match channel {
        crate::protocol::types::ChannelRecord::Helper(mut h) => {
            if let Some(ci) = new_info {
                h.communication_info = ci;
            }
            if let Some(tps) = new_transport.clone() {
                h.transports = tps;
            }
            crate::protocol::types::ChannelRecord::Helper(h)
        }
        crate::protocol::types::ChannelRecord::Replica(mut r) => {
            if let Some(ci) = new_info {
                r.communication_info = ci;
            }
            if let Some(tps) = new_transport {
                r.transports = tps;
            }
            crate::protocol::types::ChannelRecord::Replica(r)
        }
    };

    stores.channels.save(secret_id, channel).await?;

    let timestamp = current_timestamp();
    let response = UpdateChannelInfoResponseMessage {
        result: Some(DeRecResult::ok()),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UpdateChannelInfoResponse(response))
        .trace_id(exchange.trace_id)
        .encrypt(exchange.shared_key)?
        .build()?
        .encode_to_vec();

    let endpoint = stores
        .channels
        .peer_endpoints(secret_id, channel_id)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

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
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0, status = status as i32))
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    status: StatusEnum,
    memo: &str,
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
        .channel_id(exchange.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UpdateChannelInfoResponse(response))
        .trace_id(exchange.trace_id)
        .encrypt(exchange.shared_key)?
        .build()?
        .encode_to_vec();

    let endpoint = stores
        .channels
        .peer_endpoints(local.secret_id, exchange.channel_id)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("update_channel_info rejected");

    Ok(())
}

/// Receives a peer's update and asks the application to accept it.
///
/// Every announced endpoint must be well-formed. Which of them this device
/// records is decided on acceptance by the transport policy, as in pairing:
/// a peer's endpoints say where the peer listens, not what this device must
/// serve.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_request(
    exchange: &Exchange<'_>,
    request: UpdateChannelInfoRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    if request.communication_info.is_none() && request.supported_transports.is_empty() {
        return Err(EMPTY_UPDATE_ERROR);
    }

    for tp in &request.supported_transports {
        tp.validate()?;
    }

    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::UpdateChannelInfo {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_response(
    exchange: &Exchange<'_>,
    response: &UpdateChannelInfoResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let result = response.result.as_ref().ok_or(Error::Invariant(
        "update_channel_info response missing result",
    ))?;

    if result.status == StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::info!(
            exchange.channel_id = exchange.channel_id.0,
            "update_channel_info acknowledged"
        );
        Ok(vec![DeRecEvent::ChannelInfoUpdated {
            channel_id: exchange.channel_id,
        }])
    } else {
        #[cfg(feature = "logging")]
        tracing::warn!(
            exchange.channel_id = exchange.channel_id.0,
            status = result.status,
            memo = %result.memo,
            "update_channel_info rejected by peer"
        );
        Ok(vec![DeRecEvent::ChannelInfoUpdateRejected {
            channel_id: exchange.channel_id,
            status: result.status,
            memo: result.memo.clone(),
        }])
    }
}

/// Send an update to every resolved channel, reporting each outcome.
///
/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes an `UpdateChannelInfoFailed` and the
/// fan-out continues.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    keys: Vec<(ChannelId, SecretValue)>,
    comm_info_proto: Option<CommunicationInfo>,
    own_transports: Vec<TransportProtocol>,
    trace_id: u64,
) -> Vec<DeRecEvent> {
    let mut events = Vec::with_capacity(keys.len());
    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            events.push(DeRecEvent::UpdateChannelInfoFailed {
                channel_id,
                error: "channel has no shared key".to_owned(),
            });
            continue;
        };

        match dispatch_one(
            stores,
            local,
            channel_id,
            &shared_key,
            comm_info_proto.clone(),
            own_transports.clone(),
            trace_id,
        )
        .await
        {
            Ok(()) => {
                events.push(DeRecEvent::UpdateChannelInfoStarted {
                    channel_id,
                    trace_id,
                });
                #[cfg(feature = "logging")]
                tracing::debug!(
                    channel_id = channel_id.0,
                    has_communication_info = comm_info_proto.is_some(),
                    advertised_transports = own_transports.len(),
                    "update_channel_info request sent"
                );
            }
            Err(e) => {
                events.push(DeRecEvent::UpdateChannelInfoFailed {
                    channel_id,
                    error: e.to_string(),
                });
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    error = %e,
                    "update_channel_info dispatch failed"
                );
            }
        }
    }
    events
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    communication_info: Option<CommunicationInfo>,
    own_transports: Vec<TransportProtocol>,
    trace_id: u64,
) -> Result<()> {
    let timestamp = current_timestamp();
    let request = UpdateChannelInfoRequestMessage {
        communication_info,
        supported_transports: own_transports,
        timestamp: Some(timestamp),
    };
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::UpdateChannelInfoRequest(request))
        .trace_id(trace_id)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    let endpoint = stores
        .channels
        .peer_endpoints(local.secret_id, channel_id)
        .await?;
    stores.transport.send(&endpoint, envelope).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derec_message::current_timestamp;
    use crate::protocol::context::Exchange;

    /// A peer-supplied `UpdateChannelInfoRequest.supported_transports` entry
    /// declaring `Protocol::Https` but carrying a URI with an
    /// unsupported scheme is rejected by the handler before any
    /// side-effecting action is surfaced — the gate runs after the
    /// must-update-something invariant and before the `ActionRequired`
    /// event. (`http://` is intentionally accepted as a dev-mode
    /// affordance and is flagged via `tracing::warn!`; see
    /// `crate::transport`.)
    #[test]
    fn on_request_rejects_scheme_mismatched_transport_protocol() {
        let channel_id = ChannelId(31);
        let shared_key = [11u8; 32];

        let malicious_transport = derec_proto::TransportProtocol {
            uri: "ws://attacker.example/inbox".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        };

        let request = UpdateChannelInfoRequestMessage {
            supported_transports: vec![malicious_transport],
            communication_info: None,
            timestamp: Some(current_timestamp()),
        };

        let result = on_request(
            &Exchange {
                channel_id,
                shared_key: &shared_key,
                trace_id: 0,
            },
            request,
        );

        assert!(matches!(
            result,
            Err(Error::Transport(
                crate::transport::TransportValidationError::SchemeMismatch { .. }
            ))
        ));
    }

    /// Which transports this device serves has no bearing on where a peer
    /// may listen. A node serving only gRPC accepts a peer's move to HTTPS,
    /// as pairing would record it, and replies on the new endpoint once the
    /// application accepts.
    #[test]
    fn a_peer_may_move_to_a_transport_this_node_does_not_serve() {
        use crate::protocol::test::{LocalFixture, StoreRig, run_async};
        use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};

        run_async(async {
            let channel_id = ChannelId(41);
            let shared_key = [7u8; 32];
            let lf = LocalFixture {
                own_transports: vec![derec_proto::TransportProtocol {
                    uri: "grpcs://me.example.com:443".to_owned(),
                    protocol: derec_proto::Protocol::Grpc as i32,
                }],
                ..LocalFixture::new(0x0C1)
            };
            let mut rig = StoreRig::new();
            rig.channels
                .save(
                    lf.secret_id,
                    ChannelRecord::Helper(HelperChannel {
                        channel_id,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "grpcs://peer.example.com:443".to_owned(),
                            protocol: derec_proto::Protocol::Grpc as i32,
                        }],
                        communication_info: HashMap::new(),
                        peer_role: derec_proto::SenderKind::Owner,
                        status: ChannelStatus::Paired,
                        created_at: 0,
                    }),
                )
                .await
                .expect("seed channel");
            let moved_to = derec_proto::TransportProtocol {
                uri: "https://peer.example.com/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            };
            let request = UpdateChannelInfoRequestMessage {
                supported_transports: vec![moved_to.clone()],
                communication_info: None,
                timestamp: Some(current_timestamp()),
            };
            let exchange = Exchange {
                channel_id,
                shared_key: &shared_key,
                trace_id: 0,
            };

            let events = handle(
                &mut rig.stores(),
                &lf.local(),
                &exchange,
                MessageBody::UpdateChannelInfoRequest(request.clone()),
            )
            .await
            .expect("handle");
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::ActionRequired {
                        action: PendingAction::UpdateChannelInfo { .. },
                        ..
                    }]
                ),
                "the move must be surfaced for acceptance, not refused: {events:?}"
            );
            assert!(
                rig.transport.sent_envelopes().is_empty(),
                "no refusal is sent"
            );

            accept(&mut rig.stores(), &lf.local(), &exchange, &request)
                .await
                .expect("accept");
            let stored = rig
                .channels
                .load(
                    lf.secret_id,
                    crate::protocol::types::ChannelQuery::Helper { channel_id },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_helper().cloned())
                .expect("channel present");
            assert_eq!(stored.transports, vec![moved_to.clone()]);
            assert_eq!(rig.transport.sent_endpoint_sets(), vec![vec![moved_to]]);
        });
    }
}
