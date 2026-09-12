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
    "UpdateChannelInfo requires at least one of communication_info or transport_protocol",
);

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match decide(local, exchange, inner) {
        // Unlike pairing, the channel is already established: this side
        // still holds the peer's previous, working endpoint, so the refusal
        // can be sent back over it instead of only surfacing as a local
        // error the peer never learns about.
        Err(Error::NoUsableEndpoint { offered }) => {
            let memo = format!(
                "peer announced no usable transport endpoint — all \
                 {offered} offer(s) were refused by transport policy"
            );
            reject(
                stores,
                local,
                exchange,
                StatusEnum::UnsupportedTransportProtocol,
                &memo,
            )
            .await?;
            Ok(vec![DeRecEvent::UpdateChannelInfoFailed {
                channel_id: exchange.channel_id,
                error: memo,
            }])
        }
        other => other,
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
// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
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
    let transport_protocol_updated = request.transport_protocol.is_some();

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

fn decide(
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::UpdateChannelInfoRequest(request) => {
            let own = local
                .own_transports
                .iter()
                .map(crate::transport::TransportProtocol::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()?;
            on_request(exchange, request, &own)
        }
        MessageBody::UpdateChannelInfoResponse(response) => on_response(exchange, &response),
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in update_channel_info handler",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
fn on_request(
    exchange: &Exchange<'_>,
    request: UpdateChannelInfoRequestMessage,
    own_transports: &[crate::transport::TransportProtocol],
) -> Result<Vec<DeRecEvent>> {
    if request.communication_info.is_none() && request.transport_protocol.is_none() {
        return Err(EMPTY_UPDATE_ERROR);
    }

    // Structure, then servability. An endpoint this side cannot serve is
    // refused rather than recorded: following the switch would leave the
    // peer unreachable with no way to discover that. Structural validation
    // (scheme consistency, whose policy acceptability was already settled
    // by `TransportPolicy` in `handlers::handle`) runs first, so a
    // malformed endpoint is reported as malformed rather than unservable.
    if let Some(tp) = request.transport_protocol.as_ref() {
        tp.validate()?;

        let protocol = derec_proto::Protocol::try_from(tp.protocol).map_err(|_| {
            crate::transport::TransportValidationError::UnsupportedProtocol {
                discriminant: tp.protocol,
            }
        })?;

        if !own_transports.iter().any(|t| t.protocol == protocol) {
            return Err(crate::Error::NoUsableEndpoint { offered: 1 });
        }
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

// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
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
        // The first entry also fills the deprecated singular field so a
        // receiver predating `supportedTransports` still learns the new
        // address. Same rule every other pairing-time message follows.
        transport_protocol: own_transports.first().cloned(),
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

    /// A peer-supplied `UpdateChannelInfoRequest.transport_protocol`
    /// declaring `Protocol::Https` but carrying a URI with an
    /// unsupported scheme is rejected by the handler before any
    /// side-effecting action is surfaced — the gate runs after the
    /// must-update-something invariant and before the `ActionRequired`
    /// event. (`http://` is intentionally accepted as a dev-mode
    /// affordance and is flagged via `tracing::warn!`; see
    /// `crate::transport`.)
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn on_request_rejects_scheme_mismatched_transport_protocol() {
        let channel_id = ChannelId(31);
        let shared_key = [11u8; 32];

        let malicious_transport = derec_proto::TransportProtocol {
            uri: "ws://attacker.example/inbox".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        };

        let request = UpdateChannelInfoRequestMessage {
            supported_transports: Vec::new(),
            communication_info: None,
            transport_protocol: Some(malicious_transport),
            timestamp: Some(current_timestamp()),
        };

        let result = on_request(
            &Exchange {
                channel_id,
                shared_key: &shared_key,
                trace_id: 0,
            },
            request,
            &[],
        );

        assert!(matches!(
            result,
            Err(Error::Transport(
                crate::transport::TransportValidationError::SchemeMismatch { .. }
            ))
        ));
    }

    /// A peer announcing a switch to a transport this side cannot serve is
    /// refused rather than followed. Unlike the pairing case, the refusal is
    /// deliverable: the channel is up, so the peer's previous endpoint still
    /// works.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn on_request_refuses_an_unservable_transport_change() {
        let own = vec![crate::transport::TransportProtocol::new(
            "https://me.example.com/derec",
            derec_proto::Protocol::Https,
        )];
        let request = UpdateChannelInfoRequestMessage {
            supported_transports: Vec::new(),
            communication_info: None,
            transport_protocol: Some(derec_proto::TransportProtocol {
                uri: "grpcs://peer.example.com:443".to_owned(),
                protocol: derec_proto::Protocol::Grpc as i32,
            }),
            timestamp: None,
        };

        let result = on_request(
            &Exchange {
                channel_id: ChannelId(1),
                shared_key: &[0u8; 32],
                trace_id: 0,
            },
            request,
            &own,
        );
        assert!(matches!(result, Err(crate::Error::NoUsableEndpoint { .. })));
    }

    /// A switch to a transport this side does serve is still accepted.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn on_request_accepts_a_servable_transport_change() {
        let own = vec![
            crate::transport::TransportProtocol::new(
                "https://me.example.com/derec",
                derec_proto::Protocol::Https,
            ),
            crate::transport::TransportProtocol::new(
                "grpcs://me.example.com:443",
                derec_proto::Protocol::Grpc,
            ),
        ];
        let request = UpdateChannelInfoRequestMessage {
            supported_transports: Vec::new(),
            communication_info: None,
            transport_protocol: Some(derec_proto::TransportProtocol {
                uri: "grpcs://peer.example.com:443".to_owned(),
                protocol: derec_proto::Protocol::Grpc as i32,
            }),
            timestamp: None,
        };

        assert!(
            on_request(
                &Exchange {
                    channel_id: ChannelId(1),
                    shared_key: &[0u8; 32],
                    trace_id: 0
                },
                request,
                &own
            )
            .is_ok()
        );
    }
}
