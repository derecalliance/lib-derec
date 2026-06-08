// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, PendingAction, SecretKind,
    SecretValue, now_secs,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::pairing::{request, response},
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    CommunicationInfo, ContactMessage, DeRecResult, MessageBody, PairRequestMessage,
    PairResponseMessage, SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;
use std::collections::HashMap;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn handle<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    message: &MessageBody,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match message {
        MessageBody::PairRequest(request) => {
            on_request(channel_id, request, pairing_secret, inbound_trace_id)
        }
        MessageBody::PairResponse(response) => {
            on_response(
                channel_store,
                secret_store,
                channel_id,
                response,
                pairing_secret,
            )
            .await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in pairing message",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = contact.channel_id))
)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    own_transport: &TransportProtocol,
    communication_info: &HashMap<String, String>,
    kind: SenderKind,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
) -> Result<u64> {
    let channel_id = ChannelId(contact.channel_id);

    let endpoint = contact
        .transport_protocol
        .clone()
        .ok_or(Error::InvalidInput(
            "contact message has no transport endpoint",
        ))?;

    let comm_info = build_communication_info(communication_info);
    let result = request::produce(kind, own_transport.clone(), &contact, comm_info)?;

    secret_store
        .save(channel_id, SecretValue::PairingSecret(result.secret_key))
        .await?;

    secret_store
        .save(
            channel_id,
            SecretValue::PairingContact(result.initiator_contact_message),
        )
        .await?;

    channel_store
        .save(crate::types::Channel {
            id: channel_id,
            transport: endpoint.clone(),
            communication_info: peer_communication_info,
            status: crate::types::ChannelStatus::Pending,
            created_at: now_secs(),
            role: kind,
        })
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing request sent");

    let envelope = super::apply_trace_id(result.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;

    Ok(channel_id.0)
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    pairing_secret: &PairingSecretKeyMaterial,
    kind: SenderKind,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let comm_info = build_communication_info(communication_info);
    let resp = response::produce(channel_id, request, pairing_secret, comm_info)?;

    secret_store
        .save(channel_id, SecretValue::SharedKey(resp.shared_key))
        .await?;

    let peer_transport = resp.peer_transport_protocol.clone();

    let status = if kind == SenderKind::Replica {
        crate::types::ChannelStatus::Pending
    } else {
        crate::types::ChannelStatus::Paired
    };

    let peer_communication_info = extract_communication_info(&request.communication_info);

    channel_store
        .save(crate::types::Channel {
            id: channel_id,
            transport: peer_transport,
            communication_info: peer_communication_info.clone(),
            status,
            created_at: now_secs(),
            role: kind,
        })
        .await?;

    secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    transport
        .send(&resp.peer_transport_protocol, envelope)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing complete (responder side)");

    Ok(vec![DeRecEvent::PairingCompleted {
        channel_id,
        kind,
        peer_communication_info,
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let peer_transport_protocol =
        request
            .transport_protocol
            .clone()
            .ok_or(Error::InvalidInput(
                "pair request missing transport endpoint",
            ))?;

    let timestamp = current_timestamp();
    // Rejection short-circuits before channel_id rekey would happen — the
    // channel is being torn down, no shared key is derived, and the
    // requester's `process` exits on the non-Ok status without consulting
    // this field. Leave the rekey slot zeroed to make that explicit.
    let response = PairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        nonce: request.nonce,
        communication_info: build_communication_info(communication_info),
        parameter_range: None,
        timestamp: Some(timestamp),
        channel_id: 0,
    };

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::PairResponse(response))
        .trace_id(trace_id)
        .encrypt_pairing(&request.ecies_public_key)?
        .build()?
        .encode_to_vec();

    transport.send(&peer_transport_protocol, envelope).await?;

    secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing request rejected");

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
fn on_request(
    channel_id: ChannelId,
    request: &PairRequestMessage,
    pairing_secret: &PairingSecretKeyMaterial,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let peer_communication_info = extract_communication_info(&request.communication_info);
    let kind = if request.sender_kind == SenderKind::Owner as i32 {
        SenderKind::Helper
    } else if request.sender_kind == SenderKind::Replica as i32 {
        SenderKind::Replica
    } else {
        SenderKind::Owner
    };

    let action = PendingAction::Pairing {
        channel_id,
        request: request.clone(),
        pairing_secret: pairing_secret.clone(),
        kind,
        peer_communication_info,
        trace_id,
    };

    Ok(vec![DeRecEvent::ActionRequired { channel_id, action }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
async fn on_response<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    channel_id: ChannelId,
    response: &derec_proto::PairResponseMessage,
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<Vec<DeRecEvent>> {
    let contact = match secret_store
        .load(channel_id, SecretKind::PairingContact)
        .await?
    {
        Some(SecretValue::PairingContact(c)) => c,
        _ => {
            return Err(Error::InvalidInput(
                "no pairing contact stored for channel — start must be called first",
            ));
        }
    };

    let result = response::process(&contact, response, pairing_secret)?;

    secret_store
        .save(channel_id, SecretValue::SharedKey(result.shared_key))
        .await?;
    secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await?;
    secret_store
        .remove(channel_id, SecretKind::PairingContact)
        .await?;

    // The local role was committed to the channel record at `start` time;
    // load it now rather than derive it from the peer's response.
    let channel = channel_store.load(channel_id).await?.ok_or(Error::Invariant(
        "channel record missing on pair response — start must be called first",
    ))?;
    let kind = channel.role;

    let status = if kind == SenderKind::Replica {
        crate::types::ChannelStatus::Pending
    } else {
        crate::types::ChannelStatus::Paired
    };

    let peer_communication_info = extract_communication_info(&response.communication_info);

    let mut channel = channel;
    channel.status = status;
    for (k, v) in &peer_communication_info {
        channel.communication_info.insert(k.clone(), v.clone());
    }
    channel_store.save(channel).await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing complete (initiator side)");

    Ok(vec![DeRecEvent::PairingCompleted {
        channel_id,
        kind,
        peer_communication_info,
    }])
}

fn build_communication_info(info: &HashMap<String, String>) -> Option<CommunicationInfo> {
    let entries: Vec<_> = info
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| derec_proto::CommunicationInfoKeyValue {
            key: k.to_owned(),
            value: Some(
                derec_proto::communication_info_key_value::Value::StringValue(v.to_owned()),
            ),
        })
        .collect();

    if entries.is_empty() {
        return None;
    }

    Some(CommunicationInfo {
        communication_info_entries: entries,
    })
}

fn extract_communication_info(info: &Option<CommunicationInfo>) -> HashMap<String, String> {
    let Some(info) = info.as_ref() else {
        return HashMap::new();
    };

    info.communication_info_entries
        .iter()
        .filter_map(|e| {
            if let Some(derec_proto::communication_info_key_value::Value::StringValue(s)) = &e.value
            {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some((e.key.to_owned(), trimmed.to_owned()));
                }
            }
            None
        })
        .collect()
}
