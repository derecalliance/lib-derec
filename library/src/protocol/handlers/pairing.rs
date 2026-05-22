// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, PendingAction, SecretKind,
    SecretValue, now_secs,
};
use crate::{
    Error, Result,
    primitives::pairing::{
        PairingError,
        request::produce as produce_pairing_request_message,
        response::{self as pairing_response},
    },
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    CommunicationInfo, ContactMessage, DeRecMessage, MessageBody, PairRequestMessage, SenderKind,
    StatusEnum, TransportProtocol,
};
use prost::Message;
use std::collections::HashMap;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    message: &[u8],
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<Vec<DeRecEvent>> {
    let outer = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
    let plaintext = derec_cryptography::pairing::envelope::decrypt(
        &outer.message,
        pairing_secret.ecies_secret_key(),
    )
    .map_err(PairingError::PairingEncryption)?;

    match MessageBody::decode_from_vec(&plaintext).map_err(Error::ProtobufDecode)? {
        MessageBody::PairRequest(request) => Ok(on_request(channel_id, &request, pairing_secret)),
        MessageBody::PairResponse(response) => {
            on_response(
                channel_store,
                secret_store,
                channel_id,
                &response,
                pairing_secret,
            )
            .await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in pairing message",
        )),
    }
}

/// Initiate pairing by sending a PairRequest to the peer.
///
/// Returns the `channel_id` extracted from the contact.
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
    let result = produce_pairing_request_message(kind, own_transport.clone(), &contact, comm_info)?;

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
        })
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing request sent");

    transport.send(&endpoint, result.envelope).await?;
    Ok(channel_id.0)
}

/// Accept a pairing request: compute shared key and send success response.
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
    response_kind: SenderKind,
) -> Result<Vec<DeRecEvent>> {
    let comm_info = build_communication_info(communication_info);
    let resp = pairing_response::accept(response_kind, request, pairing_secret, comm_info)?;

    secret_store
        .save(channel_id, SecretValue::SharedKey(resp.shared_key))
        .await?;

    let peer_transport = resp.peer_transport_protocol.clone();

    let status = if kind == SenderKind::Replica {
        crate::types::ChannelStatus::Pending
    } else {
        crate::types::ChannelStatus::Paired
    };

    // Persist the peer's communication_info verbatim on the channel — opaque
    // to the protocol, available to the app. App-level identity heuristics
    // (e.g. the backend provisioned actor's auto-link by display name on
    // re-pairing) read from this map; the protocol does not.
    let peer_communication_info = extract_communication_info(&request.communication_info);

    channel_store
        .save(crate::types::Channel {
            id: channel_id,
            transport: peer_transport,
            communication_info: peer_communication_info.clone(),
            status,
            created_at: now_secs(),
        })
        .await?;

    secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await?;

    transport
        .send(&resp.peer_transport_protocol, resp.envelope)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing complete (responder side)");

    Ok(vec![DeRecEvent::PairingCompleted {
        channel_id,
        kind,
        peer_communication_info,
    }])
}

/// Reject a pairing request: send FAIL response.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn reject<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    response_kind: SenderKind,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let comm_info = build_communication_info(communication_info);
    let result =
        pairing_response::reject(response_kind, request, status, memo, comm_info)?;

    transport
        .send(&result.peer_transport_protocol, result.envelope)
        .await?;

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
) -> Vec<DeRecEvent> {
    let peer_communication_info = extract_communication_info(&request.communication_info);
    let (response_kind, kind) = if request.sender_kind == SenderKind::Owner as i32 {
        (SenderKind::Helper, SenderKind::Helper)
    } else if request.sender_kind == SenderKind::Replica as i32 {
        (SenderKind::Replica, SenderKind::Replica)
    } else {
        (SenderKind::Owner, SenderKind::Owner)
    };

    let action = PendingAction::Pairing {
        channel_id,
        request: request.clone(),
        pairing_secret: pairing_secret.clone(),
        kind,
        response_kind,
        peer_communication_info,
    };

    vec![DeRecEvent::ActionRequired { channel_id, action }]
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

    let result = pairing_response::process(&contact, response, pairing_secret)?;

    secret_store
        .save(channel_id, SecretValue::SharedKey(result.shared_key))
        .await?;
    secret_store
        .remove(channel_id, SecretKind::PairingSecret)
        .await?;
    secret_store
        .remove(channel_id, SecretKind::PairingContact)
        .await?;

    let kind = if response.sender_kind == SenderKind::Helper as i32 {
        SenderKind::Owner
    } else if response.sender_kind == SenderKind::Replica as i32 {
        SenderKind::Replica
    } else {
        SenderKind::Helper
    };

    // Transition channel from Pending to Paired (replicas stay Pending until
    // fingerprint verification).
    let status = if kind == SenderKind::Replica {
        crate::types::ChannelStatus::Pending
    } else {
        crate::types::ChannelStatus::Paired
    };

    let peer_communication_info = extract_communication_info(&response.communication_info);

    if let Some(mut channel) = channel_store.load(channel_id).await? {
        channel.status = status;
        // The peer's self-attested communication_info (from the wire pair-
        // response) is more authoritative than whatever the app guessed at
        // pair-start (often `{}` for QR-paste flows). Merge into the channel
        // record so any name/identity keys the peer sends are persisted —
        // and end up inside `HelperInfo.communication_info` at protect time.
        // App-only entries the initiator added pre-pair survive untouched
        // unless the peer happens to use the same key.
        for (k, v) in &peer_communication_info {
            channel.communication_info.insert(k.clone(), v.clone());
        }
        channel_store.save(channel).await?;
    }

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
            value: Some(derec_proto::communication_info_key_value::Value::StringValue(v.to_owned())),
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
