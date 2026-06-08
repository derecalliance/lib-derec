// SPDX-License-Identifier: Apache-2.0

// TODO: revisit accept vs accept_pre_pair, idem for reject and on_request/on_response. We should
// be able to come up with a single set of functions

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
    CommunicationInfo, ContactMessage, ContactMode, DeRecResult, MessageBody, PairRequestMessage,
    PairResponseMessage, PrePairRequestMessage, PrePairResponseMessage, SenderKind, StatusEnum,
    TransportProtocol,
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
        MessageBody::PrePairRequest(request) => {
            on_pre_pair_request(channel_id, request, inbound_trace_id)
        }
        // `PrePairResponse` is handled outside this entry point — its
        // state requirements (the original contact, not `pairing_secret`)
        // don't fit `handle`'s signature. See
        // [`on_pre_pair_response`] for the scanner-side path.
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in pairing message",
        )),
    }
}

/// Scanner-side entry point for the pairing flow. Branches on
/// `contact.contact_mode` to either send a regular [`PairRequest`]
/// ([`ContactMode::InlineKeys`]) or kick off the PrePair leg first
/// ([`ContactMode::HashedKeys`]).
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

    if contact.contact_mode == ContactMode::HashedKeys as i32 {
        start_hashed_keys(
            channel_store,
            secret_store,
            transport,
            own_transport,
            channel_id,
            contact,
            peer_communication_info,
            endpoint,
            kind,
        )
        .await
    } else {
        start_inlined_keys(
            channel_store,
            secret_store,
            transport,
            own_transport,
            communication_info,
            channel_id,
            contact,
            peer_communication_info,
            endpoint,
            kind,
        )
        .await
    }
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
    let peer_transport_protocol = request
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

/// Inbound `PrePairResponse` on the **scanner side**. Validates the
/// published keys against the stored contact's `contact_binding_hash`,
/// synthesizes a filled-in `InlineKeys`-shaped contact, and auto-proceeds
/// to a regular `PairRequest`.
///
/// PrePair success is invisible to the application on this side — the
/// next event the app sees is `PairingCompleted` once the PairResponse
/// round-trip lands. Failure surfaces as either a [`PrePairRejected`]
/// event (non-Ok status on the response) or a
/// [`crate::primitives::pairing::PairingError::PrePairHashMismatch`]
/// error (binding-hash mismatch).
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn on_pre_pair_response<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    own_transport: &TransportProtocol,
    communication_info: &HashMap<String, String>,
    channel_id: ChannelId,
    original_contact: &ContactMessage,
    response: &PrePairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    // `process_pre_pair` rejects malformed or non-Ok responses — surface
    // the status mismatch as an event the app can react to, propagate the
    // hash mismatch (security-relevant), and let any other error bubble.
    let validated = match response::process_pre_pair(original_contact, response) {
        Ok(v) => v,
        Err(Error::Pairing(crate::primitives::pairing::PairingError::NonOkStatus {
            status,
            memo,
        })) => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                status,
                memo = %memo,
                "PrePair rejected by initiator"
            );

            return Ok(vec![DeRecEvent::PrePairRejected {
                channel_id,
                status,
                memo,
            }]);
        }
        Err(e) => return Err(e),
    };

    // Hash matched — synthesize the filled-in contact in InlineKeys
    // shape. `request::produce` enforces the InlineKeys invariant, so
    // the mode flip and hash clear are both required.
    let filled_in_contact = ContactMessage {
        mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
        ecies_public_key: Some(validated.ecies_public_key),
        contact_mode: ContactMode::InlineKeys as i32,
        contact_binding_hash: None,
        ..original_contact.clone()
    };

    // Drive the regular PairRequest leg. The scanner's role on the
    // channel was committed at `start` time; preserve it.
    let role = channel_store
        .load(channel_id)
        .await?
        .ok_or(Error::Invariant(
            "channel record missing on PrePair response — start must be called first",
        ))?
        .role;

    let comm_info = build_communication_info(communication_info);
    let result = request::produce(role, own_transport.clone(), &filled_in_contact, comm_info)?;

    // Persist the scanner's pairing secret + overwrite the stored
    // contact with the filled-in version. `pair_response::process`
    // later reads back the InlineKeys-shaped contact to verify keys.
    secret_store
        .save(channel_id, SecretValue::PairingSecret(result.secret_key))
        .await?;
    secret_store
        .save(
            channel_id,
            SecretValue::PairingContact(result.initiator_contact_message),
        )
        .await?;

    let endpoint = original_contact
        .transport_protocol
        .clone()
        .ok_or(Error::Invariant(
            "stored contact missing transport_protocol on PrePair response",
        ))?;
    let envelope = super::apply_trace_id(result.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        "PrePair validated; PairRequest sent (HASHED_KEYS scanner side)"
    );

    // PrePair success is silent on the scanner side. The app sees
    // `PairingCompleted` later when the PairResponse arrives.
    Ok(vec![])
}

/// `accept` arm for [`PendingAction::PrePair`]. Loads the initiator's
/// `PairingSecret`, builds a `PrePairResponse` carrying the real keys,
/// and sends it back to the scanner's `replyTo` endpoint embedded in
/// the request.
pub(in crate::protocol) async fn accept_pre_pair<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let Some(SecretValue::PairingSecret(pairing_secret)) = secret_store
        .load(channel_id, SecretKind::PairingSecret)
        .await?
    else {
        return Err(Error::Invariant(
            "PrePair accept: missing PairingSecret (initiator state lost)",
        ));
    };

    let result = response::produce_pre_pair(channel_id, request, &pairing_secret)?;
    let envelope = super::apply_trace_id(result.envelope, trace_id)?;

    let endpoint = request
        .transport_protocol
        .clone()
        .ok_or(Error::InvalidInput(
            "PrePair request missing transport endpoint",
        ))?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        "PrePair accepted; published keys sent to scanner"
    );

    // Success is silent on this side too. The next inbound is the
    // regular PairRequest, which will surface its own `ActionRequired`.
    Ok(vec![])
}

/// `reject` arm for [`PendingAction::PrePair`]. Builds a non-Ok
/// `PrePairResponse` (no keys) and sends it to the scanner's `replyTo`.
/// Does NOT load `PairingSecret` — rejection carries no crypto material.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject_pre_pair<T: DeRecTransport>(
    transport: &T,
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let endpoint = request
        .transport_protocol
        .clone()
        .ok_or(Error::InvalidInput(
            "PrePair request missing transport endpoint",
        ))?;

    let timestamp = current_timestamp();
    let response = PrePairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        // Non-Ok responses MUST NOT carry keys (per `prepair.proto`).
        mlkem_encapsulation_key: None,
        ecies_public_key: None,
        nonce: request.nonce,
        timestamp: Some(timestamp.clone()),
    };

    // PrePair envelopes are plaintext — wrap the inner body directly.
    use crate::protocol_version::ProtocolVersion;
    use derec_proto::DeRecMessage;
    let protocol_version = ProtocolVersion::current();
    let envelope = DeRecMessage {
        protocol_version_major: protocol_version.major,
        protocol_version_minor: protocol_version.minor,
        sequence: 0,
        channel_id: channel_id.into(),
        timestamp: Some(timestamp),
        message: MessageBody::PrePairResponse(response).encode_to_vec(),
        trace_id,
    }
    .encode_to_vec();

    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        status = status as i32,
        "PrePair rejected by initiator"
    );

    Ok(())
}

/// Scanner-side `InlineKeys` branch of [`start`]. The responder has the
/// initiator's public keys inline on the contact, so it can go straight
/// to building the encrypted `PairRequest` envelope.
#[allow(clippy::too_many_arguments)]
async fn start_inlined_keys<Ch: DeRecChannelStore, Ss: DeRecSecretStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    own_transport: &TransportProtocol,
    communication_info: &HashMap<String, String>,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoint: TransportProtocol,
    kind: SenderKind,
) -> Result<u64> {
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

/// Scanner-side `HashedKeys` branch of [`start`]. Saves the original
/// contact via `PairingContact` (we'll re-read it when the
/// `PrePairResponse` arrives to validate the binding hash), sends a
/// plaintext `PrePairRequest`, and leaves the channel `Pending`. No
/// `PairingSecret` is saved yet — the scanner has no responder-side
/// key material until the PrePair leg completes and the regular
/// PairRequest is produced.
#[allow(clippy::too_many_arguments)]
async fn start_hashed_keys<Ch: DeRecChannelStore, Ss: DeRecSecretStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    own_transport: &TransportProtocol,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoint: TransportProtocol,
    kind: SenderKind,
) -> Result<u64> {
    let result = request::produce_pre_pair_request(own_transport.clone(), &contact)?;

    // Persist the original HashedKeys contact so the eventual
    // PrePairResponse can be validated against its binding hash.
    secret_store
        .save(channel_id, SecretValue::PairingContact(contact))
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
    tracing::info!("PrePair request sent (HASHED_KEYS scanner side)");

    let envelope = super::apply_trace_id(result.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;

    Ok(channel_id.0)
}

/// Inbound `PrePairRequest` on the **initiator side** (the party that
/// created the HashedKeys contact and saved its `PairingSecret`).
///
/// Pure function — surfaces an [`ActionRequired`] event. The application
/// decides whether to accept (publish the keys) or reject (refuse to
/// participate) by calling [`super::super::DeRecProtocol::accept`] or
/// [`reject`](super::super::DeRecProtocol::reject) with the carried
/// [`PendingAction::PrePair`].
fn on_pre_pair_request(
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::PrePair {
            channel_id,
            request: request.clone(),
            trace_id,
        },
    }])
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
    let channel = channel_store
        .load(channel_id)
        .await?
        .ok_or(Error::Invariant(
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
