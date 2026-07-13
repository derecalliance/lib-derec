// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, PendingAction, SecretKind,
    SecretValue, now_secs,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::pairing::{PairingError, request, response},
    protocol::reserved_keys,
    types::ChannelId,
    utils::{ContactMessageExt as _, SenderKindExt as _},
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
pub(in crate::protocol) async fn handle<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    message: &MessageBody,
    secret_id: u64,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
    inbound_trace_id: u64,
    replica_id: Option<u64>,
    parameter_range: Option<&derec_proto::ParameterRange>,
) -> Result<Vec<DeRecEvent>> {
    match message {
        MessageBody::PairRequest(request) => {
            if let Err(err) = crate::primitives::pairing::parameter_range::check_compatibility(
                parameter_range,
                request.parameter_range.as_ref(),
            ) {
                reject(
                    secret_store,
                    transport,
                    communication_info,
                    secret_id,
                    channel_id,
                    request,
                    StatusEnum::IncompatibleParameterRange,
                    &err.to_string(),
                    inbound_trace_id,
                )
                .await?;
                return Err(err.into());
            }
            on_request(
                channel_id,
                request,
                pairing_secret,
                inbound_trace_id,
                replica_id,
            )
        }
        MessageBody::PairResponse(response) => {
            on_response(
                channel_store,
                secret_store,
                secret_id,
                channel_id,
                response,
                pairing_secret,
                replica_id,
                parameter_range,
            )
            .await
        }
        MessageBody::PrePairRequest(request) => {
            on_pre_pair_request(channel_id, request, inbound_trace_id)
        }
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
#[allow(clippy::too_many_arguments)]
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
    secret_id: u64,
    kind: SenderKind,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
) -> Result<u64> {
    let replica_id_to_inject = require_replica_id_for_kind(kind, replica_id)?;

    let channel_id = ChannelId(contact.channel_id);

    let endpoint = contact
        .transport_protocol
        .clone()
        .ok_or(Error::InvalidInput(
            "contact message has no transport endpoint",
        ))?;
    let _ = crate::transport::TransportProtocol::try_from(&endpoint)?;

    if contact.requires_pre_pair() {
        start_pre_pair(
            channel_store,
            secret_store,
            transport,
            own_transport,
            secret_id,
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
            secret_id,
            channel_id,
            contact,
            peer_communication_info,
            endpoint,
            kind,
            replica_id_to_inject,
            parameter_range,
        )
        .await
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    communication_info: &HashMap<String, String>,
    secret_id: u64,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    pairing_secret: &PairingSecretKeyMaterial,
    kind: SenderKind,
    trace_id: u64,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
) -> Result<Vec<DeRecEvent>> {
    let replica_id_to_inject = require_replica_id_for_kind(kind, replica_id)?;

    let comm_info = build_communication_info(communication_info, replica_id_to_inject);
    let resp = response::produce(
        channel_id,
        request,
        pairing_secret,
        comm_info,
        parameter_range,
    )?;
    // Long-term id both peers atomically switch to. `channel_id` is the
    // transient pairing id from the ContactMessage and remains only as
    // the envelope route for the outgoing PairResponse.
    let new_channel_id = resp.channel_id;

    secret_store
        .save(
            secret_id,
            new_channel_id,
            SecretValue::SharedKey(resp.shared_key),
        )
        .await?;

    let peer_transport = resp.peer_transport_protocol.clone();

    let status = if kind.is_replica() {
        crate::protocol::types::ChannelStatus::Pending
    } else {
        crate::protocol::types::ChannelStatus::Paired
    };

    let peer_sender_kind = request_sender_kind(request)?;
    let (peer_communication_info, peer_replica_id) =
        extract_communication_info(&request.communication_info, peer_sender_kind)?;

    channel_store
        .save(
            secret_id,
            crate::protocol::types::Channel {
                id: new_channel_id,
                transport: peer_transport,
                communication_info: peer_communication_info.clone(),
                status,
                created_at: now_secs(),
                role: kind,
                replica_id: peer_replica_id,
            },
        )
        .await?;

    // Send on the transient id — the peer still routes on it and will
    // rotate to `new_channel_id` on receipt.
    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    transport
        .send(&resp.peer_transport_protocol, envelope)
        .await?;

    // Drop the transient channel state after the wire message is out.
    // Any inbound message routed to `channel_id` from this point is
    // rejected as unknown.
    secret_store
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await?;
    channel_store.remove(secret_id, channel_id).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        old_channel_id = channel_id.0,
        new_channel_id = new_channel_id.0,
        "pairing complete (responder side); rotated to long-term channel_id"
    );

    Ok(pair_completion_events(
        new_channel_id,
        channel_id,
        kind,
        peer_communication_info,
        peer_replica_id,
    ))
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    _communication_info: &HashMap<String, String>,
    secret_id: u64,
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
    let _ = crate::transport::TransportProtocol::try_from(&peer_transport_protocol)?;

    let timestamp = current_timestamp();

    let response = PairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        nonce: request.nonce,
        communication_info: None,
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
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
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
    replica_id: Option<u64>,
) -> Result<Vec<DeRecEvent>> {
    let peer_kind = request_sender_kind(request)?;

    let (peer_communication_info, _peer_replica_id) =
        extract_communication_info(&request.communication_info, peer_kind)?;

    let kind = peer_kind.derive_peer();
    let _ = require_replica_id_for_kind(kind, replica_id)?;

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
#[allow(clippy::too_many_arguments)]
async fn on_response<Ch: DeRecChannelStore, Ss: DeRecSecretStore>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    secret_id: u64,
    channel_id: ChannelId,
    response: &derec_proto::PairResponseMessage,
    pairing_secret: &PairingSecretKeyMaterial,
    replica_id: Option<u64>,
    parameter_range: Option<&derec_proto::ParameterRange>,
) -> Result<Vec<DeRecEvent>> {
    crate::primitives::pairing::parameter_range::check_compatibility(
        parameter_range,
        response.parameter_range.as_ref(),
    )?;

    let contact = match secret_store
        .load(secret_id, channel_id, SecretKind::PairingContact)
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
    // Long-term id the peer already rotated to on its side; both peers
    // derive it independently from `original_channel_id || shared_key`.
    // `channel_id` remains only as the (already-consumed) envelope route.
    let new_channel_id = result.channel_id;

    let channel = channel_store
        .load(secret_id, channel_id)
        .await?
        .ok_or(Error::Invariant(
            "channel record missing on pair response — start must be called first",
        ))?;
    let kind = channel.role;

    let status = if kind.is_replica() {
        crate::protocol::types::ChannelStatus::Pending
    } else {
        crate::protocol::types::ChannelStatus::Paired
    };

    let peer_kind = kind.derive_peer();
    let _ = require_replica_id_for_kind(kind, replica_id)?;
    let (peer_communication_info, peer_replica_id) =
        extract_communication_info(&response.communication_info, peer_kind)?;

    let mut channel = channel;
    channel.id = new_channel_id;
    channel.status = status;
    channel.replica_id = peer_replica_id;
    for (k, v) in &peer_communication_info {
        channel.communication_info.insert(k.clone(), v.clone());
    }
    channel_store.save(secret_id, channel).await?;

    secret_store
        .save(
            secret_id,
            new_channel_id,
            SecretValue::SharedKey(result.shared_key),
        )
        .await?;

    // Drop the transient channel's records after the long-term ones are
    // in place. Any inbound message routed to `channel_id` from this
    // point is rejected as unknown.
    channel_store.remove(secret_id, channel_id).await?;
    secret_store
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await?;
    secret_store
        .remove(secret_id, channel_id, SecretKind::PairingContact)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        old_channel_id = channel_id.0,
        new_channel_id = new_channel_id.0,
        "pairing complete (initiator side); rotated to long-term channel_id"
    );

    Ok(pair_completion_events(
        new_channel_id,
        channel_id,
        kind,
        peer_communication_info,
        peer_replica_id,
    ))
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
    secret_id: u64,
    channel_id: ChannelId,
    original_contact: &ContactMessage,
    response: &PrePairResponseMessage,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
) -> Result<Vec<DeRecEvent>> {
    let processed = if original_contact.contact_mode == ContactMode::NoKeys as i32 {
        response::process_pre_pair_no_keys(original_contact, response)
    } else {
        response::process_pre_pair(original_contact, response)
    };
    let validated = match processed {
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

    let filled_in_contact = ContactMessage {
        mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
        ecies_public_key: Some(validated.ecies_public_key),
        contact_mode: ContactMode::InlineKeys as i32,
        contact_binding_hash: None,
        ..original_contact.clone()
    };

    let role = channel_store
        .load(secret_id, channel_id)
        .await?
        .ok_or(Error::Invariant(
            "channel record missing on PrePair response — start must be called first",
        ))?
        .role;

    let replica_id_to_inject = require_replica_id_for_kind(role, replica_id)?;
    let comm_info = build_communication_info(communication_info, replica_id_to_inject);
    let result = request::produce(
        role,
        own_transport.clone(),
        &filled_in_contact,
        comm_info,
        parameter_range,
    )?;

    // Persist the scanner's pairing secret + overwrite the stored
    // contact with the filled-in version. `pair_response::process`
    // later reads back the InlineKeys-shaped contact to verify keys.
    secret_store
        .save(
            secret_id,
            channel_id,
            SecretValue::PairingSecret(result.secret_key),
        )
        .await?;
    secret_store
        .save(
            secret_id,
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

    Ok(vec![])
}

/// `accept` arm for [`PendingAction::PrePair`]. Branches on the stored
/// contact's mode:
///
/// - `HashedKeys`: loads the previously-generated `PairingSecret` and
///   publishes its keys (the scanner will match them against the
///   contact's binding hash).
/// - `NoKeys`: no `PairingSecret` exists yet — the contact was created
///   without any key material. Generates fresh key material on the fly,
///   persists it as `PairingSecret`, and publishes the keys. First
///   authenticates the request by matching `request.nonce` against the
///   stored contact's `nonce`.
pub(in crate::protocol) async fn accept_pre_pair<Ss: DeRecSecretStore, T: DeRecTransport>(
    secret_store: &mut Ss,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    // NoKeys: no PairingSecret exists at accept time. Load the stored
    // contact, verify the incoming nonce, and generate keys on the fly.
    if let Some(SecretValue::PairingContact(contact)) = secret_store
        .load(secret_id, channel_id, SecretKind::PairingContact)
        .await?
        && contact.contact_mode == ContactMode::NoKeys as i32
    {
        if request.nonce != contact.nonce {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                "NoKeys PrePair nonce mismatch — rejecting"
            );
            return Err(crate::primitives::pairing::PairingError::ProtocolViolation(
                "NoKeys PrePair nonce mismatch",
            )
            .into());
        }

        let result = response::produce_pre_pair_no_keys(channel_id, request)?;
        secret_store
            .save(
                secret_id,
                channel_id,
                SecretValue::PairingSecret(result.pairing_secret_key_material),
            )
            .await?;

        let envelope = super::apply_trace_id(result.envelope, trace_id)?;
        let endpoint = request
            .transport_protocol
            .clone()
            .ok_or(Error::InvalidInput(
                "PrePair request missing transport endpoint",
            ))?;
        let _ = crate::transport::TransportProtocol::try_from(&endpoint)?;
        transport.send(&endpoint, envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!(
            channel_id = channel_id.0,
            "NoKeys PrePair accepted; fresh keys generated and sent to scanner"
        );

        return Ok(vec![]);
    }

    let Some(SecretValue::PairingSecret(pairing_secret)) = secret_store
        .load(secret_id, channel_id, SecretKind::PairingSecret)
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
    let _ = crate::transport::TransportProtocol::try_from(&endpoint)?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        "PrePair accepted; published keys sent to scanner"
    );

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
    let _ = crate::transport::TransportProtocol::try_from(&endpoint)?;

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
        timestamp: Some(timestamp),
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
    secret_id: u64,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoint: TransportProtocol,
    kind: SenderKind,
    replica_id_to_inject: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
) -> Result<u64> {
    reject_start_on_paired_channel(channel_store, secret_id, channel_id).await?;

    let comm_info = build_communication_info(communication_info, replica_id_to_inject);
    let result = request::produce(
        kind,
        own_transport.clone(),
        &contact,
        comm_info,
        parameter_range,
    )?;

    secret_store
        .save(
            secret_id,
            channel_id,
            SecretValue::PairingSecret(result.secret_key),
        )
        .await?;
    secret_store
        .save(
            secret_id,
            channel_id,
            SecretValue::PairingContact(result.initiator_contact_message),
        )
        .await?;

    channel_store
        .save(
            secret_id,
            crate::protocol::types::Channel {
                id: channel_id,
                transport: endpoint.clone(),
                communication_info: peer_communication_info,
                status: crate::protocol::types::ChannelStatus::Pending,
                created_at: now_secs(),
                role: kind,
                replica_id: None,
            },
        )
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
/// Scanner-side entry point shared by `HashedKeys` and `NoKeys`: sends a
/// [`PrePairRequestMessage`] and persists the original contact so
/// `on_pre_pair_response` can later branch on `contact.contact_mode` to
/// decide whether to verify a binding hash (HashedKeys) or skip
/// verification (NoKeys).
async fn start_pre_pair<Ch: DeRecChannelStore, Ss: DeRecSecretStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    own_transport: &TransportProtocol,
    secret_id: u64,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoint: TransportProtocol,
    kind: SenderKind,
) -> Result<u64> {
    reject_start_on_paired_channel(channel_store, secret_id, channel_id).await?;

    let result = request::produce_pre_pair_request(own_transport.clone(), &contact)?;

    secret_store
        .save(secret_id, channel_id, SecretValue::PairingContact(contact))
        .await?;

    channel_store
        .save(
            secret_id,
            crate::protocol::types::Channel {
                id: channel_id,
                transport: endpoint.clone(),
                communication_info: peer_communication_info,
                status: crate::protocol::types::ChannelStatus::Pending,
                created_at: now_secs(),
                role: kind,
                replica_id: None,
            },
        )
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("PrePair request sent (scanner side)");

    let envelope = super::apply_trace_id(result.envelope, super::fresh_trace_id())?;
    transport.send(&endpoint, envelope).await?;

    Ok(channel_id.0)
}

/// Inbound `PrePairRequest` on the **initiator side**. Handled either by
/// the party that:
///
/// - created a `HashedKeys` contact and saved its `PairingSecret`, or
/// - created a `NoKeys` contact and saved only its `PairingContact`.
///
/// Pure function — surfaces an [`DeRecEvent::ActionRequired`] event. The
/// application decides whether to accept (publish the keys — for NoKeys
/// keys are generated on the fly at accept time) or reject (refuse to
/// participate) by calling [`super::super::DeRecProtocol::accept`] or
/// [`super::super::DeRecProtocol::reject`] with the carried
/// [`PendingAction::PrePair`].
pub(in crate::protocol) fn handle_pre_pair_request(
    message: &MessageBody,
    channel_id: ChannelId,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let MessageBody::PrePairRequest(request) = message else {
        return Err(Error::Invariant(
            "handle_pre_pair_request called with non-PrePairRequest MessageBody",
        ));
    };
    on_pre_pair_request(channel_id, request, trace_id)
}

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

/// Build a `CommunicationInfo` proto from the app's free-form key-value
/// map, optionally injecting the reserved `derec.replica_id` entry.
///
/// Callers pass `Some(id)` when the **local** kind on this pairing is
/// `Replica` (and the protocol was built with `with_replica_id`), `None`
/// otherwise. The orchestrator-level gate at `start`/`accept`/`process`
/// entry refuses replica-mode pairings before reaching this helper, so by
/// the time we get here `replica_id` being `None` always means "no
/// injection needed."
///
/// Any entry the app supplied under the reserved `derec.*` namespace is
/// **silently dropped** before serialization — the namespace is owned by
/// the library, not application territory.
fn build_communication_info(
    info: &HashMap<String, String>,
    replica_id_to_inject: Option<u64>,
) -> Option<CommunicationInfo> {
    let mut entries: Vec<_> = info
        .iter()
        .filter(|(k, _)| !is_reserved_key(k))
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| derec_proto::CommunicationInfoKeyValue {
            key: k.to_owned(),
            value: Some(
                derec_proto::communication_info_key_value::Value::StringValue(v.to_owned()),
            ),
        })
        .collect();

    if let Some(id) = replica_id_to_inject {
        entries.push(derec_proto::CommunicationInfoKeyValue {
            key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
            value: Some(
                derec_proto::communication_info_key_value::Value::StringValue(
                    reserved_keys::encode_replica_id(id),
                ),
            ),
        });
    }

    if entries.is_empty() {
        return None;
    }

    Some(CommunicationInfo {
        communication_info_entries: entries,
    })
}

/// Extract the app-level free-form `CommunicationInfo` into a flat map AND
/// pull the reserved `derec.replica_id` entry out as a typed `Option<u64>`.
///
/// The reserved key is **stripped from the returned map** so apps can't
/// accidentally observe it (or, in subsequent broadcasts, re-transmit it).
///
/// Validation against `peer_kind` (via [`SenderKindExt::is_replica`]):
/// - replica kinds (`ReplicaSource`, `ReplicaDestination`): the reserved
///   key MUST be present and parse as a valid hex `u64` (error:
///   [`PairingError::MissingReplicaId`] or [`Error::InvalidInput`]).
/// - non-replica kinds (`Owner`, `Helper`): the reserved key MUST NOT be
///   present (error: [`PairingError::UnexpectedReplicaId`]). Non-replica
///   pairings have no business carrying replica identity.
fn extract_communication_info(
    info: &Option<CommunicationInfo>,
    peer_kind: SenderKind,
) -> Result<(HashMap<String, String>, Option<u64>)> {
    let Some(info) = info.as_ref() else {
        // No comm_info means no reserved entries either; replica pairings
        // are rejected up-front by the missing-id check below.
        if peer_kind.is_replica() {
            return Err(PairingError::MissingReplicaId {
                sender_kind: peer_kind,
            }
            .into());
        }
        return Ok((HashMap::new(), None));
    };

    let mut free_form: HashMap<String, String> = HashMap::new();
    let mut peer_replica_id: Option<u64> = None;

    for e in &info.communication_info_entries {
        let Some(derec_proto::communication_info_key_value::Value::StringValue(s)) = &e.value
        else {
            continue;
        };
        let trimmed = s.trim();
        if trimmed.is_empty() {
            continue;
        }

        if e.key == reserved_keys::DEREC_REPLICA_ID_KEY {
            peer_replica_id = Some(reserved_keys::decode_replica_id(trimmed)?);
            continue;
        }
        if is_reserved_key(&e.key) {
            // Future reserved keys land here. For now there is only
            // `derec.replica_id`, so any other `derec.*` entry is foreign
            // and silently dropped — same as #43's "library owns the
            // namespace" stance for ContactMode.
            continue;
        }
        free_form.insert(e.key.to_owned(), trimmed.to_owned());
    }

    match (peer_kind.is_replica(), peer_replica_id.is_some()) {
        (true, false) => Err(PairingError::MissingReplicaId {
            sender_kind: peer_kind,
        }
        .into()),
        (false, true) => Err(PairingError::UnexpectedReplicaId {
            sender_kind: peer_kind,
        }
        .into()),
        _ => Ok((free_form, peer_replica_id)),
    }
}

/// `true` for any key in the reserved `derec.*` namespace (library-owned).
/// Apps that set such keys themselves are silently overridden.
fn is_reserved_key(key: &str) -> bool {
    key.starts_with("derec.")
}

/// Build the event stream a pair-handshake-completing handler returns.
///
/// Always emits `PairingCompleted` (the universal "handshake done" signal,
/// observed by every kind of pairing). For replica pairings, also emits
/// `ReplicaPaired` carrying the peer's replica id. The local side's role
/// (Source / Destination) is already on the saved `Channel.role`, so
/// the event doesn't repeat it.
///
/// `peer_replica_id.is_some()` and [`SenderKindExt::is_replica`] are equivalent at
/// this point — [`extract_communication_info`] rejects inconsistent
/// combinations upstream — so we branch on the `Option` directly and
/// emit `ReplicaPaired` iff a peer id is present.
fn pair_completion_events(
    channel_id: ChannelId,
    pairing_channel_id: ChannelId,
    kind: SenderKind,
    peer_communication_info: HashMap<String, String>,
    peer_replica_id: Option<u64>,
) -> Vec<DeRecEvent> {
    let mut events = vec![DeRecEvent::PairingCompleted {
        channel_id,
        pairing_channel_id,
        kind,
        peer_communication_info,
    }];
    if let Some(peer_replica_id) = peer_replica_id {
        events.push(DeRecEvent::ReplicaPaired {
            channel_id,
            peer_replica_id,
        });
    }
    events
}

/// Gate for replica-mode pairings on the local side.
///
/// Returns `Some(id)` when `kind` is `ReplicaSource` or
/// `ReplicaDestination` (and the protocol was configured with a replica
/// id), `None` for non-replica pairings, or
/// [`Error::ReplicaIdNotConfigured`] when a replica-mode pairing was
/// attempted without local identity. The returned `Option<u64>` is exactly
/// what [`build_communication_info`] expects.
fn require_replica_id_for_kind(
    local_kind: SenderKind,
    configured_replica_id: Option<u64>,
) -> Result<Option<u64>> {
    if !local_kind.is_replica() {
        return Ok(None);
    }
    configured_replica_id
        .map(Some)
        .ok_or(Error::ReplicaIdNotConfigured)
}

/// Parse the `sender_kind` field of an incoming `PairRequestMessage` into
/// the typed [`SenderKind`] enum. The raw field is an `i32` on the wire;
/// unknown values surface as
/// [`PairingError::InvalidPairRequestMessage`].
fn request_sender_kind(request: &PairRequestMessage) -> Result<SenderKind> {
    SenderKind::try_from(request.sender_kind).map_err(|_| {
        PairingError::InvalidPairRequestMessage("unknown sender_kind on PairRequest").into()
    })
}

async fn reject_start_on_paired_channel<Ch: DeRecChannelStore>(
    channel_store: &Ch,
    secret_id: u64,
    channel_id: ChannelId,
) -> Result<()> {
    if let Some(channel) = channel_store.load(secret_id, channel_id).await? {
        if channel.status == crate::protocol::types::ChannelStatus::Paired {
            return Err(Error::ChannelAlreadyPaired { channel_id });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries_of(c: &CommunicationInfo) -> Vec<(String, String)> {
        c.communication_info_entries
            .iter()
            .filter_map(|e| match &e.value {
                Some(derec_proto::communication_info_key_value::Value::StringValue(s)) => {
                    Some((e.key.clone(), s.clone()))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn build_omits_reserved_key_when_no_replica_id_to_inject() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());

        let built = build_communication_info(&info, None).expect("entries present");
        let pairs = entries_of(&built);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("name".to_owned(), "Alice".to_owned()));
    }

    #[test]
    fn build_injects_reserved_key_when_replica_id_supplied() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());

        let built = build_communication_info(&info, Some(0xDEAD_BEEFu64)).expect("entries present");
        let pairs = entries_of(&built);

        let replica_entry = pairs
            .iter()
            .find(|(k, _)| k == reserved_keys::DEREC_REPLICA_ID_KEY)
            .expect("derec.replica_id should be injected");
        assert_eq!(replica_entry.1, "3735928559");

        // The app's free-form `name` is preserved alongside the reserved entry.
        assert!(pairs.iter().any(|(k, v)| k == "name" && v == "Alice"));
    }

    #[test]
    fn build_drops_app_supplied_entries_in_reserved_namespace() {
        let mut info = HashMap::new();
        info.insert("name".to_owned(), "Alice".to_owned());
        // App tries to shadow the reserved key — should be silently dropped.
        info.insert(
            reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
            "ffffffffffff".to_owned(),
        );
        // App tries any other derec.* key — also dropped (namespace owned).
        info.insert("derec.foo".to_owned(), "bar".to_owned());

        let built = build_communication_info(&info, Some(1)).expect("entries present");
        let pairs = entries_of(&built);

        // Only the LIBRARY-injected derec.replica_id and the free-form `name`.
        assert_eq!(pairs.len(), 2);
        let replica_entry = pairs
            .iter()
            .find(|(k, _)| k == reserved_keys::DEREC_REPLICA_ID_KEY)
            .unwrap();
        assert_eq!(replica_entry.1, "1");
        assert!(!pairs.iter().any(|(k, _)| k == "derec.foo"));
    }

    #[test]
    fn extract_strips_reserved_key_and_returns_typed_id() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![
                derec_proto::CommunicationInfoKeyValue {
                    key: "name".to_owned(),
                    value: Some(
                        derec_proto::communication_info_key_value::Value::StringValue(
                            "Bob".to_owned(),
                        ),
                    ),
                },
                derec_proto::CommunicationInfoKeyValue {
                    key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                    value: Some(
                        derec_proto::communication_info_key_value::Value::StringValue(
                            "3405691582".to_owned(),
                        ),
                    ),
                },
            ],
        });

        let (map, replica_id) =
            extract_communication_info(&info, SenderKind::ReplicaSource).unwrap();
        // Map carries only the free-form entry; reserved key is gone.
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("name").map(String::as_str), Some("Bob"));
        assert!(!map.contains_key(reserved_keys::DEREC_REPLICA_ID_KEY));
        assert_eq!(replica_id, Some(0xCAFE_BABEu64));
    }

    #[test]
    fn extract_rejects_replica_pairing_missing_reserved_key() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![derec_proto::CommunicationInfoKeyValue {
                key: "name".to_owned(),
                value: Some(
                    derec_proto::communication_info_key_value::Value::StringValue("Bob".to_owned()),
                ),
            }],
        });

        let err =
            extract_communication_info(&info, SenderKind::ReplicaSource).expect_err("must reject");
        assert!(
            matches!(
                err,
                Error::Pairing(PairingError::MissingReplicaId { sender_kind })
                    if sender_kind == SenderKind::ReplicaSource
            ),
            "expected MissingReplicaId, got {err:?}"
        );
    }

    #[test]
    fn extract_rejects_non_replica_pairing_carrying_reserved_key() {
        let info = Some(CommunicationInfo {
            communication_info_entries: vec![derec_proto::CommunicationInfoKeyValue {
                key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
                value: Some(
                    derec_proto::communication_info_key_value::Value::StringValue(
                        "12345".to_owned(),
                    ),
                ),
            }],
        });

        // Helper-side extraction of a peer pretending to be Owner with replica id.
        let err = extract_communication_info(&info, SenderKind::Owner).expect_err("must reject");
        assert!(
            matches!(
                err,
                Error::Pairing(PairingError::UnexpectedReplicaId { sender_kind })
                    if sender_kind == SenderKind::Owner
            ),
            "expected UnexpectedReplicaId, got {err:?}"
        );
    }

    #[test]
    fn extract_rejects_replica_pairing_with_no_communication_info() {
        // A replica peer that sent no CommunicationInfo at all — no place to
        // carry the required `derec.replica_id`.
        let err =
            extract_communication_info(&None, SenderKind::ReplicaSource).expect_err("must reject");
        assert!(matches!(
            err,
            Error::Pairing(PairingError::MissingReplicaId { .. })
        ));
    }

    #[test]
    fn extract_accepts_non_replica_pairing_with_no_communication_info() {
        let (map, id) = extract_communication_info(&None, SenderKind::Helper).unwrap();
        assert!(map.is_empty());
        assert_eq!(id, None);
    }

    #[test]
    fn require_replica_id_for_kind_short_circuits_non_replica() {
        assert_eq!(
            require_replica_id_for_kind(SenderKind::Owner, None).unwrap(),
            None
        );
        assert_eq!(
            require_replica_id_for_kind(SenderKind::Helper, Some(123)).unwrap(),
            None,
            "Helper kind ignores configured replica id"
        );
    }

    #[test]
    fn require_replica_id_for_kind_passes_through_for_replica() {
        assert_eq!(
            require_replica_id_for_kind(SenderKind::ReplicaSource, Some(42)).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn require_replica_id_for_kind_errors_when_replica_unconfigured() {
        let err = require_replica_id_for_kind(SenderKind::ReplicaSource, None).unwrap_err();
        assert!(matches!(err, Error::ReplicaIdNotConfigured));
    }

    use crate::protocol::traits::ChannelStoreFuture;
    use crate::protocol::types::{Channel, ChannelStatus};

    /// Single-channel mock that returns whatever record was seeded at
    /// construction. All mutating methods are stubbed because the
    /// helper under test only ever calls `load`.
    struct FixedChannelStore {
        seeded: Option<Channel>,
    }

    impl DeRecChannelStore for FixedChannelStore {
        fn load(&self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
            let v = self.seeded.clone();
            Box::pin(std::future::ready(Ok(v)))
        }
        fn save(&mut self, _: u64, _: Channel) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn remove(&mut self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, bool> {
            Box::pin(std::future::ready(Ok(false)))
        }
        fn channels(&self, _: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
        fn link_channel(
            &mut self,
            _: u64,
            _: ChannelId,
            _: ChannelId,
        ) -> ChannelStoreFuture<'_, ()> {
            Box::pin(std::future::ready(Ok(())))
        }
        fn linked_channels(
            &self,
            _: u64,
            cid: ChannelId,
        ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
            Box::pin(std::future::ready(Ok(vec![cid])))
        }
    }

    fn fake_channel(status: ChannelStatus, role: SenderKind) -> Channel {
        Channel {
            id: ChannelId(1),
            transport: TransportProtocol {
                uri: "https://example.com".to_owned(),
                protocol: 0,
            },
            communication_info: HashMap::new(),
            status,
            created_at: 1_700_000_000,
            role,
            replica_id: None,
        }
    }

    /// Spin up a single-threaded tokio runtime and drive an async
    /// closure to completion. Library tests can't use `#[tokio::test]`
    /// because the crate pulls tokio in with `default-features = false,
    /// features = ["rt"]` — no `macros` feature.
    fn run_async<F: std::future::Future<Output = ()>>(f: F) {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("test runtime")
            .block_on(f)
    }

    #[test]
    fn reject_start_on_paired_channel_errors_when_channel_already_paired() {
        run_async(async {
            let store = FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Paired, SenderKind::Helper)),
            };
            let err = reject_start_on_paired_channel(&store, 42, ChannelId(1))
                .await
                .unwrap_err();
            assert!(
                matches!(err, Error::ChannelAlreadyPaired { channel_id } if channel_id == ChannelId(1)),
                "expected Error::ChannelAlreadyPaired for ChannelId(1), got {err:?}"
            );
        });
    }

    /// `Pending` is a legitimate retry state (handshake never finished) —
    /// re-running `start` must be allowed so the caller can resend a
    /// PairRequest with fresh secret material.
    #[test]
    fn reject_start_on_paired_channel_allows_pending_retry() {
        run_async(async {
            let store = FixedChannelStore {
                seeded: Some(fake_channel(ChannelStatus::Pending, SenderKind::Helper)),
            };
            reject_start_on_paired_channel(&store, 42, ChannelId(1))
                .await
                .expect("Pending channel must be accepted as a retry candidate");
        });
    }

    /// First-time pairing — no record exists yet.
    #[test]
    fn reject_start_on_paired_channel_allows_when_no_channel_record() {
        run_async(async {
            let store = FixedChannelStore { seeded: None };
            reject_start_on_paired_channel(&store, 42, ChannelId(1))
                .await
                .expect("absent channel record must be accepted");
        });
    }

    /// Replica `Paired` is also rejected — replica pairings transition
    /// to `Paired` after fingerprint verification, and once they're
    /// there the same overwrite-corruption applies.
    #[test]
    fn reject_start_on_paired_channel_errors_for_paired_replica() {
        run_async(async {
            let store = FixedChannelStore {
                seeded: Some(fake_channel(
                    ChannelStatus::Paired,
                    SenderKind::ReplicaSource,
                )),
            };
            let err = reject_start_on_paired_channel(&store, 42, ChannelId(1))
                .await
                .unwrap_err();
            assert!(matches!(err, Error::ChannelAlreadyPaired { .. }));
        });
    }
}
