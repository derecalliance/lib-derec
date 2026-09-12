// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The pairing leg: `PairRequest` → `PairResponse`.
//!
//! Reached directly by an [`InlineKeys`](derec_proto::ContactMode::InlineKeys)
//! contact, whose key material is already in hand, and by a
//! [`HashedKeys`](derec_proto::ContactMode::HashedKeys) or
//! [`NoKeys`](derec_proto::ContactMode::NoKeys) contact once
//! [`pre_pair`](super::pre_pair) has fetched it. Both arrive here the
//! same way, so nothing below reads the contact mode.

use crate::extensions::advertised_endpoints::AdvertisedEndpoints as _;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::sender_kind::SenderKindExt as _;
use crate::protocol::context::{Local, PairingConfig};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, PairingKeyMaterial,
    PendingAction, SecretKind, SecretValue, now_secs,
};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    primitives::pairing::{request, response},
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, ContactMode, DeRecResult, MessageBody, PairRequestMessage, PairResponseMessage,
    SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;
use std::collections::HashMap;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = trace_id, channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    kind: SenderKind,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let replica_id_to_inject = super::require_replica_id_for_kind(kind, local.replica_id)?;

    let Some(SecretValue::PairingSecret(pairing_secret)) = stores
        .secrets
        .load(secret_id, channel_id, SecretKind::PairingSecret)
        .await?
    else {
        return Err(Error::Invariant(
            "Pair accept: missing PairingSecret (initiator state lost)",
        ));
    };
    let pairing_secret = pairing_secret.to_secret()?;

    let comm_info =
        super::build_communication_info(pairing.communication_info, replica_id_to_inject);
    let resp = response::produce(
        channel_id,
        request,
        &pairing_secret,
        comm_info,
        pairing.parameter_range.cloned(),
        local.policy,
    )?;

    let new_channel_id = resp.channel_id;

    stores
        .secrets
        .save(
            secret_id,
            new_channel_id,
            SecretValue::SharedKey(resp.shared_key),
        )
        .await?;

    let peer_transport = resp.peer_transports.clone();

    // The contact is still stored at this point — the transient material is
    // dropped further down — so the mode this pairing ran under is readable
    // here. Only `NoKeys` leaves one on the responder side; the other modes
    // store a `PairingSecret` instead.
    let contact_mode = match stores
        .secrets
        .load(secret_id, channel_id, SecretKind::PairingContact)
        .await?
    {
        Some(SecretValue::PairingContact(contact)) => Some(contact.contact_mode),
        _ => None,
    };

    let status = completed_pairing_status(kind, contact_mode);

    let peer_sender_kind = super::request_sender_kind(request)?;
    let (peer_communication_info, peer_replica_id) =
        super::extract_communication_info(&request.communication_info, peer_sender_kind)?;

    persist_peer_record(
        stores,
        local,
        new_channel_id,
        peer_transport,
        peer_communication_info.clone(),
        peer_sender_kind,
        peer_replica_id,
        status,
    )
    .await?;

    // The responder is a group member too, and only it knows its own id and
    // endpoints. Without this row the roster it publishes would omit itself.
    if kind.is_replica() {
        super::persist_own_member(
            stores,
            local,
            new_channel_id,
            kind,
            local.replica_id,
            status,
        )
        .await?;
    }

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, trace_id)?;
    stores
        .transport
        .send(&resp.peer_transports, envelope)
        .await?;

    stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await?;
    stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingContact)
        .await?;
    stores
        .channels
        .remove(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?;

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
    tracing::instrument(skip_all, fields(trace_id = trace_id, channel_id = channel_id.0))
)]
/// Refuse an inbound `PairRequest`.
///
/// The response carries no `communication_info`: this device is declining the
/// pairing, so disclosing its own identity details to the peer would give away
/// more than the refusal itself.
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let peer_transports = local
        .policy
        .admit_peer_endpoints(request.advertised_endpoints())?;

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

    stores.transport.send(&peer_transports, envelope).await?;

    stores
        .secrets
        .remove(local.secret_id, channel_id, SecretKind::PairingSecret)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing request rejected");

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = trace_id, channel_id = channel_id.0))
)]
pub(super) fn on_request(
    local: &Local<'_>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let peer_kind = super::request_sender_kind(request)?;

    let (peer_communication_info, _peer_replica_id) =
        super::extract_communication_info(&request.communication_info, peer_kind)?;

    let kind = peer_kind.counterparty();
    // Called for its error alone: a replica pairing this device cannot
    // complete is refused now rather than after the application has been
    // asked to confirm it. The id it returns is injected at send time, and
    // nothing is sent here. Bound to `_` because `Option` is `must_use`.
    let _ = super::require_replica_id_for_kind(kind, local.replica_id)?;

    let action = PendingAction::Pairing {
        channel_id,
        request: request.clone(),
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
pub(super) async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    channel_id: ChannelId,
    response: &derec_proto::PairResponseMessage,
    pairing_secret: &PairingSecretKeyMaterial,
) -> Result<Vec<DeRecEvent>> {
    let replica_id = local.replica_id;
    let secret_id = local.secret_id;
    crate::primitives::pairing::parameter_range::check_compatibility(
        pairing.parameter_range,
        response.parameter_range.as_ref(),
    )?;

    let contact = match stores
        .secrets
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

    let new_channel_id = result.channel_id;

    // Which flow is this? A helper pairing left a `HelperChannel`
    // placeholder; a replica pairing left this device's own member row.
    // Try the helper key first — testing the local `ReplicaId` alone would
    // be wrong, since a device may have one configured while pairing with a
    // helper.
    let helper_placeholder = stores
        .channels
        .load(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?
        .and_then(|r| r.as_helper().cloned());

    let own_member = match (helper_placeholder.as_ref(), replica_id) {
        (None, Some(own)) => stores
            .channels
            .load(
                secret_id,
                crate::protocol::types::ChannelQuery::Replica {
                    channel_id,
                    replica_id: crate::types::ReplicaId::try_from(own)?,
                },
            )
            .await?
            .and_then(|r| r.as_replica().cloned()),
        _ => None,
    };

    // The peer's kind: from the placeholder for a helper pairing, or the
    // counterpart of our own role for a replica one.
    let peer_kind = match (helper_placeholder.as_ref(), own_member.as_ref()) {
        (Some(placeholder), _) => placeholder.peer_role,
        (None, Some(mine)) => mine.role.counterparty().to_sender_kind(),
        (None, None) => {
            return Err(Error::Invariant(
                "no pairing record on pair response — start must be called first",
            ));
        }
    };
    let kind = peer_kind.counterparty();

    let status = completed_pairing_status(kind, Some(contact.contact_mode));

    // Same guard as `on_request`: fail a pairing this device cannot hold up
    // its side of. This leg injects no id, so only the error matters.
    let _ = super::require_replica_id_for_kind(kind, replica_id)?;
    let (peer_communication_info, peer_replica_id) =
        super::extract_communication_info(&response.communication_info, peer_kind)?;

    // The responder announced its id only now, so this is the first chance to
    // see a collision. Unlike the responder, the initiator has no way to tell
    // the peer — a `PairResponse` is the last leg of the handshake. It stops
    // hard and cleans up its own side; the peer is left holding a pairing
    // channel that its expiry sweep will collect.
    if let Some(peer_replica_id) = peer_replica_id
        && super::replica_id_is_taken(stores, local, peer_replica_id).await?
    {
        abandon_pairing(stores, local, channel_id).await?;
        return Err(Error::ReplicaIdConflict {
            replica_id: peer_replica_id,
        });
    }

    // The peer's endpoints come from the helper placeholder when one
    // exists. A replica pairing has none, so it re-filters the contact we
    // already loaded — dropping the placeholder for replica pairings costs
    // nothing.
    let peer_transport = match helper_placeholder.as_ref() {
        Some(p) => p.transports.clone(),
        None => local
            .policy
            .admit_peer_endpoints(contact.advertised_endpoints())?,
    };

    let mut merged_info = helper_placeholder
        .as_ref()
        .map(|p| p.communication_info.clone())
        .unwrap_or_default();
    for (k, v) in &peer_communication_info {
        merged_info.insert(k.clone(), v.clone());
    }

    persist_peer_record(
        stores,
        local,
        new_channel_id,
        peer_transport,
        merged_info,
        peer_kind,
        peer_replica_id,
        status,
    )
    .await?;

    // A replica initiator's own row was written under the contact-time id at
    // `start`; point it at the rekeyed group channel. A member row is keyed by
    // `replica_id` alone, so this is a field update — re-keying it would
    // delete the row this save just wrote.
    if let Some(mine) = own_member {
        stores
            .channels
            .save(
                secret_id,
                crate::protocol::types::ChannelRecord::Replica(
                    crate::protocol::types::ReplicaMember {
                        channel_id: new_channel_id,
                        ..mine
                    },
                ),
            )
            .await?;
    }

    stores
        .secrets
        .save(
            secret_id,
            new_channel_id,
            SecretValue::SharedKey(result.shared_key),
        )
        .await?;

    stores
        .channels
        .remove(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?;
    stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await?;
    stores
        .secrets
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoints: Vec<TransportProtocol>,
    kind: SenderKind,
    replica_id_to_inject: Option<u64>,
    trace_id: u64,
) -> Result<u64> {
    super::reject_start_on_paired_channel(stores, local, channel_id).await?;

    let comm_info =
        super::build_communication_info(pairing.communication_info, replica_id_to_inject);
    let result = request::produce(
        kind,
        local.own_transports.to_vec(),
        &contact,
        comm_info,
        pairing.parameter_range.cloned(),
    )?;

    stores
        .secrets
        .save(
            local.secret_id,
            channel_id,
            SecretValue::PairingSecret(PairingKeyMaterial::from_secret(&result.secret_key)),
        )
        .await?;
    stores
        .secrets
        .save(
            local.secret_id,
            channel_id,
            SecretValue::PairingContact(result.initiator_contact_message),
        )
        .await?;

    super::persist_start_record(
        stores,
        local,
        channel_id,
        endpoints.clone(),
        peer_communication_info,
        kind,
        replica_id_to_inject,
    )
    .await?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing request sent");

    let envelope = crate::derec_message::apply_trace_id(&result.envelope, trace_id)?;
    stores.transport.send(&endpoints, envelope).await?;

    Ok(channel_id.0)
}

/// Drop everything this pairing created, leaving no trace of a handshake that
/// cannot complete.
///
/// This device's own member row is removed **only when it is the sole member
/// row** — that means no group existed before this pairing, so the row was
/// created by it and points at a transient channel about to disappear.
/// Leaving it would strand a later publish on a dead channel with no key. A
/// device already in a group keeps its row: that is its identity there, and
/// this failed pairing has no claim on it.
pub(super) async fn abandon_pairing<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
) -> Result<()> {
    let secret_id = local.secret_id;
    // Unfiltered deliberately: the test below is "am I the group's only
    // member", which is a fact about the whole roster's size.
    let roster = stores
        .channels
        .replicas_matching(secret_id, crate::protocol::types::ReplicaFilter::default())
        .await?;
    if let Some(own) = local.replica_id
        && roster.len() == 1
        && roster[0].replica_id.0 == own
    {
        stores
            .channels
            .remove(
                secret_id,
                crate::protocol::types::ChannelQuery::Replica {
                    channel_id: roster[0].channel_id,
                    replica_id: roster[0].replica_id,
                },
            )
            .await?;
    }

    let _ = stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingSecret)
        .await;
    let _ = stores
        .secrets
        .remove(secret_id, channel_id, SecretKind::PairingContact)
        .await;
    stores
        .channels
        .remove(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?;
    Ok(())
}

/// Status a channel takes once the handshake completes: `Pending` when the
/// pair must still be confirmed out of band, `Paired` when it is usable
/// immediately.
///
/// Two cases await confirmation.
///
/// Replica pairings always do — two devices claiming the same user are
/// admitted to a group, and the fingerprint is what a human compares to
/// authorise that.
///
/// [`ContactMode::NoKeys`] pairings do as well, whatever the kind. That mode
/// carries neither key material nor a commitment, and its `PrePair` leg is
/// plaintext, so nothing binds the keys the scanner receives to the contact
/// that was delivered out of band — an observer can substitute its own and
/// both sides pair with it. The fingerprint is derived from the *established
/// shared key*, so a substitution yields two different fingerprints; it is
/// therefore the check that plays the role the binding hash plays for
/// [`ContactMode::HashedKeys`], and the channel must not carry secrets until
/// it passes.
///
/// [`ContactMode::InlineKeys`] and [`ContactMode::HashedKeys`] helper
/// pairings are `Paired` at once: the contact itself carries the keys, or a
/// commitment the scanner has already verified them against.
pub(super) fn completed_pairing_status(
    kind: SenderKind,
    contact_mode: Option<i32>,
) -> crate::protocol::types::ChannelStatus {
    let awaits_confirmation = kind.is_replica() || contact_mode == Some(ContactMode::NoKeys as i32);
    if awaits_confirmation {
        crate::protocol::types::ChannelStatus::Pending
    } else {
        crate::protocol::types::ChannelStatus::Paired
    }
}

/// The own endpoints to hand a peer we have chosen to reach at `selected`.
///
/// Selection decides which of the peer's endpoints this side sends to; it says
/// nothing about which of this side's endpoints the peer can send back to.
/// Delivery is push-only in both directions, so an endpoints advertised over a
/// stores.transport the peer does not speak is undeliverable — the response simply
/// never arrives, with no error on either side.
///
/// `selected` was chosen because the peer serves that protocol, which makes it
/// the best available evidence of what the peer can also dial. Advertising the
/// own entry matching it keeps the return leg on the same stores.transport as the
/// outbound one. When this application serves no entry of that protocol the
/// primary endpoints stands, which is the behaviour of a single-stores.transport
/// deployment.
pub(super) fn pair_completion_events(
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

/// Persist the peer's record for a completed handshake.
///
/// Helper pairings write a [`HelperChannel`] — that flow is unchanged. Replica
/// pairings write the peer's [`ReplicaMember`], which requires its
/// `replica_id`; by this point the peer has announced it.
#[allow(clippy::too_many_arguments)]
pub(super) async fn persist_peer_record<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    transports: Vec<TransportProtocol>,
    communication_info: HashMap<String, String>,
    peer_kind: SenderKind,
    peer_replica_id: Option<u64>,
    status: crate::protocol::types::ChannelStatus,
) -> Result<()> {
    use crate::protocol::types::{ChannelRecord, HelperChannel, ReplicaMember, ReplicaRole};
    let record = match ReplicaRole::from_sender_kind(peer_kind) {
        Some(role) => {
            let replica_id = peer_replica_id
                .ok_or(Error::Invariant(
                    "replica pairing completed without the peer's replica_id",
                ))
                .and_then(crate::types::ReplicaId::try_from)?;
            ChannelRecord::Replica(ReplicaMember {
                channel_id,
                replica_id,
                transports,
                communication_info: communication_info.clone(),
                role,
                status,
                created_at: now_secs(),
            })
        }
        None => ChannelRecord::Helper(HelperChannel {
            channel_id,
            transports,
            communication_info: communication_info.clone(),
            peer_role: peer_kind,
            status,
            created_at: now_secs(),
        }),
    };
    stores.channels.save(local.secret_id, record).await?;
    Ok(())
}
