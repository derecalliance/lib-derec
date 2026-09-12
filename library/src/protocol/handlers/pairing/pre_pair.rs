// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The pre-pairing leg: `PrePairRequest` → `PrePairResponse`.
//!
//! A [`HashedKeys`](derec_proto::ContactMode::HashedKeys) or
//! [`NoKeys`](derec_proto::ContactMode::NoKeys) contact carries no usable key
//! material — a commitment or nothing at all — so the responder fetches it
//! over this round before the encrypted handshake in
//! [`pair`](super::pair) can begin. An `InlineKeys` contact skips this
//! leg entirely.
//!
//! This round travels in plaintext: no shared or asymmetric key exists yet,
//! so there is nothing to encrypt under. That is why its inbound halves are
//! reachable from outside [`handle`](super::handle) — the plaintext dispatch
//! in [`DeRecProtocol::process`](crate::protocol::DeRecProtocol::process)
//! decodes the body before any key is available and calls them directly.

use crate::extensions::advertised_endpoints::AdvertisedEndpoints as _;
use crate::extensions::sender_kind::SenderKindExt as _;
use crate::protocol::context::{Local, PairingConfig};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, PairingKeyMaterial,
    PendingAction, SecretKind, SecretValue,
};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::pairing::{request, response},
    types::ChannelId,
};
use derec_proto::{
    ContactMessage, ContactMode, DeRecResult, MessageBody, PrePairRequestMessage,
    PrePairResponseMessage, SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;
use std::collections::HashMap;

// The same pairing inputs its sibling `pair::start` takes, and one more:
// the round token. Both legs are the same flow entered two ways.
#[allow(clippy::too_many_arguments)]
pub(super) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    endpoints: Vec<TransportProtocol>,
    kind: SenderKind,
    trace_id: u64,
) -> Result<u64> {
    super::reject_start_on_paired_channel(stores, local, channel_id).await?;

    let result = request::produce_pre_pair_request(local.own_transports.to_vec(), &contact)?;

    stores
        .secrets
        .save(
            local.secret_id,
            channel_id,
            SecretValue::PairingContact(contact),
        )
        .await?;

    super::persist_start_record(
        stores,
        local,
        channel_id,
        endpoints.clone(),
        peer_communication_info,
        kind,
        local.replica_id,
    )
    .await?;

    #[cfg(feature = "logging")]
    tracing::info!("PrePair request sent (scanner side)");

    let envelope = crate::derec_message::apply_trace_id(&result.envelope, trace_id)?;
    stores.transport.send(&endpoints, envelope).await?;

    Ok(channel_id.0)
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
// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let policy = local.policy;
    let secret_id = local.secret_id;
    if let Some(SecretValue::PairingContact(contact)) = stores
        .secrets
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
        stores
            .secrets
            .save(
                secret_id,
                channel_id,
                SecretValue::PairingSecret(PairingKeyMaterial::from_secret(
                    &result.pairing_secret_key_material,
                )),
            )
            .await?;

        let envelope = crate::derec_message::apply_trace_id(&result.envelope, trace_id)?;
        // Every endpoint the requester advertised, so a reply that cannot
        // reach the first can fall back. Never empty: `validate` refuses a
        // request naming none.
        let endpoints = policy.admit_peer_endpoints(request.advertised_endpoints())?;
        let endpoint = endpoints[0].clone();
        // PrePair is plaintext and takes its own dispatch path, so it never
        // passes the `peer_supplied_endpoints` funnel the encrypted paths
        // run. This is the only point the policy can be applied to an
        // endpoint the peer chose, and it is where the endpoint is dialled.
        policy.check_peer(&endpoint)?;
        stores
            .transport
            .send(std::slice::from_ref(&endpoint), envelope)
            .await?;

        #[cfg(feature = "logging")]
        tracing::info!(
            channel_id = channel_id.0,
            "NoKeys PrePair accepted; fresh keys generated and sent to scanner"
        );

        return Ok(vec![]);
    }

    let Some(SecretValue::PairingSecret(pairing_secret)) = stores
        .secrets
        .load(secret_id, channel_id, SecretKind::PairingSecret)
        .await?
    else {
        return Err(Error::Invariant(
            "PrePair accept: missing PairingSecret (initiator state lost)",
        ));
    };
    let pairing_secret = pairing_secret.to_secret()?;

    let result = response::produce_pre_pair(channel_id, request, &pairing_secret)?;
    let envelope = crate::derec_message::apply_trace_id(&result.envelope, trace_id)?;

    // Same as the NoKeys branch: take every advertised endpoint, filtered.
    let endpoints = policy.admit_peer_endpoints(request.advertised_endpoints())?;
    let endpoint = endpoints[0].clone();
    // Same gate as the NoKeys branch above: this plaintext path bypasses the
    // `peer_supplied_endpoints` funnel, so the policy is applied here.
    policy.check_peer(&endpoint)?;
    stores
        .transport
        .send(std::slice::from_ref(&endpoint), envelope)
        .await?;

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
// Compatibility, not oversight — see the `transport` module docs.
#[allow(deprecated)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    // The rejection is dialled at a peer-chosen endpoint just like the
    // acceptance, so it passes the same local.policy gate.
    let endpoints = local
        .policy
        .admit_peer_endpoints(request.advertised_endpoints())?;
    let endpoint = endpoints[0].clone();

    let timestamp = current_timestamp();
    let response = PrePairResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        mlkem_encapsulation_key: None,
        ecies_public_key: None,
        nonce: request.nonce,
        timestamp: Some(timestamp),
    };

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

    stores
        .transport
        .send(std::slice::from_ref(&endpoint), envelope)
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        status = status as i32,
        "PrePair rejected by initiator"
    );

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
///
/// The local sender kind is recovered from whichever record `start` wrote,
/// and the two shapes differ: a helper or owner is stored as a
/// [`ChannelRecord::Helper`](crate::protocol::types::ChannelRecord) carrying
/// the peer's role, while a replica is stored as its **own roster row** —
/// the roster is absolute, so a member records itself rather than a view of
/// its peer. Resolving only the helper shape made `HashedKeys` and `NoKeys`
/// unusable for replica pairing, those being the two modes with a PrePair
/// leg.
pub(in crate::protocol) async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    channel_id: ChannelId,
    original_contact: &ContactMessage,
    response: &PrePairResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let replica_id = local.replica_id;
    let secret_id = local.secret_id;
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

    // The keys have arrived, so the contact is now inline-keys-shaped and can
    // drive `request::produce` like any other.
    let filled_in_contact = ContactMessage {
        mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
        ecies_public_key: Some(validated.ecies_public_key),
        contact_mode: ContactMode::InlineKeys as i32,
        contact_binding_hash: None,
        ..original_contact.clone()
    };

    // What gets *stored*, though, must keep the mode the handshake actually
    // ran under — it is what decides whether the finished channel waits for a
    // fingerprint. For `HashedKeys` the relabel above is truthful: the keys
    // were just checked against the commitment, so they are worth exactly what
    // inlined keys are worth. For `NoKeys` nothing verified them, and calling
    // the contact `InlineKeys` would claim a trust level the flow never
    // earned. This value never reaches the wire and is dropped on rekey;
    // `response::process` reads only the key fields from it.
    let stored_contact = ContactMessage {
        contact_mode: original_contact.contact_mode,
        ..filled_in_contact.clone()
    };

    let local_kind = match stores
        .channels
        .load(
            secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?
        .and_then(|r| r.as_helper().cloned())
    {
        Some(helper) => helper.peer_role.counterparty(),
        None => {
            let own_replica_id = replica_id.ok_or(Error::Invariant(
                "channel record missing on PrePair response — start must be called first",
            ))?;
            stores
                .channels
                .load(
                    secret_id,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id,
                        replica_id: crate::types::ReplicaId::try_from(own_replica_id)?,
                    },
                )
                .await?
                .and_then(|r| r.as_replica().cloned())
                .ok_or(Error::Invariant(
                    "channel record missing on PrePair response — start must be called first",
                ))?
                .role
                .to_sender_kind()
        }
    };

    let replica_id_to_inject = super::require_replica_id_for_kind(local_kind, replica_id)?;
    let comm_info =
        super::build_communication_info(pairing.communication_info, replica_id_to_inject);
    let result = request::produce(
        local_kind,
        local.own_transports.to_vec(),
        &filled_in_contact,
        comm_info,
        pairing.parameter_range.cloned(),
    )?;

    stores
        .secrets
        .save(
            secret_id,
            channel_id,
            SecretValue::PairingSecret(PairingKeyMaterial::from_secret(&result.secret_key)),
        )
        .await?;
    stores
        .secrets
        .save(
            secret_id,
            channel_id,
            SecretValue::PairingContact(stored_contact),
        )
        .await?;

    let endpoints = local
        .policy
        .admit_peer_endpoints(original_contact.advertised_endpoints())?;
    let envelope = crate::derec_message::apply_trace_id(
        &result.envelope,
        crate::derec_message::fresh_trace_id(),
    )?;
    stores.transport.send(&endpoints, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        "PrePair validated; PairRequest sent (HASHED_KEYS scanner side)"
    );

    Ok(vec![])
}

/// Inbound `PrePairRequest` on the **initiator side**. Reached either by
/// the party that:
///
/// - created a `HashedKeys` contact and saved its `PairingSecret`, or
/// - created a `NoKeys` contact and saved only its `PairingContact`.
///
/// Pure function — surfaces a [`DeRecEvent::ActionRequired`] event. The
/// application decides whether to accept (publish the keys — for NoKeys
/// keys are generated on the fly at accept time) or reject (refuse to
/// participate) by calling [`DeRecProtocol::accept`](crate::protocol::DeRecProtocol::accept)
/// or [`DeRecProtocol::reject`](crate::protocol::DeRecProtocol::reject) with
/// the carried [`PendingAction::PrePair`].
pub(in crate::protocol) fn on_request(
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
