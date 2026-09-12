// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Pairing handshake: contact → pair request → pair response, plus the
//! PrePair leg used by [`derec_proto::ContactMode::HashedKeys`] contacts.
//!
//! # The two legs
//!
//! [`pair`] is the handshake proper; [`pre_pair`] is the round that fetches
//! key material a contact did not carry. Which one a contact takes is decided
//! by [`handle`] and [`start`] here, not by whoever asked to pair, and the
//! helpers both legs share stay in this module.
//!
//! The legs answer the same questions, so they use the same names —
//! [`pair::accept`] and [`pre_pair::accept`] both accept what arrived on their
//! leg. Callers name the leg they mean rather than reading a suffix.
//!
//! [`handle`] below covers both legs, because a `PrePairRequest` can arrive
//! encrypted like any other body. It is not the only way into [`pre_pair`]:
//! PrePair normally travels in **plaintext**, and that path is dispatched by
//! [`DeRecProtocol::process`](crate::protocol::DeRecProtocol::process) before
//! any decryption is attempted, straight into
//! [`pre_pair::on_request`] and [`pre_pair::on_response`].
//!
//! # Reserved `CommunicationInfo` handling
//!
//! Outbound envelopes carry the local `replica_id` under the reserved
//! `derec.replica_id` key on replica-mode pairings only; any entry the
//! application supplied under the `derec.*` namespace is silently
//! dropped before serialization, since the namespace belongs to the
//! library. Inbound, the reserved entry is pulled out as a typed
//! `Option<u64>` and **stripped from the map handed to the application**
//! so it can neither be observed nor re-transmitted by accident.
//!
//! Presence is validated against the peer's kind:
//!
//! - replica kinds (`ReplicaSource`, `ReplicaDestination`) MUST carry the
//!   key and it MUST parse as a hex `u64` —
//!   [`PairingError::MissingReplicaId`] or [`Error::InvalidInput`]
//!   otherwise.
//! - non-replica kinds (`Owner`, `Helper`) MUST NOT carry it —
//!   [`PairingError::UnexpectedReplicaId`] otherwise. A non-replica
//!   pairing has no business carrying replica identity.
//!
//! Absent `CommunicationInfo` implies no reserved entries; replica
//! pairings are refused up-front by the missing-id check.

use super::super::{DeRecChannelStore, DeRecEvent, now_secs};
use crate::extensions::advertised_endpoints::AdvertisedEndpoints as _;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::contact_message::ContactMessageExt as _;
use crate::extensions::sender_kind::SenderKindExt as _;
use crate::protocol::context::{Local, PairingConfig};
use crate::protocol::stores::{StoreSet, Stores};
use crate::{
    Error, Result, primitives::pairing::PairingError, protocol::utils::reserved_keys,
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    CommunicationInfo, ContactMessage, MessageBody, PairRequestMessage, SenderKind, StatusEnum,
    TransportProtocol,
};
use std::collections::HashMap;

pub(in crate::protocol) mod pair;
pub(in crate::protocol) mod pre_pair;
#[cfg(test)]
mod tests;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = inbound_trace_id, channel_id = channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    message: &MessageBody,
    channel_id: ChannelId,
    pairing_secret: &PairingSecretKeyMaterial,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match message {
        MessageBody::PairRequest(request) => {
            if let Err(err) = crate::primitives::pairing::parameter_range::check_compatibility(
                pairing.parameter_range,
                request.parameter_range.as_ref(),
            ) {
                pair::reject(
                    stores,
                    local,
                    channel_id,
                    request,
                    StatusEnum::IncompatibleParameterRange,
                    &err.to_string(),
                    inbound_trace_id,
                )
                .await?;
                return Err(err.into());
            }
            // A colliding id is refused before the application is asked to
            // confirm anything: the pairing cannot complete, so surfacing an
            // ActionRequired for it would only waste a user's decision.
            let peer_kind = request_sender_kind(request)?;
            if peer_kind.is_replica() {
                let (_, peer_replica_id) =
                    extract_communication_info(&request.communication_info, peer_kind)?;
                if let Some(peer_replica_id) = peer_replica_id
                    && replica_id_is_taken(stores, local, peer_replica_id).await?
                {
                    pair::reject(
                        stores,
                        local,
                        channel_id,
                        request,
                        StatusEnum::ReplicaIdConflict,
                        "replica id already in use by a member of this group",
                        inbound_trace_id,
                    )
                    .await?;
                    return Err(Error::ReplicaIdConflict {
                        replica_id: peer_replica_id,
                    });
                }
            }
            pair::on_request(local, channel_id, request, inbound_trace_id)
        }
        MessageBody::PairResponse(response) => {
            pair::on_response(stores, local, pairing, channel_id, response, pairing_secret).await
        }
        MessageBody::PrePairRequest(request) => {
            pre_pair::on_request(channel_id, request, inbound_trace_id)
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in pairing message",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = trace_id, channel_id = contact.channel_id))
)]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    pairing: &PairingConfig<'_>,
    kind: SenderKind,
    contact: ContactMessage,
    peer_communication_info: HashMap<String, String>,
    trace_id: u64,
) -> Result<u64> {
    let replica_id_to_inject = require_replica_id_for_kind(kind, local.replica_id)?;

    let channel_id = ChannelId(contact.channel_id);

    let endpoints = local
        .policy
        .admit_peer_endpoints(contact.advertised_endpoints())?;

    if contact.requires_pre_pair() {
        pre_pair::start(
            stores,
            local,
            channel_id,
            contact,
            peer_communication_info,
            endpoints,
            kind,
            trace_id,
        )
        .await
    } else {
        pair::start(
            stores,
            local,
            pairing,
            channel_id,
            contact,
            peer_communication_info,
            endpoints,
            kind,
            replica_id_to_inject,
            trace_id,
        )
        .await
    }
}

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

fn extract_communication_info(
    info: &Option<CommunicationInfo>,
    peer_kind: SenderKind,
) -> Result<(HashMap<String, String>, Option<u64>)> {
    let Some(info) = info.as_ref() else {
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

fn is_reserved_key(key: &str) -> bool {
    key.starts_with("derec.")
}

/// Write this device's own member row when it *initiates* a replica pairing.
///
/// The initiator knows its identity and role at `start`, and the peer's role is
/// simply the counterpart — which is what lets the handshake proceed without
/// recording anything about a peer whose `replica_id` has not arrived yet.
/// Helper pairings write a [`HelperChannel`] placeholder instead, unchanged.
async fn persist_start_record<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    peer_endpoints: Vec<TransportProtocol>,
    peer_communication_info: HashMap<String, String>,
    own_kind: SenderKind,
    own_replica_id: Option<u64>,
) -> Result<()> {
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel};
    if own_kind.is_replica() {
        return persist_own_member(
            stores,
            local,
            channel_id,
            own_kind,
            own_replica_id,
            ChannelStatus::Pending,
        )
        .await;
    }
    stores
        .channels
        .save(
            local.secret_id,
            ChannelRecord::Helper(HelperChannel {
                channel_id,
                transports: peer_endpoints,
                communication_info: peer_communication_info,
                peer_role: own_kind.counterparty(),
                status: ChannelStatus::Pending,
                created_at: now_secs(),
            }),
        )
        .await?;
    Ok(())
}

/// Write this device's own row into the replica roster.
///
/// Both ends of a replica handshake do this — the initiator at `start`, the
/// responder when it accepts — because the roster is absolute, not a view from
/// one side. A group whose members cannot name themselves cannot be published.
///
/// Never called for helper pairings: a helper channel has exactly two ends and
/// one record, so there is no self-row to write.
async fn persist_own_member<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    own_kind: SenderKind,
    own_replica_id: Option<u64>,
    status: crate::protocol::types::ChannelStatus,
) -> Result<()> {
    use crate::protocol::types::{ChannelQuery, ChannelRecord, ReplicaMember, ReplicaRole};
    let role = ReplicaRole::from_sender_kind(own_kind).ok_or(Error::Invariant(
        "own member row requested for a non-replica pairing",
    ))?;
    let replica_id = own_replica_id
        .ok_or(Error::ReplicaIdNotConfigured)
        .and_then(crate::types::ReplicaId::try_from)?;

    // A device already in a group keeps the row it has. Its `channel_id` is
    // the group's, and a later pairing mints an ephemeral channel for the
    // *joiner* only — moving this row onto it would redefine the group's
    // channel, and with it the group key, on every admission.
    if stores
        .channels
        .load(
            local.secret_id,
            ChannelQuery::Replica {
                channel_id,
                replica_id,
            },
        )
        .await?
        .is_some()
    {
        return Ok(());
    }

    stores
        .channels
        .save(
            local.secret_id,
            ChannelRecord::Replica(ReplicaMember {
                channel_id,
                replica_id,
                transports: vec![local.primary().clone()],
                communication_info: HashMap::new(),
                role,
                status,
                created_at: now_secs(),
            }),
        )
        .await?;
    Ok(())
}

async fn reject_start_on_paired_channel<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
) -> Result<()> {
    if let Some(record) = stores
        .channels
        .load(
            local.secret_id,
            crate::protocol::types::ChannelQuery::Helper { channel_id },
        )
        .await?
        && record.status() == crate::protocol::types::ChannelStatus::Paired
    {
        return Err(Error::ChannelAlreadyPaired { channel_id });
    }
    Ok(())
}

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

/// Whether `candidate` is already held by a member of this group.
///
/// The roster includes this device's own row, so a peer that announced the
/// same id as us collides too — the common case, since both ends of a first
/// pairing are usually configured by the same person.
async fn replica_id_is_taken<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    candidate: u64,
) -> Result<bool> {
    Ok(!stores
        .channels
        .replicas_matching(
            local.secret_id,
            crate::protocol::types::ReplicaFilter {
                ids: vec![crate::types::ReplicaId(candidate)],
                ..Default::default()
            },
        )
        .await?
        .is_empty())
}

fn request_sender_kind(request: &PairRequestMessage) -> Result<SenderKind> {
    SenderKind::try_from(request.sender_kind).map_err(|_| {
        PairingError::InvalidPairRequestMessage("unknown sender_kind on PairRequest").into()
    })
}
