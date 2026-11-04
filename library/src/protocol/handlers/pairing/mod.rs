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
use crate::error_codes::classify;
use crate::extensions::advertised_endpoints::AdvertisedEndpoints as _;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::contact_message::ContactMessageExt as _;
use crate::extensions::sender_kind::SenderKindExt as _;
use crate::primitives::pairing::request::check_parameter_range;
use crate::protocol::context::{Local, PairingConfig};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelQuery, ChannelStatus, ReplicaFilter, ReplicaRole};
use crate::protocol::{PendingActionKind, obligation};
use crate::types::ReplicaId;
use crate::{
    Error, Result, primitives::pairing::PairingError, protocol::utils::reserved_keys,
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::communication_info_key_value::Value;
use derec_proto::{
    CommunicationInfo, CommunicationInfoKeyValue, ContactMessage, MessageBody, PairRequestMessage,
    SenderKind, StatusEnum, TransportProtocol,
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
            if let Err(err) = check_parameter_range(request, pairing.parameter_range) {
                let memo = parameter_range_memo(&err);
                return refuse(
                    stores,
                    local,
                    channel_id,
                    request,
                    StatusEnum::IncompatibleParameterRange,
                    &memo,
                    &Error::from(err),
                    inbound_trace_id,
                )
                .await;
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
                    return refuse(
                        stores,
                        local,
                        channel_id,
                        request,
                        StatusEnum::ReplicaIdConflict,
                        "replica id already in use by a member of this group",
                        &Error::ReplicaIdConflict {
                            replica_id: peer_replica_id,
                        },
                        inbound_trace_id,
                    )
                    .await;
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

/// The memo sent with an `INCOMPATIBLE_PARAMETER_RANGE` refusal.
///
/// The requester reads it, so its own range (`peer` here) is named first and
/// this device's range is the accepted one.
fn parameter_range_memo(err: &PairingError) -> String {
    match err {
        PairingError::IncompatibleParameterRange {
            field,
            local_min,
            local_max,
            peer_min,
            peer_max,
        } => format!(
            "`{field}` range [{peer_min}, {peer_max}] does not overlap \
             the accepted range [{local_min}, {local_max}]"
        ),
        _ => "parameter range does not overlap the accepted range".to_owned(),
    }
}

/// Refuse a `PairRequest` under a protocol rule: send the requester a
/// `PairResponse` carrying `status` and `memo`, and report the refusal as
/// [`DeRecEvent::PairingRefused`]. No channel is created.
///
/// `error` is the local reason for the refusal. Its code and description
/// are reported on the event and never sent to the requester.
///
/// Once the refusal was handed to the transport it is reported as sent. A
/// failure of that send, or of dropping the pairing secret after it, follows
/// as a [`DeRecEvent::RequestFailed`] with `responded: true`.
#[allow(clippy::too_many_arguments)]
async fn refuse<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    request: &PairRequestMessage,
    status: StatusEnum,
    memo: &str,
    error: &Error,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let after =
        pair::send_refusal(stores, local, channel_id, request, status, memo, trace_id).await?;
    let mut events = vec![DeRecEvent::PairingRefused {
        channel_id,
        status: status as i32,
        memo: memo.to_owned(),
        error_code: classify(error).1.name().to_owned(),
        message: error.to_string(),
    }];
    if let Some(error) = after {
        events.push(obligation::request_failed(
            channel_id,
            PendingActionKind::Pairing,
            true,
            status as i32,
            memo,
            &error,
            None,
        ));
    }
    Ok(events)
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
        .map(|(k, v)| CommunicationInfoKeyValue {
            key: k.to_owned(),
            value: Some(Value::StringValue(v.to_owned())),
        })
        .collect();

    if let Some(id) = replica_id_to_inject {
        entries.push(CommunicationInfoKeyValue {
            key: reserved_keys::DEREC_REPLICA_ID_KEY.to_owned(),
            value: Some(Value::StringValue(reserved_keys::encode_replica_id(id))),
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
        let Some(Value::StringValue(s)) = &e.value else {
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

/// This device's `communication_info` as its own roster row carries it.
///
/// The same entries a peer keeps after [`extract_communication_info`]: the
/// reserved keys and blank values a peer would drop never reach the roster.
pub(in crate::protocol) fn own_communication_info(local: &Local<'_>) -> HashMap<String, String> {
    local
        .communication_info
        .iter()
        .filter(|(k, v)| !is_reserved_key(k) && !v.trim().is_empty())
        .map(|(k, v)| (k.to_owned(), v.trim().to_owned()))
        .collect()
}

/// Record a pairing this device *initiates*, until its response arrives.
///
/// Every kind writes the same `Pending` [`HelperChannel`] placeholder at the
/// contact's channel, carrying the peer's role, the endpoints and the
/// `communication_info` to record for it. That is all the response handler
/// needs: the local kind is the counterpart of the peer's, and a replica
/// peer's `replica_id`, unknown until the response, goes on the row written
/// then. Nothing is put in the replica roster: a pairing in flight is not
/// group membership, and this device's own row is written only when a
/// replica pairing is confirmed (see [`claim_own_member`]).
async fn persist_start_record<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    peer_endpoints: Vec<TransportProtocol>,
    peer_communication_info: HashMap<String, String>,
    own_kind: SenderKind,
) -> Result<()> {
    use crate::protocol::types::{ChannelRecord, HelperChannel};
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
                weight: 1,
            }),
        )
        .await?;
    Ok(())
}

/// Write this device's own row into the replica roster, on the group channel
/// `channel_id`, as `role`.
///
/// Called when a replica pairing is confirmed: the first confirmed pairing
/// fixes the group's channel. A device that already holds a `Paired` own row
/// is in a group, and keeps that row — a later pairing admits a joiner on an
/// ephemeral channel, and moving this row onto it would redefine the group's
/// channel, and with it the group key, on every admission. Any other own row
/// is replaced.
pub(in crate::protocol) async fn claim_own_member<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    role: ReplicaRole,
) -> Result<()> {
    use crate::protocol::types::{ChannelRecord, ReplicaMember};
    let replica_id = ReplicaId::try_from(local.replica_id.ok_or(Error::ReplicaIdNotConfigured)?)?;

    let holds_a_group = stores
        .channels
        .replicas_matching(
            local.secret_id,
            ReplicaFilter {
                ids: vec![replica_id],
                status: vec![ChannelStatus::Paired],
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .next()
        .is_some();
    if holds_a_group {
        return Ok(());
    }

    stores
        .channels
        .save(
            local.secret_id,
            ChannelRecord::Replica(ReplicaMember {
                channel_id,
                replica_id,
                transports: local.own_transports.to_vec(),
                communication_info: own_communication_info(local),
                role,
                status: ChannelStatus::Paired,
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
        .load(local.secret_id, ChannelQuery::Helper { channel_id })
        .await?
        && record.status() != ChannelStatus::Pending
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
            ReplicaFilter {
                ids: vec![ReplicaId(candidate)],
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
