// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica side of sharing.
//!
//! `StoreShare` serves both relationships. Against a helper it carries one
//! share of a secret; against another group member it carries the whole
//! secret and the whole roster. The owner↔helper side lives in
//! [`handlers::sharing`](super::super::sharing), which routes here when the
//! payload names an author.
use crate::derec_message::DeRecMessageBuilder;
use crate::extensions::channel_store::ChannelStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::DeRecUserSecretStore;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecTransport, SecretKind, SecretValue,
};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    protocol::types::Secret,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, MessageBody, SenderKind, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage,
};
use prost::Message;

/// Handle a store-share message a group member authored.
///
/// Every member of the group answers on the one group channel, so the author
/// in the payload — not the channel's counterparty — is what says which
/// member the message concerns. Resolving it is this module's job rather than
/// the dispatcher's.
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    author: u64,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    let member = stores
        .channels
        .load_replica_member(local.secret_id, exchange.channel_id, author)
        .await?;
    match inner {
        MessageBody::StoreShareRequest(request) => {
            on_request(
                stores,
                local,
                &member,
                request,
                *exchange.shared_key,
                exchange.trace_id,
            )
            .await
        }
        MessageBody::StoreShareResponse(response) => {
            on_response(stores, local, exchange.channel_id, &member, &response).await
        }
        _ => Err(Error::Invariant(
            "replica identity on a message that is not a store-share exchange",
        )),
    }
}

/// Write an inbound roster into this device's stores.
///
/// The payload is self-contained by construction, so hydration is a straight
/// decomposition: helper channels and their keys, every group member against
/// the one group channel, the group key, and the user-secret snapshot. After
/// it, a destination holds the same state as the source and can publish.
///
/// Materialising the helper channels grants no capability the payload had not
/// already granted — it ships each helper's `shared_key`, which is what
/// authenticating as the source toward that helper requires.
///
/// Returns the group channel and its key when the payload carried a roster,
/// so the caller can acknowledge there.
pub(in crate::protocol) async fn hydrate<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    version: u32,
    secret: &Secret,
    description: String,
) -> Result<Option<(ChannelId, SharedKey)>> {
    let secret_id = local.secret_id;
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, UserSecrets,
    };

    for helper in &secret.helpers {
        let channel_id = ChannelId(helper.channel_id);
        let key: SharedKey =
            helper.shared_key.as_slice().try_into().map_err(|_| {
                crate::Error::InvalidInput("roster helper shared_key must be 32 bytes")
            })?;
        stores
            .channels
            .save(
                secret_id,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: helper.transports.clone(),
                    communication_info: helper.communication_info.clone(),
                    peer_role: SenderKind::Helper,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
        stores
            .secrets
            .save(secret_id, channel_id, SecretValue::SharedKey(key))
            .await?;
    }

    let group = match secret.replicas.as_ref().filter(|g| !g.members.is_empty()) {
        Some(group) => group,
        None => return Ok(None),
    };

    let group_channel = ChannelId(group.channel_id);
    let group_key: SharedKey = group
        .shared_key
        .as_slice()
        .try_into()
        .map_err(|_| crate::Error::InvalidInput("roster group shared_key must be 32 bytes"))?;

    for member in &group.members {
        stores
            .channels
            .save(
                secret_id,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: group_channel,
                    replica_id: crate::types::ReplicaId::try_from(member.replica_id)?,
                    transports: member.transports.clone(),
                    communication_info: member.communication_info.clone(),
                    // The roster is authoritative, including for this device's
                    // own row: a joiner's provisional role from pairing is
                    // corrected here.
                    role: ReplicaRole::from_i32(member.role).ok_or(crate::Error::InvalidInput(
                        "roster member carries an unknown role",
                    ))?,
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                }),
            )
            .await?;
    }

    stores
        .secrets
        .save(secret_id, group_channel, SecretValue::SharedKey(group_key))
        .await?;

    // Members present in this roster are up to date. Anything flagged as
    // leaving and now absent has completed its departure — reconciled by the
    // caller, which must acknowledge before tearing itself down.
    stores
        .user_secrets
        .save_latest(
            secret_id,
            UserSecrets {
                version,
                secrets: secret.secrets.clone(),
                description: Some(description).filter(|d| !d.is_empty()),
                replicas: secret.replicas.clone(),
            },
        )
        .await?;

    Ok(Some((group_channel, group_key)))
}

/// Inbound `StoreShareRequest` on a **replica** channel. The payload
/// is the full secret — the sender used `share_algorithm =
/// REPLICA_SECRET`. We decode the typed
/// [`crate::protocol::types::ReplicaSecretPayload`] from `request.share`,
/// auto-ack with `StoreShareResponse(Ok)`, and surface a
/// [`DeRecEvent::ReplicaSecretReceived`] carrying the decoded
/// [`crate::protocol::types::Secret`] + [`Vec<crate::protocol::types::ChannelShare>`]
/// for the application's secret-install logic.
///
/// # Group-key handover
///
/// If the payload carries a non-empty `shared_key` (32 bytes), the
/// sender is asking us to adopt the replica-group key for this
/// `secret_id`. We persist it as this channel's new `SharedKey` in
/// [`crate::protocol::DeRecSecretStore`] **before** encrypting the ack
/// — so the ack travels under the group key, matching the sender's
/// secret store after its own swap. From this round forward, this
/// channel's traffic uses the group key.
///
/// The embedded `shared_key` is delivered inside an already-decrypted
/// authenticated envelope (the pair-handshake key authenticated the
/// outer message), so the receiver does not need an additional binding
/// check.
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel: &crate::protocol::types::ReplicaMember,
    request: StoreShareRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    // The author is whoever wrote this message, which is not necessarily
    // the channel's counterparty: a member admitted by a third party
    // receives updates from every other member over the same channel.
    // The payload is authoritative; the channel record is the fallback
    // for writers that predate the field.
    let from_replica_id = request.replica_id.unwrap_or(channel.replica_id.0);
    // Two ids, deliberately distinct. `secret_id` names the secret **on the
    // wire** — the sender's — and is echoed back in the acknowledgement and in
    // the events this returns. Every *store* access uses `local.secret_id`,
    // the partition this instance owns and the one `hydrate` writes to. A
    // destination is not required to have been configured with the sender's
    // id, so reading a store under the wire id finds nothing this device ever
    // wrote.
    let secret_id = request.secret_id;
    let partition = local.secret_id;
    let version = request.version;

    let composite = crate::protocol::types::ReplicaSecretPayload::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;
    let secret = composite.secret.ok_or(crate::Error::InvalidInput(
        "replica secret payload missing `secret` field",
    ))?;
    let shares = composite.shares;

    // Whether this is the first time this device has held the secret is
    // decided before hydration writes the snapshot that would erase the
    // distinction.
    let is_install = stores.user_secrets.load_latest(partition).await?.is_none();

    // The roster is the single source of truth for the group key. The
    // payload's own `shared_key` predates that and is now only a
    // cross-check: two disagreeing copies of a key is a defect worth
    // catching at the boundary rather than a value to choose between.
    if !composite.shared_key.is_empty() {
        let roster_key = secret.replicas.as_ref().map(|g| g.shared_key.as_slice());
        if roster_key != Some(composite.shared_key.as_slice()) {
            return Err(crate::Error::InvalidInput(
                "replica payload's shared_key disagrees with the roster's group key",
            ));
        }
    }

    // Read before hydration overwrites it: a roster that removes the previous
    // source promotes another member, and this device may be the one promoted.
    let was_source = match local.replica_id {
        Some(id) => stores
            .channels
            .load(
                partition,
                crate::protocol::types::ChannelQuery::Replica {
                    channel_id: channel.channel_id,
                    replica_id: crate::types::ReplicaId(id),
                },
            )
            .await?
            .and_then(|r| r.as_replica().cloned())
            .is_some_and(|m| m.role == crate::protocol::types::ReplicaRole::Source),
        None => false,
    };

    let hydrated = hydrate(
        stores,
        local,
        version,
        &secret,
        request.version_description.clone(),
    )
    .await?;

    // Second half of the removal safety rule: a member flagged as leaving and
    // now absent from the roster has completed its departure.
    let roster_ids: Vec<u64> = secret
        .replicas
        .as_ref()
        .map(|g| g.members.iter().map(|m| m.replica_id).collect())
        .unwrap_or_default();
    let removal = super::unpairing::reconcile(stores, local, &roster_ids).await?;

    let promotion = promotion_event(local, was_source, &secret);

    // Every member answers on the group channel under the group key. Before
    // the first sync a joiner has neither, so it answers where the request
    // arrived.
    let (ack_channel, ack_key) = hydrated.unwrap_or((channel.channel_id, shared_key));

    let timestamp = current_timestamp();
    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version,
        timestamp: Some(timestamp),
        secret_id,
        // Replica-bound acknowledgement: announce which member answered,
        // since every member replies on the same group channel.
        replica_id: local.replica_id,
    };
    let envelope_bytes = DeRecMessageBuilder::channel()
        .channel_id(ack_channel)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareResponse(response))
        .encrypt(&ack_key)?
        .build()?
        .encode_to_vec();
    let envelope = crate::derec_message::apply_trace_id(&envelope_bytes, inbound_trace_id)?;
    let endpoint = request.reply_to.clone();
    let endpoint = if endpoint.is_empty() {
        channel.transports.clone()
    } else {
        endpoint
    };
    stores.transport.send(&endpoint, envelope).await?;

    // Admission handover: the sync arrived on the ephemeral channel minted
    // by the pairing with the admitter. Hydration has already moved every
    // member onto the group channel, so the only thing left at the ephemeral
    // id is its key. The admitter drops its side when this ack lands.
    if ack_channel != channel.channel_id {
        let _ = stores
            .secrets
            .remove(partition, channel.channel_id, SecretKind::SharedKey)
            .await;

        #[cfg(feature = "logging")]
        tracing::info!(
            ephemeral_channel_id = channel.channel_id.0,
            group_channel_id = ack_channel.0,
            secret_id,
            "admission handover complete; ephemeral channel dropped"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel.channel_id.0,
        from_replica_id,
        secret_id,
        version,
        is_install,
        helpers_in_secret = secret.helpers.len(),
        members_in_secret = secret.replicas.as_ref().map_or(0, |g| g.members.len()),
        secrets_in_secret = secret.secrets.len(),
        shares_count = shares.len(),
        "replica secret hydrated; ack sent"
    );

    // Teardown happens strictly after the acknowledgement above: dropping the
    // group key first would leave this device unable to encrypt its reply, so
    // the publisher's round would record a failure against a member that had
    // behaved correctly.
    match removal {
        super::unpairing::RemovalOutcome::SelfRemoved => {
            super::unpairing::tear_down(stores, local).await?;

            #[cfg(feature = "logging")]
            tracing::info!(
                secret_id,
                version,
                "left the replica group; partition dropped"
            );

            return Ok(vec![DeRecEvent::SelfRemovedFromGroup { version }]);
        }
        super::unpairing::RemovalOutcome::Removed(ids) => {
            let mut events: Vec<DeRecEvent> = ids
                .into_iter()
                .map(|replica_id| DeRecEvent::ReplicaRemoved { replica_id })
                .collect();
            events.extend(promotion);
            events.push(if is_install {
                DeRecEvent::ReplicaSecretInstalled {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            } else {
                DeRecEvent::ReplicaSecretReceived {
                    channel_id: channel.channel_id,
                    from_replica_id,
                    secret_id,
                    version,
                    secret,
                    shares,
                }
            });
            return Ok(events);
        }
        super::unpairing::RemovalOutcome::Nothing => {}
    }

    let event = if is_install {
        DeRecEvent::ReplicaSecretInstalled {
            channel_id: channel.channel_id,
            from_replica_id,
            secret_id,
            version,
            secret,
            shares,
        }
    } else {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: channel.channel_id,
            from_replica_id,
            secret_id,
            version,
            secret,
            shares,
        }
    };
    let mut events: Vec<DeRecEvent> = promotion.into_iter().collect();
    events.push(event);
    Ok(events)
}

/// Inbound `StoreShareResponse` on a **replica** channel — the source's
/// follow-up to a secret sync. Surface the peer's ack as
/// [`DeRecEvent::ReplicaSecretAcked`] so the app can decide whether to
/// retry / rebroadcast / report.
/// Surface a Destination's acknowledgement of a secret sync.
///
/// A `StoreShareResponse` missing its `result` is itself a protocol
/// violation, so a distinct out-of-range sentinel is reported rather
/// than `StatusEnum::Ok`, which would mislead the application into
/// believing the sync succeeded.
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    arrived_on: ChannelId,
    channel: &crate::protocol::types::ReplicaMember,
    response: &StoreShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    // Every member answers on the same channel, so the responder names
    // itself in the payload. Fall back to the channel's counterparty for
    // responders that predate the field.
    let from_replica_id = response.replica_id.unwrap_or(channel.replica_id.0);
    let (status, memo) = response
        .result
        .as_ref()
        .map(|r| (r.status, r.memo.clone()))
        .unwrap_or((-1, "response missing `result` field".to_owned()));

    // Admission handover, admitter side. A member this device admitted was
    // recorded against the ephemeral pairing channel; answering on the group
    // channel is its proof of having hydrated, since the reply decrypted
    // under the group key. Move the row and drop the ephemeral key.
    //
    // The row is *moved*, never removed and re-added: a member is keyed by
    // `replica_id` alone, so removing it at the old channel would delete the
    // member itself rather than the stale address.
    if status == StatusEnum::Ok as i32 && channel.channel_id != arrived_on {
        let ephemeral = channel.channel_id;
        stores
            .channels
            .save(
                secret_id,
                crate::protocol::types::ChannelRecord::Replica(
                    crate::protocol::types::ReplicaMember {
                        channel_id: arrived_on,
                        ..channel.clone()
                    },
                ),
            )
            .await?;
        let _ = stores
            .secrets
            .remove(secret_id, ephemeral, SecretKind::SharedKey)
            .await;

        #[cfg(feature = "logging")]
        tracing::info!(
            ephemeral_channel_id = ephemeral.0,
            group_channel_id = arrived_on.0,
            from_replica_id,
            "admitted member moved onto the group channel"
        );
    }

    // Acceptance and refusal are different events, mirroring the helper leg's
    // ShareConfirmed / ShareRejected split: the round accumulator moves a
    // member to `synced` on one and to `behind` on the other, and a
    // VERSION_CONFLICT here fails the round.
    if status == StatusEnum::Ok as i32 {
        Ok(vec![DeRecEvent::ReplicaSecretAcked {
            channel_id: arrived_on,
            from_replica_id,
            secret_id: response.secret_id,
            version: response.version,
            status,
            memo,
        }])
    } else {
        Ok(vec![DeRecEvent::ReplicaSyncRejected {
            replica_id: from_replica_id,
            secret_id: response.secret_id,
            version: response.version,
            status,
            memo,
        }])
    }
}

/// Report this device being promoted to the group's source by an arriving
/// roster, which happens when the previous source is removed.
///
/// Only the transition is reported: a device that was already the source and
/// still is has nothing to learn from a roster restating it. `was_source` must
/// be read before hydration, which overwrites the stored role.
fn promotion_event(local: &Local<'_>, was_source: bool, secret: &Secret) -> Option<DeRecEvent> {
    if was_source {
        return None;
    }
    let id = local.replica_id?;
    let now_source = secret.replicas.as_ref().is_some_and(|g| {
        g.members.iter().any(|m| {
            m.replica_id == id && m.role == crate::protocol::types::ReplicaRole::Source as i32
        })
    });
    now_source.then_some(DeRecEvent::ReplicaSourceChanged { replica_id: id })
}

#[cfg(test)]
mod tests {
    use crate::protocol::DeRecChannelStore;
    use crate::protocol::test::{InMemChannelStore, LocalFixture, StoreRig, run_async};
    use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaMember, ReplicaRole};
    use crate::types::{ChannelId, ReplicaId};
    use derec_proto::{Protocol, TransportProtocol};

    const SECRET_ID: u64 = 0xB0B;
    const GROUP_CHANNEL: ChannelId = ChannelId(9001);

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    async fn seed_member(
        channels: &mut InMemChannelStore,
        replica_id: u64,
        role: ReplicaRole,
        uri: &str,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP_CHANNEL,
                    replica_id: ReplicaId(replica_id),
                    transports: vec![endpoint(uri)],
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed member");
    }

    /// A Destination hydrating a roster uses each stored endpoint verbatim.
    ///
    /// The roster carries the protocol discriminant alongside the URI, so
    /// nothing is inferred here. That is the point: a roster that stored only
    /// a URI forced the discriminant to be reconstructed on every hydration,
    /// and the historical reconstruction hardcoded `Https` — producing
    /// `{grpcs://…, Https}` and silently unaddressing every gRPC peer.
    #[test]
    fn hydrate_uses_each_stored_endpoint_verbatim() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            use crate::protocol::traits::DeRecChannelStore;
            use crate::protocol::types::{
                ChannelQuery, ChannelRecord, HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret,
            };

            const SECRET_ID: u64 = 0xD3_57;

            let secret = Secret {
                helpers: vec![
                    HelperInfo {
                        channel_id: 11,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "grpcs://helper.example:443".to_owned(),
                            protocol: derec_proto::Protocol::Grpc as i32,
                        }],
                        shared_key: vec![0xAA; 32],
                        communication_info: std::collections::HashMap::new(),
                    },
                    HelperInfo {
                        channel_id: 12,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://helper-b.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        shared_key: vec![0xAB; 32],
                        communication_info: std::collections::HashMap::new(),
                    },
                ],
                secrets: Vec::new(),
                replicas: Some(Replicas {
                    channel_id: 21,
                    members: vec![ReplicaInfo {
                        replica_id: 0xCAFE,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "grpcs://replica.example:443".to_owned(),
                            protocol: derec_proto::Protocol::Grpc as i32,
                        }],
                        role: ReplicaRole::Destination as i32,
                        communication_info: std::collections::HashMap::new(),
                    }],
                    shared_key: vec![0xCC; 32],
                }),
            };

            let mut rig = StoreRig::new();

            super::hydrate(&mut rig.stores(), &lf.local(), 4, &secret, String::new())
                .await
                .expect("a grpc roster must hydrate");

            let expected = [(11_u64, Protocol::Grpc), (12, Protocol::Https)];
            for (channel_id, protocol) in expected {
                let record = rig
                    .channels
                    .load(
                        SECRET_ID,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(channel_id),
                        },
                    )
                    .await
                    .unwrap()
                    .expect("helper channel must be persisted");
                let ChannelRecord::Helper(record) = record else {
                    panic!("a helper query must never return a replica record");
                };
                assert_eq!(
                    record.transports[0].protocol, protocol as i32,
                    "helper {channel_id} must carry the protocol its URI scheme names"
                );
                for endpoint in &record.transports {
                    crate::transport::TransportProtocol::try_from(endpoint)
                        .expect("every rehydrated endpoint must be self-consistent");
                }
            }

            let member = rig
                .channels
                .load(
                    SECRET_ID,
                    ChannelQuery::Replica {
                        channel_id: ChannelId(21),
                        replica_id: crate::types::ReplicaId(0xCAFE),
                    },
                )
                .await
                .unwrap()
                .expect("group member must be persisted");
            let ChannelRecord::Replica(member) = member else {
                panic!("a replica query must never return a helper record");
            };
            assert_eq!(member.transports[0].protocol, Protocol::Grpc as i32);
        });
    }

    /// Author attribution must come from the payload, not from whoever
    /// established the channel. Once a member admitted by a third party
    /// receives updates from every other member over one group channel,
    /// `channel.replica_id` names the admitter — not the writer — so
    /// reading it would misattribute every forwarded update.
    #[test]
    fn replica_ack_attributes_the_responder_from_the_payload() {
        run_async(async {
            let lf = LocalFixture::new(SECRET_ID);
            const SECRET_ID: u64 = 0xA11CE;
            const CHANNEL_PEER: u64 = 1002;
            const ACTUAL_RESPONDER: u64 = 1003;

            let channel = crate::protocol::types::ReplicaMember {
                channel_id: ChannelId(5001),
                // The member row the response arrived against is Alice-2 …
                replica_id: crate::types::ReplicaId(CHANNEL_PEER),
                transports: vec![TransportProtocol {
                    uri: "https://alice-2.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                communication_info: std::collections::HashMap::new(),
                status: crate::protocol::types::ChannelStatus::Paired,
                created_at: 0,
                role: crate::protocol::types::ReplicaRole::Destination,
            };

            let response = derec_proto::StoreShareResponseMessage {
                result: Some(derec_proto::DeRecResult {
                    status: derec_proto::StatusEnum::Ok as i32,
                    memo: String::new(),
                }),
                secret_id: SECRET_ID,
                version: 3,
                timestamp: None,
                // … but Alice-3 is the one answering.
                replica_id: Some(ACTUAL_RESPONDER),
            };

            let mut rig = StoreRig::new();
            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
                channel.channel_id,
                &channel,
                &response,
            )
            .await
            .expect("ack is handled");

            match events.as_slice() {
                [
                    crate::protocol::DeRecEvent::ReplicaSecretAcked {
                        from_replica_id, ..
                    },
                ] => assert_eq!(
                    *from_replica_id, ACTUAL_RESPONDER,
                    "the responder names itself; the channel's counterparty is not the author"
                ),
                other => panic!("expected a single ReplicaSecretAcked, got {other:?}"),
            }
        });
    }

    /// A second roster on a device that already holds the secret reports
    /// `ReplicaSecretReceived`, not `ReplicaSecretInstalled`.
    ///
    /// The distinction is the application's cue to run its first-install logic
    /// exactly once. It is decided by whether a user-secret snapshot exists,
    /// so it only holds if the answer is read from the partition the snapshot
    /// was written to.
    ///
    /// The destination here runs under a **different `secret_id` than the
    /// sender**, which is the arrangement that broke this: a destination is
    /// not required to have been configured with the owner's id, and reading
    /// the store under the wire id found nothing this device ever wrote, so
    /// every round reported a first install.
    #[test]
    fn a_second_roster_reports_received_not_installed() {
        run_async(async {
            use crate::protocol::types::{ReplicaInfo, Replicas, Secret};

            const OWNER: u64 = 1001;
            const SELF_ID: u64 = 1002;
            /// The sender's `secret_id`, deliberately not this device's.
            const WIRE_SECRET_ID: u64 = 0xC0FFEE;

            let lf = LocalFixture::with_replica(SECRET_ID, SELF_ID);
            let mut rig = StoreRig::new();
            seed_member(
                &mut rig.channels,
                OWNER,
                ReplicaRole::Source,
                "https://owner",
            )
            .await;
            seed_member(
                &mut rig.channels,
                SELF_ID,
                ReplicaRole::Destination,
                "https://self",
            )
            .await;

            let channel = rig
                .channels
                .load(
                    SECRET_ID,
                    crate::protocol::types::ChannelQuery::Replica {
                        channel_id: GROUP_CHANNEL,
                        replica_id: ReplicaId(OWNER),
                    },
                )
                .await
                .expect("load")
                .and_then(|r| r.as_replica().cloned())
                .expect("seeded member");

            let roster = || Secret {
                helpers: Vec::new(),
                secrets: Vec::new(),
                replicas: Some(Replicas {
                    channel_id: GROUP_CHANNEL.0,
                    members: vec![
                        ReplicaInfo {
                            replica_id: OWNER,
                            transports: vec![endpoint("https://owner")],
                            role: ReplicaRole::Source as i32,
                            communication_info: std::collections::HashMap::new(),
                        },
                        ReplicaInfo {
                            replica_id: SELF_ID,
                            transports: vec![endpoint("https://self")],
                            role: ReplicaRole::Destination as i32,
                            communication_info: std::collections::HashMap::new(),
                        },
                    ],
                    shared_key: vec![0x42; 32],
                }),
            };

            let request = |version: u32| {
                let payload = crate::protocol::types::ReplicaSecretPayload {
                    secret: Some(roster()),
                    shares: Vec::new(),
                    shared_key: Vec::new(),
                };
                derec_proto::StoreShareRequestMessage {
                    secret_id: WIRE_SECRET_ID,
                    share: prost::Message::encode_to_vec(&payload),
                    version,
                    version_description: String::new(),
                    share_algorithm: 0,
                    keep_list: Vec::new(),
                    replica_id: Some(OWNER),
                    reply_to: Vec::new(),
                    timestamp: None,
                }
            };

            let first = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request(1),
                [0x11; 32],
                7,
            )
            .await
            .expect("first roster");
            assert!(
                first.iter().any(|e| matches!(
                    e,
                    crate::protocol::DeRecEvent::ReplicaSecretInstalled { .. }
                )),
                "the first roster installs; got {first:?}"
            );

            let second = super::on_request(
                &mut rig.stores(),
                &lf.local(),
                &channel,
                request(2),
                [0x11; 32],
                8,
            )
            .await
            .expect("second roster");
            assert!(
                second.iter().any(|e| matches!(
                    e,
                    crate::protocol::DeRecEvent::ReplicaSecretReceived { .. }
                )),
                "a device that already holds the secret receives rather than installs; got {second:?}"
            );

            // The events still echo the sender's id, which is what names the
            // secret on the wire — only store access moved to the local one.
            let echoed = second.iter().find_map(|e| match e {
                crate::protocol::DeRecEvent::ReplicaSecretReceived { secret_id, .. } => {
                    Some(*secret_id)
                }
                _ => None,
            });
            assert_eq!(
                echoed,
                Some(WIRE_SECRET_ID),
                "the event echoes the inbound secret_id, not the local partition"
            );
        });
    }

    /// Build a roster in which `source_id` holds the source role.
    async fn roster_with_source(source_id: u64) -> crate::protocol::types::Secret {
        let mut rig = StoreRig::new();
        for id in [1001u64, 1002] {
            let role = if id == source_id {
                ReplicaRole::Source
            } else {
                ReplicaRole::Destination
            };
            seed_member(&mut rig.channels, id, role, "https://peer").await;
        }
        let roster = rig
            .channels
            .replicas(SECRET_ID, crate::protocol::types::ReplicaFilter::default())
            .await
            .expect("roster");
        crate::protocol::handlers::sharing::build_secret(
            &[],
            &roster,
            Vec::new(),
            Some(GROUP_CHANNEL),
            Some([0x42; 32]),
        )
        .expect("build secret")
    }

    /// R1 — the successor learns of its promotion from the roster that carries
    /// it, without deriving anything locally.
    #[test]
    fn a_roster_that_promotes_this_device_reports_it() {
        run_async(async {
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1002).await;

            let event = super::promotion_event(&lf.local(), false, &secret);

            assert!(
                matches!(
                    event,
                    Some(super::DeRecEvent::ReplicaSourceChanged { replica_id })
                        if replica_id == 1002
                ),
                "got {event:?}"
            );
        });
    }

    /// R1 — a roster restating an unchanged source is not a promotion.
    #[test]
    fn an_unchanged_source_is_not_reported_again() {
        run_async(async {
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1002).await;

            assert!(
                super::promotion_event(&lf.local(), true, &secret).is_none(),
                "only the transition is an event"
            );
        });
    }

    /// R1 — a member the roster leaves as a destination is unaffected. It
    /// learns the new source from the roster like any other field.
    #[test]
    fn a_destination_is_not_promoted() {
        run_async(async {
            let lf = LocalFixture::with_replica(0, 1002);
            let secret = roster_with_source(1001).await;

            assert!(super::promotion_event(&lf.local(), false, &secret).is_none());
        });
    }
}
