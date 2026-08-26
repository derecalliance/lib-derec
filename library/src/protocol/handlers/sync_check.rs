// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Replica catch-up: a member that was offline pulls the current state.
//!
//! A member is never *partially* behind — every sync carries the whole secret
//! and the whole roster, so it simply holds an older version, and any later
//! publish brings it fully current. Convergence is automatic while the group
//! is writing. This closes the remaining gap: a quiet group, where nobody has
//! written since the member came back.
//!
//! The device that was away is the one that knows it was away, so it pulls.
//! No durable per-member sync state is kept anywhere.
//!
//! # The exchange
//!
//! It reuses the discovery and get-share messages, overloaded on the replica
//! path exactly as [`derec_proto::StoreShareRequestMessage`] already is — a
//! share to a helper, the whole secret to a member.
//!
//! 1. [`start`] asks every other member which version it holds.
//! 2. [`answer_versions`] replies with the one secret and version this device
//!    holds. A member serves exactly one secret, unlike a helper.
//! 3. [`collect_version`] accumulates. Once every member has answered, the one
//!    holding the newest state is asked for it; ties resolve to the `Source`.
//! 4. [`answer_share`] replies with the whole `ReplicaSecretPayload` under
//!    `share_algorithm = SHARE_ALGORITHM_REPLICA_SECRET`.
//! 5. [`accept_share`] hydrates it, reporting install or update as usual.
//!
//! A member reporting an *older* version than the asker is ignored: the asker
//! is already current with respect to it. The check never turns into a
//! publish — a read-shaped operation that silently wrote to peers would
//! surprise its caller, and that peer's own application is the right place to
//! decide whether being behind matters.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore, SecretKind, SecretValue, StateItem, StateKey,
};
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::primitives::sharing::request::SHARE_ALGORITHM_REPLICA_SECRET;
use crate::protocol::types::ReplicaMember;
use crate::types::{ChannelId, ReplicaId, SharedKey};
use crate::{Error, Result};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    GetShareRequestMessage, GetShareResponseMessage, MessageBody, StatusEnum,
    get_secret_ids_versions_response_message::VersionList,
    get_secret_ids_versions_response_message::version_list::VersionEntry,
};
use prost::Message as _;
use std::collections::{HashMap, HashSet};

#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

/// Ask every other member which version it holds.
///
/// Returns `Ok(None)` when there is nobody to ask — a device with no peers is
/// trivially current, and starting a round that can never complete would
/// leave state behind for the timeout sweep to clear.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(secret_id)))]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    St: DeRecStateStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &Us,
    state_store: &mut St,
    transport: &T,
    secret_id: u64,
    local_replica_id: Option<u64>,
    own_transport: &derec_proto::TransportProtocol,
) -> Result<Vec<DeRecEvent>> {
    let own = local_replica_id.ok_or(Error::ReplicaIdNotConfigured)?;

    let peers: Vec<ReplicaMember> = channel_store
        .replicas(secret_id)
        .await?
        .into_iter()
        .filter(|m| m.replica_id.0 != own)
        .collect();

    if peers.is_empty() {
        return Ok(Vec::new());
    }

    let local_version = user_secret_store
        .load_latest(secret_id)
        .await?
        .map(|s| s.version)
        .unwrap_or(0);

    let group_channel = peers[0].channel_id;
    let key = load_channel_key(secret_store, secret_id, group_channel).await?;

    let mut asked: HashSet<ReplicaId> = HashSet::new();
    for peer in &peers {
        let timestamp = current_timestamp();
        let request = GetSecretIdsVersionsRequestMessage {
            timestamp: Some(timestamp),
            // The asker names itself so the answer can be routed back to a
            // member rather than treated as an owner ↔ helper exchange.
            replica_id: Some(own),
            reply_to: Some(own_transport.clone()),
        };
        let envelope = DeRecMessageBuilder::channel()
            .channel_id(peer.channel_id)
            .timestamp(timestamp)
            .message_body(MessageBody::GetSecretIdsVersionsRequest(request))
            .encrypt(&key)?
            .build()?
            .encode_to_vec();

        // A peer we cannot reach is simply not waited on: it can never
        // answer, and counting it would stall the check until the timeout.
        if transport.send(&peer.transport, envelope).await.is_ok() {
            asked.insert(peer.replica_id);
        }
    }

    if asked.is_empty() {
        return Ok(vec![DeRecEvent::SyncCheckComplete {
            local_version,
            group_version: 0,
            fetched_from: None,
        }]);
    }

    state_store
        .save(
            secret_id,
            StateItem::PendingSyncCheck {
                local_version,
                pending: asked,
                reported: HashMap::new(),
                started_at: now_secs(),
            },
        )
        .await?;

    Ok(Vec::new())
}

/// Answer another member's version query.
///
/// A member serves exactly one secret, so the response carries exactly one
/// entry — unlike a helper, which may hold many.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn answer_versions<Us: DeRecUserSecretStore, T: DeRecTransport>(
    user_secret_store: &Us,
    transport: &T,
    member: &ReplicaMember,
    request: &GetSecretIdsVersionsRequestMessage,
    shared_key: SharedKey,
    secret_id: u64,
    local_replica_id: Option<u64>,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let version = user_secret_store
        .load_latest(secret_id)
        .await?
        .map(|s| s.version);

    let timestamp = current_timestamp();
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        // A device holding no snapshot reports nothing rather than version 0,
        // which would be indistinguishable from "I hold the empty version".
        secret_list: version
            .map(|version| VersionList {
                secret_id,
                versions: vec![VersionEntry {
                    version,
                    version_description: String::new(),
                }],
            })
            .into_iter()
            .collect(),
        timestamp: Some(timestamp),
        replica_id: local_replica_id,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsResponse(response))
        .encrypt(&shared_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope, inbound_trace_id)?;
    let endpoint = request
        .reply_to
        .clone()
        .unwrap_or_else(|| member.transport.clone());
    transport.send(&endpoint, envelope).await?;

    Ok(vec![DeRecEvent::NoOp])
}

/// Record one member's reported version; fetch once everyone has answered.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn collect_version<
    Ss: DeRecSecretStore,
    St: DeRecStateStore,
    Ch: DeRecChannelStore,
    T: DeRecTransport,
>(
    channel_store: &Ch,
    secret_store: &mut Ss,
    state_store: &mut St,
    transport: &T,
    secret_id: u64,
    from: ReplicaId,
    response: &GetSecretIdsVersionsResponseMessage,
    local_replica_id: Option<u64>,
    own_transport: &derec_proto::TransportProtocol,
) -> Result<Vec<DeRecEvent>> {
    let Some(StateItem::PendingSyncCheck {
        local_version,
        mut pending,
        mut reported,
        started_at,
    }) = state_store
        .load(secret_id, StateKey::PendingSyncCheck)
        .await?
    else {
        // No check in flight — a late answer from an abandoned one.
        return Ok(vec![DeRecEvent::NoOp]);
    };

    if pending.remove(&from) {
        // A member with no snapshot reports no entry at all; treat that as
        // version 0 rather than skipping it, so the tally stays complete.
        let version = response
            .secret_list
            .iter()
            .flat_map(|list| list.versions.iter())
            .map(|v| v.version)
            .max()
            .unwrap_or(0);
        reported.insert(from, version);
    }

    if !pending.is_empty() {
        state_store
            .save(
                secret_id,
                StateItem::PendingSyncCheck {
                    local_version,
                    pending,
                    reported,
                    started_at,
                },
            )
            .await?;
        return Ok(vec![DeRecEvent::NoOp]);
    }

    state_store
        .remove(secret_id, StateKey::PendingSyncCheck)
        .await?;
    finish(
        channel_store,
        secret_store,
        transport,
        secret_id,
        local_version,
        &reported,
        local_replica_id,
        own_transport,
    )
    .await
}

/// Choose the member holding the newest state and ask it, or report that this
/// device is already current.
#[allow(clippy::too_many_arguments)]
async fn finish<Ch: DeRecChannelStore, Ss: DeRecSecretStore, T: DeRecTransport>(
    channel_store: &Ch,
    secret_store: &mut Ss,
    transport: &T,
    secret_id: u64,
    local_version: u32,
    reported: &HashMap<ReplicaId, u32>,
    local_replica_id: Option<u64>,
    own_transport: &derec_proto::TransportProtocol,
) -> Result<Vec<DeRecEvent>> {
    let group_version = reported.values().copied().max().unwrap_or(0);

    if group_version <= local_version {
        // Members reporting an older version are ignored: this device is
        // current with respect to them, and the check never writes to a peer.
        return Ok(vec![DeRecEvent::SyncCheckComplete {
            local_version,
            group_version,
            fetched_from: None,
        }]);
    }

    let roster = channel_store.replicas(secret_id).await?;
    let source: Option<ReplicaId> = roster
        .iter()
        .find(|m| m.role == crate::protocol::types::ReplicaRole::Source)
        .map(|m| m.replica_id);

    // Ties resolve to the Source; failing that, to the lowest id, so the
    // choice is deterministic rather than dependent on map iteration order.
    let winner = reported
        .iter()
        .filter(|(_, v)| **v == group_version)
        .map(|(id, _)| *id)
        .min_by_key(|id| (Some(*id) != source, id.0))
        .ok_or(Error::Invariant(
            "a newer group version was reported by nobody",
        ))?;

    let member = roster
        .iter()
        .find(|m| m.replica_id == winner)
        .ok_or(Error::InvalidInput(
            "the member holding the newest state is no longer in the roster",
        ))?;

    let key = load_channel_key(secret_store, secret_id, member.channel_id).await?;
    let timestamp = current_timestamp();
    let request = GetShareRequestMessage {
        secret_id,
        version: group_version,
        timestamp: Some(timestamp),
        reply_to: Some(own_transport.clone()),
        replica_id: local_replica_id,
    };
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareRequest(request))
        .encrypt(&key)?
        .build()?
        .encode_to_vec();
    transport.send(&member.transport, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        local_version,
        group_version,
        from = winner.0,
        "replica catch-up: fetching the newest state"
    );

    Ok(vec![DeRecEvent::SyncCheckComplete {
        local_version,
        group_version,
        fetched_from: Some(winner.0),
    }])
}

/// Serve another member's request for the current state.
///
/// The reply carries the whole secret under
/// `SHARE_ALGORITHM_REPLICA_SECRET`, not a share — the same overload a
/// publish uses on the replica path.
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn answer_share<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &Us,
    transport: &T,
    member: &ReplicaMember,
    request: &GetShareRequestMessage,
    shared_key: SharedKey,
    secret_id: u64,
    local_replica_id: Option<u64>,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let composite = super::sharing::build_catch_up_payload(
        channel_store,
        secret_store,
        user_secret_store,
        secret_id,
        local_replica_id,
    )
    .await?;

    let (status, memo, share) = match composite {
        Some(payload) => (StatusEnum::Ok, String::new(), payload.encode_to_vec()),
        None => (
            StatusEnum::UnknownSecretId,
            "this device holds no state for that secret".to_owned(),
            Vec::new(),
        ),
    };

    let timestamp = current_timestamp();
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo,
        }),
        committed_de_rec_share: share,
        // The discriminator: the bytes are the whole secret, not a share.
        share_algorithm: SHARE_ALGORITHM_REPLICA_SECRET,
        timestamp: Some(timestamp),
        secret_id,
        version: request.version,
        replica_id: local_replica_id,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareResponse(response))
        .encrypt(&shared_key)?
        .build()?
        .encode_to_vec();
    let envelope = super::apply_trace_id(envelope, inbound_trace_id)?;
    let endpoint = request
        .reply_to
        .clone()
        .unwrap_or_else(|| member.transport.clone());
    transport.send(&endpoint, envelope).await?;

    Ok(vec![DeRecEvent::NoOp])
}

/// Hydrate the state a peer served.
pub(in crate::protocol) async fn accept_share<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    user_secret_store: &mut Us,
    secret_id: u64,
    from: ReplicaId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let status = response.result.as_ref().map(|r| r.status).unwrap_or(-1);
    if status != StatusEnum::Ok as i32 {
        return Ok(vec![DeRecEvent::NoOp]);
    }
    if response.share_algorithm != SHARE_ALGORITHM_REPLICA_SECRET {
        return Err(Error::InvalidInput(
            "a member answered a catch-up with a helper share rather than the secret",
        ));
    }

    super::sharing::hydrate_catch_up(
        channel_store,
        secret_store,
        user_secret_store,
        secret_id,
        from.0,
        response.version,
        &response.committed_de_rec_share,
    )
    .await
}

async fn load_channel_key<Ss: DeRecSecretStore>(
    secret_store: &mut Ss,
    secret_id: u64,
    channel_id: ChannelId,
) -> Result<SharedKey> {
    match secret_store
        .load(secret_id, channel_id, SecretKind::SharedKey)
        .await?
    {
        Some(SecretValue::SharedKey(key)) => Ok(key),
        _ => Err(Error::InvalidInput(
            "channel has no shared key — not yet paired",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemUserSecretStore,
        RecordingTransport, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, ReplicaRole, UserSecrets};

    const SECRET_ID: u64 = 0xCA7C4;
    const GROUP: ChannelId = ChannelId(5001);

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    async fn seed(channels: &mut InMemChannelStore, id: u64, role: ReplicaRole, uri: &str) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(id),
                    transport: endpoint(uri),
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed member");
    }

    async fn seed_key(secrets: &mut InMemSecretStore) {
        secrets
            .save(SECRET_ID, GROUP, SecretValue::SharedKey([0x11; 32]))
            .await
            .expect("seed key");
    }

    async fn seed_version(store: &mut InMemUserSecretStore, version: u32) {
        store
            .save_latest(
                SECRET_ID,
                UserSecrets {
                    version,
                    secrets: Vec::new(),
                    description: None,
                    replicas: None,
                },
            )
            .await
            .expect("seed snapshot");
    }

    fn versions_response(version: Option<u32>) -> GetSecretIdsVersionsResponseMessage {
        GetSecretIdsVersionsResponseMessage {
            result: Some(DeRecResult {
                status: StatusEnum::Ok as i32,
                memo: String::new(),
            }),
            secret_list: version
                .map(|version| VersionList {
                    secret_id: SECRET_ID,
                    versions: vec![VersionEntry {
                        version,
                        version_description: String::new(),
                    }],
                })
                .into_iter()
                .collect(),
            timestamp: None,
            replica_id: None,
        }
    }

    /// The asker addresses every member but itself — a self-addressed query
    /// could never be answered.
    #[test]
    fn start_asks_every_member_but_itself() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let mut user_secrets = InMemUserSecretStore::default();
            let mut state = InMemPersistedStateStore::default();
            let transport = RecordingTransport::default();

            seed(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut secrets).await;
            seed_version(&mut user_secrets, 5).await;

            super::start(
                &mut channels,
                &mut secrets,
                &user_secrets,
                &mut state,
                &transport,
                SECRET_ID,
                Some(1002),
                &endpoint("https://alice-2"),
            )
            .await
            .expect("start succeeds");

            let sent = transport.sent_uris();
            assert_eq!(sent.len(), 2, "two peers asked, not three");
            assert!(
                !sent.iter().any(|u| u == "https://alice-2"),
                "the asker must not query itself, got {sent:?}"
            );
        });
    }

    /// A device already current reports so and fetches nothing. This is the
    /// "asker is ahead or level" case: peers behind it are ignored, and the
    /// check never turns into a publish.
    #[test]
    fn a_current_device_fetches_nothing() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let mut state = InMemPersistedStateStore::default();
            let transport = RecordingTransport::default();

            seed(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            state
                .save(
                    SECRET_ID,
                    StateItem::PendingSyncCheck {
                        local_version: 7,
                        pending: HashSet::from([ReplicaId(1001)]),
                        reported: HashMap::new(),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            // The only peer reports an older version.
            let events = super::collect_version(
                &channels,
                &mut secrets,
                &mut state,
                &transport,
                SECRET_ID,
                ReplicaId(1001),
                &versions_response(Some(5)),
                Some(1002),
                &endpoint("https://alice-2"),
            )
            .await
            .expect("collect succeeds");

            match events.as_slice() {
                [
                    DeRecEvent::SyncCheckComplete {
                        local_version,
                        group_version,
                        fetched_from,
                    },
                ] => {
                    assert_eq!((*local_version, *group_version), (7, 5));
                    assert!(
                        fetched_from.is_none(),
                        "a member behind us must not be fetched from"
                    );
                }
                other => panic!("expected SyncCheckComplete, got {other:?}"),
            }
            assert!(
                transport.sent_uris().is_empty(),
                "a check that finds nothing newer must not send anything"
            );
        });
    }

    /// The newest member is the one asked, and the fetch is addressed to it.
    #[test]
    fn the_newest_member_is_fetched_from() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let mut state = InMemPersistedStateStore::default();
            let transport = RecordingTransport::default();

            seed(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut secrets).await;
            state
                .save(
                    SECRET_ID,
                    StateItem::PendingSyncCheck {
                        local_version: 5,
                        pending: HashSet::from([ReplicaId(1001), ReplicaId(1003)]),
                        reported: HashMap::new(),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            // The source is at v6; alice-3 is further ahead at v7.
            let events = super::collect_version(
                &channels,
                &mut secrets,
                &mut state,
                &transport,
                SECRET_ID,
                ReplicaId(1001),
                &versions_response(Some(6)),
                Some(1002),
                &endpoint("https://alice-2"),
            )
            .await
            .expect("first answer");
            assert!(
                matches!(events.as_slice(), [DeRecEvent::NoOp]),
                "the check stays open until every member has answered"
            );

            let events = super::collect_version(
                &channels,
                &mut secrets,
                &mut state,
                &transport,
                SECRET_ID,
                ReplicaId(1003),
                &versions_response(Some(7)),
                Some(1002),
                &endpoint("https://alice-2"),
            )
            .await
            .expect("second answer");

            match events.as_slice() {
                [
                    DeRecEvent::SyncCheckComplete {
                        group_version,
                        fetched_from,
                        ..
                    },
                ] => {
                    assert_eq!(*group_version, 7);
                    assert_eq!(
                        *fetched_from,
                        Some(1003),
                        "the member holding the newest state is the one asked"
                    );
                }
                other => panic!("expected SyncCheckComplete, got {other:?}"),
            }
            assert_eq!(
                transport.sent_uris(),
                vec!["https://alice-3".to_owned()],
                "the fetch is addressed to that member, not broadcast"
            );
        });
    }

    /// A tie resolves to the Source rather than to whichever member the map
    /// happened to yield first.
    #[test]
    fn a_tie_resolves_to_the_source() {
        run_async(async {
            let mut channels = InMemChannelStore::default();
            let mut secrets = InMemSecretStore::default();
            let mut state = InMemPersistedStateStore::default();
            let transport = RecordingTransport::default();

            seed(&mut channels, 1001, ReplicaRole::Source, "https://alice").await;
            seed(
                &mut channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut secrets).await;
            state
                .save(
                    SECRET_ID,
                    StateItem::PendingSyncCheck {
                        local_version: 5,
                        pending: HashSet::from([ReplicaId(1001)]),
                        reported: HashMap::from([(ReplicaId(1003), 7)]),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            let events = super::collect_version(
                &channels,
                &mut secrets,
                &mut state,
                &transport,
                SECRET_ID,
                ReplicaId(1001),
                &versions_response(Some(7)),
                Some(1002),
                &endpoint("https://alice-2"),
            )
            .await
            .expect("collect succeeds");

            match events.as_slice() {
                [DeRecEvent::SyncCheckComplete { fetched_from, .. }] => assert_eq!(
                    *fetched_from,
                    Some(1001),
                    "both are at v7; the Source wins the tie"
                ),
                other => panic!("expected SyncCheckComplete, got {other:?}"),
            }
        });
    }
}
