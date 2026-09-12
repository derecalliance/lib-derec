// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The replica side of discovery.
//!
//! `GetSecretIdsVersions` serves both relationships. Against a helper it asks
//! what that helper is holding; against another group member it asks which
//! version of the one shared secret that member has, which is the first leg
//! of catch-up. The owner↔helper side lives in
//! [`handlers::discovery`](super::super::discovery), which routes here when
//! the payload names an author.
use super::load_channel_key;
use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::extensions::channel_store::ChannelStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::ReplicaMember;
use crate::protocol::{
    DeRecEvent, DeRecStateStore, DeRecTransport, DeRecUserSecretStore, StateItem, StateKey,
};
use crate::types::{ReplicaId, SharedKey};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use crate::{Error, Result};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    GetShareRequestMessage, MessageBody, StatusEnum,
    get_secret_ids_versions_response_message::VersionList,
    get_secret_ids_versions_response_message::version_list::VersionEntry,
};
use prost::Message as _;
use std::collections::{HashMap, HashSet};

/// Handle a discovery message a group member authored.
///
/// The author is what the request must be answered to and what a response is
/// attributed to, so resolving it is this module's job rather than the
/// dispatcher's.
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    author: u64,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetSecretIdsVersionsRequest(request) => {
            let member = stores
                .channels
                .load_replica_member(local.secret_id, exchange.channel_id, author)
                .await?;
            on_request(
                stores,
                local,
                &member,
                &request,
                *exchange.shared_key,
                exchange.trace_id,
            )
            .await
        }
        MessageBody::GetSecretIdsVersionsResponse(response) => {
            on_response(stores, local, ReplicaId::try_from(author)?, &response).await
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in replica discovery handler",
        )),
    }
}

/// Ask every other member which version it holds.
///
/// Returns `Ok(None)` when there is nobody to ask — a device with no peers is
/// trivially current, and starting a round that can never complete would
/// leave state behind for the timeout sweep to clear.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = trace_id, local.secret_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let own = local.replica_id.ok_or(Error::ReplicaIdNotConfigured)?;

    let peers: Vec<ReplicaMember> = stores
        .channels
        .replicas_matching(
            secret_id,
            crate::protocol::types::ReplicaFilter {
                exclude: local.exclude_self(),
                ..Default::default()
            },
        )
        .await?;

    if peers.is_empty() {
        return Ok(Vec::new());
    }

    let local_version = stores
        .user_secrets
        .load_latest(secret_id)
        .await?
        .map(|s| s.version)
        .unwrap_or(0);

    let group_channel = peers[0].channel_id;
    let key = load_channel_key(stores, local, group_channel).await?;

    let mut asked: HashSet<ReplicaId> = HashSet::new();
    for peer in &peers {
        let timestamp = current_timestamp();
        let (legacy_reply_to, reply_to_transports) =
            crate::extensions::advertised_endpoints::split_reply_to(std::slice::from_ref(
                local.primary(),
            ));
        // Populating the deprecated singular field is the compatibility
        // path that keeps peers predating `replyToTransports`
        // answerable, so the warning is expected here.
        #[allow(deprecated)]
        let request = GetSecretIdsVersionsRequestMessage {
            timestamp: Some(timestamp),
            // The asker names itself so the answer can be routed back to a
            // member rather than treated as an owner ↔ helper exchange.
            replica_id: Some(own),
            reply_to: legacy_reply_to,
            reply_to_transports,
        };
        let envelope = DeRecMessageBuilder::channel()
            .channel_id(peer.channel_id)
            .timestamp(timestamp)
            .message_body(MessageBody::GetSecretIdsVersionsRequest(request))
            .trace_id(trace_id)
            .encrypt(&key)?
            .build()?
            .encode_to_vec();

        // A peer we cannot reach is simply not waited on: it can never
        // answer, and counting it would stall the check until the timeout.
        if stores
            .transport
            .send(&peer.transports, envelope)
            .await
            .is_ok()
        {
            asked.insert(peer.replica_id);
        }
    }

    if asked.is_empty() {
        return Ok(vec![DeRecEvent::ReplicaDiscoveryComplete {
            local_version,
            group_version: 0,
            fetched_from: None,
        }]);
    }

    stores
        .state
        .save(
            secret_id,
            StateItem::PendingReplicaDiscovery {
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
async fn on_request<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    member: &ReplicaMember,
    request: &GetSecretIdsVersionsRequestMessage,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let version = stores
        .user_secrets
        .load_latest(local.secret_id)
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
                secret_id: local.secret_id,
                versions: vec![VersionEntry {
                    version,
                    version_description: String::new(),
                }],
            })
            .into_iter()
            .collect(),
        timestamp: Some(timestamp),
        replica_id: local.replica_id,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsResponse(response))
        .encrypt(&shared_key)?
        .build()?
        .encode_to_vec();
    let envelope = crate::derec_message::apply_trace_id(&envelope, inbound_trace_id)?;
    // A reply-to overrides the recorded endpoints for this exchange only.
    let reply_to = crate::extensions::advertised_endpoints::reply_to_owned(request);
    let endpoint = if reply_to.is_empty() {
        member.transports.clone()
    } else {
        reply_to
    };
    stores.transport.send(&endpoint, envelope).await?;

    Ok(vec![DeRecEvent::NoOp])
}

/// Record one member's reported version; fetch once everyone has answered.
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    from: ReplicaId,
    response: &GetSecretIdsVersionsResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let Some(StateItem::PendingReplicaDiscovery {
        local_version,
        mut pending,
        mut reported,
        started_at,
    }) = stores
        .state
        .load(secret_id, StateKey::PendingReplicaDiscovery)
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
        stores
            .state
            .save(
                secret_id,
                StateItem::PendingReplicaDiscovery {
                    local_version,
                    pending,
                    reported,
                    started_at,
                },
            )
            .await?;
        return Ok(vec![DeRecEvent::NoOp]);
    }

    stores
        .state
        .remove(secret_id, StateKey::PendingReplicaDiscovery)
        .await?;
    finish(stores, local, local_version, &reported).await
}

/// Choose the member holding the newest state and ask it, or report that this
/// device is already current.
async fn finish<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    local_version: u32,
    reported: &HashMap<ReplicaId, u32>,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let group_version = reported.values().copied().max().unwrap_or(0);

    if group_version <= local_version {
        // Members reporting an older version are ignored: this device is
        // current with respect to them, and the check never writes to a peer.
        return Ok(vec![DeRecEvent::ReplicaDiscoveryComplete {
            local_version,
            group_version,
            fetched_from: None,
        }]);
    }

    let source: Option<ReplicaId> = stores
        .channels
        .replicas_matching(
            secret_id,
            crate::protocol::types::ReplicaFilter {
                role: Some(crate::protocol::types::ReplicaRole::Source),
                ..Default::default()
            },
        )
        .await?
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

    let member = stores
        .channels
        .replicas_matching(
            secret_id,
            crate::protocol::types::ReplicaFilter {
                ids: vec![winner],
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .find(|m| m.replica_id == winner)
        .ok_or(Error::InvalidInput(
            "the member holding the newest state is no longer in the roster",
        ))?;

    let key = load_channel_key(stores, local, member.channel_id).await?;
    let timestamp = current_timestamp();
    let (legacy_reply_to, reply_to_transports) =
        crate::extensions::advertised_endpoints::split_reply_to(std::slice::from_ref(
            local.primary(),
        ));
    // Populating the deprecated singular field is the compatibility
    // path that keeps peers predating `replyToTransports`
    // answerable, so the warning is expected here.
    #[allow(deprecated)]
    let request = GetShareRequestMessage {
        secret_id,
        version: group_version,
        timestamp: Some(timestamp),
        reply_to: legacy_reply_to,
        reply_to_transports,
        replica_id: local.replica_id,
    };
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(member.channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetShareRequest(request))
        .encrypt(&key)?
        .build()?
        .encode_to_vec();
    stores.transport.send(&member.transports, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        local_version,
        group_version,
        from = winner.0,
        "replica catch-up: fetching the newest state"
    );

    Ok(vec![DeRecEvent::ReplicaDiscoveryComplete {
        local_version,
        group_version,
        fetched_from: Some(winner.0),
    }])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::DeRecSecretStore;
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemUserSecretStore, StoreRig, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, ReplicaRole, SecretValue, UserSecrets,
    };
    use crate::types::ChannelId;
    use std::collections::HashSet;

    const SECRET_ID: u64 = 0xCA7C4;
    const GROUP: ChannelId = ChannelId(5001);

    fn endpoint(uri: &str) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    use crate::protocol::DeRecChannelStore as _;

    async fn seed(channels: &mut InMemChannelStore, id: u64, role: ReplicaRole, uri: &str) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(id),
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

    /// A fixed round token, so a test can assert what reaches the wire.
    const TRACE_ID: u64 = 0x7ACE;

    /// A device already current reports so and fetches nothing. This is the
    /// "asker is ahead or level" case: peers behind it are ignored, and the
    /// check never turns into a publish.
    #[test]
    fn a_current_device_fetches_nothing() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            seed(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingReplicaDiscovery {
                        local_version: 7,
                        pending: HashSet::from([ReplicaId(1001)]),
                        reported: HashMap::new(),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            // The only peer reports an older version.
            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
                ReplicaId(1001),
                &versions_response(Some(5)),
            )
            .await
            .expect("collect succeeds");

            match events.as_slice() {
                [
                    DeRecEvent::ReplicaDiscoveryComplete {
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
                other => panic!("expected ReplicaDiscoveryComplete, got {other:?}"),
            }
            assert!(
                rig.transport.sent_uris().is_empty(),
                "a check that finds nothing newer must not send anything"
            );
        });
    }

    /// The newest member is the one asked, and the fetch is addressed to it.
    #[test]
    fn the_newest_member_is_fetched_from() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            seed(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut rig.channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut rig.secrets).await;
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingReplicaDiscovery {
                        local_version: 5,
                        pending: HashSet::from([ReplicaId(1001), ReplicaId(1003)]),
                        reported: HashMap::new(),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            // The source is at v6; alice-3 is further ahead at v7.
            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
                ReplicaId(1001),
                &versions_response(Some(6)),
            )
            .await
            .expect("first answer");
            assert!(
                matches!(events.as_slice(), [DeRecEvent::NoOp]),
                "the check stays open until every member has answered"
            );

            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
                ReplicaId(1003),
                &versions_response(Some(7)),
            )
            .await
            .expect("second answer");

            match events.as_slice() {
                [
                    DeRecEvent::ReplicaDiscoveryComplete {
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
                other => panic!("expected ReplicaDiscoveryComplete, got {other:?}"),
            }
            assert_eq!(
                rig.transport.sent_uris(),
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
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            seed(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut rig.channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut rig.secrets).await;
            rig.state
                .save(
                    SECRET_ID,
                    StateItem::PendingReplicaDiscovery {
                        local_version: 5,
                        pending: HashSet::from([ReplicaId(1001)]),
                        reported: HashMap::from([(ReplicaId(1003), 7)]),
                        started_at: 0,
                    },
                )
                .await
                .expect("seed check");

            let events = super::on_response(
                &mut rig.stores(),
                &lf.local(),
                ReplicaId(1001),
                &versions_response(Some(7)),
            )
            .await
            .expect("collect succeeds");

            match events.as_slice() {
                [DeRecEvent::ReplicaDiscoveryComplete { fetched_from, .. }] => assert_eq!(
                    *fetched_from,
                    Some(1001),
                    "both are at v7; the Source wins the tie"
                ),
                other => panic!("expected ReplicaDiscoveryComplete, got {other:?}"),
            }
        });
    }

    /// The asker addresses every member but itself — a self-addressed query
    /// could never be answered.
    #[test]
    fn start_asks_every_member_but_itself() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1002);
            let mut rig = StoreRig::new();

            seed(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed(
                &mut rig.channels,
                1002,
                ReplicaRole::Destination,
                "https://alice-2",
            )
            .await;
            seed(
                &mut rig.channels,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut rig.secrets).await;
            seed_version(&mut rig.user_secrets, 5).await;

            super::start(&mut rig.stores(), &lf.local(), TRACE_ID)
                .await
                .expect("start succeeds");

            let sent = rig.transport.sent_uris();
            assert_eq!(sent.len(), 2, "two peers asked, not three");
            assert!(
                !sent.iter().any(|u| u == "https://alice-2"),
                "the asker must not query itself, got {sent:?}"
            );
        });
    }
}
