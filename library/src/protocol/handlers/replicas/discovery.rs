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
use super::load_member_keys;
use crate::derec_message::{DeRecMessageBuilder, apply_trace_id, current_timestamp};
use crate::extensions::advertised_endpoints::reply_to_owned;
use crate::extensions::channel_store::{ChannelStoreExt as _, filter_reply_to};
use crate::extensions::derec_result::DeRecResultExt as _;
use crate::extensions::secret_store::SecretStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::context::{Exchange, Local};
use crate::protocol::obligation::{Obligation, deliver};
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelStatus, ReplicaFilter, ReplicaMember, ReplicaRole};
use crate::protocol::{
    ChannelKey, DeRecEvent, DeRecStateStore, DeRecTransport, DeRecUserSecretStore, StateItem,
    StateKey,
};
use crate::types::ReplicaId;
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
use std::slice;
use std::time::Duration;

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
            if let Some(obligation) = exchange.obligation {
                obligation.answer_at(&member.transports);
            }
            on_request(
                stores,
                local,
                &member,
                &request,
                exchange.key,
                exchange.trace_id,
                exchange.obligation,
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

/// Ask every other `Paired` member which version it holds.
///
/// Only `Paired` members are asked, because the check waits for every member
/// it reached and has no timeout. A `Pending` member may never confirm and is
/// removed when its pairing expires; an `Unpairing` one may be a lost device
/// that never answers. Waiting on either would leave the check open forever.
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

    // A member whose pairing is unconfirmed drops every message at its
    // pending gate, so it is not asked.
    let peers: Vec<ReplicaMember> = stores
        .channels
        .replicas_matching(
            secret_id,
            ReplicaFilter {
                status: vec![ChannelStatus::Paired, ChannelStatus::Unpairing],
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

    let keys = load_member_keys(stores, local, &peers).await?;

    let mut asked: HashSet<ReplicaId> = HashSet::new();
    for peer in &peers {
        let timestamp = current_timestamp();
        let reply_to_transports = slice::from_ref(local.primary()).to_vec();
        let request = GetSecretIdsVersionsRequestMessage {
            timestamp: Some(timestamp),
            // The asker names itself so the answer can be routed back to a
            // member rather than treated as an owner ↔ helper exchange.
            replica_id: Some(own),
            reply_to_transports,
        };
        let envelope = DeRecMessageBuilder::channel()
            .channel_id(peer.channel_id)
            .timestamp(timestamp)
            .message_body(MessageBody::GetSecretIdsVersionsRequest(request))
            .trace_id(trace_id)
            .encrypt(&keys[&peer.channel_id])?
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
    key: &ChannelKey,
    inbound_trace_id: u64,
    obligation: Option<&Obligation>,
) -> Result<Vec<DeRecEvent>> {
    let version = stores
        .user_secrets
        .load_latest(local.secret_id)
        .await?
        .map(|s| s.version);

    let timestamp = current_timestamp();
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult::ok()),
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
        .encrypt(key)?
        .build()?
        .encode_to_vec();
    let envelope = apply_trace_id(&envelope, inbound_trace_id)?;
    // A reply-to overrides the recorded endpoints for this exchange only,
    // and only once it has passed the same transport policy every other
    // peer-supplied endpoint is held to; an offer refused in full is no
    // reply-to at all.
    let reply_to = filter_reply_to(local.policy, &reply_to_owned(request));
    let endpoint = if reply_to.is_empty() {
        member.transports.clone()
    } else {
        reply_to
    };
    deliver(
        obligation,
        stores.transport,
        &endpoint,
        envelope,
        StatusEnum::Ok,
        "",
    )
    .await?;

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

/// Conclude a version check that has waited longer than `timeout`, on the
/// versions already reported.
///
/// A member that never answers would otherwise hold the check open forever.
/// A silent member contributes nothing to the outcome. The row is removed
/// before the check concludes, so a store failure leaves it open for the next
/// sweep rather than concluding it twice.
pub(in crate::protocol) async fn conclude_if_expired<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    timeout: Duration,
) -> Result<Vec<DeRecEvent>> {
    let secret_id = local.secret_id;
    let Some(StateItem::PendingReplicaDiscovery {
        local_version,
        reported,
        started_at,
        ..
    }) = stores
        .state
        .load(secret_id, StateKey::PendingReplicaDiscovery)
        .await?
    else {
        return Ok(Vec::new());
    };
    if now_secs().saturating_sub(started_at) <= timeout.as_secs() {
        return Ok(Vec::new());
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
            ReplicaFilter {
                role: Some(ReplicaRole::Source),
                ..Default::default()
            },
        )
        .await?
        .iter()
        .find(|m| m.role == ReplicaRole::Source)
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
            ReplicaFilter {
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

    let key = stores
        .secrets
        .current_key(local.secret_id, member.channel_id)
        .await?;
    let timestamp = current_timestamp();
    let reply_to_transports = slice::from_ref(local.primary()).to_vec();
    let request = GetShareRequestMessage {
        secret_id,
        version: group_version,
        timestamp: Some(timestamp),
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
    use crate::derec_message::extract_inner_message;
    use crate::protocol::DeRecSecretStore;
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemUserSecretStore, StoreRig, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ReplicaRole, SecretValue, UserSecrets};
    use crate::types::ChannelId;
    use crate::types::SharedKey;
    use std::collections::HashSet;

    const SECRET_ID: u64 = 0xCA7C4;
    const GROUP: ChannelId = ChannelId(5001);

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    use crate::protocol::DeRecChannelStore as _;
    use derec_proto::{DeRecMessage, Protocol, TransportProtocol};

    async fn seed(channels: &mut InMemChannelStore, id: u64, role: ReplicaRole, uri: &str) {
        seed_on(channels, GROUP, id, role, uri).await;
    }

    async fn seed_on(
        channels: &mut InMemChannelStore,
        channel_id: ChannelId,
        id: u64,
        role: ReplicaRole,
        uri: &str,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id,
                    replica_id: ReplicaId(id),
                    transports: vec![endpoint(uri)],
                    communication_info: HashMap::new(),
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
            .save(
                SECRET_ID,
                GROUP,
                SecretValue::SharedKey(SharedKey::new([0x11; 32])),
            )
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
                    author_replica_id: None,
                    threshold: None,
                },
            )
            .await
            .expect("seed snapshot");
    }

    fn versions_response(version: Option<u32>) -> GetSecretIdsVersionsResponseMessage {
        GetSecretIdsVersionsResponseMessage {
            result: Some(DeRecResult::ok()),
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

    /// A member that has just joined still talks on its pairing channel,
    /// under that channel's key, until it is handed the group channel. Each
    /// question is sealed under the key of the channel it travels on, so the
    /// joiner can read its own.
    #[test]
    fn each_question_is_sealed_under_its_own_channel_key() {
        run_async(async {
            const PAIRING: ChannelId = ChannelId(5002);
            const GROUP_KEY: SharedKey = SharedKey::new([0x11; 32]);
            const PAIRING_KEY: SharedKey = SharedKey::new([0x22; 32]);

            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
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
            seed_on(
                &mut rig.channels,
                PAIRING,
                1003,
                ReplicaRole::Destination,
                "https://alice-3",
            )
            .await;
            seed_key(&mut rig.secrets).await;
            rig.secrets
                .save(SECRET_ID, PAIRING, SecretValue::SharedKey(PAIRING_KEY))
                .await
                .expect("seed pairing key");
            seed_version(&mut rig.user_secrets, 5).await;

            super::start(&mut rig.stores(), &lf.local(), TRACE_ID)
                .await
                .expect("start succeeds");

            let sent = rig.transport.sent_envelopes();
            assert_eq!(sent.len(), 2, "both other members are asked");
            for bytes in sent {
                let envelope = DeRecMessage::decode(bytes.as_slice()).expect("envelope decodes");
                let key = if envelope.channel_id == PAIRING.0 {
                    PAIRING_KEY
                } else {
                    GROUP_KEY
                };
                match extract_inner_message(&envelope.message, &key) {
                    Ok(MessageBody::GetSecretIdsVersionsRequest(_)) => {}
                    other => panic!(
                        "the question on channel {} must open under that channel's key, got {other:?}",
                        envelope.channel_id
                    ),
                }
            }
        });
    }

    /// A member whose pairing is unconfirmed drops every message at its
    /// pending gate, so asking it would only hold the check until it times
    /// out.
    #[test]
    fn an_unconfirmed_member_is_not_asked() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
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
            seed_unconfirmed_joiner(&mut rig).await;
            seed_key(&mut rig.secrets).await;
            seed_version(&mut rig.user_secrets, 5).await;

            super::start(&mut rig.stores(), &lf.local(), TRACE_ID)
                .await
                .expect("start succeeds");

            assert_eq!(
                rig.transport.sent_uris(),
                vec!["https://alice-2".to_owned()]
            );
        });
    }

    #[test]
    fn a_group_of_unconfirmed_members_asks_nobody() {
        run_async(async {
            let lf = LocalFixture::with_replica(SECRET_ID, 1001);
            let mut rig = StoreRig::new();
            seed(
                &mut rig.channels,
                1001,
                ReplicaRole::Source,
                "https://alice",
            )
            .await;
            seed_unconfirmed_joiner(&mut rig).await;
            seed_key(&mut rig.secrets).await;
            seed_version(&mut rig.user_secrets, 5).await;

            let events = super::start(&mut rig.stores(), &lf.local(), TRACE_ID)
                .await
                .expect("start succeeds");

            assert!(events.is_empty(), "{events:?}");
            assert!(rig.transport.sent_uris().is_empty());
        });
    }

    /// A joiner whose handshake finished but whose fingerprint this device
    /// has not confirmed: still `Pending`, on its own pairing channel.
    async fn seed_unconfirmed_joiner(rig: &mut StoreRig) {
        const PAIRING: ChannelId = ChannelId(5002);
        rig.channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: PAIRING,
                    replica_id: ReplicaId(1003),
                    transports: vec![endpoint("https://joiner")],
                    communication_info: HashMap::new(),
                    role: ReplicaRole::Destination,
                    status: ChannelStatus::Pending,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed joiner");
        rig.secrets
            .save(
                SECRET_ID,
                PAIRING,
                SecretValue::SharedKey(SharedKey::new([0x22; 32])),
            )
            .await
            .expect("seed pairing key");
    }
}
