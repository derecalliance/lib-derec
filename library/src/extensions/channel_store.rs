// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading a channel, and answering on one.
//!
//! The queries here read as methods on the channel store because that is
//! what they are — resolving a target, checking a peer's role, finding the
//! endpoints a peer can be reached at. They are not part of
//! [`DeRecChannelStore`] itself: applications implement that trait, so a
//! method added there would have to be written by every implementor and
//! every SDK's store shim. An extension trait with a blanket impl gives
//! every store the same methods for free, and leaves the trait an
//! application must satisfy as small as it was.

use crate::protocol::{DeRecChannelStore, DeRecTransport};
use crate::{
    Error, Result,
    derec_message::{DeRecMessageBuilder, current_timestamp},
    protocol::types::{
        ChannelQuery, HelperChannel, HelperFilter, ReplicaFilter, ReplicaMember, Target,
    },
    types::{ChannelId, SharedKey},
};
use derec_proto::{MessageBody, SenderKind, TransportProtocol};
use prost::Message;

/// Channel reads every flow needs, as methods on the store that holds them.
///
/// Blanket-implemented for every [`DeRecChannelStore`], so bringing the
/// trait into scope (`use crate::extensions::channel_store::ChannelStoreExt as _;`)
/// is all a caller does.
pub(crate) trait ChannelStoreExt: DeRecChannelStore {
    /// The helper channels that match `filter`, whatever the store returned.
    ///
    /// See [`Self::replicas_matching`] for why this exists. Use this, never the
    /// bare trait method: the protocol acts on these rows, and several call
    /// sites narrow to a single expected row.
    async fn helpers_matching(
        &self,
        secret_id: u64,
        filter: HelperFilter,
    ) -> Result<Vec<HelperChannel>> {
        let rows = self.helpers(secret_id, filter.clone()).await?;
        Ok(retain_matching(rows, "helpers", |c| {
            filter.matches(&c.channel_id, c.status, &c.peer_role)
        }))
    }

    /// The replica-group members that match `filter`, whatever the store
    /// returned.
    ///
    /// # Why this is not just [`DeRecChannelStore::replicas`]
    ///
    /// The filter is the store's to push into a query, and a store that does
    /// so transfers less — that is the whole point of
    /// [`ChannelFilter`](crate::protocol::types::ChannelFilter). But a store is
    /// **application-supplied code**, and the protocol acts on what comes back:
    /// it deletes rows the filter selected, and flags the member a by-id filter
    /// named. A store that ignored the filter would otherwise turn "evict
    /// member X" into evicting whichever member it listed first, and "sweep
    /// expired *pending* channels" into sweeping paired ones.
    ///
    /// That case is worth defending against because it needs no mistake to
    /// reach: TypeScript accepts a function of fewer parameters where more are
    /// declared, so a store written before the filter existed satisfies the
    /// current interface and compiles without a diagnostic. Ignoring the filter
    /// is the one wrong behaviour a binding cannot make impossible.
    ///
    /// # This is a one-way guarantee
    ///
    /// The check can only **drop** rows, so it enforces an upper bound: nothing
    /// the filter excluded reaches the caller. It cannot detect the opposite
    /// error. A store that returns *fewer* rows than the filter selects — one
    /// that over-filters, or simply answers `[]` — passes unchallenged, and the
    /// protocol then fails to act: a publish is skipped, a departure is never
    /// reconciled. That remains an application bug, and one nothing here can
    /// see.
    ///
    /// Nor does it police the `secret_id` partition: a
    /// [`ReplicaMember`](crate::protocol::types::ReplicaMember) does not carry
    /// its own `secret_id` — that is the key it is stored under — so a store
    /// that leaked rows across partitions would pass too.
    async fn replicas_matching(
        &self,
        secret_id: u64,
        filter: ReplicaFilter,
    ) -> Result<Vec<ReplicaMember>> {
        let rows = self.replicas(secret_id, filter.clone()).await?;
        Ok(retain_matching(rows, "replicas", |m| {
            filter.matches(&m.replica_id, m.status, &m.role)
        }))
    }

    /// Refuse a message whose sender does not hold `expected` on every one
    /// of `channel_ids`.
    ///
    /// A channel absent from the store is a failure, not a skip: a message
    /// naming a channel this device never paired on has no role to check.
    async fn require_role(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        expected: SenderKind,
    ) -> Result<()> {
        for channel_id in channel_ids {
            let channel = self
                .load(
                    secret_id,
                    ChannelQuery::Helper {
                        channel_id: *channel_id,
                    },
                )
                .await?
                .and_then(|r| r.as_helper().cloned())
                .ok_or(Error::InvalidInput(
                    "channel id not present in channel store",
                ))?;
            if channel.peer_role != expected {
                return Err(Error::RoleMismatch {
                    channel_id: *channel_id,
                    expected,
                    actual: channel.peer_role,
                });
            }
        }
        Ok(())
    }

    /// Narrow a caller-supplied [`Target`] to the channels this `secret_id`
    /// actually holds.
    ///
    /// Ids naming a channel that is not paired are dropped rather than
    /// refused: a target is a request to reach whoever is reachable, and a
    /// stale id in a list should not fail the whole fan-out.
    async fn resolve_target(&self, secret_id: u64, target: Target) -> Result<Vec<ChannelId>> {
        let known: Vec<ChannelId> = self
            .helpers_matching(
                secret_id,
                HelperFilter {
                    ids: target.ids(),
                    ..Default::default()
                },
            )
            .await?
            .iter()
            .map(|c| c.channel_id)
            .collect();

        Ok(target.filter(&known))
    }

    /// Every endpoint recorded for a peer, in the order it advertised them.
    ///
    /// Handed to [`DeRecTransport::send`] as-is: the library does not rank
    /// them, and the application chooses which to dial and whether to fall
    /// back.
    async fn peer_endpoints(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> Result<Vec<TransportProtocol>> {
        let channel = self
            .load(secret_id, ChannelQuery::Helper { channel_id })
            .await?;
        channel
            .map(|ch| ch.transports().to_vec())
            .filter(|endpoints| !endpoints.is_empty())
            .ok_or(Error::InvalidInput("no transport endpoint for channel"))
    }

    /// Pick the endpoints to deliver a response to.
    ///
    /// A reply-to names the addresses the requester asked to be answered on,
    /// so they stand alone rather than joining the recorded set: the recorded
    /// endpoints may belong to a different peer entirely (a replica talking
    /// to a helper paired with a sibling), so falling back to them would
    /// misroute rather than fail over.
    async fn resolve_response_endpoints(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        reply_to: &[TransportProtocol],
    ) -> Result<Vec<TransportProtocol>> {
        if !reply_to.is_empty() {
            return Ok(reply_to.to_vec());
        }
        self.peer_endpoints(secret_id, channel_id).await
    }

    /// Resolve one replica-group member by the identity the payload
    /// announced.
    ///
    /// Every member of a group answers on the same `channel_id`, so the
    /// channel alone cannot name the peer — the author does. A `0` is the
    /// wire's absent-value sentinel and never identifies a member.
    async fn load_replica_member(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        author: u64,
    ) -> Result<ReplicaMember> {
        let replica_id = crate::types::ReplicaId::try_from(author)?;
        self.load(
            secret_id,
            ChannelQuery::Replica {
                channel_id,
                replica_id,
            },
        )
        .await?
        .and_then(|r| r.as_replica().cloned())
        .ok_or(Error::InvalidInput(
            "replica sync names a member that is not in the group",
        ))
    }
}

impl<T: DeRecChannelStore> ChannelStoreExt for T {}

/// Build and dispatch an encrypted channel-mode response envelope.
///
/// `inbound_trace_id` is the `trace_id` read off the request envelope that
/// triggered this response. Echoed verbatim on the outbound envelope so the
/// requester can correlate (see the field doc on `DeRecMessage.traceId`).
/// Pass `0` when there is no inbound to echo from (e.g. unsolicited messages
/// that don't carry a meaningful correlation handle).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_channel_message<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    body: MessageBody,
    shared_key: &SharedKey,
    inbound_trace_id: u64,
    reply_to: &[TransportProtocol],
) -> Result<()> {
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(current_timestamp())
        .message_body(body)
        .trace_id(inbound_trace_id)
        .encrypt(shared_key)?
        .build()?;

    let wire_bytes = envelope.encode_to_vec();
    let endpoint = channel_store
        .resolve_response_endpoints(secret_id, channel_id, reply_to)
        .await?;
    transport.send(&endpoint, wire_bytes).await?;
    Ok(())
}

/// Drop rows the store returned that the filter excluded.
///
/// A store that pushed the filter down loses nothing here — the predicate is
/// true for every row, and nothing is logged.
///
/// One that ignored it gets those rows dropped, and, under the `logging`
/// feature, a **warning** naming the listing and the count. The level is
/// deliberate: this only fires when a store is not honouring its contract, and
/// the sooner whoever wrote it sees that, the better. It is silent for a
/// correct store, so it cannot become routine noise.
fn retain_matching<T>(rows: Vec<T>, listing: &str, keep: impl Fn(&T) -> bool) -> Vec<T> {
    let before = rows.len();
    let kept: Vec<T> = rows.into_iter().filter(keep).collect();

    #[cfg(feature = "logging")]
    if kept.len() != before {
        tracing::warn!(
            listing,
            returned = before,
            kept = kept.len(),
            "channel store did not apply the filter it was given; the excluded \
             rows were dropped here, but the store is transferring rows the \
             protocol discards and must apply the filter in its query"
        );
    }
    #[cfg(not(feature = "logging"))]
    let _ = (before, listing);

    kept
}

#[cfg(test)]
mod defiant_store_tests {
    use super::*;
    use crate::protocol::test::{InMemChannelStore, run_async};
    use crate::protocol::traits::{ChannelStoreFuture, DeRecChannelStore};
    use crate::protocol::types::{
        ChannelQuery, ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole,
    };
    use crate::types::ReplicaId;

    const SECRET_ID: u64 = 0xDEF1;
    const GROUP: ChannelId = ChannelId(500);

    /// A store that accepts a filter and ignores it — the shape a TypeScript
    /// store written against 0.0.2 still compiles into, and the shape any
    /// binding can produce by simply not implementing the restriction.
    #[derive(Default)]
    struct DefiantStore(InMemChannelStore);

    impl DeRecChannelStore for DefiantStore {
        fn load(
            &self,
            secret_id: u64,
            query: ChannelQuery,
        ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
            self.0.load(secret_id, query)
        }
        fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
            self.0.save(secret_id, record)
        }
        fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
            self.0.remove(secret_id, query)
        }
        fn helpers(
            &self,
            secret_id: u64,
            _filter: HelperFilter,
        ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
            self.0.helpers(secret_id, HelperFilter::default())
        }
        fn replicas(
            &self,
            secret_id: u64,
            _filter: ReplicaFilter,
        ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
            self.0.replicas(secret_id, ReplicaFilter::default())
        }
        fn link_channel(
            &mut self,
            secret_id: u64,
            a: ChannelId,
            b: ChannelId,
        ) -> ChannelStoreFuture<'_, ()> {
            self.0.link_channel(secret_id, a, b)
        }
        fn linked_channels(
            &self,
            secret_id: u64,
            channel_id: ChannelId,
        ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
            self.0.linked_channels(secret_id, channel_id)
        }
    }

    async fn seed(store: &mut DefiantStore, replica_id: u64, status: ChannelStatus) {
        store
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id: GROUP,
                    replica_id: ReplicaId(replica_id),
                    transports: vec![TransportProtocol {
                        uri: "https://peer.example".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    communication_info: std::collections::HashMap::new(),
                    role: ReplicaRole::Destination,
                    status,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed");
    }

    /// The eviction case: a by-id filter must never hand back a different
    /// member. Without the re-check, `on_request` would flag whichever row this
    /// store listed first, and the completing roster would delete it — turning
    /// "evict member X" into evicting member Y, with no error anywhere.
    #[test]
    fn a_by_id_filter_yields_only_that_member_even_when_the_store_ignores_it() {
        run_async(async {
            let mut store = DefiantStore::default();
            for id in [7001u64, 7002, 7003] {
                seed(&mut store, id, ChannelStatus::Paired).await;
            }

            let rows = store
                .replicas_matching(
                    SECRET_ID,
                    ReplicaFilter {
                        ids: vec![ReplicaId(7002)],
                        ..Default::default()
                    },
                )
                .await
                .expect("listing");

            assert_eq!(
                rows.iter().map(|m| m.replica_id.0).collect::<Vec<_>>(),
                vec![7002],
                "the defiant store returned the whole roster; only the named member may survive"
            );
        });
    }

    /// The destructive case: `remove_expired_channels` deletes what this
    /// listing returns, and only the filter says `Pending`. A store that
    /// ignores it would otherwise offer up paired channels for deletion.
    #[test]
    fn a_status_filter_holds_even_when_the_store_ignores_it() {
        run_async(async {
            let mut store = DefiantStore::default();
            seed(&mut store, 8001, ChannelStatus::Pending).await;
            seed(&mut store, 8002, ChannelStatus::Paired).await;
            seed(&mut store, 8003, ChannelStatus::Paired).await;

            let rows = store
                .replicas_matching(
                    SECRET_ID,
                    ReplicaFilter {
                        status: vec![ChannelStatus::Pending],
                        ..Default::default()
                    },
                )
                .await
                .expect("listing");

            assert_eq!(
                rows.iter().map(|m| m.replica_id.0).collect::<Vec<_>>(),
                vec![8001],
                "a paired member must never reach a sweep that asked for pending ones"
            );
        });
    }

    /// `exclude` is what keeps a device from dispatching to itself and from
    /// counting its own row as a peer.
    #[test]
    fn exclude_holds_even_when_the_store_ignores_it() {
        run_async(async {
            let mut store = DefiantStore::default();
            for id in [9001u64, 9002] {
                seed(&mut store, id, ChannelStatus::Paired).await;
            }

            let rows = store
                .replicas_matching(
                    SECRET_ID,
                    ReplicaFilter {
                        exclude: vec![ReplicaId(9001)],
                        ..Default::default()
                    },
                )
                .await
                .expect("listing");

            assert_eq!(
                rows.iter().map(|m| m.replica_id.0).collect::<Vec<_>>(),
                vec![9002]
            );
        });
    }

    /// A store that does push the filter down loses nothing: the re-check is a
    /// no-op over rows that already satisfy it.
    #[test]
    fn a_conforming_store_is_unaffected() {
        run_async(async {
            let mut store = InMemChannelStore::default();
            for (id, status) in [(1u64, ChannelStatus::Pending), (2, ChannelStatus::Paired)] {
                store
                    .save(
                        SECRET_ID,
                        ChannelRecord::Replica(ReplicaMember {
                            channel_id: GROUP,
                            replica_id: ReplicaId(id),
                            transports: Vec::new(),
                            communication_info: std::collections::HashMap::new(),
                            role: ReplicaRole::Destination,
                            status,
                            created_at: 0,
                        }),
                    )
                    .await
                    .expect("seed");
            }

            let rows = store
                .replicas_matching(
                    SECRET_ID,
                    ReplicaFilter {
                        status: vec![ChannelStatus::Paired],
                        ..Default::default()
                    },
                )
                .await
                .expect("listing");

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].replica_id.0, 2);
        });
    }
}
