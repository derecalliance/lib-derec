// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, MissingPolicy, PendingAction, SecretKind, SecretValue,
};
use super::replicas::recovery as replica;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::stores::{StoreSet, Stores};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::recovery::{RecoveryError, request, response},
    protocol::types::{StateItem, StateKey},
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, DeRecSecret, GetShareRequestMessage, GetShareResponseMessage, MessageBody,
    SenderKind, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

/// Route an inbound recovery message.
///
/// `secret_id` names the partition our state lives in. A response
/// carries the secret being *recovered*, and the two differ whenever a
/// device recovers from an ephemeral instance, so a response is never
/// validated against `secret_id`. Two checks stand in its place:
///
/// * The channel is one of ours, paired, and we hold its shared key.
///   Established before this point — [`super::handle`] requires the
///   channel to exist under `secret_id` with an `Owner` peer, and the
///   caller resolved a shared key from the same partition.
/// * The response corresponds to a request we actually made, proven by a
///   `PendingRecovery` row under `(secret_id, recovered secret, version)`.
///   No row means unsolicited or stale; the response is dropped.
///
/// Once the threshold is met, VSS reconstructs the *outer* protect-side
/// wrapping: a `DeRecSecret` envelope whose `secret_data` holds the
/// gzip-compressed JSON encoding of the secret (see
/// [`crate::protocol::types::secret`]). Both layers are decoded before
/// [`DeRecEvent::SecretRecovered`] is emitted; either failing yields
/// [`RecoveryError::MalformedRecoveredSecret`] — the math reconstructed
/// *something*, but not a wire shape the protocol recognises.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    match (inner.route(), inner) {
        (Route::Replica(author), inner) => {
            replica::handle(stores, local, exchange, author, inner).await
        }
        (_, inner) => {
            let expected = match &inner {
                MessageBody::GetShareRequest(_) => SenderKind::Owner,
                _ => SenderKind::Helper,
            };
            stores
                .channels
                .require_role(local.secret_id, &[exchange.channel_id], expected)
                .await?;
            match inner {
                MessageBody::GetShareRequest(request) => on_request(exchange, request),
                MessageBody::GetShareResponse(response) => {
                    on_response(stores, local, exchange.channel_id, &response).await
                }
                _ => Err(Error::Invariant(
                    "unexpected MessageBody variant in recovery handler",
                )),
            }
        }
    }
}

/// Dispatch a `GetShareRequest` to every helper paired with the running
/// instance.
///
/// Two distinct secret ids are in play and must not be conflated:
///
/// * `local_secret_id` — the running instance's own id. It names the
///   partitions holding our channels, shared keys and recovery state.
///   Requests go to *its* helpers, because those are the only peers we
///   hold keys for.
/// * `target_secret_id` — the secret being recovered. It appears in the
///   request payload and nowhere else.
///
/// The two are equal when an Owner re-requests its own shares in place.
/// They differ during device recovery, where an ephemeral instance pairs
/// afresh and then asks those helpers for a *different* secret.
///
/// Only channels whose `peer_role` is [`derec_proto::SenderKind::Helper`]
/// and whose status is
/// [`ChannelStatus::Paired`](crate::protocol::types::ChannelStatus::Paired)
/// are asked. Replica
/// channels (`ReplicaSource` / `ReplicaDestination`) are excluded: a
/// replica syncs whole secrets and holds no VSS share, so it has
/// nothing to answer a `GetShareRequest` with. Channels where we are
/// the Helper belong to someone else's secret. This mirrors the
/// selection [`super::sharing`] performs when publishing.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            local.secret_id = local.secret_id,
            target_secret_id = target_secret_id,
            version = version
        )
    )
)]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    target_secret_id: u64,
    version: u32,
    round: &Round<'_>,
) -> Result<Vec<DeRecEvent>> {
    stores
        .state
        .save(
            local.secret_id,
            StateItem::PendingRecovery {
                secret_id: target_secret_id,
                version,
                shares: Vec::new(),
            },
        )
        .await?;

    let all_channels: Vec<crate::protocol::types::HelperChannel> = stores
        .channels
        .helpers_matching(
            local.secret_id,
            crate::protocol::types::HelperFilter {
                status: vec![crate::protocol::types::ChannelStatus::Paired],
                role: Some(derec_proto::SenderKind::Helper),
                ..Default::default()
            },
        )
        .await?;

    let channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.channel_id).collect();
    let keys: std::collections::HashMap<ChannelId, SharedKey> = stores
        .secrets
        .load_many(
            local.secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?
        .into_iter()
        .filter_map(|(cid, v)| match v {
            SecretValue::SharedKey(k) => Some((cid, k)),
            _ => None,
        })
        .collect();

    let events = dispatch_all(stores, all_channels, keys, target_secret_id, version, round).await;

    #[cfg(feature = "logging")]
    tracing::info!(
        local_secret_id = local.secret_id,
        target_secret_id,
        version,
        "share requests dispatched to all helpers"
    );

    Ok(events)
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &GetShareRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = stores
        .channels
        .linked_channels(local.secret_id, exchange.channel_id)
        .await?;

    // `secret_id` is the partition this node stores under, not the secret
    // being asked for: a helper holds shares for other people's secrets, and
    // `request.secret_id` is the only thing that names which one. Selecting
    // on the partition alone leaves the choice to whatever order the store
    // returns rows in, so a partition holding a second secret at the same
    // version could yield the wrong share — which `response::produce` then
    // rejects as `SecretIdMismatch`, failing a request whose share is
    // present and readable.
    let encoded = stores
        .shares
        .load_many(local.secret_id, &linked_ids, &[request.version])
        .await?
        .into_iter()
        .find(|s| s.secret_id == request.secret_id)
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput("no stored share for recovery request"))?;

    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = response::produce(exchange.channel_id, request, &stored, exchange.shared_key)?;

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoints = stores
        .channels
        .resolve_response_endpoints(
            local.secret_id,
            exchange.channel_id,
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
        .await?;
    stores.transport.send(&endpoints, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = exchange.channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        "recovery share response sent"
    );

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &GetShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        committed_de_rec_share: Vec::new(),
        share_algorithm: 0,
        timestamp: Some(current_timestamp()),
        secret_id: request.secret_id,
        version: request.version,
        // Answer on the path the request arrived on: a member asking gets a
        // member's answer, a helper exchange stays helper-bound.
        replica_id: local.replica_id.filter(|_| request.replica_id.is_some()),
    };

    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        local.secret_id,
        exchange.channel_id,
        MessageBody::GetShareResponse(response),
        exchange.shared_key,
        exchange.trace_id,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(trace_id = exchange.trace_id,
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(exchange: &Exchange<'_>, request: GetShareRequestMessage) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::GetShare {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version
        )
    )
)]
async fn on_response<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let state_key = StateKey::PendingRecovery {
        secret_id: response.secret_id,
        version: response.version,
    };

    let mut shares = match stores
        .state
        .load(local.secret_id, state_key.clone())
        .await?
    {
        Some(StateItem::PendingRecovery { shares, .. }) => shares,
        Some(_) => {
            return Err(Error::Invariant(
                "state store returned wrong StateItem variant for PendingRecovery key",
            ));
        }
        None => {
            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = response.version,
                "recovery response has no matching pending recovery; dropping"
            );
            return Ok(vec![DeRecEvent::NoOp]);
        }
    };

    shares.push(response.clone());
    let shares_received = shares.len();
    let inputs: Vec<&GetShareResponseMessage> = shares.iter().collect();

    let event = match response::recover(response.secret_id, response.version, &inputs) {
        Ok(result) => {
            let typed_secret = match decode_recovered_secret(&result.secret_data) {
                Ok(s) => s,
                Err(e) => {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        channel_id = channel_id.0,
                        secret_id = response.secret_id,
                        version = response.version,
                        shares_received,
                        error = %e,
                        "recovered bytes did not decode as canonical Secret protobuf"
                    );

                    return Ok(vec![DeRecEvent::RecoveryShareError {
                        channel_id,
                        shares_received,
                        error: e.to_string(),
                    }]);
                }
            };

            stores.state.remove(local.secret_id, state_key).await?;

            #[cfg(feature = "logging")]
            tracing::info!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = response.version,
                shares_received,
                "secret reconstructed from shares"
            );

            DeRecEvent::SecretRecovered {
                secret: typed_secret,
            }
        }
        Err(Error::Recovery(RecoveryError::ReconstructionFailed { ref source }))
            if matches!(
                source,
                derec_cryptography::vss::DerecVSSError::InsufficientShares
            ) =>
        {
            stores
                .state
                .save(
                    local.secret_id,
                    StateItem::PendingRecovery {
                        secret_id: response.secret_id,
                        version: response.version,
                        shares,
                    },
                )
                .await?;

            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = response.version,
                shares_received,
                "reconstruction not yet possible — insufficient shares"
            );

            DeRecEvent::RecoveryShareReceived {
                channel_id,
                shares_received,
            }
        }
        Err(e) => {
            stores
                .state
                .save(
                    local.secret_id,
                    StateItem::PendingRecovery {
                        secret_id: response.secret_id,
                        version: response.version,
                        shares,
                    },
                )
                .await?;

            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id = response.secret_id,
                version = response.version,
                shares_received,
                error = %e,
                "recovery share response received but reconstruction failed"
            );

            DeRecEvent::RecoveryShareError {
                channel_id,
                shares_received,
                error: e.to_string(),
            }
        }
    };

    Ok(vec![event])
}

fn decode_recovered_secret(outer_bytes: &[u8]) -> Result<crate::protocol::types::Secret> {
    let derec_secret =
        DeRecSecret::decode(outer_bytes).map_err(|e| RecoveryError::MalformedRecoveredSecret {
            source: Box::new(e),
        })?;
    let secret =
        crate::protocol::types::Secret::decode(&derec_secret.secret_data).map_err(|e| {
            RecoveryError::MalformedRecoveredSecret {
                source: Box::new(e),
            }
        })?;
    Ok(secret)
}

/// Send a share request to every resolved channel, reporting each outcome.
///
/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes a `RecoverSecretFailed` and the
/// fan-out continues, so one unreachable helper cannot suppress the rest.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    all_channels: Vec<crate::protocol::types::HelperChannel>,
    mut keys: std::collections::HashMap<ChannelId, SharedKey>,
    target_secret_id: u64,
    version: u32,
    round: &Round<'_>,
) -> Vec<DeRecEvent> {
    let mut events = Vec::with_capacity(all_channels.len());
    for channel in all_channels {
        let shared_key = keys
            .remove(&channel.channel_id)
            .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");

        match dispatch_one(
            stores,
            channel.channel_id,
            &channel.transports,
            target_secret_id,
            version,
            &shared_key,
            round,
        )
        .await
        {
            Ok(()) => {
                events.push(DeRecEvent::RecoverSecretStarted {
                    channel_id: channel.channel_id,
                    version,
                    trace_id: round.trace_id,
                });
                #[cfg(feature = "logging")]
                tracing::debug!(
                    channel_id = channel.channel_id.0,
                    target_secret_id,
                    version,
                    "share request sent"
                );
            }
            Err(e) => {
                events.push(DeRecEvent::RecoverSecretFailed {
                    channel_id: channel.channel_id,
                    version,
                    error: e.to_string(),
                });
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel.channel_id.0,
                    target_secret_id,
                    version,
                    error = %e,
                    "share request dispatch failed"
                );
            }
        }
    }
    events
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    channel_id: ChannelId,
    endpoints: &[derec_proto::TransportProtocol],
    secret_id: u64,
    version: u32,
    shared_key: &SharedKey,
    round: &Round<'_>,
) -> Result<()> {
    let msg = request::produce(channel_id, secret_id, version, shared_key, round.reply_to)?;
    let envelope = crate::derec_message::apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(endpoints, envelope).await?;
    Ok(())
}

#[cfg(test)]
mod recovery_ids_tests {
    //! Coverage for the two secret ids a recovery involves.
    //!
    //! A recovering device runs an *ephemeral* instance: its own
    //! `secret_id` (`LOCAL` below) owns the local partitions — channels,
    //! shared keys, recovery state — while the secret being recovered
    //! (`TARGET`) exists only on the wire. The two are equal for an
    //! in-place re-share, so every assertion here deliberately uses
    //! `LOCAL != TARGET`.

    use super::*;
    use crate::protocol::context::Exchange;
    use crate::protocol::test::LocalFixture;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, RecordingTransport,
        StoreRig, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, SecretValue,
    };
    use crate::types::ChannelId;
    use derec_proto::{DeRecMessage, SenderKind, TransportProtocol};
    use prost::Message;

    /// The ephemeral instance's own secret id — owns every local partition.
    const LOCAL: u64 = 0xE0;
    /// The secret being recovered — belongs on the wire only.
    const TARGET: u64 = 0xA0;
    /// A third instance sharing the same physical stores.
    const OTHER: u64 = 0xF0;

    const VERSION: u32 = 3;

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// Seed a paired Owner-role channel plus its shared key under `sid`.
    async fn seed_channel(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        sid: u64,
        cid: u64,
        key_byte: u8,
    ) {
        seed_channel_as(
            channels,
            secrets,
            sid,
            cid,
            key_byte,
            SenderKind::Helper,
            ChannelStatus::Paired,
        )
        .await
    }

    /// Seed a channel with an explicit peer role and status.
    ///
    /// `peer_role` is what the *other end* is, so a helper-pairing an
    /// Owner holds is `SenderKind::Helper`. A replica `peer_role` seeds a
    /// group member instead, keyed on `replica_id = cid` so tests can name
    /// the member with the same literal they use for the channel.
    async fn seed_channel_as(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        sid: u64,
        cid: u64,
        key_byte: u8,
        peer_role: SenderKind,
        status: ChannelStatus,
    ) {
        let transport = endpoint(&format!("https://helper-{cid}.example"));
        let record = match ReplicaRole::from_sender_kind(peer_role) {
            Some(role) => ChannelRecord::Replica(ReplicaMember {
                channel_id: ChannelId(cid),
                replica_id: crate::types::ReplicaId(cid),
                transports: vec![transport.clone()],
                communication_info: Default::default(),
                role,
                status,
                created_at: 1,
            }),
            None => ChannelRecord::Helper(HelperChannel {
                channel_id: ChannelId(cid),
                transports: vec![transport],
                communication_info: Default::default(),
                status,
                created_at: 1,
                peer_role,
            }),
        };
        channels.save(sid, record).await.expect("channel saved");
        secrets
            .save(sid, ChannelId(cid), SecretValue::SharedKey([key_byte; 32]))
            .await
            .expect("shared key saved");
    }

    /// Decrypt an outbound envelope back into the `GetShareRequestMessage`
    /// a helper would actually see.
    fn decode_request(envelope: &[u8], key_byte: u8) -> GetShareRequestMessage {
        let msg = DeRecMessage::decode(envelope).expect("outbound envelope decodes");
        let inner = crate::derec_message::extract_inner_message(&msg.message, &[key_byte; 32])
            .expect("inner message decrypts");
        match inner {
            MessageBody::GetShareRequest(r) => r,
            other => panic!("expected GetShareRequest, got {other:?}"),
        }
    }

    /// Real VSS shares for `secret_id`, wrapped as the `GetShareResponseMessage`s
    /// a helper would return.
    fn helper_responses(
        secret_id: u64,
        version: u32,
        channel_ids: &[u64],
        threshold: usize,
        payload: &[u8],
    ) -> Vec<GetShareResponseMessage> {
        let cids: Vec<ChannelId> = channel_ids.iter().copied().map(ChannelId).collect();
        let split = crate::primitives::sharing::request::split(
            &cids, secret_id, version, payload, threshold,
        )
        .expect("split succeeds");
        cids.iter()
            .map(|cid| GetShareResponseMessage {
                result: Some(DeRecResult {
                    status: StatusEnum::Ok as i32,
                    memo: String::new(),
                }),
                committed_de_rec_share: split
                    .shares
                    .get(cid)
                    .expect("share for channel")
                    .encode_to_vec(),
                share_algorithm: 0,
                timestamp: Some(current_timestamp()),
                secret_id,
                version,
                replica_id: None,
            })
            .collect()
    }

    fn pending_key(secret_id: u64, version: u32) -> StateKey {
        StateKey::PendingRecovery { secret_id, version }
    }

    // ---------------------------------------------------------------
    // Definition 1 — outbound: requests go to the LOCAL instance's
    // helpers and carry the TARGET secret id.
    // ---------------------------------------------------------------

    /// A fixed round, so a test can assert what reaches the wire.
    const ROUND: crate::protocol::context::Round<'static> = crate::protocol::context::Round {
        reply_to: &[],
        trace_id: 0x7ACE,
    };

    #[test]
    fn start_dispatches_to_every_channel_of_the_local_instance() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;
            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 12, 0xA2).await;

            let events = start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            let mut uris = rig.transport.sent_uris();
            uris.sort();
            assert_eq!(
                uris,
                vec![
                    "https://helper-11.example".to_owned(),
                    "https://helper-12.example".to_owned()
                ],
                "a request must reach every paired helper of the local instance"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e, DeRecEvent::RecoverSecretStarted { .. }))
                    .count(),
                2
            );
        });
    }

    #[test]
    fn start_sends_request_carrying_the_target_secret_id() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;

            start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            let envelopes = rig.transport.sent_envelopes();
            assert_eq!(envelopes.len(), 1);
            let request = decode_request(&envelopes[0], 0xA1);
            assert_eq!(
                request.secret_id, TARGET,
                "the wire payload must name the secret being recovered, not the ephemeral instance"
            );
            assert_eq!(request.version, VERSION);
        });
    }

    #[test]
    fn start_ignores_channels_belonging_to_other_instances() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            // One physical store, three instances. Only LOCAL's helpers
            // are ours to talk to.
            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;
            seed_channel(&mut rig.channels, &mut rig.secrets, TARGET, 21, 0xB1).await;
            seed_channel(&mut rig.channels, &mut rig.secrets, OTHER, 31, 0xC1).await;

            start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            assert_eq!(
                rig.transport.sent_uris(),
                vec!["https://helper-11.example".to_owned()],
                "recovery is scoped to the running instance's channels"
            );
        });
    }

    #[test]
    fn start_records_pending_recovery_under_the_local_partition() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;

            start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            let key = pending_key(TARGET, VERSION);
            assert!(
                matches!(
                    rig.state.load(LOCAL, key.clone()).await.expect("load"),
                    Some(StateItem::PendingRecovery { secret_id, version, .. })
                        if secret_id == TARGET && version == VERSION
                ),
                "state lives in the local partition, keyed by the target"
            );
            assert!(
                rig.state.load(TARGET, key).await.expect("load").is_none(),
                "nothing may be written to the target's partition"
            );
        });
    }

    /// Replicas never answer `GetShareRequest` — they sync whole secrets
    /// rather than holding VSS shares. A recovering instance must ask
    /// only the peers that actually store shares.
    #[test]
    fn start_excludes_replica_channels() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;
            for (cid, peer_role) in [
                (41, SenderKind::ReplicaDestination),
                (42, SenderKind::ReplicaSource),
            ] {
                seed_channel_as(
                    &mut rig.channels,
                    &mut rig.secrets,
                    LOCAL,
                    cid,
                    0xD1,
                    peer_role,
                    ChannelStatus::Paired,
                )
                .await;
            }

            let events = start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("a replica channel must not abort the recovery");

            assert_eq!(
                rig.transport.sent_uris(),
                vec!["https://helper-11.example".to_owned()],
                "only share-holding helpers may be asked for shares"
            );
            assert_eq!(events.len(), 1);
        });
    }

    /// A channel whose peer is an Owner means *we* are the helper on it —
    /// someone else's share, not a peer we can request from.
    #[test]
    fn start_excludes_channels_whose_peer_is_an_owner() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel_as(
                &mut rig.channels,
                &mut rig.secrets,
                LOCAL,
                51,
                0xE1,
                SenderKind::Owner,
                ChannelStatus::Paired,
            )
            .await;

            start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            assert!(rig.transport.sent_uris().is_empty());
        });
    }

    /// A `Pending` channel has not cleared fingerprint verification, so
    /// it is not yet a paired helper.
    #[test]
    fn start_excludes_channels_pending_fingerprint_verification() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            seed_channel(&mut rig.channels, &mut rig.secrets, LOCAL, 11, 0xA1).await;
            seed_channel_as(
                &mut rig.channels,
                &mut rig.secrets,
                LOCAL,
                61,
                0xF1,
                SenderKind::Helper,
                ChannelStatus::Pending,
            )
            .await;

            start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            assert_eq!(
                rig.transport.sent_uris(),
                vec!["https://helper-11.example".to_owned()]
            );
        });
    }

    #[test]
    fn start_dispatches_nothing_when_the_local_instance_has_no_channels() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            // Channels exist, but under the target — not under us.
            seed_channel(&mut rig.channels, &mut rig.secrets, TARGET, 21, 0xB1).await;

            let events = start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            assert!(rig.transport.sent_uris().is_empty());
            assert!(events.is_empty());
        });
    }

    // ---------------------------------------------------------------
    // Definition 2 — inbound: a response is correlated to a request we
    // made, never to the running instance's own secret id.
    // ---------------------------------------------------------------

    #[test]
    fn on_response_accepts_share_whose_secret_id_differs_from_the_local_instance() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    LOCAL,
                    StateItem::PendingRecovery {
                        secret_id: TARGET,
                        version: VERSION,
                        shares: Vec::new(),
                    },
                )
                .await
                .expect("seed pending");

            let responses = helper_responses(TARGET, VERSION, &[11, 12, 13], 2, b"payload");

            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("a response for the requested secret must not be rejected");

            assert!(matches!(
                events.as_slice(),
                [DeRecEvent::RecoveryShareReceived {
                    shares_received: 1,
                    ..
                }]
            ));
        });
    }

    #[test]
    fn on_response_accumulates_shares_until_threshold() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    LOCAL,
                    StateItem::PendingRecovery {
                        secret_id: TARGET,
                        version: VERSION,
                        shares: Vec::new(),
                    },
                )
                .await
                .expect("seed pending");

            let responses = helper_responses(TARGET, VERSION, &[11, 12, 13], 3, b"payload");

            on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("first share accepted");
            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &responses[1])
                .await
                .expect("second share accepted");

            assert!(matches!(
                events.as_slice(),
                [DeRecEvent::RecoveryShareReceived {
                    shares_received: 2,
                    ..
                }]
            ));
        });
    }

    #[test]
    fn on_response_reconstructs_secret_once_threshold_is_met() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    LOCAL,
                    StateItem::PendingRecovery {
                        secret_id: TARGET,
                        version: VERSION,
                        shares: Vec::new(),
                    },
                )
                .await
                .expect("seed pending");

            let payload = super::tests::encode_protect_wrapping(&super::tests::fixture_secret());
            let responses = helper_responses(TARGET, VERSION, &[11, 12], 2, &payload);

            on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("first share accepted");
            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &responses[1])
                .await
                .expect("second share accepted");

            let recovered = match events.as_slice() {
                [DeRecEvent::SecretRecovered { secret }] => secret.clone(),
                other => panic!("expected SecretRecovered, got {other:?}"),
            };
            assert_eq!(recovered, super::tests::fixture_secret());
        });
    }

    #[test]
    fn on_response_clears_pending_state_after_reconstruction() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            rig.state
                .save(
                    LOCAL,
                    StateItem::PendingRecovery {
                        secret_id: TARGET,
                        version: VERSION,
                        shares: Vec::new(),
                    },
                )
                .await
                .expect("seed pending");

            let payload = super::tests::encode_protect_wrapping(&super::tests::fixture_secret());
            let responses = helper_responses(TARGET, VERSION, &[11, 12], 2, &payload);

            on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("first share accepted");
            on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &responses[1])
                .await
                .expect("second share accepted");

            assert!(
                rig.state
                    .load(LOCAL, pending_key(TARGET, VERSION))
                    .await
                    .expect("load")
                    .is_none(),
                "the accumulator is dropped once the secret is reconstructed"
            );
        });
    }

    #[test]
    fn on_response_drops_response_with_no_matching_pending_recovery() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            let responses = helper_responses(TARGET, VERSION, &[11, 12], 2, b"payload");

            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("an unsolicited response is dropped, not an error");

            assert!(matches!(events.as_slice(), [DeRecEvent::NoOp]));
        });
    }

    #[test]
    fn on_response_keeps_concurrent_recoveries_of_different_targets_separate() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            const TARGET_A: u64 = 0xA1;
            const TARGET_B: u64 = 0xB2;

            let mut rig = StoreRig::new();
            for target in [TARGET_A, TARGET_B] {
                rig.state
                    .save(
                        LOCAL,
                        StateItem::PendingRecovery {
                            secret_id: target,
                            version: VERSION,
                            shares: Vec::new(),
                        },
                    )
                    .await
                    .expect("seed pending");
            }

            // Same version, different vaults — the accumulators must not
            // share a row, or shares from one recovery poison the other.
            let a = helper_responses(TARGET_A, VERSION, &[11, 12, 13], 3, b"vault-a");
            let b = helper_responses(TARGET_B, VERSION, &[21, 22, 23], 3, b"vault-b");

            on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &a[0])
                .await
                .expect("vault A share accepted");
            on_response(&mut rig.stores(), &lf.local(), ChannelId(21), &b[0])
                .await
                .expect("vault B share accepted");
            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &a[1])
                .await
                .expect("second vault A share accepted");

            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::RecoveryShareReceived {
                        shares_received: 2,
                        ..
                    }]
                ),
                "vault A must have exactly its own two shares, got {events:?}"
            );

            let b_shares = match rig
                .state
                .load(LOCAL, pending_key(TARGET_B, VERSION))
                .await
                .expect("load")
            {
                Some(StateItem::PendingRecovery { shares, .. }) => shares,
                other => panic!("expected vault B accumulator, got {other:?}"),
            };
            assert_eq!(b_shares.len(), 1, "vault B keeps its own single share");
        });
    }

    // ---------------------------------------------------------------
    // Wiring — the same two ids, driven through the public protocol
    // surface rather than the handler directly.
    // ---------------------------------------------------------------

    mod wiring {
        use super::*;
        use crate::protocol::test::{InMemShareStore, InMemUserSecretStore};
        use crate::protocol::{DeRecFlow, DeRecProtocolBuilder};

        type TestProto = crate::protocol::DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            RecordingTransport,
        >;

        struct Rig {
            protocol: TestProto,
            channel_store: InMemChannelStore,
            secret_store: InMemSecretStore,
            state_store: InMemPersistedStateStore,
            transport: RecordingTransport,
        }

        /// A protocol instance running under `LOCAL` — the ephemeral
        /// instance a recovering device would spin up.
        fn build_rig() -> Rig {
            let rig = StoreRig::new();
            let protocol = DeRecProtocolBuilder::new(LOCAL)
                .with_channel_store(rig.channels.clone())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(rig.secrets.clone())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(rig.state.clone())
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://recovering-device.example"])
                .with_threshold(2)
                .build()
                .expect("test rig builds");
            Rig {
                protocol,
                channel_store: rig.channels,
                secret_store: rig.secrets,
                state_store: rig.state,
                transport: rig.transport,
            }
        }

        #[test]
        fn recover_secret_flow_requests_the_target_from_the_local_instances_helpers() {
            run_async(async {
                let mut rig = build_rig();
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    11,
                    0xA1,
                )
                .await;
                // A channel under the target's partition must not be
                // reachable from this instance.
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    TARGET,
                    21,
                    0xB1,
                )
                .await;

                rig.protocol
                    .start(DeRecFlow::RecoverSecret {
                        secret_id: TARGET,
                        version: VERSION,
                    })
                    .await
                    .expect("recovery starts");

                assert_eq!(
                    rig.transport.sent_uris(),
                    vec!["https://helper-11.example".to_owned()],
                    "requests go to the running instance's helpers only"
                );
                let request = decode_request(&rig.transport.sent_envelopes()[0], 0xA1);
                assert_eq!(
                    request.secret_id, TARGET,
                    "and they ask for the secret the caller named"
                );
            });
        }

        /// A replica channel alongside the helpers must not abort the
        /// flow: replicas sync secrets, they do not hold shares, so they
        /// are simply not recovery peers.
        #[test]
        fn recover_secret_flow_excludes_replica_channels() {
            run_async(async {
                let mut rig = build_rig();
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    11,
                    0xA1,
                )
                .await;
                seed_channel_as(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    41,
                    0xD1,
                    SenderKind::ReplicaDestination,
                    ChannelStatus::Paired,
                )
                .await;

                rig.protocol
                    .start(DeRecFlow::RecoverSecret {
                        secret_id: TARGET,
                        version: VERSION,
                    })
                    .await
                    .expect("a paired replica must not block recovery");

                assert_eq!(
                    rig.transport.sent_uris(),
                    vec!["https://helper-11.example".to_owned()],
                    "the replica must not receive a GetShareRequest"
                );
            });
        }

        #[test]
        fn recover_secret_flow_registers_the_target_in_the_local_partition() {
            run_async(async {
                let mut rig = build_rig();
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    11,
                    0xA1,
                )
                .await;

                rig.protocol
                    .start(DeRecFlow::RecoverSecret {
                        secret_id: TARGET,
                        version: VERSION,
                    })
                    .await
                    .expect("recovery starts");

                assert!(
                    rig.state_store
                        .load(LOCAL, pending_key(TARGET, VERSION))
                        .await
                        .expect("load")
                        .is_some(),
                    "an inbound response must be able to find this row"
                );
            });
        }

        /// Build the envelope a helper would return for `TARGET`, sealed
        /// under the shared key of one of `LOCAL`'s channels.
        fn helper_response_envelope(
            channel_id: u64,
            key_byte: u8,
            response: &GetShareResponseMessage,
        ) -> Vec<u8> {
            crate::derec_message::DeRecMessageBuilder::channel()
                .channel_id(ChannelId(channel_id))
                .timestamp(response.timestamp.expect("response timestamp"))
                .message_body(MessageBody::GetShareResponse(response.clone()))
                .encrypt(&[key_byte; 32])
                .expect("encrypts")
                .build()
                .expect("builds")
                .encode_to_vec()
        }

        #[test]
        fn process_accepts_a_response_for_a_secret_other_than_the_instances_own() {
            run_async(async {
                let mut rig = build_rig();
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    11,
                    0xA1,
                )
                .await;
                rig.protocol
                    .start(DeRecFlow::RecoverSecret {
                        secret_id: TARGET,
                        version: VERSION,
                    })
                    .await
                    .expect("recovery starts");

                let responses = helper_responses(TARGET, VERSION, &[11, 12, 13], 3, b"payload");
                let events = rig
                    .protocol
                    .process(&helper_response_envelope(11, 0xA1, &responses[0]))
                    .await
                    .expect("a share for the recovered secret is accepted");

                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        DeRecEvent::RecoveryShareReceived {
                            shares_received: 1,
                            ..
                        }
                    )),
                    "expected the share to be accumulated, got {events:?}"
                );
            });
        }

        #[test]
        fn process_rejects_a_response_on_a_channel_the_instance_is_not_paired_on() {
            run_async(async {
                let mut rig = build_rig();
                seed_channel(
                    &mut rig.channel_store,
                    &mut rig.secret_store,
                    LOCAL,
                    11,
                    0xA1,
                )
                .await;
                rig.protocol
                    .start(DeRecFlow::RecoverSecret {
                        secret_id: TARGET,
                        version: VERSION,
                    })
                    .await
                    .expect("recovery starts");

                // Channel 99 was never paired with this instance, so no
                // shared key exists for it under LOCAL.
                let responses = helper_responses(TARGET, VERSION, &[11, 12, 13], 3, b"payload");
                let err = rig
                    .protocol
                    .process(&helper_response_envelope(99, 0xA1, &responses[0]))
                    .await
                    .expect_err("a share off an unpaired channel is refused");

                assert_eq!(err.channel_id, Some(ChannelId(99)));
                let shares = match rig
                    .state_store
                    .load(LOCAL, pending_key(TARGET, VERSION))
                    .await
                    .expect("load")
                {
                    Some(StateItem::PendingRecovery { shares, .. }) => shares,
                    other => panic!("expected accumulator, got {other:?}"),
                };
                assert!(shares.is_empty(), "the accumulator stays untouched");
            });
        }
    }

    /// Serving a `GetShareRequest` out of a partition holding more than one
    /// secret.
    ///
    /// A helper's `secret_id` is a storage partition for shares belonging to
    /// other people's secrets, not "the one secret this instance manages" —
    /// the owner-side reading of the term. `load_many` is keyed on that
    /// partition, so with two secrets stored at the same version across
    /// linked channels it legitimately returns both, and which one arrives
    /// first is a property of the store, not of the request.
    mod partition_holding_two_secrets {
        use super::*;
        use crate::protocol::Share;

        /// A stored `StoreShareRequestMessage`, shaped the way `accept`
        /// re-decodes it: the requested secret id lives on the innermost
        /// `DeRecShare`, which is what `response::produce` checks against.
        fn stored_share(secret_id: u64, version: u32) -> Vec<u8> {
            let share = derec_proto::DeRecShare {
                encrypted_secret: vec![0xAB; 4],
                x: vec![0x01],
                y: vec![0x02],
                secret_id,
                version,
            };
            let committed = derec_proto::CommittedDeRecShare {
                de_rec_share: share.encode_to_vec(),
                commitment: vec![0xCD; 4],
                merkle_path: Vec::new(),
            };
            derec_proto::StoreShareRequestMessage {
                share: committed.encode_to_vec(),
                secret_id,
                version,
                ..Default::default()
            }
            .encode_to_vec()
        }

        /// The decoy sorts ahead of the wanted share, so a handler that takes
        /// whatever `load_many` returns first picks the wrong secret. It then
        /// fails the request outright — `response::produce` rejects the
        /// mismatch with `SecretIdMismatch` rather than serving another
        /// secret's share — so the symptom is a recovery that cannot
        /// complete even though the right share is stored.
        #[test]
        fn the_share_served_is_the_one_the_request_asked_for() {
            run_async(async {
                let lf = LocalFixture::new(LOCAL);
                const DECOY_CHANNEL: u64 = 0x10;
                const WANTED_CHANNEL: u64 = 0x20;
                const DECOY_SECRET: u64 = 0x88;

                let mut rig = StoreRig::new();

                seed_channel(
                    &mut rig.channels,
                    &mut rig.secrets,
                    LOCAL,
                    DECOY_CHANNEL,
                    0xB1,
                )
                .await;
                seed_channel(
                    &mut rig.channels,
                    &mut rig.secrets,
                    LOCAL,
                    WANTED_CHANNEL,
                    0xB2,
                )
                .await;
                DeRecChannelStore::link_channel(
                    &mut rig.channels,
                    LOCAL,
                    ChannelId(DECOY_CHANNEL),
                    ChannelId(WANTED_CHANNEL),
                )
                .await
                .expect("link the two channels");

                for (channel, secret) in [(DECOY_CHANNEL, DECOY_SECRET), (WANTED_CHANNEL, TARGET)] {
                    DeRecShareStore::save(
                        &mut rig.shares,
                        LOCAL,
                        ChannelId(channel),
                        Share {
                            secret_id: secret,
                            version: VERSION,
                            bytes: stored_share(secret, VERSION),
                        },
                    )
                    .await
                    .expect("seed share");
                }

                let request = GetShareRequestMessage {
                    secret_id: TARGET,
                    version: VERSION,
                    ..Default::default()
                };

                accept(
                    &mut rig.stores(),
                    &lf.local(),
                    &Exchange {
                        channel_id: ChannelId(WANTED_CHANNEL),
                        shared_key: &[0xB2; 32],
                        trace_id: 0,
                    },
                    &request,
                )
                .await
                .expect("the share for TARGET is stored and must be the one served");
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::{HelperInfo, ReplicaInfo, Secret, UserSecret};
    use prost::Message;
    use std::collections::HashMap;

    /// Encode a `Secret` the same way `handlers::sharing::wrap_for_helper_split`
    /// does, producing the bytes that VSS would reconstruct on the happy
    /// path. The protect side is the canonical source of this wrapping;
    /// `decode_recovered_secret` is its inverse.
    pub(super) fn encode_protect_wrapping(secret: &Secret) -> Vec<u8> {
        let derec_secret = derec_proto::DeRecSecret {
            secret_data: secret.encode(),
            creation_time: None,
            helper_threshold_for_recovery: 2,
            helper_threshold_for_confirming_share_receipt: 2,
            helpers: Vec::new(),
        };
        derec_secret.encode_to_vec()
    }

    pub(super) fn fixture_secret() -> Secret {
        Secret {
            helpers: vec![HelperInfo {
                channel_id: 7,
                transports: vec![derec_proto::TransportProtocol {
                    uri: "https://helper.example".to_owned(),
                    protocol: derec_proto::Protocol::Https as i32,
                }],
                shared_key: vec![0xAA; 32],
                communication_info: HashMap::from([("name".to_owned(), "Helper".to_owned())]),
            }],
            secrets: vec![
                UserSecret {
                    id: vec![0x01],
                    name: "wallet seed".to_owned(),
                    data: b"correct horse battery staple".to_vec(),
                },
                UserSecret {
                    id: vec![0x02],
                    name: "api token".to_owned(),
                    data: b"hunter2".to_vec(),
                },
            ],
            replicas: Some(crate::protocol::types::Replicas {
                channel_id: 11,
                members: vec![
                    ReplicaInfo {
                        replica_id: 0xBEEF,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://owner.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        role: crate::protocol::types::ReplicaRole::Source as i32,
                        communication_info: HashMap::new(),
                    },
                    ReplicaInfo {
                        replica_id: 0xCAFE,
                        transports: vec![derec_proto::TransportProtocol {
                            uri: "https://replica.example".to_owned(),
                            protocol: derec_proto::Protocol::Https as i32,
                        }],
                        role: crate::protocol::types::ReplicaRole::Destination as i32,
                        communication_info: HashMap::new(),
                    },
                ],
                shared_key: vec![0x55; 32],
            }),
        }
    }

    #[test]
    fn decode_recovered_secret_round_trips_user_secrets() {
        let original = fixture_secret();
        let wrapped = encode_protect_wrapping(&original);

        let decoded = decode_recovered_secret(&wrapped).expect("decode must succeed");

        assert_eq!(
            decoded.secrets.len(),
            original.secrets.len(),
            "all UserSecret entries must round-trip"
        );
        for (got, want) in decoded.secrets.iter().zip(original.secrets.iter()) {
            assert_eq!(got.id, want.id, "UserSecret.id must round-trip");
            assert_eq!(got.name, want.name, "UserSecret.name must round-trip");
            assert_eq!(got.data, want.data, "UserSecret.data must round-trip");
        }

        assert_eq!(decoded.helpers.len(), 1);
        assert_eq!(decoded.helpers[0].channel_id, 7);
        let group = decoded.replicas.as_ref().expect("replicas must round-trip");
        assert_eq!(group.channel_id, 11);
        assert_eq!(group.members.len(), 2);
        // The roster names its source by role rather than a separate field.
        let source = group
            .members
            .iter()
            .find(|m| m.role == crate::protocol::types::ReplicaRole::Source as i32)
            .expect("the roster names exactly one source");
        assert_eq!(source.replica_id, 0xBEEF);
    }

    /// Empty `secret_data` is not a valid gzip stream, so the inner
    /// secret decode rejects it. The protect side never produces this.
    #[test]
    fn decode_recovered_secret_rejects_empty_inner_secret() {
        let wrapped = derec_proto::DeRecSecret {
            secret_data: Vec::new(),
            creation_time: None,
            helper_threshold_for_recovery: 1,
            helper_threshold_for_confirming_share_receipt: 1,
            helpers: Vec::new(),
        }
        .encode_to_vec();

        let err = decode_recovered_secret(&wrapped).expect_err("empty inner must fail");
        let Error::Recovery(RecoveryError::MalformedRecoveredSecret { .. }) = err else {
            panic!("expected MalformedRecoveredSecret, got {err:?}");
        };
    }

    #[test]
    fn decode_recovered_secret_rejects_garbage_outer_bytes() {
        // Crafted to fail the outer `DeRecSecret::decode` step — high-bit
        // bytes that don't form a valid protobuf tag.
        let garbage = vec![0xFFu8; 32];
        let err = decode_recovered_secret(&garbage).expect_err("garbage outer must fail");
        let Error::Recovery(RecoveryError::MalformedRecoveredSecret { .. }) = err else {
            panic!("expected MalformedRecoveredSecret, got {err:?}");
        };
    }

    #[test]
    fn decode_recovered_secret_rejects_non_gzip_inner() {
        // Valid outer DeRecSecret, but secret_data is not a gzip stream.
        let wrapped = derec_proto::DeRecSecret {
            secret_data: vec![0x01, 0x02, 0x03, 0x04],
            creation_time: None,
            helper_threshold_for_recovery: 1,
            helper_threshold_for_confirming_share_receipt: 1,
            helpers: Vec::new(),
        }
        .encode_to_vec();

        let err = decode_recovered_secret(&wrapped).expect_err("non-gzip inner must fail");
        let Error::Recovery(RecoveryError::MalformedRecoveredSecret { .. }) = err else {
            panic!("expected MalformedRecoveredSecret, got {err:?}");
        };
    }

    #[test]
    fn decode_recovered_secret_rejects_unknown_version() {
        let wrapped = derec_proto::DeRecSecret {
            secret_data: vec![0xFF, 0x00],
            creation_time: None,
            helper_threshold_for_recovery: 1,
            helper_threshold_for_confirming_share_receipt: 1,
            helpers: Vec::new(),
        }
        .encode_to_vec();
        let err = decode_recovered_secret(&wrapped).expect_err("unknown version must fail");
        let Error::Recovery(RecoveryError::MalformedRecoveredSecret { .. }) = err else {
            panic!("expected MalformedRecoveredSecret, got {err:?}");
        };
    }
}
