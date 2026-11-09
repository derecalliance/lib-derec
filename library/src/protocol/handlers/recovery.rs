// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    CollectedShare, CorruptionReason, DeRecChannelStore, DeRecEvent, DeRecSecretStore,
    DeRecShareStore, DeRecStateStore, DeRecTransport, MissingPolicy, PendingAction,
    RecoveryCandidate, RecoveryHelper, SecretKind, SecretValue, now_secs,
};
use super::NO_SHARE_FOR_VERSION;
use super::replicas::recovery as replica;
use crate::derec_message::apply_trace_id;
use crate::extensions::advertised_endpoints::reply_to_owned;
use crate::extensions::channel_store::{ChannelStoreExt as _, send_channel_message};
use crate::extensions::derec_result::DeRecResultExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::protocol::context::{Exchange, Local, Round};
use crate::protocol::obligation;
use crate::protocol::stores::{StoreSet, Stores};
use crate::protocol::types::{ChannelStatus, HelperChannel, HelperFilter, Secret};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::recovery::{RecoveryError, request, response},
    protocol::types::{StateItem, StateKey},
    types::{ChannelId, SharedKey},
};
use derec_cryptography::vss;
use derec_proto::{
    DeRecResult, DeRecSecret, GetShareRequestMessage, GetShareResponseMessage, MessageBody,
    SenderKind, StatusEnum, StoreShareRequestMessage, TransportProtocol,
};
use prost::Message;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};

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
/// Every response is that helper's answer: it leaves the row's `pending`
/// set, and the recovery decides — see [`settle`] — only once that set is
/// empty, or when the timeout sweep closes it. Nothing is reconstructed
/// while an answer is still due, so a share still on its way can never
/// contradict a secret already reported.
///
/// A response whose status is not OK is the helper refusing the request —
/// typically `UNKNOWN_SHARE_VERSION` from a helper that holds no share for
/// the version asked for. It carries no share, so it is never added to the
/// collected set: it surfaces as [`DeRecEvent::RecoveryShareRefused`].
///
/// An OK response is checked on its own before it is collected (see
/// [`response::inspect`]); one that fails surfaces as
/// [`DeRecEvent::RecoveryShareCorrupted`] and, like a refusal, is not
/// collected. Before that check ever parses the share, its committed
/// bytes are measured against this device's own configured
/// `parameter_range.max_share_size` (`0` or no range means unbounded); an
/// oversized response is set aside the same way, without being decoded —
/// the owner holds no proofs to validate against here, so size is the only
/// admission check available, mirroring the helper-side check in
/// `handlers::sharing::on_request`. The collected set holds one share per
/// channel.
///
/// What VSS reconstructs is the *outer* protect-side wrapping: a
/// `DeRecSecret` envelope whose `secret_data` holds the gzip-compressed JSON
/// encoding of the secret (see [`crate::protocol::types::secret`]). Both
/// layers must decode for a group to count as a secret at all.
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
    let all_channels: Vec<HelperChannel> = stores
        .channels
        .helpers_matching(
            local.secret_id,
            HelperFilter {
                status: vec![ChannelStatus::Paired],
                role: Some(SenderKind::Helper),
                ..Default::default()
            },
        )
        .await?;

    let channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.channel_id).collect();
    let keys: HashMap<ChannelId, SharedKey> = stores
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

    let (mut events, asked) =
        dispatch_all(stores, all_channels, keys, target_secret_id, version, round).await;

    if asked.is_empty() {
        stores
            .state
            .remove(
                local.secret_id,
                StateKey::PendingRecovery {
                    secret_id: target_secret_id,
                    version,
                },
            )
            .await?;
        events.extend(settle(target_secret_id, version, &[], &HashMap::new()));
        return Ok(events);
    }

    stores
        .state
        .save(
            local.secret_id,
            StateItem::PendingRecovery {
                secret_id: target_secret_id,
                version,
                shares: Vec::new(),
                pending: asked,
                started_at: now_secs(),
            },
        )
        .await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        local_secret_id = local.secret_id,
        target_secret_id,
        version,
        "share requests dispatched to all helpers"
    );

    Ok(events)
}

/// Answer a `GetShareRequest` with the share stored for it.
///
/// The share is looked up across every channel linked to the one the
/// request arrived on (see
/// [`DeRecChannelStore::link_channel`](crate::protocol::DeRecChannelStore::link_channel)),
/// at the requested version, and the answer carries **one** share: the
/// first whose `secret_id` matches the request, in the order the share
/// store returns. With one-to-one links a helper holds at most one share
/// per owner for a given `secret_id` and version, so there is only one
/// candidate; otherwise the share store's order decides which is served.
///
/// A helper holding no share for the requested `(secret_id, version)` still
/// answers: the response carries `UNKNOWN_SHARE_VERSION` and no share, the
/// failure the protocol defines for a missing version, so the owner learns
/// of the refusal instead of waiting on a reply that never comes. That is an
/// answer rather than a failure of this device, so `accept` succeeds either
/// way, whether the application accepted the action or the
/// [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy) did.
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
    let Some(encoded) = stores
        .shares
        .load_many(local.secret_id, &linked_ids, &[request.version])
        .await?
        .into_iter()
        .find(|s| s.secret_id == request.secret_id)
        .map(|s| s.bytes)
    else {
        #[cfg(feature = "logging")]
        tracing::info!(
            channel_id = exchange.channel_id.0,
            secret_id = request.secret_id,
            version = request.version,
            "no stored share for the requested version; answering UNKNOWN_SHARE_VERSION"
        );
        let sent = reject(
            stores,
            local,
            exchange,
            request,
            StatusEnum::UnknownShareVersion,
            NO_SHARE_FOR_VERSION,
        )
        .await;
        return obligation::refused(
            exchange.obligation,
            DeRecEvent::NoOp,
            StatusEnum::UnknownShareVersion,
            NO_SHARE_FOR_VERSION,
            sent,
        );
    };

    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = response::produce(exchange.channel_id, request, &stored, exchange.shared_key)?;

    let envelope = apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoints = stores
        .channels
        .resolve_response_endpoints(
            local.secret_id,
            exchange.channel_id,
            local.policy,
            &reply_to_owned(request),
        )
        .await?;
    obligation::deliver(
        exchange.obligation,
        stores.transport,
        &endpoints,
        envelope,
        StatusEnum::Ok,
        "",
    )
    .await?;

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
    send_channel_message(
        stores.channels,
        stores.transport,
        local.secret_id,
        exchange.channel_id,
        failure_response(local, request, status, memo),
        exchange.shared_key,
        exchange.trace_id,
        local.policy,
        &reply_to_owned(request),
        exchange.obligation,
        status,
        memo,
    )
    .await
}

/// The `GetShareResponse` that answers `request` with a non-`Ok` `status`
/// and no share.
pub(in crate::protocol) fn failure_response(
    local: &Local<'_>,
    request: &GetShareRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> MessageBody {
    MessageBody::GetShareResponse(GetShareResponseMessage {
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
    })
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

    let (mut shares, mut pending, started_at) = match stores
        .state
        .load(local.secret_id, state_key.clone())
        .await?
    {
        Some(StateItem::PendingRecovery {
            shares,
            pending,
            started_at,
            ..
        }) => (shares, pending, started_at),
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

    pending.remove(&channel_id);
    let event = judge_response(local, channel_id, response, &mut shares);

    let mut events = vec![event];
    if pending.is_empty() {
        let helpers = describe_helpers(&*stores.channels, local.secret_id, &shares).await?;
        stores.state.remove(local.secret_id, state_key).await?;
        events.extend(settle(
            response.secret_id,
            response.version,
            &shares,
            &helpers,
        ));
    } else {
        stores
            .state
            .save(
                local.secret_id,
                StateItem::PendingRecovery {
                    secret_id: response.secret_id,
                    version: response.version,
                    shares,
                    pending,
                    started_at,
                },
            )
            .await?;
    }
    Ok(events)
}

/// Judge one Helper's answer on its own, collecting it into `shares` when it
/// is a valid share, and return the event that reports it.
///
/// A refusal or a corrupted share is not collected. A Helper that answers
/// again replaces its earlier share.
fn judge_response(
    local: &Local<'_>,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
    shares: &mut Vec<CollectedShare>,
) -> DeRecEvent {
    if let Some(Err((status, memo))) = response
        .result
        .as_ref()
        .map(|result| result.validate(|status, memo| (status, memo)))
    {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version,
            status,
            memo = %memo,
            "recovery share request refused by helper"
        );
        return DeRecEvent::RecoveryShareRefused {
            channel_id,
            version: response.version,
            status,
            memo,
        };
    }

    let oversized = local.parameter_range.is_some_and(|range| {
        range.max_share_size != 0
            && response.committed_de_rec_share.len() as i64 > range.max_share_size
    });

    let fault = if oversized {
        Some(CorruptionReason::Malformed)
    } else {
        inspect(response.secret_id, response.version, response)
            .err()
            .map(ShareFault::reason)
    };

    if let Some(reason) = fault {
        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version,
            ?reason,
            "recovery share is corrupted; set aside"
        );
        return DeRecEvent::RecoveryShareCorrupted {
            channel_id,
            version: response.version,
            reason,
        };
    }

    shares.retain(|share| share.channel_id != channel_id);
    shares.push(CollectedShare {
        channel_id,
        response: response.clone(),
    });

    #[cfg(feature = "logging")]
    tracing::debug!(
        channel_id = channel_id.0,
        secret_id = response.secret_id,
        version = response.version,
        shares_received = shares.len(),
        "recovery share collected"
    );

    DeRecEvent::RecoveryShareReceived {
        channel_id,
        shares_received: shares.len(),
    }
}

/// What the owner knows of each Helper whose share was collected: the
/// `communication_info` stored on its channel. A channel no longer stored is
/// absent.
pub(in crate::protocol) async fn describe_helpers<C: DeRecChannelStore>(
    channels: &C,
    secret_id: u64,
    shares: &[CollectedShare],
) -> Result<HashMap<ChannelId, HashMap<String, String>>> {
    if shares.is_empty() {
        return Ok(HashMap::new());
    }
    let ids: Vec<ChannelId> = shares.iter().map(|s| s.channel_id).collect();
    Ok(channels
        .helpers_matching(
            secret_id,
            HelperFilter {
                ids,
                ..Default::default()
            },
        )
        .await?
        .into_iter()
        .map(|c| (c.channel_id, c.communication_info))
        .collect())
}

/// Decide a closed recovery of `(secret_id, version)` from every share it
/// collected, returning the events that report the decision. `helpers` is
/// what [`describe_helpers`] returned for `shares`.
///
/// Called once per recovery: when its last answer arrives, or when the
/// timeout sweep closes it. Every reconstructing group is a candidate (see
/// [`candidates`]). Shares in a group that reconstructs something that is
/// not a secret are reported as [`CorruptionReason::Forged`] first. Every
/// other share outside the candidates disputes them. Then:
///
/// - no candidate is [`DeRecEvent::RecoveryIncomplete`];
/// - one candidate is [`DeRecEvent::SecretRecovered`], or
///   [`DeRecEvent::RecoveryDisputed`] when any share disputes it;
/// - several are [`DeRecEvent::RecoveryConflict`].
pub(in crate::protocol) fn settle(
    secret_id: u64,
    version: u32,
    shares: &[CollectedShare],
    helpers: &HashMap<ChannelId, HashMap<String, String>>,
) -> Vec<DeRecEvent> {
    let responses: Vec<&GetShareResponseMessage> = shares.iter().map(|s| &s.response).collect();
    let CandidateSet {
        candidates,
        forged,
        faults,
    } = candidates(secret_id, version, &responses);

    let helper = |i: usize| RecoveryHelper {
        channel_id: shares[i].channel_id,
        communication_info: helpers
            .get(&shares[i].channel_id)
            .cloned()
            .unwrap_or_default(),
    };

    let mut events: Vec<DeRecEvent> = faults
        .iter()
        .copied()
        .chain(forged.iter().map(|&i| (i, CorruptionReason::Forged)))
        .map(|(i, reason)| DeRecEvent::RecoveryShareCorrupted {
            channel_id: shares[i].channel_id,
            version,
            reason,
        })
        .collect();

    if candidates.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!(
            secret_id,
            version,
            shares_received = shares.len() - faults.len(),
            "recovery closed without reconstructing a secret"
        );
        events.push(DeRecEvent::RecoveryIncomplete {
            secret_id,
            version,
            shares_received: shares.len() - faults.len(),
        });
        return events;
    }

    let accounted: HashSet<usize> = candidates
        .iter()
        .flat_map(|c| c.members.iter().copied())
        .chain(forged.iter().copied())
        .chain(faults.iter().map(|&(i, _)| i))
        .collect();
    let disputed_by: Vec<RecoveryHelper> = (0..shares.len())
        .filter(|i| !accounted.contains(i))
        .map(helper)
        .collect();

    let mut candidates = candidates;
    if candidates.len() == 1 {
        let candidate = candidates.remove(0);
        if disputed_by.is_empty() {
            #[cfg(feature = "logging")]
            tracing::info!(
                secret_id,
                version,
                used = candidate.members.len(),
                "secret reconstructed from shares"
            );
            events.push(DeRecEvent::SecretRecovered {
                secret: candidate.secret,
            });
        } else {
            #[cfg(feature = "logging")]
            tracing::warn!(
                secret_id,
                version,
                supported = candidate.members.len(),
                disputed = disputed_by.len(),
                "reconstructed secret is disputed by shares of another split"
            );
            events.push(DeRecEvent::RecoveryDisputed {
                version,
                secret: candidate.secret,
                supported_by: candidate.members.iter().map(|&i| helper(i)).collect(),
                disputed_by,
            });
        }
        return events;
    }

    #[cfg(feature = "logging")]
    tracing::warn!(
        secret_id,
        version,
        candidates = candidates.len(),
        "recovery reconstructed conflicting secrets"
    );
    events.push(DeRecEvent::RecoveryConflict {
        version,
        candidates: candidates
            .into_iter()
            .map(|c| RecoveryCandidate {
                supported_by: c.members.iter().map(|&i| helper(i)).collect(),
                secret: c.secret,
            })
            .collect(),
        disputed_by,
    });
    events
}

fn decode_recovered_secret(outer_bytes: &[u8]) -> Result<Secret> {
    let derec_secret =
        DeRecSecret::decode(outer_bytes).map_err(|e| RecoveryError::MalformedRecoveredSecret {
            source: Box::new(e),
        })?;
    let secret = Secret::decode(&derec_secret.secret_data).map_err(|e| {
        RecoveryError::MalformedRecoveredSecret {
            source: Box::new(e),
        }
    })?;
    Ok(secret)
}

/// Send a share request to every resolved channel, reporting each outcome
/// and returning the channels a request reached.
///
/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes a `RecoverSecretFailed` and the
/// fan-out continues, so one unreachable helper cannot suppress the rest.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    all_channels: Vec<HelperChannel>,
    mut keys: HashMap<ChannelId, SharedKey>,
    target_secret_id: u64,
    version: u32,
    round: &Round<'_>,
) -> (Vec<DeRecEvent>, HashSet<ChannelId>) {
    let mut events = Vec::with_capacity(all_channels.len());
    let mut asked = HashSet::with_capacity(all_channels.len());
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
                asked.insert(channel.channel_id);
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
    (events, asked)
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    channel_id: ChannelId,
    endpoints: &[TransportProtocol],
    secret_id: u64,
    version: u32,
    shared_key: &SharedKey,
    round: &Round<'_>,
) -> Result<()> {
    let msg = request::produce(channel_id, secret_id, version, shared_key, round.reply_to)?;
    let envelope = apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(endpoints, envelope).await?;
    Ok(())
}

/// Why [`inspect`] refused a single share.
#[derive(Debug)]
enum ShareFault {
    /// The response carries no decodable committed share for the requested
    /// `(secret_id, version)`: missing result, empty or undecodable share
    /// bytes, or a share bound to another secret or version.
    Malformed,
    /// The share decodes but its Merkle proof does not open to its own
    /// commitment.
    InvalidProof,
}

impl ShareFault {
    /// How [`DeRecEvent::RecoveryShareCorrupted`] reports this fault.
    fn reason(self) -> CorruptionReason {
        match self {
            Self::Malformed => CorruptionReason::Malformed,
            Self::InvalidProof => CorruptionReason::InvalidProof,
        }
    }
}

/// Every check a single OK-status share admits without the others: it
/// decodes, it belongs to `(secret_id, version)`, and it passes
/// [`vss::verify`].
///
/// A share that passes can still disagree with the rest of a set — carry a
/// different commitment or ciphertext — which only [`recover_consistent`]
/// can judge.
fn inspect(
    secret_id: u64,
    version: u32,
    response: &GetShareResponseMessage,
) -> std::result::Result<vss::VSSShare, ShareFault> {
    let share = response::extract_share_from_response(response, secret_id, version)
        .map_err(|_| ShareFault::Malformed)?;
    if !vss::verify(&share) {
        return Err(ShareFault::InvalidProof);
    }
    Ok(share)
}

/// The fewest distinct shares a group is tried with: [`vss::share`] refuses a
/// threshold below two and a weight of the threshold or more, so every honest
/// split needs subshares from at least two helpers. A share received is not
/// trusted to keep that bound, so a single share is never tried however many
/// subshares it carries.
const MIN_RECONSTRUCTION_SHARES: usize = 2;

/// One secret reconstructed from a collected set.
struct Candidate {
    /// The reconstructed secret, decoded.
    secret: Secret,
    /// Indices into the `responses` passed to [`candidates`] of the shares
    /// that reconstruct it.
    members: Vec<usize>,
}

/// Every secret a collected set reconstructs, the shares that provably
/// forge one, and the shares that fail on their own.
struct CandidateSet {
    /// Distinct secrets, largest group first, ties going to the group whose
    /// first share was collected earliest.
    candidates: Vec<Candidate>,
    /// Indices of the shares in a group that reconstructs under one key but
    /// not to a secret, in collection order.
    forged: Vec<usize>,
    /// Indices of the shares that fail [`inspect`], with why. They are in no
    /// group.
    faults: Vec<(usize, CorruptionReason)>,
}

/// Every secret a set of collected shares reconstructs.
///
/// Shares are grouped by `(commitment, encrypted_secret)`, and every group is
/// tried, so a forged group cannot hide an honest one by reconstructing
/// first. A share repeated across channels counts once: a share whose
/// subshares equal those of a share already taken is skipped. A group is a
/// candidate when it holds at least [`MIN_RECONSTRUCTION_SHARES`] distinct
/// shares, decrypts, decodes as a secret, and fits the threshold that secret
/// declares (see [`fits_declared_threshold`]). Two groups that reconstruct
/// the same bytes are one candidate.
///
/// A group that decrypts and is not a candidate is forged: it holds a whole
/// split under one key — which takes at least the threshold of subshares —
/// yet too few Helpers for an honest split, or bytes that are not a secret,
/// or a threshold its own shares contradict. An honest split produces none
/// of these.
///
/// Decryption is what proves a group whole: a key interpolated from fewer
/// than the threshold of genuine subshares fails the ciphertext's
/// authentication. No threshold is known before reconstruction, so a group
/// that fails is not evidence against any of its shares.
///
/// Every share was inspected when it was collected; one that no longer
/// passes is reported in [`CandidateSet::faults`] and left out.
fn candidates(
    secret_id: u64,
    version: u32,
    responses: &[&GetShareResponseMessage],
) -> CandidateSet {
    let mut faults = Vec::new();
    let mut shares: Vec<(usize, vss::VSSShare)> = Vec::with_capacity(responses.len());
    for (i, response) in responses.iter().enumerate() {
        match inspect(secret_id, version, response) {
            Ok(share) => shares.push((i, share)),
            Err(fault) => faults.push((i, fault.reason())),
        }
    }

    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (pos, (_, share)) in shares.iter().enumerate() {
        let existing = groups.iter_mut().find(|group| {
            let first = &shares[group[0]].1;
            first.commitment == share.commitment && first.encrypted_secret == share.encrypted_secret
        });
        match existing {
            Some(group) => group.push(pos),
            None => groups.push(vec![pos]),
        }
    }
    groups.sort_by_key(|group| Reverse(group.len()));

    let mut found: Vec<(Vec<u8>, Candidate)> = Vec::new();
    let mut forged = Vec::new();
    for group in &groups {
        let mut distinct: Vec<vss::VSSShare> = Vec::with_capacity(group.len());
        for &pos in group {
            if !distinct
                .iter()
                .any(|s| s.subshares == shares[pos].1.subshares)
            {
                distinct.push(shares[pos].1.clone());
            }
        }
        let members: Vec<usize> = group.iter().map(|&pos| shares[pos].0).collect();
        let Ok(secret_data) = vss::recover(&distinct) else {
            continue;
        };
        if distinct.len() < MIN_RECONSTRUCTION_SHARES {
            #[cfg(feature = "logging")]
            tracing::warn!("a single share reconstructed on its own; forged");
            forged.extend(members);
            continue;
        }
        let secret = match decode_recovered_secret(&secret_data) {
            Ok(secret) => secret,
            Err(_e) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    used = group.len(),
                    error = %_e,
                    "group decrypted to bytes that are not a secret; forged"
                );
                forged.extend(members);
                continue;
            }
        };
        if !fits_declared_threshold(&secret, &distinct) {
            #[cfg(feature = "logging")]
            tracing::warn!(
                used = group.len(),
                threshold = secret.threshold,
                "reconstructed secret does not fit its declared threshold; forged"
            );
            forged.extend(members);
            continue;
        }
        match found.iter_mut().find(|(bytes, _)| *bytes == secret_data) {
            Some((_, same)) => {
                same.members.extend(members);
                same.members.sort_unstable();
            }
            None => found.push((secret_data, Candidate { secret, members })),
        }
    }

    forged.sort_unstable();
    CandidateSet {
        candidates: found.into_iter().map(|(_, c)| c).collect(),
        forged,
        faults,
    }
}

/// Whether `shares` could be an honest split of `secret` at the threshold it
/// declares: every share carries fewer subshares than the threshold, and
/// together they carry at least the threshold. A secret that records no
/// threshold is not checked.
fn fits_declared_threshold(secret: &Secret, shares: &[vss::VSSShare]) -> bool {
    let Some(threshold) = secret.threshold else {
        return true;
    };
    let threshold = threshold as usize;
    let total: usize = shares.iter().map(|s| s.subshares.len()).sum();
    total >= threshold && shares.iter().all(|s| s.subshares.len() < threshold)
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

    use super::tests::{encode_protect_wrapping, fixture_secret};
    use super::*;
    use crate::derec_message::extract_inner_message;
    use crate::primitives::sharing::request;
    use crate::protocol::context::{Exchange, Round};
    use crate::protocol::tests::LocalFixture;
    use crate::protocol::tests::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, RecordingTransport,
        StoreRig, run_async,
    };
    use crate::protocol::types::{
        ChannelRecord, ChannelStatus, HelperChannel, ReplicaMember, ReplicaRole, SecretValue,
    };
    use crate::types::{ChannelId, ReplicaId};
    use crate::utils::now_secs;
    use derec_proto::{DeRecMessage, Protocol, SenderKind, TransportProtocol};
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
            protocol: Protocol::Https as i32,
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
                replica_id: ReplicaId(cid),
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
                weight: 1,
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
        let inner =
            extract_inner_message(&msg.message, &[key_byte; 32]).expect("inner message decrypts");
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
        let weighted: Vec<_> = cids.iter().map(|&cid| (cid, 1)).collect();
        let split = request::split(&weighted, secret_id, version, payload, threshold)
            .expect("split succeeds");
        cids.iter()
            .map(|cid| GetShareResponseMessage {
                result: Some(DeRecResult::ok()),
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

    /// An open recovery of `(target, VERSION)` still waiting on `channels`.
    async fn seed_pending(state: &mut InMemPersistedStateStore, target: u64, channels: &[u64]) {
        state
            .save(
                LOCAL,
                StateItem::PendingRecovery {
                    secret_id: target,
                    version: VERSION,
                    shares: Vec::new(),
                    pending: channels.iter().copied().map(ChannelId).collect(),
                    started_at: now_secs(),
                },
            )
            .await
            .expect("seed pending");
    }

    // ---------------------------------------------------------------
    // Definition 1 — outbound: requests go to the LOCAL instance's
    // helpers and carry the TARGET secret id.
    // ---------------------------------------------------------------

    /// A fixed round, so a test can assert what reaches the wire.
    const ROUND: Round<'static> = Round {
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
    fn start_closes_incomplete_when_the_local_instance_has_no_channels() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            // Channels exist, but under the target — not under us.
            seed_channel(&mut rig.channels, &mut rig.secrets, TARGET, 21, 0xB1).await;

            let events = start(&mut rig.stores(), &lf.local(), TARGET, VERSION, &ROUND)
                .await
                .expect("start succeeds");

            assert!(rig.transport.sent_uris().is_empty());
            assert!(
                matches!(
                    events.as_slice(),
                    [DeRecEvent::RecoveryIncomplete {
                        secret_id: TARGET,
                        version: VERSION,
                        shares_received: 0,
                    }]
                ),
                "with no Helper to ask the recovery closes at once, got {events:?}"
            );
            assert!(
                rig.state
                    .load(LOCAL, pending_key(TARGET, VERSION))
                    .await
                    .expect("load")
                    .is_none(),
                "nothing is left waiting"
            );
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
            seed_pending(&mut rig.state, TARGET, &[11, 12, 13]).await;

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
            seed_pending(&mut rig.state, TARGET, &[11, 12, 13]).await;

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
            seed_pending(&mut rig.state, TARGET, &[11, 12]).await;

            let payload = encode_protect_wrapping(&fixture_secret());
            let responses = helper_responses(TARGET, VERSION, &[11, 12], 2, &payload);

            on_response(&mut rig.stores(), &lf.local(), ChannelId(11), &responses[0])
                .await
                .expect("first share accepted");
            let events = on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &responses[1])
                .await
                .expect("second share accepted");

            let recovered = match events.as_slice() {
                [
                    DeRecEvent::RecoveryShareReceived {
                        shares_received: 2, ..
                    },
                    DeRecEvent::SecretRecovered { secret },
                ] => secret.clone(),
                other => panic!("expected SecretRecovered, got {other:?}"),
            };
            assert_eq!(recovered, fixture_secret());
        });
    }

    #[test]
    fn on_response_clears_pending_state_after_reconstruction() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            seed_pending(&mut rig.state, TARGET, &[11, 12]).await;

            let payload = encode_protect_wrapping(&fixture_secret());
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
            seed_pending(&mut rig.state, TARGET_A, &[11, 12, 13]).await;
            seed_pending(&mut rig.state, TARGET_B, &[21, 22, 23]).await;

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

    /// A `GetShareResponse` carrying the given refusal instead of a share.
    fn refusal(secret_id: u64, version: u32, status: StatusEnum) -> GetShareResponseMessage {
        GetShareResponseMessage {
            result: Some(DeRecResult {
                status: status as i32,
                memo: "no share stored for this secret and version".to_owned(),
            }),
            committed_de_rec_share: Vec::new(),
            share_algorithm: 0,
            timestamp: Some(current_timestamp()),
            secret_id,
            version,
            replica_id: None,
        }
    }

    /// A helper that holds no share for the version answers with a refusal.
    /// Collecting it would make every later reconstruction attempt fail on
    /// it, so one refusal would block the recovery for good; it is reported
    /// and set aside instead, and the remaining helpers complete the
    /// recovery.
    #[test]
    fn on_response_sets_a_refusal_aside_and_recovers_from_the_other_shares() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();
            seed_pending(&mut rig.state, TARGET, &[11, 12, 13]).await;

            let payload = encode_protect_wrapping(&fixture_secret());
            let responses = helper_responses(TARGET, VERSION, &[12, 13], 2, &payload);

            let refused = on_response(
                &mut rig.stores(),
                &lf.local(),
                ChannelId(11),
                &refusal(TARGET, VERSION, StatusEnum::UnknownShareVersion),
            )
            .await
            .expect("a refusal is an outcome, not an error");
            assert!(
                matches!(
                    refused.as_slice(),
                    [DeRecEvent::RecoveryShareRefused { channel_id, version, status, memo }]
                        if *channel_id == ChannelId(11)
                            && *version == VERSION
                            && *status == StatusEnum::UnknownShareVersion as i32
                            && memo == "no share stored for this secret and version"
                ),
                "got {refused:?}"
            );
            assert!(
                matches!(
                    rig.state.load(LOCAL, pending_key(TARGET, VERSION)).await.expect("load"),
                    Some(StateItem::PendingRecovery { ref shares, .. }) if shares.is_empty()
                ),
                "a refusal must not enter the collected set"
            );

            let first = on_response(&mut rig.stores(), &lf.local(), ChannelId(12), &responses[0])
                .await
                .expect("first share accepted");
            assert!(
                matches!(
                    first.as_slice(),
                    [DeRecEvent::RecoveryShareReceived {
                        shares_received: 1,
                        ..
                    }]
                ),
                "the refusal must not count as a received share, got {first:?}"
            );

            let second = on_response(&mut rig.stores(), &lf.local(), ChannelId(13), &responses[1])
                .await
                .expect("second share accepted");
            match second.as_slice() {
                [
                    DeRecEvent::RecoveryShareReceived { .. },
                    DeRecEvent::SecretRecovered { secret },
                ] => {
                    assert_eq!(*secret, fixture_secret())
                }
                other => panic!("expected SecretRecovered, got {other:?}"),
            }
        });
    }

    /// A refusal for a recovery this device never started is as unsolicited
    /// as a share would be, and is dropped the same way.
    #[test]
    fn on_response_drops_a_refusal_with_no_matching_pending_recovery() {
        run_async(async {
            let lf = LocalFixture::new(LOCAL);
            let mut rig = StoreRig::new();

            let events = on_response(
                &mut rig.stores(),
                &lf.local(),
                ChannelId(11),
                &refusal(TARGET, VERSION, StatusEnum::UnknownShareVersion),
            )
            .await
            .expect("an unsolicited refusal is dropped, not an error");

            assert!(matches!(events.as_slice(), [DeRecEvent::NoOp]));
        });
    }

    /// Per-helper detection of corrupted shares: a share that cannot be part
    /// of the secret is reported against the channel it arrived on and set
    /// aside, so it never blocks reconstruction from the honest shares.
    mod corrupted_shares {
        use super::super::tests::{encode_protect_wrapping, fixture_secret};
        use super::*;
        use crate::protocol::CorruptionReason;
        use derec_proto::{CommittedDeRecShare, DeRecShare, ParameterRange};
        use prost::encoding::bytes;

        /// An open recovery waiting on `channels`: it decides when the last
        /// of them answers.
        async fn seeded(channels: &[u64]) -> (LocalFixture, StoreRig) {
            seeded_with(LocalFixture::new(LOCAL), channels).await
        }

        async fn seeded_with(lf: LocalFixture, channels: &[u64]) -> (LocalFixture, StoreRig) {
            let mut rig = StoreRig::new();
            seed_pending(&mut rig.state, TARGET, channels).await;
            (lf, rig)
        }

        /// Appends a harmless, unrecognized field to a committed share's
        /// encoding, growing it by roughly `extra_len` bytes without
        /// changing what it decodes to: an unknown field is skipped during
        /// `CommittedDeRecShare::decode`.
        fn padded(response: &GetShareResponseMessage, extra_len: usize) -> GetShareResponseMessage {
            let mut bytes = response.committed_de_rec_share.clone();
            bytes::encode(9_999, &vec![0xAA_u8; extra_len], &mut bytes);
            GetShareResponseMessage {
                committed_de_rec_share: bytes,
                ..response.clone()
            }
        }

        fn secret_payload() -> Vec<u8> {
            encode_protect_wrapping(&fixture_secret())
        }

        fn rewrite_share(
            response: &GetShareResponseMessage,
            edit: impl FnOnce(&mut DeRecShare),
        ) -> GetShareResponseMessage {
            let mut committed =
                CommittedDeRecShare::decode(response.committed_de_rec_share.as_slice())
                    .expect("committed share decodes");
            let mut share =
                DeRecShare::decode(committed.de_rec_share.as_slice()).expect("share decodes");
            edit(&mut share);
            committed.de_rec_share = share.encode_to_vec();
            GetShareResponseMessage {
                committed_de_rec_share: committed.encode_to_vec(),
                ..response.clone()
            }
        }

        fn with_flipped_y(response: &GetShareResponseMessage) -> GetShareResponseMessage {
            rewrite_share(response, |share| share.subshares[0].y[0] ^= 0x01)
        }

        fn with_flipped_ciphertext(response: &GetShareResponseMessage) -> GetShareResponseMessage {
            rewrite_share(response, |share| share.encrypted_secret[0] ^= 0x01)
        }

        async fn deliver(
            rig: &mut StoreRig,
            lf: &LocalFixture,
            channel: u64,
            response: &GetShareResponseMessage,
        ) -> Vec<DeRecEvent> {
            on_response(&mut rig.stores(), &lf.local(), ChannelId(channel), response)
                .await
                .expect("a share response is an outcome, not an error")
        }

        fn corrupted(events: &[DeRecEvent]) -> Vec<(ChannelId, CorruptionReason)> {
            events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::RecoveryShareCorrupted {
                        channel_id,
                        version,
                        reason,
                    } => {
                        assert_eq!(*version, VERSION);
                        Some((*channel_id, *reason))
                    }
                    _ => None,
                })
                .collect()
        }

        fn recovered(events: &[DeRecEvent]) -> bool {
            events.iter().any(|e| match e {
                DeRecEvent::SecretRecovered { secret } => {
                    assert_eq!(*secret, fixture_secret());
                    true
                }
                _ => false,
            })
        }

        async fn collected(rig: &StoreRig) -> Vec<ChannelId> {
            match rig
                .state
                .load(LOCAL, pending_key(TARGET, VERSION))
                .await
                .expect("load")
            {
                Some(StateItem::PendingRecovery { shares, .. }) => {
                    shares.iter().map(|s| s.channel_id).collect()
                }
                other => panic!("expected an open accumulator, got {other:?}"),
            }
        }

        /// The tampered share arrives first. Before per-share checks it was
        /// collected, and every later reconstruction failed on it, so the
        /// recovery could never complete.
        #[test]
        fn a_tampered_share_arriving_first_is_reported_and_recovery_completes() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12, 13]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12, 13], 2, &secret_payload());
                let bad = with_flipped_y(&good[0]);

                let first = deliver(&mut rig, &lf, 11, &bad).await;
                assert_eq!(
                    corrupted(&first),
                    vec![(ChannelId(11), CorruptionReason::InvalidProof)]
                );
                assert_eq!(first.len(), 1, "got {first:?}");
                assert!(
                    collected(&rig).await.is_empty(),
                    "a corrupted share must not enter the collected set"
                );

                let second = deliver(&mut rig, &lf, 12, &good[1]).await;
                assert!(
                    matches!(
                        second.as_slice(),
                        [DeRecEvent::RecoveryShareReceived {
                            shares_received: 1,
                            ..
                        }]
                    ),
                    "got {second:?}"
                );

                let third = deliver(&mut rig, &lf, 13, &good[2]).await;
                assert!(
                    corrupted(&third).is_empty(),
                    "reported once only: {third:?}"
                );
                assert!(recovered(&third), "got {third:?}");
            });
        }

        /// Wherever the tampered share falls among the shares that complete
        /// the recovery, it is reported once and the recovery completes.
        #[test]
        fn a_tampered_share_at_any_position_before_completion_is_set_aside() {
            run_async(async {
                for position in 0..3 {
                    let (lf, mut rig) = seeded(&[11, 12, 13, 14]).await;
                    let good =
                        helper_responses(TARGET, VERSION, &[11, 12, 13, 14], 3, &secret_payload());
                    let bad = with_flipped_y(&good[0]);

                    let mut order: Vec<(u64, GetShareResponseMessage)> = vec![
                        (12, good[1].clone()),
                        (13, good[2].clone()),
                        (14, good[3].clone()),
                    ];
                    order.insert(position, (11, bad));

                    let mut events = Vec::new();
                    for (channel, response) in &order {
                        events.extend(deliver(&mut rig, &lf, *channel, response).await);
                    }

                    assert_eq!(
                        corrupted(&events),
                        vec![(ChannelId(11), CorruptionReason::InvalidProof)],
                        "position {position}: {events:?}"
                    );
                    assert!(
                        matches!(events.last(), Some(DeRecEvent::SecretRecovered { .. })),
                        "position {position}: {events:?}"
                    );
                    assert!(recovered(&events));
                }
            });
        }

        /// A share arriving after the recovery completed finds no open
        /// recovery and is dropped like any unsolicited response.
        #[test]
        fn a_tampered_share_after_completion_is_dropped() {
            run_async(async {
                let (lf, mut rig) = seeded(&[12, 13]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12, 13], 2, &secret_payload());

                deliver(&mut rig, &lf, 12, &good[1]).await;
                let done = deliver(&mut rig, &lf, 13, &good[2]).await;
                assert!(recovered(&done));

                let late = deliver(&mut rig, &lf, 11, &with_flipped_y(&good[0])).await;
                assert!(
                    matches!(late.as_slice(), [DeRecEvent::NoOp]),
                    "got {late:?}"
                );
            });
        }

        /// Below the threshold a tampered share is still reported at once,
        /// nothing is recovered, and the remaining good shares complete it.
        #[test]
        fn a_tampered_share_below_threshold_is_reported_and_later_shares_complete() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12, 13, 14]).await;
                let good =
                    helper_responses(TARGET, VERSION, &[11, 12, 13, 14], 3, &secret_payload());

                let mut events = deliver(&mut rig, &lf, 11, &with_flipped_y(&good[0])).await;
                events.extend(deliver(&mut rig, &lf, 12, &good[1]).await);
                events.extend(deliver(&mut rig, &lf, 13, &good[2]).await);

                assert_eq!(
                    corrupted(&events),
                    vec![(ChannelId(11), CorruptionReason::InvalidProof)]
                );
                assert!(!recovered(&events), "two of three shares: {events:?}");
                assert!(matches!(
                    events.last(),
                    Some(DeRecEvent::RecoveryShareReceived {
                        shares_received: 2,
                        ..
                    })
                ));
                assert_eq!(collected(&rig).await, vec![ChannelId(12), ChannelId(13)]);

                let last = deliver(&mut rig, &lf, 14, &good[3]).await;
                assert!(corrupted(&last).is_empty(), "got {last:?}");
                assert!(recovered(&last), "got {last:?}");
            });
        }

        /// A share that verifies on its own but belongs to another split —
        /// another root and ciphertext, or the same root with an altered
        /// ciphertext — is excluded from the reconstruction. It is not
        /// evidence against its Helper, so it disputes the secret rather than
        /// being reported as corrupted.
        #[test]
        fn a_self_consistent_share_from_another_split_disputes_the_secret() {
            run_async(async {
                let good = helper_responses(TARGET, VERSION, &[11, 12, 13], 2, &secret_payload());
                let other_split =
                    helper_responses(TARGET, VERSION, &[11, 12, 13], 2, b"another round entirely");
                for outlier in [other_split[0].clone(), with_flipped_ciphertext(&good[0])] {
                    let (lf, mut rig) = seeded(&[11, 12, 13]).await;

                    let first = deliver(&mut rig, &lf, 11, &outlier).await;
                    assert!(
                        matches!(
                            first.as_slice(),
                            [DeRecEvent::RecoveryShareReceived {
                                shares_received: 1,
                                ..
                            }]
                        ),
                        "a share valid on its own is collected: {first:?}"
                    );
                    let second = deliver(&mut rig, &lf, 12, &good[1]).await;
                    assert!(
                        matches!(
                            second.as_slice(),
                            [DeRecEvent::RecoveryShareReceived {
                                shares_received: 2,
                                ..
                            }]
                        ),
                        "two disagreeing shares wait for a third: {second:?}"
                    );

                    let third = deliver(&mut rig, &lf, 13, &good[2]).await;
                    assert!(corrupted(&third).is_empty(), "got {third:?}");
                    match third.last() {
                        Some(DeRecEvent::RecoveryDisputed {
                            version,
                            secret,
                            supported_by,
                            disputed_by,
                        }) => {
                            assert_eq!(*version, VERSION);
                            assert_eq!(*secret, fixture_secret());
                            let ids = |hs: &[RecoveryHelper]| {
                                hs.iter().map(|h| h.channel_id).collect::<Vec<_>>()
                            };
                            assert_eq!(ids(supported_by), vec![ChannelId(12), ChannelId(13)]);
                            assert_eq!(ids(disputed_by), vec![ChannelId(11)]);
                        }
                        other => panic!("expected RecoveryDisputed, got {other:?}"),
                    }
                }
            });
        }

        /// An OK response whose share bytes do not decode is reported as
        /// malformed and leaves the collected set untouched.
        #[test]
        fn an_undecodable_share_is_reported_as_malformed() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12, 13]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12], 2, &secret_payload());
                deliver(&mut rig, &lf, 12, &good[1]).await;

                let garbage = GetShareResponseMessage {
                    committed_de_rec_share: vec![0xFF; 16],
                    ..good[0].clone()
                };
                let events = deliver(&mut rig, &lf, 11, &garbage).await;
                assert_eq!(
                    corrupted(&events),
                    vec![(ChannelId(11), CorruptionReason::Malformed)]
                );
                assert_eq!(collected(&rig).await, vec![ChannelId(12)]);
            });
        }

        /// A share bigger than this device's own `max_share_size` is set
        /// aside before it is even parsed, exactly like an undecodable
        /// share. The threshold is still met from the shares that fit.
        #[test]
        fn recovery_sets_aside_a_share_above_max_share_size() {
            run_async(async {
                let good = helper_responses(TARGET, VERSION, &[11, 12, 13], 2, &secret_payload());
                let max = good[0]
                    .committed_de_rec_share
                    .len()
                    .max(good[1].committed_de_rec_share.len()) as i64;
                let range = ParameterRange {
                    max_share_size: max,
                    ..Default::default()
                };
                let (lf, mut rig) = seeded_with(
                    LocalFixture::with_parameter_range(LOCAL, range),
                    &[11, 12, 13],
                )
                .await;
                let oversized = padded(&good[2], 256);

                let first = deliver(&mut rig, &lf, 13, &oversized).await;
                assert_eq!(
                    corrupted(&first),
                    vec![(ChannelId(13), CorruptionReason::Malformed)]
                );
                assert!(
                    collected(&rig).await.is_empty(),
                    "an oversized share must not enter the collected set"
                );

                let second = deliver(&mut rig, &lf, 11, &good[0]).await;
                assert!(
                    matches!(
                        second.as_slice(),
                        [DeRecEvent::RecoveryShareReceived {
                            shares_received: 1,
                            ..
                        }]
                    ),
                    "got {second:?}"
                );

                let third = deliver(&mut rig, &lf, 12, &good[1]).await;
                assert!(corrupted(&third).is_empty(), "got {third:?}");
                assert!(recovered(&third), "got {third:?}");
            });
        }

        /// With no `max_share_size` configured (no parameter range at all),
        /// a large share is accepted and recovery proceeds normally.
        #[test]
        fn recovery_accepts_large_shares_without_a_limit() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12], 2, &secret_payload());
                let large = padded(&good[0], 64 * 1024);

                deliver(&mut rig, &lf, 11, &large).await;
                let last = deliver(&mut rig, &lf, 12, &good[1]).await;
                assert!(corrupted(&last).is_empty(), "got {last:?}");
                assert!(recovered(&last), "got {last:?}");
            });
        }

        /// A parameter range whose `max_share_size` is `0` means unbounded:
        /// a large share is accepted and recovery proceeds normally.
        #[test]
        fn recovery_accepts_large_shares_when_max_share_size_is_zero() {
            run_async(async {
                let range = ParameterRange {
                    max_share_size: 0,
                    ..Default::default()
                };
                let (lf, mut rig) =
                    seeded_with(LocalFixture::with_parameter_range(LOCAL, range), &[11, 12]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12], 2, &secret_payload());
                let large = padded(&good[0], 64 * 1024);

                let first = deliver(&mut rig, &lf, 11, &large).await;
                assert!(corrupted(&first).is_empty(), "got {first:?}");
                let last = deliver(&mut rig, &lf, 12, &good[1]).await;
                assert!(corrupted(&last).is_empty(), "got {last:?}");
                assert!(recovered(&last), "got {last:?}");
            });
        }

        /// A response from a channel that already answered replaces its
        /// earlier share instead of counting twice.
        #[test]
        fn a_repeated_answer_from_one_channel_counts_once() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12, 13]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12, 13], 3, &secret_payload());

                deliver(&mut rig, &lf, 11, &good[0]).await;
                let again = deliver(&mut rig, &lf, 11, &good[0]).await;
                assert!(
                    matches!(
                        again.as_slice(),
                        [DeRecEvent::RecoveryShareReceived {
                            shares_received: 1,
                            ..
                        }]
                    ),
                    "got {again:?}"
                );
                assert_eq!(collected(&rig).await, vec![ChannelId(11)]);
            });
        }

        /// The same share reaching the owner on two channels — an original
        /// and its linked recovery channel — counts once, not twice. It must
        /// neither complete the recovery alone nor fail the interpolation.
        #[test]
        fn one_share_arriving_on_two_channels_counts_once() {
            run_async(async {
                let (lf, mut rig) = seeded(&[11, 12, 21]).await;
                let good = helper_responses(TARGET, VERSION, &[11, 12], 2, &secret_payload());

                deliver(&mut rig, &lf, 11, &good[0]).await;
                let duplicate = deliver(&mut rig, &lf, 21, &good[0]).await;
                assert!(
                    matches!(
                        duplicate.as_slice(),
                        [DeRecEvent::RecoveryShareReceived {
                            shares_received: 2,
                            ..
                        }]
                    ),
                    "got {duplicate:?}"
                );

                let last = deliver(&mut rig, &lf, 12, &good[1]).await;
                assert!(corrupted(&last).is_empty(), "got {last:?}");
                assert!(recovered(&last), "got {last:?}");
            });
        }
    }

    /// The helper side of a refusal: a helper asked for a version it does not
    /// hold answers `UNKNOWN_SHARE_VERSION` rather than leaving the owner
    /// waiting, and the exchange is not a failure of the helper's `process`.
    mod helper_without_the_share {
        use super::*;
        use crate::derec_message::{DeRecMessageBuilder, extract_inner_message};
        use crate::protocol::tests::{InMemShareStore, InMemUserSecretStore};
        use crate::protocol::{AutoAcceptPolicy, DeRecProtocol, DeRecProtocolBuilder};

        type TestProto = DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            RecordingTransport,
        >;

        const OWNER_CHANNEL: u64 = 11;
        const KEY_BYTE: u8 = 0xA1;

        async fn helper(auto_accept: AutoAcceptPolicy) -> (TestProto, RecordingTransport) {
            let mut rig = StoreRig::new();
            seed_channel_as(
                &mut rig.channels,
                &mut rig.secrets,
                LOCAL,
                OWNER_CHANNEL,
                KEY_BYTE,
                SenderKind::Owner,
                ChannelStatus::Paired,
            )
            .await;
            let protocol = DeRecProtocolBuilder::new(LOCAL)
                .with_channel_store(rig.channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(rig.secrets)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(rig.state)
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://helper.example"])
                .with_auto_accept(auto_accept)
                .build()
                .expect("test rig builds");
            (protocol, rig.transport)
        }

        fn request_envelope() -> Vec<u8> {
            let timestamp = current_timestamp();
            DeRecMessageBuilder::channel()
                .channel_id(ChannelId(OWNER_CHANNEL))
                .timestamp(timestamp)
                .message_body(MessageBody::GetShareRequest(GetShareRequestMessage {
                    secret_id: TARGET,
                    version: VERSION,
                    timestamp: Some(timestamp),
                    ..Default::default()
                }))
                .encrypt(&[KEY_BYTE; 32])
                .expect("encrypts")
                .build()
                .expect("builds")
                .encode_to_vec()
        }

        fn sent_response(transport: &RecordingTransport) -> GetShareResponseMessage {
            let envelopes = transport.sent_envelopes();
            assert_eq!(envelopes.len(), 1, "exactly one answer must be sent");
            let msg = DeRecMessage::decode(envelopes[0].as_slice()).expect("envelope decodes");
            match extract_inner_message(&msg.message, &[KEY_BYTE; 32])
                .expect("inner message decrypts")
            {
                MessageBody::GetShareResponse(r) => r,
                other => panic!("expected GetShareResponse, got {other:?}"),
            }
        }

        fn assert_unknown_share_version(response: &GetShareResponseMessage) {
            let result = response.result.as_ref().expect("response carries a result");
            assert_eq!(result.status, StatusEnum::UnknownShareVersion as i32);
            assert!(response.committed_de_rec_share.is_empty());
            assert_eq!(response.secret_id, TARGET);
            assert_eq!(response.version, VERSION);
        }

        #[test]
        fn auto_accept_answers_unknown_share_version() {
            run_async(async {
                let (mut protocol, transport) = helper(AutoAcceptPolicy {
                    get_share: true,
                    ..Default::default()
                })
                .await;

                let events = protocol
                    .process(&request_envelope())
                    .await
                    .expect("a request for a share not held is answered, not failed");

                assert!(
                    events
                        .iter()
                        .any(|e| matches!(e, DeRecEvent::AutoAccepted { .. })),
                    "got {events:?}"
                );
                assert_unknown_share_version(&sent_response(&transport));
            });
        }

        #[test]
        fn manual_accept_answers_unknown_share_version() {
            run_async(async {
                let (mut protocol, transport) = helper(AutoAcceptPolicy::default()).await;

                let events = protocol
                    .process(&request_envelope())
                    .await
                    .expect("the request surfaces for a decision");
                let action = events
                    .into_iter()
                    .find_map(|e| match e {
                        DeRecEvent::ActionRequired { action, .. } => Some(action),
                        _ => None,
                    })
                    .expect("ActionRequired for the GetShare request");
                assert!(transport.sent_envelopes().is_empty());

                let accepted = protocol
                    .accept(action)
                    .await
                    .expect("accepting a request for a share not held succeeds");

                assert!(
                    matches!(accepted.as_slice(), [DeRecEvent::NoOp]),
                    "got {accepted:?}"
                );
                assert_unknown_share_version(&sent_response(&transport));
            });
        }
    }

    // ---------------------------------------------------------------
    // Wiring — the same two ids, driven through the public protocol
    // surface rather than the handler directly.
    // ---------------------------------------------------------------

    mod wiring {
        use super::*;
        use crate::derec_message::DeRecMessageBuilder;
        use crate::protocol::tests::{InMemShareStore, InMemUserSecretStore};
        use crate::protocol::{DeRecFlow, DeRecProtocol, DeRecProtocolBuilder};

        type TestProto = DeRecProtocol<
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
            DeRecMessageBuilder::channel()
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
        use derec_proto::de_rec_share::Subshare;
        use derec_proto::{CommittedDeRecShare, DeRecShare, StoreShareRequestMessage};

        /// A stored `StoreShareRequestMessage`, shaped the way `accept`
        /// re-decodes it: the requested secret id lives on the innermost
        /// `DeRecShare`, which is what `response::produce` checks against.
        fn stored_share(secret_id: u64, version: u32) -> Vec<u8> {
            let share = DeRecShare {
                encrypted_secret: vec![0xAB; 4],
                subshares: vec![Subshare {
                    x: vec![0x01],
                    y: vec![0x02],
                }],
                secret_id,
                version,
            };
            let committed = CommittedDeRecShare {
                de_rec_share: share.encode_to_vec(),
                commitment: vec![0xCD; 4],
                merkle_path: Vec::new(),
            };
            StoreShareRequestMessage {
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
                            subshares: None,
                            threshold: None,
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
                        obligation: None,
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
    use crate::protocol::types::{
        HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret,
    };
    use derec_proto::{DeRecSecret, Protocol, TransportProtocol};
    use prost::Message;
    use std::collections::HashMap;

    /// Encode a `Secret` the same way `handlers::sharing::wrap_for_helper_split`
    /// does, producing the bytes that VSS would reconstruct on the happy
    /// path. The protect side is the canonical source of this wrapping;
    /// `decode_recovered_secret` is its inverse.
    pub(super) fn encode_protect_wrapping(secret: &Secret) -> Vec<u8> {
        let derec_secret = DeRecSecret {
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
                transports: vec![TransportProtocol {
                    uri: "https://helper.example".to_owned(),
                    protocol: Protocol::Https as i32,
                }],
                shared_key: vec![0xAA; 32],
                communication_info: HashMap::from([("name".to_owned(), "Helper".to_owned())]),
                weight: 1,
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
            replicas: Some(Replicas {
                channel_id: 11,
                members: vec![
                    ReplicaInfo {
                        replica_id: 0xBEEF,
                        transports: vec![TransportProtocol {
                            uri: "https://owner.example".to_owned(),
                            protocol: Protocol::Https as i32,
                        }],
                        role: ReplicaRole::Source as i32,
                        communication_info: HashMap::new(),
                    },
                    ReplicaInfo {
                        replica_id: 0xCAFE,
                        transports: vec![TransportProtocol {
                            uri: "https://replica.example".to_owned(),
                            protocol: Protocol::Https as i32,
                        }],
                        role: ReplicaRole::Destination as i32,
                        communication_info: HashMap::new(),
                    },
                ],
                shared_key: vec![0x55; 32],
            }),
            threshold: None,
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
            .find(|m| m.role == ReplicaRole::Source as i32)
            .expect("the roster names exactly one source");
        assert_eq!(source.replica_id, 0xBEEF);
    }

    /// Empty `secret_data` is not a valid gzip stream, so the inner
    /// secret decode rejects it. The protect side never produces this.
    #[test]
    fn decode_recovered_secret_rejects_empty_inner_secret() {
        let wrapped = DeRecSecret {
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
        let wrapped = DeRecSecret {
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
        let wrapped = DeRecSecret {
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

#[cfg(test)]
mod share_judging_tests {
    use super::tests::{encode_protect_wrapping, fixture_secret};
    use super::*;
    use crate::primitives::sharing::request::{SplitResult, split as sharing_split};
    use crate::protocol::tests::pre_0_0_9_derec_share;
    use crate::protocol::types::Secret;
    use derec_proto::{CommittedDeRecShare, DeRecShare, committed_de_rec_share::SiblingHash};
    use sha2::{Digest, Sha256};

    const SECRET_ID: u64 = 9;
    const VERSION: u32 = 2;

    fn responses(payload: &[u8], threshold: usize, count: u64) -> Vec<GetShareResponseMessage> {
        let channels: Vec<ChannelId> = (1..=count).map(ChannelId).collect();
        let weighted: Vec<_> = channels.iter().map(|&c| (c, 1)).collect();
        let SplitResult { shares } =
            sharing_split(&weighted, SECRET_ID, VERSION, payload, threshold).expect("split");
        channels
            .iter()
            .map(|c| GetShareResponseMessage {
                result: Some(DeRecResult::ok()),
                committed_de_rec_share: shares[c].encode_to_vec(),
                secret_id: SECRET_ID,
                version: VERSION,
                ..Default::default()
            })
            .collect()
    }

    fn with_flipped_y(response: &GetShareResponseMessage) -> GetShareResponseMessage {
        let mut committed =
            CommittedDeRecShare::decode(response.committed_de_rec_share.as_slice()).unwrap();
        let mut share = DeRecShare::decode(committed.de_rec_share.as_slice()).unwrap();
        share.subshares[0].y[0] ^= 0x01;
        committed.de_rec_share = share.encode_to_vec();
        GetShareResponseMessage {
            committed_de_rec_share: committed.encode_to_vec(),
            ..response.clone()
        }
    }

    #[test]
    fn inspect_accepts_an_untouched_share() {
        let good = responses(b"payload", 2, 3);
        assert!(inspect(SECRET_ID, VERSION, &good[0]).is_ok());
    }

    #[test]
    fn inspect_rejects_a_tampered_coordinate_as_invalid_proof() {
        let good = responses(b"payload", 2, 3);
        assert!(matches!(
            inspect(SECRET_ID, VERSION, &with_flipped_y(&good[0])),
            Err(ShareFault::InvalidProof)
        ));
    }

    #[test]
    fn inspect_rejects_undecodable_or_misbound_shares_as_malformed() {
        let good = responses(b"payload", 2, 3);
        let garbage = GetShareResponseMessage {
            committed_de_rec_share: vec![0xFF; 8],
            ..good[0].clone()
        };
        assert!(matches!(
            inspect(SECRET_ID, VERSION, &garbage),
            Err(ShareFault::Malformed)
        ));
        assert!(matches!(
            inspect(SECRET_ID, VERSION + 1, &good[0]),
            Err(ShareFault::Malformed)
        ));
        let no_result = GetShareResponseMessage {
            result: None,
            ..good[0].clone()
        };
        assert!(matches!(
            inspect(SECRET_ID, VERSION, &no_result),
            Err(ShareFault::Malformed)
        ));
    }

    #[test]
    fn inspect_rejects_a_pre_0_0_9_layout_share_as_malformed() {
        let good = responses(b"payload", 2, 3);
        let mut committed =
            CommittedDeRecShare::decode(good[0].committed_de_rec_share.as_slice()).unwrap();
        committed.de_rec_share = pre_0_0_9_derec_share(SECRET_ID, VERSION);
        let old = GetShareResponseMessage {
            committed_de_rec_share: committed.encode_to_vec(),
            ..good[0].clone()
        };
        assert!(matches!(
            inspect(SECRET_ID, VERSION, &old),
            Err(ShareFault::Malformed)
        ));
    }

    /// A recoverable vault naming `name` as its only user secret and declaring
    /// `threshold`.
    fn vault(name: &str, threshold: Option<u32>) -> Secret {
        let mut secret = fixture_secret();
        secret.secrets.truncate(1);
        secret.secrets[0].name = name.to_owned();
        secret.threshold = threshold;
        secret
    }

    fn vault_bytes(name: &str, threshold: Option<u32>) -> Vec<u8> {
        encode_protect_wrapping(&vault(name, threshold))
    }

    fn names(set: &CandidateSet) -> Vec<&str> {
        set.candidates
            .iter()
            .map(|c| c.secret.secrets[0].name.as_str())
            .collect()
    }

    fn members(set: &CandidateSet) -> Vec<Vec<usize>> {
        set.candidates.iter().map(|c| c.members.clone()).collect()
    }

    fn collected(responses: &[&GetShareResponseMessage]) -> Vec<CollectedShare> {
        responses
            .iter()
            .enumerate()
            .map(|(i, r)| CollectedShare {
                channel_id: ChannelId(100 + i as u64),
                response: (*r).clone(),
            })
            .collect()
    }

    /// The share a single malicious helper builds: every subshare of its own
    /// threshold-2 split of `payload` in one share, under a Merkle root of its
    /// own whose path opens from that one leaf.
    fn forged_single_share(payload: &[u8]) -> GetShareResponseMessage {
        let parts = responses(payload, 2, 2);
        let decode = |r: &GetShareResponseMessage| {
            let committed =
                CommittedDeRecShare::decode(r.committed_de_rec_share.as_slice()).unwrap();
            let share = DeRecShare::decode(committed.de_rec_share.as_slice()).unwrap();
            (committed, share)
        };
        let (mut committed, mut share) = decode(&parts[0]);
        let (_, other) = decode(&parts[1]);
        share.subshares.extend(other.subshares);

        let mut leaf = vec![0x00];
        leaf.extend_from_slice(&(share.subshares.len() as u64).to_be_bytes());
        for subshare in &share.subshares {
            leaf.extend_from_slice(&(subshare.x.len() as u64).to_be_bytes());
            leaf.extend_from_slice(&subshare.x);
            leaf.extend_from_slice(&(subshare.y.len() as u64).to_be_bytes());
            leaf.extend_from_slice(&subshare.y);
        }
        let mut root = Sha256::digest(&leaf).to_vec();
        let depth = committed.merkle_path.len();
        committed.merkle_path = (0..depth)
            .map(|level| {
                let sibling = vec![level as u8; 32];
                let mut node = vec![0x02];
                node.extend_from_slice(&root);
                node.extend_from_slice(&sibling);
                root = Sha256::digest(&node).to_vec();
                SiblingHash {
                    is_left: false,
                    hash: sibling,
                }
            })
            .collect();
        committed.commitment = root;
        committed.de_rec_share = share.encode_to_vec();

        let forged = GetShareResponseMessage {
            committed_de_rec_share: committed.encode_to_vec(),
            ..parts[0].clone()
        };
        assert!(
            inspect(SECRET_ID, VERSION, &forged).is_ok(),
            "the forged share must pass every per-share check"
        );
        forged
    }

    fn assert_none(set: CandidateSet) {
        assert!(
            set.candidates.is_empty(),
            "no group may reconstruct: {:?}",
            names(&set)
        );
    }

    #[test]
    fn candidates_reconstruct_the_group_that_completes_and_leave_the_rest_out() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 3);
        let other = responses(&vault_bytes("other", Some(2)), 2, 3);
        let set = candidates(SECRET_ID, VERSION, &[&other[0], &good[0], &good[1]]);
        assert_eq!(names(&set), vec!["real"]);
        assert_eq!(members(&set), vec![vec![1, 2]]);
        assert!(set.faults.is_empty());
    }

    #[test]
    fn candidates_never_come_from_one_forged_share() {
        let forged = forged_single_share(&vault_bytes("forged", Some(2)));
        let set = candidates(SECRET_ID, VERSION, &[&forged]);
        assert_eq!(set.forged, vec![0]);
        assert_none(set);
    }

    #[test]
    fn candidates_ignore_a_forged_share_among_honest_ones_below_threshold() {
        let honest = responses(&vault_bytes("real", Some(3)), 3, 4);
        let forged = forged_single_share(&vault_bytes("forged", Some(2)));

        assert_none(candidates(
            SECRET_ID,
            VERSION,
            &[&honest[0], &forged, &honest[1]],
        ));

        let set = candidates(
            SECRET_ID,
            VERSION,
            &[&honest[0], &forged, &honest[1], &honest[2]],
        );
        assert_eq!(names(&set), vec!["real"]);
        assert_eq!(members(&set), vec![vec![0, 2, 3]]);
        assert_eq!(set.forged, vec![1]);
    }

    /// Two colluding helpers can still forge a complete split. Every group is
    /// tried, so the honest secret is found beside it rather than hidden by
    /// whichever reconstructs first.
    #[test]
    fn candidates_include_every_group_that_reconstructs() {
        let honest = responses(&vault_bytes("real", Some(2)), 2, 3);
        let forged = responses(&vault_bytes("forged", Some(2)), 2, 2);
        let set = candidates(
            SECRET_ID,
            VERSION,
            &[&forged[0], &honest[0], &forged[1], &honest[1], &honest[2]],
        );
        assert_eq!(names(&set), vec!["real", "forged"]);
        assert_eq!(members(&set), vec![vec![1, 3, 4], vec![0, 2]]);
    }

    #[test]
    fn candidates_mark_a_group_that_does_not_fit_its_declared_threshold_forged() {
        let lying = responses(&vault_bytes("lying", Some(3)), 2, 2);
        let set = candidates(SECRET_ID, VERSION, &[&lying[0], &lying[1]]);
        assert_eq!(set.forged, vec![0, 1]);
        assert_none(set);
    }

    #[test]
    fn candidates_accept_a_secret_that_records_no_threshold() {
        let good = responses(&vault_bytes("legacy", None), 2, 2);
        let set = candidates(SECRET_ID, VERSION, &[&good[0], &good[1]]);
        assert_eq!(names(&set), vec!["legacy"]);
    }

    #[test]
    fn candidates_mark_a_group_that_decrypts_to_undecodable_bytes_forged() {
        let garbage = responses(b"not a vault", 2, 2);
        let set = candidates(SECRET_ID, VERSION, &[&garbage[0], &garbage[1]]);
        assert_eq!(set.forged, vec![0, 1]);
        assert_none(set);
    }

    #[test]
    fn candidates_are_empty_while_no_group_completes() {
        let good = responses(&vault_bytes("real", Some(3)), 3, 4);
        let other = responses(&vault_bytes("other", Some(2)), 2, 3);
        assert_none(candidates(
            SECRET_ID,
            VERSION,
            &[&other[0], &good[0], &good[1]],
        ));
    }

    #[test]
    fn candidates_never_come_from_a_single_share() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 3);
        assert_none(candidates(SECRET_ID, VERSION, &[&good[0]]));
    }

    #[test]
    fn candidates_count_a_repeated_share_once() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 3);
        assert_none(candidates(SECRET_ID, VERSION, &[&good[0], &good[0]]));

        let set = candidates(SECRET_ID, VERSION, &[&good[0], &good[0], &good[1]]);
        assert_eq!(names(&set), vec!["real"]);
        assert_eq!(members(&set), vec![vec![0, 1, 2]]);
    }

    #[test]
    fn candidates_report_a_stored_share_that_no_longer_inspects() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 3);
        let garbage = GetShareResponseMessage {
            committed_de_rec_share: vec![0xFF; 8],
            ..good[0].clone()
        };
        let set = candidates(SECRET_ID, VERSION, &[&garbage, &good[1], &good[2]]);
        assert_eq!(names(&set), vec!["real"]);
        assert_eq!(set.faults, vec![(0, CorruptionReason::Malformed)]);
    }

    /// What `describe_helpers` would return for channels `100..100 + n`.
    fn named(n: usize) -> HashMap<ChannelId, HashMap<String, String>> {
        (0..n)
            .map(|i| {
                (
                    ChannelId(100 + i as u64),
                    HashMap::from([("name".to_owned(), format!("helper-{i}"))]),
                )
            })
            .collect()
    }

    fn names_of(helpers: &[RecoveryHelper]) -> Vec<&str> {
        helpers
            .iter()
            .map(|h| h.communication_info["name"].as_str())
            .collect()
    }

    #[test]
    fn settle_recovers_when_every_share_is_part_of_the_secret() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 3);
        let shares = collected(&[&good[0], &good[1], &good[2]]);

        match settle(SECRET_ID, VERSION, &shares, &named(3)).as_slice() {
            [DeRecEvent::SecretRecovered { secret }] => {
                assert_eq!(secret.secrets[0].name, "real")
            }
            other => panic!("expected SecretRecovered, got {other:?}"),
        }
    }

    /// Three colluding Helpers forge a complete split; the two honest ones
    /// are too few to reconstruct theirs. Size says nothing about which side
    /// is the owner's, so the secret is reported as disputed, naming both
    /// sides, and no Helper is reported as corrupted.
    #[test]
    fn settle_reports_a_secret_disputed_by_a_split_that_cannot_reconstruct() {
        let forged = responses(&vault_bytes("forged", Some(3)), 3, 3);
        let honest = responses(&vault_bytes("real", Some(3)), 3, 5);
        let shares = collected(&[&forged[0], &honest[0], &forged[1], &honest[1], &forged[2]]);

        match settle(SECRET_ID, VERSION, &shares, &named(5)).as_slice() {
            [
                DeRecEvent::RecoveryDisputed {
                    version: VERSION,
                    secret,
                    supported_by,
                    disputed_by,
                },
            ] => {
                assert_eq!(secret.secrets[0].name, "forged");
                assert_eq!(
                    names_of(supported_by),
                    vec!["helper-0", "helper-2", "helper-4"]
                );
                assert_eq!(names_of(disputed_by), vec!["helper-1", "helper-3"]);
            }
            other => panic!("expected RecoveryDisputed, got {other:?}"),
        }
    }

    #[test]
    fn settle_raises_a_conflict_when_two_secrets_reconstruct() {
        let honest = responses(&vault_bytes("real", Some(2)), 2, 3);
        let forged = responses(&vault_bytes("forged", Some(2)), 2, 2);
        let other = responses(&vault_bytes("other", Some(3)), 3, 3);
        let shares = collected(&[&forged[0], &honest[0], &forged[1], &honest[1], &other[0]]);

        match settle(SECRET_ID, VERSION, &shares, &named(5)).as_slice() {
            [
                DeRecEvent::RecoveryConflict {
                    version: VERSION,
                    candidates,
                    disputed_by,
                },
            ] => {
                let got: Vec<(&str, Vec<&str>)> = candidates
                    .iter()
                    .map(|c| (c.secret.secrets[0].name.as_str(), names_of(&c.supported_by)))
                    .collect();
                assert_eq!(
                    got,
                    vec![
                        ("forged", vec!["helper-0", "helper-2"]),
                        ("real", vec!["helper-1", "helper-3"]),
                    ]
                );
                assert_eq!(names_of(disputed_by), vec!["helper-4"]);
            }
            other => panic!("expected RecoveryConflict, got {other:?}"),
        }
    }

    /// One share that reconstructs on its own holds the whole split, which
    /// no honest Helper's weight allows: provably forged.
    #[test]
    fn settle_reports_a_single_share_that_reconstructs_alone_as_forged() {
        let good = responses(&vault_bytes("real", Some(2)), 2, 2);
        let forged = forged_single_share(&vault_bytes("forged", Some(2)));
        let shares = collected(&[&forged, &good[0], &good[1]]);

        match settle(SECRET_ID, VERSION, &shares, &named(3)).as_slice() {
            [
                DeRecEvent::RecoveryShareCorrupted {
                    channel_id,
                    version: VERSION,
                    reason: CorruptionReason::Forged,
                },
                DeRecEvent::SecretRecovered { secret },
            ] => {
                assert_eq!(*channel_id, ChannelId(100));
                assert_eq!(secret.secrets[0].name, "real");
            }
            other => panic!("expected Forged then SecretRecovered, got {other:?}"),
        }
    }

    #[test]
    fn settle_reports_a_group_that_reconstructs_no_secret_as_forged() {
        for bogus in [
            responses(b"not a vault", 2, 2),
            responses(&vault_bytes("lying", Some(3)), 2, 2),
        ] {
            let good = responses(&vault_bytes("real", Some(2)), 2, 2);
            let shares = collected(&[&bogus[0], &good[0], &bogus[1], &good[1]]);

            let events = settle(SECRET_ID, VERSION, &shares, &named(4));
            let forged: Vec<ChannelId> = events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::RecoveryShareCorrupted {
                        channel_id,
                        reason: CorruptionReason::Forged,
                        ..
                    } => Some(*channel_id),
                    _ => None,
                })
                .collect();
            assert_eq!(forged, vec![ChannelId(100), ChannelId(102)]);
            assert!(
                matches!(events.last(), Some(DeRecEvent::SecretRecovered { .. })),
                "a forged group does not dispute the honest secret: {events:?}"
            );
        }
    }

    #[test]
    fn settle_closes_incomplete_when_nothing_reconstructs() {
        let good = responses(&vault_bytes("real", Some(3)), 3, 4);
        let shares = collected(&[&good[0], &good[1]]);

        let events = settle(SECRET_ID, VERSION, &shares, &named(2));
        assert!(
            matches!(
                events.as_slice(),
                [DeRecEvent::RecoveryIncomplete {
                    secret_id: SECRET_ID,
                    version: VERSION,
                    shares_received: 2,
                }]
            ),
            "got {events:?}"
        );
    }

    #[test]
    fn settle_with_no_shares_is_incomplete() {
        assert!(matches!(
            settle(SECRET_ID, VERSION, &[], &HashMap::new()).as_slice(),
            [DeRecEvent::RecoveryIncomplete {
                secret_id: SECRET_ID,
                version: VERSION,
                shares_received: 0,
            }]
        ));
    }
}
