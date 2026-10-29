// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The one response every authenticated inbound request is owed.
//!
//! A request that decrypted under a channel key came from the peer that
//! channel names, so it can be answered, and it is answered exactly once.
//! An [`Obligation`] is built for each such request: in `handlers::handle`
//! once the body is known to be a request, and again from a persisted
//! [`PendingAction`] in `accept` and `reject`. Every response to that request,
//! success or failure, goes out through [`deliver`], which marks the request
//! answered *before* handing the response to the transport. A transport error
//! after that is reported, never followed by a second response.
//!
//! [`settle`] is the single place a failure is turned into what the
//! application sees:
//!
//! - already answered: [`DeRecEvent::RequestFailed`] with `responded: true`;
//! - `auto_respond_on_failure` on: the failure response is sent, then
//!   `responded: true`;
//! - off, or on with no reply target resolvable before any send attempt:
//!   `responded: false` with a [`Action::RespondToFailure`] the
//!   application passes to `reject`. No token is issued when `reject` could
//!   never answer it: no reply target can exist, or the channel whose key
//!   would encrypt the response has none stored.
//!
//! Exempt messages build no obligation and keep their behaviour: anything
//! that fails before decryption, an expired message (older than the
//! `inbound_message` window, which is the library's replay bound), every
//! response body, the pairing handshake, and a replica `UnpairRequest`, which
//! is a one-way notice.

use crate::derec_message::DeRecMessageBuilder;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::secret_store::SecretStoreExt as _;
use crate::protocol::DeRecTransport;
use crate::protocol::context::Local;
use crate::protocol::events::{
    Action, DeRecEvent, FailedRequest, PendingAction, PendingActionKind, ReplyTarget,
};
use crate::protocol::stores::{StoreSet, Stores};
use crate::transport::TransportPolicy;
use crate::types::{ChannelId, SharedKey};
use crate::{Error, Result};
use derec_proto::{MessageBody, StatusEnum, TransportProtocol};
use prost::Message as _;
use std::sync::Mutex;

/// The memo sent with a failure that has no protocol meaning of its own.
///
/// The local error text stays in the `message` of
/// [`DeRecEvent::RequestFailed`] and never reaches the wire.
pub(crate) const GENERIC_FAILURE_MEMO: &str = "request could not be processed";

/// The memo an authenticated message is answered with when its body could
/// not be decoded or is a request the channel cannot carry.
pub(crate) const UNDECODABLE_MEMO: &str = "message body could not be decoded";

/// One authenticated inbound request and the response it is owed.
pub(crate) struct Obligation {
    /// The channel the request arrived on.
    channel_id: ChannelId,
    trace_id: u64,
    request: FailedRequest,
    /// The request's `reply_to`, narrowed to what the transport policy allows.
    reply_to: Vec<TransportProtocol>,
    state: Mutex<State>,
}

struct State {
    /// The channel whose key encrypts the response.
    channel_id: ChannelId,
    /// That channel's key, when it is already known in memory. `None` loads
    /// it from the secret store at send time.
    key: Option<SharedKey>,
    /// The endpoints the response goes to, once a flow has named them.
    endpoints: Option<Vec<TransportProtocol>>,
    /// The status and memo of the response handed to the transport, once
    /// one was.
    sent: Option<(i32, String)>,
    /// The status and memo the request's failure carries a protocol meaning
    /// for, set by the flow that knows it. Unset means [`failure_status`]
    /// decides.
    known: Option<(StatusEnum, String)>,
    /// Events a flow reached before failing that the application must still
    /// see, such as a refusal whose answer could not be sent.
    carried: Vec<DeRecEvent>,
}

impl Obligation {
    fn new(
        channel_id: ChannelId,
        key: Option<SharedKey>,
        trace_id: u64,
        request: FailedRequest,
        policy: TransportPolicy,
    ) -> Self {
        let reply_to = crate::extensions::channel_store::filter_reply_to(
            policy,
            &requested_reply_to(&request),
        );
        Self {
            channel_id,
            trace_id,
            request,
            reply_to,
            state: Mutex::new(State {
                channel_id,
                key,
                endpoints: None,
                sent: None,
                known: None,
                carried: Vec::new(),
            }),
        }
    }

    /// The obligation a decrypted channel message carries, or `None` when the
    /// body is not a request owed a response.
    pub(crate) fn for_body(
        body: &MessageBody,
        channel_id: ChannelId,
        key: &SharedKey,
        trace_id: u64,
        policy: TransportPolicy,
    ) -> Option<Self> {
        let request = match body {
            MessageBody::StoreShareRequest(r) => FailedRequest::StoreShare(r.clone()),
            MessageBody::VerifyShareRequest(r) => FailedRequest::VerifyShare(r.clone()),
            MessageBody::GetSecretIdsVersionsRequest(r) => {
                FailedRequest::GetSecretIdsVersions(r.clone())
            }
            MessageBody::GetShareRequest(r) => FailedRequest::GetShare(r.clone()),
            MessageBody::UnpairRequest(r) if r.replica_id.is_none() => {
                FailedRequest::Unpair(r.clone())
            }
            MessageBody::UpdateChannelInfoRequest(r) => FailedRequest::UpdateChannelInfo(r.clone()),
            MessageBody::PairRequest(_) | MessageBody::PrePairRequest(_) => {
                FailedRequest::Undecodable
            }
            _ => return None,
        };
        Some(Self::new(
            channel_id,
            Some(key.clone()),
            trace_id,
            request,
            policy,
        ))
    }

    /// The obligation of a message that decrypted under the channel key but
    /// whose body could not be decoded. Like a request the channel cannot
    /// carry, it is answered on the channel's recorded endpoints, echoing the
    /// envelope's `trace_id`.
    pub(crate) fn undecodable(
        channel_id: ChannelId,
        key: &SharedKey,
        trace_id: u64,
        policy: TransportPolicy,
    ) -> Self {
        Self::new(
            channel_id,
            Some(key.clone()),
            trace_id,
            FailedRequest::Undecodable,
            policy,
        )
    }

    /// The obligation a persisted action still carries, or `None` for an
    /// action that answers no channel request: the pairing handshake, and a
    /// [`Action::RespondToFailure`], which only `reject` resolves.
    /// The action carries no key, so the response is encrypted under the
    /// channel's key, loaded when it is sent.
    pub(crate) fn for_action(action: &PendingAction, policy: TransportPolicy) -> Option<Self> {
        let Action::Request(request) = action.action() else {
            return None;
        };
        Some(Self::new(
            action.channel_id(),
            None,
            action.trace_id(),
            request.clone().into(),
            policy,
        ))
    }

    /// The obligation a [`Action::RespondToFailure`] token stands for.
    /// The key is loaded from `reply.channel_id` when the response is sent.
    pub(crate) fn for_failure(
        channel_id: ChannelId,
        trace_id: u64,
        reply: &ReplyTarget,
        request: FailedRequest,
        policy: TransportPolicy,
    ) -> Self {
        let obligation = Self::new(channel_id, None, trace_id, request, policy);
        {
            let mut state = obligation.lock();
            state.channel_id = reply.channel_id;
            if !reply.endpoints.is_empty() {
                state.endpoints = Some(reply.endpoints.clone());
            }
        }
        obligation
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The request type this obligation answers.
    pub(crate) fn kind(&self) -> PendingActionKind {
        request_kind(&self.request)
    }

    /// The response goes to the policy-filtered `reply_to` when the request
    /// carried one, otherwise to `fallback`.
    ///
    /// Used by the replica flows once the member that sent the request is
    /// known, so a group channel is never answered through a helper lookup.
    pub(crate) fn answer_at(&self, fallback: &[TransportProtocol]) {
        let endpoints = if self.reply_to.is_empty() {
            fallback.to_vec()
        } else {
            self.reply_to.clone()
        };
        self.lock().endpoints = Some(endpoints);
    }

    /// The response is encrypted for `channel_id` under `key` rather than for
    /// the channel the request arrived on.
    pub(crate) fn encrypt_for(&self, channel_id: ChannelId, key: SharedKey) {
        let mut state = self.lock();
        state.channel_id = channel_id;
        state.key = Some(key);
    }

    /// Record that a response with `status` and `memo` is being handed to
    /// the transport.
    ///
    /// `false` when one already was: the caller must not send.
    fn claim(&self, status: StatusEnum, memo: &str) -> bool {
        let mut state = self.lock();
        if state.sent.is_some() {
            return false;
        }
        state.sent = Some((status as i32, memo.to_owned()));
        true
    }

    /// Answer this request's failure with `status` and `memo` instead of the
    /// mapping [`failure_status`] applies: the failure is a protocol rule the
    /// request broke, and the peer is told which.
    pub(crate) fn fail_with(&self, status: StatusEnum, memo: &str) {
        self.lock().known = Some((status, memo.to_owned()));
    }

    /// A refusal whose answer failed before it was handed to the transport:
    /// the router answers with the refusal's own status and memo, and
    /// `event` is reported ahead of the failure.
    fn carry_refusal(&self, status: StatusEnum, memo: &str, event: DeRecEvent) {
        let mut state = self.lock();
        state.known = Some((status, memo.to_owned()));
        state.carried.push(event);
    }

    /// The status and memo of the response already handed to the
    /// transport, if any.
    pub(crate) fn answered(&self) -> Option<(i32, String)> {
        self.lock().sent.clone()
    }

    /// The failure of a request whose response, with `sent`'s status and
    /// memo, was already attempted.
    fn failed_after_answer(&self, (status, memo): (i32, String), error: &Error) -> DeRecEvent {
        request_failed(
            self.channel_id,
            self.kind(),
            true,
            status,
            &memo,
            error,
            None,
        )
    }

    /// Where the response goes, with the key that encrypts it.
    ///
    /// `None` when no reply target can exist: the request arrived on a
    /// replica group channel, names no member and carries no `reply_to`, so
    /// nothing identifies which member to answer. A group channel is never
    /// resolved through the helper-channel lookup.
    async fn resolve<S: StoreSet>(
        &self,
        stores: &mut Stores<'_, S>,
        local: &Local<'_>,
    ) -> Result<Option<Target>> {
        let (channel_id, key, endpoints) = {
            let state = self.lock();
            (state.channel_id, state.key.clone(), state.endpoints.clone())
        };
        let endpoints = match endpoints {
            Some(endpoints) if !endpoints.is_empty() => endpoints,
            _ if !self.reply_to.is_empty() => self.reply_to.clone(),
            // A member is answered on its own recorded endpoints, looked up
            // by the identity it named on the channel it wrote on — never
            // through a helper-channel lookup, which a group channel has no
            // row for.
            _ if let Some(author) = replica_author(&self.request) => {
                stores
                    .channels
                    .load_replica_member(local.secret_id, self.channel_id, author)
                    .await?
                    .transports
            }
            _ if self.arrived_on_group(stores, local).await? => return Ok(None),
            _ => {
                stores
                    .channels
                    .peer_endpoints(local.secret_id, channel_id)
                    .await?
            }
        };
        let key = match key {
            Some(key) => key,
            None => {
                stores
                    .secrets
                    .paired_key(local.secret_id, channel_id)
                    .await?
            }
        };
        Ok(Some((channel_id, endpoints, key)))
    }

    /// Whether the request arrived on a replica group channel.
    async fn arrived_on_group<S: StoreSet>(
        &self,
        stores: &mut Stores<'_, S>,
        local: &Local<'_>,
    ) -> Result<bool> {
        Ok(!stores
            .channels
            .replicas_on_channel(
                local.secret_id,
                self.channel_id,
                crate::protocol::types::ReplicaFilter::default(),
            )
            .await?
            .is_empty())
    }

    /// The target a token carries when none could be resolved: the channel
    /// and whatever endpoints are known. An empty list is resolved again
    /// when the token is rejected: the request's `reply_to`, then the
    /// sending member's recorded endpoints for a replica-bound request, or
    /// the channel's recorded endpoints for a helper-bound one.
    fn unresolved_target(&self) -> ReplyTarget {
        let state = self.lock();
        ReplyTarget {
            channel_id: state.channel_id,
            endpoints: state.endpoints.clone().unwrap_or_default(),
        }
    }
}

/// The channel whose key encrypts a response, the endpoints it goes to, and
/// that key.
type Target = (ChannelId, Vec<TransportProtocol>, SharedKey);

/// Hand `envelope` to the transport as the response `obligation` is owed.
/// `status` and `memo` are the result the envelope's response carries.
///
/// The request is marked answered first, so a transport error leaves it
/// answered. A request that already was is not sent again. Without an
/// obligation the envelope is sent as is.
pub(crate) async fn deliver<T: DeRecTransport>(
    obligation: Option<&Obligation>,
    transport: &T,
    endpoints: &[TransportProtocol],
    envelope: Vec<u8>,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    if let Some(obligation) = obligation
        && !obligation.claim(status, memo)
    {
        return Ok(());
    }
    transport.send(endpoints, envelope).await
}

/// Whether a response to `obligation` was handed to the transport.
pub(crate) fn attempted(obligation: Option<&Obligation>) -> bool {
    obligation.is_some_and(|o| o.answered().is_some())
}

/// The events of a flow whose response was attempted, with `outcome`'s
/// failure appended as answered.
///
/// A failure before any response was attempted is returned as is, for the
/// router to answer.
pub(crate) fn reported(
    obligation: Option<&Obligation>,
    mut events: Vec<DeRecEvent>,
    outcome: Result<()>,
) -> Result<Vec<DeRecEvent>> {
    match (
        outcome,
        obligation.and_then(|o| o.answered().map(|sent| (o, sent))),
    ) {
        (Ok(()), _) => Ok(events),
        (Err(error), Some((obligation, sent))) => {
            events.push(obligation.failed_after_answer(sent, &error));
            Ok(events)
        }
        (Err(error), None) => Err(error),
    }
}

/// The outcome of a refusal: `event` once its answer was handed to the
/// transport, with a later failure appended as answered.
///
/// A failure before that keeps the refusal: the router answers with
/// `status` and `memo` and reports `event` ahead of the failure, so the
/// application learns of the refusal either way.
pub(crate) fn refused(
    obligation: Option<&Obligation>,
    event: DeRecEvent,
    status: StatusEnum,
    memo: &str,
    outcome: Result<()>,
) -> Result<Vec<DeRecEvent>> {
    match (outcome, obligation) {
        (Ok(()), _) => Ok(vec![event]),
        (Err(error), Some(obligation)) if let Some(sent) = obligation.answered() => {
            Ok(vec![event, obligation.failed_after_answer(sent, &error)])
        }
        (Err(error), Some(obligation)) => {
            obligation.carry_refusal(status, memo, event);
            Err(error)
        }
        (Err(error), None) => Err(error),
    }
}

/// Turn a flow's outcome into the events the application sees, answering a
/// failure once.
///
/// Never fails: an answerable failure is reported as
/// [`DeRecEvent::RequestFailed`] inside the returned events.
pub(crate) async fn settle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    obligation: &Obligation,
    auto_respond_on_failure: bool,
    outcome: Result<Vec<DeRecEvent>>,
) -> Vec<DeRecEvent> {
    let error = match outcome {
        Ok(events) => return events,
        Err(error) => error,
    };
    let (known, mut events) = {
        let mut state = obligation.lock();
        (state.known.take(), std::mem::take(&mut state.carried))
    };
    if let Some(sent) = obligation.answered() {
        events.push(obligation.failed_after_answer(sent, &error));
        return events;
    }

    let (status, memo) = match (&known, &obligation.request) {
        (Some((status, memo)), _) => (*status, memo.as_str()),
        (None, FailedRequest::Undecodable) => (StatusEnum::FormatError, UNDECODABLE_MEMO),
        (None, _) => failure_status(&error),
    };
    let target = match obligation.resolve(stores, local).await {
        Ok(None) => {
            events.push(request_failed(
                obligation.channel_id,
                obligation.kind(),
                false,
                status as i32,
                memo,
                &error,
                None,
            ));
            return events;
        }
        Ok(Some(target)) => Ok(target),
        Err(error) => Err(error),
    };

    if auto_respond_on_failure && let Ok(target) = &target {
        let _sent = send_failure(stores, local, obligation, target, status, memo).await;
        if obligation.answered().is_some() {
            #[cfg(feature = "logging")]
            if let Err(send_error) = &_sent {
                tracing::warn!(
                    channel_id = obligation.channel_id.0,
                    error = %send_error,
                    "the failure response could not be delivered; it is not sent again"
                );
            }
            events.push(request_failed(
                obligation.channel_id,
                obligation.kind(),
                true,
                status as i32,
                memo,
                &error,
                None,
            ));
            return events;
        }
    }

    let reply = match target {
        Ok((channel_id, endpoints, _)) => ReplyTarget {
            channel_id,
            endpoints,
        },
        Err(_) => obligation.unresolved_target(),
    };
    // The token is sealed under the reply channel's key, which `reject` also
    // answers under: a channel whose key cannot be read could neither seal
    // the token nor answer it, so no token is issued.
    let token = match stores
        .secrets
        .shared_key(local.secret_id, reply.channel_id)
        .await
    {
        Ok(Some(key)) => Some(
            PendingAction::failure(
                obligation.channel_id,
                obligation.trace_id,
                reply,
                obligation.request.clone(),
            )
            .sealed_with(&key),
        ),
        Ok(None) | Err(_) => None,
    };
    events.push(request_failed(
        obligation.channel_id,
        obligation.kind(),
        false,
        status as i32,
        memo,
        &error,
        token,
    ));
    events
}

/// Answer the request `obligation` stands for with `status` and `memo`, using
/// that request type's own response.
pub(crate) async fn respond_to_failure<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    obligation: &Obligation,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let target = obligation
        .resolve(stores, local)
        .await?
        .ok_or(Error::InvalidInput(
            "the request names no member of the group channel it arrived on",
        ))?;
    send_failure(stores, local, obligation, &target, status, memo).await
}

async fn send_failure<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    obligation: &Obligation,
    (channel_id, endpoints, key): &Target,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    use crate::extensions::message_body::MessageBodyExt as _;

    let mut body = failure_body(local, &obligation.request, status, memo);
    let timestamp = crate::derec_message::current_timestamp();
    body.set_timestamp(timestamp);
    let envelope = DeRecMessageBuilder::channel()
        .channel_id(*channel_id)
        .timestamp(timestamp)
        .message_body(body)
        .trace_id(obligation.trace_id)
        .encrypt(key)?
        .build()?
        .encode_to_vec();
    deliver(
        Some(obligation),
        stores.transport,
        endpoints,
        envelope,
        status,
        memo,
    )
    .await
}

/// The response `request`'s type answers a failure with. A body that could
/// not be decoded or a request the channel cannot carry names no request
/// type the channel answers, so it is answered with an
/// `ErrorResponseMessage`.
fn failure_body(
    local: &Local<'_>,
    request: &FailedRequest,
    status: StatusEnum,
    memo: &str,
) -> MessageBody {
    use crate::protocol::handlers;
    match request {
        FailedRequest::StoreShare(r) => handlers::sharing::failure_response(local, r, status, memo),
        FailedRequest::VerifyShare(r) => handlers::verification::failure_response(r, status, memo),
        FailedRequest::GetSecretIdsVersions(r) => {
            handlers::discovery::failure_response(local, r, status, memo)
        }
        FailedRequest::GetShare(r) => handlers::recovery::failure_response(local, r, status, memo),
        FailedRequest::Unpair(_) => handlers::unpairing::failure_response(status, memo),
        FailedRequest::UpdateChannelInfo(_) => {
            handlers::update_channel_info::failure_response(status, memo)
        }
        FailedRequest::Undecodable => {
            MessageBody::ErrorResponse(derec_proto::ErrorResponseMessage {
                result: Some(derec_proto::DeRecResult {
                    status: status as i32,
                    memo: memo.to_owned(),
                }),
                timestamp: None,
            })
        }
    }
}

/// The status and memo a failure is answered with.
///
/// A failure with a protocol meaning keeps its own status and memo. Anything
/// else — a store backend, an internal invariant, a primitive — is `FAIL`
/// with [`GENERIC_FAILURE_MEMO`], so no local error text reaches the peer.
pub(crate) fn failure_status(error: &Error) -> (StatusEnum, &'static str) {
    match error {
        Error::RoleMismatch { .. } => (
            StatusEnum::Rejected,
            "the sender's role does not permit this request",
        ),
        Error::NoUsableEndpoint { .. } => (
            StatusEnum::UnsupportedTransportProtocol,
            "no transport endpoint in the request is supported",
        ),
        Error::Transport(_) => (
            StatusEnum::UnsupportedTransportProtocol,
            "a transport endpoint in the request was refused",
        ),
        _ => (StatusEnum::Fail, GENERIC_FAILURE_MEMO),
    }
}

/// A [`DeRecEvent::RequestFailed`] for `error`, answered (or to be
/// answered) with `status` and `memo`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn request_failed(
    channel_id: ChannelId,
    kind: PendingActionKind,
    responded: bool,
    status: i32,
    memo: &str,
    error: &Error,
    action: Option<PendingAction>,
) -> DeRecEvent {
    DeRecEvent::RequestFailed {
        channel_id,
        action_kind: kind,
        responded,
        status,
        memo: memo.to_owned(),
        error_code: crate::error_codes::classify(error).1.name().to_owned(),
        message: error.to_string(),
        action,
    }
}

fn request_kind(request: &FailedRequest) -> PendingActionKind {
    match request {
        FailedRequest::StoreShare(_) => PendingActionKind::StoreShare,
        FailedRequest::VerifyShare(_) => PendingActionKind::VerifyShare,
        FailedRequest::GetSecretIdsVersions(_) => PendingActionKind::Discovery,
        FailedRequest::GetShare(_) => PendingActionKind::GetShare,
        FailedRequest::Unpair(_) => PendingActionKind::Unpair,
        FailedRequest::UpdateChannelInfo(_) => PendingActionKind::UpdateChannelInfo,
        FailedRequest::Undecodable => PendingActionKind::Failed,
    }
}

/// The member that sent a replica-bound request, which is answered on that
/// member's own endpoints and never through a helper-channel lookup.
fn replica_author(request: &FailedRequest) -> Option<u64> {
    match request {
        FailedRequest::StoreShare(r) => r.replica_id,
        FailedRequest::GetSecretIdsVersions(r) => r.replica_id,
        FailedRequest::GetShare(r) => r.replica_id,
        // A replica `UnpairRequest` is a one-way notice and builds no
        // obligation, so an unpair here is always helper-bound.
        FailedRequest::Unpair(_)
        | FailedRequest::VerifyShare(_)
        | FailedRequest::UpdateChannelInfo(_)
        | FailedRequest::Undecodable => None,
    }
}

fn requested_reply_to(request: &FailedRequest) -> Vec<TransportProtocol> {
    use crate::extensions::advertised_endpoints::reply_to_owned;
    match request {
        FailedRequest::StoreShare(r) => reply_to_owned(r),
        FailedRequest::VerifyShare(r) => reply_to_owned(r),
        FailedRequest::GetSecretIdsVersions(r) => reply_to_owned(r),
        FailedRequest::GetShare(r) => reply_to_owned(r),
        FailedRequest::Unpair(r) => reply_to_owned(r),
        FailedRequest::UpdateChannelInfo(_) | FailedRequest::Undecodable => Vec::new(),
    }
}
