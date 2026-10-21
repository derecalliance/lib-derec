// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Typestate builder for [`DeRecProtocol`]. See [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder).
//!
//! Each store/transport slot is tracked by its own type parameter, starting
//! at [`BuilderSlotMissingMarker`] and transitioning to
//! [`BuilderSlotSetMarker<T>`] when its `with_*` setter runs. Setters only
//! touch their own slot, which is what makes call order irrelevant — and,
//! for the five store slots, what makes a setter safe to call again later:
//! it replaces whatever was in its own slot (whether that was still
//! [`BuilderSlotMissingMarker`] or already a [`BuilderSlotSetMarker<_>`]
//! from an earlier call, including [`DeRecProtocolBuilder::with_stores`])
//! without disturbing the other four.
//! [`DeRecProtocolBuilder::build`](crate::protocol::DeRecProtocolBuilder::build) is reachable only when every slot has
//! reached [`BuilderSlotSetMarker<_>`].
//!
//! The six slots are the five stores and the [`DeRecTransport`]. This
//! device's own transport endpoints are not a slot: like every other data
//! setting they are an ordinary value, settable through
//! [`DeRecProtocolBuilder::with_own_transports`] or
//! [`DeRecProtocolBuilder::with_config`], and `build` refuses a builder that
//! has none.

use std::collections::HashMap;
use std::time::Duration;

use super::{
    DeRecChannelStore, DeRecProtocol, DeRecProtocolConfig, DeRecSecretStore, DeRecShareStore,
    DeRecStateStore, DeRecTransport, DeRecUserSecretStore, UnpairAck,
};
use derec_proto::TransportProtocol;

pub struct BuilderSlotMissingMarker;

pub struct BuilderSlotSetMarker<T>(T);

/// The five stores [`DeRecProtocolBuilder::build`] requires, bundled for
/// [`DeRecProtocolBuilder::with_stores`].
///
/// Each field matches the store its corresponding `with_*_store` setter
/// takes: `channels` is [`with_channel_store`](DeRecProtocolBuilder::with_channel_store),
/// `shares` is [`with_share_store`](DeRecProtocolBuilder::with_share_store),
/// `secrets` is [`with_secret_store`](DeRecProtocolBuilder::with_secret_store),
/// `user_secrets` is [`with_user_secret_store`](DeRecProtocolBuilder::with_user_secret_store),
/// and `state` is [`with_state_store`](DeRecProtocolBuilder::with_state_store).
pub struct DeRecStores<Cs, Sh, Ss, Us, St> {
    pub channels: Cs,
    pub shares: Sh,
    pub secrets: Ss,
    pub user_secrets: Us,
    pub state: St,
}

/// Minimum number of shares required to reconstruct the secret, absent an
/// explicit [`DeRecProtocolBuilder::with_threshold`](crate::protocol::DeRecProtocolBuilder::with_threshold) call. This is the sole
/// definition of the value — [`DeRecProtocolBuilder::new`](crate::protocol::DeRecProtocolBuilder::new) and the FFI
/// config's serde default both read it rather than each hardcoding `3`.
pub const DEFAULT_THRESHOLD: usize = 3;

/// Typestate builder for [`DeRecProtocol`].
///
/// Call each store/transport setter, then [`build`](DeRecProtocolBuilder::build).
/// The "every store and the transport are set" constraint is enforced at
/// compile time by the impl-block bounds — calling `build()` without one is a
/// type error, not a runtime panic. Every data setting, including the
/// required own transports, is an ordinary value checked by `build()` at run
/// time, so it can also arrive through [`with_config`](DeRecProtocolBuilder::with_config).
///
/// Setters may be called in any order.
///
/// # Example
///
/// The store types are yours to supply, so this cannot be a compiled example:
///
/// ```text
/// let protocol = DeRecProtocolBuilder::new(secret_id)
///     .with_channel_store(my_channel_store)
///     .with_share_store(my_share_store)
///     .with_secret_store(my_secret_store)
///     .with_user_secret_store(my_user_secret_store)
///     .with_state_store(my_state_store)
///     .with_transport(my_transport)
///     .with_own_transports(["https://me.example.com"])
///     // Plus any optional with_* setters to override defaults.
///     .build()?;
/// ```
///
/// The five store setters can be replaced by one
/// [`with_stores`](DeRecProtocolBuilder::with_stores) call taking a
/// [`DeRecStores`] bundle.
pub struct DeRecProtocolBuilder<
    ChannelStore,
    ShareStore,
    SecretStore,
    UserSecretStore,
    StateStore,
    Transport,
> {
    secret_id: u64,
    channel_store: ChannelStore,
    share_store: ShareStore,
    secret_store: SecretStore,
    user_secret_store: UserSecretStore,
    state_store: StateStore,
    transport: Transport,
    own_transports: Option<
        Result<
            Vec<crate::transport::TransportProtocol>,
            crate::transport::TransportValidationError,
        >,
    >,
    threshold: usize,
    timeouts: crate::protocol::types::Timeouts,
    unsafe_connection: Option<bool>,
    communication_info: HashMap<String, String>,
    auto_respond_on_failure: bool,
    unpair_ack: UnpairAck,
    auto_reply_to: bool,
    auto_accept: crate::protocol::AutoAcceptPolicy,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
    max_subshares: Option<u64>,
}

impl
    DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
    >
{
    /// Construct a new builder bound to a specific secret.
    ///
    /// `secret_id` identifies the single secret this protocol instance
    /// manages. Apps that juggle multiple secrets instantiate one
    /// [`DeRecProtocol`] per `secret_id`.
    pub fn new(secret_id: u64) -> Self {
        Self {
            secret_id,
            channel_store: BuilderSlotMissingMarker,
            share_store: BuilderSlotMissingMarker,
            secret_store: BuilderSlotMissingMarker,
            user_secret_store: BuilderSlotMissingMarker,
            state_store: BuilderSlotMissingMarker,
            transport: BuilderSlotMissingMarker,
            own_transports: None,
            threshold: DEFAULT_THRESHOLD,
            timeouts: crate::protocol::types::Timeouts::default(),
            unsafe_connection: None,
            communication_info: HashMap::new(),
            auto_respond_on_failure: false,
            unpair_ack: UnpairAck::Required,
            auto_reply_to: false,
            auto_accept: crate::protocol::AutoAcceptPolicy::default(),
            replica_id: None,
            parameter_range: None,
            max_subshares: None,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Minimum number of subshares required to reconstruct the secret.
    ///
    /// A Helper holds one subshare unless
    /// [`DeRecFlow::ProtectSecret`](crate::protocol::DeRecFlow::ProtectSecret)
    /// gives it a weight, so with no weights this is the number of Helpers,
    /// as before. Every weight must be below this threshold, so no single
    /// Helper can recover alone.
    ///
    /// Large subshare totals are costly to recover: reconstruction time grows
    /// quadratically with the total number of subshares. See
    /// [`with_max_subshares`](Self::with_max_subshares) for the cost and the
    /// cap that bounds it.
    ///
    /// Default: [`DEFAULT_THRESHOLD`]. This setter is infallible — invariant checks run
    /// at [`build`](Self::build) time and surface a structured
    /// [`crate::Error`] so callers can handle invalid configurations
    /// uniformly across SDKs (FFI / WASM bindings translate that error
    /// into their native shape rather than seeing a panic propagate
    /// across the language boundary).
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    /// Upper bound on the total subshares of a sharing round.
    ///
    /// A round's total is the sum of every paired Helper's weight (one per
    /// Helper not given a weight by
    /// [`DeRecFlow::ProtectSecret`](crate::protocol::DeRecFlow::ProtectSecret)).
    /// Splitting stays cheap at any total, but reconstruction time grows
    /// quadratically with it — measured in release mode on a laptop, about
    /// 0.2 s at 200 subshares, 5.5 s at 1,000 and 87 s at 4,000, per
    /// recovery attempt. Nothing at sharing time reveals that cost, so this
    /// cap is where an application bounds it.
    ///
    /// When set, a `ProtectSecret` round whose total exceeds `max` fails with
    /// [`SharingError::TooManySubshares`](crate::primitives::sharing::SharingError::TooManySubshares)
    /// before a version is chosen: nothing is sent and no version is
    /// consumed. Publishes the library starts on its own (after a pairing
    /// completes or a fingerprint is confirmed) give every Helper one
    /// subshare, so their total is the Helper count, and they are bounded
    /// the same way.
    ///
    /// Recovery applies no cap: a recovering device cannot know the cap the
    /// secret was shared under, and a lower one could leave it unrecoverable.
    ///
    /// Default: no cap. `max` must be at least the
    /// [`threshold`](Self::with_threshold) — a lower cap could never be met
    /// by a round that splits — and [`build`](Self::build) rejects it
    /// otherwise.
    pub fn with_max_subshares(mut self, max: u64) -> Self {
        self.max_subshares = Some(max);
        self
    }

    /// Configure how long the protocol waits on each thing that can keep it
    /// waiting.
    ///
    /// One call sets all four; anything left unspecified keeps its default:
    ///
    /// ```no_run
    /// # use derec_library::protocol::types::Timeouts;
    /// # use std::time::Duration;
    /// # let builder = derec_library::protocol::DeRecProtocolBuilder::new(1);
    /// builder.with_timeouts(Timeouts {
    ///     sharing_round: Duration::from_secs(30),
    ///     ..Default::default()
    /// })
    /// # ;
    /// ```
    ///
    /// These used to be a single knob, which forced a bad trade: shortening
    /// the sharing round to make a stalled publish surface sooner also
    /// narrowed the replay window every inbound message is judged against.
    /// [`Timeouts::inbound_message`](crate::protocol::types::Timeouts::inbound_message)
    /// is a security boundary and the other
    /// three are liveness budgets; they are configured separately because
    /// they answer different questions. See
    /// [`Timeouts`](crate::protocol::types::Timeouts) for what each one
    /// governs and how to choose it.
    ///
    /// Every value is clamped to at least one second — this is the single
    /// normalization point, so the clamp applies however the value was
    /// constructed.
    pub fn with_timeouts(mut self, timeouts: crate::protocol::types::Timeouts) -> Self {
        let secs = |d: Duration| d.as_secs().max(1);
        self.timeouts = crate::protocol::types::Timeouts {
            inbound_message: Duration::from_secs(secs(timeouts.inbound_message)),
            sharing_round: Duration::from_secs(secs(timeouts.sharing_round)),
            unpair_ack: Duration::from_secs(secs(timeouts.unpair_ack)),
            expired_channels: match timeouts.expired_channels {
                crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs } => {
                    crate::protocol::ExpiredChannelCleanup::Enabled {
                        timeout_in_secs: timeout_in_secs.max(1),
                    }
                }
                crate::protocol::ExpiredChannelCleanup::Disabled => {
                    crate::protocol::ExpiredChannelCleanup::Disabled
                }
            },
        };
        self
    }

    /// Accept plaintext transport endpoints — `http://` and `grpc://`.
    /// **Development only.**
    ///
    /// Default: `false`, which is the production posture.
    ///
    /// # What it changes
    ///
    /// With it `false`, plaintext is accepted in exactly one situation: an
    /// endpoint **this device configured for itself** that names loopback
    /// (`localhost`, `127.0.0.1`, `::1`). That covers running a dev server on
    /// your own machine with no configuration at all.
    ///
    /// With it `true`, plaintext is accepted for **any host, on any path** —
    /// this device's own endpoint and any endpoint a peer supplies, including
    /// public hosts. That is what makes it usable for the case it exists for:
    /// testing a phone against a laptop across a LAN, where neither side is
    /// loopback. It is also why the name is blunt.
    ///
    /// See [`TransportPolicy`](crate::transport::TransportPolicy) for the
    /// full table, including why loopback is free for your own endpoint but
    /// not for one a peer names.
    ///
    /// # This is a guardrail, not transport security
    ///
    /// The SDK opens no sockets — delivery is the application's
    /// [`DeRecTransport`](crate::protocol::DeRecTransport). Nothing here can
    /// stop an application sending plaintext; what it does is refuse to
    /// record, propagate or reply to a plaintext endpoint. Leaving it `false`
    /// does not make a deployment secure on its own, and setting it `true`
    /// does not by itself send anything in the clear.
    pub fn with_unsafe_connection(mut self, allow: bool) -> Self {
        self.unsafe_connection = Some(allow);
        self
    }

    /// Key-value pairs included in `CommunicationInfo` within pairing request
    /// and response messages (e.g. `"name"`, `"email"`, `"phone"`).
    ///
    /// Default: empty.
    pub fn with_communication_info(mut self, info: HashMap<String, String>) -> Self {
        self.communication_info = info;
        self
    }

    /// Whether the protocol replies to peers on inbound processing failures.
    ///
    /// - `true`: when an inbound request fails after it was decrypted, the
    ///   protocol also sends the peer a response with a non-`Ok` status
    ///   (`FORMAT_ERROR` for a decode failure, `REJECTED` for a role mismatch,
    ///   `UNSUPPORTED_TRANSPORT_PROTOCOL` when no endpoint is usable, `FAIL`
    ///   otherwise). [`DeRecProtocol::process`] still returns the error.
    /// - `false`: the failure is only returned from
    ///   [`DeRecProtocol::process`] and nothing is sent — the application
    ///   decides how to respond.
    ///
    /// A message that fails to decrypt is never answered: it carries no proof
    /// of who sent it, and replying would make this device a decryption
    /// oracle. The reply is best effort; failing to send it does not replace
    /// the original error.
    ///
    /// Default: `false`.
    pub fn with_auto_respond_on_failure(mut self, enabled: bool) -> Self {
        self.auto_respond_on_failure = enabled;
        self
    }

    /// Whether the unpair initiator waits for the peer's acknowledgement
    /// before dropping local state.
    ///
    /// - [`UnpairAck::Required`]: keep state until the peer responds with `Ok`,
    ///   or until the timeout configured via [`Self::with_timeouts`] elapses.
    /// - [`UnpairAck::NotRequired`]: drop state immediately after sending the
    ///   request; any later response is silently ignored.
    ///
    /// Default: [`UnpairAck::Required`].
    pub fn with_unpair_ack(mut self, ack: UnpairAck) -> Self {
        self.unpair_ack = ack;
        self
    }

    /// Whether outbound requests carry `replyToTransports` set to this
    /// node's own transport endpoints.
    ///
    /// - `true`: every outbound request stamps `replyToTransports` with the
    ///   current own transports (see [`Self::with_own_transports`]). The
    ///   responder routes its response to those endpoints, ignoring the
    ///   channel's stored peer endpoints. Useful when two peers share a
    ///   channel record but reach out from different endpoints (e.g. replicas
    ///   talking to a helper that was paired with a sibling replica) — without
    ///   this, the responder would reply to the sibling.
    /// - `false`: outbound requests leave `replyToTransports` empty. The
    ///   responder routes to the channel's stored endpoints, which is correct
    ///   for the single-device case.
    ///
    /// Only affects outbound requests originated through
    /// [`DeRecProtocol::start`], and only on channel-mode flows: pairing
    /// carries its endpoints in its own `supportedTransports` field and is
    /// unaffected. Responders always honour an inbound `replyToTransports`
    /// regardless of this flag (it is purely a per-request hint on the wire).
    ///
    /// Default: `false`.
    pub fn with_auto_reply_to(mut self, enabled: bool) -> Self {
        self.auto_reply_to = enabled;
        self
    }

    /// Per-flow opt-in for auto-accepting inbound requests.
    ///
    /// When a flow's field on the policy is `true`,
    /// [`DeRecProtocol::process`] internally runs the equivalent of
    /// [`DeRecProtocol::accept`] for that flow and emits
    /// [`crate::protocol::DeRecEvent::AutoAccepted`] in place of
    /// [`crate::protocol::DeRecEvent::ActionRequired`] (followed in
    /// the same event vec by the flow's completion events).
    ///
    /// Default: [`crate::protocol::AutoAcceptPolicy::default()`] —
    /// every field `false`, behaviour identical to today's
    /// `ActionRequired` flow. See the field-level docs on
    /// [`crate::protocol::AutoAcceptPolicy`] for the per-flow trade-offs.
    pub fn with_auto_accept(mut self, policy: crate::protocol::AutoAcceptPolicy) -> Self {
        self.auto_accept = policy;
        self
    }

    /// Configure this node's local **replica identity**.
    ///
    /// Required to participate in any replica-mode pairing — when set, the
    /// orchestrator auto-injects the id (decimal-encoded) under the reserved key
    /// `derec.replica_id` in outbound `PairRequest` / `PairResponse`
    /// envelopes whose `sender_kind` is `ReplicaSource` or
    /// `ReplicaDestination`, and accepts inbound replica pairings that
    /// advertise the peer's id under the same key.
    ///
    /// Apps that do not use replica flows simply do not call this setter.
    /// With no replica id configured, the orchestrator rejects every
    /// replica-mode entry point with
    /// [`Error::ReplicaIdNotConfigured`](crate::Error::ReplicaIdNotConfigured);
    /// `Owner` and `Helper` pairings are unaffected.
    ///
    /// The id must be **stable across restarts** — persist it on the device
    /// once and pass the same value on every protocol init. Use
    /// [`crate::generate_replica_id`] to mint a fresh one with the OS CSPRNG.
    ///
    /// Default: unset (replica flows disabled).
    pub fn with_replica_id(mut self, id: u64) -> Self {
        self.replica_id = Some(id);
        self
    }

    /// Declare the local node's acceptable [`ParameterRange`](derec_proto::ParameterRange)
    /// for pair negotiation.
    ///
    /// Embedded in outbound `PairRequest` / `PairResponse` envelopes and
    /// checked against the peer's range on inbound ones: if any field's
    /// range fails to intersect (e.g. local `minShareSize` exceeds a non-zero
    /// peer `maxShareSize`), or the peer's range is malformed, the pairing is
    /// rejected with
    /// [`Error::Pairing(PairingError::IncompatibleParameterRange { .. })`](crate::Error::Pairing).
    ///
    /// A field value of `0` means "no bound", on both sides: `min == 0` is no
    /// minimum and `max == 0` is no maximum, so a `max` of `0` overlaps any
    /// `min`. Each field's `min` and `max` must be `>= 0`, and when
    /// `max != 0`, `min <= max`. A local range breaking either rule is
    /// rejected by [`build`](DeRecProtocolBuilder::build) with
    /// [`Error::InvalidInput`](crate::Error::InvalidInput) naming the field.
    ///
    /// Default: unset — the local side advertises no constraints and
    /// accepts any peer range.
    ///
    /// # Enforcement
    ///
    /// Negotiating a range is not the same as enforcing it; what happens
    /// after pairing differs by field:
    ///
    /// - `minShareSize`/`maxShareSize`: enforced by the library itself, on
    ///   helper channels only. Every inbound `StoreShareRequest` has its
    ///   `share` length checked against this device's own range before
    ///   `ActionRequired` is raised or auto-accept runs; an out-of-range
    ///   share is refused with `SIZE_LIMIT_EXCEEDED` and never reaches the
    ///   application.
    /// - `minTimeBetweenShareUpdates`/`maxTimeBetweenShareUpdates` and
    ///   `minTimeBetweenVerifications`/`maxTimeBetweenVerifications`: only
    ///   negotiated here. Enforcing them is the application's
    ///   responsibility, through its [`DeRecShareStore`](super::DeRecShareStore)
    ///   — returning
    ///   [`ShareStoreError::Refused`](super::error::ShareStoreError::Refused)
    ///   from [`DeRecShareStore::save`](super::DeRecShareStore::save) or
    ///   [`DeRecShareStore::record_verification`](super::DeRecShareStore::record_verification)
    ///   turns the application's refusal into the matching status for the
    ///   owner. The library never stores timestamps itself.
    /// - the unresponsive deletion/deactivation timeout fields: negotiated
    ///   only; the library enforces nothing from them.
    pub fn with_parameter_range(mut self, range: derec_proto::ParameterRange) -> Self {
        self.parameter_range = Some(range);
        self
    }

    /// Set every transport endpoint this application serves, in preference
    /// order. Required: [`build`](Self::build) refuses a builder on which
    /// neither this nor [`with_config`](Self::with_config) set any.
    ///
    /// The order is meaningful: peers record these endpoints in this order,
    /// and their transport receives them in it, so it is the order in which
    /// they try to reach this device (the default
    /// [`SequentialFailover`](crate::protocol::SequentialFailover) tries them
    /// in turn). The library itself does not rank endpoints. The first entry
    /// is also this device's primary endpoint.
    ///
    /// Because delivery is push-only, an endpoint listed here is one this
    /// application must actually **serve** — a peer can only reply to an
    /// address it can reach. Listing a transport that is not served makes
    /// pairing succeed and replies vanish.
    ///
    /// Calling this again replaces the earlier list. The list must be
    /// non-empty — [`build`](Self::build) rejects an empty one with
    /// [`crate::Error::InvalidInput`].
    pub fn with_own_transports<I, T>(mut self, transports: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: crate::transport::IntoOwnTransport,
    {
        // Stash the fallible conversion, surface failures from `.build()`,
        // keep the setter chain infallible.
        self.own_transports = Some(
            transports
                .into_iter()
                .map(crate::transport::IntoOwnTransport::into_own_transport)
                .collect(),
        );
        self
    }

    /// Apply every setting a [`DeRecProtocolConfig`] carries.
    ///
    /// Each field that is set is applied through its own `with_*` setter, so
    /// it behaves exactly as calling that setter would. A field left unset
    /// leaves whatever the builder already holds — a default, an earlier
    /// `with_config`, or an earlier setter — untouched.
    ///
    /// # Layering
    ///
    /// Settings are applied in call order and the last write wins, per
    /// field. The intended order is a general config (from the environment
    /// or a config file), then a per-user config (from a user record), then
    /// any individual `with_*` calls:
    ///
    /// ```
    /// use derec_library::protocol::{DeRecProtocolBuilder, DeRecProtocolConfig, TimeoutsConfig};
    ///
    /// let general = DeRecProtocolConfig {
    ///     threshold: Some(3),
    ///     timeouts: Some(TimeoutsConfig {
    ///         sharing_round_secs: Some(30),
    ///         ..Default::default()
    ///     }),
    ///     ..Default::default()
    /// };
    /// let per_user = DeRecProtocolConfig {
    ///     threshold: Some(4),
    ///     timeouts: Some(TimeoutsConfig {
    ///         inbound_message_secs: Some(120),
    ///         ..Default::default()
    ///     }),
    ///     ..Default::default()
    /// };
    /// // Threshold ends at 5; the sharing round stays at 30 seconds and
    /// // the inbound-message window becomes 120 seconds.
    /// let builder = DeRecProtocolBuilder::new(1)
    ///     .with_config(general)
    ///     .with_config(per_user)
    ///     .with_threshold(5);
    /// # let _ = builder;
    /// ```
    ///
    /// Every nested object replaces the builder's value as a whole, except
    /// `timeouts`: each of its fields is merged separately against the
    /// timeouts the builder currently holds, so a later config that sets
    /// only one timeout keeps the others an earlier call set.
    ///
    /// # Validation
    ///
    /// Nothing is checked here. [`build`](Self::build) validates the result
    /// with the same rules whichever way a value was set.
    pub fn with_config(mut self, config: DeRecProtocolConfig) -> Self {
        let DeRecProtocolConfig {
            threshold,
            max_subshares,
            timeouts,
            parameter_range,
            auto_accept,
            auto_respond_on_failure,
            auto_reply_to,
            unpair_ack,
            unsafe_connection,
            communication_info,
            own_transports,
            replica_id,
        } = config;
        if let Some(threshold) = threshold {
            self = self.with_threshold(threshold);
        }
        if let Some(max) = max_subshares {
            self = self.with_max_subshares(max);
        }
        if let Some(timeouts) = timeouts {
            let merged = timeouts.merged_onto(self.timeouts);
            self = self.with_timeouts(merged);
        }
        if let Some(range) = parameter_range {
            self = self.with_parameter_range(range);
        }
        if let Some(policy) = auto_accept {
            self = self.with_auto_accept(policy);
        }
        if let Some(enabled) = auto_respond_on_failure {
            self = self.with_auto_respond_on_failure(enabled);
        }
        if let Some(enabled) = auto_reply_to {
            self = self.with_auto_reply_to(enabled);
        }
        if let Some(ack) = unpair_ack {
            self = self.with_unpair_ack(ack);
        }
        if let Some(allow) = unsafe_connection {
            self = self.with_unsafe_connection(allow);
        }
        if let Some(info) = communication_info {
            self = self.with_communication_info(info);
        }
        if let Some(transports) = own_transports {
            self = self.with_own_transports(transports);
        }
        if let Some(id) = replica_id {
            self = self.with_replica_id(id);
        }
        self
    }

    /// Set every store in one call.
    ///
    /// Equivalent to calling [`with_channel_store`](Self::with_channel_store),
    /// [`with_share_store`](Self::with_share_store),
    /// [`with_secret_store`](Self::with_secret_store),
    /// [`with_user_secret_store`](Self::with_user_secret_store) and
    /// [`with_state_store`](Self::with_state_store) in turn — it reuses them
    /// rather than assigning the five slots itself, so the two paths can
    /// never disagree about what a store setter does.
    ///
    /// Each of those setters only ever touches its own slot, so calling one
    /// of them again afterwards — on the result of `with_stores` or of
    /// another setter — replaces just that store and leaves the other four
    /// as they were. Likewise, `with_stores` replaces any store set by an
    /// earlier call:
    ///
    /// ```text
    /// let protocol = DeRecProtocolBuilder::new(secret_id)
    ///     .with_stores(DeRecStores {
    ///         channels: my_channel_store,
    ///         shares: my_share_store,
    ///         secrets: my_secret_store,
    ///         user_secrets: my_user_secret_store,
    ///         state: my_state_store,
    ///     })
    ///     // Overrides only the share store set above.
    ///     .with_share_store(a_different_share_store)
    ///     .with_transport(my_transport)
    ///     .with_own_transports(["https://me.example.com"])
    ///     .build()?;
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn with_stores<Cs, Sh, Ss, Us, St>(
        self,
        stores: DeRecStores<Cs, Sh, Ss, Us, St>,
    ) -> DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        BuilderSlotSetMarker<Sh>,
        BuilderSlotSetMarker<Ss>,
        BuilderSlotSetMarker<Us>,
        BuilderSlotSetMarker<St>,
        Transport,
    >
    where
        Cs: DeRecChannelStore,
        Sh: DeRecShareStore,
        Ss: DeRecSecretStore,
        Us: DeRecUserSecretStore,
        St: DeRecStateStore,
    {
        self.with_channel_store(stores.channels)
            .with_share_store(stores.shares)
            .with_secret_store(stores.secrets)
            .with_user_secret_store(stores.user_secrets)
            .with_state_store(stores.state)
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Set the [`DeRecChannelStore`] implementation responsible for persisting
    /// channel records.
    ///
    /// Calling this again later — including after
    /// [`with_stores`](Self::with_stores) — replaces the channel store the
    /// prior call set, without touching any other slot.
    pub fn with_channel_store<Cs: DeRecChannelStore>(
        self,
        store: Cs,
    ) -> DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: BuilderSlotSetMarker(store),
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Set the [`DeRecShareStore`] implementation responsible for persisting
    /// secret shares.
    ///
    /// Calling this again later — including after
    /// [`with_stores`](Self::with_stores) — replaces the share store the
    /// prior call set, without touching any other slot.
    pub fn with_share_store<Sh: DeRecShareStore>(
        self,
        store: Sh,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        BuilderSlotSetMarker<Sh>,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: BuilderSlotSetMarker(store),
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Set the [`DeRecSecretStore`] implementation responsible for persisting
    /// per-channel key material (pairing secrets, shared keys, pairing contacts).
    ///
    /// Calling this again later — including after
    /// [`with_stores`](Self::with_stores) — replaces the secret store the
    /// prior call set, without touching any other slot.
    pub fn with_secret_store<Ss: DeRecSecretStore>(
        self,
        store: Ss,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        BuilderSlotSetMarker<Ss>,
        UserSecretStore,
        StateStore,
        Transport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: BuilderSlotSetMarker(store),
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Set the [`DeRecUserSecretStore`] implementation responsible for
    /// persisting the user-facing secret contents keyed by `secret_id`.
    /// Written on every `start(FlowKind::ProtectSecret)`; read by the
    /// pair-completion auto-publish hook so freshly-paired peers
    /// receive the current secret without an explicit re-publish.
    ///
    /// Calling this again later — including after
    /// [`with_stores`](Self::with_stores) — replaces the user-secret store
    /// the prior call set, without touching any other slot.
    pub fn with_user_secret_store<Us: DeRecUserSecretStore>(
        self,
        store: Us,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        BuilderSlotSetMarker<Us>,
        StateStore,
        Transport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: BuilderSlotSetMarker(store),
            state_store: self.state_store,
            transport: self.transport,
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        BuilderSlotMissingMarker,
    >
{
    /// Set the [`DeRecTransport`] implementation responsible for delivering
    /// outbound envelopes to peers.
    pub fn with_transport<Tr: DeRecTransport>(
        self,
        transport: Tr,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        BuilderSlotSetMarker<Tr>,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: BuilderSlotSetMarker(transport),
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
    >
{
    /// Set the [`DeRecStateStore`] implementation responsible for
    /// persisting in-flight orchestrator state (outstanding verification
    /// challenges, recovery accumulators, pending unpair
    /// acknowledgements). Required for stateless / load-balanced
    /// deployments where the process may be recycled between an outbound
    /// request and its inbound response; see the trait documentation for
    /// the concurrency contract.
    ///
    /// Calling this again later — including after
    /// [`with_stores`](Self::with_stores) — replaces the state store the
    /// prior call set, without touching any other slot.
    pub fn with_state_store<St: DeRecStateStore>(
        self,
        store: St,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        BuilderSlotSetMarker<St>,
        Transport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: BuilderSlotSetMarker(store),
            transport: self.transport,
            own_transports: self.own_transports,
            threshold: self.threshold,
            timeouts: self.timeouts,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
            max_subshares: self.max_subshares,
        }
    }
}

impl<
    Cs: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    St: DeRecStateStore,
    Tr: DeRecTransport,
>
    DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        BuilderSlotSetMarker<Sh>,
        BuilderSlotSetMarker<Ss>,
        BuilderSlotSetMarker<Us>,
        BuilderSlotSetMarker<St>,
        BuilderSlotSetMarker<Tr>,
    >
{
    /// Consume the builder and return a fully-initialized [`DeRecProtocol`].
    ///
    /// The "every store and the transport are set" constraint is enforced by
    /// this impl block's type bounds — the call is only reachable once each
    /// of those slots has been filled. Every data setting, however it was
    /// set (its `with_*` setter or [`with_config`](Self::with_config)), is
    /// validated here and an invalid one surfaces as [`crate::Error`].
    ///
    /// # Errors
    ///
    /// - [`crate::Error::InvalidInput`] if `threshold < 2`. A threshold
    ///   of `0` or `1` collapses threshold secret sharing and lets a
    ///   single helper reconstruct the secret unilaterally.
    /// - [`crate::Error::InvalidInput`] if no own transports were set, or
    ///   [`with_own_transports`](Self::with_own_transports) was given an
    ///   empty list. Delivery is push-only, so an application serving no
    ///   endpoint can never be replied to.
    /// - [`crate::Error::InvalidInput`] naming the field if the range passed
    ///   to [`with_parameter_range`](Self::with_parameter_range) has a
    ///   negative `min` or `max`, or a `min` greater than a non-zero `max`.
    ///   A value of `0` means "no bound", so `max == 0` accepts any `min >= 0`.
    /// - [`crate::Error::InvalidInput`] if
    ///   [`with_max_subshares`](Self::with_max_subshares) was given a cap
    ///   below the threshold.
    /// - [`crate::Error::Transport`] if any endpoint passed to
    ///   [`with_own_transports`](Self::with_own_transports) failed
    ///   validation (malformed scheme, empty URI, …) — the first
    ///   invalid entry stops the build.
    /// - [`crate::Error::Transport`] carrying
    ///   [`DuplicateProtocol`](crate::transport::TransportValidationError::DuplicateProtocol)
    ///   if the list names one protocol twice. A device serves at most one
    ///   address per protocol, so the list is a preference order over
    ///   distinct protocols — see the [`transport`](crate::transport) module
    ///   docs.
    pub fn build(self) -> crate::Result<DeRecProtocol<Cs, Sh, Ss, Us, St, Tr>> {
        // The protocol treats `own_transports[0]` as this device's primary
        // endpoint, so an application with no endpoint — none set, or an
        // empty list — cannot be reached at all.
        let own_transports: Vec<TransportProtocol> = match self.own_transports {
            Some(transports) => transports?.into_iter().map(Into::into).collect(),
            None => Vec::new(),
        };
        if own_transports.is_empty() {
            return Err(crate::Error::InvalidInput(
                "own transports must not be empty: this application needs at \
                 least one endpoint peers can reach it on",
            ));
        }
        if let Some(range) = &self.parameter_range {
            crate::primitives::pairing::parameter_range::validate(range)?;
        }
        if let Some(max) = self.max_subshares
            && max < self.threshold as u64
        {
            return Err(crate::Error::InvalidInput(
                "max_subshares must be >= threshold; a lower cap fails every round that splits",
            ));
        }
        // One resolution feeds both the build-time `check_own` below and the
        // runtime policy stored on the protocol, so the two never disagree
        // about which flag decided the posture.
        let unsafe_connection = self.unsafe_connection.unwrap_or(false);
        // Deferred to here rather than to `with_own_transport` /
        // `with_own_transports`: the setters may be called in either order,
        // so this is the first point at which both the endpoint(s) and the
        // policy are known. Every entry is checked — an unvalidated
        // secondary endpoint would otherwise be advertised to peers in
        // `supportedTransports` without ever passing policy.
        let policy = crate::transport::TransportPolicy::new(unsafe_connection);
        for own_transport in &own_transports {
            policy.check_own(own_transport)?;
        }
        // Each endpoint may be individually fine and the set still wrong: a
        // device serves one address per protocol, so two of the same protocol
        // leave peers with no rule for choosing between them.
        policy.check_own_set(&own_transports)?;
        let mut protocol = DeRecProtocol::new(
            self.secret_id,
            self.channel_store.0,
            self.share_store.0,
            self.secret_store.0,
            self.user_secret_store.0,
            self.state_store.0,
            self.transport.0,
            own_transports,
            self.threshold,
            self.timeouts,
        )?;
        protocol.communication_info = self.communication_info;
        protocol.auto_respond_on_failure = self.auto_respond_on_failure;
        protocol.unpair_ack = self.unpair_ack;
        protocol.auto_reply_to = self.auto_reply_to;
        protocol.auto_accept = self.auto_accept;
        protocol.replica_id = self.replica_id;
        protocol.parameter_range = self.parameter_range;
        protocol.max_subshares = self.max_subshares;
        protocol.unsafe_connection = unsafe_connection;
        Ok(protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A freshly-constructed builder carries `DEFAULT_THRESHOLD` until a
    /// setter overrides it — the same constant the FFI config's serde
    /// default reads, so both paths stay in lockstep by construction rather
    /// than by convention.
    #[test]
    fn new_defaults_to_the_shared_constants() {
        let b = DeRecProtocolBuilder::new(0);
        assert_eq!(b.threshold, DEFAULT_THRESHOLD);
    }

    /// Boundary value: threshold == 2 is the minimum valid input.
    #[test]
    fn with_threshold_accepts_2() {
        let b = DeRecProtocolBuilder::new(0).with_threshold(2);
        assert_eq!(b.threshold, 2);
    }

    /// Builder round-trip: `with_auto_accept` stores the policy on the
    /// builder so it lands on the eventual `DeRecProtocol`.
    #[test]
    fn with_auto_accept_round_trips_policy() {
        let policy = crate::protocol::AutoAcceptPolicy {
            store_share: true,
            verify_share: true,
            ..Default::default()
        };
        let b = DeRecProtocolBuilder::new(0).with_auto_accept(policy);
        assert_eq!(b.auto_accept, policy);
    }

    /// Default builder leaves `auto_accept` empty (every flow off).
    #[test]
    fn auto_accept_defaults_to_empty_policy() {
        let b = DeRecProtocolBuilder::new(0);
        assert_eq!(b.auto_accept, crate::protocol::AutoAcceptPolicy::default());
    }

    /// Higher thresholds (production default and beyond) pass through.
    #[test]
    fn with_threshold_accepts_3_and_above() {
        let b3 = DeRecProtocolBuilder::new(0).with_threshold(3);
        assert_eq!(b3.threshold, 3);
        let b_high = DeRecProtocolBuilder::new(0).with_threshold(100);
        assert_eq!(b_high.threshold, 100);
    }

    /// `with_threshold` is infallible — invalid values are accepted
    /// here and surface as `Error::InvalidInput` at `build()` time.
    /// This test only asserts the value round-trips into the builder.
    #[test]
    fn with_threshold_accepts_invalid_values_silently() {
        let b0 = DeRecProtocolBuilder::new(0).with_threshold(0);
        assert_eq!(b0.threshold, 0);
        let b1 = DeRecProtocolBuilder::new(0).with_threshold(1);
        assert_eq!(b1.threshold, 1);
    }

    /// The low-level [`DeRecProtocol::new`] constructor enforces the
    /// threshold floor for callers that bypass the typed builder. We
    /// construct via no-op stores so the type bound resolves with
    /// concrete `DeRecChannelStore` etc. implementations.
    #[test]
    fn protocol_new_rejects_zero_threshold() {
        use crate::protocol::traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture,
            TransportFuture,
        };
        use crate::protocol::types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
            ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(
                &self,
                _: u64,
                _: ChannelQuery,
            ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn helpers(
                &self,
                _: u64,
                _: HelperFilter,
            ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn replicas(
                &self,
                _: u64,
                _: ReplicaFilter,
            ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn link_channel(
                &mut self,
                _: u64,
                _: ChannelId,
                _: ChannelId,
            ) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn linked_channels(
                &self,
                _: u64,
                cid: ChannelId,
            ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
                Box::pin(std::future::ready(Ok(vec![cid])))
            }
        }

        struct NoopShareStore;
        impl DeRecShareStore for NoopShareStore {
            fn load(&self, _: u64, _: ChannelId, _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: Share) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_versions(
                &mut self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
                Box::pin(std::future::ready(Ok(None)))
            }
        }

        struct NoopSecretStore;
        impl DeRecSecretStore for NoopSecretStore {
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, Option<SecretValue>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: SecretKind,
                _: MissingPolicy,
            ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: SecretValue) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId, _: SecretKind) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        struct NoopUserSecretStore;
        impl DeRecUserSecretStore for NoopUserSecretStore {
            fn load_latest(&self, _: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save_latest(&mut self, _: u64, _: UserSecrets) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        struct NoopTransport;
        impl DeRecTransport for NoopTransport {
            fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        struct NoopStateStore;
        impl crate::protocol::DeRecStateStore for NoopStateStore {
            fn save(
                &mut self,
                _: u64,
                _: crate::protocol::StateItem,
            ) -> crate::protocol::StateStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn load(
                &self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, Option<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn remove(
                &mut self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn load_all(
                &self,
                _: u64,
                _: crate::protocol::StateKind,
            ) -> crate::protocol::StateStoreFuture<'_, Vec<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
        }

        // threshold = 0 — `DeRecProtocol::new` returns
        // `Error::InvalidInput` rather than panicking.
        let result = DeRecProtocol::new(
            0,
            NoopChannelStore,
            NoopShareStore,
            NoopSecretStore,
            NoopUserSecretStore,
            NoopStateStore,
            NoopTransport,
            vec![TransportProtocol {
                uri: String::new(),
                protocol: 0,
            }],
            0, // ← invalid threshold
            crate::protocol::types::Timeouts::default(),
        );
        assert!(matches!(result, Err(crate::Error::InvalidInput(_))));
    }

    /// End-to-end: the typed builder propagates the threshold error
    /// from `DeRecProtocol::new` instead of panicking, so callers can
    /// handle invalid configurations uniformly via `Result`.
    #[test]
    fn build_rejects_zero_threshold_via_invalid_input() {
        use crate::protocol::traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture,
            TransportFuture,
        };
        use crate::protocol::types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
            ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(
                &self,
                _: u64,
                _: ChannelQuery,
            ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn helpers(
                &self,
                _: u64,
                _: HelperFilter,
            ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn replicas(
                &self,
                _: u64,
                _: ReplicaFilter,
            ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn link_channel(
                &mut self,
                _: u64,
                _: ChannelId,
                _: ChannelId,
            ) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn linked_channels(
                &self,
                _: u64,
                cid: ChannelId,
            ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
                Box::pin(std::future::ready(Ok(vec![cid])))
            }
        }
        struct NoopShareStore;
        impl DeRecShareStore for NoopShareStore {
            fn load(&self, _: u64, _: ChannelId, _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: Share) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_versions(
                &mut self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
                Box::pin(std::future::ready(Ok(None)))
            }
        }
        struct NoopSecretStore;
        impl DeRecSecretStore for NoopSecretStore {
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, Option<SecretValue>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: SecretKind,
                _: MissingPolicy,
            ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: SecretValue) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId, _: SecretKind) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopUserSecretStore;
        impl DeRecUserSecretStore for NoopUserSecretStore {
            fn load_latest(&self, _: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save_latest(&mut self, _: u64, _: UserSecrets) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopTransport;
        impl DeRecTransport for NoopTransport {
            fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        struct NoopStateStore;
        impl crate::protocol::DeRecStateStore for NoopStateStore {
            fn save(
                &mut self,
                _: u64,
                _: crate::protocol::StateItem,
            ) -> crate::protocol::StateStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn load(
                &self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, Option<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn remove(
                &mut self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn load_all(
                &self,
                _: u64,
                _: crate::protocol::StateKind,
            ) -> crate::protocol::StateStoreFuture<'_, Vec<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
        }

        let result = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_state_store(NoopStateStore)
            .with_own_transports(["https://owner.example/derec"])
            .with_threshold(1)
            .build();
        assert!(matches!(result, Err(crate::Error::InvalidInput(_))));
    }

    /// `with_own_transport` defers URI validation to `build()`, so a
    /// malformed scheme surfaces as `crate::Error::Transport` rather
    /// than panicking mid-chain or being silently accepted.
    #[test]
    fn build_rejects_malformed_own_transport_via_transport_error() {
        use crate::protocol::traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture,
            TransportFuture,
        };
        use crate::protocol::types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
            ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(
                &self,
                _: u64,
                _: ChannelQuery,
            ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn helpers(
                &self,
                _: u64,
                _: HelperFilter,
            ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn replicas(
                &self,
                _: u64,
                _: ReplicaFilter,
            ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn link_channel(
                &mut self,
                _: u64,
                _: ChannelId,
                _: ChannelId,
            ) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn linked_channels(
                &self,
                _: u64,
                cid: ChannelId,
            ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
                Box::pin(std::future::ready(Ok(vec![cid])))
            }
        }
        struct NoopShareStore;
        impl DeRecShareStore for NoopShareStore {
            fn load(&self, _: u64, _: ChannelId, _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: Share) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_versions(
                &mut self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
                Box::pin(std::future::ready(Ok(None)))
            }
        }
        struct NoopSecretStore;
        impl DeRecSecretStore for NoopSecretStore {
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, Option<SecretValue>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: SecretKind,
                _: MissingPolicy,
            ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: SecretValue) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId, _: SecretKind) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopUserSecretStore;
        impl DeRecUserSecretStore for NoopUserSecretStore {
            fn load_latest(&self, _: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save_latest(&mut self, _: u64, _: UserSecrets) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopTransport;
        impl DeRecTransport for NoopTransport {
            fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        struct NoopStateStore;
        impl crate::protocol::DeRecStateStore for NoopStateStore {
            fn save(
                &mut self,
                _: u64,
                _: crate::protocol::StateItem,
            ) -> crate::protocol::StateStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn load(
                &self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, Option<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn remove(
                &mut self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn load_all(
                &self,
                _: u64,
                _: crate::protocol::StateKind,
            ) -> crate::protocol::StateStoreFuture<'_, Vec<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
        }

        let result = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_state_store(NoopStateStore)
            .with_own_transports(["ws://owner.example/derec"])
            .with_threshold(2)
            .build();
        assert!(matches!(
            result,
            Err(crate::Error::Transport(
                crate::transport::TransportValidationError::UnknownScheme { .. }
            ))
        ));
    }

    /// `with_own_transport` fills the same slot as `with_own_transports`,
    /// as a one-element list.
    #[test]
    fn single_own_transport_becomes_a_one_element_list() {
        use crate::protocol::traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture,
            TransportFuture,
        };
        use crate::protocol::types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
            ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::{Protocol, TransportProtocol};

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(
                &self,
                _: u64,
                _: ChannelQuery,
            ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn helpers(
                &self,
                _: u64,
                _: HelperFilter,
            ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn replicas(
                &self,
                _: u64,
                _: ReplicaFilter,
            ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn link_channel(
                &mut self,
                _: u64,
                _: ChannelId,
                _: ChannelId,
            ) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn linked_channels(
                &self,
                _: u64,
                cid: ChannelId,
            ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
                Box::pin(std::future::ready(Ok(vec![cid])))
            }
        }
        struct NoopShareStore;
        impl DeRecShareStore for NoopShareStore {
            fn load(&self, _: u64, _: ChannelId, _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: Share) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_versions(
                &mut self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
                Box::pin(std::future::ready(Ok(None)))
            }
        }
        struct NoopSecretStore;
        impl DeRecSecretStore for NoopSecretStore {
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, Option<SecretValue>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: SecretKind,
                _: MissingPolicy,
            ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: SecretValue) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId, _: SecretKind) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopUserSecretStore;
        impl DeRecUserSecretStore for NoopUserSecretStore {
            fn load_latest(&self, _: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save_latest(&mut self, _: u64, _: UserSecrets) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopTransport;
        impl DeRecTransport for NoopTransport {
            fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopStateStore;
        impl crate::protocol::DeRecStateStore for NoopStateStore {
            fn save(
                &mut self,
                _: u64,
                _: crate::protocol::StateItem,
            ) -> crate::protocol::StateStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn load(
                &self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, Option<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn remove(
                &mut self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn load_all(
                &self,
                _: u64,
                _: crate::protocol::StateKind,
            ) -> crate::protocol::StateStoreFuture<'_, Vec<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
        }

        let protocol = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_state_store(NoopStateStore)
            .with_own_transports([crate::transport::TransportProtocol::new(
                "https://me.example.com/derec",
                Protocol::Https,
            )])
            .with_threshold(2)
            .build()
            .expect("valid single-endpoint builder should build");
        assert_eq!(protocol.own_transports.len(), 1);
        assert_eq!(protocol.own_transports[0].protocol, Protocol::Https as i32);
    }

    /// The order the application passes is its preference order and must
    /// survive verbatim — it is the order the peer is advertised in.
    #[test]
    fn own_transports_preserve_caller_order() {
        use crate::protocol::traits::{
            ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
            DeRecTransport, DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture,
            TransportFuture,
        };
        use crate::protocol::types::{
            ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
            ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::{Protocol, TransportProtocol};

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(
                &self,
                _: u64,
                _: ChannelQuery,
            ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn helpers(
                &self,
                _: u64,
                _: HelperFilter,
            ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn replicas(
                &self,
                _: u64,
                _: ReplicaFilter,
            ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn link_channel(
                &mut self,
                _: u64,
                _: ChannelId,
                _: ChannelId,
            ) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn linked_channels(
                &self,
                _: u64,
                cid: ChannelId,
            ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
                Box::pin(std::future::ready(Ok(vec![cid])))
            }
        }
        struct NoopShareStore;
        impl DeRecShareStore for NoopShareStore {
            fn load(&self, _: u64, _: ChannelId, _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: Share) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove_versions(
                &mut self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
                Box::pin(std::future::ready(Ok(None)))
            }
        }
        struct NoopSecretStore;
        impl DeRecSecretStore for NoopSecretStore {
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, Option<SecretValue>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn load_many(
                &self,
                _: u64,
                _: &[ChannelId],
                _: SecretKind,
                _: MissingPolicy,
            ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
            fn save(&mut self, _: u64, _: ChannelId, _: SecretValue) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId, _: SecretKind) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopUserSecretStore;
        impl DeRecUserSecretStore for NoopUserSecretStore {
            fn load_latest(&self, _: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save_latest(&mut self, _: u64, _: UserSecrets) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64) -> ShareStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopTransport;
        impl DeRecTransport for NoopTransport {
            fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }
        struct NoopStateStore;
        impl crate::protocol::DeRecStateStore for NoopStateStore {
            fn save(
                &mut self,
                _: u64,
                _: crate::protocol::StateItem,
            ) -> crate::protocol::StateStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn load(
                &self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, Option<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn remove(
                &mut self,
                _: u64,
                _: crate::protocol::StateKey,
            ) -> crate::protocol::StateStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn load_all(
                &self,
                _: u64,
                _: crate::protocol::StateKind,
            ) -> crate::protocol::StateStoreFuture<'_, Vec<crate::protocol::StateItem>>
            {
                Box::pin(std::future::ready(Ok(Vec::new())))
            }
        }

        let protocol = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_state_store(NoopStateStore)
            .with_own_transports(vec![
                crate::transport::TransportProtocol::new(
                    "grpcs://me.example.com:443",
                    Protocol::Grpc,
                ),
                crate::transport::TransportProtocol::new(
                    "https://me.example.com/derec",
                    Protocol::Https,
                ),
            ])
            .with_threshold(2)
            .build()
            .expect("valid multi-endpoint builder should build");
        assert_eq!(protocol.own_transports[0].protocol, Protocol::Grpc as i32);
        assert_eq!(protocol.own_transports[1].protocol, Protocol::Https as i32);
    }

    /// `with_own_transports` takes any iterator, so an empty one would leave
    /// `own_transports[0]` — the primary endpoint the protocol indexes
    /// unconditionally — with nothing to return.
    #[test]
    fn build_rejects_an_empty_own_transport_list() {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport,
        };

        let built = DeRecProtocolBuilder::new(0)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(Vec::<crate::transport::TransportProtocol>::new())
            .with_threshold(2)
            .build();
        match built {
            Err(crate::Error::InvalidInput(_)) => {}
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("an application serving no endpoint must not build"),
        }
    }

    fn build_with_parameter_range(
        range: derec_proto::ParameterRange,
    ) -> crate::Result<
        DeRecProtocol<
            crate::protocol::test::InMemChannelStore,
            crate::protocol::test::InMemShareStore,
            crate::protocol::test::InMemSecretStore,
            crate::protocol::test::InMemUserSecretStore,
            crate::protocol::test::InMemStateStore,
            crate::protocol::test::NoopTransport,
        >,
    > {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport,
        };

        DeRecProtocolBuilder::new(0)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example/derec"])
            .with_threshold(2)
            .with_parameter_range(range)
            .build()
    }

    fn build_with_max_subshares(
        threshold: usize,
        max_subshares: Option<u64>,
    ) -> crate::Result<
        DeRecProtocol<
            crate::protocol::test::InMemChannelStore,
            crate::protocol::test::InMemShareStore,
            crate::protocol::test::InMemSecretStore,
            crate::protocol::test::InMemUserSecretStore,
            crate::protocol::test::InMemStateStore,
            crate::protocol::test::NoopTransport,
        >,
    > {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport,
        };

        let builder = DeRecProtocolBuilder::new(0)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example/derec"])
            .with_threshold(threshold);
        match max_subshares {
            Some(max) => builder.with_max_subshares(max).build(),
            None => builder.build(),
        }
    }

    #[test]
    fn max_subshares_defaults_to_no_cap() {
        let b = DeRecProtocolBuilder::new(0);
        assert_eq!(b.max_subshares, None);
        let protocol = build_with_max_subshares(3, None).expect("no cap builds");
        assert_eq!(protocol.max_subshares, None);
    }

    #[test]
    fn build_accepts_a_cap_at_or_above_the_threshold() {
        for max in [3, 4, 1_000] {
            let protocol = build_with_max_subshares(3, Some(max)).expect("a cap >= threshold");
            assert_eq!(protocol.max_subshares, Some(max));
        }
    }

    /// A cap below the threshold could never be met by a round that splits,
    /// so every publish would fail; it is rejected at build time instead.
    #[test]
    fn build_rejects_a_cap_below_the_threshold() {
        for max in [0, 1, 2] {
            match build_with_max_subshares(3, Some(max)) {
                Err(crate::Error::InvalidInput(msg)) => {
                    assert!(msg.contains("max_subshares"), "{msg}")
                }
                Err(other) => panic!("expected InvalidInput, got {other:?}"),
                Ok(_) => panic!("a cap of {max} below threshold 3 must not build"),
            }
        }
    }

    #[test]
    fn build_accepts_a_valid_parameter_range() {
        let range = derec_proto::ParameterRange {
            min_share_size: 1,
            max_share_size: 1_000_000,
            min_time_between_verifications: 60,
            max_time_between_verifications: 0,
            ..Default::default()
        };
        assert!(build_with_parameter_range(range).is_ok());
    }

    #[test]
    fn build_accepts_an_all_zero_parameter_range() {
        assert!(build_with_parameter_range(derec_proto::ParameterRange::default()).is_ok());
    }

    #[test]
    fn build_rejects_an_invalid_parameter_range_naming_the_field() {
        let cases = [
            derec_proto::ParameterRange {
                min_share_size: -1,
                ..Default::default()
            },
            derec_proto::ParameterRange {
                max_share_size: -1,
                ..Default::default()
            },
            derec_proto::ParameterRange {
                min_share_size: 11,
                max_share_size: 10,
                ..Default::default()
            },
        ];
        for range in cases {
            match build_with_parameter_range(range) {
                Err(crate::Error::InvalidInput(msg)) => {
                    assert!(msg.contains("shareSize"), "{msg}")
                }
                Err(other) => panic!("expected InvalidInput, got {other:?}"),
                Ok(_) => panic!("an invalid parameter range must not build"),
            }
        }
    }

    /// Normalization is the builder's single responsibility here: a zero
    /// arriving by any construction path is clamped to one second, because a
    /// zero would expire every `Pending` channel on the next `process()`
    /// call — including pairings that had only just started.
    #[test]
    fn with_timeouts_expired_channels_clamps_zero_from_constructor() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            expired_channels: crate::protocol::ExpiredChannelCleanup::from_secs(0),
            ..Default::default()
        });
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 }
        );
    }

    #[test]
    fn with_timeouts_expired_channels_clamps_zero_from_new() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            expired_channels: crate::protocol::ExpiredChannelCleanup::new(true, 0),
            ..Default::default()
        });
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 }
        );
    }

    #[test]
    fn with_timeouts_expired_channels_clamps_zero_from_literal() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            expired_channels: crate::protocol::ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 0,
            },
            ..Default::default()
        });
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 }
        );
    }

    /// The three `Duration` budgets clamp to one second, for the same
    /// reason the sweep does: wire timestamps carry whole seconds, so a
    /// zero would mean "expire everything on the next pass" rather than
    /// "no timeout".
    #[test]
    fn with_timeouts_clamps_every_duration_to_at_least_one_second() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            inbound_message: Duration::ZERO,
            sharing_round: Duration::ZERO,
            unpair_ack: Duration::from_millis(400),
            ..Default::default()
        });
        assert_eq!(b.timeouts.inbound_message, Duration::from_secs(1));
        assert_eq!(b.timeouts.sharing_round, Duration::from_secs(1));
        assert_eq!(b.timeouts.unpair_ack, Duration::from_secs(1));
    }

    /// Sub-second precision is truncated, not rounded — 2.5s is 2s.
    #[test]
    fn with_timeouts_truncates_sub_second_precision() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            sharing_round: Duration::from_millis(2500),
            ..Default::default()
        });
        assert_eq!(b.timeouts.sharing_round, Duration::from_secs(2));
    }

    /// Setting one field leaves the other three at their defaults — the
    /// struct-update ergonomics every binding relies on.
    #[test]
    fn with_timeouts_leaves_unspecified_fields_at_their_defaults() {
        let d = crate::protocol::types::Timeouts::default();
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            sharing_round: Duration::from_secs(30),
            ..Default::default()
        });
        assert_eq!(b.timeouts.sharing_round, Duration::from_secs(30));
        assert_eq!(b.timeouts.inbound_message, d.inbound_message);
        assert_eq!(b.timeouts.unpair_ack, d.unpair_ack);
        assert_eq!(b.timeouts.expired_channels, d.expired_channels);
    }

    #[test]
    fn with_timeouts_expired_channels_preserves_disabled() {
        let b = DeRecProtocolBuilder::new(0).with_timeouts(crate::protocol::types::Timeouts {
            expired_channels: crate::protocol::ExpiredChannelCleanup::Disabled,
            ..Default::default()
        });
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Disabled
        );
    }

    #[test]
    fn builder_defaults_to_enabled_300() {
        let b = DeRecProtocolBuilder::new(0);
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled {
                timeout_in_secs: 300
            }
        );
    }

    /// `with_stores` must drive [`DeRecProtocol::start`] to the same
    /// observable outcome as the five individual setters: given the same
    /// contact, both builds produce the same `PairingStarted` channel id,
    /// dispatch to the same endpoint, and persist the same shape of channel
    /// record and pairing secret.
    #[test]
    fn with_stores_builds_like_the_five_setters() {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, RecordingTransport, run_async,
        };
        use crate::protocol::types::{ChannelQuery, ChannelRecord, ChannelStatus, SecretKind};
        use crate::types::ChannelId;
        use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};

        const SECRET_ID: u64 = 0x0005_EC57;
        const CHANNEL_ID: u64 = 99;

        let contact = crate::primitives::pairing::request::create_contact(
            ChannelId(CHANNEL_ID),
            ContactMode::InlineKeys,
            vec![TransportProtocol {
                uri: "https://helper.example/derec".to_owned(),
                protocol: Protocol::Https.into(),
            }],
            None,
        )
        .expect("contact creation")
        .contact_message;

        run_async(async {
            let via_setters_transport = RecordingTransport::default();
            let mut via_setters = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(InMemStateStore)
                .with_transport(via_setters_transport.clone())
                .with_own_transports(["https://owner-a.example"])
                .build()
                .expect("five-setter build");

            let via_stores_transport = RecordingTransport::default();
            let mut via_stores = DeRecProtocolBuilder::new(SECRET_ID)
                .with_stores(DeRecStores {
                    channels: InMemChannelStore::default(),
                    shares: InMemShareStore::default(),
                    secrets: InMemSecretStore::default(),
                    user_secrets: InMemUserSecretStore::default(),
                    state: InMemStateStore,
                })
                .with_transport(via_stores_transport.clone())
                .with_own_transports(["https://owner-b.example"])
                .build()
                .expect("with_stores build");

            for (protocol, transport) in [
                (&mut via_setters, &via_setters_transport),
                (&mut via_stores, &via_stores_transport),
            ] {
                let events = protocol
                    .start(crate::protocol::DeRecFlow::Pairing {
                        kind: SenderKind::Owner,
                        contact: contact.clone(),
                        peer_communication_info: std::collections::HashMap::new(),
                    })
                    .await
                    .expect("pairing starts");

                assert_eq!(events.len(), 1, "exactly one PairingStarted: {events:?}");
                match &events[0] {
                    crate::protocol::DeRecEvent::PairingStarted {
                        channel_id, kind, ..
                    } => {
                        assert_eq!(*channel_id, ChannelId(CHANNEL_ID));
                        assert_eq!(*kind, SenderKind::Owner);
                    }
                    other => panic!("expected PairingStarted, got {other:?}"),
                }

                assert_eq!(
                    transport.sent_uris(),
                    vec!["https://helper.example/derec".to_owned()],
                    "pairing dispatches one request to the contact's endpoint"
                );

                let saved = protocol
                    .channel_store
                    .load(
                        SECRET_ID,
                        ChannelQuery::Helper {
                            channel_id: ChannelId(CHANNEL_ID),
                        },
                    )
                    .await
                    .expect("channel load")
                    .expect("channel record persisted");
                match saved {
                    ChannelRecord::Helper(h) => {
                        assert_eq!(h.status, ChannelStatus::Pending);
                        assert_eq!(h.peer_role, SenderKind::Helper);
                    }
                    other => panic!("expected a Helper record, got {other:?}"),
                }

                let pairing_contact = protocol
                    .secret_store
                    .load(SECRET_ID, ChannelId(CHANNEL_ID), SecretKind::PairingContact)
                    .await
                    .expect("secret load")
                    .expect("pairing contact persisted");
                assert!(matches!(
                    pairing_contact,
                    crate::protocol::types::SecretValue::PairingContact(_)
                ));
            }
        });
    }

    /// Calling `with_stores` and then an individual setter replaces only
    /// that one slot — the protocol ends up writing through the setter's
    /// store, not the one `with_stores` put there.
    #[test]
    fn with_stores_then_a_setter_replaces_that_store() {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport, run_async,
        };
        use crate::protocol::types::Share;
        use crate::types::ChannelId;

        run_async(async {
            let discarded_shares = InMemShareStore::default();
            let discarded_handle = discarded_shares.clone();
            let kept_shares = InMemShareStore::default();
            let kept_handle = kept_shares.clone();

            let mut protocol = DeRecProtocolBuilder::new(0)
                .with_stores(DeRecStores {
                    channels: InMemChannelStore::default(),
                    shares: discarded_shares,
                    secrets: InMemSecretStore::default(),
                    user_secrets: InMemUserSecretStore::default(),
                    state: InMemStateStore,
                })
                // Overrides only the share store `with_stores` set above.
                .with_share_store(kept_shares)
                .with_transport(NoopTransport)
                .with_own_transports(["https://owner.example"])
                .build()
                .expect("builder with an overridden store builds");

            protocol
                .share_store
                .save(
                    0,
                    ChannelId(1),
                    Share {
                        secret_id: 0,
                        version: 1,
                        bytes: vec![0xAB],
                    },
                )
                .await
                .expect("save through the store the protocol is actually wired to");

            let kept = kept_handle.load(0, ChannelId(1), &[1]).await.unwrap();
            assert_eq!(
                kept.len(),
                1,
                "the setter's store is the one the protocol writes through"
            );

            let discarded = discarded_handle.load(0, ChannelId(1), &[1]).await.unwrap();
            assert!(
                discarded.is_empty(),
                "with_stores's share store must not have been written to"
            );
        });
    }

    /// Every data setting the builder holds, in comparable form.
    #[derive(Debug, PartialEq)]
    struct Settings {
        threshold: usize,
        timeouts: crate::protocol::types::Timeouts,
        unsafe_connection: Option<bool>,
        communication_info: HashMap<String, String>,
        auto_respond_on_failure: bool,
        unpair_ack: UnpairAck,
        auto_reply_to: bool,
        auto_accept: crate::protocol::AutoAcceptPolicy,
        replica_id: Option<u64>,
        parameter_range: Option<derec_proto::ParameterRange>,
        max_subshares: Option<u64>,
        own_transports: Option<Option<Vec<crate::transport::TransportProtocol>>>,
    }

    fn settings<Cs, Sh, Ss, Us, St, Tr>(
        b: &DeRecProtocolBuilder<Cs, Sh, Ss, Us, St, Tr>,
    ) -> Settings {
        Settings {
            threshold: b.threshold,
            timeouts: b.timeouts,
            unsafe_connection: b.unsafe_connection,
            communication_info: b.communication_info.clone(),
            auto_respond_on_failure: b.auto_respond_on_failure,
            unpair_ack: b.unpair_ack,
            auto_reply_to: b.auto_reply_to,
            auto_accept: b.auto_accept,
            replica_id: b.replica_id,
            parameter_range: b.parameter_range,
            max_subshares: b.max_subshares,
            own_transports: b.own_transports.as_ref().map(|r| r.as_ref().ok().cloned()),
        }
    }

    fn full_config() -> crate::protocol::DeRecProtocolConfig {
        crate::protocol::DeRecProtocolConfig {
            threshold: Some(4),
            max_subshares: Some(12),
            timeouts: Some(crate::protocol::TimeoutsConfig {
                inbound_message_secs: Some(120),
                sharing_round_secs: Some(30),
                unpair_ack_secs: Some(45),
                expired_channels: Some(crate::protocol::ExpiredChannelsConfig {
                    enabled: false,
                    timeout_in_secs: 600,
                }),
            }),
            parameter_range: Some(derec_proto::ParameterRange {
                min_share_size: 1,
                max_share_size: 4096,
                ..Default::default()
            }),
            auto_accept: Some(crate::protocol::AutoAcceptPolicy {
                pairing: true,
                store_share: true,
                ..Default::default()
            }),
            auto_respond_on_failure: Some(true),
            auto_reply_to: Some(true),
            unpair_ack: Some(UnpairAck::NotRequired),
            unsafe_connection: Some(true),
            communication_info: Some(HashMap::from([("name".to_owned(), "alice".to_owned())])),
            own_transports: Some(vec![
                crate::transport::TransportProtocol::new(
                    "grpcs://me.example.com:443",
                    derec_proto::Protocol::Grpc,
                ),
                crate::transport::TransportProtocol::new(
                    "https://me.example.com/derec",
                    derec_proto::Protocol::Https,
                ),
            ]),
            replica_id: Some(9_007_199_254_740_993),
        }
    }

    /// An empty config is a no-op: every setting an earlier call made, and
    /// every default, survives it.
    #[test]
    fn with_config_leaves_unset_fields_untouched() {
        let b = DeRecProtocolBuilder::new(0)
            .with_threshold(5)
            .with_replica_id(7)
            .with_auto_reply_to(true)
            .with_own_transports(["https://me.example.com"])
            .with_timeouts(crate::protocol::types::Timeouts {
                sharing_round: Duration::from_secs(30),
                ..Default::default()
            });
        let before = settings(&b);
        let b = b.with_config(crate::protocol::DeRecProtocolConfig::default());
        assert_eq!(settings(&b), before);

        let fresh = DeRecProtocolBuilder::new(0);
        let defaults = settings(&fresh);
        let fresh = fresh.with_config(crate::protocol::DeRecProtocolConfig::default());
        assert_eq!(settings(&fresh), defaults);
    }

    /// Each set field lands exactly where its `with_*` setter would put it.
    #[test]
    fn with_config_matches_the_individual_setters() {
        let via_config = DeRecProtocolBuilder::new(0).with_config(full_config());
        let via_setters = DeRecProtocolBuilder::new(0)
            .with_threshold(4)
            .with_max_subshares(12)
            .with_timeouts(crate::protocol::types::Timeouts {
                inbound_message: Duration::from_secs(120),
                sharing_round: Duration::from_secs(30),
                unpair_ack: Duration::from_secs(45),
                expired_channels: crate::protocol::ExpiredChannelCleanup::Disabled,
            })
            .with_parameter_range(derec_proto::ParameterRange {
                min_share_size: 1,
                max_share_size: 4096,
                ..Default::default()
            })
            .with_auto_accept(crate::protocol::AutoAcceptPolicy {
                pairing: true,
                store_share: true,
                ..Default::default()
            })
            .with_auto_respond_on_failure(true)
            .with_auto_reply_to(true)
            .with_unpair_ack(UnpairAck::NotRequired)
            .with_unsafe_connection(true)
            .with_communication_info(HashMap::from([("name".to_owned(), "alice".to_owned())]))
            .with_own_transports(vec![
                crate::transport::TransportProtocol::new(
                    "grpcs://me.example.com:443",
                    derec_proto::Protocol::Grpc,
                ),
                crate::transport::TransportProtocol::new(
                    "https://me.example.com/derec",
                    derec_proto::Protocol::Https,
                ),
            ])
            .with_replica_id(9_007_199_254_740_993);
        assert_eq!(settings(&via_config), settings(&via_setters));
    }

    /// A general config, then a per-user config, then a setter: the last
    /// write wins per field, and timeouts merge per field against what the
    /// builder already holds rather than against the library default.
    #[test]
    fn with_config_layers_last_write_wins_per_field() {
        let general = crate::protocol::DeRecProtocolConfig {
            threshold: Some(4),
            replica_id: Some(11),
            auto_reply_to: Some(true),
            timeouts: Some(crate::protocol::TimeoutsConfig {
                sharing_round_secs: Some(30),
                ..Default::default()
            }),
            own_transports: Some(vec![crate::transport::TransportProtocol::new(
                "https://general.example.com",
                derec_proto::Protocol::Https,
            )]),
            ..Default::default()
        };
        let per_user = crate::protocol::DeRecProtocolConfig {
            threshold: Some(5),
            communication_info: Some(HashMap::from([("name".to_owned(), "bob".to_owned())])),
            timeouts: Some(crate::protocol::TimeoutsConfig {
                inbound_message_secs: Some(120),
                ..Default::default()
            }),
            ..Default::default()
        };
        let b = DeRecProtocolBuilder::new(0)
            .with_config(general)
            .with_config(per_user)
            .with_threshold(6);
        let s = settings(&b);
        let d = crate::protocol::types::Timeouts::default();

        assert_eq!(s.threshold, 6);
        assert_eq!(s.replica_id, Some(11));
        assert!(s.auto_reply_to);
        assert_eq!(
            s.communication_info.get("name").map(String::as_str),
            Some("bob")
        );
        assert_eq!(s.timeouts.sharing_round, Duration::from_secs(30));
        assert_eq!(s.timeouts.inbound_message, Duration::from_secs(120));
        assert_eq!(s.timeouts.unpair_ack, d.unpair_ack);
        assert_eq!(s.timeouts.expired_channels, d.expired_channels);
        assert_eq!(
            s.own_transports,
            Some(Some(vec![crate::transport::TransportProtocol::new(
                "https://general.example.com",
                derec_proto::Protocol::Https,
            )]))
        );
        assert_eq!(s.unpair_ack, UnpairAck::Required);
    }

    /// A config's timeouts go through the same one-second clamp as
    /// `with_timeouts`.
    #[test]
    fn with_config_timeouts_are_clamped_like_with_timeouts() {
        let b = DeRecProtocolBuilder::new(0).with_config(crate::protocol::DeRecProtocolConfig {
            timeouts: Some(crate::protocol::TimeoutsConfig {
                inbound_message_secs: Some(0),
                expired_channels: Some(crate::protocol::ExpiredChannelsConfig {
                    enabled: true,
                    timeout_in_secs: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(b.timeouts.inbound_message, Duration::from_secs(1));
        assert_eq!(
            b.timeouts.expired_channels,
            crate::protocol::ExpiredChannelCleanup::Enabled { timeout_in_secs: 1 }
        );
    }

    type InMemBuilder = DeRecProtocolBuilder<
        BuilderSlotSetMarker<crate::protocol::test::InMemChannelStore>,
        BuilderSlotSetMarker<crate::protocol::test::InMemShareStore>,
        BuilderSlotSetMarker<crate::protocol::test::InMemSecretStore>,
        BuilderSlotSetMarker<crate::protocol::test::InMemUserSecretStore>,
        BuilderSlotSetMarker<crate::protocol::test::InMemStateStore>,
        BuilderSlotSetMarker<crate::protocol::test::NoopTransport>,
    >;

    fn in_mem_builder() -> InMemBuilder {
        use crate::protocol::test::{
            InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
            InMemUserSecretStore, NoopTransport,
        };
        DeRecProtocolBuilder::new(0)
            .with_stores(DeRecStores {
                channels: InMemChannelStore::default(),
                shares: InMemShareStore::default(),
                secrets: InMemSecretStore::default(),
                user_secrets: InMemUserSecretStore::default(),
                state: InMemStateStore,
            })
            .with_transport(NoopTransport)
    }

    fn invalid_input_message<T>(result: crate::Result<T>) -> &'static str {
        match result {
            Err(crate::Error::InvalidInput(msg)) => msg,
            Err(other) => panic!("expected InvalidInput, got {other:?}"),
            Ok(_) => panic!("expected InvalidInput, got a built protocol"),
        }
    }

    /// A value set through a config meets exactly the validation the same
    /// value meets through its setter.
    #[test]
    fn with_config_values_are_validated_at_build_like_the_setters() {
        let via_config = in_mem_builder()
            .with_config(crate::protocol::DeRecProtocolConfig {
                threshold: Some(1),
                own_transports: Some(vec![crate::transport::TransportProtocol::new(
                    "https://me.example.com",
                    derec_proto::Protocol::Https,
                )]),
                ..Default::default()
            })
            .build();
        let via_setter = in_mem_builder()
            .with_own_transports(["https://me.example.com"])
            .with_threshold(1)
            .build();
        assert_eq!(
            invalid_input_message(via_config),
            invalid_input_message(via_setter)
        );

        let via_config = in_mem_builder()
            .with_own_transports(["https://me.example.com"])
            .with_config(crate::protocol::DeRecProtocolConfig {
                threshold: Some(3),
                max_subshares: Some(2),
                ..Default::default()
            })
            .build();
        let via_setter = in_mem_builder()
            .with_own_transports(["https://me.example.com"])
            .with_threshold(3)
            .with_max_subshares(2)
            .build();
        let msg = invalid_input_message(via_config);
        assert!(msg.contains("max_subshares"), "{msg}");
        assert_eq!(msg, invalid_input_message(via_setter));
    }

    /// Own transports are an ordinary setting: a builder that never names
    /// one is refused at `build()` rather than at compile time.
    #[test]
    fn build_rejects_a_builder_with_no_own_transports() {
        let msg = invalid_input_message(in_mem_builder().build());
        assert!(msg.contains("own transports"), "{msg}");
        let msg = invalid_input_message(
            in_mem_builder()
                .with_config(crate::protocol::DeRecProtocolConfig::default())
                .build(),
        );
        assert!(msg.contains("own transports"), "{msg}");
    }

    /// Own transports supplied only through a config build a protocol that
    /// advertises them in the given order.
    #[test]
    fn with_config_own_transports_build_in_order() {
        let protocol = in_mem_builder()
            .with_config(full_config())
            .build()
            .expect("a full config builds");
        assert_eq!(protocol.threshold, 4);
        assert_eq!(protocol.max_subshares, Some(12));
        assert_eq!(protocol.replica_id, Some(9_007_199_254_740_993));
        assert_eq!(
            protocol.own_transports[0].protocol,
            derec_proto::Protocol::Grpc as i32
        );
        assert_eq!(
            protocol.own_transports[1].protocol,
            derec_proto::Protocol::Https as i32
        );
    }
}
