// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Typestate builder for [`DeRecProtocol`]. See [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder).
//!
//! Each store/transport slot is tracked by its own type parameter, starting
//! at [`BuilderSlotMissingMarker`] and transitioning to
//! [`BuilderSlotSetMarker<T>`] when its `with_*` setter runs. Setters only
//! touch their own slot, which is what makes call order irrelevant.
//! [`DeRecProtocolBuilder::build`](crate::protocol::DeRecProtocolBuilder::build) is reachable only when every slot has
//! reached [`BuilderSlotSetMarker<_>`].

use std::collections::HashMap;
use std::time::Duration;

use super::{
    DeRecChannelStore, DeRecProtocol, DeRecSecretStore, DeRecShareStore, DeRecStateStore,
    DeRecTransport, DeRecUserSecretStore, UnpairAck,
};
use derec_proto::TransportProtocol;

pub struct BuilderSlotMissingMarker;

pub struct BuilderSlotSetMarker<T>(T);

/// Minimum number of shares required to reconstruct the secret, absent an
/// explicit [`DeRecProtocolBuilder::with_threshold`](crate::protocol::DeRecProtocolBuilder::with_threshold) call. This is the sole
/// definition of the value — [`DeRecProtocolBuilder::new`](crate::protocol::DeRecProtocolBuilder::new) and the FFI
/// config's serde default both read it rather than each hardcoding `3`.
pub const DEFAULT_THRESHOLD: usize = 3;

/// Number of recent share versions each helper retains, absent an explicit
/// [`DeRecProtocolBuilder::with_keep_versions_count`](crate::protocol::DeRecProtocolBuilder::with_keep_versions_count) call. Sole definition
/// of the value; see [`DEFAULT_THRESHOLD`].
pub const DEFAULT_KEEP_VERSIONS_COUNT: usize = 3;

/// Resolve the two plaintext opt-in flags to a single policy value.
///
/// `unsafe_http` is superseded by `unsafe_connection` but still honored,
/// and **wins on conflict** so an existing deployment that only knows the
/// old flag keeps its current behavior after upgrading.
///
/// The distinction is *presence*, not value: an SDK that never sets the old
/// flag sends nothing, which must not override a deliberate new-flag
/// setting. Callers that cannot express absence must pass `None`.
#[cfg_attr(not(feature = "logging"), allow(unused_variables))]
pub(crate) fn resolve_plaintext_opt_in(
    unsafe_http: Option<bool>,
    unsafe_connection: Option<bool>,
) -> bool {
    match (unsafe_http, unsafe_connection) {
        (Some(old), Some(new)) => {
            #[cfg(feature = "logging")]
            if old != new {
                tracing::warn!(
                    unsafe_http = old,
                    unsafe_connection = new,
                    "both plaintext opt-in flags set and disagreeing — honoring the \
                     deprecated `unsafe_http`; migrate to `unsafe_connection`, which \
                     becomes the only flag at 0.1.0",
                );
            }
            old
        }
        (Some(old), None) => old,
        (None, Some(new)) => new,
        (None, None) => false,
    }
}

/// Typestate builder for [`DeRecProtocol`].
///
/// Call each store/transport setter, then [`build`](DeRecProtocolBuilder::build).
/// The "every required slot is filled" constraint is enforced at compile time
/// by the impl-block bounds — calling `build()` on an incomplete builder is a
/// type error, not a runtime panic.
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
pub struct DeRecProtocolBuilder<
    ChannelStore,
    ShareStore,
    SecretStore,
    UserSecretStore,
    StateStore,
    Transport,
    OwnTransport,
> {
    secret_id: u64,
    channel_store: ChannelStore,
    share_store: ShareStore,
    secret_store: SecretStore,
    user_secret_store: UserSecretStore,
    state_store: StateStore,
    transport: Transport,
    own_transport: OwnTransport,
    threshold: usize,
    keep_versions_count: usize,
    timeouts: crate::protocol::types::Timeouts,
    unsafe_http: Option<bool>,
    unsafe_connection: Option<bool>,
    communication_info: HashMap<String, String>,
    auto_respond_on_failure: bool,
    unpair_ack: UnpairAck,
    auto_reply_to: bool,
    auto_accept: crate::protocol::AutoAcceptPolicy,
    replica_id: Option<u64>,
    parameter_range: Option<derec_proto::ParameterRange>,
}

impl
    DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
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
            own_transport: BuilderSlotMissingMarker,
            threshold: DEFAULT_THRESHOLD,
            keep_versions_count: DEFAULT_KEEP_VERSIONS_COUNT,
            timeouts: crate::protocol::types::Timeouts::default(),
            unsafe_http: None,
            unsafe_connection: None,
            communication_info: HashMap::new(),
            auto_respond_on_failure: false,
            unpair_ack: UnpairAck::Required,
            auto_reply_to: false,
            auto_accept: crate::protocol::AutoAcceptPolicy::default(),
            replica_id: None,
            parameter_range: None,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
        OwnTransport,
    >
{
    /// Minimum number of shares required to reconstruct the secret.
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

    /// Number of recent versions each helper must retain.
    ///
    /// Default: [`DEFAULT_KEEP_VERSIONS_COUNT`].
    pub fn with_keep_versions_count(mut self, count: usize) -> Self {
        self.keep_versions_count = count;
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

    /// Accept plaintext `http://` transport endpoints. **Development only.**
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
    #[deprecated(
        since = "0.0.3",
        note = "use `with_unsafe_connection`, which names both gated schemes; \
                removed at 0.1.0"
    )]
    pub fn with_unsafe_http(mut self, allow: bool) -> Self {
        self.unsafe_http = Some(allow);
        self
    }

    /// Accept plaintext transport endpoints — `http://` and `grpc://`.
    ///
    /// Supersedes [`with_unsafe_http`](Self::with_unsafe_http), which named
    /// only one of the two schemes it gates. Both are honored; if both are
    /// set and disagree, the deprecated one wins and a warning is emitted.
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
    /// record, propagate or reply to a plaintext endpoint.
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
    /// - `true`: on a failed inbound request (e.g. format errors, decryption
    ///   failures), the protocol automatically sends a failure response to the
    ///   peer.
    /// - `false`: inbound processing errors are only surfaced as events and no
    ///   response is sent — the application decides how to respond.
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

    /// Whether outbound requests carry an ephemeral `replyTo` set to this
    /// node's own transport endpoint.
    ///
    /// - `true`: every outbound request envelope stamps
    ///   `request.replyTo = own_transport`. The responder routes its
    ///   response to that endpoint, ignoring the channel's stored peer
    ///   endpoint. Useful when two peers share a channel record but reach
    ///   out from different endpoints (e.g. replicas talking to a helper
    ///   that was paired with a sibling replica) — without this, the
    ///   responder would reply to the sibling.
    /// - `false`: outbound requests leave `replyTo` unset. The responder
    ///   routes to the channel's stored endpoint, which is correct for the
    ///   single-device case.
    ///
    /// Only affects outbound requests originated through
    /// [`DeRecProtocol::start`], and only on channel-mode flows: pairing
    /// carries its endpoints in its own `transportProtocol` field and is
    /// unaffected. Responders always honour an inbound `replyTo` regardless
    /// of this flag (it is purely a per-request hint on the wire).
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
    /// range fails to intersect (e.g. local `minShareSize` exceeds peer
    /// `maxShareSize`) the pairing is rejected with
    /// [`Error::Pairing(PairingError::IncompatibleParameterRange { .. })`](crate::Error::Pairing).
    ///
    /// Default: unset — the local side advertises no constraints and
    /// accepts any peer range.
    pub fn with_parameter_range(mut self, range: derec_proto::ParameterRange) -> Self {
        self.parameter_range = Some(range);
        self
    }
}

impl<ShareStore, SecretStore, UserSecretStore, StateStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
        OwnTransport,
    >
{
    /// Set the [`DeRecChannelStore`] implementation responsible for persisting
    /// channel records.
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: BuilderSlotSetMarker(store),
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }
}

impl<ChannelStore, SecretStore, UserSecretStore, StateStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        BuilderSlotMissingMarker,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
        OwnTransport,
    >
{
    /// Set the [`DeRecShareStore`] implementation responsible for persisting
    /// secret shares.
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: BuilderSlotSetMarker(store),
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }
}

impl<ChannelStore, ShareStore, UserSecretStore, StateStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        BuilderSlotMissingMarker,
        UserSecretStore,
        StateStore,
        Transport,
        OwnTransport,
    >
{
    /// Set the [`DeRecSecretStore`] implementation responsible for persisting
    /// per-channel key material (pairing secrets, shared keys, pairing contacts).
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: BuilderSlotSetMarker(store),
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, StateStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        BuilderSlotMissingMarker,
        StateStore,
        Transport,
        OwnTransport,
    >
{
    /// Set the [`DeRecUserSecretStore`] implementation responsible for
    /// persisting the user-facing secret contents keyed by `secret_id`.
    /// Written on every `start(FlowKind::ProtectSecret)`; read by the
    /// pair-completion auto-publish hook so freshly-paired peers
    /// receive the current secret without an explicit re-publish.
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: BuilderSlotSetMarker(store),
            state_store: self.state_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        BuilderSlotMissingMarker,
        OwnTransport,
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: BuilderSlotSetMarker(transport),
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
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
        BuilderSlotMissingMarker,
    >
{
    /// The local node's transport endpoint that peers will use to reach it.
    ///
    /// Embedded into outgoing contact and pairing messages so peers know
    /// where to send their replies. Accepts anything implementing
    /// [`IntoOwnTransport`](crate::transport::IntoOwnTransport): a typed
    /// [`TransportProtocol`](crate::transport::TransportProtocol), a
    /// `&str`, or a `String`. URI validation is deferred to
    /// [`build`](DeRecProtocolBuilder::build) so the setter chain stays
    /// infallible — a malformed URI surfaces as
    /// [`crate::Error::Transport`] when `build()` runs.
    ///
    /// Stores a one-element preference list, so this and
    /// [`with_own_transports`](Self::with_own_transports) fill the same
    /// slot — whichever is called last wins, same as any other setter.
    ///
    /// # Migrating
    ///
    /// [`with_own_transports`](Self::with_own_transports) takes the whole
    /// preference list and is what this becomes internally, so a
    /// single-endpoint deployment migrates by wrapping its argument:
    ///
    /// ```ignore
    /// // before
    /// .with_own_transport("https://me.example/derec")
    /// // after
    /// .with_own_transports(["https://me.example/derec"])
    /// ```
    ///
    /// The singular spelling is going away because it can name only one
    /// protocol, and a device serving several advertises all of them in
    /// preference order. See the [`transport`](crate::transport) module docs
    /// for how the list is used during pairing, and for the one-endpoint-per-
    /// protocol rule the set is held to.
    #[allow(clippy::type_complexity)]
    #[deprecated(
        since = "0.0.3",
        note = "use `with_own_transports`, which takes the whole preference \
                list; removed at 0.0.5"
    )]
    pub fn with_own_transport(
        self,
        own_transport: impl crate::transport::IntoOwnTransport,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
        BuilderSlotSetMarker<
            Result<
                Vec<crate::transport::TransportProtocol>,
                crate::transport::TransportValidationError,
            >,
        >,
    > {
        let own_transport = own_transport.into_own_transport().map(|t| vec![t]);
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transport: BuilderSlotSetMarker(own_transport),
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }

    /// Set every transport endpoint this application serves, in preference
    /// order.
    ///
    /// The order is meaningful: it is what decides which of a peer's offered
    /// endpoints gets used. The first entry is also this device's primary
    /// endpoint, the one advertised to implementations predating the offer
    /// list.
    ///
    /// Because delivery is push-only, an endpoint listed here is one this
    /// application must actually **serve** — a peer can only reply to an
    /// address it can reach. Listing a transport that is not served makes
    /// pairing succeed and replies vanish.
    ///
    /// Supersedes [`with_own_transport`](Self::with_own_transport) for
    /// applications serving more than one transport; the single-endpoint
    /// setter remains fully supported and is equivalent to passing a
    /// one-element list.
    ///
    /// The list must be non-empty — [`build`](Self::build) rejects an empty
    /// one with [`crate::Error::InvalidInput`].
    #[allow(clippy::type_complexity)]
    pub fn with_own_transports<I, T>(
        self,
        transports: I,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        StateStore,
        Transport,
        BuilderSlotSetMarker<
            Result<
                Vec<crate::transport::TransportProtocol>,
                crate::transport::TransportValidationError,
            >,
        >,
    >
    where
        I: IntoIterator<Item = T>,
        T: crate::transport::IntoOwnTransport,
    {
        // Same error-deferral shape as `with_own_transport`: stash the
        // fallible conversion, surface failures from `.build()`, keep the
        // setter chain infallible.
        let own_transports: Result<Vec<_>, _> = transports
            .into_iter()
            .map(crate::transport::IntoOwnTransport::into_own_transport)
            .collect();
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: self.state_store,
            transport: self.transport,
            own_transport: BuilderSlotSetMarker(own_transports),
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        BuilderSlotMissingMarker,
        Transport,
        OwnTransport,
    >
{
    /// Set the [`DeRecStateStore`] implementation responsible for
    /// persisting in-flight orchestrator state (outstanding verification
    /// challenges, recovery accumulators, pending unpair
    /// acknowledgements). Required for stateless / load-balanced
    /// deployments where the process may be recycled between an outbound
    /// request and its inbound response; see the trait documentation for
    /// the concurrency contract.
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
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            state_store: BuilderSlotSetMarker(store),
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeouts: self.timeouts,
            unsafe_http: self.unsafe_http,
            unsafe_connection: self.unsafe_connection,
            communication_info: self.communication_info,
            auto_respond_on_failure: self.auto_respond_on_failure,
            unpair_ack: self.unpair_ack,
            auto_reply_to: self.auto_reply_to,
            auto_accept: self.auto_accept,
            replica_id: self.replica_id,
            parameter_range: self.parameter_range,
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
        BuilderSlotSetMarker<
            Result<
                Vec<crate::transport::TransportProtocol>,
                crate::transport::TransportValidationError,
            >,
        >,
    >
{
    /// Consume the builder and return a fully-initialized [`DeRecProtocol`].
    ///
    /// The "all required slots set" constraint is enforced by this impl
    /// block's type bounds — the call is only reachable once every slot
    /// has been filled. Runtime invariant checks (currently:
    /// `threshold >= 2` and own-transport URI validity, checked for
    /// every entry) are deferred to this point and surface as
    /// [`crate::Error`].
    ///
    /// # Errors
    ///
    /// - [`crate::Error::InvalidInput`] if `threshold < 2`. A threshold
    ///   of `0` or `1` collapses threshold secret sharing and lets a
    ///   single helper reconstruct the secret unilaterally.
    /// - [`crate::Error::InvalidInput`] if
    ///   [`with_own_transports`](Self::with_own_transports) was given an
    ///   empty list. Delivery is push-only, so an application serving no
    ///   endpoint can never be replied to.
    /// - [`crate::Error::Transport`] if any endpoint passed to
    ///   [`with_own_transport`](Self::with_own_transport) or
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
        let own_transports: Vec<TransportProtocol> =
            self.own_transport.0?.into_iter().map(Into::into).collect();
        // The typestate proves the slot was *filled*, not that it was filled
        // with anything. `with_own_transports` accepts any iterator, so an
        // empty one reaches here having satisfied every type bound, and the
        // protocol treats `own_transports[0]` as this device's primary
        // endpoint — an application with no endpoint cannot be reached at all.
        if own_transports.is_empty() {
            return Err(crate::Error::InvalidInput(
                "own transports must not be empty: this application needs at \
                 least one endpoint peers can reach it on",
            ));
        }
        // One resolution feeds both the build-time `check_own` below and the
        // runtime policy stored on the protocol, so the two never disagree
        // about which flag decided the posture.
        let unsafe_connection = resolve_plaintext_opt_in(self.unsafe_http, self.unsafe_connection);
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
            self.keep_versions_count,
            self.timeouts,
        )?;
        protocol.communication_info = self.communication_info;
        protocol.auto_respond_on_failure = self.auto_respond_on_failure;
        protocol.unpair_ack = self.unpair_ack;
        protocol.auto_reply_to = self.auto_reply_to;
        protocol.auto_accept = self.auto_accept;
        protocol.replica_id = self.replica_id;
        protocol.parameter_range = self.parameter_range;
        protocol.unsafe_http = unsafe_connection;
        Ok(protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_connection_alone_is_honored() {
        assert!(resolve_plaintext_opt_in(None, Some(true)));
        assert!(!resolve_plaintext_opt_in(None, Some(false)));
    }

    /// The deprecated flag wins on conflict, so an existing deployment that
    /// only knows `unsafe_http` keeps behaving exactly as it did.
    #[test]
    fn deprecated_flag_wins_on_conflict() {
        assert!(resolve_plaintext_opt_in(Some(true), Some(false)));
        assert!(!resolve_plaintext_opt_in(Some(false), Some(true)));
    }

    /// Presence, not value. An SDK that never sets `unsafe_http` must not
    /// override a deliberate `unsafe_connection`.
    #[test]
    fn absent_deprecated_flag_does_not_override() {
        assert!(resolve_plaintext_opt_in(None, Some(true)));
    }

    #[test]
    fn neither_flag_is_the_production_posture() {
        assert!(!resolve_plaintext_opt_in(None, None));
    }

    /// The old flag alone still decides, so an application that upgrades
    /// without touching its configuration keeps exactly its previous
    /// posture.
    #[test]
    fn deprecated_flag_alone_is_honored() {
        assert!(resolve_plaintext_opt_in(Some(true), None));
        assert!(!resolve_plaintext_opt_in(Some(false), None));
    }

    /// A freshly-constructed builder carries `DEFAULT_THRESHOLD` /
    /// `DEFAULT_KEEP_VERSIONS_COUNT` until a setter overrides them — the
    /// same constants the FFI config's serde defaults read, so both paths
    /// stay in lockstep by construction rather than by convention.
    #[test]
    fn new_defaults_to_the_shared_constants() {
        let b = DeRecProtocolBuilder::new(0);
        assert_eq!(b.threshold, DEFAULT_THRESHOLD);
        assert_eq!(b.keep_versions_count, DEFAULT_KEEP_VERSIONS_COUNT);
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
            3,
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

    /// The typestate proves the own-transport slot was filled, not that it was
    /// filled with an endpoint. `with_own_transports` takes any iterator, so an
    /// empty one satisfies every type bound and would leave `own_transports[0]`
    /// — the primary endpoint the protocol indexes unconditionally — with
    /// nothing to return.
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
}
