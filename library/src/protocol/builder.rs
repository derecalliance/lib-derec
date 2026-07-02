// SPDX-License-Identifier: Apache-2.0

//! Typestate builder for [`DeRecProtocol`]. See [`DeRecProtocolBuilder`].
//!
//! Each store/transport slot is tracked by its own type parameter, starting
//! at [`BuilderSlotMissingMarker`] and transitioning to
//! [`BuilderSlotSetMarker<T>`] when its `with_*` setter runs. Setters only
//! touch their own slot, which is what makes call order irrelevant.
//! [`DeRecProtocolBuilder::build`] is reachable only when every slot has
//! reached [`BuilderSlotSetMarker<_>`].

use std::collections::HashMap;
use std::time::Duration;

use super::{
    DeRecChannelStore, DeRecProtocol, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, UnpairAck,
};
use derec_proto::TransportProtocol;

pub struct BuilderSlotMissingMarker;

pub struct BuilderSlotSetMarker<T>(T);

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
/// ```rust,ignore
/// let protocol = DeRecProtocolBuilder::new()
///     .with_channel_store(my_channel_store)
///     .with_share_store(my_share_store)
///     .with_secret_store(my_secret_store)
///     .with_transport(my_transport)
///     .with_own_transport(TransportProtocol { uri: "https://me.example.com".into(), .. })
///     // Plus any optional with_* setters to override defaults.
///     .build();
/// ```
pub struct DeRecProtocolBuilder<
    ChannelStore,
    ShareStore,
    SecretStore,
    UserSecretStore,
    Transport,
    OwnTransport,
> {
    secret_id: u64,
    channel_store: ChannelStore,
    share_store: ShareStore,
    secret_store: SecretStore,
    user_secret_store: UserSecretStore,
    transport: Transport,
    own_transport: OwnTransport,
    threshold: usize,
    keep_versions_count: usize,
    timeout_in_secs: u64,
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
            transport: BuilderSlotMissingMarker,
            own_transport: BuilderSlotMissingMarker,
            threshold: 3,
            keep_versions_count: 3,
            timeout_in_secs: 300,
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

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        Transport,
        OwnTransport,
    >
{
    /// Minimum number of shares required to reconstruct the secret.
    ///
    /// Default: `3`. This setter is infallible — invariant checks run
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
    /// Default: `3`.
    pub fn with_keep_versions_count(mut self, count: usize) -> Self {
        self.keep_versions_count = count;
        self
    }

    /// Protocol-wide staleness boundary.
    ///
    /// Any inbound envelope whose timestamp is older than this is discarded
    /// on receipt, regardless of flow.
    ///
    /// The same threshold is also used to age out local state that is
    /// waiting on a peer: incomplete pairings, in-flight sharing rounds,
    /// and outstanding unpair acknowledgements.
    ///
    /// # Granularity
    ///
    /// **One second is the smallest effective unit.** The protocol's wire
    /// timestamps (protobuf `Timestamp.seconds`) carry only whole-second
    /// resolution, so message ages can only be measured to the nearest
    /// second. As a consequence:
    ///
    /// - sub-second precision in the supplied [`Duration`] is truncated
    ///   ([`Duration::from_millis(2500)`](Duration::from_millis) becomes 2 seconds);
    /// - any value below one second is clamped to one second, so an
    ///   accidental [`Duration::ZERO`] does not silently disable the timeout.
    ///
    /// Default: 5 minutes.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_in_secs = timeout.as_secs().max(1);
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
    ///   or until the timeout configured via [`Self::with_timeout`] elapses.
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
    /// [`DeRecProtocol::start`]. Responders always honour an inbound
    /// `replyTo` regardless of this flag (it is purely a per-request hint
    /// on the wire).
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
    pub fn with_auto_accept(
        mut self,
        policy: crate::protocol::AutoAcceptPolicy,
    ) -> Self {
        self.auto_accept = policy;
        self
    }

    /// Configure this node's local **replica identity**.
    ///
    /// Required to participate in any replica-mode pairing — when set, the
    /// orchestrator auto-injects the id (hex-encoded) under the reserved key
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

impl<ShareStore, SecretStore, UserSecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
        ShareStore,
        SecretStore,
        UserSecretStore,
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
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: BuilderSlotSetMarker(store),
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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

impl<ChannelStore, SecretStore, UserSecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        BuilderSlotMissingMarker,
        SecretStore,
        UserSecretStore,
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
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: BuilderSlotSetMarker(store),
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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

impl<ChannelStore, ShareStore, UserSecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        BuilderSlotMissingMarker,
        UserSecretStore,
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
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: BuilderSlotSetMarker(store),
            user_secret_store: self.user_secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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

impl<ChannelStore, ShareStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        BuilderSlotMissingMarker,
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
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: BuilderSlotSetMarker(store),
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
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
        BuilderSlotSetMarker<Tr>,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            transport: BuilderSlotSetMarker(transport),
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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

impl<ChannelStore, ShareStore, SecretStore, UserSecretStore, Transport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
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
    pub fn with_own_transport(
        self,
        own_transport: impl crate::transport::IntoOwnTransport,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        Transport,
        BuilderSlotSetMarker<
            Result<crate::transport::TransportProtocol, crate::transport::TransportValidationError>,
        >,
    > {
        let own_transport = own_transport.into_own_transport();
        DeRecProtocolBuilder {
            secret_id: self.secret_id,
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            user_secret_store: self.user_secret_store,
            transport: self.transport,
            own_transport: BuilderSlotSetMarker(own_transport),
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            timeout_in_secs: self.timeout_in_secs,
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
    Tr: DeRecTransport,
>
    DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        BuilderSlotSetMarker<Sh>,
        BuilderSlotSetMarker<Ss>,
        BuilderSlotSetMarker<Us>,
        BuilderSlotSetMarker<Tr>,
        BuilderSlotSetMarker<
            Result<crate::transport::TransportProtocol, crate::transport::TransportValidationError>,
        >,
    >
{
    /// Consume the builder and return a fully-initialized [`DeRecProtocol`].
    ///
    /// The "all required slots set" constraint is enforced by this impl
    /// block's type bounds — the call is only reachable once every slot
    /// has been filled. Runtime invariant checks (currently:
    /// `threshold >= 2` and own-transport URI validity) are deferred to
    /// this point and surface as [`crate::Error`].
    ///
    /// # Errors
    ///
    /// - [`crate::Error::InvalidInput`] if `threshold < 2`. A threshold
    ///   of `0` or `1` collapses threshold secret sharing and lets a
    ///   single helper reconstruct the secret unilaterally.
    /// - [`crate::Error::Transport`] if the URI passed to
    ///   [`with_own_transport`](Self::with_own_transport) failed
    ///   validation (malformed scheme, empty URI, …).
    pub fn build(self) -> crate::Result<DeRecProtocol<Cs, Sh, Ss, Us, Tr>> {
        let own_transport: TransportProtocol = self.own_transport.0?.into();
        let mut protocol = DeRecProtocol::new(
            self.secret_id,
            self.channel_store.0,
            self.share_store.0,
            self.secret_store.0,
            self.user_secret_store.0,
            self.transport.0,
            own_transport,
            self.threshold,
            self.keep_versions_count,
            self.timeout_in_secs,
        )?;
        protocol.communication_info = self.communication_info;
        protocol.auto_respond_on_failure = self.auto_respond_on_failure;
        protocol.unpair_ack = self.unpair_ack;
        protocol.auto_reply_to = self.auto_reply_to;
        protocol.auto_accept = self.auto_accept;
        protocol.replica_id = self.replica_id;
        protocol.parameter_range = self.parameter_range;
        Ok(protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::protocol::types::{Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecrets};
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(&self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: Channel) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn channels(&self, _: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
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
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn load_all(
                &self,
                _: u64,
                _: &[ChannelId],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn save(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretValue,
            ) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, ()> {
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
            fn send(&self, _: &TransportProtocol, _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
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
            NoopTransport,
            TransportProtocol {
                uri: String::new(),
                protocol: 0,
            },
            0, // ← invalid threshold
            3,
            30,
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
            Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(&self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: Channel) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn channels(&self, _: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
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
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn load_all(
                &self,
                _: u64,
                _: &[ChannelId],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn save(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretValue,
            ) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, ()> {
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
            fn send(&self, _: &TransportProtocol, _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        let result = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_own_transport("https://owner.example/derec")
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
            Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecrets,
        };
        use crate::types::ChannelId;
        use derec_proto::TransportProtocol;

        struct NoopChannelStore;
        impl DeRecChannelStore for NoopChannelStore {
            fn load(&self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
                Box::pin(std::future::ready(Ok(None)))
            }
            fn save(&mut self, _: u64, _: Channel) -> ChannelStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(&mut self, _: u64, _: ChannelId) -> ChannelStoreFuture<'_, bool> {
                Box::pin(std::future::ready(Ok(false)))
            }
            fn channels(&self, _: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
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
            fn load(
                &self,
                _: u64,
                _: ChannelId,
                _: &[u32],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn load_all(
                &self,
                _: u64,
                _: &[ChannelId],
            ) -> ShareStoreFuture<'_, Vec<Share>> {
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
            fn save(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretValue,
            ) -> SecretStoreFuture<'_, ()> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn remove(
                &mut self,
                _: u64,
                _: ChannelId,
                _: SecretKind,
            ) -> SecretStoreFuture<'_, ()> {
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
            fn send(&self, _: &TransportProtocol, _: Vec<u8>) -> TransportFuture<'_> {
                Box::pin(std::future::ready(Ok(())))
            }
        }

        let result = DeRecProtocolBuilder::new(0)
            .with_channel_store(NoopChannelStore)
            .with_share_store(NoopShareStore)
            .with_secret_store(NoopSecretStore)
            .with_user_secret_store(NoopUserSecretStore)
            .with_transport(NoopTransport)
            .with_own_transport("ws://owner.example/derec")
            .with_threshold(2)
            .build();
        assert!(matches!(
            result,
            Err(crate::Error::Transport(
                crate::transport::TransportValidationError::SchemeMismatch { .. }
            ))
        ));
    }
}
