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
    replica_id: Option<u64>,
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
    /// Construct a new builder bound to a specific vault.
    ///
    /// `secret_id` identifies the single vault this protocol instance
    /// manages. Apps that juggle multiple vaults instantiate one
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
            replica_id: None,
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
    /// Default: `3`.
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
            replica_id: self.replica_id,
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
            replica_id: self.replica_id,
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
            replica_id: self.replica_id,
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
    /// persisting the user-facing vault contents keyed by `secret_id`.
    /// Written on every `start(FlowKind::ProtectSecret)`; read by the
    /// pair-completion auto-publish hook so freshly-paired peers
    /// receive the current vault without an explicit re-publish.
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
            replica_id: self.replica_id,
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
            replica_id: self.replica_id,
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
    /// where to send their replies. Accepts any value convertible to
    /// [`crate::transport::TransportProtocol`] — call sites can pass a
    /// `&str` (defaults the protocol to `HTTPS`) or build the typed
    /// value explicitly with
    /// [`crate::transport::TransportProtocol::new`].
    pub fn with_own_transport(
        self,
        own_transport: impl Into<crate::transport::TransportProtocol>,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        UserSecretStore,
        Transport,
        BuilderSlotSetMarker<TransportProtocol>,
    > {
        let own_transport: TransportProtocol = own_transport.into().into();
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
            replica_id: self.replica_id,
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
        BuilderSlotSetMarker<TransportProtocol>,
    >
{
    /// Consume the builder and return a fully-initialized [`DeRecProtocol`].
    ///
    /// The "all required slots set" constraint is enforced by this impl
    /// block's type bounds — the call is only reachable once every slot has
    /// been filled, so there is no runtime check and no failure mode.
    pub fn build(self) -> DeRecProtocol<Cs, Sh, Ss, Us, Tr> {
        let mut protocol = DeRecProtocol::new(
            self.secret_id,
            self.channel_store.0,
            self.share_store.0,
            self.secret_store.0,
            self.user_secret_store.0,
            self.transport.0,
            self.own_transport.0,
            self.threshold,
            self.keep_versions_count,
            self.timeout_in_secs,
        );
        protocol.communication_info = self.communication_info;
        protocol.auto_respond_on_failure = self.auto_respond_on_failure;
        protocol.unpair_ack = self.unpair_ack;
        protocol.auto_reply_to = self.auto_reply_to;
        protocol.replica_id = self.replica_id;
        protocol
    }
}
