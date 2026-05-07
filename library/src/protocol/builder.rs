// SPDX-License-Identifier: Apache-2.0

//! Typestate builder for [`DeRecProtocol`].
//!
//! [`DeRecProtocolBuilder`] enforces at **compile time** that every required
//! field is supplied before [`build`](DeRecProtocolBuilder::build) is callable.
//! Calling `build()` on an incomplete builder is a type error — no runtime
//! panics or `Option` unwrapping needed.
//!
//! # Example
//!
//! ```rust,ignore
//! let protocol = DeRecProtocolBuilder::new()
//!     .with_channel_store(my_channel_store)
//!     .with_share_store(my_share_store)
//!     .with_secret_store(my_secret_store)
//!     .with_transport(my_transport)
//!     .with_own_transport(TransportProtocol { uri: "https://me.example.com".into(), .. })
//!     .build();
//! ```
//!
//! The setters may be called in any order.

use std::collections::HashMap;

use super::{DeRecChannelStore, DeRecProtocol, DeRecSecretStore, DeRecShareStore, DeRecTransport};
use derec_proto::TransportProtocol;

pub struct BuilderSlotMissingMarker;

pub struct BuilderSlotSetMarker<T>(T);

/// Typestate builder for [`DeRecProtocol`].
///
/// Start with [`DeRecProtocolBuilder::new`], call each setter, then call
/// [`build`](DeRecProtocolBuilder::build) once all slots are filled.
///
/// Each starts as [`Missing`] and becomes [`Set<T>`] after the corresponding
/// setter is called. `build()` is only available when all five are `Set<_>`.
pub struct DeRecProtocolBuilder<ChannelStore, ShareStore, SecretStore, Transport, OwnTransport> {
    channel_store: ChannelStore,
    share_store: ShareStore,
    secret_store: SecretStore,
    transport: Transport,
    own_transport: OwnTransport,
    threshold: usize,
    keep_versions_count: usize,
    secret_id: Vec<u8>,
    timeout_in_secs: u64,
    communication_info: HashMap<String, String>,
}

impl
    DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
    >
{
    /// Create a new builder with all slots empty and sensible defaults
    /// (`threshold = 3`, `keep_versions_count = 3`, `timeout_in_secs = 300`).
    pub fn new() -> Self {
        Self {
            channel_store: BuilderSlotMissingMarker,
            share_store: BuilderSlotMissingMarker,
            secret_store: BuilderSlotMissingMarker,
            transport: BuilderSlotMissingMarker,
            own_transport: BuilderSlotMissingMarker,
            threshold: 3,
            keep_versions_count: 3,
            secret_id: Vec::new(),
            timeout_in_secs: 300,
            communication_info: HashMap::new(),
        }
    }
}

impl Default
    for DeRecProtocolBuilder<
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
        BuilderSlotMissingMarker,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

impl<ChannelStore, ShareStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<ChannelStore, ShareStore, SecretStore, Transport, OwnTransport>
{
    pub fn with_threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn with_keep_versions_count(mut self, count: usize) -> Self {
        self.keep_versions_count = count;
        self
    }

    /// Application-provided secret identifier for this protocol instance.
    pub fn with_secret_id(mut self, secret_id: Vec<u8>) -> Self {
        self.secret_id = secret_id;
        self
    }

    /// Timeout in seconds for pending channels (default: 300 = 5 minutes).
    ///
    /// Channels that remain in `Pending` status beyond this duration are
    /// automatically removed along with their pairing keys.
    pub fn with_timeout_in_secs(mut self, secs: u64) -> Self {
        self.timeout_in_secs = secs;
        self
    }

    /// Key-value pairs included in `CommunicationInfo` within pairing
    /// messages (e.g. `"name"`, `"email"`, `"phone"`).
    pub fn with_communication_info(mut self, info: HashMap<String, String>) -> Self {
        self.communication_info = info;
        self
    }
}

impl<ShareStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<BuilderSlotMissingMarker, ShareStore, SecretStore, Transport, OwnTransport>
{
    pub fn with_channel_store<Cs: DeRecChannelStore>(
        self,
        store: Cs,
    ) -> DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        ShareStore,
        SecretStore,
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            channel_store: BuilderSlotSetMarker(store),
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            secret_id: self.secret_id,
            timeout_in_secs: self.timeout_in_secs,
            communication_info: self.communication_info,
        }
    }
}

impl<ChannelStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        BuilderSlotMissingMarker,
        SecretStore,
        Transport,
        OwnTransport,
    >
{
    pub fn with_share_store<Sh: DeRecShareStore>(
        self,
        store: Sh,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        BuilderSlotSetMarker<Sh>,
        SecretStore,
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            channel_store: self.channel_store,
            share_store: BuilderSlotSetMarker(store),
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            secret_id: self.secret_id,
            timeout_in_secs: self.timeout_in_secs,
            communication_info: self.communication_info,
        }
    }
}

impl<ChannelStore, ShareStore, Transport, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        BuilderSlotMissingMarker,
        Transport,
        OwnTransport,
    >
{
    pub fn with_secret_store<Ss: DeRecSecretStore>(
        self,
        store: Ss,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        BuilderSlotSetMarker<Ss>,
        Transport,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: BuilderSlotSetMarker(store),
            transport: self.transport,
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            secret_id: self.secret_id,
            timeout_in_secs: self.timeout_in_secs,
            communication_info: self.communication_info,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, OwnTransport>
    DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        BuilderSlotMissingMarker,
        OwnTransport,
    >
{
    pub fn with_transport<Tr: DeRecTransport>(
        self,
        transport: Tr,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        BuilderSlotSetMarker<Tr>,
        OwnTransport,
    > {
        DeRecProtocolBuilder {
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: BuilderSlotSetMarker(transport),
            own_transport: self.own_transport,
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            secret_id: self.secret_id,
            timeout_in_secs: self.timeout_in_secs,
            communication_info: self.communication_info,
        }
    }
}

impl<ChannelStore, ShareStore, SecretStore, Transport>
    DeRecProtocolBuilder<ChannelStore, ShareStore, SecretStore, Transport, BuilderSlotMissingMarker>
{
    pub fn with_own_transport(
        self,
        own_transport: TransportProtocol,
    ) -> DeRecProtocolBuilder<
        ChannelStore,
        ShareStore,
        SecretStore,
        Transport,
        BuilderSlotSetMarker<TransportProtocol>,
    > {
        DeRecProtocolBuilder {
            channel_store: self.channel_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: BuilderSlotSetMarker(own_transport),
            threshold: self.threshold,
            keep_versions_count: self.keep_versions_count,
            secret_id: self.secret_id,
            timeout_in_secs: self.timeout_in_secs,
            communication_info: self.communication_info,
        }
    }
}

impl<Cs: DeRecChannelStore, Sh: DeRecShareStore, Ss: DeRecSecretStore, Tr: DeRecTransport>
    DeRecProtocolBuilder<
        BuilderSlotSetMarker<Cs>,
        BuilderSlotSetMarker<Sh>,
        BuilderSlotSetMarker<Ss>,
        BuilderSlotSetMarker<Tr>,
        BuilderSlotSetMarker<TransportProtocol>,
    >
{
    pub fn build(self) -> DeRecProtocol<Cs, Sh, Ss, Tr> {
        let mut protocol = DeRecProtocol::new(
            self.channel_store.0,
            self.share_store.0,
            self.secret_store.0,
            self.transport.0,
            self.own_transport.0,
            self.threshold,
            self.keep_versions_count,
            self.secret_id,
            self.timeout_in_secs,
        );
        protocol.communication_info = self.communication_info;
        protocol
    }
}
