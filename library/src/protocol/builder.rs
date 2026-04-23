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
//!     .with_contact_store(my_contact_store)
//!     .with_share_store(my_share_store)
//!     .with_secret_store(my_secret_store)
//!     .with_transport(my_transport)
//!     .with_own_transport(TransportProtocol { uri: "https://me.example.com".into(), .. })
//!     .build();
//! ```
//!
//! The setters may be called in any order.

use super::{DeRecContactStore, DeRecProtocol, DeRecSecretStore, DeRecShareStore, DeRecTransport};
use derec_proto::TransportProtocol;

// ── Typestate markers ─────────────────────────────────────────────────────────

/// Marker: this builder slot has not been filled yet.
pub struct Missing;

/// Marker: this builder slot has been filled with a value of type `T`.
pub struct Set<T>(T);

/// Typestate builder for [`DeRecProtocol`].
///
/// Start with [`DeRecProtocolBuilder::new`], call each setter, then call
/// [`build`](DeRecProtocolBuilder::build) once all slots are filled.
///
/// Each starts as [`Missing`] and becomes [`Set<T>`] after the corresponding
/// setter is called. `build()` is only available when all five are `Set<_>`.
pub struct DeRecProtocolBuilder<ContactStore, ShareStore, SecretStore, Transport, OwnTransport> {
    contact_store: ContactStore,
    share_store: ShareStore,
    secret_store: SecretStore,
    transport: Transport,
    own_transport: OwnTransport,
}

impl DeRecProtocolBuilder<Missing, Missing, Missing, Missing, Missing> {
    /// Create a new builder with all slots empty.
    pub fn new() -> Self {
        Self {
            contact_store: Missing,
            share_store: Missing,
            secret_store: Missing,
            transport: Missing,
            own_transport: Missing,
        }
    }
}

impl Default for DeRecProtocolBuilder<Missing, Missing, Missing, Missing, Missing> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ShareStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<Missing, ShareStore, SecretStore, Transport, OwnTransport>
{
    /// Set the contact store.
    pub fn with_contact_store<Cs: DeRecContactStore>(
        self,
        store: Cs,
    ) -> DeRecProtocolBuilder<Set<Cs>, ShareStore, SecretStore, Transport, OwnTransport> {
        DeRecProtocolBuilder {
            contact_store: Set(store),
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
        }
    }
}

impl<ContactStore, SecretStore, Transport, OwnTransport>
    DeRecProtocolBuilder<ContactStore, Missing, SecretStore, Transport, OwnTransport>
{
    /// Set the share store.
    pub fn with_share_store<Sh: DeRecShareStore>(
        self,
        store: Sh,
    ) -> DeRecProtocolBuilder<ContactStore, Set<Sh>, SecretStore, Transport, OwnTransport> {
        DeRecProtocolBuilder {
            contact_store: self.contact_store,
            share_store: Set(store),
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: self.own_transport,
        }
    }
}

impl<ContactStore, ShareStore, Transport, OwnTransport>
    DeRecProtocolBuilder<ContactStore, ShareStore, Missing, Transport, OwnTransport>
{
    /// Set the secret store.
    pub fn with_secret_store<Ss: DeRecSecretStore>(
        self,
        store: Ss,
    ) -> DeRecProtocolBuilder<ContactStore, ShareStore, Set<Ss>, Transport, OwnTransport> {
        DeRecProtocolBuilder {
            contact_store: self.contact_store,
            share_store: self.share_store,
            secret_store: Set(store),
            transport: self.transport,
            own_transport: self.own_transport,
        }
    }
}

impl<ContactStore, ShareStore, SecretStore, OwnTransport>
    DeRecProtocolBuilder<ContactStore, ShareStore, SecretStore, Missing, OwnTransport>
{
    /// Set the outbound transport.
    pub fn with_transport<Tr: DeRecTransport>(
        self,
        transport: Tr,
    ) -> DeRecProtocolBuilder<ContactStore, ShareStore, SecretStore, Set<Tr>, OwnTransport> {
        DeRecProtocolBuilder {
            contact_store: self.contact_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: Set(transport),
            own_transport: self.own_transport,
        }
    }
}

impl<ContactStore, ShareStore, SecretStore, Transport>
    DeRecProtocolBuilder<ContactStore, ShareStore, SecretStore, Transport, Missing>
{
    /// Set the own transport endpoint advertised to peers during pairing.
    pub fn with_own_transport(
        self,
        own_transport: TransportProtocol,
    ) -> DeRecProtocolBuilder<
        ContactStore,
        ShareStore,
        SecretStore,
        Transport,
        Set<TransportProtocol>,
    > {
        DeRecProtocolBuilder {
            contact_store: self.contact_store,
            share_store: self.share_store,
            secret_store: self.secret_store,
            transport: self.transport,
            own_transport: Set(own_transport),
        }
    }
}

impl<Cs: DeRecContactStore, Sh: DeRecShareStore, Ss: DeRecSecretStore, Tr: DeRecTransport>
    DeRecProtocolBuilder<Set<Cs>, Set<Sh>, Set<Ss>, Set<Tr>, Set<TransportProtocol>>
{
    /// Construct a [`DeRecProtocol`] from the configured slots.
    pub fn build(self) -> DeRecProtocol<Cs, Sh, Ss, Tr> {
        DeRecProtocol::new(
            self.contact_store.0,
            self.share_store.0,
            self.secret_store.0,
            self.transport.0,
            self.own_transport.0,
        )
    }
}
