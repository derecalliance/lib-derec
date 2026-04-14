// SPDX-License-Identifier: Apache-2.0

//! Higher-level protocol orchestrator for the DeRec protocol.
//!
//! This module provides [`DeRecProtocol`], a stateful orchestrator that wraps all
//! four protocol flows (pairing, sharing, verification, recovery) behind two simple
//! abstractions:
//!
//! - [`DeRecStore`] — persistent storage backend (keys, pairing state, shares)
//! - [`DeRecTransport`] — outbound message delivery
//!
//! The application feeds incoming wire bytes to [`DeRecProtocol::process`] and
//! reacts to the returned [`DeRecEvent`] values. All routing, state persistence,
//! and reply sending are handled internally.

use crate::{
    Error, Result,
    state_machine::{ChannelStateMachine, OnGetShareResponseOutput, PairingStateMachine},
    derec_message::extract_inner_message,
    primitives::pairing::{PairingError, request::{
        create_contact as create_contact_message,
        produce as produce_pairing_request_message,
    }},
    primitives::recovery::request::produce as produce_get_share_request_message,
    primitives::sharing::request::{produce as produce_store_share_request_message, split},
    types::{ChannelId, Secret, SharedKey},
    primitives::verification::request::produce as produce_verify_share_request_message,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, DeRecMessage, GetShareRequestMessage, GetShareResponseMessage, MessageBody,
    PairRequestMessage, PairResponseMessage, SenderKind, StoreShareRequestMessage,
    StoreShareResponseMessage, TransportProtocol, VerifyShareRequestMessage,
    VerifyShareResponseMessage,
};
use prost::Message;
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// Store errors
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by [`DeRecSecretStore`] implementations.
///
/// Individual Verifiable Secret Sharing shares are information-theoretically
/// secure, so "secret" here refers only to [`SharedKey`] and
/// [`PairingSecretKeyMaterial`] — the two kinds of data stored in this trait.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretStoreError {
    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// Used when the implementation cannot categorise the failure more
    /// precisely (e.g., a file-system error, an SQLite constraint, or a
    /// serialization failure).
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("secret store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors produced by [`DeRecContactStore`] implementations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ContactStoreError {
    /// A contact with the given `channel_id` already exists.
    ///
    /// Returned by [`DeRecContactStore::save`] when the implementation enforces
    /// uniqueness and the caller attempts to create a second entry for the same
    /// channel without an explicit replace/upsert path.
    #[error("contact already exists for channel {channel_id}")]
    AlreadyExists { channel_id: u64 },

    /// No contact was found for the given `channel_id`.
    ///
    /// Implementations that prefer an explicit error over returning `Ok(None)`
    /// may return this variant from [`DeRecContactStore::load`].
    #[error("contact not found for channel {channel_id}")]
    NotFound { channel_id: u64 },

    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("contact store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Errors produced by [`DeRecShareStore`] implementations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ShareStoreError {
    /// A share for `(channel_id, version)` already exists.
    ///
    /// Returned by [`DeRecShareStore::save`] when the implementation enforces
    /// immutability of versioned share slots.  The protocol treats each
    /// `(channel_id, version)` pair as write-once; overwriting a confirmed share
    /// is a protocol violation.
    #[error("share already exists for channel {channel_id} version {version}")]
    AlreadyExists { channel_id: u64, version: i32 },

    /// No share was found for `(channel_id, version)`.
    ///
    /// Implementations that prefer an explicit error over returning `Ok(None)`
    /// may return this variant from [`DeRecShareStore::load`].
    #[error("share not found for channel {channel_id} version {version}")]
    NotFound { channel_id: u64, version: i32 },

    /// An I/O or serialization error in the underlying storage backend.
    ///
    /// The original error is preserved as the `source` so that callers can
    /// inspect the full error chain via [`std::error::Error::source`].
    #[error("share store backend error")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

// ─────────────────────────────────────────────────────────────────────────────
// Traits
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// Secret store
// ─────────────────────────────────────────────────────────────────────────────

/// Discriminator for the type of secret to load, save, or remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretKind {
    /// The post-pairing symmetric channel key (`SharedKey`).
    SharedKey = 0,
    /// The ephemeral ECIES / ML-KEM key material used during pairing.
    PairingSecret = 1,
}

/// Typed container for a secret value, matching [`SecretKind`].
pub enum SecretValue {
    SharedKey(SharedKey),
    PairingSecret(PairingSecretKeyMaterial),
}

/// Keychain-grade storage for cryptographic secrets.
///
/// Only two kinds of material ever need special protection:
///
/// - [`SecretKind::SharedKey`] — the symmetric key that authenticates and
///   encrypts all post-pairing messages for a channel.
/// - [`SecretKind::PairingSecret`] — the ephemeral ECIES / ML-KEM key pair
///   that is alive only between a pairing request and its response.
///
/// Everything else (contacts, share requests, channel registry) is plain data
/// and goes through [`DeRecStore`].
///
/// # VSS guarantee
///
/// Individual Verifiable Secret Sharing shares reveal **zero** information
/// about the original secret (information-theoretic security), so share
/// storage does **not** require this trait.
///
/// # Note on `Send` bounds
///
/// The futures returned by async trait methods do not carry an explicit `Send`
/// bound. This is intentional: both the FFI adapter (single-threaded Tokio
/// runtime) and WASM (single-threaded JS event loop) do not require `Send`.
#[allow(async_fn_in_trait)]
pub trait DeRecSecretStore {
    /// Load a secret for the given channel.
    ///
    /// Returns `Ok(None)` when no secret of the requested [`SecretKind`] exists
    /// for `channel_id`.  The returned [`SecretValue`] variant will always match
    /// the requested `kind`.
    async fn load(
        &self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> std::result::Result<Option<SecretValue>, SecretStoreError>;

    /// Persist a secret for the given channel.
    ///
    /// The [`SecretKind`] is derived from the [`SecretValue`] variant, so
    /// callers do not need to pass it explicitly.  An existing entry of the
    /// same kind is silently overwritten.
    async fn save(
        &mut self,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> std::result::Result<(), SecretStoreError>;

    /// Remove a secret for the given channel.
    ///
    /// Idempotent: removing a non-existent entry is `Ok(())`.
    async fn remove(
        &mut self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> std::result::Result<(), SecretStoreError>;
}

/// Storage backend for peer contacts.
///
/// All methods are `async` so implementations may perform I/O (disk, network)
/// without blocking the executor.
///
/// # Implementor notes
///
/// - [`load`](DeRecContactStore::load) returns `Ok(None)` when no contact exists for the channel.
/// - [`save`](DeRecContactStore::save) silently replaces any previously stored contact.
/// - [`load_all`](DeRecContactStore::load_all) returns every contact known to this node; the
///   library never calls it while holding a mutable borrow, so re-entrancy is not a concern.
///
/// # Note on `Send` bounds
///
/// The futures returned by async trait methods do not carry an explicit `Send`
/// bound. This is intentional: both the FFI adapter (single-threaded Tokio
/// runtime) and WASM (single-threaded JS event loop) do not require `Send`.
/// Implementations that need `Send` futures should ensure their types are `Send`.
#[allow(async_fn_in_trait)]
pub trait DeRecContactStore {
    /// Load the peer's [`ContactMessage`] for the given channel.
    ///
    /// Returns `Ok(None)` when no contact has been stored for `channel_id`.
    ///
    /// The contact encodes everything the library needs to reach the peer:
    ///
    /// - `transport_protocol` — where to send outbound messages
    /// - public keys and nonce — needed by the responder to verify the pairing response
    ///
    /// A minimal contact containing only `transport_protocol` is sufficient for
    /// channels where the full pairing contact is not available (Owner side after
    /// receiving a `PairRequest`).
    async fn load(
        &self,
        channel_id: ChannelId,
    ) -> std::result::Result<Option<ContactMessage>, ContactStoreError>;

    /// Persist the peer's [`ContactMessage`] for the given channel.
    ///
    /// Replaces any previously stored contact for the same `channel_id`.
    async fn save(
        &mut self,
        channel_id: ChannelId,
        contact: ContactMessage,
    ) -> std::result::Result<(), ContactStoreError>;

    /// Return every [`ContactMessage`] known to this node.
    ///
    /// Used by fan-out operations such as [`DeRecProtocol::verify_shares`].
    /// The `channel_id` for each channel is available as `contact.channel_id`.
    async fn load_all(&self) -> std::result::Result<Vec<ContactMessage>, ContactStoreError>;
}

/// Storage backend for secret shares.
///
/// Stores raw encoded [`derec_proto::StoreShareRequestMessage`] protobuf bytes keyed by
/// `(channel_id, secret_id, version)`. The full request is stored rather than just the
/// share field because:
///
/// - **recovery** needs to return the whole `StoreShareRequestMessage` to the library
/// - **verification** derives the share content from `StoreShareRequestMessage.share`
///
/// Used by both sides:
///
/// - **Helper** stores the full encoded request received from the Owner.
/// - **Owner** stores an empty (`vec![]`) tracking record so that
///   [`DeRecProtocol::verify_shares`] can enumerate which helpers hold shares for
///   a given `(secret_id, version)` via [`load_channels_for_secret`].
///
/// All methods are `async` so implementations may perform I/O without blocking.
///
/// # Implementor notes
///
/// - [`load`](DeRecShareStore::load) returns `Ok(None)` when no share exists for the given key.
/// - [`save`](DeRecShareStore::save) silently replaces any previously stored share for the same key.
///
/// # Note on `Send` bounds
///
/// Same as [`DeRecContactStore`] — no `Send` bound is required.
#[allow(async_fn_in_trait)]
pub trait DeRecShareStore {
    /// Load the encoded `StoreShareRequestMessage` for `(channel_id, secret_id, version)`.
    ///
    /// Returns `Ok(None)` when no share has been stored for that key.
    async fn load(
        &self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
    ) -> std::result::Result<Option<Vec<u8>>, ShareStoreError>;

    /// Persist the encoded `StoreShareRequestMessage` for `(channel_id, secret_id, version)`.
    ///
    /// Replaces any previously stored entry for the same key.
    ///
    /// Owner-side callers may pass `vec![]` as `encoded` to record a tracking
    /// entry without storing full share bytes.
    async fn save(
        &mut self,
        channel_id: ChannelId,
        secret_id: &[u8],
        version: i32,
        encoded: Vec<u8>,
    ) -> std::result::Result<(), ShareStoreError>;

    /// Return all channel IDs that have a stored entry for `(secret_id, version)`.
    ///
    /// Used by the Owner side to fan-out verification challenges to only the helpers
    /// that participated in protecting a specific secret, rather than broadcasting
    /// to all known contacts.
    async fn load_channels_for_secret(
        &self,
        secret_id: &[u8],
        version: i32,
    ) -> std::result::Result<Vec<ChannelId>, ShareStoreError>;
}

/// Outbound transport abstraction.
///
/// The library calls `send` whenever it needs to deliver bytes to a peer.
/// The `endpoint` value comes from the `TransportProtocol` stored during pairing.
#[allow(async_fn_in_trait)]
pub trait DeRecTransport {
    async fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> Result<()>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Events
// ─────────────────────────────────────────────────────────────────────────────

/// Events emitted by [`DeRecProtocol::process`].
///
/// The application reacts to these instead of routing raw messages manually.
#[non_exhaustive]
pub enum DeRecEvent {
    /// Pairing completed — the shared key for `channel_id` is now persisted.
    PairingComplete { channel_id: ChannelId },

    /// A share was accepted and stored locally (Helper side).
    ShareStored { channel_id: ChannelId, version: i32 },

    /// A Helper confirmed it stored our share (Owner side).
    ShareConfirmed { channel_id: ChannelId, version: i32 },

    /// A Helper's verification proof checked out (Owner side).
    ShareVerified { channel_id: ChannelId, version: i32 },

    /// Recovery completed — the reconstructed secret is returned exactly once.
    SecretRecovered { secret: Vec<u8> },

    /// Well-formed message with no actionable effect (e.g. an ACK).
    NoOp,
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// Higher-level DeRec protocol orchestrator.
///
/// Generic over:
/// - `Cs` — contact storage ([`DeRecContactStore`])
/// - `Sh` — share storage ([`DeRecShareStore`])
/// - `Ss` — secret storage ([`DeRecSecretStore`])
/// - `T`  — outbound transport ([`DeRecTransport`])
///
/// The caller provides concrete implementations; the library imposes no
/// runtime or I/O requirements.
///
/// # Lifecycle
///
/// ```text
/// DeRecProtocol::new(contact_store, share_store, secret_store, transport, own_endpoint)
///   │
///   ├── create_contact / initiate_pairing  → pairing
///   ├── protect_secret                     → sharing
///   ├── verify_shares                      → verification
///   └── start_recovery                     → recovery
///
/// loop { process(incoming_bytes) → Vec<DeRecEvent> }
/// ```
pub struct DeRecProtocol<
    Cs: DeRecContactStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
> {
    pub contact_store: Cs,
    pub share_store: Sh,
    pub secret_store: Ss,
    pub transport: T,
    /// Our own transport endpoint, advertised to peers during pairing.
    pub own_transport: TransportProtocol,
    /// In-progress recovery accumulators keyed by `(secret_id, version)`.
    /// Each entry collects `GetShareResponse` messages until reconstruction succeeds.
    pending_recovery: HashMap<(Vec<u8>, i32), Vec<(GetShareResponseMessage, SharedKey)>>,
}

impl<Cs: DeRecContactStore, Sh: DeRecShareStore, Ss: DeRecSecretStore, T: DeRecTransport>
    DeRecProtocol<Cs, Sh, Ss, T>
{
    pub fn new(
        contact_store: Cs,
        share_store: Sh,
        secret_store: Ss,
        transport: T,
        own_transport: TransportProtocol,
    ) -> Self {
        Self {
            contact_store,
            share_store,
            secret_store,
            transport,
            own_transport,
            pending_recovery: HashMap::new(),
        }
    }

    /// Generate an out-of-band contact message (QR code payload, deep link, …).
    ///
    /// Either party (Owner or Helper) may call this to begin a pairing session.
    /// The returned [`ContactMessage`] should be serialized with `.encode_to_vec()`
    /// and delivered out-of-band to the peer (e.g. as a QR code or deep link).
    /// The ephemeral pairing secret is persisted automatically via `secret_store`.
    ///
    /// # Channel ID
    ///
    /// Pass `Some(id)` to use a specific channel identifier, or `None` to have
    /// the library generate a random one. The generated ID is embedded in the
    /// returned [`ContactMessage`] and should be treated as the canonical
    /// identifier for this pairing session going forward.
    pub async fn create_contact(
        &mut self,
        channel_id: Option<ChannelId>,
    ) -> Result<ContactMessage> {
        let channel_id = channel_id.unwrap_or_else(|| ChannelId(rand::random::<u64>()));
        let result = create_contact_message(channel_id, self.own_transport.clone())?;

        self.secret_store
            .save(channel_id, SecretValue::PairingSecret(result.secret_key))
            .await?;

        Ok(result.contact_message)
    }

    /// Begin pairing as the **responder** — Owner scanned a Helper's contact.
    ///
    /// Sends the pairing request via transport immediately and returns.
    /// The pairing response will arrive later via [`process`].
    pub async fn initiate_pairing(
        &mut self,
        kind: SenderKind,
        contact: ContactMessage,
    ) -> Result<()> {
        let channel_id = ChannelId(contact.channel_id);

        let endpoint = contact
            .transport_protocol
            .clone()
            .ok_or(Error::InvalidInput(
                "contact message has no transport endpoint",
            ))?;

        let result = produce_pairing_request_message(kind, self.own_transport.clone(), &contact)?;

        self.secret_store
            .save(channel_id, SecretValue::PairingSecret(result.secret_key))
            .await?;
        // `result.initiator_contact_message` is the peer's contact (a clone of the
        // contact passed in), which already embeds `transport_protocol`. Store it
        // once rather than storing transport and contact separately.
        self.contact_store
            .save(channel_id, result.initiator_contact_message)
            .await?;

        self.transport.send(&endpoint, result.envelope).await
    }

    /// Split a secret and send one share to each of the specified Helpers.
    ///
    /// The shared key and transport endpoint for each Helper are loaded from
    /// the stores automatically — callers only need to specify which channels
    /// should receive a share and the reconstruction threshold.
    ///
    /// Helpers that have no paired `SharedKey` in the secret store are silently
    /// skipped (they are not yet paired and cannot receive an encrypted share).
    pub async fn protect_secret(
        &mut self,
        secret: Secret,
        threshold: usize,
        helpers: &[ChannelId],
    ) -> Result<()> {
        let result = split(helpers, &secret.id, secret.version, &secret.data, threshold)?;

        for channel_id in helpers {
            let Some(committed_share) = result.shares.get(channel_id) else {
                continue;
            };

            let Some(SecretValue::SharedKey(shared_key)) = self
                .secret_store
                .load(*channel_id, SecretKind::SharedKey)
                .await?
            else {
                continue;
            };

            let endpoint = self.peer_endpoint(*channel_id).await?;

            let msg = produce_store_share_request_message(
                *channel_id,
                secret.version,
                &secret.id,
                committed_share,
                &[],
                "",
                &shared_key,
            )?;
            self.transport.send(&endpoint, msg.envelope).await?;

            // Owner-side tracking: record that this channel holds a share for
            // (secret_id, version) so verify_shares can enumerate them.
            self.share_store
                .save(*channel_id, &secret.id, secret.version, vec![])
                .await?;
        }
        Ok(())
    }

    /// Send a verification challenge to every Helper that holds a share for
    /// `(secret_id, version)`.
    ///
    /// Only channels that participated in protecting this specific secret receive
    /// the challenge — not all known contacts.
    pub async fn verify_shares(&mut self, secret_id: &[u8], version: i32) -> Result<()> {
        let channel_ids = self
            .share_store
            .load_channels_for_secret(secret_id, version)
            .await?;

        for channel_id in channel_ids {
            let Some(SecretValue::SharedKey(shared_key)) = self
                .secret_store
                .load(channel_id, SecretKind::SharedKey)
                .await?
            else {
                continue;
            };
            let endpoint = self.peer_endpoint(channel_id).await?;
            let msg =
                produce_verify_share_request_message(channel_id, secret_id, version, &shared_key)?;
            self.transport.send(&endpoint, msg.envelope).await?;
        }
        Ok(())
    }

    /// Pair in recovery mode with the supplied Helpers, then request shares.
    ///
    /// [`DeRecEvent::SecretRecovered`] is emitted from [`process`] once a
    /// threshold of share responses have been collected and reconstruction succeeds.
    pub async fn start_recovery(
        &mut self,
        kind: SenderKind,
        secret_id: Vec<u8>,
        version: i32,
        helpers: Vec<ContactMessage>,
    ) -> Result<()> {
        // Register the recovery context so process() knows to accumulate shares.
        self.pending_recovery
            .insert((secret_id, version), Vec::new());

        for contact in helpers {
            self.initiate_pairing(kind, contact).await?;
        }

        Ok(())
    }

    // ── Single inbound entry point ───────────────────────────────────────────

    /// Feed any incoming wire bytes here regardless of which flow they belong to.
    ///
    /// The library:
    ///
    /// 1. Decodes the outer [`DeRecMessage`] envelope to read `channel_id`
    /// 2. Looks up state for that channel in [`DeRecStore`]
    /// 3. Routes to the appropriate flow handler
    /// 4. Persists updated state
    /// 5. Sends any required replies via [`DeRecTransport`]
    /// 6. Returns the events the application should react to
    pub async fn process(&mut self, message: &[u8]) -> Result<Vec<DeRecEvent>> {
        let envelope = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
        let channel_id = ChannelId(envelope.channel_id);

        // TODO: every inner message uses Any for deserialization and has a type_url.
        //       So flow recognition should be based on message types rather than on finding or not
        //       a key.

        // Route 1: post-pairing channel message (symmetric encryption)
        if let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        {
            return self
                .handle_channel_message(message, channel_id, &shared_key)
                .await;
        }

        // Route 2: in-progress pairing message (asymmetric ECIES encryption)
        if let Some(SecretValue::PairingSecret(pairing_secret)) = self
            .secret_store
            .load(channel_id, SecretKind::PairingSecret)
            .await?
        {
            return self
                .handle_pairing_message(message, channel_id, &pairing_secret)
                .await;
        }

        Err(Error::InvalidInput(
            "unknown channel_id: no shared key or pairing secret found",
        ))
    }

    // ── Internal: pairing message handler ───────────────────────────────────

    /// Decrypts the pairing envelope and dispatches to the appropriate transition handler.
    async fn handle_pairing_message(
        &mut self,
        message: &[u8],
        channel_id: ChannelId,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> Result<Vec<DeRecEvent>> {
        let outer = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
        let plaintext = derec_cryptography::pairing::envelope::decrypt(
            &outer.message,
            &pairing_secret.ecies_secret_key,
        )
        .map_err(PairingError::PairingEncryption)?;

        match MessageBody::decode_from_vec(&plaintext).map_err(Error::ProtobufDecode)? {
            MessageBody::PairRequest(request) => {
                self.on_pair_request(channel_id, &request, pairing_secret)
                    .await
            }
            MessageBody::PairResponse(response) => {
                self.on_pair_response(channel_id, &response, pairing_secret)
                    .await
            }
            _ => Err(Error::Invariant(
                "unexpected MessageBody variant in pairing message",
            )),
        }
    }

    /// Owner side: received a Helper's pairing request, produce and send a response.
    ///
    /// We created the contact. The Helper scanned it and sent a `PairRequest`
    /// encrypted to our ECIES public key.
    async fn on_pair_request(
        &mut self,
        channel_id: ChannelId,
        request: &PairRequestMessage,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> Result<Vec<DeRecEvent>> {
        let out = PairingStateMachine::on_pair_request(request, pairing_secret)?;

        self.secret_store
            .save(channel_id, SecretValue::SharedKey(out.shared_key))
            .await?;

        // On the Owner side we receive a PairRequest but not a full ContactMessage.
        // Build a minimal contact carrying just the peer's transport endpoint so
        // contact_store loads work uniformly everywhere.
        self.contact_store
            .save(
                channel_id,
                ContactMessage {
                    transport_protocol: Some(out.peer_endpoint.clone()),
                    ..Default::default()
                },
            )
            .await?;

        self.secret_store
            .remove(channel_id, SecretKind::PairingSecret)
            .await?;

        self.transport
            .send(&out.peer_endpoint, out.response_envelope)
            .await?;

        Ok(vec![DeRecEvent::PairingComplete { channel_id }])
    }

    /// Helper side: received the Owner's pairing response, finalize the shared key.
    ///
    /// We sent the pairing request. The Owner replied with a `PairResponse`
    /// encrypted to our ECIES public key.
    async fn on_pair_response(
        &mut self,
        channel_id: ChannelId,
        response: &PairResponseMessage,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> Result<Vec<DeRecEvent>> {
        let contact = self
            .contact_store
            .load(channel_id)
            .await?
            .ok_or(Error::InvalidInput("no contact stored for channel"))?;

        let endpoint = contact
            .transport_protocol
            .clone()
            .ok_or(Error::InvalidInput(
                "no transport endpoint in stored contact",
            ))?;

        let out = PairingStateMachine::on_pair_response(&contact, response, pairing_secret)?;

        self.secret_store
            .save(channel_id, SecretValue::SharedKey(out.shared_key))
            .await?;
        self.secret_store
            .remove(channel_id, SecretKind::PairingSecret)
            .await?;

        // If we paired as part of recovery, send GetShareRequest now that
        // we have a shared key.
        let recovery_keys: Vec<(Vec<u8>, i32)> = self.pending_recovery.keys().cloned().collect();

        for (secret_id, version) in recovery_keys {
            let msg = produce_get_share_request_message(
                channel_id,
                &secret_id,
                version,
                &out.shared_key,
            )?;
            self.transport.send(&endpoint, msg.envelope).await?;
        }

        Ok(vec![DeRecEvent::PairingComplete { channel_id }])
    }

    // ── Internal: post-pairing channel message handler ───────────────────────

    /// Decrypts the channel envelope and dispatches to the appropriate handler.
    async fn handle_channel_message(
        &mut self,
        message: &[u8],
        channel_id: ChannelId,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let envelope = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
        let inner = extract_inner_message(&envelope.message, shared_key)?;

        match inner {
            MessageBody::StoreShareRequest(request) => {
                self.on_store_share_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::StoreShareResponse(response) => {
                self.on_store_share_response(channel_id, &response).await
            }
            MessageBody::VerifyShareRequest(request) => {
                self.on_verify_share_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::VerifyShareResponse(response) => {
                self.on_verify_share_response(channel_id, &response).await
            }
            MessageBody::GetShareRequest(request) => {
                self.on_get_share_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::GetShareResponse(response) => {
                self.on_get_share_response(channel_id, &response, shared_key)
                    .await
            }
            _ => Err(Error::Invariant(
                "unexpected MessageBody variant in channel message",
            )),
        }
    }

    // ── Sharing ───────────────────────────────────────────────────────────────

    /// Helper side: received a share storage request, persist and acknowledge.
    async fn on_store_share_request(
        &mut self,
        channel_id: ChannelId,
        request: &StoreShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let out = ChannelStateMachine::on_store_share_request(channel_id, request, shared_key)?;

        self.share_store
            .save(channel_id, &out.secret_id, out.version, out.encoded_request)
            .await?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport
            .send(&endpoint, out.response_envelope)
            .await?;

        Ok(vec![DeRecEvent::ShareStored {
            channel_id,
            version: out.version,
        }])
    }

    /// Owner side: received a share storage confirmation.
    async fn on_store_share_response(
        &mut self,
        channel_id: ChannelId,
        response: &StoreShareResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let out = ChannelStateMachine::on_store_share_response(response)?;

        Ok(vec![DeRecEvent::ShareConfirmed {
            channel_id,
            version: out.version,
        }])
    }

    // ── Verification ──────────────────────────────────────────────────────────

    /// Helper side: received a verification challenge, load share and respond.
    async fn on_verify_share_request(
        &mut self,
        channel_id: ChannelId,
        request: &VerifyShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let encoded = self
            .share_store
            .load(channel_id, &request.secret_id, request.version)
            .await?
            .ok_or(Error::InvalidInput(
                "no stored share for verification request",
            ))?;
        let stored =
            StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

        let out = ChannelStateMachine::on_verify_share_request(
            channel_id,
            request,
            shared_key,
            &stored.share,
        )?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport
            .send(&endpoint, out.response_envelope)
            .await?;

        Ok(vec![DeRecEvent::NoOp])
    }

    /// Owner side: received a verification proof, validate it.
    async fn on_verify_share_response(
        &mut self,
        channel_id: ChannelId,
        response: &VerifyShareResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let out = ChannelStateMachine::on_verify_share_response(response)?;

        Ok(vec![DeRecEvent::ShareVerified {
            channel_id,
            version: out.version,
        }])
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    /// Helper side: received a recovery share request, load share and respond.
    async fn on_get_share_request(
        &mut self,
        channel_id: ChannelId,
        request: &GetShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let encoded = self
            .share_store
            .load(channel_id, &request.secret_id, request.share_version)
            .await?
            .ok_or(Error::InvalidInput("no stored share for recovery request"))?;
        let stored =
            StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

        let out =
            ChannelStateMachine::on_get_share_request(channel_id, request, &stored, shared_key)?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport
            .send(&endpoint, out.response_envelope)
            .await?;

        Ok(vec![DeRecEvent::NoOp])
    }

    /// Owner side: received a recovery share, accumulate and attempt reconstruction.
    async fn on_get_share_response(
        &mut self,
        _channel_id: ChannelId,
        response: &GetShareResponseMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let mut events = Vec::new();

        // Add this response to every in-progress recovery context and attempt
        // reconstruction. Each context that reaches the threshold emits SecretRecovered.
        let keys: Vec<(Vec<u8>, i32)> = self.pending_recovery.keys().cloned().collect();
        for key in keys {
            let (ref secret_id, version) = key;
            let bucket = self.pending_recovery.get_mut(&key).unwrap();
            bucket.push((response.clone(), *shared_key));

            if let Some(OnGetShareResponseOutput { secret }) =
                ChannelStateMachine::on_get_share_response(secret_id, version, bucket)?
            {
                self.pending_recovery.remove(&key);
                events.push(DeRecEvent::SecretRecovered { secret });
            }
        }

        if events.is_empty() {
            events.push(DeRecEvent::NoOp);
        }
        Ok(events)
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Load the peer's transport endpoint for `channel_id` from the contact store.
    async fn peer_endpoint(&mut self, channel_id: ChannelId) -> Result<TransportProtocol> {
        self.contact_store
            .load(channel_id)
            .await?
            .and_then(|c| c.transport_protocol)
            .ok_or(Error::InvalidInput("no transport endpoint for channel"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FFI layer
// ─────────────────────────────────────────────────────────────────────────────
//
// Exposes DeRecProtocol over a C ABI for non-Rust consumers (.Net, etc.).
//
// Design:
//   - DeRecStore and DeRecTransport are implemented using C function-pointer
//     callbacks supplied by the host at construction time.
//   - The protocol handle is an opaque heap-allocated struct that owns the
//     Tokio runtime.  All async protocol methods are called via block_on().
//   - Results that cannot be expressed as plain C values are serialized to
//     protobuf bytes and returned as DeRecBuffer.
//   - Events are returned as a length-prefixed binary list (see encode_events).

#[cfg(not(target_arch = "wasm32"))]
pub mod ffi {
    use super::*;
    use crate::ffi::common::{
        DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, vec_into_buffer,
    };
    use tokio::runtime::Runtime;

    // ── Callback type aliases ────────────────────────────────────────────────
    //
    // Return code convention (all callbacks):
    //   0  → Ok / found
    //   1  → Ok / not found  (load_ variants only)
    //  <0  → error

    // Secret store callbacks.
    // `kind`: 0 = SharedKey, 1 = PairingSecret
    // load: callback heap-allocates via malloc; Rust reads and frees via libc::free.
    type LoadSecretFn =
        extern "C" fn(channel_id: u64, kind: i32, out: *mut *mut u8, out_len: *mut usize) -> i32;
    type SaveSecretFn =
        extern "C" fn(channel_id: u64, kind: i32, data: *const u8, data_len: usize) -> i32;
    type RemoveSecretFn = extern "C" fn(channel_id: u64, kind: i32) -> i32;

    // Contact store callbacks.
    // Contact is serialized as a `ContactMessage` protobuf.
    // load / load_all: callback heap-allocates via malloc; Rust reads and frees via libc::free.
    type LoadContactFn =
        extern "C" fn(channel_id: u64, out: *mut *mut u8, out_len: *mut usize) -> i32;
    type SaveContactFn =
        extern "C" fn(channel_id: u64, contact: *const u8, contact_len: usize) -> i32;
    // load_all returns a flat buffer: u32 count, then count × (u32 len, bytes).
    type LoadAllContactsFn = extern "C" fn(out: *mut *mut u8, out_len: *mut usize) -> i32;

    // Share store callbacks.
    // Keyed by (channel_id, secret_id, version).
    // load / load_channels_for_secret: callback heap-allocates via malloc; Rust reads and frees.
    type LoadShareFn = extern "C" fn(
        channel_id: u64,
        secret_id_ptr: *const u8,
        secret_id_len: usize,
        version: i32,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    type SaveShareFn = extern "C" fn(
        channel_id: u64,
        secret_id_ptr: *const u8,
        secret_id_len: usize,
        version: i32,
        data: *const u8,
        data_len: usize,
    ) -> i32;
    // Returns a flat buffer: u32 count (LE), then count × u64 channel_id (LE).
    type LoadChannelsForSecretFn = extern "C" fn(
        secret_id_ptr: *const u8,
        secret_id_len: usize,
        version: i32,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32;
    type SendFn = extern "C" fn(
        endpoint: *const u8,
        endpoint_len: usize,
        msg: *const u8,
        msg_len: usize,
    ) -> i32;

    // ── Callback structs ─────────────────────────────────────────────────────

    /// `#[repr(C)]` struct of function pointers implementing [`DeRecSecretStore`] callbacks.
    ///
    /// A single `load_secret` / `save_secret` / `remove_secret` triple replaces
    /// the old per-kind callbacks. The `kind` parameter carries the [`SecretKind`]
    /// discriminant (0 = SharedKey, 1 = PairingSecret).
    ///
    /// The host (C#) fills this struct and passes it to [`derec_protocol_create`].
    /// All function pointers must remain valid for the lifetime of the handle.
    #[repr(C)]
    pub struct FfiSecretStoreCallbacks {
        pub load_secret: LoadSecretFn,
        pub save_secret: SaveSecretFn,
        pub remove_secret: RemoveSecretFn,
    }

    /// `#[repr(C)]` struct of function pointers implementing [`DeRecStore`] callbacks.
    ///
    /// The host (C#) fills this struct and passes it to [`derec_protocol_create`].
    /// All function pointers must remain valid for the lifetime of the handle.
    /// `#[repr(C)]` struct of function pointers implementing [`DeRecContactStore`] callbacks.
    ///
    /// The host (C#) fills this struct and passes it to [`derec_protocol_create`].
    /// All function pointers must remain valid for the lifetime of the handle.
    ///
    /// # Memory contract for load callbacks
    ///
    /// Both `load` and `load_all` heap-allocate their output with a
    /// `malloc`-compatible allocator. Rust reads the bytes and frees the pointer
    /// via `libc::free`, so the C# side must allocate with `NativeMemory.Alloc`
    /// or an equivalent.
    #[repr(C)]
    pub struct FfiContactStoreCallbacks {
        /// Load the peer's [`ContactMessage`] (serialized protobuf) for `channel_id`.
        ///
        /// Returns `0` (found), `1` (not found), or a negative value on error.
        pub load: LoadContactFn,
        /// Persist the peer's [`ContactMessage`] for `channel_id`. Returns `0` on success.
        pub save: SaveContactFn,
        /// Return all contacts as a flat heap-allocated buffer.
        ///
        /// Buffer format: `u32 count` (little-endian), then `count` items of
        /// `u32 len` (little-endian) followed by `len` bytes of serialized
        /// `ContactMessage` protobuf. Returns `0` on success, negative on error.
        pub load_all: LoadAllContactsFn,
    }

    /// `#[repr(C)]` struct of function pointers implementing [`DeRecShareStore`] callbacks.
    ///
    /// The host (C#) fills this struct and passes it to [`derec_protocol_create`].
    /// All function pointers must remain valid for the lifetime of the handle.
    #[repr(C)]
    pub struct FfiShareStoreCallbacks {
        /// Load the encoded `StoreShareRequestMessage` for `(channel_id, secret_id, version)`.
        ///
        /// Heap-allocates on success. Returns `0` (found), `1` (not found), or negative on error.
        pub load: LoadShareFn,
        /// Persist the encoded `StoreShareRequestMessage`. Returns `0` on success.
        pub save: SaveShareFn,
        /// Return all channel IDs that have an entry for `(secret_id, version)`.
        ///
        /// Output buffer format: `u32 count` (LE), then `count` × `u64 channel_id` (LE).
        /// Heap-allocates on success. Returns `0` on success, or negative on error.
        pub load_channels_for_secret: LoadChannelsForSecretFn,
    }

    /// `#[repr(C)]` struct of function pointers implementing [`DeRecTransport`] callbacks.
    #[repr(C)]
    pub struct FfiTransportCallbacks {
        pub send: SendFn,
    }

    // ── Rust-side adapter structs ─────────────────────────────────────────────

    struct FfiSecretStore(FfiSecretStoreCallbacks);
    struct FfiContactStore(FfiContactStoreCallbacks);
    struct FfiShareStore(FfiShareStoreCallbacks);
    struct FfiTransport(FfiTransportCallbacks);

    // Helper: copy bytes returned by a `LoadXxxFn` into a Vec<u8> and free.
    // The callback writes a heap pointer + length into `out`/`out_len`.
    // Ownership of that memory is transferred to this helper, which copies and frees.
    // The C# side must allocate with a malloc-compatible allocator (e.g. NativeMemory.Alloc).
    fn read_ffi_alloc(ptr: *mut u8, len: usize) -> Vec<u8> {
        let data = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        libc_free(ptr as *mut std::ffi::c_void);
        data
    }

    unsafe extern "C" {
        fn free(ptr: *mut std::ffi::c_void);
    }

    fn libc_free(ptr: *mut std::ffi::c_void) {
        if !ptr.is_null() {
            unsafe { free(ptr) }
        }
    }

    impl DeRecSecretStore for FfiSecretStore {
        async fn load(
            &self,
            channel_id: ChannelId,
            kind: SecretKind,
        ) -> std::result::Result<Option<SecretValue>, SecretStoreError> {
            let kind_i32 = kind as i32;
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            match (self.0.load_secret)(channel_id.0, kind_i32, &mut ptr, &mut len) {
                0 => {
                    let bytes = read_ffi_alloc(ptr, len);
                    let value = match kind {
                        SecretKind::SharedKey => {
                            let arr: SharedKey = bytes.try_into().map_err(|_| {
                                SecretStoreError::Backend(Box::new(std::io::Error::other(
                                    "shared key must be 32 bytes",
                                )))
                            })?;
                            SecretValue::SharedKey(arr)
                        }
                        SecretKind::PairingSecret => {
                            let sk = deserialize_pairing_secret(&bytes).map_err(|_| {
                                SecretStoreError::Backend(Box::new(std::io::Error::other(
                                    "invalid pairing secret bytes",
                                )))
                            })?;
                            SecretValue::PairingSecret(sk)
                        }
                    };
                    Ok(Some(value))
                }
                1 => Ok(None),
                _ => Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                    "load_secret callback failed",
                )))),
            }
        }

        async fn save(
            &mut self,
            channel_id: ChannelId,
            value: SecretValue,
        ) -> std::result::Result<(), SecretStoreError> {
            let (kind_i32, bytes) = match value {
                SecretValue::SharedKey(key) => (SecretKind::SharedKey as i32, key.to_vec()),
                SecretValue::PairingSecret(sk) => (
                    SecretKind::PairingSecret as i32,
                    serialize_pairing_secret(&sk),
                ),
            };
            match (self.0.save_secret)(channel_id.0, kind_i32, bytes.as_ptr(), bytes.len()) {
                0 => Ok(()),
                _ => Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                    "save_secret callback failed",
                )))),
            }
        }

        async fn remove(
            &mut self,
            channel_id: ChannelId,
            kind: SecretKind,
        ) -> std::result::Result<(), SecretStoreError> {
            match (self.0.remove_secret)(channel_id.0, kind as i32) {
                0 => Ok(()),
                _ => Err(SecretStoreError::Backend(Box::new(std::io::Error::other(
                    "remove_secret callback failed",
                )))),
            }
        }
    }

    impl DeRecContactStore for FfiContactStore {
        async fn load(
            &self,
            channel_id: ChannelId,
        ) -> std::result::Result<Option<ContactMessage>, ContactStoreError> {
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            match (self.0.load)(channel_id.0, &mut ptr, &mut len) {
                0 => {
                    let bytes = read_ffi_alloc(ptr, len);
                    let contact = ContactMessage::decode(bytes.as_slice())
                        .map_err(|e| ContactStoreError::Backend(Box::new(e)))?;
                    Ok(Some(contact))
                }
                1 => Ok(None),
                _ => Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                    "contact load callback failed",
                )))),
            }
        }

        async fn save(
            &mut self,
            channel_id: ChannelId,
            contact: ContactMessage,
        ) -> std::result::Result<(), ContactStoreError> {
            let bytes = contact.encode_to_vec();
            match (self.0.save)(channel_id.0, bytes.as_ptr(), bytes.len()) {
                0 => Ok(()),
                _ => Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                    "contact save callback failed",
                )))),
            }
        }

        async fn load_all(&self) -> std::result::Result<Vec<ContactMessage>, ContactStoreError> {
            // The callback heap-allocates a flat buffer:
            //   u32 count (LE), then count × (u32 len (LE), bytes).
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut total_len: usize = 0;
            match (self.0.load_all)(&mut ptr, &mut total_len) {
                0 => {}
                _ => {
                    return Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                        "contact load_all callback failed",
                    ))));
                }
            }
            if ptr.is_null() || total_len == 0 {
                return Ok(Vec::new());
            }
            let buf = read_ffi_alloc(ptr, total_len);
            let mut cursor = buf.as_slice();

            // Read u32 count.
            if cursor.len() < 4 {
                return Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                    "load_all buffer too short for count",
                ))));
            }
            let count = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
            cursor = &cursor[4..];

            let mut contacts = Vec::with_capacity(count);
            for _ in 0..count {
                if cursor.len() < 4 {
                    return Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                        "load_all buffer truncated (len field)",
                    ))));
                }
                let item_len = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
                cursor = &cursor[4..];
                if cursor.len() < item_len {
                    return Err(ContactStoreError::Backend(Box::new(std::io::Error::other(
                        "load_all buffer truncated (item bytes)",
                    ))));
                }
                let contact = ContactMessage::decode(&cursor[..item_len])
                    .map_err(|e| ContactStoreError::Backend(Box::new(e)))?;
                contacts.push(contact);
                cursor = &cursor[item_len..];
            }
            Ok(contacts)
        }
    }

    impl DeRecShareStore for FfiShareStore {
        async fn load(
            &self,
            channel_id: ChannelId,
            secret_id: &[u8],
            version: i32,
        ) -> std::result::Result<Option<Vec<u8>>, ShareStoreError> {
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut len: usize = 0;
            match (self.0.load)(
                channel_id.0,
                secret_id.as_ptr(),
                secret_id.len(),
                version,
                &mut ptr,
                &mut len,
            ) {
                0 => Ok(Some(read_ffi_alloc(ptr, len))),
                1 => Ok(None),
                _ => Err(ShareStoreError::Backend(Box::new(std::io::Error::other(
                    "share load callback failed",
                )))),
            }
        }

        async fn save(
            &mut self,
            channel_id: ChannelId,
            secret_id: &[u8],
            version: i32,
            encoded: Vec<u8>,
        ) -> std::result::Result<(), ShareStoreError> {
            match (self.0.save)(
                channel_id.0,
                secret_id.as_ptr(),
                secret_id.len(),
                version,
                encoded.as_ptr(),
                encoded.len(),
            ) {
                0 => Ok(()),
                _ => Err(ShareStoreError::Backend(Box::new(std::io::Error::other(
                    "share save callback failed",
                )))),
            }
        }

        async fn load_channels_for_secret(
            &self,
            secret_id: &[u8],
            version: i32,
        ) -> std::result::Result<Vec<ChannelId>, ShareStoreError> {
            let mut ptr: *mut u8 = std::ptr::null_mut();
            let mut total_len: usize = 0;
            match (self.0.load_channels_for_secret)(
                secret_id.as_ptr(),
                secret_id.len(),
                version,
                &mut ptr,
                &mut total_len,
            ) {
                0 => {}
                _ => {
                    return Err(ShareStoreError::Backend(Box::new(std::io::Error::other(
                        "load_channels_for_secret callback failed",
                    ))));
                }
            }
            if ptr.is_null() || total_len == 0 {
                return Ok(Vec::new());
            }
            let buf = read_ffi_alloc(ptr, total_len);
            let mut cursor = buf.as_slice();

            if cursor.len() < 4 {
                return Err(ShareStoreError::Backend(Box::new(std::io::Error::other(
                    "load_channels_for_secret buffer too short for count",
                ))));
            }
            let count = u32::from_le_bytes(cursor[..4].try_into().unwrap()) as usize;
            cursor = &cursor[4..];

            let mut channels = Vec::with_capacity(count);
            for _ in 0..count {
                if cursor.len() < 8 {
                    return Err(ShareStoreError::Backend(Box::new(std::io::Error::other(
                        "load_channels_for_secret buffer truncated",
                    ))));
                }
                let id = u64::from_le_bytes(cursor[..8].try_into().unwrap());
                channels.push(ChannelId(id));
                cursor = &cursor[8..];
            }
            Ok(channels)
        }
    }

    impl DeRecTransport for FfiTransport {
        async fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> Result<()> {
            let ep = endpoint.encode_to_vec();
            match (self.0.send)(ep.as_ptr(), ep.len(), message.as_ptr(), message.len()) {
                0 => Ok(()),
                _ => Err(Error::InvalidInput("transport send callback failed")),
            }
        }
    }

    // ── Pairing secret serialization (reuse format from ffi/pairing.rs) ──────

    fn serialize_pairing_secret(sk: &PairingSecretKeyMaterial) -> Vec<u8> {
        use crate::ffi::common::{write_len_prefixed, write_optional_len_prefixed};
        let mut out = Vec::new();
        write_optional_len_prefixed(&mut out, sk.mlkem_decapsulation_key.as_deref());
        write_optional_len_prefixed(
            &mut out,
            sk.mlkem_shared_secret.as_ref().map(|x| x.as_slice()),
        );
        write_len_prefixed(&mut out, &sk.ecies_secret_key);
        out
    }

    fn deserialize_pairing_secret(
        bytes: &[u8],
    ) -> std::result::Result<PairingSecretKeyMaterial, String> {
        use crate::ffi::common::{read_len_prefixed_vec, read_optional_len_prefixed_vec};
        let mut input = bytes;
        let mlkem_decapsulation_key = read_optional_len_prefixed_vec(&mut input)?;
        let mlkem_shared_secret = match read_optional_len_prefixed_vec(&mut input)? {
            Some(v) => {
                let arr: [u8; 32] = v
                    .try_into()
                    .map_err(|_| "mlkem_shared_secret must be 32 bytes".to_string())?;
                Some(arr)
            }
            None => None,
        };
        let ecies_secret_key = read_len_prefixed_vec(&mut input)?;
        Ok(PairingSecretKeyMaterial {
            mlkem_decapsulation_key,
            mlkem_shared_secret,
            ecies_secret_key,
        })
    }

    // ── Event serialization ───────────────────────────────────────────────────
    //
    // Binary format (little-endian):
    //
    //   u32  event_count
    //   for each event:
    //     u8   tag      (0=PairingComplete, 1=ShareStored, 2=ShareConfirmed,
    //                    3=ShareVerified,   4=SecretRecovered, 255=NoOp)
    //     u32  payload_len
    //     [u8] payload  (event-specific; see below)
    //
    // Payloads:
    //   PairingComplete  → u64 channel_id
    //   ShareStored      → u64 channel_id, i32 version
    //   ShareConfirmed   → u64 channel_id, i32 version
    //   ShareVerified    → u64 channel_id, i32 version
    //   SecretRecovered  → raw secret bytes
    //   NoOp             → empty

    fn encode_events(events: &[DeRecEvent]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(events.len() as u32).to_le_bytes());
        for ev in events {
            match ev {
                DeRecEvent::PairingComplete { channel_id } => {
                    let payload = channel_id.0.to_le_bytes();
                    out.push(0u8);
                    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    out.extend_from_slice(&payload);
                }
                DeRecEvent::ShareStored {
                    channel_id,
                    version,
                } => {
                    let mut payload = channel_id.0.to_le_bytes().to_vec();
                    payload.extend_from_slice(&version.to_le_bytes());
                    out.push(1u8);
                    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    out.extend_from_slice(&payload);
                }
                DeRecEvent::ShareConfirmed {
                    channel_id,
                    version,
                } => {
                    let mut payload = channel_id.0.to_le_bytes().to_vec();
                    payload.extend_from_slice(&version.to_le_bytes());
                    out.push(2u8);
                    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    out.extend_from_slice(&payload);
                }
                DeRecEvent::ShareVerified {
                    channel_id,
                    version,
                } => {
                    let mut payload = channel_id.0.to_le_bytes().to_vec();
                    payload.extend_from_slice(&version.to_le_bytes());
                    out.push(3u8);
                    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                    out.extend_from_slice(&payload);
                }
                DeRecEvent::SecretRecovered { secret } => {
                    out.push(4u8);
                    out.extend_from_slice(&(secret.len() as u32).to_le_bytes());
                    out.extend_from_slice(secret);
                }
                DeRecEvent::NoOp => {
                    out.push(255u8);
                    out.extend_from_slice(&0u32.to_le_bytes());
                }
            }
        }
        out
    }

    // ── Protocol handle ───────────────────────────────────────────────────────

    /// Opaque protocol handle returned to C callers.
    pub struct DeRecProtocolHandle {
        runtime: Runtime,
        protocol: DeRecProtocol<FfiContactStore, FfiShareStore, FfiSecretStore, FfiTransport>,
    }

    // ── FFI result structs ────────────────────────────────────────────────────

    /// Result of [`derec_protocol_create_contact`].
    #[repr(C)]
    pub struct CreateContactResult {
        pub status: DeRecStatus,
        /// Serialized `ContactMessage` protobuf bytes.
        pub contact_bytes: DeRecBuffer,
    }

    /// Result of [`derec_protocol_process`] and all other action functions.
    #[repr(C)]
    pub struct ProcessResult {
        pub status: DeRecStatus,
        /// Encoded event list (see `encode_events` format).
        pub events: DeRecBuffer,
    }

    // ── Public FFI surface ────────────────────────────────────────────────────

    /// Create a new protocol handle.
    ///
    /// # Safety
    ///
    /// - All function pointers in `contact_store`, `share_store`, `secret_store`,
    ///   and `transport` must remain valid for the lifetime of the returned handle.
    /// - `own_endpoint_ptr` must point to `own_endpoint_len` readable bytes
    ///   of a serialized `TransportProtocol` protobuf.
    /// - The caller must eventually call [`derec_protocol_destroy`].
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_create(
        contact_store: FfiContactStoreCallbacks,
        share_store: FfiShareStoreCallbacks,
        secret_store: FfiSecretStoreCallbacks,
        transport: FfiTransportCallbacks,
        own_endpoint_ptr: *const u8,
        own_endpoint_len: usize,
    ) -> *mut DeRecProtocolHandle {
        if own_endpoint_ptr.is_null() {
            return std::ptr::null_mut();
        }

        let own_endpoint_bytes =
            unsafe { std::slice::from_raw_parts(own_endpoint_ptr, own_endpoint_len) };

        let own_transport = match TransportProtocol::decode(own_endpoint_bytes) {
            Ok(tp) => tp,
            Err(_) => return std::ptr::null_mut(),
        };

        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(_) => return std::ptr::null_mut(),
        };

        let protocol = DeRecProtocol::new(
            FfiContactStore(contact_store),
            FfiShareStore(share_store),
            FfiSecretStore(secret_store),
            FfiTransport(transport),
            own_transport,
        );

        Box::into_raw(Box::new(DeRecProtocolHandle { runtime, protocol }))
    }

    /// Destroy a protocol handle and release all associated resources.
    ///
    /// # Safety
    ///
    /// `handle` must have been returned by [`derec_protocol_create`] and must
    /// not be used after this call.
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_destroy(handle: *mut DeRecProtocolHandle) {
        if !handle.is_null() {
            unsafe { drop(Box::from_raw(handle)) };
        }
    }

    /// Feed incoming wire bytes to the protocol.
    ///
    /// Returns an encoded event list. Free it with [`derec_free_buffer`].
    ///
    /// # Safety
    ///
    /// `handle` must be a valid non-null pointer. `message_ptr` must point to
    /// `message_len` readable bytes.
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_process(
        handle: *mut DeRecProtocolHandle,
        message_ptr: *const u8,
        message_len: usize,
    ) -> ProcessResult {
        let h = unsafe { &mut *handle };
        let bytes = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };

        match h.runtime.block_on(h.protocol.process(bytes)) {
            Ok(events) => ProcessResult {
                status: ok_status(),
                events: vec_into_buffer(encode_events(&events)),
            },
            Err(e) => ProcessResult {
                status: err_status(e.to_string()),
                events: empty_buffer(),
            },
        }
    }

    /// Generate an out-of-band contact message.
    ///
    /// # Safety
    ///
    /// `handle` must be a valid non-null pointer.
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_create_contact(
        handle: *mut DeRecProtocolHandle,
        channel_id: u64,
    ) -> CreateContactResult {
        let h = unsafe { &mut *handle };
        let channel_id_opt = if channel_id == 0 {
            None
        } else {
            Some(ChannelId(channel_id))
        };
        match h
            .runtime
            .block_on(h.protocol.create_contact(channel_id_opt))
        {
            Ok(contact) => CreateContactResult {
                status: ok_status(),
                contact_bytes: vec_into_buffer(contact.encode_to_vec()),
            },
            Err(e) => CreateContactResult {
                status: err_status(e.to_string()),
                contact_bytes: empty_buffer(),
            },
        }
    }

    /// Begin pairing as the responder (scanned a peer's contact).
    ///
    /// # Safety
    ///
    /// `handle` must be valid. `contact_ptr` must point to `contact_len` bytes
    /// of a serialized `ContactMessage` protobuf.
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_initiate_pairing(
        handle: *mut DeRecProtocolHandle,
        sender_kind: i32,
        contact_ptr: *const u8,
        contact_len: usize,
    ) -> DeRecStatus {
        let h = unsafe { &mut *handle };
        let bytes = unsafe { std::slice::from_raw_parts(contact_ptr, contact_len) };

        let kind = match SenderKind::try_from(sender_kind) {
            Ok(k) => k,
            Err(_) => return err_status(format!("invalid SenderKind value: {sender_kind}")),
        };

        let contact = match ContactMessage::decode(bytes) {
            Ok(c) => c,
            Err(e) => return err_status(format!("invalid ContactMessage: {e}")),
        };

        match h
            .runtime
            .block_on(h.protocol.initiate_pairing(kind, contact))
        {
            Ok(()) => ok_status(),
            Err(e) => err_status(e.to_string()),
        }
    }

    /// Start recovery mode: pair with helpers and request shares.
    ///
    /// `helpers_ptr` points to `helpers_count` serialized `ContactMessage` protobufs,
    /// each preceded by a 4-byte little-endian length.
    ///
    /// # Safety
    ///
    /// `handle` must be valid. The helpers buffer must be well-formed.
    #[unsafe(no_mangle)]
    pub extern "C" fn derec_protocol_start_recovery(
        handle: *mut DeRecProtocolHandle,
        sender_kind: i32,
        secret_id_ptr: *const u8,
        secret_id_len: usize,
        version: i32,
        helpers_ptr: *const u8,
        helpers_len: usize,
    ) -> DeRecStatus {
        let h = unsafe { &mut *handle };

        let kind = match SenderKind::try_from(sender_kind) {
            Ok(k) => k,
            Err(_) => return err_status(format!("invalid SenderKind value: {sender_kind}")),
        };

        let secret_id =
            unsafe { std::slice::from_raw_parts(secret_id_ptr, secret_id_len) }.to_vec();

        // Decode length-prefixed ContactMessage list
        let raw = unsafe { std::slice::from_raw_parts(helpers_ptr, helpers_len) };
        let helpers = match decode_len_prefixed_contact_list(raw) {
            Ok(v) => v,
            Err(e) => return err_status(e),
        };

        match h
            .runtime
            .block_on(h.protocol.start_recovery(kind, secret_id, version, helpers))
        {
            Ok(()) => ok_status(),
            Err(e) => err_status(e.to_string()),
        }
    }

    fn decode_len_prefixed_contact_list(
        mut raw: &[u8],
    ) -> std::result::Result<Vec<ContactMessage>, String> {
        let mut contacts = Vec::new();
        while !raw.is_empty() {
            if raw.len() < 4 {
                return Err("truncated contact list".into());
            }
            let len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
            raw = &raw[4..];
            if raw.len() < len {
                return Err("truncated contact bytes".into());
            }
            let contact = ContactMessage::decode(&raw[..len])
                .map_err(|e| format!("invalid ContactMessage: {e}"))?;
            contacts.push(contact);
            raw = &raw[len..];
        }
        Ok(contacts)
    }
}
