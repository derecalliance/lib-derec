// SPDX-License-Identifier: Apache-2.0

//! Higher-level protocol orchestrator for the DeRec protocol.
//!
//! This module provides [`DeRecProtocol`], a stateful orchestrator that wraps all
//! five protocol flows (pairing, sharing, verification, discovery, recovery). The
//! caller supplies concrete implementations of:
//!
//! - [`DeRecContactStore`] — peer contact storage
//! - [`DeRecShareStore`] — secret share storage
//! - [`DeRecSecretStore`] — cryptographic key storage
//! - [`DeRecTransport`] — outbound message delivery
//!
//! The application feeds incoming wire bytes to [`DeRecProtocol::process`] and
//! reacts to the returned [`DeRecEvent`] values. All routing, state persistence,
//! and reply sending are handled internally.

pub mod builder;
pub mod error;
pub mod traits;

mod channel_handler;
mod pairing_handler;

use crate::{
    Error, Result,
    primitives::channels_discovery::{
        request::produce as produce_channels_discovery_request,
        response::{ChannelEntry, produce as produce_channels_discovery_response},
    },
    primitives::discovery::request::produce as produce_discovery_request,
    primitives::discovery::response::SecretVersionEntry,
    primitives::pairing::request::{
        create_contact as create_contact_message, produce as produce_pairing_request_message,
    },
    primitives::recovery::request::produce as produce_get_share_request_message,
    primitives::replica_confirmation::{
        request::produce as produce_replica_confirmation_request,
        response::produce as produce_replica_confirmation_response,
    },
    primitives::sharing::request::{produce as produce_store_share_request_message, split},
    primitives::verification::request::produce as produce_verify_share_request_message,
    types::{ChannelId, Secret},
};
pub use builder::{DeRecProtocolBuilder, Missing, Set};
use channel_handler::ChannelHandler;
use derec_proto::{
    ContactMessage, DeRecMessage, GetShareResponseMessage, SenderKind, TransportProtocol,
};
pub use error::{ContactStoreError, SecretStoreError, ShareStoreError};
use pairing_handler::PairingHandler;
use prost::Message;
use std::collections::HashMap;
pub use traits::{
    ContactStoreFuture, DeRecContactStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    SecretKind, SecretStoreFuture, SecretValue, ShareStoreFuture, TransportFuture,
};

/// In-progress recovery accumulators keyed by `(secret_id, version)`.
///
/// Each entry collects [`GetShareResponseMessage`] values for a pending recovery
/// context until enough shares arrive for reconstruction.
pub(super) type PendingRecovery = HashMap<(Vec<u8>, i32), Vec<GetShareResponseMessage>>;

/// Events emitted by [`DeRecProtocol::process`].
///
/// The application reacts to these instead of routing raw messages manually.
#[non_exhaustive]
pub enum DeRecEvent {
    /// Pairing completed — the shared key for `channel_id` is now persisted.
    ///
    /// `kind` is the local party's role in the pairing. Applications use this
    /// to decide what to do next:
    ///
    /// - [`SenderKind::OwnerRecovery`] — the Owner just completed a recovery
    ///   pairing. Once out-of-band authentication is done, call
    ///   [`DeRecProtocol::request_discovery`] to ask the Helper which secrets
    ///   it holds.
    /// - [`SenderKind::OwnerNonRecovery`] — standard Owner pairing; proceed
    ///   with [`DeRecProtocol::protect_secret`] or
    ///   [`DeRecProtocol::verify_shares`] as needed.
    /// - [`SenderKind::Helper`] — the Helper side completed pairing; no
    ///   additional action is required (the Helper waits for incoming messages).
    /// - [`SenderKind::Replica`] — a Replica pairing completed; the channel is
    ///   unconfirmed. The application should initiate the Replica confirmation
    ///   flow (fingerprint verification) before proceeding with channels or
    ///   secret discovery.
    PairingComplete { channel_id: ChannelId, kind: SenderKind },

    /// A share was accepted and stored locally (Helper side).
    ShareStored { channel_id: ChannelId, version: i32 },

    /// A Helper confirmed it stored our share (Owner side).
    ShareConfirmed { channel_id: ChannelId, version: i32 },

    /// A Helper's verification proof checked out (Owner side).
    ShareVerified { channel_id: ChannelId, version: i32 },

    /// A Helper reported all secrets it currently stores for this channel (Owner side).
    ///
    /// Emitted after the Owner calls [`DeRecProtocol::request_discovery`] and the
    /// Helper responds. Each [`SecretVersionEntry`] carries a `secret_id` and a list
    /// of `(version, description)` pairs for every share the Helper holds.
    ///
    /// The application should persist this list and, once enough Helpers have
    /// responded, call [`DeRecProtocol::recover_secret`] with the desired
    /// `(secret_id, version)`.
    SecretsDiscovered {
        channel_id: ChannelId,
        /// All secrets and their stored versions the Helper holds for this channel.
        secrets: Vec<SecretVersionEntry>,
    },

    /// A recovery share response was received from a Helper but reconstruction
    /// cannot succeed yet — more shares are needed to meet the threshold.
    ///
    /// - `channel_id` identifies the Helper that sent this share response.
    /// - `shares_received` is the total number of share responses collected so far
    ///   for this `(secret_id, version)` recovery context.
    RecoveryShareReceived {
        channel_id: ChannelId,
        shares_received: usize,
    },

    /// A recovery share response was received but reconstruction failed for a
    /// reason other than insufficient shares (e.g. corrupted share, version
    /// mismatch, decode error).
    ///
    /// - `channel_id` identifies the Helper that sent this share response.
    /// - `shares_received` is the total number of share responses collected so far.
    /// - `error` describes the failure cause.
    RecoveryShareError {
        channel_id: ChannelId,
        shares_received: usize,
        error: String,
    },

    /// Recovery completed — the reconstructed secret is returned exactly once.
    SecretRecovered { secret: Vec<u8> },

    /// A replica confirmation request was received (receiver side).
    ///
    /// The fingerprint has been cryptographically validated against the shared
    /// key. The application should display `fingerprint` to the user for visual
    /// comparison with the initiator's device. If the user confirms the match,
    /// call [`DeRecProtocol::confirm_replica`] to complete the handshake.
    ReplicaConfirmationReceived {
        channel_id: ChannelId,
        /// The peer's replica identifier.
        replica_id: i32,
        /// 16-digit fingerprint (each byte 0–9) for user display.
        fingerprint: [u8; 16],
    },

    /// Replica confirmation completed (initiator side).
    ///
    /// Emitted after the peer's confirmation response is received and validated.
    /// The application may now proceed with
    /// [`DeRecProtocol::request_channels_discovery`] or secret discovery.
    ReplicaConfirmed {
        channel_id: ChannelId,
        /// The peer's replica identifier within the Owner's device set.
        replica_id: i32,
    },

    /// A Replica requested channels discovery (Owner side).
    ///
    /// The application should enumerate all active Helper channels and call
    /// [`DeRecProtocol::respond_channels_discovery`] with the entries.
    ChannelsDiscoveryRequested {
        channel_id: ChannelId,
        last_batch_index: i32,
    },

    /// A batch of Helper channel entries was received from the Owner (Replica side).
    ///
    /// The Replica should persist the entries and, if `current_batch < total_batches`,
    /// request the next batch via [`DeRecProtocol::request_channels_discovery`]
    /// with `last_batch_index = current_batch`.
    ChannelsDiscovered {
        channel_id: ChannelId,
        total_batches: i32,
        current_batch: i32,
        entries: Vec<ChannelEntry>,
    },

    /// Well-formed message with no actionable effect (e.g. an ACK).
    NoOp,
}

/// Higher-level DeRec protocol orchestrator.
///
/// Generic over:
/// - `ContactStores` — contact storage ([`DeRecContactStore`])
/// - `ShareStore` — share storage ([`DeRecShareStore`])
/// - `SecretStore` — secret storage ([`DeRecSecretStore`])
/// - `Transport`  — outbound transport ([`DeRecTransport`])
///
/// The caller provides concrete implementations; the library imposes no
/// runtime or I/O requirements.
///
/// # Lifecycle
///
/// ```text
/// DeRecProtocol::new(contact_store, share_store, secret_store, transport, own_endpoint)
///   │
///   ├── create_contact / start_pairing         → pairing
///   ├── protect_secret                         → sharing
///   ├── verify_shares                          → verification
///   ├── start_pairing(OwnerRecovery, ...)
///   │     └── request_discovery(channel_id)   → discovery  (emits SecretsDiscovered)
///   └── recover_secret                         → recovery   (emits SecretRecovered)
///
/// loop { process(incoming_bytes) → Vec<DeRecEvent> }
/// ```
pub struct DeRecProtocol<
    ContactStore: DeRecContactStore,
    ShareStore: DeRecShareStore,
    SecretStore: DeRecSecretStore,
    Transport: DeRecTransport,
> {
    pub contact_store: ContactStore,
    pub share_store: ShareStore,
    pub secret_store: SecretStore,
    pub transport: Transport,
    pub own_transport: TransportProtocol,
    pending_recovery: PendingRecovery,
}

impl<Cs: DeRecContactStore, Sh: DeRecShareStore, Ss: DeRecSecretStore, T: DeRecTransport>
    DeRecProtocol<Cs, Sh, Ss, T>
{
    /// Construct a new [`DeRecProtocol`] with the provided stores, transport, and own endpoint.
    ///
    /// Prefer [`DeRecProtocolBuilder`] for a compile-time-checked construction path.
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
    /// The returned [`ContactMessage`] should be delivered out-of-band to the peer
    /// (e.g. serialized into a QR code or deep link). The ephemeral pairing secret
    /// is persisted automatically via `secret_store`.
    ///
    /// # Channel ID
    ///
    /// Pass `Some(id)` to use a specific channel identifier, or `None` to have
    /// the library generate a random one. The channel ID is embedded in the
    /// returned [`ContactMessage`] and should be treated as the canonical
    /// identifier for this pairing session going forward.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn create_contact(
        &mut self,
        channel_id: Option<ChannelId>,
    ) -> Result<ContactMessage> {
        let channel_id = channel_id.unwrap_or_else(|| ChannelId(rand::random::<u64>()));

        #[cfg(feature = "logging")]
        tracing::debug!(channel_id = channel_id.0, "creating contact message");

        let result = create_contact_message(channel_id, self.own_transport.clone())?;

        self.secret_store
            .save(channel_id, SecretValue::PairingSecret(result.secret_key))
            .await?;

        #[cfg(feature = "logging")]
        tracing::info!(channel_id = channel_id.0, "contact message created");

        Ok(result.contact_message)
    }

    /// Begin pairing after receiving a peer's contact out-of-band.
    ///
    /// Sends a `PairRequestMessage` to the peer immediately and returns.
    /// The pairing response will arrive later via [`process`], which emits
    /// [`DeRecEvent::PairingComplete`] carrying `kind` so the application can
    /// determine what to do next.
    ///
    /// # Recovery pairing
    ///
    /// Pass `SenderKind::OwnerRecovery` when the Owner is re-pairing with
    /// Helpers to recover a lost secret. The Helper app sees the recovery intent
    /// and can map the new channel to the old one at the application level (e.g.
    /// updating a contact record with the new channel ID).
    ///
    /// Once [`DeRecEvent::PairingComplete { kind: SenderKind::OwnerRecovery, .. }`]
    /// is received, the application should perform whatever out-of-band
    /// authentication is required and then call
    /// [`request_discovery`](Self::request_discovery) to ask the Helper which
    /// secrets it holds.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = contact.channel_id))
    )]
    pub async fn start_pairing(
        &mut self,
        kind: SenderKind,
        contact: ContactMessage,
    ) -> Result<u64> {
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

        self.contact_store
            .save(channel_id, result.initiator_contact_message)
            .await?;

        #[cfg(feature = "logging")]
        tracing::info!("pairing request sent");

        self.transport.send(&endpoint, result.envelope).await?;
        Ok(channel_id.0)
    }

    /// Send a discovery request to the Helper on the given channel.
    ///
    /// This is the second step of the recovery flow, called after
    /// [`DeRecEvent::PairingComplete { kind: SenderKind::OwnerRecovery, .. }`]
    /// has been received and any required out-of-band authentication has
    /// been completed.
    ///
    /// The Helper responds with the list of all `(secret_id, version)` pairs
    /// it currently holds for this channel. [`process`] emits
    /// [`DeRecEvent::SecretsDiscovered`] when the response arrives.
    ///
    /// # Authorization
    ///
    /// Authentication is an application concern. The application must ensure
    /// the Helper has verified the requester's identity before calling this
    /// method. If sent without proper authentication the Helper may return an
    /// empty list or reject the request entirely.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    pub async fn request_discovery(&mut self, channel_id: ChannelId) -> Result<()> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Err(Error::InvalidInput(
                "no shared key for channel — pairing must complete before requesting discovery",
            ));
        };

        let endpoint = self.peer_endpoint(channel_id).await?;
        let msg = produce_discovery_request(channel_id, &shared_key)?;
        self.transport.send(&endpoint, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("discovery request sent");

        Ok(())
    }

    /// Start the replica confirmation flow by sending a fingerprint to the peer.
    ///
    /// Call this after [`DeRecEvent::PairingComplete { kind: SenderKind::Replica, .. }`]
    /// has been received. The returned fingerprint (16 decimal digits, each 0–9) should
    /// be displayed to the user for visual comparison with the peer device.
    ///
    /// The peer receives a [`ReplicaConfirmationRequestMessage`], verifies the
    /// fingerprint, and responds. [`process`] emits [`DeRecEvent::ReplicaConfirmed`]
    /// when the response arrives.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, replica_id))
    )]
    pub async fn start_replica_confirmation(
        &mut self,
        channel_id: ChannelId,
        replica_id: i32,
    ) -> Result<[u8; 16]> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Err(Error::InvalidInput(
                "no shared key for channel — pairing must complete before replica confirmation",
            ));
        };

        let endpoint = self.peer_endpoint(channel_id).await?;
        let result = produce_replica_confirmation_request(channel_id, &shared_key, replica_id)?;
        self.transport.send(&endpoint, result.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("replica confirmation request sent");

        Ok(result.fingerprint)
    }

    /// Confirm a Replica channel after the user has verified the fingerprint.
    ///
    /// Call this on the **receiving** side of the confirmation flow after
    /// the application has displayed the fingerprint and the user confirmed
    /// it matches the peer device. Sends a
    /// [`ReplicaConfirmationResponseMessage`] with an OK status.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, replica_id))
    )]
    pub async fn confirm_replica(
        &mut self,
        channel_id: ChannelId,
        replica_id: i32,
    ) -> Result<()> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Err(Error::InvalidInput(
                "no shared key for channel — pairing must complete before confirming replica",
            ));
        };

        let endpoint = self.peer_endpoint(channel_id).await?;
        let result = produce_replica_confirmation_response(channel_id, &shared_key, replica_id)?;
        self.transport.send(&endpoint, result.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("replica confirmation response sent");

        Ok(())
    }

    /// Request channels discovery from the Owner on the given Replica channel.
    ///
    /// Call this after [`DeRecEvent::ReplicaConfirmed`] to begin synchronising
    /// Helper channels. Use `last_batch_index = 0` for the initial request.
    /// After receiving a [`DeRecEvent::ChannelsDiscovered`] batch with
    /// `current_batch < total_batches`, call again with
    /// `last_batch_index = current_batch` to fetch the next batch.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, last_batch_index))
    )]
    pub async fn request_channels_discovery(
        &mut self,
        channel_id: ChannelId,
        last_batch_index: i32,
    ) -> Result<()> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Err(Error::InvalidInput(
                "no shared key for channel — pairing must complete before channels discovery",
            ));
        };

        let endpoint = self.peer_endpoint(channel_id).await?;
        let msg = produce_channels_discovery_request(channel_id, &shared_key, last_batch_index)?;
        self.transport.send(&endpoint, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("channels discovery request sent");

        Ok(())
    }

    /// Respond to a channels discovery request from a Replica.
    ///
    /// Call this on the **Owner** side after receiving a
    /// [`ReplicaChannelsDiscoveryRequestMessage`] (dispatched via [`process`]).
    /// The Owner enumerates its Helper channels and sends them to the Replica
    /// in a single batch or across multiple batches.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(
            channel_id = channel_id.0,
            total_batches,
            current_batch,
            entries_count = entries.len()
        ))
    )]
    pub async fn respond_channels_discovery(
        &mut self,
        channel_id: ChannelId,
        entries: &[ChannelEntry],
        total_batches: i32,
        current_batch: i32,
    ) -> Result<()> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Err(Error::InvalidInput(
                "no shared key for channel — pairing must complete before responding to channels discovery",
            ));
        };

        let endpoint = self.peer_endpoint(channel_id).await?;
        let msg = produce_channels_discovery_response(
            channel_id,
            &shared_key,
            entries,
            total_batches,
            current_batch,
        )?;
        self.transport.send(&endpoint, msg.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("channels discovery response sent");

        Ok(())
    }

    /// Split a secret and send one share to each of the specified Helpers.
    ///
    /// The shared key and transport endpoint for each Helper are loaded from
    /// the stores automatically — callers only need to specify which channels
    /// should receive a share and the reconstruction threshold.
    ///
    /// Helpers that have no paired `SharedKey` in the secret store are silently
    /// skipped (they are not yet paired and cannot receive an encrypted share).
    ///
    /// # Keep List
    ///
    /// `keep_list` is the set of share versions each Helper **must** retain.
    /// Any stored version not in the list **should** be deleted by the Helper.
    ///
    /// Pass an empty slice to let each Helper apply its default retention policy:
    /// retain the existing keep-list and add `secret.version` to it.
    ///
    /// Helpers **must** ignore the keep-list when `secret.version` is older than
    /// the latest version they already hold, preventing replay attacks.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(version = secret.version, helpers_count = helpers.len()))
    )]
    pub async fn protect_secret(
        &mut self,
        secret: Secret,
        threshold: usize,
        helpers: &[ChannelId],
        keep_list: &[i32],
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
                keep_list,
                &secret.description,
                &shared_key,
            )?;
            self.transport.send(&endpoint, msg.envelope).await?;

            // Save the committed share bytes so the owner can verify the helper's proof later.
            // The helper stores `StoreShareRequestMessage.share = committed_share.encode_to_vec()`
            // and uses those bytes to produce `SHA384(share || nonce)` in verification responses.
            // The owner needs the same bytes to recompute the expected hash.
            self.share_store
                .save(*channel_id, &secret.id, secret.version, committed_share.encode_to_vec())
                .await?;

            #[cfg(feature = "logging")]
            tracing::debug!(channel_id = channel_id.0, "share envelope sent");
        }

        #[cfg(feature = "logging")]
        tracing::info!("secret distributed to helpers");

        Ok(())
    }

    /// Send a verification challenge to every Helper that holds a share for
    /// `(secret_id, version)`.
    ///
    /// Only channels that participated in protecting this specific secret receive
    /// the challenge — not all known contacts.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(version = version))
    )]
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

            #[cfg(feature = "logging")]
            tracing::debug!(channel_id = channel_id.0, "verification challenge sent");

            self.transport.send(&endpoint, msg.envelope).await?;
        }

        #[cfg(feature = "logging")]
        tracing::info!("verification challenges sent");

        Ok(())
    }

    /// Request shares from the specified Helpers for a known `(secret_id, version)`.
    ///
    /// This is the final step of the recovery flow. The application inspects the
    /// [`DeRecEvent::SecretsDiscovered`] events received from each Helper, selects
    /// the desired `(secret_id, version)`, and passes the channels that hold it here.
    ///
    /// Each Helper listed in `helpers` must already be paired (a `SharedKey` must
    /// exist for the channel). Helpers with no `SharedKey` are silently skipped.
    ///
    /// [`DeRecEvent::SecretRecovered`] is emitted from [`process`] once a
    /// threshold of share responses have been collected and reconstruction succeeds.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(version = version, helpers_count = helpers.len()))
    )]
    pub async fn recover_secret(
        &mut self,
        secret_id: Vec<u8>,
        version: i32,
        helpers: &[ChannelId],
    ) -> Result<()> {
        self.pending_recovery
            .insert((secret_id.clone(), version), Vec::new());

        for &channel_id in helpers {
            let Some(SecretValue::SharedKey(shared_key)) = self
                .secret_store
                .load(channel_id, SecretKind::SharedKey)
                .await?
            else {
                continue;
            };

            let endpoint = self.peer_endpoint(channel_id).await?;
            let msg =
                produce_get_share_request_message(channel_id, &secret_id, version, &shared_key)?;
            self.transport.send(&endpoint, msg.envelope).await?;

            #[cfg(feature = "logging")]
            tracing::debug!(channel_id = channel_id.0, version = version, "share request sent");
        }

        #[cfg(feature = "logging")]
        tracing::info!(version = version, "share requests dispatched to all helpers");

        Ok(())
    }

    /// Feed any incoming wire bytes here regardless of which flow they belong to.
    ///
    /// The library:
    ///
    /// 1. Decodes the outer [`DeRecMessage`] envelope to read `channel_id`
    /// 2. Looks up the channel's key material to determine the message kind
    /// 3. Dispatches to the appropriate message handler based on the channel state
    /// 4. Returns the events the application should react to
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(message_len = message.len()))
    )]
    pub async fn process(&mut self, message: &[u8]) -> Result<Vec<DeRecEvent>> {
        let envelope = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
        let channel_id = ChannelId(envelope.channel_id);

        if let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(channel_id, SecretKind::SharedKey)
            .await?
        {
            return ChannelHandler {
                contact_store: &mut self.contact_store,
                share_store: &mut self.share_store,
                transport: &self.transport,
                pending_recovery: &mut self.pending_recovery,
            }
            .handle(message, channel_id, &shared_key)
            .await;
        }

        if let Some(SecretValue::PairingSecret(pairing_secret)) = self
            .secret_store
            .load(channel_id, SecretKind::PairingSecret)
            .await?
        {
            return PairingHandler {
                contact_store: &mut self.contact_store,
                secret_store: &mut self.secret_store,
                transport: &self.transport,
            }
            .handle(message, channel_id, &pairing_secret)
            .await;
        }

        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = envelope.channel_id,
            "no key material for channel"
        );

        Err(Error::InvalidInput(
            "unknown channel_id: no shared key or pairing secret found",
        ))
    }

    async fn peer_endpoint(&mut self, channel_id: ChannelId) -> Result<TransportProtocol> {
        self.contact_store
            .load(channel_id)
            .await?
            .and_then(|c| c.transport_protocol)
            .ok_or(Error::InvalidInput("no transport endpoint for channel"))
    }
}
