// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result,
    derec_message::extract_inner_message,
    primitives::{
        channels_discovery::response::{self as channels_discovery_response},
        discovery::response::{self as discovery_response, SecretVersionEntry, VersionEntry},
        recovery::{
            RecoveryError,
            response::{self as recovery_response, RecoveryResponseInput},
        },
        replica_confirmation::{
            request::verify_fingerprint,
            response::{self as replica_confirmation_response},
        },
        sharing::response::{self as sharing_response},
        verification::response::{self as verification_response},
    },
    types::{ChannelId, SharedKey},
};

use super::{DeRecContactStore, DeRecEvent, DeRecShareStore, DeRecTransport, PendingRecovery};
use derec_proto::{
    DeRecMessage, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    GetShareRequestMessage, GetShareResponseMessage, MessageBody,
    ReplicaChannelsDiscoveryRequestMessage, ReplicaChannelsDiscoveryResponseMessage,
    ReplicaConfirmationRequestMessage, ReplicaConfirmationResponseMessage,
    StoreShareRequestMessage, StoreShareResponseMessage, TransportProtocol,
    VerifyShareRequestMessage, VerifyShareResponseMessage,
};
use prost::Message;

/// Transient handler for post-pairing channel messages.
///
/// Constructed inside [`super::DeRecProtocol::process`] when the incoming message
/// belongs to a fully-paired channel (i.e. a `SharedKey` exists for the channel).
/// Borrows the protocol fields it needs for the duration of a single `handle` call.
pub(super) struct ChannelHandler<'a, Cs, Sh, T>
where
    Cs: DeRecContactStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
{
    pub contact_store: &'a mut Cs,
    pub share_store: &'a mut Sh,
    pub transport: &'a T,
    pub pending_recovery: &'a mut PendingRecovery,
}

impl<'a, Cs, Sh, T> ChannelHandler<'a, Cs, Sh, T>
where
    Cs: DeRecContactStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
{
    /// Decrypts the channel envelope and dispatches to the appropriate handler.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    pub async fn handle(
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
            MessageBody::GetSecretIdsVersionsRequest(request) => {
                self.on_get_secret_ids_versions_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::GetSecretIdsVersionsResponse(response) => {
                self.on_get_secret_ids_versions_response(channel_id, &response)
                    .await
            }
            MessageBody::GetShareRequest(request) => {
                self.on_get_share_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::GetShareResponse(response) => {
                self.on_get_share_response(channel_id, &response, shared_key)
                    .await
            }
            MessageBody::ReplicaConfirmationRequest(request) => {
                self.on_replica_confirmation_request(channel_id, &request, shared_key)
                    .await
            }
            MessageBody::ReplicaConfirmationResponse(response) => {
                self.on_replica_confirmation_response(channel_id, &response)
                    .await
            }
            MessageBody::ReplicaChannelsDiscoveryRequest(request) => {
                self.on_channels_discovery_request(channel_id, &request)
                    .await
            }
            MessageBody::ReplicaChannelsDiscoveryResponse(response) => {
                self.on_channels_discovery_response(channel_id, &response)
                    .await
            }
            _ => Err(Error::Invariant(
                "unexpected MessageBody variant in channel message",
            )),
        }
    }

    /// Helper side: received a share storage request, persist and acknowledge.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.version))
    )]
    async fn on_store_share_request(
        &mut self,
        channel_id: ChannelId,
        request: &StoreShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let version = request.version;
        let secret_id = request.secret_id.clone();
        let encoded_request = request.encode_to_vec();
        let resp = sharing_response::produce(channel_id, request, shared_key)?;

        self.share_store
            .save(channel_id, &secret_id, version, encoded_request)
            .await?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport.send(&endpoint, resp.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("share stored and acknowledged");

        Ok(vec![DeRecEvent::ShareStored {
            channel_id,
            version,
        }])
    }

    /// Owner side: received a share storage confirmation.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = response.version))
    )]
    async fn on_store_share_response(
        &mut self,
        channel_id: ChannelId,
        response: &StoreShareResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let version = response.version;
        sharing_response::process(version, response)?;

        #[cfg(feature = "logging")]
        tracing::info!("share confirmed by helper");

        Ok(vec![DeRecEvent::ShareConfirmed {
            channel_id,
            version,
        }])
    }

    /// Helper side: received a verification challenge, load share and respond.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.version))
    )]
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

        let resp = verification_response::produce(channel_id, request, shared_key, &stored.share)?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport.send(&endpoint, resp.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("verification response sent");

        Ok(vec![DeRecEvent::NoOp])
    }

    /// Owner side: received a verification proof, validate it.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = response.version))
    )]
    async fn on_verify_share_response(
        &mut self,
        channel_id: ChannelId,
        response: &VerifyShareResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let version = response.version;

        // Load the committed share bytes saved by the owner during protect_secret.
        // The helper used StoreShareRequestMessage.share (= committed_share.encode_to_vec())
        // to compute SHA384(share || nonce). We need those same bytes to verify the proof.
        let committed_share_bytes = self
            .share_store
            .load(channel_id, &response.secret_id, version)
            .await?
            .ok_or(Error::InvalidInput(
                "no committed share stored for this channel/secret/version — cannot verify proof",
            ))?;

        let valid = verification_response::process(response, &committed_share_bytes)?;
        if !valid {
            #[cfg(feature = "logging")]
            tracing::warn!("verification proof is invalid");
            return Err(Error::Invariant("verification proof is invalid"));
        }

        #[cfg(feature = "logging")]
        tracing::info!("share verified");

        Ok(vec![DeRecEvent::ShareVerified {
            channel_id,
            version,
        }])
    }

    /// Helper side: received a recovery share request, load share and respond.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = request.share_version))
    )]
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

        let resp = recovery_response::produce(
            channel_id,
            &request.secret_id,
            request,
            &stored,
            shared_key,
        )?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport.send(&endpoint, resp.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("recovery share response sent");

        Ok(vec![DeRecEvent::NoOp])
    }

    /// Owner side: received a recovery share, accumulate and attempt reconstruction.
    ///
    /// Every incoming response is added to all in-progress recovery contexts.
    /// Reconstruction is attempted after each addition:
    ///
    /// - **Success** → [`DeRecEvent::SecretRecovered`], context is removed.
    /// - **Failure with `ReconstructionFailed`** → [`DeRecEvent::RecoveryShareReceived`]
    ///   (threshold not yet met, more shares needed).
    /// - **Failure for any other reason** → [`DeRecEvent::RecoveryShareError`]
    ///   (corrupted share, version mismatch, decode error, etc.).
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = _channel_id.0))
    )]
    async fn on_get_share_response(
        &mut self,
        channel_id: ChannelId,
        response: &GetShareResponseMessage,
        _shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let mut events = Vec::new();

        // Add this response to every in-progress recovery context and attempt
        // reconstruction. Each context that reaches the threshold emits SecretRecovered.
        let keys: Vec<(Vec<u8>, i32)> = self.pending_recovery.keys().cloned().collect();
        for key in keys {
            let (ref secret_id, version) = key;
            let bucket = self.pending_recovery.get_mut(&key).unwrap();
            bucket.push(response.clone());

            let shares_received = bucket.len();

            let inputs: Vec<RecoveryResponseInput<'_>> = bucket
                .iter()
                .map(|r| RecoveryResponseInput { share_response: r })
                .collect();

            match recovery_response::recover(secret_id, version, &inputs) {
                Ok(result) => {
                    self.pending_recovery.remove(&key);

                    #[cfg(feature = "logging")]
                    tracing::info!(
                        version = version,
                        shares_received,
                        "secret reconstructed from shares"
                    );

                    events.push(DeRecEvent::SecretRecovered {
                        secret: result.secret_data,
                    });
                }
                Err(Error::Recovery(RecoveryError::ReconstructionFailed { ref source }))
                    if matches!(
                        source,
                        derec_cryptography::vss::DerecVSSError::InsufficientShares
                    ) =>
                {
                    #[cfg(feature = "logging")]
                    tracing::debug!(
                        version = version,
                        shares_received,
                        channel_id = channel_id.0,
                        "reconstruction not yet possible — insufficient shares"
                    );

                    events.push(DeRecEvent::RecoveryShareReceived {
                        channel_id,
                        shares_received,
                    });
                }
                Err(e) => {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        version = version,
                        shares_received,
                        channel_id = channel_id.0,
                        error = %e,
                        "recovery share response received but reconstruction failed"
                    );

                    events.push(DeRecEvent::RecoveryShareError {
                        channel_id,
                        shares_received,
                        error: e.to_string(),
                    });
                }
            }
        }

        if events.is_empty() {
            events.push(DeRecEvent::NoOp);
        }
        Ok(events)
    }

    /// Helper side: received a discovery request, enumerate stored secrets and respond.
    ///
    /// For each `(secret_id, version)` stored for this channel the Helper loads the
    /// raw [`StoreShareRequestMessage`] bytes, decodes them to retrieve the
    /// `version_description`, and includes it in the response so the recovering Owner
    /// can identify secrets by their human-readable labels.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_get_secret_ids_versions_request(
        &mut self,
        channel_id: ChannelId,
        _request: &GetSecretIdsVersionsRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        let raw = self
            .share_store
            .load_secrets_for_channel(channel_id)
            .await?;

        let mut secret_list: Vec<SecretVersionEntry> = Vec::with_capacity(raw.len());

        for (secret_id, versions) in raw {
            let mut version_entries: Vec<VersionEntry> = Vec::with_capacity(versions.len());

            for version in versions {
                let description = match self
                    .share_store
                    .load(channel_id, &secret_id, version)
                    .await?
                {
                    Some(encoded) => StoreShareRequestMessage::decode(encoded.as_slice())
                        .map(|msg| msg.version_description)
                        .unwrap_or_default(),
                    None => String::new(),
                };

                version_entries.push(VersionEntry {
                    version,
                    description,
                });
            }

            secret_list.push(SecretVersionEntry {
                secret_id,
                versions: version_entries,
            });
        }

        let resp = discovery_response::produce(channel_id, &secret_list, shared_key)?;

        let endpoint = self.peer_endpoint(channel_id).await?;
        self.transport.send(&endpoint, resp.envelope).await?;

        #[cfg(feature = "logging")]
        tracing::info!("discovery response sent");

        Ok(vec![DeRecEvent::NoOp])
    }

    /// Owner side: received a discovery response, emit `SecretsDiscovered`.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_get_secret_ids_versions_response(
        &mut self,
        channel_id: ChannelId,
        response: &GetSecretIdsVersionsResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let result = discovery_response::process(response)?;

        #[cfg(feature = "logging")]
        tracing::info!(
            secrets_count = result.secret_list.len(),
            "secrets discovered"
        );

        Ok(vec![DeRecEvent::SecretsDiscovered {
            channel_id,
            secrets: result.secret_list,
        }])
    }

    /// Receiver side: received a confirmation request, verify fingerprint and
    /// emit [`DeRecEvent::ReplicaConfirmationReceived`] so the application can
    /// display the fingerprint for user verification.
    ///
    /// The application should call [`super::DeRecProtocol::confirm_replica`] after
    /// the user confirms the fingerprint matches the peer device.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0, replica_id = request.replica_id))
    )]
    async fn on_replica_confirmation_request(
        &mut self,
        channel_id: ChannelId,
        request: &ReplicaConfirmationRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<Vec<DeRecEvent>> {
        verify_fingerprint(request, shared_key)?;
        let fingerprint = derec_cryptography::replica::fingerprint(shared_key);

        #[cfg(feature = "logging")]
        tracing::info!("replica confirmation request verified — awaiting user confirmation");

        Ok(vec![DeRecEvent::ReplicaConfirmationReceived {
            channel_id,
            replica_id: request.replica_id,
            fingerprint,
        }])
    }

    /// Initiator side: received a confirmation response, validate and emit
    /// [`DeRecEvent::ReplicaConfirmed`] with the peer's replica_id.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_replica_confirmation_response(
        &mut self,
        channel_id: ChannelId,
        response: &ReplicaConfirmationResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let result = replica_confirmation_response::process(response)?;

        #[cfg(feature = "logging")]
        tracing::info!(replica_id = result.replica_id, "replica confirmed");

        Ok(vec![DeRecEvent::ReplicaConfirmed {
            channel_id,
            replica_id: result.replica_id,
        }])
    }

    /// Owner side: received a channels discovery request from a Replica.
    ///
    /// The Owner cannot enumerate Helper channels from inside the library (that
    /// is application-level state), so this handler emits [`DeRecEvent::NoOp`]
    /// and the application is expected to call
    /// [`super::DeRecProtocol::respond_channels_discovery`] with the channel
    /// entries.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_channels_discovery_request(
        &mut self,
        channel_id: ChannelId,
        request: &ReplicaChannelsDiscoveryRequestMessage,
    ) -> Result<Vec<DeRecEvent>> {
        #[cfg(feature = "logging")]
        tracing::info!(
            last_batch_index = request.last_batch_index,
            "channels discovery request received — application must respond"
        );

        Ok(vec![DeRecEvent::ChannelsDiscoveryRequested {
            channel_id,
            last_batch_index: request.last_batch_index,
        }])
    }

    /// Replica side: received a channels discovery response, validate and emit
    /// [`DeRecEvent::ChannelsDiscovered`].
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_channels_discovery_response(
        &mut self,
        channel_id: ChannelId,
        response: &ReplicaChannelsDiscoveryResponseMessage,
    ) -> Result<Vec<DeRecEvent>> {
        let result = channels_discovery_response::process(response)?;

        #[cfg(feature = "logging")]
        tracing::info!(
            total_batches = result.total_batches,
            current_batch = result.current_batch,
            entries_count = result.entries.len(),
            "channels discovered"
        );

        Ok(vec![DeRecEvent::ChannelsDiscovered {
            channel_id,
            total_batches: result.total_batches,
            current_batch: result.current_batch,
            entries: result.entries,
        }])
    }

    async fn peer_endpoint(&mut self, channel_id: ChannelId) -> Result<TransportProtocol> {
        self.contact_store
            .load(channel_id)
            .await?
            .and_then(|c| c.transport_protocol)
            .ok_or(Error::InvalidInput("no transport endpoint for channel"))
    }
}
