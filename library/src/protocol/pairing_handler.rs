// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result,
    primitives::pairing::{
        PairingError,
        response::{self as pairing_response},
    },
    types::ChannelId,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{
    ContactMessage, DeRecMessage, MessageBody, PairRequestMessage, PairResponseMessage, SenderKind,
};
use prost::Message;

use super::{DeRecContactStore, DeRecEvent, DeRecSecretStore, DeRecTransport, SecretKind, SecretValue};

/// Transient handler for in-progress pairing messages.
///
/// Constructed inside [`super::DeRecProtocol::process`] when the incoming message
/// belongs to an active pairing session (i.e. a `PairingSecretKeyMaterial` exists
/// for the channel). Borrows the protocol fields it needs for the duration of a
/// single `handle` call.
pub(super) struct PairingHandler<'a, Cs, Ss, T>
where
    Cs: DeRecContactStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
{
    pub contact_store: &'a mut Cs,
    pub secret_store: &'a mut Ss,
    pub transport: &'a T,
}

impl<'a, Cs, Ss, T> PairingHandler<'a, Cs, Ss, T>
where
    Cs: DeRecContactStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
{
    /// Decrypts the pairing envelope and dispatches to the appropriate transition handler.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    pub async fn handle(
        &mut self,
        message: &[u8],
        channel_id: ChannelId,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> Result<Vec<DeRecEvent>> {
        let outer = DeRecMessage::decode(message).map_err(Error::ProtobufDecode)?;
        let plaintext = derec_cryptography::pairing::envelope::decrypt(
            &outer.message,
            pairing_secret.ecies_secret_key(),
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

    /// Received a pairing request — produce and send a response.
    ///
    /// This fires on whichever party created the contact (stored the pairing secret):
    ///
    /// - **Normal pairing**: the Owner created the contact; a Helper sent the request.
    ///   `request.sender_kind == Helper` → respond as `OwnerNonRecovery`.
    /// - **Recovery pairing**: the Helper created the contact; a recovering Owner sent
    ///   the request. `request.sender_kind == OwnerRecovery` → respond as `Helper`.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
    async fn on_pair_request(
        &mut self,
        channel_id: ChannelId,
        request: &PairRequestMessage,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> Result<Vec<DeRecEvent>> {
        // Determine local role from the requester's kind.
        let (response_kind, my_kind) = if request.sender_kind == SenderKind::OwnerRecovery as i32 {
            // Recovering Owner sent the request → I am the Helper responding.
            (SenderKind::Helper, SenderKind::Helper)
        } else {
            // Helper sent the request → I am the Owner responding.
            (SenderKind::OwnerNonRecovery, SenderKind::OwnerNonRecovery)
        };

        let resp = pairing_response::produce(response_kind, request, pairing_secret)?;

        self.secret_store
            .save(channel_id, SecretValue::SharedKey(resp.shared_key))
            .await?;

        // Build a minimal contact carrying just the peer's transport endpoint so
        // contact_store loads work uniformly everywhere.
        self.contact_store
            .save(
                channel_id,
                ContactMessage {
                    transport_protocol: Some(resp.responder_transport_protocol.clone()),
                    ..Default::default()
                },
            )
            .await?;

        self.secret_store
            .remove(channel_id, SecretKind::PairingSecret)
            .await?;

        self.transport
            .send(&resp.responder_transport_protocol, resp.envelope)
            .await?;

        #[cfg(feature = "logging")]
        tracing::info!("pairing complete (contact creator side)");

        Ok(vec![DeRecEvent::PairingComplete { channel_id, kind: my_kind }])
    }

    /// Received a pairing response — finalize the shared key.
    ///
    /// This fires on whichever party sent the initial request:
    ///
    /// - **Normal pairing**: the Helper sent the request and receives the Owner's
    ///   response. `response.sender_kind == OwnerNonRecovery` → my kind is `Helper`.
    /// - **Recovery pairing**: the recovering Owner sent the request and receives
    ///   the Helper's response. `response.sender_kind == Helper` → my kind is
    ///   `OwnerRecovery`.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(channel_id = channel_id.0))
    )]
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

        let result = pairing_response::process(&contact, response, pairing_secret)?;

        self.secret_store
            .save(channel_id, SecretValue::SharedKey(result.shared_key))
            .await?;
        self.secret_store
            .remove(channel_id, SecretKind::PairingSecret)
            .await?;

        // Determine local role from the responder's kind.
        let my_kind = if response.sender_kind == SenderKind::Helper as i32 {
            // Helper responded → I am the recovering Owner.
            SenderKind::OwnerRecovery
        } else {
            // Owner responded → I am the Helper.
            SenderKind::Helper
        };

        #[cfg(feature = "logging")]
        tracing::info!("pairing complete (initiator side)");

        Ok(vec![DeRecEvent::PairingComplete { channel_id, kind: my_kind }])
    }
}
