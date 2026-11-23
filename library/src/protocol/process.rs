// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Inbound message processing.
//!
//! [`DeRecProtocol::process`] is the single entry point for anything arriving
//! off a transport. It decides whether a message is still fresh, which of the
//! two dispatch paths it takes — encrypted channel traffic, or the plaintext
//! pairing handshake — and hands it to [`handlers`](super::handlers).

use super::context::{local, pairing_config};
use super::error::ProcessError;
use super::events::DeRecEvent;
use super::keychain::{KeyRing, Lookup};
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::{SecretKind, SecretValue};
use super::{DeRecProtocol, handlers};
use crate::derec_message;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::derec_message::DeRecMessageExt as _;
use crate::extensions::secret_store::SecretStoreExt as _;
#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
use crate::protocol::IgnoreReason;
use crate::protocol::types::{ChannelQuery, ChannelStatus, ReplicaFilter};
use crate::protocol_version::ProtocolVersion;
use crate::types::{ChannelId, ChannelKey};
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;
use crate::utils::verify_protocol_version;
use crate::{Error, Result};
use derec_proto::{DeRecMessage, PrePairRequestMessage, PrePairResponseMessage};
use prost::Message;

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Feed any incoming wire bytes here regardless of which flow they belong to.
    ///
    /// The library:
    ///
    /// 1. Decodes the outer [`DeRecMessage`] envelope to read `channel_id`
    /// 2. Looks up the channel's key material to determine the message kind
    /// 3. Dispatches to the appropriate message handler based on the channel state
    /// 4. Returns the events the application should react to
    ///
    /// # Expired channel cleanup
    ///
    /// Each call first removes `Pending` channels that have exceeded the
    /// configured
    /// [`ExpiredChannelCleanup`](crate::protocol::ExpiredChannelCleanup)
    /// timeout, along with their pairing keys. Removal is **lazy**: it
    /// happens only when this function runs, so an idle node retains
    /// expired channels until the next inbound message arrives. The
    /// removed ids are discarded on this path — call
    /// [`remove_expired_channels`](Self::remove_expired_channels)
    /// directly to observe them.
    ///
    /// # Auto-accept
    ///
    /// Any [`DeRecEvent::ActionRequired`] whose action kind the configured
    /// [`AutoAcceptPolicy`](crate::protocol::AutoAcceptPolicy) opts into is replaced in place with
    /// `AutoAccepted` plus the events a manual
    /// [`accept`](Self::accept) would have produced, including a
    /// [`DeRecEvent::RequestFailed`] when accepting fails.
    ///
    /// # Failed requests
    ///
    /// A request that arrived on an authenticated channel and then failed is
    /// **not** an `Err`. It is answered exactly once, and reported as
    /// [`DeRecEvent::RequestFailed`] inside `Ok`, so the other events of the
    /// call are kept. Whether the library sends the answer or hands the
    /// application a token for [`reject`](Self::reject) is
    /// [`with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure).
    /// That includes a message that decrypts but whose body cannot be
    /// decoded, which is answered with an `ErrorResponseMessage`. A received
    /// `ErrorResponseMessage` is reported as
    /// [`DeRecEvent::ErrorResponseReceived`] and never answered.
    ///
    /// A `PairRequest` refused under a protocol rule is not an `Err` either:
    /// the refusal is sent and reported as [`DeRecEvent::PairingRefused`].
    ///
    /// [`ProcessError`] is left for what cannot be answered: an envelope that
    /// does not decode, a channel with no key, a message that does not
    /// decrypt, any other failure of the pairing handshake or of a response
    /// this device received, and a store failure before the message could be
    /// authenticated, or while the message's answers were recorded on the
    /// open sharing rounds.
    ///
    /// # Event ordering
    ///
    /// Timeout events come first — sharing-round before unpair — then the
    /// events this message produced. An application reading the returned
    /// list in order therefore sees deadlines settle before new work.
    ///
    /// A failed call still reports what it produced before failing, in
    /// [`ProcessError::events`]: the timeout events at least, and every
    /// event of the message when only the follow-up auto-publish or the
    /// recording of the message's answers failed. Those deadlines are
    /// already settled and are never reported again.
    ///
    /// When the state store fails while the message's answers are recorded
    /// on the open sharing rounds, the message itself was handled but no
    /// round has taken its answers yet. Processing the same bytes again,
    /// within the inbound message timeout, records them; that call repeats
    /// the message's own events, never a round's.
    ///
    /// # Security: replay and reflection
    ///
    /// An envelope older than
    /// [`Timeouts::inbound_message`](crate::protocol::types::Timeouts::inbound_message)
    /// is ignored as `Expired`, but within that window this function keeps
    /// no record of what it has processed: a copy of a message is processed
    /// again. Both ends of a channel encrypt under one key, so a message this
    /// device sent, delivered back to it, decrypts too. Detecting both is the
    /// **application's** job, and how is its choice. One that keys on the
    /// envelope's encrypted `message` field
    /// ([`crate::derec_message::encrypted_payload`] reads it) gets a key that
    /// cannot be changed
    /// without failing decryption, and that differs for every message, since
    /// each is sealed under a fresh nonce; a hash of the raw envelope does
    /// not work, because `sequence` and `traceId` are not authenticated and a
    /// copy can arrive as different bytes. Whatever the key, keep it for the
    /// whole inbound window, measured from the later of arrival and the
    /// envelope's `timestamp`, and across restarts.
    ///
    /// A message held back and delivered late is a first delivery, so no
    /// record catches it. Where its order matters to the protocol's own
    /// state, the library enforces it: a `StoreShareRequest` older than the
    /// newest version stored on its channel is ignored as `Superseded`.
    /// Where it matters only to the application, the application enforces
    /// it: the `timestamp` of the envelope that raised an `UpdateChannelInfo`
    /// [`ActionRequired`](DeRecEvent::ActionRequired) is when the update was
    /// sent, and an update older than the last one accepted on the channel
    /// should be rejected.
    ///
    /// # Security: bounding inbound message size
    ///
    /// This function does **not** enforce an upper bound on `message.len()`,
    /// and no library entry point that ingests peer wire bytes does either.
    /// Legitimate envelopes span many orders of magnitude:
    ///
    /// - Tens of bytes for empty acks / ping-class messages.
    /// - A few KB for pairing material and verification proofs.
    /// - Hundreds of KB to several MB for `StoreShareRequest` carrying a
    ///   share of a large secret.
    /// - Many MB for `ReplicaSync` envelopes carrying an entire secret
    ///   (`O(num_secrets × num_helpers × max_secret_bytes)`).
    ///
    /// Any cap tight enough to provide meaningful DoS resistance would risk
    /// silently truncating a legitimate replica sync — at which point the
    /// secret can become unrecoverable. The protocol therefore delegates
    /// inbound-size bounding to the **application's transport layer**,
    /// which knows the deployment's max secret size, helper count, and
    /// replica fan-out and can pick a ceiling that fits.
    ///
    /// Callers MUST refuse oversized envelopes upstream (e.g. enforce a
    /// max HTTP body / WebSocket frame size consistent with their
    /// configuration) before handing bytes to this function.
    ///
    /// Malformed bytes — including truncation, varint overflow, and any
    /// `prost`-level decode failure — surface as
    /// [`ProcessError`] wrapping [`Error::ProtobufDecode`], except an inner
    /// body that decrypts under the channel key and then fails to decode,
    /// which is a failed request (see *Failed requests* above). This function
    /// never panics on adversarial input. Protobuf recursion depth is
    /// bounded by `prost`'s decoder; DeRec's schema is shallow (~3 levels),
    /// so no additional caller-side recursion limit is required.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(
            skip_all,
            fields(trace_id = tracing::field::Empty, message_len = message.len())
        )
    )]
    pub async fn process(
        &mut self,
        message: &[u8],
    ) -> std::result::Result<Vec<DeRecEvent>, ProcessError> {
        let share_holders = self.pending_unpair_share_holders().await;
        let mut events = self.run_timeout_sweeps().await;

        let handled = self.handle_message(message).await;
        let channel_id = match handled {
            Ok((channel_id, mut message_events)) => {
                events.append(&mut message_events);
                channel_id
            }
            Err((channel_id, source)) => {
                if let Err(_error) = self.update_sharing_round(&mut events).await {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        error = %_error,
                        "sharing rounds could not be settled after a failed message"
                    );
                }
                return Err(ProcessError {
                    channel_id,
                    source,
                    events,
                });
            }
        };

        let settled = self.update_sharing_round(&mut events).await;

        let published = match self.maybe_auto_publish(&events, &share_holders).await {
            Ok(auto_publish_events) => {
                events.extend(auto_publish_events);
                Ok(())
            }
            Err(source) => Err(source),
        };

        let failure = match (settled, published) {
            (Ok(()), Ok(())) => return Ok(events),
            (Err(source), Ok(())) | (Ok(()), Err(source)) => source,
            (Err(source), Err(_publish_error)) => {
                #[cfg(feature = "logging")]
                tracing::warn!(
                    error = %_publish_error,
                    "publish after an unpair failed; the remaining helpers keep the previous version"
                );
                source
            }
        };
        Err(ProcessError {
            channel_id: Some(channel_id),
            source: failure,
            events,
        })
    }

    async fn handle_message(
        &mut self,
        message: &[u8],
    ) -> std::result::Result<(ChannelId, Vec<DeRecEvent>), (Option<ChannelId>, Error)> {
        let envelope =
            DeRecMessage::decode(message).map_err(|e| (None, Error::ProtobufDecode(e)))?;
        let channel_id = ChannelId(envelope.channel_id);
        #[cfg(feature = "logging")]
        tracing::Span::current().record("trace_id", envelope.trace_id);

        let events = self
            .process_inner(&envelope, channel_id)
            .await
            .map_err(|source| (Some(channel_id), source))?;
        let events = self
            .apply_auto_accept(events)
            .await
            .map_err(|source| (Some(channel_id), source))?;
        Ok((channel_id, events))
    }

    async fn process_inner(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Vec<DeRecEvent>> {
        let version = ProtocolVersion {
            major: message.protocol_version_major,
            minor: message.protocol_version_minor,
        };
        if version < self.min_protocol_version {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                major = version.major,
                minor = version.minor,
                "message ignored — protocol version below the configured minimum"
            );
            return Ok(vec![DeRecEvent::MessageIgnored {
                channel_id,
                reason: IgnoreReason::ProtocolVersionTooOld,
                trace_id: message.trace_id,
            }]);
        }

        if message.is_expired(now_secs(), self.timeouts.inbound_message) {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                timeout_secs = self.timeouts.inbound_message.as_secs(),
                "message discarded — older than configured timeout"
            );
            return Ok(vec![DeRecEvent::MessageIgnored {
                channel_id,
                reason: IgnoreReason::Expired,
                trace_id: message.trace_id,
            }]);
        }

        if let Some(events) = self.process_channel_message(message, channel_id).await? {
            return Ok(events);
        }

        if let Some(events) = self.process_pairing_message(message, channel_id).await? {
            return Ok(events);
        }

        #[cfg(feature = "logging")]
        tracing::warn!(channel_id = channel_id.0, "no key material for channel");

        Err(Error::InvalidInput(
            "unknown channel_id: no shared key or pairing secret found",
        ))
    }

    /// Open and handle a message that arrived on a paired channel, or return
    /// `None` when the channel has no key ring here.
    ///
    /// The key is chosen by the envelope's `sequence`, the epoch of the key
    /// the payload is under. An epoch the ring cannot give a key for is
    /// ignored as
    /// [`IgnoreReason::KeyUnavailable`](crate::protocol::IgnoreReason::KeyUnavailable).
    /// An epoch ahead of the newest is opened by deriving forward, within the
    /// forward-jump limit; once the payload decrypts, the new epoch is
    /// persisted before the message is handled, so a failure in handling does
    /// not undo the move. An epoch below the newest is opened with the key the
    /// ring holds or derives, and the ring does not move.
    ///
    /// A message that does not decrypt has no authenticated sender: it fails
    /// with `Err`, nothing is sent, and no state changes.
    async fn process_channel_message(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let Some(ring) = self
            .secret_store
            .key_ring(self.secret_id, channel_id)
            .await?
        else {
            return Ok(None);
        };

        if let Some(events) = self
            .ignore_if_pending_verification(message, channel_id)
            .await?
        {
            return Ok(Some(events));
        }

        let Some((key, inner_message)) = self.open(&ring, message, channel_id).await? else {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                sequence = message.sequence,
                "message ignored — no key for its epoch"
            );
            return Ok(Some(vec![DeRecEvent::MessageIgnored {
                channel_id,
                reason: IgnoreReason::KeyUnavailable,
                trace_id: message.trace_id,
            }]));
        };

        let events = handlers::handle(
            &mut borrow_stores!(self),
            &local!(self),
            message,
            channel_id,
            &inner_message,
            &key,
            self.auto_respond_on_failure,
        )
        .await?;

        Ok(Some(events))
    }

    /// Decrypt `message` under the key `ring` holds for its `sequence`, and
    /// store the ring moved forward when that epoch is ahead of the newest.
    /// Returns the key and the decrypted payload, or `None` when the ring
    /// has no key for the epoch.
    ///
    /// The sender holds the newer key, so the move is kept even if handling
    /// then fails. A save failure leaves the ring where it was, and
    /// processing the same bytes again retries it.
    async fn open(
        &mut self,
        ring: &KeyRing,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<(ChannelKey, Vec<u8>)>> {
        let (key, advanced) = match ring.lookup(message.sequence) {
            Lookup::Unavailable => return Ok(None),
            Lookup::Held(key) | Lookup::Behind(key) => (key, None),
            Lookup::Ahead { key, advanced } => (key, Some(advanced)),
        };

        let inner_message = derec_message::decrypt_inner_message(&message.message, &key.key)?;

        if let Some(advanced) = advanced {
            self.secret_store
                .save_key_ring(self.secret_id, channel_id, &advanced)
                .await?;
        }
        Ok(Some((key, inner_message)))
    }

    /// Dispatch a pairing message, trying the plaintext leg before the
    /// encrypted one.
    ///
    /// `PrePair` envelopes carry a serialized `MessageBody` directly — no
    /// shared or asymmetric key exists yet, so there is nothing to encrypt
    /// under — and therefore decode without any crypto material. ECIES
    /// ciphertext for the regular `Pair` flow will not realistically decode to
    /// a valid `PrePair*` variant; if it ever did, it falls through to the
    /// encrypted path.
    ///
    /// A `PrePairRequest` is routed only when this device holds a correlation
    /// record for the channel, and either kind will do:
    /// [`SecretKind::PairingSecret`](crate::protocol::SecretKind::PairingSecret) from a `HashedKeys` contact, whose keys
    /// the accept path publishes, or [`SecretKind::PairingContact`](crate::protocol::SecretKind::PairingContact) from a
    /// `NoKeys` one, which has no keys until the accept path generates them.
    /// Holding neither means the channel is unknown, and the message is
    /// dropped silently. A `PrePairResponse` needs the stored contact
    /// specifically, to check the keys against its binding hash.
    async fn process_pairing_message(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        use derec_proto::MessageBody;

        if let Ok((inner, payload_version)) = MessageBody::decode_versioned(&message.message) {
            let version_mismatch = verify_protocol_version(message, payload_version)
                .is_err()
                .then(|| {
                    vec![DeRecEvent::MessageIgnored {
                        channel_id,
                        reason: IgnoreReason::ProtocolVersionMismatch,
                        trace_id: message.trace_id,
                    }]
                });
            match inner {
                MessageBody::PrePairRequest(request) => {
                    return self
                        .process_pre_pair_request(message, channel_id, &request, version_mismatch)
                        .await;
                }
                MessageBody::PrePairResponse(response) => {
                    return self
                        .process_pre_pair_response(channel_id, &response, version_mismatch)
                        .await;
                }
                _ => {} // Fall through to the encrypted Pair path.
            }
        }

        let Some(SecretValue::PairingSecret(pairing_secret)) = self
            .secret_store
            .load(self.secret_id, channel_id, SecretKind::PairingSecret)
            .await?
        else {
            return Ok(None);
        };
        let pairing_secret = pairing_secret.to_secret()?;

        let events = handlers::handle_pairing(
            &mut borrow_stores!(self),
            &local!(self),
            &pairing_config!(self),
            message,
            channel_id,
            &pairing_secret,
        )
        .await?;
        Ok(Some(events))
    }

    /// Handle a `PrePairRequest` on a channel this device holds a
    /// correlation record for, or return `None` when it holds neither kind.
    /// `version_mismatch` is the event reporting a payload whose protocol
    /// version differs from the envelope's, returned in place of handling.
    async fn process_pre_pair_request(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
        request: &PrePairRequestMessage,
        version_mismatch: Option<Vec<DeRecEvent>>,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let has_pairing_secret = matches!(
            self.secret_store
                .load(self.secret_id, channel_id, SecretKind::PairingSecret)
                .await?,
            Some(SecretValue::PairingSecret(_))
        );
        let has_pairing_contact = matches!(
            self.secret_store
                .load(self.secret_id, channel_id, SecretKind::PairingContact)
                .await?,
            Some(SecretValue::PairingContact(_))
        );
        if !has_pairing_secret && !has_pairing_contact {
            return Ok(None);
        }
        if let Some(ignored) = version_mismatch {
            return Ok(Some(ignored));
        }
        if let Some(events) = handlers::pairing::ignored_if_expired(
            &mut borrow_stores!(self),
            &local!(self),
            &pairing_config!(self),
            channel_id,
            request.timestamp.as_ref(),
            message.trace_id,
        )
        .await?
        {
            return Ok(Some(events));
        }
        let events =
            handlers::pairing::pre_pair::on_request(channel_id, request, message.trace_id)?;
        Ok(Some(events))
    }

    /// Handle a `PrePairResponse` against the contact this device stored,
    /// or return `None` when it stored none for the channel.
    /// `version_mismatch` is as for
    /// [`process_pre_pair_request`](Self::process_pre_pair_request).
    async fn process_pre_pair_response(
        &mut self,
        channel_id: ChannelId,
        response: &PrePairResponseMessage,
        version_mismatch: Option<Vec<DeRecEvent>>,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let Some(SecretValue::PairingContact(contact)) = self
            .secret_store
            .load(self.secret_id, channel_id, SecretKind::PairingContact)
            .await?
        else {
            return Ok(None);
        };
        if let Some(ignored) = version_mismatch {
            return Ok(Some(ignored));
        }
        let events = handlers::pairing::pre_pair::on_response(
            &mut borrow_stores!(self),
            &local!(self),
            &pairing_config!(self),
            channel_id,
            &contact,
            response,
        )
        .await?;
        Ok(Some(events))
    }

    async fn ignore_if_pending_verification(
        &self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let helper_pending = self
            .channel_store
            .load(self.secret_id, ChannelQuery::Helper { channel_id })
            .await?
            .is_some_and(|record| record.status() == ChannelStatus::Pending);
        let pending = helper_pending
            || !self
                .channel_store
                .replicas_on_channel(
                    self.secret_id,
                    channel_id,
                    ReplicaFilter {
                        status: vec![ChannelStatus::Pending],
                        ..Default::default()
                    },
                )
                .await?
                .is_empty();
        if !pending {
            return Ok(None);
        }

        #[cfg(feature = "logging")]
        tracing::warn!(
            channel_id = channel_id.0,
            "message ignored — channel is pending fingerprint verification"
        );
        Ok(Some(vec![DeRecEvent::MessageIgnored {
            channel_id,
            reason: IgnoreReason::PendingVerification,
            trace_id: message.trace_id,
        }]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derec_message;
    use crate::derec_message::DeRecMessageBuilder;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::tests::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::ReplicaMember;
    use crate::protocol::types::ReplicaRole;
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};
    use crate::types::ReplicaId;

    use derec_proto::MessageBody;
    use derec_proto::Protocol;
    use derec_proto::SenderKind;
    use derec_proto::StatusEnum;

    use derec_proto::TransportProtocol;

    use std::collections::HashMap;

    const SECRET_ID: u64 = 0xAF;
    const CHANNEL: ChannelId = ChannelId(808);
    const SHARED_KEY: crate::types::SharedKey = crate::types::SharedKey::new([9u8; 32]);

    fn endpoint() -> TransportProtocol {
        TransportProtocol {
            uri: "https://peer.example.com/derec".to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    /// A paired channel with the peer in the **Helper** role, so an inbound
    /// request that requires an `Owner` peer fails the role gate. That is a
    /// post-decrypt failure: authenticated, and therefore answerable.
    async fn seed(channels: &mut InMemChannelStore, secrets: &mut InMemSecretStore) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![endpoint()],
                    communication_info: HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    peer_role: SenderKind::Helper,
                    weight: 1,
                }),
            )
            .await
            .expect("seed channel");
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey(SHARED_KEY))
            .await
            .expect("seed shared key");
    }

    fn build(
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
        transport: RecordingTransport,
        auto_respond: bool,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        RecordingTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(transport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_auto_respond_on_failure(auto_respond)
            .build()
            .expect("test protocol builds")
    }

    /// An inbound `VerifyShareResponse` from a peer recorded as a Helper
    /// fails the role gate — a response is only legal from a Helper, so the
    /// request direction is what this channel refuses.
    fn failing_request() -> Vec<u8> {
        let timestamp = derec_message::current_timestamp();
        DeRecMessageBuilder::channel()
            .channel_id(CHANNEL)
            .timestamp(timestamp)
            .message_body(derec_proto::MessageBody::VerifyShareRequest(
                derec_proto::VerifyShareRequestMessage {
                    secret_id: SECRET_ID,
                    version: 1,
                    nonce: 7,
                    timestamp: Some(timestamp),
                    reply_to_transports: Vec::new(),
                },
            ))
            .encrypt(&crate::types::ChannelKey::new(0, SHARED_KEY.clone()))
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    /// Disabled is the default: nothing is sent, and the caller gets the
    /// failure as a `RequestFailed` carrying the token that answers it.
    #[test]
    fn disabled_sends_nothing_and_hands_over_a_token() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            let mut protocol = build(channels, secrets, transport.clone(), false);
            let events = protocol
                .process(&failing_request())
                .await
                .expect("an answerable failure is reported, not raised");

            assert!(
                transport.sent_envelopes().is_empty(),
                "nothing may go on the wire when the setting is off"
            );
            let token = events
                .into_iter()
                .find_map(|e| match e {
                    DeRecEvent::RequestFailed {
                        responded: false,
                        action: Some(action),
                        ..
                    } => Some(action),
                    _ => None,
                })
                .expect("a RequestFailed carrying a token");

            protocol
                .reject(token, StatusEnum::Rejected, "declined")
                .await
                .expect("the token answers the request");
            assert_eq!(transport.sent_envelopes().len(), 1, "exactly one response");
        });
    }

    /// Enabled tells the peer, and reports the failure as answered.
    #[test]
    fn enabled_sends_a_failure_response_and_reports_it() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            let mut protocol = build(channels, secrets, transport.clone(), true);
            let events = protocol
                .process(&failing_request())
                .await
                .expect("an answerable failure is reported, not raised");

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::RequestFailed {
                        responded: true,
                        action: None,
                        ..
                    }
                )),
                "{events:?}"
            );

            let sent = transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one failure response");

            // It is a real, decryptable VerifyShareResponse carrying the
            // role-mismatch status — not merely "some bytes were sent".
            let envelope =
                DeRecMessage::decode(sent[0].as_slice()).expect("the response is a DeRec envelope");
            let inner = derec_message::extract_inner_message(&envelope.message, &SHARED_KEY)
                .expect("the peer can decrypt it under the channel key");
            let MessageBody::VerifyShareResponse(response) = inner else {
                panic!("expected a VerifyShareResponse, got {inner:?}");
            };
            let status = response.result.expect("a result is present").status;
            assert_eq!(status, StatusEnum::Rejected as i32);
        });
    }

    /// A message that fails to decrypt is not authenticated, so nothing is
    /// sent back even with the setting on — otherwise anyone able to reach
    /// this device could use it as an oracle.
    #[test]
    fn an_undecryptable_message_is_never_answered() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            // Right channel, wrong key: decryption fails before dispatch.
            let timestamp = derec_message::current_timestamp();
            let envelope = DeRecMessageBuilder::channel()
                .channel_id(CHANNEL)
                .timestamp(timestamp)
                .message_body(derec_proto::MessageBody::VerifyShareRequest(
                    derec_proto::VerifyShareRequestMessage {
                        secret_id: SECRET_ID,
                        version: 1,
                        nonce: 7,
                        timestamp: Some(timestamp),
                        reply_to_transports: Vec::new(),
                    },
                ))
                .encrypt(&crate::types::ChannelKey::new(
                    0,
                    crate::types::SharedKey::new([1u8; 32]),
                ))
                .expect("encrypt")
                .build()
                .expect("build")
                .encode_to_vec();

            let mut protocol = build(channels, secrets, transport.clone(), true);
            let result = protocol.process(&envelope).await;

            assert!(result.is_err(), "an undecryptable message still errors");
            assert!(
                transport.sent_envelopes().is_empty(),
                "an unauthenticated message must never be answered"
            );
        });
    }

    const PAIRING_CHANNEL: ChannelId = ChannelId(4040);
    const GROUP_CHANNEL: ChannelId = ChannelId(5050);
    const SOURCE_ID: u64 = 0x5_0C;
    const DESTINATION_ID: u64 = 0xDE_57;
    const TRACE: u64 = 0x7_7ACE;

    async fn seed_member(
        channels: &mut InMemChannelStore,
        channel_id: ChannelId,
        replica_id: u64,
        role: ReplicaRole,
        status: ChannelStatus,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(ReplicaMember {
                    channel_id,
                    replica_id: ReplicaId(replica_id),
                    transports: vec![endpoint()],
                    communication_info: HashMap::new(),
                    role,
                    status,
                    created_at: now_secs(),
                    handover_channel: None,
                }),
            )
            .await
            .expect("seed replica member");
    }

    async fn seed_unconfirmed_destination(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
    ) {
        use crate::protocol::types::ReplicaRole;
        seed_member(
            channels,
            PAIRING_CHANNEL,
            DESTINATION_ID,
            ReplicaRole::Destination,
            ChannelStatus::Pending,
        )
        .await;
        seed_member(
            channels,
            PAIRING_CHANNEL,
            SOURCE_ID,
            ReplicaRole::Source,
            ChannelStatus::Pending,
        )
        .await;
        secrets
            .save(
                SECRET_ID,
                PAIRING_CHANNEL,
                SecretValue::SharedKey(SHARED_KEY),
            )
            .await
            .expect("seed pairing key");
    }

    fn replica_push(channel_id: ChannelId, sent_at: prost_types::Timestamp) -> Vec<u8> {
        DeRecMessageBuilder::channel()
            .channel_id(channel_id)
            .timestamp(sent_at)
            .trace_id(TRACE)
            .message_body(derec_proto::MessageBody::StoreShareRequest(
                derec_proto::StoreShareRequestMessage {
                    secret_id: SECRET_ID,
                    version: 1,
                    timestamp: Some(sent_at),
                    replica_id: Some(SOURCE_ID),
                    ..Default::default()
                },
            ))
            .encrypt(&crate::types::ChannelKey::new(0, SHARED_KEY.clone()))
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    fn build_with(
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
        user_secrets: InMemUserSecretStore,
        transport: RecordingTransport,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        RecordingTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(user_secrets)
            .with_transport(transport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://destination.example.com"])
            .with_threshold(2)
            .with_replica_id(DESTINATION_ID)
            .build()
            .expect("test protocol builds")
    }

    fn ignored(reason: IgnoreReason, channel_id: ChannelId) -> impl Fn(&DeRecEvent) -> bool {
        move |e| {
            matches!(e, DeRecEvent::MessageIgnored { channel_id: c, reason: r, trace_id }
                if *c == channel_id && *r == reason && *trace_id == TRACE)
        }
    }

    #[test]
    fn an_unconfirmed_replica_destination_ignores_the_mirror_push() {
        run_async(async {
            let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
            let user_secrets = InMemUserSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed_unconfirmed_destination(&mut c, &mut s).await;
            let members_before = channels.member_rows.lock().unwrap().len();
            let secrets_before = secrets.data.lock().unwrap().len();

            let mut protocol = build_with(
                channels.clone(),
                secrets.clone(),
                user_secrets.clone(),
                transport.clone(),
            );
            let events = protocol
                .process(&replica_push(
                    PAIRING_CHANNEL,
                    derec_message::current_timestamp(),
                ))
                .await
                .expect("an ignored message is not an error");

            assert!(
                events
                    .iter()
                    .any(ignored(IgnoreReason::PendingVerification, PAIRING_CHANNEL)),
                "expected MessageIgnored(PendingVerification) on the pairing channel, got {events:?}"
            );
            assert!(
                !events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ReplicaSecretInstalled { .. }
                        | DeRecEvent::ReplicaSecretReceived { .. }
                )),
                "the copy must not be installed: {events:?}"
            );
            assert!(
                transport.sent_envelopes().is_empty(),
                "nothing may be acknowledged"
            );
            assert!(
                user_secrets.data.lock().unwrap().is_empty(),
                "no snapshot may be written"
            );
            assert_eq!(
                channels.member_rows.lock().unwrap().len(),
                members_before,
                "no member may be added"
            );
            assert!(
                channels
                    .member_rows
                    .lock()
                    .unwrap()
                    .values()
                    .all(|m| m.status == ChannelStatus::Pending),
                "no member may be promoted"
            );
            assert!(
                channels.helper_rows.lock().unwrap().is_empty(),
                "no helper may be written"
            );
            assert_eq!(
                secrets.data.lock().unwrap().len(),
                secrets_before,
                "no key may be written or dropped"
            );
        });
    }

    #[test]
    fn a_pending_helper_channel_ignores_inbound_traffic() {
        run_async(async {
            let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;
            channels
                .helper_rows
                .lock()
                .unwrap()
                .values_mut()
                .for_each(|h| h.status = ChannelStatus::Pending);

            let mut protocol = build(channels, secrets, transport.clone(), true);
            let events = protocol
                .process(&failing_request())
                .await
                .expect("ignored, not failed");

            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::MessageIgnored {
                        channel_id,
                        reason: IgnoreReason::PendingVerification,
                        ..
                    } if *channel_id == CHANNEL
                )),
                "expected MessageIgnored(PendingVerification), got {events:?}"
            );
            assert!(
                transport.sent_envelopes().is_empty(),
                "a pending channel is answered with nothing, not even a failure status"
            );
        });
    }

    #[test]
    fn a_pending_pairing_does_not_gate_the_group_channel() {
        run_async(async {
            use crate::protocol::types::ReplicaRole;
            let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed_unconfirmed_destination(&mut c, &mut s).await;
            seed_member(
                &mut c,
                GROUP_CHANNEL,
                0x07_4E4,
                ReplicaRole::Source,
                ChannelStatus::Paired,
            )
            .await;
            s.save(SECRET_ID, GROUP_CHANNEL, SecretValue::SharedKey(SHARED_KEY))
                .await
                .expect("seed group key");

            let mut protocol = build_with(
                channels,
                secrets,
                InMemUserSecretStore::default(),
                transport,
            );
            let outcome = protocol
                .process(&replica_push(
                    GROUP_CHANNEL,
                    derec_message::current_timestamp(),
                ))
                .await;

            let gated = outcome.as_ref().is_ok_and(|events| {
                events
                    .iter()
                    .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. }))
            });
            assert!(
                !gated,
                "group traffic must not be gated by another channel's pairing: {outcome:?}"
            );
        });
    }

    #[test]
    fn an_expired_message_is_reported_as_ignored() {
        run_async(async {
            let (channels, secrets) = (InMemChannelStore::default(), InMemSecretStore::default());
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed_unconfirmed_destination(&mut c, &mut s).await;

            let mut protocol = build_with(
                channels,
                secrets,
                InMemUserSecretStore::default(),
                transport.clone(),
            );
            let stale = prost_types::Timestamp {
                seconds: now_secs() as i64 - 24 * 60 * 60,
                nanos: 0,
            };
            let events = protocol
                .process(&replica_push(PAIRING_CHANNEL, stale))
                .await
                .expect("an expired message is not an error");

            assert!(
                events
                    .iter()
                    .any(ignored(IgnoreReason::Expired, PAIRING_CHANNEL)),
                "expected MessageIgnored(Expired), got {events:?}"
            );
            assert!(transport.sent_envelopes().is_empty());
        });
    }

    mod minimum_protocol_version {
        use super::*;
        use crate::derec_message::apply_trace_id;
        use crate::primitives::pairing::request::{create_contact, produce_pre_pair_request};
        use derec_proto::ContactMode;

        fn with_floor(
            channels: InMemChannelStore,
            secrets: InMemSecretStore,
            transport: RecordingTransport,
            floor: ProtocolVersion,
        ) -> DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemStateStore,
            RecordingTransport,
        > {
            DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(transport)
                .with_state_store(InMemStateStore)
                .with_own_transports(["https://owner.example.com"])
                .with_threshold(2)
                .with_min_protocol_version(floor)
                .build()
                .expect("test protocol builds")
        }

        const OLDEST: ProtocolVersion = ProtocolVersion { major: 0, minor: 0 };
        const CUTOFF: ProtocolVersion = ProtocolVersion { major: 0, minor: 1 };

        /// `bytes` relabelled as version 0.0, the version an earlier release
        /// writes.
        fn as_version_0_0(bytes: &[u8]) -> Vec<u8> {
            let mut envelope = DeRecMessage::decode(bytes).expect("envelope");
            envelope.protocol_version_minor = 0;
            envelope.encode_to_vec()
        }

        /// The request [`failing_request`] builds, as an earlier release
        /// writes it: no version in the payload, version 0.0 on the envelope.
        fn from_an_earlier_release() -> Vec<u8> {
            let timestamp = derec_message::current_timestamp();
            let body = MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
                secret_id: SECRET_ID,
                version: 1,
                nonce: 7,
                timestamp: Some(timestamp),
                reply_to_transports: Vec::new(),
            });
            DeRecMessage {
                protocol_version_major: 0,
                protocol_version_minor: 0,
                sequence: 0,
                channel_id: CHANNEL.0,
                timestamp: Some(timestamp),
                message: derec_cryptography::channel::encrypt_message(
                    &body.encode_to_vec(),
                    SHARED_KEY.as_bytes(),
                    &[1u8; 32],
                )
                .expect("encrypt"),
                trace_id: 0,
            }
            .encode_to_vec()
        }

        fn ignored_as_mismatch(events: &[DeRecEvent]) -> bool {
            matches!(
                events,
                [DeRecEvent::MessageIgnored {
                    reason: IgnoreReason::ProtocolVersionMismatch,
                    ..
                }]
            )
        }

        async fn run(floor: ProtocolVersion, bytes: &[u8]) -> Result<Vec<DeRecEvent>> {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;
            with_floor(channels, secrets, RecordingTransport::default(), floor)
                .process(bytes)
                .await
                .map_err(|e| e.source)
        }

        fn processed(events: &[DeRecEvent]) -> bool {
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::RequestFailed { .. }))
        }

        fn ignored_as_too_old(events: &[DeRecEvent]) -> bool {
            matches!(
                events,
                [DeRecEvent::MessageIgnored {
                    reason: IgnoreReason::ProtocolVersionTooOld,
                    ..
                }]
            )
        }

        #[test]
        fn a_current_message_is_accepted_at_either_floor() {
            run_async(async {
                for floor in [OLDEST, CUTOFF] {
                    let events = run(floor, &failing_request()).await.expect("processed");
                    assert!(processed(&events), "{floor:?}: {events:?}");
                }
            });
        }

        #[test]
        fn a_message_from_an_earlier_version_is_accepted_by_default() {
            run_async(async {
                let events = run(OLDEST, &from_an_earlier_release())
                    .await
                    .expect("processed");
                assert!(processed(&events), "{events:?}");
            });
        }

        #[test]
        fn a_message_below_the_floor_is_ignored_unread() {
            run_async(async {
                let channels = InMemChannelStore::default();
                let secrets = InMemSecretStore::default();
                let transport = RecordingTransport::default();
                let (mut c, mut s) = (channels.clone(), secrets.clone());
                seed(&mut c, &mut s).await;
                let events = with_floor(channels, secrets, transport.clone(), CUTOFF)
                    .process(&from_an_earlier_release())
                    .await
                    .expect("an ignored message is an outcome");
                assert!(ignored_as_too_old(&events), "{events:?}");
                assert!(transport.sent_envelopes().is_empty());
            });
        }

        /// A current message relabelled 0.0 carries 0.1 in its encrypted
        /// payload: it is ignored as a mismatch, or as too old once the floor
        /// is raised, which is checked first.
        #[test]
        fn a_message_relabelled_to_an_earlier_version_is_ignored() {
            run_async(async {
                let relabelled = as_version_0_0(&failing_request());
                let events = run(OLDEST, &relabelled).await.expect("ignored");
                assert!(ignored_as_mismatch(&events), "{events:?}");
                let events = run(CUTOFF, &relabelled).await.expect("ignored");
                assert!(ignored_as_too_old(&events), "{events:?}");
            });
        }

        /// A message from an earlier release relabelled 0.1 to pass the floor
        /// carries no version in its payload, which reads as 0.0.
        #[test]
        fn an_earlier_message_relabelled_to_the_current_version_is_ignored() {
            run_async(async {
                let mut envelope =
                    DeRecMessage::decode(from_an_earlier_release().as_slice()).expect("envelope");
                envelope.protocol_version_minor = 1;
                let events = run(CUTOFF, &envelope.encode_to_vec())
                    .await
                    .expect("ignored");
                assert!(ignored_as_mismatch(&events), "{events:?}");
            });
        }

        /// `traceId` is re-stamped after sealing, by the library and by
        /// applications, so it is not covered.
        #[test]
        fn a_trace_id_stamped_after_sealing_is_accepted() {
            run_async(async {
                let bytes = apply_trace_id(&failing_request(), 0xFEED).expect("restamp");
                let events = run(OLDEST, &bytes).await.expect("processed");
                assert!(processed(&events), "{events:?}");
            });
        }

        /// The floor is checked before routing, so it covers pairing
        /// messages too.
        #[test]
        fn a_pairing_message_below_the_floor_is_ignored() {
            run_async(async {
                let contact = create_contact(
                    ChannelId(9_999),
                    ContactMode::NoKeys,
                    vec![endpoint()],
                    None,
                )
                .expect("contact")
                .contact_message;
                let pre_pair = produce_pre_pair_request(vec![endpoint()], &contact)
                    .expect("pre-pair")
                    .envelope;
                let events = run(CUTOFF, &as_version_0_0(&pre_pair))
                    .await
                    .expect("ignored");
                assert!(ignored_as_too_old(&events), "{events:?}");
            });
        }
    }
}
