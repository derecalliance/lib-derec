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
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::{SecretKind, SecretValue};
use super::{DeRecProtocol, handlers};
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::{Error, Result, types::ChannelId};
use derec_proto::DeRecMessage;
use prost::Message;

#[cfg(target_arch = "wasm32")]
use crate::interop::wasm::now_secs;
#[cfg(not(target_arch = "wasm32"))]
use crate::utils::now_secs;

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
    /// [`accept`](Self::accept) would have produced. A failure while
    /// accepting surfaces as [`ProcessError`], the same way a manual accept
    /// would reach the caller.
    ///
    /// # Event ordering
    ///
    /// Timeout events come first — sharing-round before unpair — then the
    /// events this message produced. An application reading the returned
    /// list in order therefore sees deadlines settle before new work.
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
    /// [`ProcessError`] wrapping [`Error::ProtobufDecode`]. This function
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
        let mut timeout_events = self.run_timeout_sweeps().await;

        let envelope = DeRecMessage::decode(message).map_err(|e| ProcessError {
            channel_id: None,
            source: Error::ProtobufDecode(e),
        })?;
        let channel_id = ChannelId(envelope.channel_id);
        #[cfg(feature = "logging")]
        tracing::Span::current().record("trace_id", envelope.trace_id);

        let result = self.process_inner(&envelope, channel_id).await;
        let mut events = result.map_err(|source| ProcessError {
            channel_id: Some(channel_id),
            source,
        })?;

        events = self
            .apply_auto_accept(events)
            .await
            .map_err(|source| ProcessError {
                channel_id: Some(channel_id),
                source,
            })?;

        timeout_events.append(&mut events);
        let mut events = timeout_events;

        self.update_sharing_round(&mut events).await;

        let auto_publish_events =
            self.maybe_auto_publish_after_pair(&events)
                .await
                .map_err(|source| ProcessError {
                    channel_id: Some(channel_id),
                    source,
                })?;
        events.extend(auto_publish_events);

        Ok(events)
    }

    async fn is_pending_verification(&self, channel_id: ChannelId) -> Result<bool> {
        use crate::protocol::types::{ChannelQuery, ChannelStatus, ReplicaFilter};

        if let Some(record) = self
            .channel_store
            .load(self.secret_id, ChannelQuery::Helper { channel_id })
            .await?
            && record.status() == ChannelStatus::Pending
        {
            return Ok(true);
        }

        Ok(self
            .channel_store
            .replicas_matching(
                self.secret_id,
                ReplicaFilter {
                    status: vec![ChannelStatus::Pending],
                    ..Default::default()
                },
            )
            .await?
            .iter()
            .any(|member| member.channel_id == channel_id))
    }

    pub(super) fn is_message_expired(
        &self,
        envelope: &DeRecMessage,
        #[cfg_attr(not(feature = "logging"), allow(unused))] channel_id: ChannelId,
    ) -> bool {
        let Some(ts) = &envelope.timestamp else {
            return false;
        };
        let msg_secs = ts.seconds as u64;
        let now = now_secs();
        let age = now.saturating_sub(msg_secs);
        if age > self.timeouts.inbound_message.as_secs() {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                message_age_secs = age,
                timeout_secs = self.timeouts.inbound_message.as_secs(),
                "message discarded — older than configured timeout"
            );
            return true;
        }
        false
    }

    async fn process_inner(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Vec<DeRecEvent>> {
        if self.is_message_expired(message, channel_id) {
            return Ok(vec![DeRecEvent::MessageIgnored {
                channel_id,
                reason: crate::protocol::IgnoreReason::Expired,
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

    async fn process_channel_message(
        &mut self,
        message: &DeRecMessage,
        channel_id: ChannelId,
    ) -> Result<Option<Vec<DeRecEvent>>> {
        let Some(SecretValue::SharedKey(shared_key)) = self
            .secret_store
            .load(self.secret_id, channel_id, SecretKind::SharedKey)
            .await?
        else {
            return Ok(None);
        };

        if self.is_pending_verification(channel_id).await? {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                "message ignored — channel is pending fingerprint verification"
            );
            return Ok(Some(vec![DeRecEvent::MessageIgnored {
                channel_id,
                reason: crate::protocol::IgnoreReason::PendingVerification,
                trace_id: message.trace_id,
            }]));
        }

        let events = handlers::handle(
            &mut borrow_stores!(self),
            &local!(self),
            message,
            channel_id,
            &shared_key,
            self.auto_respond_on_failure,
        )
        .await?;

        Ok(Some(events))
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

        if let Ok(inner) = crate::derec_message::extract_inner_plaintext_message(&message.message) {
            match inner {
                MessageBody::PrePairRequest(request) => {
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
                    let events = handlers::pairing::pre_pair::on_request(
                        channel_id,
                        &request,
                        message.trace_id,
                    )?;
                    return Ok(Some(events));
                }
                MessageBody::PrePairResponse(resp) => {
                    let Some(SecretValue::PairingContact(contact)) = self
                        .secret_store
                        .load(self.secret_id, channel_id, SecretKind::PairingContact)
                        .await?
                    else {
                        return Ok(None);
                    };
                    let events = handlers::pairing::pre_pair::on_response(
                        &mut borrow_stores!(self),
                        &local!(self),
                        &pairing_config!(self),
                        channel_id,
                        &contact,
                        &resp,
                    )
                    .await?;
                    return Ok(Some(events));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, RecordingTransport, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};

    const SECRET_ID: u64 = 0xAF;
    const CHANNEL: ChannelId = ChannelId(808);
    const SHARED_KEY: crate::types::SharedKey = [9u8; 32];

    fn endpoint() -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: "https://peer.example.com/derec".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
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
                    communication_info: std::collections::HashMap::new(),
                    status: ChannelStatus::Paired,
                    created_at: now_secs(),
                    peer_role: derec_proto::SenderKind::Helper,
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
        let timestamp = crate::derec_message::current_timestamp();
        crate::derec_message::DeRecMessageBuilder::channel()
            .channel_id(CHANNEL)
            .timestamp(timestamp)
            .message_body(derec_proto::MessageBody::VerifyShareRequest(
                derec_proto::VerifyShareRequestMessage {
                    secret_id: SECRET_ID,
                    version: 1,
                    nonce: 7,
                    timestamp: Some(timestamp),
                    #[allow(deprecated)]
                    reply_to: None,
                    reply_to_transports: Vec::new(),
                },
            ))
            .encrypt(&SHARED_KEY)
            .expect("encrypt")
            .build()
            .expect("build")
            .encode_to_vec()
    }

    /// Disabled is the default and stays silent: the failure is the caller's
    /// to act on, and the peer is told nothing.
    #[test]
    fn disabled_sends_nothing_and_still_errors() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            let mut protocol = build(channels, secrets, transport.clone(), false);
            let result = protocol.process(&failing_request()).await;

            assert!(result.is_err(), "the failure must reach the caller");
            assert!(
                transport.sent_envelopes().is_empty(),
                "nothing may go on the wire when the setting is off"
            );
        });
    }

    /// Enabled tells the peer as well — and still returns the same error, so
    /// the caller's handling does not change with the setting.
    #[test]
    fn enabled_sends_a_failure_response_and_still_errors() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let transport = RecordingTransport::default();
            let (mut c, mut s) = (channels.clone(), secrets.clone());
            seed(&mut c, &mut s).await;

            let mut protocol = build(channels, secrets, transport.clone(), true);
            let result = protocol.process(&failing_request()).await;

            assert!(
                result.is_err(),
                "the caller still gets the error that mattered"
            );

            let sent = transport.sent_envelopes();
            assert_eq!(sent.len(), 1, "exactly one failure response");

            // It is a real, decryptable VerifyShareResponse carrying a
            // non-Ok status — not merely "some bytes were sent".
            let envelope = derec_proto::DeRecMessage::decode(sent[0].as_slice())
                .expect("the response is a DeRec envelope");
            let inner = crate::derec_message::extract_inner_message(&envelope.message, &SHARED_KEY)
                .expect("the peer can decrypt it under the channel key");
            let derec_proto::MessageBody::VerifyShareResponse(response) = inner else {
                panic!("expected a VerifyShareResponse, got {inner:?}");
            };
            let status = response.result.expect("a result is present").status;
            assert_ne!(
                status,
                derec_proto::StatusEnum::Ok as i32,
                "the response must report failure"
            );
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
            let timestamp = crate::derec_message::current_timestamp();
            let envelope = crate::derec_message::DeRecMessageBuilder::channel()
                .channel_id(CHANNEL)
                .timestamp(timestamp)
                .message_body(derec_proto::MessageBody::VerifyShareRequest(
                    derec_proto::VerifyShareRequestMessage {
                        secret_id: SECRET_ID,
                        version: 1,
                        nonce: 7,
                        timestamp: Some(timestamp),
                        #[allow(deprecated)]
                        reply_to: None,
                        reply_to_transports: Vec::new(),
                    },
                ))
                .encrypt(&[1u8; 32])
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
        role: crate::protocol::types::ReplicaRole,
        status: ChannelStatus,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Replica(crate::protocol::types::ReplicaMember {
                    channel_id,
                    replica_id: crate::types::ReplicaId(replica_id),
                    transports: vec![endpoint()],
                    communication_info: std::collections::HashMap::new(),
                    role,
                    status,
                    created_at: now_secs(),
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
        crate::derec_message::DeRecMessageBuilder::channel()
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
            .encrypt(&SHARED_KEY)
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

    fn ignored(
        reason: crate::protocol::IgnoreReason,
        channel_id: ChannelId,
    ) -> impl Fn(&DeRecEvent) -> bool {
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
                    crate::derec_message::current_timestamp(),
                ))
                .await
                .expect("an ignored message is not an error");

            assert!(
                events.iter().any(ignored(
                    crate::protocol::IgnoreReason::PendingVerification,
                    PAIRING_CHANNEL
                )),
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
                        reason: crate::protocol::IgnoreReason::PendingVerification,
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
                    crate::derec_message::current_timestamp(),
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
                events.iter().any(ignored(
                    crate::protocol::IgnoreReason::Expired,
                    PAIRING_CHANNEL
                )),
                "expected MessageIgnored(Expired), got {events:?}"
            );
            assert!(transport.sent_envelopes().is_empty());
        });
    }
}
