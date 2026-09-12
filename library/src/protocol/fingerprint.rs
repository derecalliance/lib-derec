// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The out-of-band confirmation gate.
//!
//! A pairing that cannot authenticate itself cryptographically completes as
//! [`ChannelStatus::Pending`](super::types::ChannelStatus) and carries no
//! secrets until a human compares fingerprints on both devices. Deriving that
//! string and acting on the comparison are the two halves here.

use super::DeRecProtocol;
use super::context::Round;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::{SecretKind, SecretValue};
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::{Error, Result, types::ChannelId};

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Compute the fingerprint for a paired channel.
    ///
    /// Returns a formatted string like `"1234-5678-9012-3456"` derived from
    /// the channel's shared key via SHA-256. Both parties will derive the same
    /// fingerprint for the same shared key, enabling visual out-of-band
    /// verification.
    ///
    /// Returns an error if the channel has no shared key (not yet paired).
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(channel_id = channel_id.0)))]
    pub async fn get_fingerprint(&self, channel_id: ChannelId) -> Result<String> {
        let shared_key = match self
            .secret_store
            .load(self.secret_id, channel_id, SecretKind::SharedKey)
            .await?
        {
            Some(SecretValue::SharedKey(key)) => key,
            _ => {
                return Err(Error::InvalidInput(
                    "channel has no shared key — not yet paired",
                ));
            }
        };

        Ok(derec_cryptography::replica::fingerprint(&shared_key))
    }

    /// Verify that a fingerprint matches the one derived from a channel's shared key.
    ///
    /// If the fingerprint matches, the channel status is updated from `Pending`
    /// to `Paired`, enabling it to process protocol messages. Returns `true` on
    /// match, `false` otherwise. Returns an error if the channel has no shared key.
    ///
    /// This is the confirmation step for both gated cases: every replica
    /// pairing, and every [`derec_proto::ContactMode::NoKeys`] pairing —
    /// helper channels included, since that mode binds nothing to the contact
    /// and a man-in-the-middle on its plaintext `PrePair` leg would leave the
    /// two sides holding different shared keys, and so different fingerprints.
    /// Compare the two values out of band before calling this.
    ///
    /// A match promotes every row on the channel, not just the peer that was
    /// confirmed: on a group channel that is every member and this device's
    /// own row, so the whole group becomes usable at once and the roster stays
    /// reconstructible from the stores.
    ///
    /// On a promotion the current snapshot is published to the newly usable
    /// peer, because it was not an eligible target while `Pending` and the
    /// pairing-time hook therefore skipped it. That is the only push it gets —
    /// nothing else republishes before the next explicit
    /// [`DeRecFlow::ProtectSecret`](crate::protocol::DeRecFlow::ProtectSecret). A device holding no snapshot still
    /// publishes an empty one to a promoted Destination, since the payload
    /// carries the roster; a promoted helper, for which an empty payload is
    /// inert, is sent nothing.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(channel_id = channel_id.0)))]
    pub async fn verify_fingerprint(
        &mut self,
        channel_id: ChannelId,
        fingerprint: &str,
    ) -> Result<bool> {
        let local = self.get_fingerprint(channel_id).await?;
        if local != fingerprint {
            return Ok(false);
        }

        let mut transitioned_helper = false;
        if let Some(record) = self
            .channel_store
            .load(
                self.secret_id,
                crate::protocol::types::ChannelQuery::Helper { channel_id },
            )
            .await?
            && let Some(helper) = record.as_helper()
            && helper.status == crate::protocol::types::ChannelStatus::Pending
        {
            let mut helper = helper.clone();
            helper.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store
                .save(
                    self.secret_id,
                    crate::protocol::types::ChannelRecord::Helper(helper),
                )
                .await?;
            transitioned_helper = true;
        }

        let mut transitioned_replica = false;
        let members = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    status: vec![crate::protocol::types::ChannelStatus::Pending],
                    ..Default::default()
                },
            )
            .await?;
        for mut member in members {
            if member.channel_id != channel_id {
                continue;
            }
            if member.role == crate::protocol::types::ReplicaRole::Destination
                && Some(member.replica_id.0) != self.replica_id
            {
                transitioned_replica = true;
            }
            member.status = crate::protocol::types::ChannelStatus::Paired;
            self.channel_store
                .save(
                    self.secret_id,
                    crate::protocol::types::ChannelRecord::Replica(member),
                )
                .await?;
        }

        if transitioned_replica || transitioned_helper {
            let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
            let payload = match snapshot {
                Some(s) => Some((s.secrets, s.description)),
                None if transitioned_replica || self.has_paired_replica_destination().await? => {
                    Some((Vec::new(), None))
                }
                None => None,
            };
            if let Some((secrets, description)) = payload {
                let reply_to: Vec<derec_proto::TransportProtocol> = if self.auto_reply_to {
                    self.own_transports.clone()
                } else {
                    Vec::new()
                };
                self.start_protect_secret(
                    secrets,
                    description,
                    &Round {
                        reply_to: &reply_to,
                        trace_id: crate::derec_message::fresh_trace_id(),
                    },
                )
                .await?;
            }
        }

        Ok(true)
    }

    /// The scheme policy this protocol applies to every transport endpoint
    /// that reaches it. Built from
    /// [`DeRecProtocolBuilder::with_unsafe_http`](crate::protocol::DeRecProtocolBuilder::with_unsafe_http); see
    /// [`TransportPolicy`](crate::transport::TransportPolicy).
    pub(crate) fn transport_policy(&self) -> crate::transport::TransportPolicy {
        crate::transport::TransportPolicy::new(self.unsafe_http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemSecretStore, InMemShareStore, InMemStateStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};
    use crate::utils::now_secs;

    const SECRET_ID: u64 = 0xF1;
    const CHANNEL: ChannelId = ChannelId(77);

    fn endpoint() -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: "https://helper.example.com".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        }
    }

    /// A helper channel mid-gate: pairing completed, fingerprint not yet
    /// compared. This is the state a `NoKeys` helper pairing now lands in.
    async fn seed_pending_helper(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        status: ChannelStatus,
    ) {
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id: CHANNEL,
                    transports: vec![endpoint()],
                    communication_info: std::collections::HashMap::new(),
                    status,
                    created_at: now_secs(),
                    peer_role: derec_proto::SenderKind::Helper,
                }),
            )
            .await
            .expect("seed helper channel");
        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::SharedKey([7u8; 32]))
            .await
            .expect("seed shared key");
    }

    fn build(
        channels: InMemChannelStore,
        secrets: InMemSecretStore,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(channels)
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .build()
            .expect("test protocol builds")
    }

    async fn status_of(channels: &mut InMemChannelStore) -> ChannelStatus {
        channels
            .load(
                SECRET_ID,
                crate::protocol::types::ChannelQuery::Helper {
                    channel_id: CHANNEL,
                },
            )
            .await
            .expect("load helper")
            .expect("helper row present")
            .status()
    }

    /// The gate opens. Without this the `Pending` status a `NoKeys` helper
    /// pairing lands in would be terminal — `verify_fingerprint` only ever
    /// walked `replicas()`, so the channel could never become usable.
    #[test]
    fn a_matching_fingerprint_promotes_a_pending_helper() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Pending).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            let fingerprint = protocol
                .get_fingerprint(CHANNEL)
                .await
                .expect("fingerprint derives from the shared key");

            assert!(
                protocol
                    .verify_fingerprint(CHANNEL, &fingerprint)
                    .await
                    .expect("verify_fingerprint"),
                "a matching fingerprint must verify"
            );

            let mut check = channels.clone();
            assert_eq!(
                status_of(&mut check).await,
                ChannelStatus::Paired,
                "a verified helper channel must become usable"
            );
        });
    }

    /// A mismatch is the MITM case the gate exists for: the channel stays
    /// inert so nothing can be shared over it.
    #[test]
    fn a_wrong_fingerprint_leaves_the_helper_pending() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Pending).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            assert!(
                !protocol
                    .verify_fingerprint(CHANNEL, "not-the-fingerprint")
                    .await
                    .expect("verify_fingerprint"),
                "a mismatched fingerprint must not verify"
            );

            let mut check = channels.clone();
            assert_eq!(
                status_of(&mut check).await,
                ChannelStatus::Pending,
                "a failed comparison must leave the channel inert"
            );
        });
    }

    /// An already-`Paired` helper — the `InlineKeys` / `HashedKeys` case — is
    /// untouched, so re-confirming a channel is harmless and the promotion
    /// branch cannot re-fire the publish hook.
    #[test]
    fn verifying_an_already_paired_helper_changes_nothing() {
        run_async(async {
            let channels = InMemChannelStore::default();
            let secrets = InMemSecretStore::default();
            let (mut seeded_ch, mut seeded_se) = (channels.clone(), secrets.clone());
            seed_pending_helper(&mut seeded_ch, &mut seeded_se, ChannelStatus::Paired).await;

            let mut protocol = build(channels.clone(), secrets.clone());
            let fingerprint = protocol
                .get_fingerprint(CHANNEL)
                .await
                .expect("fingerprint");
            assert!(
                protocol
                    .verify_fingerprint(CHANNEL, &fingerprint)
                    .await
                    .expect("verify_fingerprint")
            );

            let mut check = channels.clone();
            assert_eq!(status_of(&mut check).await, ChannelStatus::Paired);
        });
    }
}
