// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Resolving a [`PendingAction`].
//!
//! A flow that needs the application's decision surfaces
//! [`DeRecEvent::ActionRequired`](crate::protocol::DeRecEvent::ActionRequired) and stops. [`DeRecProtocol::accept`] and
//! [`DeRecProtocol::reject`] are how that decision comes back, and each
//! dispatches on the action to the handler that raised it.

use super::context::{Exchange, Round, local, pairing_config};
use super::events::{DeRecEvent, PendingAction};
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::{DeRecProtocol, handlers};
use crate::Result;
use crate::extensions::channel_store::ChannelStoreExt as _;
use derec_proto::StatusEnum;

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Accept a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Executes the "do work + send response" path for the given action,
    /// returning the same events that auto-respond would have produced.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = action.trace_id())))]
    pub async fn accept(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
        let mut events = self.accept_inner(action).await?;
        let auto_publish_events = self.maybe_auto_publish_after_pair(&events).await?;
        events.extend(auto_publish_events);
        Ok(events)
    }

    /// Reject a pending action from an [`DeRecEvent::ActionRequired`] event.
    ///
    /// Builds and sends a rejection response to the peer with the given status
    /// and memo. The `status` parameter allows the caller to specify the exact
    /// failure reason (e.g. [`StatusEnum::Rejected`], [`StatusEnum::Fail`],
    /// [`StatusEnum::TooFrequent`], etc.).
    ///
    /// # Helper-side admission control
    ///
    /// This is where a helper enforces its own limits on inbound shares.
    /// The protocol imposes none of its own: it does not bound share
    /// size, storage per sharer, or update frequency, and the
    /// `maxShareSize` negotiated from [`derec_proto::ParameterRange`] is
    /// only checked for range overlap at pairing time, never against an
    /// actual share.
    ///
    /// [`PendingAction::StoreShare`] carries the already-decrypted,
    /// already-parsed [`derec_proto::StoreShareRequestMessage`], so the
    /// application inspects the share without touching wire bytes,
    /// envelopes or key material:
    ///
    /// The application context (`my_app`, its per-user limits) is yours, so
    /// this is illustrative rather than a compiled example:
    ///
    /// ```text
    /// for event in protocol.process(&wire_bytes).await? {
    ///     let DeRecEvent::ActionRequired { action, channel_id } = event else { continue };
    ///     match &action {
    ///         PendingAction::StoreShare { request, .. } => {
    ///             // `channel_id` maps to a user in the application's own
    ///             // store, so the limit can be per-user, per-plan, or
    ///             // whatever the deployment needs.
    ///             let limit = my_app.share_limit_for(channel_id);
    ///             if request.share.len() > limit {
    ///                 protocol
    ///                     .reject(
    ///                         action,
    ///                         StatusEnum::SizeLimitExceeded,
    ///                         &format!("share exceeds the {limit}-byte limit"),
    ///                     )
    ///                     .await?;
    ///             } else {
    ///                 protocol.accept(action).await?;
    ///             }
    ///         }
    ///         _ => { protocol.accept(action).await?; }
    ///     }
    /// }
    /// ```
    ///
    /// The owner receives a `StoreShareResponse` carrying that status and
    /// memo, surfacing as [`DeRecEvent::ShareRejected`] on its side — so
    /// the failure is attributable rather than a silent timeout.
    ///
    /// [`StatusEnum::SizeLimitExceeded`] is the protocol's designated code
    /// for this case; [`StatusEnum::TooFrequent`] covers rate limiting and
    /// [`StatusEnum::Rejected`] a user-declined request.
    ///
    /// This gate exists only while
    /// [`AutoAcceptPolicy::store_share`](crate::protocol::AutoAcceptPolicy::store_share)
    /// is `false`. Enabling it makes `process()` accept and store every
    /// inbound share internally, and no `ActionRequired` is emitted to
    /// reject.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = action.trace_id())))]
    pub async fn reject(
        &mut self,
        action: PendingAction,
        status: StatusEnum,
        memo: &str,
    ) -> Result<()> {
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                trace_id,
                ..
            } => {
                handlers::pairing::pair::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                    status,
                    memo,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                shared_key,
                trace_id,
                ..
            } => {
                handlers::update_channel_info::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    status,
                    memo,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::pre_pair::reject(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    status,
                    memo,
                    trace_id,
                )
                .await
            }
        }
    }

    /// Walk the post-`process_inner` event list and apply the
    /// [`AutoAcceptPolicy`]: each `ActionRequired` whose action kind
    /// the policy opts into is replaced with `AutoAccepted` plus the
    /// flow events `accept_inner(action)` produces. Other events pass
    /// through unchanged.
    pub(super) async fn apply_auto_accept(
        &mut self,
        events: Vec<DeRecEvent>,
    ) -> Result<Vec<DeRecEvent>> {
        let mut out = Vec::with_capacity(events.len());
        for event in events {
            match event {
                DeRecEvent::ActionRequired { channel_id, action }
                    if self.auto_accept.allows(&action) =>
                {
                    let action_kind = action.kind();
                    out.push(DeRecEvent::AutoAccepted {
                        channel_id,
                        action_kind,
                    });
                    let accept_events = self.accept_inner(action).await?;
                    out.extend(accept_events);
                }
                other => out.push(other),
            }
        }
        Ok(out)
    }

    /// Auto-publish the cached secret if `events` contain a
    /// helper-side `PairingCompleted` (the freshly-paired Helper needs
    /// shares). The replica-side equivalent fires from
    /// `verify_fingerprint` once the channel leaves `Pending`.
    ///
    /// The completion event is not on its own enough: a `NoKeys` pairing
    /// completes into `ChannelStatus::Pending` and is not a publish target
    /// until its fingerprint is confirmed. Publishing then would bump the
    /// version for every *other* helper while reaching the new one with
    /// nothing, and `verify_fingerprint` would publish again the moment the
    /// gate opened — two rounds where the flow calls for one. So the hook
    /// fires only for a helper that is already usable, and the gated case is
    /// left to `verify_fingerprint`.
    ///
    /// The payload comes from `user_secret_store.load_latest()` when one
    /// has been cached by an earlier `start(ProtectSecret)`. When no
    /// snapshot exists yet **and** at least one Replica Destination is
    /// already paired, the hook publishes an empty payload so the roster
    /// snapshot still reaches every Destination — that's how a
    /// multi-device sync stays consistent before the application has
    /// added any user secrets.
    pub(super) async fn maybe_auto_publish_after_pair(
        &mut self,
        events: &[DeRecEvent],
    ) -> Result<Vec<DeRecEvent>> {
        let mut a_usable_helper_just_paired = false;
        for event in events {
            let DeRecEvent::PairingCompleted {
                kind: derec_proto::SenderKind::Owner,
                channel_id,
                ..
            } = event
            else {
                continue;
            };
            if self
                .channel_store
                .load(
                    self.secret_id,
                    crate::protocol::types::ChannelQuery::Helper {
                        channel_id: *channel_id,
                    },
                )
                .await?
                .is_some_and(|record| {
                    record.status() == crate::protocol::types::ChannelStatus::Paired
                })
            {
                a_usable_helper_just_paired = true;
                break;
            }
        }
        if !a_usable_helper_just_paired {
            return Ok(Vec::new());
        }
        let snapshot = self.user_secret_store.load_latest(self.secret_id).await?;
        let (secrets, description) = match snapshot {
            Some(s) => (s.secrets, s.description),
            None => {
                if !self.has_paired_replica_destination().await? {
                    return Ok(Vec::new());
                }
                (Vec::new(), None)
            }
        };
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
        .await
    }

    /// Returns `true` when at least one channel records a
    /// `ReplicaDestination` peer in `Paired` status — i.e. a Destination
    /// that is fully verified and eligible for secret sync.
    pub(super) async fn has_paired_replica_destination(&self) -> Result<bool> {
        let members = self
            .channel_store
            .replicas_matching(
                self.secret_id,
                crate::protocol::types::ReplicaFilter {
                    status: vec![crate::protocol::types::ChannelStatus::Paired],
                    role: Some(crate::protocol::types::ReplicaRole::Destination),
                    exclude: self.exclude_self(),
                    ..Default::default()
                },
            )
            .await?;
        Ok(!members.is_empty())
    }

    /// This device's own row, as a
    /// [`ReplicaFilter::exclude`](crate::protocol::types::ChannelFilter::exclude)
    /// list. See [`Local::exclude_self`](crate::protocol::context::Local::exclude_self).
    pub(super) fn exclude_self(&self) -> Vec<crate::types::ReplicaId> {
        self.replica_id
            .map(crate::types::ReplicaId)
            .into_iter()
            .collect()
    }

    async fn accept_inner(&mut self, action: PendingAction) -> Result<Vec<DeRecEvent>> {
        match action {
            PendingAction::Pairing {
                channel_id,
                request,
                kind,
                trace_id,
                ..
            } => {
                handlers::pairing::pair::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &pairing_config!(self),
                    channel_id,
                    &request,
                    kind,
                    trace_id,
                )
                .await
            }
            PendingAction::StoreShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::sharing::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::VerifyShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::verification::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::Discovery {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::discovery::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::GetShare {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::recovery::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::Unpair {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::unpairing::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::UpdateChannelInfo {
                channel_id,
                request,
                shared_key,
                trace_id,
            } => {
                handlers::update_channel_info::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    &Exchange {
                        channel_id,
                        shared_key: &shared_key,
                        trace_id,
                    },
                    &request,
                )
                .await
            }
            PendingAction::PrePair {
                channel_id,
                request,
                trace_id,
            } => {
                handlers::pairing::pre_pair::accept(
                    &mut borrow_stores!(self),
                    &local!(self),
                    channel_id,
                    &request,
                    trace_id,
                )
                .await
            }
        }
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
    use crate::protocol::types::SecretValue;
    use crate::types::ChannelId;

    const SECRET_ID: u64 = 0xF2;
    const CHANNEL: ChannelId = ChannelId(4242);
    const NONCE: u64 = 0xABCD;

    /// A NoKeys contact is the cheapest way into `pre_pair::accept`: it needs
    /// only a stored `PairingContact` whose nonce the request echoes.
    async fn seed_no_keys_contact(secrets: &mut InMemSecretStore) {
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::PairingContact(derec_proto::ContactMessage {
                    channel_id: CHANNEL.0,
                    contact_mode: derec_proto::ContactMode::NoKeys as i32,
                    nonce: NONCE,
                    ..Default::default()
                }),
            )
            .await
            .expect("seed NoKeys pairing contact");
    }

    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn request_answering_on(uri: &str, protocol: derec_proto::Protocol) -> PendingAction {
        PendingAction::PrePair {
            channel_id: CHANNEL,
            request: derec_proto::PrePairRequestMessage {
                nonce: NONCE,
                // Exercises the deprecated singular spelling deliberately:
                // a peer predating `supportedTransports` sends only this.
                transport_protocol: Some(derec_proto::TransportProtocol {
                    uri: uri.to_owned(),
                    protocol: protocol as i32,
                }),
                supported_transports: Vec::new(),
                timestamp: None,
            },
            trace_id: 0,
        }
    }

    fn build(
        secrets: InMemSecretStore,
        unsafe_connection: bool,
    ) -> DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemStateStore,
        NoopTransport,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(secrets)
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemStateStore)
            .with_own_transports(["https://owner.example.com"])
            .with_threshold(2)
            .with_unsafe_connection(unsafe_connection)
            .build()
            .expect("test protocol builds")
    }

    /// The gap this guards: a peer asking to be answered over LAN plaintext
    /// was dialled regardless of `unsafe_connection`, because this path
    /// validated the endpoint's *structure* and never applied the policy.
    #[test]
    fn lan_plaintext_reply_endpoint_is_refused() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            let err = protocol
                .accept(request_answering_on(
                    "http://192.168.1.42:8080",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect_err("LAN plaintext must not be dialled without the flag");

            // Endpoints are filtered rather than fail-fasted, so a request
            // whose *every* endpoint is refused reports that none was usable.
            // The guarantee is unchanged: plaintext is not dialled.
            assert!(
                matches!(err, crate::Error::NoUsableEndpoint { offered: 1 }),
                "expected a no-usable-endpoint refusal, got {err:?}"
            );
        });
    }

    /// Same request succeeds once plaintext is opted into, proving the
    /// refusal above comes from the policy rather than from the fixture.
    #[test]
    fn lan_plaintext_reply_endpoint_is_accepted_with_the_flag() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, true);
            protocol
                .accept(request_answering_on(
                    "http://192.168.1.42:8080",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect("plaintext is dialled once unsafe_connection is set");
        });
    }

    // Constructs the deprecated singular field explicitly: this test covers
    // the list spelling, so it states the singular one is absent.
    #[allow(deprecated)]
    /// A requester offering both is answered over the secure one rather than
    /// refused outright — one bad endpoint does not sink the request. This is
    /// what filtering buys over the fail-fast the singular field forced.
    #[test]
    fn a_plaintext_entry_is_skipped_when_a_secure_one_is_offered() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            protocol
                .accept(PendingAction::PrePair {
                    channel_id: CHANNEL,
                    request: derec_proto::PrePairRequestMessage {
                        nonce: NONCE,
                        transport_protocol: None,
                        supported_transports: vec![
                            derec_proto::TransportProtocol {
                                uri: "http://192.168.1.42:8080".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            },
                            derec_proto::TransportProtocol {
                                uri: "https://helper.example.com".to_owned(),
                                protocol: derec_proto::Protocol::Https as i32,
                            },
                        ],
                        timestamp: None,
                    },
                    trace_id: 0,
                })
                .await
                .expect("the secure entry survives the plaintext one");
        });
    }

    /// The ordinary case stays working: a secure endpoint needs no flag.
    #[test]
    fn secure_reply_endpoint_needs_no_flag() {
        run_async(async {
            let secrets = InMemSecretStore::default();
            let mut seeded = secrets.clone();
            seed_no_keys_contact(&mut seeded).await;

            let mut protocol = build(secrets, false);
            protocol
                .accept(request_answering_on(
                    "https://helper.example.com",
                    derec_proto::Protocol::Https,
                ))
                .await
                .expect("a secure reply endpoint is dialled by default");
        });
    }
}
