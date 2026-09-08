// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Starting a round.
//!
//! [`DeRecProtocol::start`] takes a [`DeRecFlow`](crate::protocol::DeRecFlow) and hands it to the one
//! private starter that owns it. Each starter does only what is specific to
//! its flow — the shared work of resolving targets and dispatching lives in
//! the handlers it calls.

use super::context::{Round, local, pairing_config};
use super::events::{DeRecEvent, DeRecFlow};
use super::stores::borrow_stores;
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::StateItem;
use super::{DeRecProtocol, handlers};
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::{Result, types::ChannelId};
use std::collections::{HashMap, HashSet};

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
    /// Unified entry point for initiating any protocol flow.
    ///
    /// Returns the flow's per-target `*Started` / `*Failed` events (one
    /// `PairingStarted` for [`DeRecFlow::Pairing`]; one per targeted
    /// channel for fan-out flows). See each `*Started` /
    /// `*Failed` variant on [`DeRecEvent`] for the per-flow shape.
    ///
    /// # Errors
    ///
    /// - Programmer errors (invalid input, missing preconditions, role
    ///   mismatch) surface as `Err` before any fan-out begins. Once
    ///   fan-out starts for a multi-target flow, per-channel transport
    ///   failures become `*Failed` events in the returned vec — they do
    ///   not abort the round.
    /// - Single-channel flows ([`DeRecFlow::Pairing`],
    ///   [`DeRecFlow::Unpair`]) return `Err` on send failure — no
    ///   `*Failed` event exists, so the single-`Err` signal is
    ///   unambiguous.
    #[cfg_attr(
        feature = "logging",
        tracing::instrument(skip_all, fields(trace_id = tracing::field::Empty))
    )]
    pub async fn start(&mut self, flow: DeRecFlow) -> Result<Vec<DeRecEvent>> {
        let trace_id = crate::derec_message::fresh_trace_id();
        #[cfg(feature = "logging")]
        tracing::Span::current().record("trace_id", trace_id);
        let reply_to: Vec<derec_proto::TransportProtocol> = if self.auto_reply_to {
            self.own_transports.clone()
        } else {
            Vec::new()
        };
        let round = &Round {
            reply_to: &reply_to,
            trace_id,
        };

        match flow {
            DeRecFlow::Pairing {
                kind,
                contact,
                peer_communication_info,
            } => {
                self.start_pairing(kind, contact, peer_communication_info, trace_id)
                    .await
            }
            DeRecFlow::Discovery { target } => self.start_discovery(target, round).await,
            DeRecFlow::ProtectSecret {
                secrets,
                description,
            } => self.start_protect_secret(secrets, description, round).await,
            DeRecFlow::VerifyShares {
                secret_id,
                version,
                target,
            } => {
                self.start_verify_shares(secret_id, version, target, round)
                    .await
            }
            DeRecFlow::RecoverSecret { secret_id, version } => {
                self.start_recover_secret(secret_id, version, round).await
            }
            DeRecFlow::ReplicaDiscovery => {
                handlers::replicas::discovery::start(
                    &mut borrow_stores!(self),
                    &local!(self),
                    trace_id,
                )
                .await
            }
            DeRecFlow::UnpairReplica { replica_id, memo } => {
                handlers::replicas::unpairing::start(
                    &mut borrow_stores!(self),
                    &local!(self),
                    replica_id,
                    memo,
                    trace_id,
                )
                .await
            }
            DeRecFlow::Unpair { channel_id, memo } => {
                self.start_unpair(channel_id, memo, round).await
            }
            DeRecFlow::UpdateChannelInfo {
                target,
                communication_info,
                own_transports,
            } => {
                self.start_update_channel_info(target, communication_info, own_transports, trace_id)
                    .await
            }
        }
    }

    /// Rebuild this protocol's `secret_id` namespace from a
    /// [`crate::protocol::types::Secret`] handed up by a
    /// [`DeRecEvent::SecretRecovered`] event.
    ///
    /// # Caller flow
    ///
    /// ```text
    /// fresh DeRecProtocol → empty stores
    ///   → re-pair with helpers on a fresh channel-id namespace
    ///   → start(RecoverSecret { secret_id, version })
    ///   → SecretRecovered { secret } event arrives
    ///   → DeRecProtocol::restore(&secret, version)
    /// ```
    ///
    /// On success: canonical helper channels are persisted with
    /// `SharedKey` + owner-side tracking shares at
    /// `recovered_version`; canonical replica channels are persisted
    /// with the group key from `secret.replicas.shared_key`;
    /// the user-secret snapshot is committed at `recovered_version`;
    /// every other
    /// channel under `self.secret_id` (i.e. the recovery-mode
    /// channels) is unpaired (request sent to the helper, local
    /// state dropped). The protocol resumes normal operation
    /// immediately — the next `start(ProtectSecret)` publishes
    /// `recovered_version + 1` to the restored helpers.
    ///
    /// The snapshot write is the commit point — nothing is removed
    /// before it succeeds. Any mid-flight failure leaves state the
    /// next `restore` call will detect as one of the precondition
    /// errors below.
    ///
    /// # Errors
    ///
    /// Precondition / invariant failures surface as
    /// [`crate::Error::Restore`] wrapping one of:
    ///
    /// - [`RestoreError::AlreadyRestored`](crate::protocol::RestoreError::AlreadyRestored) when a user-secret
    ///   snapshot exists for this `secret_id`.
    /// - [`RestoreError::Conflict`](crate::protocol::RestoreError::Conflict) when one or more channels live
    ///   at canonical helper / replica ids carried by `secret`.
    /// - [`RestoreError::Invariant`](crate::protocol::RestoreError::Invariant) when the recovered `Secret`
    ///   is internally inconsistent (e.g. non-empty `replicas` with
    ///   empty `replicas.shared_key`).
    ///
    /// [`crate::Error::Transport`] surfaces on the same terms when a roster
    /// entry's `transport_uri` names a scheme this library serves no
    /// transport for: the roster carries no protocol discriminant, so each
    /// peer's is derived from its URI scheme, and an unknown scheme leaves
    /// nothing to derive.
    ///
    /// Store I/O failures mid-restore propagate as the underlying
    /// [`crate::Error::ShareStore`], [`crate::Error::ChannelStore`],
    /// or [`crate::Error::SecretStore`] variant.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn restore(
        &mut self,
        secret: &crate::protocol::types::Secret,
        recovered_version: u32,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::restore::restore(
            &mut borrow_stores!(self),
            &local!(self),
            secret,
            recovered_version,
        )
        .await
    }

    /// Run one publish round: VSS-split for Helpers when the threshold is
    /// met, build the Replica composite payload with the share material
    /// embedded, and fan both out. A no-op (silent return) when no paired
    /// Helpers or Replicas exist.
    ///
    /// Only targets whose dispatch succeeded join the round's pending set: a
    /// peer that could not be reached will never answer, so counting it would
    /// hold the round open until its timeout. Such a peer is reported once
    /// here, where the transport error is still in hand, and settles as
    /// `behind`.
    pub(super) async fn start_protect_secret(
        &mut self,
        secrets: Vec<crate::protocol::types::UserSecret>,
        description: Option<String>,
        round: &Round<'_>,
    ) -> Result<Vec<DeRecEvent>> {
        let Some(result) = handlers::sharing::start(
            &mut borrow_stores!(self),
            &local!(self),
            secrets,
            description,
            self.threshold,
            self.keep_versions_count,
            round,
        )
        .await?
        else {
            return Ok(Vec::new());
        };

        let version = result.version;
        let pending: HashSet<ChannelId> = result
            .outcomes
            .iter()
            .filter_map(|(cid, r)| r.as_ref().ok().map(|_| *cid))
            .collect();
        let pending_replicas: HashSet<crate::types::ReplicaId> = result
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| r.as_ref().ok().map(|_| *rid))
            .collect();
        let behind_replicas: HashSet<crate::types::ReplicaId> = result
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| r.as_ref().err().map(|_| *rid))
            .collect();

        let mut undeliverable: Vec<DeRecEvent> = result
            .replica_outcomes
            .iter()
            .filter_map(|(rid, r)| {
                r.as_ref().err().map(|e| DeRecEvent::ReplicaSyncFailed {
                    replica_id: rid.0,
                    version,
                    reason: e.to_string(),
                })
            })
            .collect();

        if !pending.is_empty() || !pending_replicas.is_empty() {
            self.state_store
                .save(
                    self.secret_id,
                    StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                        version,
                        pending,
                        confirmed: HashSet::new(),
                        failed: HashSet::new(),
                        pending_replicas,
                        synced_replicas: HashSet::new(),
                        behind_replicas,
                        started_at: now_secs(),
                    })),
                )
                .await?;
        }

        let mut started: Vec<DeRecEvent> = result
            .outcomes
            .into_iter()
            .map(|(channel_id, res)| match res {
                Ok(()) => DeRecEvent::ProtectSecretStarted {
                    channel_id,
                    version,
                    trace_id: round.trace_id,
                },
                Err(e) => DeRecEvent::ProtectSecretFailed {
                    channel_id,
                    version,
                    error: e.to_string(),
                },
            })
            .collect();
        started.append(&mut undeliverable);
        Ok(started)
    }

    async fn start_pairing(
        &mut self,
        kind: derec_proto::SenderKind,
        contact: derec_proto::ContactMessage,
        peer_communication_info: HashMap<String, String>,
        trace_id: u64,
    ) -> Result<Vec<DeRecEvent>> {
        let channel_id = handlers::pairing::start(
            &mut borrow_stores!(self),
            &local!(self),
            &pairing_config!(self),
            kind,
            contact,
            peer_communication_info,
            trace_id,
        )
        .await?;
        Ok(vec![DeRecEvent::PairingStarted {
            channel_id: ChannelId(channel_id),
            kind,
            trace_id,
        }])
    }

    async fn start_discovery(
        &mut self,
        target: crate::protocol::types::Target,
        round: &Round<'_>,
    ) -> Result<Vec<DeRecEvent>> {
        let resolved = self
            .channel_store
            .resolve_target(self.secret_id, target.clone())
            .await?;
        self.channel_store
            .require_role(
                self.secret_id,
                &resolved, // Owner-initiated flow: every target must be a Helper peer.
                derec_proto::SenderKind::Helper,
            )
            .await?;
        handlers::discovery::start(&mut borrow_stores!(self), &local!(self), target, round).await
    }

    async fn start_verify_shares(
        &mut self,
        secret_id: u64,
        version: u32,
        target: crate::protocol::types::Target,
        round: &Round<'_>,
    ) -> Result<Vec<DeRecEvent>> {
        // Verification only ever challenges the helpers holding this
        // instance's own shares, so the flow's `secret_id` has one legal
        // value. Refusing anything else turns a caller's mistaken belief that
        // it was verifying a different secret into an error, rather than
        // reporting success for a secret it never touched.
        if secret_id != self.secret_id {
            return Err(crate::Error::InvalidInput(
                "VerifyShares secret_id must be this instance's own secret_id",
            ));
        }
        let resolved = self
            .channel_store
            .resolve_target(self.secret_id, target.clone())
            .await?;
        self.channel_store
            .require_role(
                self.secret_id,
                &resolved, // Owner-initiated flow: every target must be a Helper peer.
                derec_proto::SenderKind::Helper,
            )
            .await?;
        handlers::verification::start(
            &mut borrow_stores!(self),
            &local!(self),
            version,
            target,
            round,
        )
        .await
    }

    /// No role gate is applied before the fan-out. An instance legitimately
    /// holds replica channels alongside its helper pairings, so requiring
    /// every resolved channel to be Owner-role would abort the recovery over a
    /// peer that was never a target. The handler selects the Owner-role,
    /// `Paired` channels itself.
    async fn start_recover_secret(
        &mut self,
        secret_id: u64,
        version: u32,
        round: &Round<'_>,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::recovery::start(
            &mut borrow_stores!(self),
            &local!(self),
            secret_id,
            version,
            round,
        )
        .await
    }

    /// Emits `UnpairStarted`. When the channel needs no acknowledgement the
    /// handler returns `Unpaired` immediately, interleaved after it; otherwise
    /// `Unpaired` arrives later, from [`process`](Self::process) on the
    /// response or from the timeout sweep.
    async fn start_unpair(
        &mut self,
        channel_id: ChannelId,
        memo: Option<String>,
        round: &Round<'_>,
    ) -> Result<Vec<DeRecEvent>> {
        self.channel_store
            .require_role(
                self.secret_id,
                &[channel_id], // Owner-initiated teardown: the peer must be a Helper.
                derec_proto::SenderKind::Helper,
            )
            .await?;
        let mut events = vec![DeRecEvent::UnpairStarted {
            channel_id,
            trace_id: round.trace_id,
        }];
        events.extend(
            handlers::unpairing::start(
                &mut borrow_stores!(self),
                &local!(self),
                channel_id,
                memo,
                self.unpair_ack,
                now_secs(),
                round,
            )
            .await?,
        );
        Ok(events)
    }

    async fn start_update_channel_info(
        &mut self,
        target: crate::protocol::types::Target,
        communication_info: Option<HashMap<String, String>>,
        own_transports: Vec<derec_proto::TransportProtocol>,
        trace_id: u64,
    ) -> Result<Vec<DeRecEvent>> {
        handlers::update_channel_info::start(
            &mut borrow_stores!(self),
            &local!(self),
            target,
            communication_info,
            own_transports,
            trace_id,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, StoreRig, run_async,
    };
    use crate::protocol::types::{ChannelRecord, ChannelStatus, HelperChannel, SecretValue};
    use crate::protocol::{DeRecChannelStore, DeRecSecretStore};

    const SECRET_ID: u64 = 0x7E57;

    async fn seed_helper(
        channels: &mut InMemChannelStore,
        secrets: &mut InMemSecretStore,
        cid: u64,
        key_byte: u8,
    ) {
        let channel_id = ChannelId(cid);
        channels
            .save(
                SECRET_ID,
                ChannelRecord::Helper(HelperChannel {
                    channel_id,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: format!("https://helper-{cid}.example"),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    communication_info: HashMap::new(),
                    peer_role: derec_proto::SenderKind::Helper,
                    status: ChannelStatus::Paired,
                    created_at: 0,
                }),
            )
            .await
            .expect("seed helper");
        secrets
            .save(
                SECRET_ID,
                channel_id,
                SecretValue::SharedKey([key_byte; 32]),
            )
            .await
            .expect("seed key");
    }

    /// One `start` is one round, so every request it fans out carries the
    /// same token and the `*Started` events report that same value.
    ///
    /// Without this the caller has nothing to correlate a round by: each
    /// dispatch used to draw its own token, so a publish to three helpers
    /// produced three unrelated traces.
    #[test]
    fn one_round_shares_one_trace_id_across_its_fan_out() {
        run_async(async {
            let rig = StoreRig::new();
            let mut channels = rig.channels.clone();
            let mut secrets = rig.secrets.clone();
            seed_helper(&mut channels, &mut secrets, 11, 0xA1).await;
            seed_helper(&mut channels, &mut secrets, 12, 0xA2).await;
            seed_helper(&mut channels, &mut secrets, 13, 0xA3).await;

            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(InMemPersistedStateStore::default())
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://owner.example"])
                .build()
                .expect("test rig builds");

            let events = protocol
                .start(DeRecFlow::Discovery {
                    target: crate::protocol::types::Target::All,
                })
                .await
                .expect("discovery starts");

            let on_the_wire: Vec<u64> = rig
                .transport
                .sent_envelopes()
                .iter()
                .map(|e| crate::derec_message::read_trace_id(e).expect("envelope decodes"))
                .collect();
            assert_eq!(on_the_wire.len(), 3, "one request per helper");
            assert!(
                on_the_wire.windows(2).all(|w| w[0] == w[1]),
                "every request in the round carries one token, got {on_the_wire:?}"
            );
            assert_ne!(on_the_wire[0], 0, "the round must draw a token");

            let reported: Vec<u64> = events
                .iter()
                .filter_map(|e| match e {
                    DeRecEvent::DiscoveryStarted { trace_id, .. } => Some(*trace_id),
                    _ => None,
                })
                .collect();
            assert_eq!(
                reported,
                vec![on_the_wire[0]; 3],
                "each DiscoveryStarted reports the token its request carried"
            );
        });
    }

    /// `VerifyShares` carries a `secret_id` that has exactly one legal value:
    /// verification challenges the helpers holding *this* device's shares.
    /// A caller passing another id is told so, rather than being reported
    /// success for a secret the round never touched.
    #[test]
    fn verify_shares_refuses_a_foreign_secret_id() {
        run_async(async {
            let rig = StoreRig::new();
            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(rig.channels.clone())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(rig.secrets.clone())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(rig.state.clone())
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://owner.example"])
                .build()
                .expect("test rig builds");

            let err = protocol
                .start(DeRecFlow::VerifyShares {
                    secret_id: SECRET_ID ^ 0xFFFF,
                    version: 1,
                    target: crate::protocol::types::Target::All,
                })
                .await
                .expect_err("a foreign secret_id must be refused");
            assert!(
                matches!(err, crate::Error::InvalidInput(_)),
                "expected InvalidInput, got {err:?}"
            );

            // The instance's own id is accepted — the guard rejects the
            // mismatch, not the flow.
            protocol
                .start(DeRecFlow::VerifyShares {
                    secret_id: SECRET_ID,
                    version: 1,
                    target: crate::protocol::types::Target::All,
                })
                .await
                .expect("this instance's own secret_id is the legal value");
        });
    }

    /// Two rounds are two traces — the token is per-`start`, not per-process.
    #[test]
    fn separate_rounds_draw_separate_trace_ids() {
        run_async(async {
            let rig = StoreRig::new();
            let mut channels = rig.channels.clone();
            let mut secrets = rig.secrets.clone();
            seed_helper(&mut channels, &mut secrets, 11, 0xA1).await;

            let mut protocol = DeRecProtocolBuilder::new(SECRET_ID)
                .with_channel_store(channels)
                .with_share_store(InMemShareStore::default())
                .with_secret_store(secrets)
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_state_store(InMemPersistedStateStore::default())
                .with_transport(rig.transport.clone())
                .with_own_transports(["https://owner.example"])
                .build()
                .expect("test rig builds");

            for _ in 0..2 {
                protocol
                    .start(DeRecFlow::Discovery {
                        target: crate::protocol::types::Target::All,
                    })
                    .await
                    .expect("discovery starts");
            }

            let tokens: Vec<u64> = rig
                .transport
                .sent_envelopes()
                .iter()
                .map(|e| crate::derec_message::read_trace_id(e).expect("envelope decodes"))
                .collect();
            assert_eq!(tokens.len(), 2);
            assert_ne!(tokens[0], tokens[1], "each round draws its own token");
        });
    }
}

/// The round token is on the span, not just on the wire.
///
/// Every handler entered from [`DeRecProtocol::start`] records it through
/// `#[instrument(fields(trace_id = …))]`, so a log line emitted anywhere
/// under a round is attributable to it. This drives a real instrumented
/// handler rather than a hand-built span, which is what makes it a
/// regression net for the attribute itself.
#[cfg(all(test, feature = "logging"))]
mod trace_id_span_tests {
    use crate::protocol::test::{StoreRig, run_async};
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    #[test]
    fn a_handler_span_carries_the_round_token() {
        const TRACE_ID: u64 = 0xDEC0_DE15;

        let captured = Captured::default();
        let sink = captured.clone();
        // Span lifecycle events are what carry the recorded fields: the
        // handler's span opens and closes inside `start`, so nothing this
        // test emits itself would sit under it.
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            run_async(async {
                let mut rig = StoreRig::new();
                let lf = crate::protocol::test::LocalFixture::with_replica(0x5EC, 1001);
                // No peers, so the flow returns immediately — the span is
                // still entered, which is all this asserts.
                let _ = super::super::handlers::replicas::discovery::start(
                    &mut rig.stores(),
                    &lf.local(),
                    TRACE_ID,
                )
                .await;
            });
        });

        let text = captured.text();
        assert!(
            text.contains(&TRACE_ID.to_string()),
            "the handler's `fields(trace_id = ...)` must reach the subscriber; got: {text}"
        );
    }

    /// `start` draws its token inside the body, so its span declares the field
    /// empty and records it after the draw. That is a different mechanism from
    /// the attribute above, and it has its own way of silently not working.
    #[test]
    fn the_start_span_records_the_token_it_draws() {
        let captured = Captured::default();
        let sink = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            run_async(async {
                let rig = StoreRig::new();
                let mut protocol = crate::protocol::builder::DeRecProtocolBuilder::new(0x5EC)
                    .with_channel_store(rig.channels.clone())
                    .with_share_store(crate::protocol::test::InMemShareStore::default())
                    .with_secret_store(rig.secrets.clone())
                    .with_user_secret_store(crate::protocol::test::InMemUserSecretStore::default())
                    .with_state_store(rig.state.clone())
                    .with_transport(rig.transport.clone())
                    .with_own_transports(["https://owner.example"])
                    .build()
                    .expect("test rig builds");
                let _ = protocol
                    .start(crate::protocol::DeRecFlow::Discovery {
                        target: crate::protocol::types::Target::All,
                    })
                    .await;
            });
        });

        let text = captured.text();
        let recorded = text
            .lines()
            .find(|l| l.contains("start"))
            .unwrap_or_default();
        assert!(
            recorded.contains("trace_id"),
            "`start`'s span must carry the token it drew; got: {text}"
        );
        assert!(
            !recorded.contains("trace_id=Empty"),
            "the field must be recorded, not left empty; got: {recorded}"
        );
    }
}
