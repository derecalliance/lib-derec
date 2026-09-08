// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Construction, configuration, and contact creation.
//!
//! Everything that shapes a [`DeRecProtocol`] before or between rounds: how it
//! is built, what it advertises about itself, and the contact a peer scans to
//! reach it. Nothing here drives a protocol round.

use super::DeRecProtocol;
use super::events::{AutoAcceptPolicy, UnpairAck};
use super::traits::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use super::types::{PairingKeyMaterial, SecretValue};
use crate::{
    Result, primitives::pairing::request::create_contact as create_contact_message,
    types::ChannelId,
};
use derec_proto::{ContactMessage, ContactMode, TransportProtocol};
use std::collections::HashMap;

impl<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    T: DeRecTransport,
    St: DeRecStateStore,
> DeRecProtocol<Ch, Sh, Ss, Us, St, T>
{
    /// Construct a [`DeRecProtocol`] directly from its components.
    ///
    /// Prefer [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder) for the type-checked
    /// construction path; both entry points run the same runtime
    /// validation and surface the same errors.
    ///
    /// `own_transports` must be non-empty and in preference order — the
    /// first entry is treated as this device's primary endpoint. Unlike
    /// the builder, this constructor does not run [`TransportPolicy`
    /// ](crate::transport::TransportPolicy) validation on them; callers
    /// bypassing [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder) own that check themselves.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidInput`] if `threshold < 2`. A
    /// threshold of `0` or `1` collapses threshold secret sharing and
    /// lets a single helper reconstruct the secret unilaterally — two
    /// is the minimum value that preserves secret confidentiality
    /// against one compromised helper.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_id: u64,
        channel_store: Ch,
        share_store: Sh,
        secret_store: Ss,
        user_secret_store: Us,
        state_store: St,
        transport: T,
        own_transports: Vec<TransportProtocol>,
        threshold: usize,
        keep_versions_count: usize,
        timeouts: crate::protocol::types::Timeouts,
    ) -> Result<Self> {
        if threshold < 2 {
            return Err(crate::Error::InvalidInput(
                "threshold must be >= 2; 0 or 1 lets a single helper reconstruct the secret \
                 and defeats threshold sharing",
            ));
        }
        Ok(Self {
            channel_store,
            share_store,
            secret_store,
            user_secret_store,
            state_store,
            transport,
            own_transports,
            unpair_ack: UnpairAck::Required,
            threshold,
            keep_versions_count,
            timeouts,
            unsafe_http: false,
            communication_info: HashMap::new(),
            auto_respond_on_failure: false,
            auto_reply_to: false,
            auto_accept: AutoAcceptPolicy::default(),
            replica_id: None,
            parameter_range: None,
            secret_id,
        })
    }

    /// Returns the secret identifier this protocol instance was configured with.
    pub fn secret_id(&self) -> u64 {
        self.secret_id
    }

    /// Returns the configured local replica id, or `None` if the protocol
    /// was built without [`DeRecProtocolBuilder::with_replica_id`](crate::protocol::DeRecProtocolBuilder::with_replica_id).
    ///
    /// Apps can use this to surface "replica flows are enabled" to the user,
    /// or to inspect their own identity for logging/diagnostics. The id is
    /// the same value that the orchestrator auto-injects under
    /// `derec.replica_id` in outbound replica-mode `PairRequest` /
    /// `PairResponse` envelopes.
    pub fn replica_id(&self) -> Option<u64> {
        self.replica_id
    }

    /// Generate an out-of-band contact message (QR code payload, deep link, …).
    ///
    /// Either party (Owner or Helper) may call this to begin a pairing session.
    /// The returned [`ContactMessage`] should be delivered out-of-band to the peer.
    /// Any material the library needs later — either the ephemeral pairing
    /// secret (`InlineKeys` / `HashedKeys`) or the contact itself (`NoKeys`) —
    /// is persisted automatically via the configured stores.
    ///
    /// # Channel ID
    ///
    /// Pass `Some(id)` to use a specific channel identifier, or `None` to have
    /// the library generate a random one. Applications targeting `NoKeys` mode
    /// typically pass a small human-typable value (4 digits) for manual entry.
    ///
    /// # Contact mode
    ///
    /// - [`ContactMode::InlineKeys`] embeds the initiator's ML-KEM + ECIES
    ///   public keys directly in the contact. Simplest to use; the contact is
    ///   ~1.2 KB.
    /// - [`ContactMode::HashedKeys`] embeds only a SHA-384 binding hash over
    ///   the keys. The contact stays small enough for a QR code; the scanner
    ///   obtains the real keys via a `PrePair` round-trip and validates them
    ///   against the hash. Requires every endpoint in `own_transports` —
    ///   all of them are advertised in the contact's `supported_transports`
    ///   — to be **ephemeral**, since the plaintext PrePair traffic must
    ///   not be linkable to a long-lived endpoint.
    /// - [`ContactMode::NoKeys`] carries no key material and no commitment —
    ///   only `channel_id`, `nonce`, and `transport_protocol`. Small enough
    ///   to be hand-typed. Keys are generated on the fly by the creator when
    ///   the corresponding `PrePairRequest` arrives; trust rests entirely on
    ///   the OOB delivery channel being fully trusted (e.g. a verified email
    ///   from an already-KYC-authenticated institution). Applications MUST
    ///   rate-limit inbound `PrePairRequest`s per `channel_id` and expire
    ///   outstanding NoKeys contacts on a short timer.
    ///
    /// # Nonce
    ///
    /// - `None`: the library generates a fresh cryptographically-random
    ///   `u64`. Recommended default for `InlineKeys` and `HashedKeys` where
    ///   the nonce is a security parameter.
    /// - `Some(n)`: application-controlled value. Required for `NoKeys`
    ///   where the recipient typically types it in; also valid for the
    ///   other modes if the app wants deterministic control.
    ///
    /// # What is persisted
    ///
    /// Each mode leaves behind what its inbound handler will need to look the
    /// contact back up:
    ///
    /// - `InlineKeys` and `HashedKeys` store the generated secret key as
    ///   [`SecretKind::PairingSecret`](crate::protocol::SecretKind::PairingSecret). The handler decrypts the encrypted
    ///   `PairRequest` with it, and republishes the keys on the `PrePair` leg
    ///   for `HashedKeys`.
    /// - `NoKeys` has no key material yet, so the contact itself is stored as
    ///   [`SecretKind::PairingContact`](crate::protocol::SecretKind::PairingContact). The inbound `PrePairRequest` handler
    ///   authenticates the caller by matching its `nonce` against it, then
    ///   generates fresh key material for the response.
    #[cfg_attr(feature = "logging", tracing::instrument(skip_all))]
    pub async fn create_contact(
        &mut self,
        channel_id: Option<ChannelId>,
        contact_mode: ContactMode,
        nonce: Option<u64>,
    ) -> Result<ContactMessage> {
        let channel_id = channel_id.unwrap_or_else(|| ChannelId(rand::random::<u64>()));

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            contact_mode = contact_mode as i32,
            "creating contact message"
        );

        let result =
            create_contact_message(channel_id, contact_mode, self.own_transports.clone(), nonce)?;

        match result.secret_key {
            Some(secret_key) => {
                self.secret_store
                    .save(
                        self.secret_id,
                        channel_id,
                        SecretValue::PairingSecret(PairingKeyMaterial::from_secret(&secret_key)),
                    )
                    .await?;
            }
            None => {
                self.secret_store
                    .save(
                        self.secret_id,
                        channel_id,
                        SecretValue::PairingContact(result.contact_message.clone()),
                    )
                    .await?;
            }
        }

        #[cfg(feature = "logging")]
        tracing::info!(channel_id = channel_id.0, "contact message created");

        Ok(result.contact_message)
    }

    /// Replace this node's local communication info.
    ///
    /// Only mutates local state — to propagate the change to paired peers,
    /// follow up with [`DeRecFlow::UpdateChannelInfo`](crate::protocol::DeRecFlow::UpdateChannelInfo).
    ///
    /// # Destructive replacement
    ///
    /// The supplied map fully replaces the current value. An empty map will
    /// be transmitted as "clear all entries" when a subsequent
    /// `UpdateChannelInfo` flow runs, which the peer will mirror into its
    /// stored map. Pass the complete new map, not a delta.
    pub fn set_communication_info(&mut self, info: HashMap<String, String>) {
        self.communication_info = info;
    }

    /// Replace this node's local transport endpoint.
    ///
    /// Only mutates local state — to propagate the change to paired peers,
    /// follow up with [`DeRecFlow::UpdateChannelInfo`](crate::protocol::DeRecFlow::UpdateChannelInfo).
    ///
    /// # Endpoint changeover discipline
    ///
    /// When `UpdateChannelInfo` is broadcast, each receiving peer routes its
    /// response (and all subsequent messages) to the NEW endpoint. The
    /// application MUST therefore:
    ///
    /// 1. Bring up the new endpoint and start listening on it **before**
    ///    initiating the `UpdateChannelInfo` flow.
    /// 2. Keep the old endpoint operational during the changeover. Peers
    ///    that have not yet processed the update still route to the old
    ///    address; in-flight messages may also be targeted there.
    /// 3. Retire the old endpoint only once every targeted peer has
    ///    surfaced [`DeRecEvent::ChannelInfoUpdated`](crate::protocol::DeRecEvent::ChannelInfoUpdated) (or
    ///    [`DeRecEvent::ChannelInfoUpdateRejected`](crate::protocol::DeRecEvent::ChannelInfoUpdateRejected)), plus a grace window
    ///    for in-flight traffic.
    ///
    /// Failing to keep both endpoints reachable during this window will
    /// cause messages to be lost.
    /// Replace this device's endpoint **for one protocol**, leaving the
    /// others alone.
    ///
    /// A device serves at most one address per protocol, so an endpoint
    /// identifies the protocol it speaks. Setting one therefore means
    /// "this is where I now serve HTTPS" — the gRPC entry beside it is
    /// untouched, and the replaced entry keeps its position in the
    /// preference order, because changing an address is not a change of
    /// preference. An endpoint for a protocol not yet served is appended.
    ///
    /// Accepts anything implementing
    /// [`IntoOwnTransport`](crate::transport::IntoOwnTransport): a
    /// typed [`crate::transport::TransportProtocol`], a `&str`, or a
    /// `String`. Validation runs eagerly — a malformed URI surfaces
    /// as [`crate::Error::Transport`] instead of being stored and
    /// later propagated to peers.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Transport`] if the supplied value
    /// fails URI validation (empty, oversize, control characters,
    /// or scheme mismatch).
    /// # Migrating
    ///
    /// [`Self::set_own_transports`] takes the whole preference list and is
    /// what this becomes internally, so a single-endpoint deployment
    /// migrates by wrapping its argument:
    ///
    /// ```ignore
    /// // before
    /// protocol.set_own_transport("https://me.example/derec")?;
    /// // after
    /// protocol.set_own_transports(["https://me.example/derec"])?;
    /// ```
    ///
    /// The singular spelling is still going away: it can change exactly one
    /// protocol's endpoint, so a device altering which protocols it serves —
    /// or their order — has to reach for [`Self::set_own_transports`]
    /// anyway. Two setters for one piece of state is the redundancy being
    /// removed, not a defect in what this one now does.
    #[deprecated(
        since = "0.0.3",
        note = "use `set_own_transports`, which takes the whole preference \
                list; removed at 0.0.5"
    )]
    pub fn set_own_transport(
        &mut self,
        own_transport: impl crate::transport::IntoOwnTransport,
    ) -> crate::Result<()> {
        let endpoint: derec_proto::TransportProtocol = own_transport.into_own_transport()?.into();
        match self
            .own_transports
            .iter_mut()
            .find(|e| e.protocol == endpoint.protocol)
        {
            Some(existing) => *existing = endpoint,
            None => self.own_transports.push(endpoint),
        }
        Ok(())
    }

    /// Replace the endpoints this device advertises, in preference order.
    ///
    /// The runtime counterpart to
    /// [`DeRecProtocolBuilder::with_own_transports`](crate::protocol::DeRecProtocolBuilder::with_own_transports).
    /// The way to change *which* protocols this device serves, or their
    /// preference order — [`Self::set_own_transport`] can only re-point a
    /// protocol already in the list.
    ///
    /// A device serves at most one endpoint per protocol, so the list is a
    /// preference order over distinct protocols; see the
    /// [`transport`](crate::transport) module docs.
    ///
    /// The list is validated and stored whole, so peers learn the new set
    /// in the order given. Read the discipline on
    /// [`Self::set_own_transport`] before broadcasting a change — the same
    /// overlap window applies.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Transport`] if any entry fails URI
    /// validation or if the list names one protocol twice, or
    /// [`crate::Error::InvalidInput`] if the list is empty: a device that
    /// advertises nothing cannot be reached, and the builder cannot produce
    /// that state either.
    ///
    /// Held to exactly the rules [`DeRecProtocolBuilder::build`](crate::protocol::DeRecProtocolBuilder::build)
    /// applies, so a set can never reach a state the builder would refuse.
    /// Nothing is stored unless every check passes.
    pub fn set_own_transports<I, E>(&mut self, own_transports: I) -> crate::Result<()>
    where
        I: IntoIterator<Item = E>,
        E: crate::transport::IntoOwnTransport,
    {
        let validated: Vec<crate::transport::TransportProtocol> = own_transports
            .into_iter()
            .map(crate::transport::IntoOwnTransport::into_own_transport)
            .collect::<std::result::Result<_, _>>()?;
        if validated.is_empty() {
            return Err(crate::Error::InvalidInput(
                "own transports must not be empty",
            ));
        }
        let wire: Vec<derec_proto::TransportProtocol> =
            validated.into_iter().map(Into::into).collect();
        self.transport_policy().check_own_set(&wire)?;
        self.own_transports = wire;
        Ok(())
    }
}

#[cfg(test)]
mod own_transport_setter_tests {
    use super::*;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport,
    };

    const SECRET_ID: u64 = 0x60A7;

    type Proto = DeRecProtocol<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        NoopTransport,
    >;

    fn build(endpoints: &[&str]) -> crate::Result<Proto> {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports(endpoints.to_vec())
            .with_threshold(2)
            .build()
    }

    /// A device serving both protocols, HTTPS preferred.
    fn multi_protocol() -> Proto {
        build(&["https://primary.example", "grpcs://primary.example:443"]).expect("builds")
    }

    fn uris(p: &Proto) -> Vec<String> {
        p.own_transports.iter().map(|t| t.uri.clone()).collect()
    }

    // ---------------------------------------------------------------
    // One endpoint per protocol
    // ---------------------------------------------------------------

    /// Two addresses for the same protocol contradict rather than extend:
    /// a peer would have no rule for choosing, and two peers could choose
    /// differently. The builder refuses the set even though each entry is
    /// individually well-formed.
    #[test]
    fn the_builder_refuses_two_endpoints_of_one_protocol() {
        // `DeRecProtocol` is not `Debug` (its stores need not be), so the Ok
        // side cannot be unwrapped for the message.
        let Err(err) = build(&["https://a.example", "https://b.example"]) else {
            panic!("one protocol may name only one endpoint");
        };
        assert!(
            matches!(
                err,
                crate::Error::Transport(
                    crate::transport::TransportValidationError::DuplicateProtocol { .. }
                )
            ),
            "got {err:?}"
        );
    }

    /// Distinct protocols are the point of a list, so they are accepted and
    /// the order given is the order peers are told.
    #[test]
    fn distinct_protocols_are_kept_in_the_order_given() {
        let p = multi_protocol();
        assert_eq!(
            uris(&p),
            vec![
                "https://primary.example".to_owned(),
                "grpcs://primary.example:443".to_owned()
            ]
        );
    }

    /// The runtime setter is held to the same rule as the builder — the two
    /// cannot disagree about what a valid advertisement is.
    #[test]
    fn set_own_transports_refuses_two_endpoints_of_one_protocol() {
        let mut p = multi_protocol();
        let before = uris(&p);
        let err = p
            .set_own_transports(["https://a.example", "https://b.example"])
            .expect_err("one protocol may name only one endpoint");
        assert!(
            matches!(
                err,
                crate::Error::Transport(
                    crate::transport::TransportValidationError::DuplicateProtocol { .. }
                )
            ),
            "got {err:?}"
        );
        assert_eq!(uris(&p), before, "a refused set must not mutate the list");
    }

    // ---------------------------------------------------------------
    // The singular setter: a per-protocol override
    // ---------------------------------------------------------------

    /// Setting an HTTPS endpoint re-points HTTPS and nothing else. The
    /// device still serves gRPC at the address it always did.
    #[test]
    #[allow(deprecated)]
    fn set_own_transport_replaces_only_its_own_protocol() {
        let mut p = multi_protocol();
        p.set_own_transport("https://moved.example")
            .expect("valid endpoint");
        assert_eq!(
            uris(&p),
            vec![
                "https://moved.example".to_owned(),
                "grpcs://primary.example:443".to_owned()
            ],
            "re-pointing HTTPS must not disturb the gRPC entry"
        );
    }

    /// Changing an address is not a change of preference: the replaced
    /// entry keeps its position, so a routine move never silently demotes a
    /// protocol below the others.
    #[test]
    #[allow(deprecated)]
    fn a_replaced_endpoint_keeps_its_position() {
        let mut p = multi_protocol();
        p.set_own_transport("grpcs://moved.example:443")
            .expect("valid endpoint");
        assert_eq!(
            uris(&p),
            vec![
                "https://primary.example".to_owned(),
                "grpcs://moved.example:443".to_owned()
            ],
            "gRPC was second and must stay second"
        );
    }

    /// A protocol not yet served is added rather than replacing anything.
    #[test]
    #[allow(deprecated)]
    fn an_unserved_protocol_is_appended() {
        let mut p = build(&["https://only.example"]).expect("builds");
        p.set_own_transport("grpcs://new.example:443")
            .expect("valid endpoint");
        assert_eq!(
            uris(&p),
            vec![
                "https://only.example".to_owned(),
                "grpcs://new.example:443".to_owned()
            ]
        );
    }

    /// The override cannot produce a state the builder would refuse.
    #[test]
    #[allow(deprecated)]
    fn repeated_overrides_never_duplicate_a_protocol() {
        let mut p = multi_protocol();
        for uri in [
            "https://a.example",
            "https://b.example",
            "https://c.example",
        ] {
            p.set_own_transport(uri).expect("valid endpoint");
        }
        assert_eq!(
            uris(&p),
            vec![
                "https://c.example".to_owned(),
                "grpcs://primary.example:443".to_owned()
            ],
            "each set replaces the previous HTTPS entry rather than stacking"
        );
    }

    // ---------------------------------------------------------------
    // Refusals leave the previous list intact
    // ---------------------------------------------------------------

    /// A device that advertises nothing cannot be reached, and the
    /// builder cannot produce that state either.
    #[test]
    fn set_own_transports_refuses_an_empty_list() {
        let mut p = multi_protocol();
        let before = uris(&p);
        let err = p
            .set_own_transports(Vec::<String>::new())
            .expect_err("an empty endpoint list must be refused");
        assert!(matches!(err, crate::Error::InvalidInput(_)), "got {err:?}");
        assert_eq!(uris(&p), before, "a refused set must not mutate the list");
    }

    /// Validation runs before anything is stored, so a bad entry cannot
    /// leave the list half-updated.
    #[test]
    fn set_own_transports_rejects_a_malformed_entry_without_mutating() {
        let mut p = multi_protocol();
        let before = uris(&p);
        let err = p
            .set_own_transports(["https://good.example", "not a uri"])
            .expect_err("a malformed endpoint must be refused");
        assert!(matches!(err, crate::Error::Transport(_)), "got {err:?}");
        assert_eq!(
            uris(&p),
            before,
            "a refused set must leave the previous endpoints intact"
        );
    }

    /// A malformed singular override leaves the served set untouched.
    #[test]
    #[allow(deprecated)]
    fn a_malformed_override_does_not_mutate() {
        let mut p = multi_protocol();
        let before = uris(&p);
        let err = p
            .set_own_transport("not a uri")
            .expect_err("a malformed endpoint must be refused");
        assert!(matches!(err, crate::Error::Transport(_)), "got {err:?}");
        assert_eq!(uris(&p), before);
    }
}

#[cfg(test)]
mod transport_gate_tests {
    use super::*;
    use crate::extensions::message_body::MessageBodyExt as _;
    use crate::protocol::builder::DeRecProtocolBuilder;
    use crate::protocol::test::{
        InMemChannelStore, InMemPersistedStateStore, InMemSecretStore, InMemShareStore,
        InMemUserSecretStore, NoopTransport, run_async,
    };

    const SECRET_ID: u64 = 0x60A7;

    // Exercises the deprecated `with_unsafe_http` deliberately — this is
    // the regression net proving the old flag still works unchanged.
    #[allow(deprecated)]
    fn builder_with(
        own: &str,
        unsafe_http: bool,
    ) -> crate::Result<
        DeRecProtocol<
            InMemChannelStore,
            InMemShareStore,
            InMemSecretStore,
            InMemUserSecretStore,
            InMemPersistedStateStore,
            NoopTransport,
        >,
    > {
        DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemChannelStore::default())
            .with_share_store(InMemShareStore::default())
            .with_secret_store(InMemSecretStore::default())
            .with_user_secret_store(InMemUserSecretStore::default())
            .with_transport(NoopTransport)
            .with_state_store(InMemPersistedStateStore::default())
            .with_own_transports([own])
            .with_threshold(2)
            .with_unsafe_http(unsafe_http)
            .build()
    }

    /// The zero-config developer case: a loopback dev server just works.
    #[test]
    fn own_loopback_needs_no_configuration() {
        run_async(async {
            for uri in [
                "http://localhost:8080",
                "http://127.0.0.1:8080",
                "http://[::1]:8080",
            ] {
                assert!(builder_with(uri, false).is_ok(), "{uri} should build");
            }
        });
    }

    /// The LAN case — a phone talking to a laptop — is what the flag exists
    /// for, and it is refused until you ask for it.
    #[test]
    fn own_lan_plaintext_needs_the_flag() {
        run_async(async {
            let Err(err) = builder_with("http://192.168.1.42:8080", false) else {
                panic!("LAN plaintext must not build by default");
            };
            assert!(
                matches!(
                    err,
                    crate::Error::Transport(
                        crate::transport::TransportValidationError::PlaintextRefused { .. }
                    )
                ),
                "expected a plaintext refusal, got {err:?}"
            );
            assert!(builder_with("http://192.168.1.42:8080", true).is_ok());
        });
    }

    /// Order of the two setters must not matter — the policy is applied at
    /// `build`, not when either one is called.
    #[test]
    #[allow(deprecated)]
    fn setter_order_does_not_matter() {
        run_async(async {
            let built = DeRecProtocolBuilder::new(SECRET_ID)
                .with_unsafe_http(true)
                .with_channel_store(InMemChannelStore::default())
                .with_share_store(InMemShareStore::default())
                .with_secret_store(InMemSecretStore::default())
                .with_user_secret_store(InMemUserSecretStore::default())
                .with_transport(NoopTransport)
                .with_state_store(InMemPersistedStateStore::default())
                .with_own_transports(["http://192.168.1.42:8080"])
                .with_threshold(2)
                .build();
            assert!(built.is_ok(), "unsafe_http set before the endpoint");
        });
    }

    /// `https` is unaffected by any of this.
    #[test]
    fn https_builds_under_either_setting() {
        run_async(async {
            assert!(builder_with("https://owner.example.com", false).is_ok());
            assert!(builder_with("https://owner.example.com", true).is_ok());
        });
    }

    /// The accessor the funnel depends on must actually see every field a
    /// peer controls. If a new message type gains a `reply_to` or a
    /// transport, this is what should fail first.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn every_peer_supplied_endpoint_is_reachable_from_the_funnel() {
        use derec_proto::{MessageBody, TransportProtocol};
        let one = || TransportProtocol {
            uri: "http://127.0.0.1:9999".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        };
        // Only `reply_to` reaches the funnel now, and it is a list.
        let eps = || vec![one()];

        let bodies = [
            MessageBody::StoreShareRequest(derec_proto::StoreShareRequestMessage {
                reply_to: eps(),
                ..Default::default()
            }),
            MessageBody::VerifyShareRequest(derec_proto::VerifyShareRequestMessage {
                reply_to: eps(),
                ..Default::default()
            }),
            MessageBody::GetSecretIdsVersionsRequest(
                derec_proto::GetSecretIdsVersionsRequestMessage {
                    reply_to: eps(),
                    ..Default::default()
                },
            ),
            MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
                reply_to: eps(),
                ..Default::default()
            }),
            MessageBody::UnpairRequest(derec_proto::UnpairRequestMessage {
                reply_to: eps(),
                ..Default::default()
            }),
        ];

        for body in &bodies {
            let found: Vec<_> = body.peer_supplied_endpoints().collect();
            assert_eq!(
                found.len(),
                1,
                "the funnel missed the peer endpoint on {body:?}"
            );
            // And the strict policy refuses it — peer loopback is not free.
            assert!(
                crate::transport::TransportPolicy::new(false)
                    .check_peer(found[0])
                    .is_err()
            );
        }
    }

    /// `PairRequest` is the deliberate exception to the funnel: it carries
    /// an offer list, and gating on its legacy singular field ahead of
    /// `admit_peer_endpoints` would fail-fast on an endpoint that a later
    /// one in the list would have survived. Locks in the exclusion so it isn't
    /// re-added by habit alongside the other message types above.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn pair_request_is_not_gated_by_the_funnel() {
        use derec_proto::MessageBody;
        let body = MessageBody::PairRequest(derec_proto::PairRequestMessage {
            transport_protocol: Some(derec_proto::TransportProtocol {
                uri: "http://127.0.0.1:9999".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }),
            ..Default::default()
        });
        assert_eq!(body.peer_supplied_endpoints().count(), 0);
    }

    /// `UpdateChannelInfo` is excluded for the same reason, with an extra
    /// one: fail-fasting here would reject the whole announcement and leave
    /// the peer's *stale* endpoints in place. Its handler filters instead.
    #[test]
    fn update_channel_info_is_not_gated_by_the_funnel() {
        use derec_proto::MessageBody;
        let body =
            MessageBody::UpdateChannelInfoRequest(derec_proto::UpdateChannelInfoRequestMessage {
                supported_transports: vec![derec_proto::TransportProtocol {
                    uri: "http://127.0.0.1:9999".to_owned(),
                    protocol: derec_proto::Protocol::Https as i32,
                }],
                ..Default::default()
            });
        assert_eq!(body.peer_supplied_endpoints().count(), 0);
    }

    /// `PrePairRequest` is excluded for the same reason, and additionally
    /// could not be gated here at all: it is plaintext and takes its own
    /// dispatch path, which never reaches this function. Its endpoints are
    /// filtered in `pre_pair::accept` / `pre_pair::reject` instead.
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    #[test]
    fn pre_pair_request_is_not_gated_by_the_funnel() {
        use derec_proto::MessageBody;
        let body = MessageBody::PrePairRequest(derec_proto::PrePairRequestMessage {
            transport_protocol: Some(derec_proto::TransportProtocol {
                uri: "http://127.0.0.1:9999".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }),
            supported_transports: vec![derec_proto::TransportProtocol {
                uri: "http://127.0.0.1:9999".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            ..Default::default()
        });
        assert_eq!(body.peer_supplied_endpoints().count(), 0);
    }
}
