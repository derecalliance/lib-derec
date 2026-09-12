// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// The offer-list-else-legacy-field rule, shared by both implementors.
fn advertised<'a>(
    offers: &'a [derec_proto::TransportProtocol],
    legacy: Option<&'a derec_proto::TransportProtocol>,
) -> Vec<&'a derec_proto::TransportProtocol> {
    if offers.is_empty() {
        legacy.into_iter().collect()
    } else {
        offers.iter().collect()
    }
}

/// A peer-supplied message that advertises where its sender can be reached.
///
/// Implemented for every message type carrying the field pair:
/// [`ContactMessage`](derec_proto::ContactMessage),
/// [`PairRequestMessage`](derec_proto::PairRequestMessage),
/// [`PrePairRequestMessage`](derec_proto::PrePairRequestMessage) and
/// [`UpdateChannelInfoRequestMessage`](derec_proto::UpdateChannelInfoRequestMessage).
pub trait AdvertisedEndpoints {
    /// The endpoints this message advertises, in the peer's own order.
    ///
    /// Yields the `supportedTransports` offer list when it is non-empty, and
    /// otherwise the singular `transportProtocol` — which is how every
    /// implementation predating the offer list advertises, and the reason
    /// this is a method rather than a field read.
    ///
    /// Order is the peer's, preserved verbatim, and nothing is validated
    /// here: this reports what was advertised, not what is acceptable. Pass
    /// the result to [`TransportPolicy::admit_peer_endpoints`](crate::transport::TransportPolicy::admit_peer_endpoints) before
    /// recording any of it. Borrows rather than clones — nothing is copied
    /// until the policy has decided what survives.
    fn advertised_endpoints(&self) -> Vec<&derec_proto::TransportProtocol>;
}

impl AdvertisedEndpoints for derec_proto::ContactMessage {
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn advertised_endpoints(&self) -> Vec<&derec_proto::TransportProtocol> {
        advertised(&self.supported_transports, self.transport_protocol.as_ref())
    }
}

impl AdvertisedEndpoints for derec_proto::PairRequestMessage {
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn advertised_endpoints(&self) -> Vec<&derec_proto::TransportProtocol> {
        advertised(&self.supported_transports, self.transport_protocol.as_ref())
    }
}

impl AdvertisedEndpoints for derec_proto::PrePairRequestMessage {
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn advertised_endpoints(&self) -> Vec<&derec_proto::TransportProtocol> {
        advertised(&self.supported_transports, self.transport_protocol.as_ref())
    }
}

impl AdvertisedEndpoints for derec_proto::UpdateChannelInfoRequestMessage {
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn advertised_endpoints(&self) -> Vec<&derec_proto::TransportProtocol> {
        advertised(&self.supported_transports, self.transport_protocol.as_ref())
    }
}

/// A request that names where its response should be delivered.
///
/// The same offer-list-else-legacy-field rule as [`AdvertisedEndpoints`],
/// applied to the `replyTo` / `replyToTransports` pair on the five request
/// types that carry one.
///
/// The two are separate traits rather than one because the fields mean
/// different things. What [`AdvertisedEndpoints`] reports is where a peer can
/// be reached in general, and it is recorded on the channel; what this reports
/// overrides that for a single exchange and is deliberately *not* persisted.
/// A message can carry both, and conflating them would let a one-round-trip
/// override leak into the stored set.
pub trait ReplyToEndpoints {
    /// The endpoints this request asked to be answered on, in its own order.
    ///
    /// Empty means the requester named none, which is distinct from naming an
    /// unreachable one: the responder then falls back to the endpoints stored
    /// on the channel rather than failing to answer.
    fn reply_to_endpoints(&self) -> Vec<&derec_proto::TransportProtocol>;
}

/// Implement [`ReplyToEndpoints`] for a request carrying the field pair.
///
/// A macro rather than five hand-written impls: the bodies are identical, and
/// a sixth request type gaining a `replyTo` should not be able to acquire a
/// subtly different resolution rule by being written out by hand.
macro_rules! impl_reply_to_endpoints {
    ($($message:ty),+ $(,)?) => {
        $(
            impl ReplyToEndpoints for $message {
                // Compatibility, not oversight — see the `transport` module docs.
                #[allow(deprecated)]
                fn reply_to_endpoints(&self) -> Vec<&derec_proto::TransportProtocol> {
                    advertised(&self.reply_to_transports, self.reply_to.as_ref())
                }
            }
        )+
    };
}

impl_reply_to_endpoints!(
    derec_proto::StoreShareRequestMessage,
    derec_proto::VerifyShareRequestMessage,
    derec_proto::GetSecretIdsVersionsRequestMessage,
    derec_proto::GetShareRequestMessage,
    derec_proto::UnpairRequestMessage,
);

/// [`ReplyToEndpoints::reply_to_endpoints`] as owned values.
///
/// The borrowing form suits the policy-filtering path, which discards most of
/// what it inspects. A response path instead keeps everything it resolves and
/// hands it to a transport that outlives the request, so it would clone
/// immediately anyway.
pub(crate) fn reply_to_owned(
    request: &impl ReplyToEndpoints,
) -> Vec<derec_proto::TransportProtocol> {
    request.reply_to_endpoints().into_iter().cloned().collect()
}

/// Split a preference-ordered list into the pair a request puts on the wire.
///
/// The first entry fills the deprecated singular `replyTo`, which is what an
/// implementation predating `replyToTransports` reads, and the whole list
/// fills `replyToTransports`. Every writer goes through this so the two can
/// never disagree about which entry is the legacy-readable one.
pub(crate) fn split_reply_to(
    reply_to: &[derec_proto::TransportProtocol],
) -> (
    Option<derec_proto::TransportProtocol>,
    Vec<derec_proto::TransportProtocol>,
) {
    (reply_to.first().cloned(), reply_to.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportPolicy;
    use derec_proto::Protocol;

    fn endpoint(uri: &str, protocol: Protocol) -> derec_proto::TransportProtocol {
        derec_proto::TransportProtocol {
            uri: uri.to_owned(),
            protocol: protocol as i32,
        }
    }

    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn contact(
        offers: Vec<derec_proto::TransportProtocol>,
        legacy: Option<derec_proto::TransportProtocol>,
    ) -> derec_proto::ContactMessage {
        derec_proto::ContactMessage {
            supported_transports: offers,
            transport_protocol: legacy,
            ..Default::default()
        }
    }

    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn pair_request(
        offers: Vec<derec_proto::TransportProtocol>,
        legacy: Option<derec_proto::TransportProtocol>,
    ) -> derec_proto::PairRequestMessage {
        derec_proto::PairRequestMessage {
            supported_transports: offers,
            transport_protocol: legacy,
            ..Default::default()
        }
    }

    const STRICT: TransportPolicy = TransportPolicy::new(false);

    /// The peer's order survives untouched — the library has no opinion on
    /// which endpoint is better, and reordering here would silently become
    /// a preference the application never expressed.
    #[test]
    fn peer_order_is_preserved_verbatim() {
        let message = contact(
            vec![
                endpoint("grpcs://peer.example.com:443", Protocol::Grpc),
                endpoint("https://peer.example.com/derec", Protocol::Https),
            ],
            None,
        );

        let kept = STRICT
            .admit_peer_endpoints(message.advertised_endpoints())
            .expect("both endpoints are usable");

        assert_eq!(kept.len(), 2);
        assert_eq!(kept[0].uri, "grpcs://peer.example.com:443");
        assert_eq!(kept[1].uri, "https://peer.example.com/derec");
    }

    /// A peer predating the offer list advertises through the singular field
    /// alone; reading only `supportedTransports` would make it unreachable.
    #[test]
    fn empty_offers_fall_back_to_the_singular_field() {
        let message = contact(
            vec![],
            Some(endpoint("https://peer.example.com/derec", Protocol::Https)),
        );

        let advertised = message.advertised_endpoints();

        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].uri, "https://peer.example.com/derec");
    }

    /// A non-empty offer list wins outright: the singular field is a legacy
    /// duplicate of the first entry, not an extra endpoint to append.
    #[test]
    fn a_non_empty_offer_list_shadows_the_singular_field() {
        let message = contact(
            vec![endpoint("grpcs://peer.example.com:443", Protocol::Grpc)],
            Some(endpoint("https://peer.example.com/derec", Protocol::Https)),
        );

        let advertised = message.advertised_endpoints();

        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].uri, "grpcs://peer.example.com:443");
    }

    /// Both implementors share one rule; a divergence between them would be
    /// a peer reachable when it pairs but not when it is accepted.
    #[test]
    fn pair_request_advertises_identically_to_contact() {
        let offers = vec![endpoint("grpcs://peer.example.com:443", Protocol::Grpc)];
        let legacy = Some(endpoint("https://peer.example.com/derec", Protocol::Https));

        let from_contact = contact(offers.clone(), legacy.clone());
        let from_request = pair_request(offers, legacy);

        assert_eq!(
            from_contact.advertised_endpoints(),
            from_request.advertised_endpoints(),
        );

        let fallback_contact = contact(
            vec![],
            Some(endpoint("https://peer.example.com/derec", Protocol::Https)),
        );
        let fallback_request = pair_request(
            vec![],
            Some(endpoint("https://peer.example.com/derec", Protocol::Https)),
        );

        assert_eq!(
            fallback_contact.advertised_endpoints(),
            fallback_request.advertised_endpoints(),
        );
    }

    /// A plaintext entry is dropped, not fatal — the secure sibling survives
    /// and the peer stays reachable.
    #[test]
    fn policy_failing_endpoints_are_dropped_not_fatal() {
        let message = contact(
            vec![
                endpoint("grpc://peer.example.com:50051", Protocol::Grpc),
                endpoint("https://peer.example.com/derec", Protocol::Https),
            ],
            None,
        );

        let kept = STRICT
            .admit_peer_endpoints(message.advertised_endpoints())
            .expect("the secure sibling survives");

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].protocol, Protocol::Https as i32);
    }

    #[test]
    fn structurally_invalid_endpoints_are_dropped() {
        let message = contact(
            vec![
                endpoint("ws://peer.example.com", Protocol::Https),
                endpoint("https://peer.example.com/derec", Protocol::Https),
            ],
            None,
        );

        let kept = STRICT
            .admit_peer_endpoints(message.advertised_endpoints())
            .expect("the valid sibling survives");

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].uri, "https://peer.example.com/derec");
    }

    /// Every endpoint failing policy is fatal rather than a partial or
    /// guessed set: there is nowhere left to send the reply.
    #[test]
    fn all_endpoints_dropped_is_an_error() {
        let message = contact(
            vec![endpoint("grpc://peer.example.com:50051", Protocol::Grpc)],
            None,
        );

        let error = STRICT
            .admit_peer_endpoints(message.advertised_endpoints())
            .expect_err("the only endpoint is plaintext");

        assert!(matches!(
            error,
            crate::Error::NoUsableEndpoint { offered: 1 },
        ));
    }

    /// `offered` counts what the peer advertised, not what survived — the
    /// number is there to tell "sent nothing" apart from "sent only
    /// unusable endpoints" in a diagnostic.
    #[test]
    fn a_peer_advertising_nothing_reports_zero_offered() {
        let message = contact(vec![], None);

        let error = STRICT
            .admit_peer_endpoints(message.advertised_endpoints())
            .expect_err("nothing was advertised");

        assert!(matches!(
            error,
            crate::Error::NoUsableEndpoint { offered: 0 },
        ));
    }
}
