// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Which of a peer's endpoints this library is willing to record.
//!
//! The library **filters**; the application **chooses**. Filtering is a
//! guardrail the library must own, because it decides what it will persist
//! and propagate onward to other peers. Choosing between the survivors —
//! and failing over when one is unreachable — is transport mechanism, which
//! belongs to the application implementing
//! [`DeRecTransport`](crate::protocol::DeRecTransport).
//!
//! Nothing is negotiated on the wire. There is no capability exchange and no
//! round trip: each side filters what the other advertised, independently.
//!
//! The two halves are deliberately separate. [`AdvertisedEndpoints`] answers
//! *what did this peer advertise* — a property of the message's shape, so it
//! lives on the message. [`TransportPolicy::admit_peer_endpoints`] answers
//! *which of those will we accept* — a property of the policy, so it lives
//! there. Keeping them apart means a caller cannot reach the second without
//! passing through the first.

use super::TransportPolicy;

impl TransportPolicy {
    /// Keep the advertised endpoints this library is willing to record.
    ///
    /// Takes what [`AdvertisedEndpoints::advertised_endpoints`](crate::extensions::advertised_endpoints::AdvertisedEndpoints::advertised_endpoints) reported and
    /// applies [`check_peer`](Self::check_peer) to each. Order is the peer's,
    /// preserved verbatim. This does not rank: ranking would mean the library
    /// choosing a transport on the application's behalf, and the application
    /// is the only party that knows which of its own transports is reachable,
    /// cheap, or currently healthy.
    ///
    /// An endpoint failing structural validation or policy is dropped with a
    /// warning rather than failing the whole set, so a peer advertising both
    /// a plaintext and a secure endpoint still pairs over the secure one.
    ///
    /// # Errors
    ///
    /// [`Error::NoUsableEndpoint`](crate::Error::NoUsableEndpoint) when
    /// nothing survives — including when the peer advertised nothing at all.
    /// Every caller treats an empty survivor set as fatal (there is nowhere
    /// to send the reply), which is why this returns `Result` rather than an
    /// empty `Vec` each caller must remember to check.
    pub fn admit_peer_endpoints(
        &self,
        advertised: Vec<&derec_proto::TransportProtocol>,
    ) -> Result<Vec<derec_proto::TransportProtocol>, crate::Error> {
        let offered = advertised.len();

        let mut seen: Vec<i32> = Vec::new();
        let kept: Vec<derec_proto::TransportProtocol> = advertised
            .into_iter()
            .filter(|endpoint| match self.check_peer(endpoint) {
                Ok(()) => true,
                Err(_reason) => {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        uri = %endpoint.uri,
                        error = %_reason,
                        "dropping a peer-advertised transport endpoint; the peer's \
                         remaining endpoints, if any, are still recorded",
                    );
                    false
                }
            })
            // A device serves one address per protocol, so a second entry for
            // a protocol already offered contradicts the first rather than
            // adding reach. The earlier entry wins: the list is the peer's own
            // preference order, so the first is the one it prefers.
            //
            // Filtered rather than refused. A peer's advertisement is
            // untrusted input, and failing the whole message over a
            // contradiction we can resolve would abort a pairing that has a
            // perfectly usable endpoint in it. This device's *own* endpoints
            // are held to the stricter rule — see
            // [`TransportPolicy::check_own_set`].
            .filter(|endpoint| {
                if seen.contains(&endpoint.protocol) {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        uri = %endpoint.uri,
                        protocol = endpoint.protocol,
                        "dropping a duplicate peer-advertised protocol; the \
                         earlier entry for it is kept",
                    );
                    return false;
                }
                seen.push(endpoint.protocol);
                true
            })
            .cloned()
            .collect();

        if kept.is_empty() {
            return Err(crate::Error::NoUsableEndpoint { offered });
        }

        Ok(kept)
    }
}
