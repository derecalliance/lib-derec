// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// Structural validation for a decoded [`PrePairRequestMessage`], attached
/// as a method the same way [`ContactMessageExt`](super::contact_message::ContactMessageExt) and
/// [`PairRequestMessageExt`](super::pair_request::PairRequestMessageExt) attach it to their messages.
///
/// Sidesteps the orphan rule: the message is generated in `derec-proto`, so
/// the check cannot be an inherent method. Bring the trait into scope
/// (`use crate::extensions::pre_pair_request::PrePairRequestMessageExt as _;`) and call
/// `request.validate()?` before handing a peer-supplied request to protocol
/// code.
pub(crate) trait PrePairRequestMessageExt {
    /// Structural validator for a decoded [`PrePairRequestMessage`].
    ///
    /// The message carries only `nonce`, `transportProtocol` and
    /// `timestamp`, and just one of those is checkable from the message
    /// alone:
    ///
    /// - `transportProtocol`, when present, MUST be a structurally valid
    ///   endpoint — within the length cap, free of control characters, and
    ///   carrying a scheme consistent with its protocol discriminant.
    ///
    /// The other two are deliberately not checked here. `nonce` is only
    /// meaningful against the originating `ContactMessage`, which this
    /// message does not carry, and `timestamp` is validated as a *binding*
    /// against the outer envelope by
    /// [`verify_timestamps`] — a relationship between two messages rather
    /// than a property of this one.
    ///
    /// Says nothing about whether the endpoint is *acceptable*: that is
    /// [`TransportPolicy`](crate::transport::TransportPolicy)'s decision,
    /// applied to this message type through the inbound funnel.
    fn validate(&self) -> Result<(), crate::Error>;
}

impl PrePairRequestMessageExt for derec_proto::PrePairRequestMessage {
    // Compatibility, not oversight — see the `transport` module docs.
    #[allow(deprecated)]
    fn validate(&self) -> Result<(), crate::Error> {
        use crate::extensions::transport_protocol::TransportProtocolExt as _;

        if let Some(tp) = self.transport_protocol.as_ref() {
            tp.validate()?;
        }

        Ok(())
    }
}
