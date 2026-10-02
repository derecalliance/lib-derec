// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::primitives::pairing::PairingError;

/// Structural validation for a decoded [`PairRequestMessage`], attached as a
/// method the same way [`ContactMessageExt`] attaches it to
/// [`ContactMessage`].
///
/// Sidesteps the orphan rule: the message is generated in `derec-proto`, so
/// the check cannot be an inherent method. Bring the trait into scope
/// (`use crate::extensions::pair_request::PairRequestMessageExt as _;`) and call
/// `request.validate()?` before handing a peer-supplied request to protocol
/// code.
pub(crate) trait PairRequestMessageExt {
    /// Structural validator for a decoded [`PairRequestMessage`]. Enforces
    /// the field-presence invariants the proto schema documents but cannot
    /// itself express:
    ///
    /// - `mlkem_ciphertext` MUST be present and non-empty — without it the
    ///   responder has no encapsulated secret to decapsulate.
    /// - `ecies_public_key` MUST be present and non-empty, for the same
    ///   reason on the ECIES half of the hybrid handshake.
    /// - The request MUST advertise at least one endpoint in
    ///   `supportedTransports`.
    ///
    /// Says nothing about whether those endpoints are *acceptable* — that is
    /// [`TransportPolicy`](crate::transport::TransportPolicy)'s decision, made
    /// later against configuration this validator cannot see.
    fn validate(&self) -> Result<(), crate::Error>;
}

impl PairRequestMessageExt for derec_proto::PairRequestMessage {
    fn validate(&self) -> Result<(), crate::Error> {
        if self.mlkem_ciphertext.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("pair request missing mlkem_ciphertext");

            return Err(
                PairingError::InvalidPairRequestMessage("mlkem_ciphertext is empty").into(),
            );
        }

        if self.ecies_public_key.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("pair request missing ecies_public_key");

            return Err(
                PairingError::InvalidPairRequestMessage("ecies_public_key is empty").into(),
            );
        }

        if self.supported_transports.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("pair request advertises no usable transport endpoint");

            return Err(PairingError::EmptyTransportUri.into());
        }

        Ok(())
    }
}
