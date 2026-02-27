// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PairingError {
    #[error("transport_uri is empty")]
    EmptyTransportUri,

    #[error("invalid contact message: {0}")]
    InvalidContactMessage(&'static str),

    #[error("invalid pairing request message: {0}")]
    InvalidPairRequestMessage(&'static str),

    #[error("invalid pairing response message: {0}")]
    InvalidPairResponseMessage(&'static str),

    #[error("pairing protocol violation: {0}")]
    ProtocolViolation(&'static str),

    #[error("internal invariant violated: {0}")]
    Invariant(&'static str),

    #[error("failed to generate contact message key material")]
    ContactMessageKeygen {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to generate pairing request key material")]
    PairRequestKeygen {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to finalize pairing (contactor side)")]
    FinishPairingContactor {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },

    #[error("failed to finalize pairing (requestor side)")]
    FinishPairingRequestor {
        #[source]
        source: derec_cryptography::pairing::DerecPairingError,
    },
}
