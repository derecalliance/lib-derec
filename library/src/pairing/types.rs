// SPDX-License-Identifier: Apache-2.0

use derec_cryptography::pairing::{self as cryptography_pairing, PairingSecretKeyMaterial};
use derec_proto::{ContactMessage, TransportProtocol};

/// Result of [`create_contact_message`].
///
/// This type contains the serialized out-of-band contact payload together with the
/// freshly generated initiator-side pairing secret key material.
///
/// The `wire_bytes` field contains a plain serialized [`derec_proto::ContactMessage`].
/// It is intended to be delivered out of band, for example via QR code, deep link,
/// clipboard transfer, or another side channel.
///
/// The `secret_key` field contains the pairing secret key material associated with
/// that contact. Callers must preserve it securely and pass it back into later
/// pairing steps when processing the responder's reply.
pub struct CreateContactMessageResult {
    /// Plain serialized [`derec_proto::ContactMessage`] bytes.
    pub wire_bytes: Vec<u8>,

    /// Initiator-side pairing secret key material associated with this contact.
    pub secret_key: PairingSecretKeyMaterial,
}

/// Result of [`produce_pairing_request_message`].
///
/// This type contains the responder-side pairing request envelope together with the
/// freshly generated responder-side pairing secret key material.
///
/// The `wire_bytes` field contains a serialized outer [`derec_proto::DeRecMessage`]
/// envelope. Its inner payload is an encrypted [`derec_proto::PairRequestMessage`].
///
/// The `initiator_contact_message` field is the decoded initiator contact message. It
/// provides the responder with the initiator's transport endpoint, public keys, channel
/// identifier, and nonce — everything needed to complete the pairing flow.
///
/// The `secret_key` field contains the responder-side pairing secret key material
/// generated while constructing the request. Callers must preserve it securely and
/// later pass it into [`process_pairing_response_message`] to derive the final
/// shared pairing key.
pub struct ProducePairingRequestMessageResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
    /// inner [`derec_proto::PairRequestMessage`].
    pub wire_bytes: Vec<u8>,

    /// The validated [`derec_proto::ContactMessage`] decoded from the initiator's out-of-band
    /// contact bytes. Provides the responder with the initiator's transport endpoint, public
    /// keys, channel identifier, and nonce — everything needed to complete the pairing flow.
    pub initiator_contact_message: ContactMessage,

    /// Responder-side pairing secret key material associated with this request.
    pub secret_key: PairingSecretKeyMaterial,
}

/// Result of [`produce_pairing_response_message`].
///
/// This type contains the initiator-side pairing response envelope together with the
/// derived final shared pairing key and the transport information extracted from the
/// incoming pairing request.
///
/// The `wire_bytes` field contains a serialized outer [`derec_proto::DeRecMessage`]
/// envelope. Its inner payload is an encrypted [`derec_proto::PairResponseMessage`].
///
/// The `transport_protocol` field is copied from the validated pairing request and
/// tells the initiator which transport endpoint and transport protocol the responder
/// wants to use for subsequent communication.
///
/// The `shared_key` field is the final pairing shared key derived by the initiator.
/// This key is expected to match the responder-side key later produced by
/// [`process_pairing_response_message`].
pub struct ProducePairingResponseMessageResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
    /// inner [`derec_proto::PairResponseMessage`].
    pub wire_bytes: Vec<u8>,

    /// Transport information extracted from the validated pairing request.
    pub responder_transport_protocol: TransportProtocol,

    /// Final pairing shared key derived by the initiator.
    pub shared_key: cryptography_pairing::PairingSharedKey,
}

/// Result of [`process_pairing_response_message`].
///
/// This type contains the responder-side final shared pairing key derived after
/// validating and processing the initiator's pairing response.
///
/// The derived `shared_key` is expected to match the initiator-side shared key
/// returned earlier by [`produce_pairing_response_message`]. Once both sides have
/// derived the same key, it can be used as the symmetric channel key for subsequent
/// encrypted protocol messages.
pub struct ProcessPairingResponseMessageResult {
    /// Final pairing shared key derived by the responder.
    pub shared_key: cryptography_pairing::PairingSharedKey,
}
