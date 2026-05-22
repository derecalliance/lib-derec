// SPDX-License-Identifier: Apache-2.0

use crate::primitives::pairing::error::PairingError;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp},
    types::ChannelId,
    utils::generate_seed,
};
use derec_cryptography::pairing::{self as cryptography_pairing, PairingSecretKeyMaterial};
use derec_proto::{
    CommunicationInfo, ContactMessage, DeRecMessage, MessageBody, PairRequestMessage, SenderKind,
    TransportProtocol,
};
use prost::Message;
use rand::{Rng, rng};

pub struct CreateContactResult {
    /// Decoded [`derec_proto::ContactMessage`] — serialize with `.encode_to_vec()` before sending out-of-band.
    pub contact_message: ContactMessage,
    /// Initiator-side pairing secret key material associated with this contact.
    pub secret_key: PairingSecretKeyMaterial,
}

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted inner
    /// [`derec_proto::PairRequestMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
    /// The validated [`derec_proto::ContactMessage`] decoded from the initiator's out-of-band
    /// contact bytes.
    pub initiator_contact_message: ContactMessage,
    /// Responder-side pairing secret key material associated with this request.
    pub secret_key: PairingSecretKeyMaterial,
}

pub struct ExtractResult {
    /// Decrypted inner pairing request message.
    pub request: PairRequestMessage,
}

/// Creates a [`derec_proto::ContactMessage`] used to bootstrap the DeRec *pairing* flow.
///
/// In DeRec, pairing begins with an **out-of-band contact transfer** (typically QR or
/// another side channel). Unlike normal DeRec protocol traffic, the contact message is
/// **not wrapped in a `DeRecMessage` envelope** and is **not encrypted**. It is sent as
/// plain protobuf bytes (serialize the returned `contact_message` with `.encode_to_vec()`).
///
/// The contact contains:
///
/// - The initiator's public pairing material
/// - The initiator's transport information
/// - The logical `channel_id` associated with the pairing session
/// - A fresh nonce identifying the pairing session
/// - A creation timestamp
///
/// The returned [`derec_cryptography::pairing::PairingSecretKeyMaterial`] must be stored
/// locally and treated as secret state; it is required later to finalize the pairing flow
/// and derive the shared pairing key.
///
/// # Arguments
///
/// * `channel_id` - Identifier associated with the generated pairing key material.
///   This value is embedded into the contact and later copied into pairing messages
///   so the peer can associate the session with the correct channel.
/// * `transport_protocol` - Transport endpoint and protocol the peer should use for
///   subsequent DeRec protocol messages after reading the contact.
///   The `uri` field must not be empty or whitespace-only.
///
/// # Returns
///
/// On success returns [`CreateContactResult`] containing:
///
/// - `contact_message`: decoded [`derec_proto::ContactMessage`] — serialize with
///   `.encode_to_vec()` before sending out-of-band
/// - `secret_key`: secret pairing state that must be retained locally
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::EmptyTransportUri`] if `transport_protocol.uri` is empty or whitespace
/// - [`PairingError::ContactMessageKeygen`] if pairing key generation fails
///
/// # Security Notes
///
/// - The `contact_message` is public and intended for out-of-band exchange.
/// - The returned secret key material must be protected.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::pairing::request;
/// use derec_library::types::ChannelId;
/// use derec_proto::{Protocol, TransportProtocol};
///
/// let channel_id = ChannelId(42);
///
/// let request::CreateContactResult {
///     contact_message,
///     secret_key,
/// } = request::create_contact(
///     channel_id,
///     TransportProtocol {
///         uri: "https://relay.example/derec".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("Failed to create contact message");
///
/// let _ = (contact_message, secret_key);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn create_contact(
    channel_id: ChannelId,
    transport_protocol: TransportProtocol,
) -> Result<CreateContactResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("transport URI is empty");
        return Err(PairingError::EmptyTransportUri.into());
    }

    let mut rng = rng();
    let seed = generate_seed::<32>();

    let (pk, secret_key) = cryptography_pairing::contact_message(*seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e })?;

    let contact_message = ContactMessage {
        channel_id: channel_id.into(),
        transport_protocol: Some(transport_protocol),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        timestamp: Some(current_timestamp()),
    };

    #[cfg(feature = "logging")]
    tracing::info!("contact message created");

    Ok(CreateContactResult {
        contact_message,
        secret_key: PairingSecretKeyMaterial::Initiator(secret_key),
    })
}

/// Produces a pairing request [`derec_proto::DeRecMessage`] envelope, continuing the DeRec
/// pairing flow.
///
/// This function is executed by the **responder** (the party that scanned or otherwise
/// received the initiator's contact out-of-band).
///
/// Under the current protocol model:
///
/// 1. The initiator sends a [`derec_proto::ContactMessage`] out-of-band
/// 2. The responder decodes that contact, performs the responder-side pairing-request
///    cryptographic step, and constructs a [`derec_proto::PairRequestMessage`]
/// 3. The inner [`derec_proto::PairRequestMessage`] is protobuf-serialized and then encrypted
///    using the initiator's public ECIES key
/// 4. The encrypted bytes are placed into a plain [`derec_proto::DeRecMessage`] envelope
/// 5. The final result is serialized envelope bytes ready to be sent over the transport
///
/// Because pairing happens *before* a shared symmetric key exists, this function uses the
/// pairing-specific **asymmetric** encryption mechanism for the inner message.
///
/// The returned [`derec_cryptography::pairing::PairingSecretKeyMaterial`] must be retained
/// locally and later used to finalize pairing when the response arrives.
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol (for example
///   `Owner`, `Helper`, or `Replica`)
/// * `transport_protocol` - Transport endpoint the initiator can use to reach this responder
///   for subsequent protocol traffic. The `uri` field must not be empty or whitespace-only.
/// * `contact_message` - The decoded [`derec_proto::ContactMessage`] received from the
///   initiator, as returned by [`create_contact`] and decoded by the caller.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] envelope bytes
/// - `initiator_contact_message`: the decoded initiator [`derec_proto::ContactMessage`],
///   providing transport endpoint, public keys, channel identifier, and nonce
/// - `secret_key`: responder-side pairing secret state required later to derive the final
///   shared pairing key
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::EmptyTransportUri`] if `transport_protocol.uri` is empty or whitespace
/// - [`PairingError::InvalidContactMessage`] if required contact fields are missing or the
///   contact transport protocol is absent or has an empty URI
/// - [`PairingError::PairRequestKeygen`] if ML-KEM encapsulation or key generation fails
/// - [`PairingError::PairingEncryption`] if inner-message encryption fails
///
/// # Security Notes
///
/// - The `contact_message` is peer-provided data; validate all required fields before use.
/// - The returned secret key material must be securely retained by the responder.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::pairing::request;
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// // Assuming contact_message was received out-of-band from the initiator:
/// // let request::ProduceResult { envelope, initiator_contact_message, secret_key } =
/// //     request::produce(
/// //         Helper,
/// //         TransportProtocol { uri: "https://relay.example/responder".to_owned(), protocol: Protocol::Https.into() },
/// //         &contact_message,
/// //     )?;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = contact_message.channel_id, kind = kind as i32))
)]
pub fn produce(
    kind: SenderKind,
    transport_protocol: TransportProtocol,
    contact_message: &ContactMessage,
    communication_info: Option<CommunicationInfo>,
) -> Result<ProduceResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("transport URI is empty");
        return Err(PairingError::EmptyTransportUri.into());
    }

    if contact_message.mlkem_encapsulation_key.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("contact message missing mlkem_encapsulation_key");
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }

    if contact_message.ecies_public_key.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("contact message missing ecies_public_key");
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    {
        let initiator_tp = contact_message.transport_protocol.as_ref().ok_or(
            PairingError::InvalidContactMessage("transport_protocol is missing"),
        )?;
        if initiator_tp.uri.trim().is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("contact message transport_protocol.uri is empty");
            return Err(
                PairingError::InvalidContactMessage("transport_protocol.uri is empty").into(),
            );
        }
    }

    let contact_pk = cryptography_pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let seed = generate_seed::<32>();

    let (req_pk, secret_key) = cryptography_pairing::pairing_request_message(*seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e })?;

    let timestamp = current_timestamp();

    let request = PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: req_pk.mlkem_ciphertext,
        ecies_public_key: req_pk.ecies_public_key,
        channel_id: contact_message.channel_id,
        nonce: contact_message.nonce,
        communication_info,
        parameter_range: None,
        transport_protocol: Some(transport_protocol),
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(contact_message.channel_id.into())
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(request))
        .encrypt_pairing(&contact_message.ecies_public_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("pairing request envelope produced");

    Ok(ProduceResult {
        envelope,
        initiator_contact_message: contact_message.clone(),
        secret_key: PairingSecretKeyMaterial::Responder(secret_key),
    })
}

/// Decrypts the inner pairing request from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// Because pairing happens *before* a shared symmetric key exists, the inner message is
/// decrypted using the pairing-specific **asymmetric** ECIES decryption mechanism.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts the inner message bytes using `ecies_secret_key`
/// 3. Decodes the decrypted bytes as a [`derec_proto::PairRequestMessage`]
/// 4. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   asymmetrically-encrypted inner [`derec_proto::PairRequestMessage`], as produced by
///   [`produce`].
/// * `ecies_secret_key` - The initiator's ECIES secret key. Must correspond to the
///   `ecies_public_key` the initiator published in their [`derec_proto::ContactMessage`],
///   which is the key used by [`produce`] to encrypt the inner request.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::PairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - ECIES decryption fails
/// - the decrypted bytes cannot be decoded as a [`derec_proto::PairRequestMessage`]
/// - `envelope.timestamp != request.timestamp`
/// - the inner message is not a [`derec_proto::PairRequestMessage`]
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(envelope_len = envelope_bytes.len()))
)]
pub fn extract(
    envelope_bytes: &[u8],
    ecies_secret_key: &[u8],
) -> Result<ExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let plaintext =
        derec_cryptography::pairing::envelope::decrypt(&envelope.message, ecies_secret_key)
            .map_err(PairingError::PairingEncryption)?;

    let request = match MessageBody::decode_from_vec(plaintext.as_slice())
        .map_err(crate::Error::ProtobufDecode)?
    {
        MessageBody::PairRequest(r) => r,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected PairRequestMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: PairRequestMessage",
            ));
        }
    };

    if envelope.timestamp != request.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("pairing request extracted and validated");

    Ok(ExtractResult { request })
}
