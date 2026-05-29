// SPDX-License-Identifier: Apache-2.0

use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::primitives::pairing::PairingError;
use crate::utils::verify_timestamps;
use derec_cryptography::pairing::{
    self as cryptography_pairing, PairingSecretKeyMaterial, PairingSharedKey,
};
use derec_proto::{
    CommunicationInfo, ContactMessage, DeRecMessage, DeRecResult, MessageBody, PairRequestMessage,
    PairResponseMessage, SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted inner
    /// [`derec_proto::PairResponseMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
    pub peer_transport_protocol: TransportProtocol,
    pub shared_key: PairingSharedKey,
}

pub struct ExtractResult {
    pub response: PairResponseMessage,
}

pub struct ProcessResult {
    pub shared_key: PairingSharedKey,
}

/// Produces a pairing response envelope and derives the final pairing shared key on the
/// **Initiator** side (the party that originally created the contact message).
///
/// After receiving the responder's pairing request, the initiator:
///
/// 1. Validates the provided [`derec_proto::PairRequestMessage`] contents
/// 2. Finalizes the initiator-side pairing computation using its previously stored
///    [`derec_cryptography::pairing::PairingSecretKeyMaterial`]
/// 3. Derives the final 256-bit [`derec_cryptography::pairing::PairingSharedKey`]
/// 4. Constructs a [`derec_proto::PairResponseMessage`] with an `Ok` status
/// 5. Encrypts the serialized inner response message to the responder's ECIES public key
/// 6. Wraps the encrypted inner bytes into a plain [`derec_proto::DeRecMessage`] envelope
///
/// Because the pairing flow does not yet rely on the final shared symmetric key for
/// transport, this function uses the pairing-specific **asymmetric** encryption mechanism
/// for the inner response message.
///
/// To signal rejection instead of acceptance, callers build the
/// [`derec_proto::PairResponseMessage`] themselves (with a non-`Ok`
/// [`derec_proto::StatusEnum`]) and encrypt it with [`crate::derec_message::DeRecMessageBuilder::pairing`].
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol
/// * `request` - The decoded [`derec_proto::PairRequestMessage`] previously returned by
///   [`super::request::extract`].
/// * `pairing_secret_key_material` - Initiator-side pairing secret state previously returned
///   by [`super::request::create_contact`]. Must be the
///   [`derec_cryptography::pairing::PairingSecretKeyMaterial::Initiator`] variant; passing the
///   `Responder` variant will return [`PairingError::Invariant`].
/// * `communication_info` - Optional application-level identity metadata to advertise to the
///   peer (free-form key/value pairs). Pass `None` to send no metadata; the protocol treats
///   this as opaque.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] envelope bytes carrying
///   the encrypted inner [`derec_proto::PairResponseMessage`]
/// - `shared_key`: the initiator-side derived pairing shared key
/// - `peer_transport_protocol`: peer transport information extracted from the
///   validated [`derec_proto::PairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::InvalidPairRequestMessage`] if the request is malformed or missing fields
/// - [`PairingError::EmptyTransportUri`] if the request transport information is missing or empty
/// - [`PairingError::Invariant`] if `pairing_secret_key_material` is not the `Initiator` variant
/// - [`PairingError::FinishPairingInitiator`] if pairing finalization fails
/// - [`PairingError::PairingEncryption`] if inner-message encryption fails
///
/// # Security Notes
///
/// - The derived shared key should be treated as sensitive material.
/// - The returned `peer_transport_protocol` is peer-provided data; apply any
///   caller-side validation required by the selected transport layer before using it.
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::{request, response};
/// use derec_library::types::ChannelId;
/// use derec_proto::{Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     TransportProtocol {
///         uri: "https://relay.example/initiator".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("create_contact failed");
///
/// // Responder side: build and send the pairing request envelope.
/// let request::ProduceResult { envelope: request_envelope, .. } = request::produce(
///     SenderKind::Helper,
///     TransportProtocol {
///         uri: "https://relay.example/responder".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     &contact_message,
///     None,
/// ).expect("produce failed");
///
/// // Initiator side: extract the pairing request, then produce the response.
/// let request::ExtractResult { request: pair_request } = request::extract(
///     &request_envelope,
///     initiator_key.ecies_secret_key(),
/// ).expect("extract failed");
///
/// let response::ProduceResult { envelope, shared_key, .. } = response::produce(
///     SenderKind::Owner,
///     &pair_request,
///     &initiator_key,
///     None,
/// ).expect("produce failed");
///
/// assert!(!envelope.is_empty());
/// let _ = shared_key;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = request.channel_id, kind = kind as i32))
)]
pub fn produce(
    kind: SenderKind,
    request: &PairRequestMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
    communication_info: Option<CommunicationInfo>,
) -> Result<ProduceResult, crate::Error> {
    validate_produce_inputs(request)?;

    let peer_transport_protocol = extract_peer_transport_protocol(request)?;

    let pairing_request = cryptography_pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: request.mlkem_ciphertext.clone(),
        ecies_public_key: request.ecies_public_key.clone(),
    };

    let initiator_material = match pairing_secret_key_material {
        cryptography_pairing::PairingSecretKeyMaterial::Initiator(m) => m,
        _ => {
            return Err(PairingError::Invariant(
                "expected Initiator key material for pairing response",
            )
            .into());
        }
    };

    let shared_key =
        cryptography_pairing::finish_pairing_initiator(initiator_material, &pairing_request)
            .map_err(|e| PairingError::FinishPairingInitiator { source: e })?;

    let timestamp = current_timestamp();
    let response = PairResponseMessage {
        sender_kind: kind.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: request.nonce,
        communication_info,
        parameter_range: None,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(request.channel_id.into())
        .timestamp(timestamp)
        .message_body(MessageBody::PairResponse(response))
        .encrypt_pairing(&request.ecies_public_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("pairing response envelope produced; initiator shared key derived");

    Ok(ProduceResult {
        envelope,
        shared_key,
        peer_transport_protocol,
    })
}

/// Decrypts and decodes an incoming [`derec_proto::PairResponseMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// Because pairing happens *before* a shared symmetric key exists, the inner message is
/// decrypted using the pairing-specific **asymmetric** ECIES decryption mechanism.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts the inner message bytes using `ecies_secret_key`
/// 3. Decodes the decrypted bytes as a [`derec_proto::PairResponseMessage`]
/// 4. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   asymmetrically-encrypted inner [`derec_proto::PairResponseMessage`], as produced by
///   [`produce`].
/// * `ecies_secret_key` - The responder's ECIES secret key. Must correspond to the
///   `ecies_public_key` the responder embedded in their [`derec_proto::PairRequestMessage`],
///   which is the key used by [`produce`] to encrypt the inner response.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::PairResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - ECIES decryption fails
/// - the decrypted bytes cannot be decoded as a [`derec_proto::PairResponseMessage`]
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::PairResponseMessage`]
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::{request, response};
/// use derec_library::types::ChannelId;
/// use derec_proto::{Protocol, SenderKind, TransportProtocol};
///
/// // Initiator: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     TransportProtocol {
///         uri: "https://relay.example/initiator".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("create_contact failed");
///
/// // Responder: build the pairing request envelope.
/// let request::ProduceResult {
///     envelope: request_envelope,
///     secret_key: responder_key,
///     ..
/// } = request::produce(
///     SenderKind::Helper,
///     TransportProtocol {
///         uri: "https://relay.example/responder".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     &contact_message,
///     None,
/// ).expect("produce failed");
///
/// // Initiator: extract the pairing request, then produce the response.
/// let request::ExtractResult { request: pair_request } = request::extract(
///     &request_envelope,
///     initiator_key.ecies_secret_key(),
/// ).expect("extract request failed");
/// let response::ProduceResult { envelope: response_envelope, .. } =
///     response::produce(SenderKind::Owner, &pair_request, &initiator_key, None)
///         .expect("produce failed");
///
/// // Responder: decrypt the pairing response.
/// let response::ExtractResult { response } =
///     response::extract(&response_envelope, responder_key.ecies_secret_key())
///         .expect("extract response failed");
///
/// assert_eq!(response.nonce, pair_request.nonce);
/// ```
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

    let response = match MessageBody::decode_from_vec(plaintext.as_slice())
        .map_err(crate::Error::ProtobufDecode)?
    {
        MessageBody::PairResponse(r) => r,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected PairResponseMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: PairResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing response extracted and validated");

    Ok(ExtractResult { response })
}

/// Processes a decrypted pairing response and derives the final pairing shared key on the
/// **Responder** side.
///
/// This function is executed by the party that:
///
/// 1. Received the initiator's contact out-of-band
/// 2. Produced and sent a pairing request using [`super::request::produce`]
///
/// After receiving the initiator's decrypted pairing response, the responder:
///
/// 1. Validates the response status and binds it to the same pairing session using the nonce
/// 2. Uses the responder's previously stored [`derec_cryptography::pairing::PairingSecretKeyMaterial`]
///    together with the initiator's original public pairing material from the contact message
///    to finalize the responder side
/// 3. Derives the final 256-bit [`derec_cryptography::pairing::PairingSharedKey`]
///
/// Both parties should derive the same shared key if the pairing flow completed successfully.
///
/// # Arguments
///
/// * `contact_message` - Decoded [`derec_proto::ContactMessage`] previously returned as
///   `initiator_contact_message` by [`super::request::produce`].
/// * `response` - The decrypted [`derec_proto::PairResponseMessage`] previously returned
///   by [`extract`].
/// * `pairing_secret_key_material` - Responder-side secret state previously returned by
///   [`super::request::produce`]. Must be the
///   [`derec_cryptography::pairing::PairingSecretKeyMaterial::Responder`] variant; passing the
///   `Initiator` variant will return [`PairingError::Invariant`].
///
/// # Returns
///
/// On success returns [`ProcessResult`] containing:
///
/// - `shared_key`: the responder-side derived pairing shared key
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::NonOkStatus`] if `result.status != Ok`, carrying the peer's status code
///   and memo string
/// - [`PairingError::InvalidPairResponseMessage`] if the response is malformed (e.g. missing result)
/// - [`PairingError::InvalidContactMessage`] if the contact message is missing required fields
/// - [`PairingError::ProtocolViolation`] if the response does not match the pairing session
///   (for example, nonce mismatch)
/// - [`PairingError::Invariant`] if `pairing_secret_key_material` is not the `Responder` variant
/// - [`PairingError::FinishPairingResponder`] if final pairing derivation fails
///
/// # Security Notes
///
/// - The nonce check is a critical session-binding validation.
/// - The derived shared key should be treated as sensitive material and stored securely.
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::{request, response};
/// use derec_library::types::ChannelId;
/// use derec_proto::{Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     TransportProtocol {
///         uri: "https://relay.example/initiator".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("create_contact failed");
///
/// // Responder side: build and send the pairing request envelope.
/// let request::ProduceResult {
///     envelope: request_envelope,
///     initiator_contact_message,
///     secret_key: responder_key,
/// } = request::produce(
///     SenderKind::Helper,
///     TransportProtocol {
///         uri: "https://relay.example/responder".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     &contact_message,
///     None,
/// ).expect("produce failed");
///
/// // Initiator side: extract the pairing request and produce the response.
/// let request::ExtractResult { request: pair_request } = request::extract(
///     &request_envelope,
///     initiator_key.ecies_secret_key(),
/// ).expect("extract request failed");
///
/// let response::ProduceResult { envelope: response_envelope, shared_key: initiator_shared_key, .. } =
///     response::produce(SenderKind::Owner, &pair_request, &initiator_key, None)
///         .expect("produce failed");
///
/// // Responder side: extract the pairing response and derive the shared key.
/// let response::ExtractResult { response: pair_response } = response::extract(
///     &response_envelope,
///     responder_key.ecies_secret_key(),
/// ).expect("extract response failed");
///
/// let response::ProcessResult { shared_key: responder_shared_key } =
///     response::process(&initiator_contact_message, &pair_response, &responder_key)
///         .expect("process failed");
///
/// assert_eq!(initiator_shared_key, responder_shared_key);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = contact_message.channel_id))
)]
pub fn process(
    contact_message: &ContactMessage,
    response: &PairResponseMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
) -> Result<ProcessResult, crate::Error> {
    validate_process_inputs(contact_message, response)?;

    let pk = cryptography_pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let responder_material = match pairing_secret_key_material {
        cryptography_pairing::PairingSecretKeyMaterial::Responder(m) => m,
        _ => {
            return Err(PairingError::Invariant(
                "expected Responder key material for pairing process",
            )
            .into());
        }
    };

    let shared_key = cryptography_pairing::finish_pairing_responder(responder_material, &pk)
        .map_err(|e| PairingError::FinishPairingResponder { source: e })?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing complete; responder shared key derived");

    Ok(ProcessResult { shared_key })
}

fn validate_produce_inputs(request: &PairRequestMessage) -> Result<(), crate::Error> {
    if request.mlkem_ciphertext.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("pair request missing mlkem_ciphertext");

        return Err(PairingError::InvalidPairRequestMessage("mlkem_ciphertext is empty").into());
    }

    if request.ecies_public_key.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("pair request missing ecies_public_key");

        return Err(PairingError::InvalidPairRequestMessage("ecies_public_key is empty").into());
    }

    Ok(())
}

fn extract_peer_transport_protocol(
    request: &PairRequestMessage,
) -> Result<TransportProtocol, crate::Error> {
    let peer_transport_protocol = request
        .transport_protocol
        .clone()
        .ok_or(PairingError::EmptyTransportUri)?;

    if peer_transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("peer transport URI is empty");

        return Err(PairingError::EmptyTransportUri.into());
    }

    Ok(peer_transport_protocol)
}

fn validate_process_inputs(
    contact_message: &ContactMessage,
    response: &PairResponseMessage,
) -> Result<(), crate::Error> {
    let res = response
        .result
        .as_ref()
        .ok_or(PairingError::InvalidPairResponseMessage("missing result"))?;

    if res.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = res.status, memo = %res.memo, "pair response status is not Ok");

        return Err(PairingError::NonOkStatus {
            status: res.status,
            memo: res.memo.to_owned(),
        }
        .into());
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

    if response.nonce != contact_message.nonce {
        #[cfg(feature = "logging")]
        tracing::warn!("nonce mismatch; possible replay or wrong pairing session");
        return Err(PairingError::ProtocolViolation("nonce mismatch").into());
    }

    Ok(())
}
