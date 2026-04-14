// SPDX-License-Identifier: Apache-2.0

use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::primitives::pairing::error::PairingError;
use derec_cryptography::pairing::{
    self as cryptography_pairing, PairingSecretKeyMaterial, PairingSharedKey,
};
use derec_proto::{
    ContactMessage, DeRecMessage, DeRecResult, MessageBody, PairRequestMessage,
    PairResponseMessage, SenderKind, StatusEnum, TransportProtocol,
};
use prost::Message;

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted inner
    /// [`derec_proto::PairResponseMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
    /// Transport information extracted from the validated pairing request.
    pub responder_transport_protocol: TransportProtocol,
    /// Final pairing shared key derived by the initiator.
    pub shared_key: PairingSharedKey,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// Decrypted inner pairing response message.
    pub response: PairResponseMessage,
}

/// Result of [`process`].
pub struct ProcessResult {
    /// Final pairing shared key derived by the responder.
    pub shared_key: PairingSharedKey,
}

/// Produces a pairing response envelope and derives the final pairing shared key on the
/// **initiator** side.
///
/// This function is executed by the party that originally created the contact message.
/// After receiving the responder's pairing request, the initiator:
///
/// 1. Validates the provided [`derec_proto::PairRequestMessage`] contents
/// 2. Finalizes the initiator-side pairing computation using its previously stored
///    [`derec_cryptography::pairing::PairingSecretKeyMaterial`]
/// 3. Derives the final 256-bit [`derec_cryptography::pairing::PairingSharedKey`]
/// 4. Constructs a [`derec_proto::PairResponseMessage`]
/// 5. Encrypts the serialized inner response message to the responder's ECIES public key
/// 6. Wraps the encrypted inner bytes into a plain [`derec_proto::DeRecMessage`] envelope
///
/// Because the pairing flow still does not yet rely on the final shared symmetric key for
/// transport, this function uses the pairing-specific **asymmetric** encryption mechanism
/// for the inner response message.
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol
/// * `request` - The decoded [`derec_proto::PairRequestMessage`] previously returned by the
///   request module's `extract` function.
/// * `pairing_secret_key_material` - Initiator-side pairing secret state previously returned
///   by the request module's `create_contact` function.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] envelope bytes carrying
///   the encrypted inner [`derec_proto::PairResponseMessage`]
/// - `shared_key`: the initiator-side derived pairing shared key
/// - `responder_transport_protocol`: responder transport information extracted from the
///   validated [`derec_proto::PairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::InvalidPairRequestMessage`] if the request is malformed or missing fields
/// - [`PairingError::EmptyTransportUri`] if the request transport information is missing or empty
/// - [`PairingError::FinishPairingContactor`] if pairing finalization fails
/// - envelope construction or inner-message encryption fails
///
/// # Security Notes
///
/// - The derived shared key should be treated as sensitive material.
/// - The inner response message is encrypted to the responder's public key.
/// - The outer `DeRecMessage` envelope is plain protobuf metadata and is not itself encrypted.
/// - The returned `responder_transport_protocol` is peer-provided data; apply any
///   caller-side validation required by the selected transport layer before using it.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::pairing::{request, response};
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// // After extracting the pairing request:
/// // let request::ExtractResult { request } = request::extract(&envelope_bytes, &ecies_secret_key)?;
/// // let response::ProduceResult { envelope, shared_key, responder_transport_protocol } =
/// //     response::produce(Helper, &request, &initiator_secret_key)?;
/// ```
pub fn produce(
    kind: SenderKind,
    request: &PairRequestMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
) -> Result<ProduceResult, crate::Error> {
    if request.mlkem_ciphertext.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("mlkem_ciphertext is empty").into());
    }

    if request.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("ecies_public_key is empty").into());
    }

    let responder_transport_protocol = request
        .transport_protocol
        .clone()
        .ok_or(PairingError::EmptyTransportUri)?;

    if responder_transport_protocol.uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let pairing_request = cryptography_pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: request.mlkem_ciphertext.clone(),
        ecies_public_key: request.ecies_public_key.clone(),
    };

    let shared_key = cryptography_pairing::finish_pairing_contactor(
        pairing_secret_key_material,
        &pairing_request,
    )
    .map_err(|e| PairingError::FinishPairingContactor { source: e })?;

    let timestamp = current_timestamp();

    let response = PairResponseMessage {
        sender_kind: kind.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: request.nonce,
        communication_info: None,
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

    Ok(ProduceResult {
        envelope,
        shared_key,
        responder_transport_protocol,
    })
}

/// Decrypts the inner pairing response from an outer [`derec_proto::DeRecMessage`] envelope.
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
/// * `ecies_secret_key` - The ECIES secret key to use for decryption. This must correspond
///   to the public key embedded in the pairing request used during [`produce`].
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
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: PairResponseMessage",
            ));
        }
    };

    if envelope.timestamp != response.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    Ok(ExtractResult { response })
}

/// Processes a decrypted pairing response and derives the final pairing shared key on the
/// **responder** side.
///
/// This function is executed by the party that:
///
/// 1. Received the initiator's contact out-of-band
/// 2. Produced and sent a pairing request using the request module's `produce` function
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
///   `initiator_contact_message` by the request module's `produce` function.
/// * `response` - The decrypted [`derec_proto::PairResponseMessage`] previously returned
///   by [`extract`].
/// * `pairing_secret_key_material` - Responder-side secret state previously returned by
///   the request module's `produce` function.
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
/// - [`PairingError::InvalidContactMessage`] if the contact message is missing required fields
/// - [`PairingError::InvalidPairResponseMessage`] if the response indicates failure or is malformed
/// - [`PairingError::ProtocolViolation`] if the response does not match the pairing session
///   (for example, nonce mismatch or invalid status enum)
/// - [`PairingError::FinishPairingRequestor`] if final pairing derivation fails
///
/// # Security Notes
///
/// - The nonce check is a critical session-binding validation.
/// - The derived shared key should be treated as sensitive material and stored securely.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::pairing::{request, response};
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// // After extracting the pairing response and having the initiator contact and responder secret:
/// // let response::ExtractResult { response: resp } = response::extract(&envelope_bytes, &ecies_secret_key)?;
/// // let response::ProcessResult { shared_key } =
/// //     response::process(&initiator_contact_message, &resp, &responder_secret_key)?;
/// ```
pub fn process(
    contact_message: &ContactMessage,
    response: &PairResponseMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
) -> Result<ProcessResult, crate::Error> {
    if contact_message.mlkem_encapsulation_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }

    if contact_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    let res = response
        .result
        .as_ref()
        .ok_or(PairingError::InvalidPairResponseMessage("missing result"))?;

    let status = StatusEnum::try_from(res.status)
        .map_err(|_| PairingError::ProtocolViolation("invalid status enum value"))?;

    if status != StatusEnum::Ok {
        return Err(
            PairingError::InvalidPairResponseMessage("response indicates non-ok status").into(),
        );
    }

    if response.nonce != contact_message.nonce {
        return Err(PairingError::ProtocolViolation("nonce mismatch").into());
    }

    let pk = cryptography_pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let shared_key =
        cryptography_pairing::finish_pairing_requestor(pairing_secret_key_material, &pk)
            .map_err(|e| PairingError::FinishPairingRequestor { source: e })?;

    Ok(ProcessResult { shared_key })
}
