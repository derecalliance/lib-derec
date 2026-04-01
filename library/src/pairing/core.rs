// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp},
    pairing::{
        CreateContactMessageResult, PairingError, ProcessPairingResponseMessageResult,
        ProducePairingRequestMessageResult, ProducePairingResponseMessageResult,
    },
    types::ChannelId,
    utils::generate_seed,
};
use derec_cryptography::pairing;
use derec_proto::{
    ContactMessage, DeRecMessage, DeRecResult, PairRequestMessage, PairResponseMessage, SenderKind,
    StatusEnum, TransportProtocol,
};
use prost::Message;
use rand::{Rng, rng};

/// Creates a serialized [`ContactMessage`] used to bootstrap the DeRec *pairing* flow.
///
/// In DeRec, pairing begins with an **out-of-band contact transfer** (typically QR or
/// another side channel). Unlike normal DeRec protocol traffic, the contact message is
/// **not wrapped in a `DeRecMessage` envelope** and is **not encrypted**. It is sent as
/// plain protobuf bytes.
///
/// The contact contains:
///
/// - The initiator’s public pairing material
/// - The initiator’s transport information
/// - The logical `channel_id` associated with the pairing session
/// - A fresh nonce identifying the pairing session
/// - A creation timestamp
///
/// The returned [`pairing::PairingSecretKeyMaterial`] must be stored locally and treated as
/// secret state; it is required later to finalize the pairing flow and derive the
/// shared pairing key.
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
/// On success returns [`CreateContactMessageResult`] containing:
///
/// - `wire_bytes`: serialized [`ContactMessage`] protobuf bytes to send out-of-band
/// - `secret_key`: secret pairing state that must be retained locally
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - `PairingError::EmptyTransportUri` if `transport_protocol.uri` is empty or whitespace
/// - `PairingError::ContactMessageKeygen { .. }` if pairing key generation fails
///
/// # Security Notes
///
/// - The returned `wire_bytes` are public and intended for out-of-band exchange
/// - The returned secret key material must be protected
/// - The session nonce is generated from a cryptographically secure RNG and is later
///   used to bind pairing messages to the same session
///
/// # Example
///
/// ```rust
/// use derec_library::pairing::*;
/// use derec_library::types::ChannelId;
/// use derec_proto::{Protocol, TransportProtocol};
///
/// let channel_id = ChannelId(42);
///
/// let CreateContactMessageResult {
///     wire_bytes,
///     secret_key,
/// } = create_contact_message(
///     channel_id,
///     TransportProtocol {
///         uri: "https://relay.example/derec".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("Failed to create contact message");
///
/// assert!(!wire_bytes.is_empty());
/// let _ = secret_key;
/// ```
pub fn create_contact_message(
    channel_id: ChannelId,
    transport_protocol: TransportProtocol,
) -> Result<CreateContactMessageResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let mut rng = rng();
    let seed = generate_seed::<32>();

    let (pk, sk) = pairing::contact_message(*seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e })?;

    let message = ContactMessage {
        channel_id: channel_id.into(),
        transport_protocol: Some(transport_protocol),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        timestamp: Some(current_timestamp()),
    };

    let wire_bytes = message.encode_to_vec();

    Ok(CreateContactMessageResult {
        wire_bytes,
        secret_key: sk,
    })
}

/// Produces a serialized pairing request wrapped in a plain [`derec_proto::DeRecMessage`]
/// envelope, continuing the DeRec pairing flow.
///
/// This function is executed by the **responder** (the party that scanned or otherwise
/// received the initiator’s contact bytes out-of-band).
///
/// Under the current protocol model:
///
/// 1. The initiator sends a plain serialized [`ContactMessage`] out-of-band
/// 2. The responder decodes that contact, performs the responder-side pairing-request
///    cryptographic step, and constructs a [`PairRequestMessage`]
/// 3. The inner [`PairRequestMessage`] is protobuf-serialized and then encrypted using the
///    initiator’s public ECIES key
/// 4. The encrypted bytes are placed into the `message` field of a plain
///    [`derec_proto::DeRecMessage`] envelope
/// 5. The final result is serialized envelope bytes ready to be sent over the transport
///
/// Because pairing happens *before* a shared symmetric key exists, this function uses the
/// pairing-specific **asymmetric** encryption mechanism for the inner message.
///
/// The returned [`pairing::PairingSecretKeyMaterial`] must be retained locally and later used to
/// finalize pairing when the response arrives.
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol (for example
///   `SharerNonRecovery`, `SharerRecovery`, or `Helper`)
/// * `transport_protocol` - Transport endpoint the initiator can use to reach this responder
///   for subsequent protocol traffic. The `uri` field must not be empty or whitespace-only.
/// * `contact_message_bytes` - Plain serialized [`ContactMessage`] received from the initiator
///
/// # Returns
///
/// On success returns [`ProducePairingRequestMessageResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] envelope bytes
/// - `initiator_contact_message`: the decoded initiator [`derec_proto::ContactMessage`],
///   providing transport endpoint, public keys, channel identifier, and nonce
/// - `secret_key`: responder-side pairing secret state required later to derive the final
///   shared pairing key
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - the provided contact bytes are not a valid [`ContactMessage`]
/// - `PairingError::EmptyTransportUri` if `transport_protocol.uri` is empty or whitespace
/// - `PairingError::InvalidContactMessage` if required contact fields are missing or the
///   contact transport protocol is absent or has an empty URI
/// - `PairingError::PairRequestKeygen { .. }` if ML-KEM encapsulation or key generation fails
/// - envelope construction or inner-message encryption fails
///
/// # Security Notes
///
/// - `contact_message_bytes` are untrusted input and must be validated
/// - The inner pairing request is encrypted to the initiator’s public key
/// - The outer `DeRecMessage` envelope is plain protobuf metadata and is not itself encrypted
/// - The returned secret key material must be securely retained by the responder
/// - The returned `initiator_transport_protocol` is peer-provided data; apply any
///   caller-side validation required by the selected transport layer before using it
///
/// # Example
///
/// ```rust
/// use derec_library::pairing::*;
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// let CreateContactMessageResult {
///     wire_bytes: contact_message_bytes,
///     ..
/// } = create_contact_message(
///     42.into(),
///     TransportProtocol {
///         uri: "https://relay.example/derec".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
/// ).expect("Failed to create contact message");
///
/// let ProducePairingRequestMessageResult {
///     wire_bytes,
///     initiator_contact_message,
///     secret_key,
/// } = produce_pairing_request_message(
///     Helper,
///     TransportProtocol {
///         uri: "https://relay.example/responder".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     &contact_message_bytes,
/// ).expect("Failed to produce pairing request message");
///
/// assert!(!wire_bytes.is_empty());
/// assert_eq!(initiator_contact_message.transport_protocol.unwrap().uri, "https://relay.example/derec");
/// let _ = secret_key;
/// ```
pub fn produce_pairing_request_message(
    kind: SenderKind,
    transport_protocol: TransportProtocol,
    contact_message_bytes: &[u8],
) -> Result<ProducePairingRequestMessageResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let contact_message =
        ContactMessage::decode(contact_message_bytes).map_err(crate::Error::ProtobufDecode)?;

    if contact_message.mlkem_encapsulation_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }

    if contact_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    {
        let initiator_tp = contact_message.transport_protocol.as_ref().ok_or(
            PairingError::InvalidContactMessage("transport_protocol is missing"),
        )?;
        if initiator_tp.uri.trim().is_empty() {
            return Err(
                PairingError::InvalidContactMessage("transport_protocol.uri is empty").into(),
            );
        }
    }

    let contact_pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let seed = generate_seed::<32>();

    let (req_pk, secret_key) = pairing::pairing_request_message(*seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e })?;

    let timestamp = current_timestamp();

    let request = PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: req_pk.mlkem_ciphertext,
        ecies_public_key: req_pk.ecies_public_key,
        channel_id: contact_message.channel_id,
        nonce: contact_message.nonce,
        communication_info: None,
        parameter_range: None,
        transport_protocol: Some(transport_protocol),
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::pairing()
        .channel_id(contact_message.channel_id.into())
        .timestamp(timestamp)
        .message(&request)
        .encrypt_pairing(&contact_message.ecies_public_key)?
        .build()?
        .encode_to_vec();

    Ok(ProducePairingRequestMessageResult {
        wire_bytes,
        initiator_contact_message: contact_message,
        secret_key,
    })
}

/// Produces a serialized pairing response wrapped in a plain [`derec_proto::DeRecMessage`]
/// envelope and derives the final pairing shared key on the **initiator** side.
///
/// This function is executed by the party that originally created the contact message.
/// After receiving the responder’s serialized pairing-request envelope, the initiator:
///
/// 1. Decrypts and decodes the inner [`PairRequestMessage`] from the provided wire bytes
/// 2. Validates the pairing request contents
/// 3. Finalizes the initiator-side pairing computation using its previously stored
///    [`pairing::PairingSecretKeyMaterial`]
/// 4. Derives the final 256-bit [`pairing::PairingSharedKey`]
/// 5. Constructs a [`PairResponseMessage`]
/// 6. Encrypts the serialized inner response message to the responder’s ECIES public key
/// 7. Wraps the encrypted inner bytes into a plain [`derec_proto::DeRecMessage`] envelope
///
/// Because the pairing flow still does not yet rely on the final shared symmetric key for
/// transport, this function uses the pairing-specific **asymmetric** encryption mechanism
/// for the inner response message.
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol
/// * `pair_request_wire_bytes` - Serialized outer [`derec_proto::DeRecMessage`] containing
///   the encrypted inner [`PairRequestMessage`]
/// * `pairing_secret_key_material` - Initiator-side pairing secret state previously returned
///   by [`create_contact_message`]
///
/// # Returns
///
/// On success returns [`ProducePairingResponseMessageResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] envelope bytes carrying
///   the encrypted inner [`PairResponseMessage`]
/// - `shared_key`: the initiator-side derived pairing shared key
/// - `responder_transport_protocol`: responder transport information extracted from the validated
///   [`PairRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - the provided request bytes cannot be decoded/decrypted into a valid pairing request
/// - `PairingError::EmptyTransportUri` if the request transport information is missing or empty
/// - `PairingError::InvalidPairRequestMessage` if the request is malformed or missing fields
/// - `PairingError::FinishPairingContactor { .. }` if pairing finalization fails
/// - envelope construction or inner-message encryption fails
///
/// # Security Notes
///
/// - `pair_request_wire_bytes` are untrusted input and must be decrypted, decoded, and validated
/// - The derived shared key should be treated as sensitive material
/// - The inner response message is encrypted to the responder’s public key
/// - The outer `DeRecMessage` envelope is plain protobuf metadata and is not itself encrypted
/// - The returned `responder_transport_protocol` is peer-provided data and should only be used after any
///   caller-side validation required by the selected transport layer
///
/// # Example
///
/// ```rust
/// use derec_library::pairing::*;
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// let CreateContactMessageResult {
///     wire_bytes: contact_bytes,
///     secret_key: initiator_secret_key,
/// } = create_contact_message(
///     42.into(),
///     TransportProtocol { uri: "https://relay.example/derec".to_owned(), protocol: Protocol::Https.into() },
/// ).expect("Failed to create contact message");
///
/// let ProducePairingRequestMessageResult {
///     wire_bytes: pair_request_wire_bytes,
///     ..
/// } = produce_pairing_request_message(
///     Helper,
///     TransportProtocol { uri: "https://relay.example/responder".to_owned(), protocol: Protocol::Https.into() },
///     &contact_bytes,
/// ).expect("Failed to produce pairing request message");
///
/// let ProducePairingResponseMessageResult {
///     wire_bytes,
///     shared_key,
///     responder_transport_protocol,
/// } = produce_pairing_response_message(
///     Helper,
///     &pair_request_wire_bytes,
///     &initiator_secret_key,
/// ).expect("Failed to produce pairing response message");
///
/// assert!(!wire_bytes.is_empty());
/// let _ = (shared_key, responder_transport_protocol);
/// ```
pub fn produce_pairing_response_message(
    kind: SenderKind,
    request_bytes: impl AsRef<[u8]>,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<ProducePairingResponseMessageResult, crate::Error> {
    let receiver_secret_key = pairing_secret_key_material.ecies_secret_key.clone();

    let (envelope, request) = extract_inner_pairing_message::<PairRequestMessage>(
        request_bytes.as_ref(),
        &receiver_secret_key,
    )?;

    if envelope.timestamp != request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    if request.mlkem_ciphertext.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("mlkem_ciphertext is empty").into());
    }

    if request.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("ecies_public_key is empty").into());
    }

    let transport_protocol = request
        .transport_protocol
        .clone()
        .ok_or(PairingError::EmptyTransportUri)?;

    if transport_protocol.uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let pairing_request = pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: request.mlkem_ciphertext.clone(),
        ecies_public_key: request.ecies_public_key.clone(),
    };

    let shared_key =
        pairing::finish_pairing_contactor(pairing_secret_key_material, &pairing_request)
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

    let wire_bytes = DeRecMessageBuilder::pairing()
        .channel_id(request.channel_id.into())
        .timestamp(timestamp)
        .message(&response)
        .encrypt_pairing(&request.ecies_public_key)?
        .build()?
        .encode_to_vec();

    Ok(ProducePairingResponseMessageResult {
        wire_bytes,
        shared_key,
        responder_transport_protocol: transport_protocol,
    })
}

/// Processes a serialized pairing response envelope and derives the final pairing shared key
/// on the **responder** side.
///
/// This function is executed by the party that:
///
/// 1. Received the initiator’s contact bytes out-of-band
/// 2. Produced and sent a pairing request using [`produce_pairing_request_message`]
///
/// After receiving the initiator’s serialized pairing-response envelope, the responder:
///
/// 1. Decrypts and decodes the inner [`PairResponseMessage`] from the response wire bytes
/// 2. Validates the response status and binds it to the same pairing session using the nonce
/// 3. Uses the responder’s previously stored [`pairing::PairingSecretKeyMaterial`] together with
///    the initiator’s original public pairing material from the contact message to finalize the
///    responder side
/// 4. Derives the final 256-bit [`pairing::PairingSharedKey`]
///
/// Both parties should derive the same shared key if the pairing flow completed successfully.
///
/// # Arguments
///
/// * `contact_message` - Decoded [`ContactMessage`] previously returned as
///   `initiator_contact_message` by [`produce_pairing_request_message`]
/// * `pair_response_wire_bytes` - Serialized outer [`derec_proto::DeRecMessage`] carrying
///   the encrypted inner [`PairResponseMessage`]
/// * `pairing_secret_key_material` - Responder-side secret state previously returned by
///   [`produce_pairing_request_message`]
///
/// # Returns
///
/// On success returns [`ProcessPairingResponseMessageResult`] containing:
///
/// - `shared_key`: the responder-side derived pairing shared key
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - the provided response bytes cannot be decrypted/decoded into a valid response
/// - `PairingError::InvalidPairResponseMessage` if the response indicates failure or is malformed
/// - `PairingError::ProtocolViolation` if the response does not match the pairing session
///   (for example, nonce mismatch)
/// - `PairingError::InvalidContactMessage` if the contact message is missing required fields
/// - `PairingError::FinishPairingRequestor { .. }` if final pairing derivation fails
///
/// # Security Notes
///
/// - `pair_response_wire_bytes` is untrusted input and must be decrypted and validated
/// - The nonce check is a critical session-binding validation
/// - The derived shared key should be treated as sensitive material and stored securely
///
/// # Example
///
/// ```rust
/// use derec_library::pairing::*;
/// use derec_proto::{Protocol, SenderKind::Helper, TransportProtocol};
///
/// let CreateContactMessageResult {
///     wire_bytes: contact_bytes,
///     secret_key: initiator_secret_key,
/// } = create_contact_message(
///     42.into(),
///     TransportProtocol { uri: "https://relay.example/derec".to_owned(), protocol: Protocol::Https.into() },
/// ).expect("Failed to create contact message");
///
/// let ProducePairingRequestMessageResult {
///     wire_bytes: request_bytes,
///     initiator_contact_message,
///     secret_key: responder_secret_key,
/// } = produce_pairing_request_message(
///     Helper,
///     TransportProtocol { uri: "https://relay.example/responder".to_owned(), protocol: Protocol::Https.into() },
///     &contact_bytes,
/// ).expect("Failed to produce pairing request message");
///
/// let ProducePairingResponseMessageResult {
///     wire_bytes: response_bytes,
///     ..
/// } = produce_pairing_response_message(
///     Helper,
///     &request_bytes,
///     &initiator_secret_key,
/// ).expect("Failed to produce pairing response message");
///
/// let ProcessPairingResponseMessageResult { shared_key } =
///     process_pairing_response_message(
///         initiator_contact_message,
///         &response_bytes,
///         &responder_secret_key,
///     ).expect("Failed to process pairing response message");
///
/// let _ = shared_key;
/// ```
pub fn process_pairing_response_message(
    contact_message: ContactMessage,
    response_bytes: &[u8],
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<ProcessPairingResponseMessageResult, crate::Error> {
    let (envelope, response) = extract_inner_pairing_message::<PairResponseMessage>(
        response_bytes,
        &pairing_secret_key_material.ecies_secret_key,
    )?;

    if envelope.timestamp != response.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

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

    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let shared_key = pairing::finish_pairing_requestor(pairing_secret_key_material, &pk)
        .map_err(|e| PairingError::FinishPairingRequestor { source: e })?;

    Ok(ProcessPairingResponseMessageResult { shared_key })
}

fn extract_inner_pairing_message<M>(
    wire_bytes: impl AsRef<[u8]>,
    receiver_secret_key: impl AsRef<[u8]>,
) -> Result<(DeRecMessage, M), crate::Error>
where
    M: Message + Default,
{
    let derec_message =
        DeRecMessage::decode(wire_bytes.as_ref()).map_err(crate::Error::ProtobufDecode)?;

    let plaintext = derec_cryptography::pairing::envelope::decrypt(
        &derec_message.message,
        receiver_secret_key.as_ref(),
    )
    .map_err(PairingError::PairingEncryption)?;

    let message = M::decode(plaintext.as_slice()).map_err(crate::Error::ProtobufDecode)?;

    Ok((derec_message, message))
}
