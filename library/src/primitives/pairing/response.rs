// SPDX-License-Identifier: Apache-2.0

use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::primitives::pairing::PairingError;
use crate::protocol_version::ProtocolVersion;
use crate::types::ChannelId;
use crate::utils::verify_timestamps;
use derec_cryptography::pairing::{
    self as cryptography_pairing, PairingSecretKeyMaterial, PairingSharedKey,
};
use derec_proto::{
    CommunicationInfo, ContactMessage, ContactMode, DeRecMessage, DeRecResult, MessageBody,
    PairRequestMessage, PairResponseMessage, PrePairRequestMessage, PrePairResponseMessage,
    StatusEnum, TransportProtocol,
};
use prost::Message;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted inner
    /// [`derec_proto::PairResponseMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
    pub peer_transport_protocol: TransportProtocol,
    pub shared_key: PairingSharedKey,
    /// Channel identifier the responder is committing to for all future
    /// traffic on this channel — derived from the pre-rekey id and the
    /// freshly negotiated `shared_key` via a deterministic hash. Callers
    /// MUST rename their local channel record from the old id to this
    /// value once they finish handling this response.
    pub channel_id: ChannelId,
}

pub struct ExtractResult {
    pub response: PairResponseMessage,
}

pub struct ProcessResult {
    pub shared_key: PairingSharedKey,
    /// Channel identifier both peers MUST switch to for all future traffic
    /// on this channel. Already validated against the local derivation; the
    /// caller's only remaining job is to atomically rename its channel
    /// record from the old id to this value.
    pub channel_id: ChannelId,
}

pub struct ProducePrePairResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying a **plaintext**
    /// inner [`derec_proto::PrePairResponseMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
}

pub struct PrePairExtractResult {
    pub response: PrePairResponseMessage,
}

pub struct ProcessPrePairResult {
    pub mlkem_encapsulation_key: Vec<u8>,
    pub ecies_public_key: Vec<u8>,
    pub nonce: u64,
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
/// # Channel id rekey
///
/// After the handshake completes both sides switch from the pre-rekey
/// `channel_id` (the contact-time value) to a post-handshake id derived
/// deterministically from the pre-rekey id and the freshly-negotiated
/// `shared_key` via a SHA-384 hash. This response is the
/// **only** place the new id crosses the wire, and it travels inside the
/// encrypted inner message; a passive observer who saw only pre-rekey
/// traffic cannot link the long-running channel back to its pairing-time
/// id without the shared key.
///
/// The outer envelope still routes on the pre-rekey id — the requester has
/// no way to know the new id until it has decrypted the inner message and
/// derived its own copy of the shared key.
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::{request, response};
/// use derec_library::types::ChannelId;
/// use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     ContactMode::InlineKeys,
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
///     ChannelId(42),
///     &pair_request,
///     &initiator_key,
///     None,
///     None,
/// ).expect("produce failed");
///
/// assert!(!envelope.is_empty());
/// let _ = shared_key;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn produce(
    channel_id: ChannelId,
    request: &PairRequestMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
    communication_info: Option<CommunicationInfo>,
    parameter_range: Option<derec_proto::ParameterRange>,
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

    let rekeyed_channel_id = derive_rekeyed_channel_id(channel_id, &shared_key);

    let timestamp = current_timestamp();
    let response = PairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: request.nonce,
        communication_info,
        parameter_range,
        timestamp: Some(timestamp),
        channel_id: rekeyed_channel_id.into(),
    };

    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(channel_id)
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
        channel_id: rekeyed_channel_id,
    })
}

/// Produces a `PrePairResponseMessage` envelope on the **contact creator** side,
/// the second leg of the [`derec_proto::ContactMode::HashedKeys`] pairing flow.
///
/// In `HASHED_KEYS` mode the contact carries only a SHA-384 commitment to the
/// initiator's public keys (not the keys themselves), so before the scanner can
/// build a [`PairRequestMessage`] it must ask the contact creator for the actual
/// keys. This function builds the reply.
///
/// The inner [`PrePairResponseMessage`] is **plaintext** — no shared key exists yet
/// — so the outer [`DeRecMessage`] envelope is constructed directly rather than
/// through the encryption-enforcing [`DeRecMessageBuilder`]. The envelope's
/// `channelId` is the local pairing channel (the same one the request arrived on),
/// and the response echoes the request's `nonce` so the scanner can correlate it
/// with the original contact and reject stale or spoofed replies.
///
/// # Arguments
///
/// * `channel_id` - Identifier of the local pairing channel this response belongs
///   to. Echoed on the outer envelope so the peer can route the reply.
/// * `request` - The decoded [`PrePairRequestMessage`] previously returned by
///   [`super::request::extract_pre_pair`]. Only its `nonce` is consumed.
/// * `pairing_secret_key_material` - Initiator-side pairing secret state previously
///   returned by [`super::request::create_contact`]. Must be the
///   [`PairingSecretKeyMaterial::Initiator`] variant; the responder variant cannot
///   serve a `PrePairResponse` because it doesn't own the keys.
///
/// # Returns
///
/// On success returns [`ProducePrePairResult`] containing the serialized outer
/// [`DeRecMessage`] envelope bytes.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::Invariant`] if `pairing_secret_key_material` is not the
///   `Initiator` variant
///
/// # Security Notes
///
/// - The envelope is plaintext; any passive observer can read the public keys
///   advertised here. The keys are public material, but the transport endpoint
///   used for this exchange MUST be ephemeral (see the security note on
///   `PrePairRequestMessage`) so the keys cannot be linked to a long-term
///   identity by a passive observer.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub fn produce_pre_pair(
    channel_id: ChannelId,
    request: &PrePairRequestMessage,
    pairing_secret_key_material: &PairingSecretKeyMaterial,
) -> Result<ProducePrePairResult, crate::Error> {
    let initiator_material = match pairing_secret_key_material {
        PairingSecretKeyMaterial::Initiator(m) => m,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("expected Initiator key material for PrePair response");

            return Err(PairingError::Invariant(
                "expected Initiator key material for PrePair response",
            )
            .into());
        }
    };

    let timestamp = current_timestamp();
    let response = PrePairResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        mlkem_encapsulation_key: Some(initiator_material.mlkem_encapsulation_key.clone()),
        ecies_public_key: Some(initiator_material.ecies_public_key.clone()),
        nonce: request.nonce,
        timestamp: Some(timestamp),
    };

    let protocol_version = ProtocolVersion::current();
    let envelope = DeRecMessage {
        protocol_version_major: protocol_version.major,
        protocol_version_minor: protocol_version.minor,
        sequence: 0,
        channel_id: channel_id.into(),
        timestamp: Some(timestamp),
        message: MessageBody::PrePairResponse(response).encode_to_vec(),
        trace_id: 0,
    }
    .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("PrePair response envelope produced");

    Ok(ProducePrePairResult { envelope })
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
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured ciphertext. Pairing
/// has a small extra mitigation (the per-channel `ContactMessage`
/// nonce is one-shot, so a replayed PairResponse cannot complete a
/// fresh pairing once the original session is over), but a recorded
/// envelope can still be re-decoded and inspected later. Callers
/// MUST add a freshness window and per-channel anti-replay
/// (monotonic counter or nonce log) on top before driving any
/// side-effecting state off the parsed body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::{request, response};
/// use derec_library::types::ChannelId;
/// use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
///
/// // Initiator: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     ContactMode::InlineKeys,
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
///     None,
/// ).expect("produce failed");
///
/// // Initiator: extract the pairing request, then produce the response.
/// let request::ExtractResult { request: pair_request } = request::extract(
///     &request_envelope,
///     initiator_key.ecies_secret_key(),
/// ).expect("extract request failed");
/// let response::ProduceResult { envelope: response_envelope, .. } =
///     response::produce(ChannelId(42), &pair_request, &initiator_key, None, None)
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

/// Decodes a plaintext [`PrePairResponseMessage`] from an outer
/// [`DeRecMessage`] envelope produced by [`produce_pre_pair`].
///
/// Like its request-side counterpart [`super::request::extract_pre_pair`],
/// the `PrePair` flow carries its inner message **in plaintext** inside the
/// envelope (no shared key exists yet, and the keys the response is delivering
/// cannot themselves be used for encryption). This function performs no
/// decryption — it decodes the envelope, decodes the inner [`MessageBody`],
/// and validates the envelope-vs-body timestamp invariant.
///
/// Status and content validation (confirming `result.status == OK` and
/// recomputing the SHA-384 binding hash against
/// [`derec_proto::ContactMessage::contact_binding_hash`]) is the caller's
/// responsibility — see the receiver checklist on
/// [`derec_proto::PrePairResponseMessage`].
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`DeRecMessage`] wire bytes, as
///   produced by [`produce_pre_pair`].
///
/// # Returns
///
/// On success returns [`PrePairExtractResult`] containing the decoded inner
/// [`PrePairResponseMessage`]. The caller can recover the routing
/// `channel_id` by decoding the envelope separately if it is not already
/// known from context.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`DeRecMessage`]
/// - the inner [`MessageBody`] cannot be decoded
/// - the inner [`MessageBody`] is not a [`PrePairResponseMessage`]
/// - `envelope.timestamp != response.timestamp`
///
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured envelope. PrePair
/// envelopes are plaintext (no shared key yet), so a recorded
/// envelope can be replayed verbatim by anyone on path. Callers
/// MUST add a freshness window and per-channel anti-replay
/// (monotonic counter or nonce log) on top before driving any
/// side-effecting state off the parsed body.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(envelope_len = envelope_bytes.len()))
)]
pub fn extract_pre_pair(envelope_bytes: &[u8]) -> Result<PrePairExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let response = match crate::derec_message::extract_inner_plaintext_message(&envelope.message)? {
        MessageBody::PrePairResponse(r) => r,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected PrePairResponseMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: PrePairResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("PrePair response envelope decoded and validated");

    Ok(PrePairExtractResult { response })
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
/// use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create the out-of-band contact message.
/// let request::CreateContactResult {
///     contact_message,
///     secret_key: initiator_key,
/// } = request::create_contact(
///     ChannelId(42),
///     ContactMode::InlineKeys,
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
///     response::produce(ChannelId(42), &pair_request, &initiator_key, None, None)
///         .expect("produce failed");
///
/// // Responder side: extract the pairing response and derive the shared key.
/// let response::ExtractResult { response: pair_response } = response::extract(
///     &response_envelope,
///     responder_key.ecies_secret_key(),
/// ).expect("extract response failed");
///
/// let response::ProcessResult { shared_key: responder_shared_key, .. } =
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
    let responder_material =
        validate_process_inputs(contact_message, response, pairing_secret_key_material)?;

    let pairing_contact_key_material = build_pairing_contact_material(contact_message);

    let shared_key = cryptography_pairing::finish_pairing_responder(
        responder_material,
        &pairing_contact_key_material,
    )
    .map_err(|e| PairingError::FinishPairingResponder { source: e })?;

    let expected_channel_id =
        validate_rekeyed_channel_id(response, ChannelId(contact_message.channel_id), &shared_key)?;

    #[cfg(feature = "logging")]
    tracing::info!("pairing complete; responder shared key derived");

    Ok(ProcessResult {
        shared_key,
        channel_id: expected_channel_id,
    })
}

/// Validates an incoming [`PrePairResponseMessage`] against the original
/// [`ContactMessage`] and, on success, hands back the initiator's public
/// keys ready to be used to construct a normal [`PairRequestMessage`].
///
/// This is the **scanner**-side check that closes the
/// [`derec_proto::ContactMode::HashedKeys`] pre-pair leg. Per the receiver
/// checklist on [`derec_proto::PrePairResponseMessage`], a conforming
/// implementation MUST:
///
/// 1. confirm `result.status == OK`;
/// 2. recompute `SHA-384(mlkemEncapsulationKey || eciesPublicKey
///    || u64_be(nonce) || u64_be(channelId))` and verify it matches the
///    original [`ContactMessage::contact_binding_hash`];
/// 3. only on match, proceed to construct a normal [`PairRequestMessage`].
///
/// This function performs all three checks. The recomputation uses the
/// `nonce` and `channelId` from the **contact** — the trusted out-of-band
/// values — so a tampered response that swapped them cannot mask a hash
/// mismatch by tampering them in parallel.
///
/// # Arguments
///
/// * `contact_message` - The decoded [`ContactMessage`] received out-of-band.
///   Its [`ContactMode`] must be [`ContactMode::HashedKeys`] and it must
///   carry a non-empty `contact_binding_hash`.
/// * `response` - The decoded [`PrePairResponseMessage`] previously returned
///   by [`extract_pre_pair`].
///
/// # Returns
///
/// On success returns [`ProcessPrePairResult`] containing the validated
/// `mlkem_encapsulation_key`, `ecies_public_key`, and the echoed `nonce`.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - [`PairingError::InvalidPairResponseMessage`] if the response is malformed
///   (missing result, missing/empty keys)
/// - [`PairingError::NonOkStatus`] if `result.status != Ok`, carrying the
///   peer's status code and memo string
/// - [`PairingError::InvalidContactMessage`] if the contact is not in
///   [`ContactMode::HashedKeys`] or lacks a `contact_binding_hash`
/// - [`PairingError::ProtocolViolation`] if `response.nonce` does not match
///   `contact_message.nonce` (session correlation failure) or if the
///   recomputed binding hash does not match `contact_binding_hash`
///   (potential MITM on the plaintext pre-pair leg)
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = contact_message.channel_id))
)]
pub fn process_pre_pair(
    contact_message: &ContactMessage,
    response: &PrePairResponseMessage,
) -> Result<ProcessPrePairResult, crate::Error> {
    validate_process_pre_pair_inputs(contact_message, response)?;

    let (mlkem_encapsulation_key, ecies_public_key) =
        validate_contact_binding_hash(contact_message, response)?;

    #[cfg(feature = "logging")]
    tracing::info!("PrePair response validated against contact binding hash");

    Ok(ProcessPrePairResult {
        mlkem_encapsulation_key,
        ecies_public_key,
        nonce: response.nonce,
    })
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

    // Structural + scheme/protocol consistency check. Rejects peer-
    // supplied URIs that downgrade the declared protocol (e.g. an
    // `http://` URI carried with `Protocol::Https`) and unknown
    // `protocol` discriminants. `TryFrom` runs both the enum
    // conversion and the URI validation in one step; surfaces as
    // `crate::Error::Transport`.
    let _ = crate::transport::TransportProtocol::try_from(&peer_transport_protocol)?;

    Ok(peer_transport_protocol)
}

/// Single chokepoint for `process`'s preconditions. Returning the borrowed
/// `Responder` half lets the caller skip a redundant match after the gate
/// passes.
fn validate_process_inputs<'a>(
    contact_message: &ContactMessage,
    response: &PairResponseMessage,
    pairing_secret_key_material: &'a PairingSecretKeyMaterial,
) -> Result<&'a cryptography_pairing::ResponderSecretKeyMaterial, crate::Error> {
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

    let mlkem_present = contact_message
        .mlkem_encapsulation_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    if !mlkem_present {
        #[cfg(feature = "logging")]
        tracing::warn!("contact message missing mlkem_encapsulation_key");
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }

    let ecies_present = contact_message
        .ecies_public_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    if !ecies_present {
        #[cfg(feature = "logging")]
        tracing::warn!("contact message missing ecies_public_key");
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    if response.nonce != contact_message.nonce {
        #[cfg(feature = "logging")]
        tracing::warn!("nonce mismatch; possible replay or wrong pairing session");
        return Err(PairingError::ProtocolViolation("nonce mismatch").into());
    }

    match pairing_secret_key_material {
        PairingSecretKeyMaterial::Responder(m) => Ok(m),
        PairingSecretKeyMaterial::Initiator(_) => Err(PairingError::Invariant(
            "expected Responder key material for pairing process",
        )
        .into()),
    }
}

fn build_pairing_contact_material(
    contact_message: &ContactMessage,
) -> cryptography_pairing::PairingContactMessageMaterial {
    let mlkem_encapsulation_key = contact_message
        .mlkem_encapsulation_key
        .as_ref()
        .expect("validate_process_inputs guarantees mlkem_encapsulation_key is Some")
        .clone();
    let ecies_public_key = contact_message
        .ecies_public_key
        .as_ref()
        .expect("validate_process_inputs guarantees ecies_public_key is Some")
        .clone();
    cryptography_pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key,
        ecies_public_key,
    }
}

/// A rekey-id mismatch means either both sides derived different shared
/// keys (channel would be unusable anyway) or the responder is misbehaving
/// / a forged envelope somehow decrypted — either way we refuse the id.
fn validate_rekeyed_channel_id(
    response: &PairResponseMessage,
    original_channel_id: ChannelId,
    shared_key: &PairingSharedKey,
) -> Result<ChannelId, crate::Error> {
    let expected_channel_id = derive_rekeyed_channel_id(original_channel_id, shared_key);
    if response.channel_id != u64::from(expected_channel_id) {
        #[cfg(feature = "logging")]
        tracing::warn!(
            advertised = response.channel_id,
            expected = u64::from(expected_channel_id),
            "channel id rekey mismatch"
        );
        return Err(PairingError::ProtocolViolation("channel_id rekey mismatch").into());
    }
    Ok(expected_channel_id)
}

fn validate_process_pre_pair_inputs(
    contact_message: &ContactMessage,
    response: &PrePairResponseMessage,
) -> Result<(), crate::Error> {
    let res = response
        .result
        .as_ref()
        .ok_or(PairingError::InvalidPairResponseMessage("missing result"))?;

    if res.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(
            status = res.status,
            memo = %res.memo,
            "PrePair response status is not Ok"
        );

        return Err(PairingError::NonOkStatus {
            status: res.status,
            memo: res.memo.to_owned(),
        }
        .into());
    }

    // Shape + mode invariants for the contact. Catches an attacker who
    // tampered with `contact_mode` between the out-of-band exchange and
    // this validation point, and rejects malformed contacts that carry
    // both inline keys and a binding hash.
    super::request::validate_contact_for_mode(contact_message, ContactMode::HashedKeys)?;

    let mlkem_present = response
        .mlkem_encapsulation_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    if !mlkem_present {
        #[cfg(feature = "logging")]
        tracing::warn!("PrePair response missing mlkem_encapsulation_key");
        return Err(
            PairingError::InvalidPairResponseMessage("mlkem_encapsulation_key is empty").into(),
        );
    }

    let ecies_present = response
        .ecies_public_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    if !ecies_present {
        #[cfg(feature = "logging")]
        tracing::warn!("PrePair response missing ecies_public_key");
        return Err(PairingError::InvalidPairResponseMessage("ecies_public_key is empty").into());
    }

    if response.nonce != contact_message.nonce {
        #[cfg(feature = "logging")]
        tracing::warn!("nonce mismatch; possible replay or wrong pairing session");
        return Err(PairingError::ProtocolViolation("nonce mismatch").into());
    }

    Ok(())
}

/// Derives the post-handshake channel id used by the pairing rekey.
///
/// Computes:
///
/// ```text
/// SHA-384( u64_be(original_channel_id) || shared_key )
/// ```
///
/// and returns the first 8 bytes interpreted as a big-endian `u64`. Both
/// sides feed identical inputs so they reach the same result independently.
fn derive_rekeyed_channel_id(
    original_channel_id: ChannelId,
    shared_key: &PairingSharedKey,
) -> ChannelId {
    let mut hasher = Sha384::new();
    hasher.update(u64::from(original_channel_id).to_be_bytes());
    hasher.update(shared_key.as_slice());
    let digest = hasher.finalize();
    let prefix: [u8; 8] = digest[..8]
        .try_into()
        .expect("SHA-384 digest has at least 8 bytes");
    ChannelId(u64::from_be_bytes(prefix))
}

/// Recompute the contact-binding hash from the keys the contact creator
/// published in the `PrePairResponse` and compare it (constant-time)
/// against the commitment carried by the original `ContactMessage`. A
/// mismatch means the keys the scanner is about to pair with do not match
/// the contact it scanned — either an attacker swapped the keys on the
/// plaintext PrePair leg, or the contact itself was tampered between
/// creation and scanning.
///
/// `validate_process_pre_pair_inputs` guarantees the two response key
/// fields and the contact's `contact_binding_hash` are present, so the
/// `.expect()`s here are infallible.
fn validate_contact_binding_hash(
    contact_message: &ContactMessage,
    response: &PrePairResponseMessage,
) -> Result<(Vec<u8>, Vec<u8>), crate::Error> {
    let mlkem_encapsulation_key = response
        .mlkem_encapsulation_key
        .clone()
        .expect("validate_process_pre_pair_inputs guarantees mlkem_encapsulation_key is Some");
    let ecies_public_key = response
        .ecies_public_key
        .clone()
        .expect("validate_process_pre_pair_inputs guarantees ecies_public_key is Some");
    let expected_hash = contact_message
        .contact_binding_hash
        .as_ref()
        .expect("validate_process_pre_pair_inputs guarantees contact_binding_hash is Some");

    let recomputed = derec_cryptography::pairing::contact_binding_hash(
        &mlkem_encapsulation_key,
        &ecies_public_key,
        contact_message.nonce,
        contact_message.channel_id,
    );

    let matched: bool = recomputed.as_slice().ct_eq(expected_hash.as_slice()).into();
    if !matched {
        #[cfg(feature = "logging")]
        tracing::warn!(
            "contact binding hash mismatch; published keys do not match the contact commitment"
        );
        return Err(PairingError::PrePairHashMismatch.into());
    }

    Ok((mlkem_encapsulation_key, ecies_public_key))
}
