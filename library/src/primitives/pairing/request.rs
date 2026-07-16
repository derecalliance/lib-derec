// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::primitives::pairing::PairingError;
use crate::transport::TransportProtocolExt as _;
use crate::utils::{ContactMessageExt as _, verify_timestamps};
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp},
    protocol_version::ProtocolVersion,
    types::ChannelId,
    utils::generate_seed,
};
use derec_cryptography::pairing::{
    self as cryptography_pairing, PairingContactMessageMaterial, PairingSecretKeyMaterial,
};
use derec_proto::{
    CommunicationInfo, ContactMessage, ContactMode, DeRecMessage, MessageBody, PairRequestMessage,
    PrePairRequestMessage, SenderKind, TransportProtocol,
};
use prost::Message;
use rand::{Rng, rng};

pub struct CreateContactResult {
    pub contact_message: ContactMessage,
    /// Fresh pairing secret material tied to the keys the contact
    /// creator has committed to.
    ///
    /// - [`ContactMode::InlineKeys`] / [`ContactMode::HashedKeys`]:
    ///   `Some(...)`. Callers MUST persist it — it is required later
    ///   to finalize pairing (decrypt the incoming `PairRequest` and
    ///   derive the shared key).
    /// - [`ContactMode::NoKeys`]: `None`. No key material exists at
    ///   contact-creation time; the contact creator generates it on
    ///   the fly when the corresponding `PrePairRequest` arrives.
    pub secret_key: Option<PairingSecretKeyMaterial>,
}

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted inner
    /// [`derec_proto::PairRequestMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
    pub initiator_contact_message: ContactMessage,
    pub secret_key: PairingSecretKeyMaterial,
}

pub struct ExtractResult {
    pub request: PairRequestMessage,
}

pub struct ProducePrePairResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying a **plaintext**
    /// inner [`derec_proto::PrePairRequestMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
}

pub struct PrePairExtractResult {
    pub request: PrePairRequestMessage,
}

/// Creates a [`derec_proto::ContactMessage`] used to bootstrap the DeRec *pairing* flow.
///
/// In DeRec, pairing begins with an **out-of-band contact transfer** (typically QR or
/// another side channel). Unlike normal DeRec protocol traffic, the contact message is
/// **not wrapped in a `DeRecMessage` envelope** and is **not encrypted**. It is sent as
/// plain protobuf bytes (serialize the returned `contact_message` with `.encode_to_vec()`).
///
/// Single entry point for all three `contact_mode` variants. Mode-specific
/// assembly happens in private helpers (`create_contact_inlined_keys`,
/// `create_contact_hashed_keys`, `create_contact_no_keys`) invoked here.
///
/// # Arguments
///
/// * `channel_id` — Identifier embedded in the contact and copied into subsequent
///   pairing messages by the recipient.
/// * `contact_mode` — Selects how the initiator's public pairing material is delivered:
///   - [`ContactMode::InlineKeys`]: keys are embedded directly in the contact.
///   - [`ContactMode::HashedKeys`]: only a SHA-384 binding hash is embedded; the peer
///     obtains the keys via a `PrePair` round-trip and verifies against the hash. The
///     transport endpoint advertised here MUST be ephemeral — the plaintext `PrePair*`
///     traffic must not be linkable to a long-lived endpoint.
///   - [`ContactMode::NoKeys`]: no key material and no commitment. Keys are generated
///     on the fly by the creator when the corresponding `PrePairRequest` arrives.
///     Trust rests entirely on the OOB delivery channel being fully trusted.
/// * `transport_protocol` — Endpoint the recipient uses to reach this initiator with
///   the next protocol message. The `uri` field must not be empty.
/// * `nonce` — Correlation nonce embedded in the contact.
///   - `None`: the library generates a fresh cryptographically-random `u64`. Suitable
///     default for `InlineKeys` / `HashedKeys` where the nonce is a security parameter.
///   - `Some(n)`: application-controlled value. Required for `NoKeys` where callers
///     typically pick a small human-typable value (4–6 decimal digits) for manual entry.
///     Also valid for `InlineKeys` / `HashedKeys` if the app wants deterministic control.
///
/// # Returns
///
/// [`CreateContactResult`] with:
///
/// - `contact_message`: decoded [`ContactMessage`] — serialize with `.encode_to_vec()`
///   before sending out-of-band.
/// - `secret_key`: `Some(...)` for `InlineKeys` and `HashedKeys` (must be persisted);
///   `None` for `NoKeys` (no key material at contact-creation time).
///
/// # Errors
///
/// - [`PairingError::EmptyTransportUri`] if `transport_protocol.uri` is empty.
/// - [`PairingError::ContactMessageKeygen`] if pairing key generation fails
///   (`InlineKeys` / `HashedKeys` only — `NoKeys` skips keygen).
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::request;
/// use derec_library::types::ChannelId;
/// use derec_proto::{ContactMode, Protocol, TransportProtocol};
///
/// let request::CreateContactResult {
///     contact_message,
///     secret_key,
/// } = request::create_contact(
///     ChannelId(42),
///     ContactMode::InlineKeys,
///     TransportProtocol {
///         uri: "https://relay.example/derec".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     None,
/// ).expect("Failed to create contact message");
///
/// assert!(secret_key.is_some());
/// let _ = contact_message;
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, contact_mode = contact_mode as i32))
)]
pub fn create_contact(
    channel_id: ChannelId,
    contact_mode: ContactMode,
    transport_protocol: TransportProtocol,
    nonce: Option<u64>,
) -> Result<CreateContactResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("transport URI is empty");

        return Err(PairingError::EmptyTransportUri.into());
    }

    let nonce = nonce.unwrap_or_else(|| rng().next_u64());

    let (contact_message, secret_key) = match contact_mode {
        ContactMode::InlineKeys => {
            let (pk, sk) = generate_pairing_keys()?;
            let msg = ContactMessage::inline_keys(channel_id, nonce, transport_protocol, pk);
            (msg, Some(PairingSecretKeyMaterial::Initiator(sk)))
        }
        ContactMode::HashedKeys => {
            let (pk, sk) = generate_pairing_keys()?;
            let msg = ContactMessage::hashed_keys(channel_id, nonce, transport_protocol, &pk);
            (msg, Some(PairingSecretKeyMaterial::Initiator(sk)))
        }
        ContactMode::NoKeys => {
            let msg = ContactMessage::no_keys(channel_id, nonce, transport_protocol);
            (msg, None)
        }
    };

    #[cfg(feature = "logging")]
    tracing::info!("contact message created");

    Ok(CreateContactResult {
        contact_message,
        secret_key,
    })
}

/// Produces a pairing request [`derec_proto::DeRecMessage`] envelope, continuing the DeRec
/// pairing flow.
///
/// This function is executed by the **Responder** (the party that scanned or otherwise
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
/// * `communication_info` - Optional application-level identity metadata to advertise to the
///   peer (free-form key/value pairs). Pass `None` to send no metadata; the protocol treats
///   this as opaque.
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
/// ```
/// use derec_library::primitives::pairing::request;
/// use derec_library::types::ChannelId;
/// use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create a contact message out-of-band.
/// let request::CreateContactResult { contact_message, .. } = request::create_contact(
///     ChannelId(42),
///     ContactMode::InlineKeys,
///     TransportProtocol {
///         uri: "https://relay.example/initiator".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     None,
/// ).expect("create_contact failed");
///
/// // Responder side: build the pairing request envelope from the received contact.
/// let request::ProduceResult { envelope, .. } = request::produce(
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
/// assert!(!envelope.is_empty());
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
    parameter_range: Option<derec_proto::ParameterRange>,
) -> Result<ProduceResult, crate::Error> {
    validate_inputs(
        &transport_protocol,
        contact_message,
        ContactMode::InlineKeys,
    )?;

    let (pairing_request_key_material, secret_key) =
        create_pairing_request_material(contact_message)?;

    let timestamp = current_timestamp();

    let request = PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: pairing_request_key_material.mlkem_ciphertext,
        ecies_public_key: pairing_request_key_material.ecies_public_key.clone(),
        nonce: contact_message.nonce,
        communication_info,
        parameter_range,
        transport_protocol: Some(transport_protocol),
        timestamp: Some(timestamp),
    };

    // Encrypt with the INITIATOR's ECIES public key (from the contact) —
    // only the initiator's matching secret key can decrypt. The
    // responder's own freshly-generated pubkey travels in
    // `request.ecies_public_key` (above) for the initiator to ECDH against
    // when finishing the pairing; it is NOT the encryption key here.
    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(contact_message.channel_id.into())
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(request))
        .encrypt_pairing(
            contact_message
                .ecies_public_key
                .as_ref()
                .expect("validate_inputs guarantees ecies_public_key is Some"),
        )?
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

/// Produces a `PrePairRequestMessage` envelope, the first step of the
/// [`ContactMode::HashedKeys`] pairing flow.
///
/// When a [`ContactMessage`] arrives with `contactMode == HASHED_KEYS`, it carries
/// only a SHA-384 commitment to the initiator's public keys (so the contact stays
/// small enough for a QR code) — the actual ML-KEM and ECIES keys must be fetched
/// over the wire via `PrePair` before a [`PairRequestMessage`] can be built. This
/// function builds that fetch envelope on the responder (scanner) side.
///
/// The inner [`PrePairRequestMessage`] is **plaintext** — no shared key exists yet
/// and the keys it asks for cannot themselves be used for encryption — so the outer
/// [`DeRecMessage`] envelope is constructed directly rather than via the
/// encryption-enforcing [`DeRecMessageBuilder`]. The envelope's `channelId` is
/// taken from the [`ContactMessage`] so the contact creator can correlate the
/// request with the right local pairing state.
///
/// # Arguments
///
/// * `transport_protocol` - Transport endpoint the contact creator should use to
///   send the [`derec_proto::PrePairResponseMessage`] back. The `uri` field must
///   not be empty or whitespace-only. Because [`PrePair`-messages][PrePairRequestMessage]
///   travel as plaintext, this endpoint MUST be ephemeral (see the security note
///   on `PrePairRequestMessage`).
/// * `contact_message` - The decoded [`ContactMessage`] received out-of-band. Its
///   `contact_mode` must be [`ContactMode::HashedKeys`]; for
///   [`ContactMode::InlineKeys`] the responder already has the keys and should
///   call [`produce`] directly instead.
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
/// - [`PairingError::EmptyTransportUri`] if `transport_protocol.uri` is empty or whitespace
/// - [`PairingError::InvalidContactMessage`] if `contact_message.contact_mode` is neither
///   [`ContactMode::HashedKeys`] nor [`ContactMode::NoKeys`] — including
///   [`ContactMode::InlineKeys`] (which carries the keys inline and has no
///   PrePair step) and any unknown enum value
///
/// # Security Notes
///
/// - The envelope is plaintext; do not include any sensitive material beyond
///   what `PrePairRequestMessage` already exposes.
/// - The transport endpoint advertised here is visible to passive observers.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = contact_message.channel_id))
)]
pub fn produce_pre_pair_request(
    transport_protocol: TransportProtocol,
    contact_message: &ContactMessage,
) -> Result<ProducePrePairResult, crate::Error> {
    validate_pre_pair_inputs(&transport_protocol, contact_message)?;

    let timestamp = current_timestamp();
    let request = PrePairRequestMessage {
        nonce: contact_message.nonce,
        transport_protocol: Some(transport_protocol),
        timestamp: Some(timestamp),
    };

    let protocol_version = ProtocolVersion::current();
    let envelope = DeRecMessage {
        protocol_version_major: protocol_version.major,
        protocol_version_minor: protocol_version.minor,
        sequence: 0,
        channel_id: contact_message.channel_id,
        timestamp: Some(timestamp),
        message: MessageBody::PrePairRequest(request).encode_to_vec(),
        trace_id: 0,
    }
    .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("PrePair request envelope produced");

    Ok(ProducePrePairResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::PairRequestMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
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
///
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured ciphertext. Pairing
/// has a small extra mitigation (the per-channel `ContactMessage`
/// nonce is one-shot — once consumed by the initiator the same
/// `PairRequest` can no longer drive a fresh pairing forward), but
/// a recorded envelope can still be re-decoded and inspected at
/// any later time. Callers MUST add a freshness window and per-
/// channel anti-replay (monotonic counter or nonce log) on top
/// before driving any side-effecting state off the parsed body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::request;
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
///     None,
/// ).expect("create_contact failed");
///
/// // Responder: build the pairing request envelope.
/// let request::ProduceResult { envelope, .. } = request::produce(
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
/// // Initiator: decrypt the pairing request with the ECIES secret key.
/// let request::ExtractResult { request: pair_request } =
///     request::extract(&envelope, initiator_key.as_ref().unwrap().ecies_secret_key())
///         .expect("extract failed");
///
/// assert_eq!(pair_request.nonce, contact_message.nonce);
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

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    if let Some(tp) = request.transport_protocol.as_ref() {
        tp.validate()?;
    }

    #[cfg(feature = "logging")]
    tracing::info!("pairing request extracted and validated");

    Ok(ExtractResult { request })
}

/// Decodes a plaintext [`PrePairRequestMessage`] from an outer
/// [`DeRecMessage`] envelope produced by [`produce_pre_pair_request`].
///
/// The `PrePair` flow exchanges its messages **in plaintext** inside the
/// envelope (no shared key exists yet, and the keys the message is asking
/// for cannot themselves be used for encryption). This function performs
/// no decryption — it decodes the envelope, decodes the inner
/// [`MessageBody`], and validates the envelope-vs-body timestamp invariant.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`DeRecMessage`] wire bytes, as
///   produced by [`produce_pre_pair_request`].
///
/// # Returns
///
/// On success returns [`PrePairExtractResult`] containing the decoded inner
/// [`PrePairRequestMessage`]. The caller can recover the routing
/// `channel_id` by decoding the envelope separately if it is not already
/// known from context.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`DeRecMessage`]
/// - the inner [`MessageBody`] cannot be decoded
/// - the inner [`MessageBody`] is not a [`PrePairRequestMessage`]
/// - `envelope.timestamp != request.timestamp`
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

    let request = match crate::derec_message::extract_inner_plaintext_message(&envelope.message)? {
        MessageBody::PrePairRequest(r) => r,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected PrePairRequestMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: PrePairRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    if let Some(tp) = request.transport_protocol.as_ref() {
        tp.validate()?;
    }

    #[cfg(feature = "logging")]
    tracing::info!("PrePair request envelope decoded and validated");

    Ok(PrePairExtractResult { request })
}

fn validate_inputs(
    transport_protocol: &TransportProtocol,
    contact_message: &ContactMessage,
    expected_mode: ContactMode,
) -> Result<(), crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("transport URI is empty");

        return Err(PairingError::EmptyTransportUri.into());
    }
    transport_protocol.validate()?;

    super::validate_contact_for_mode(contact_message, expected_mode)?;

    let initiator_tp =
        contact_message
            .transport_protocol
            .as_ref()
            .ok_or(PairingError::InvalidContactMessage(
                "transport_protocol is missing",
            ))?;

    if initiator_tp.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("contact message transport_protocol.uri is empty");

        return Err(PairingError::InvalidContactMessage("transport_protocol.uri is empty").into());
    }
    initiator_tp.validate()?;

    Ok(())
}

fn validate_pre_pair_inputs(
    transport_protocol: &TransportProtocol,
    contact_message: &ContactMessage,
) -> Result<(), crate::Error> {
    let expected_mode = if contact_message.contact_mode == ContactMode::HashedKeys as i32 {
        ContactMode::HashedKeys
    } else if contact_message.contact_mode == ContactMode::NoKeys as i32 {
        ContactMode::NoKeys
    } else {
        return Err(PairingError::InvalidContactMessage(
            "contact_mode must be HashedKeys or NoKeys for PrePairRequest",
        )
        .into());
    };
    validate_inputs(transport_protocol, contact_message, expected_mode)
}

fn create_pairing_request_material(
    contact_message: &ContactMessage,
) -> Result<
    (
        cryptography_pairing::PairingRequestMessageMaterial,
        cryptography_pairing::ResponderSecretKeyMaterial,
    ),
    crate::Error,
> {
    let mlkem_encapsulation_key = contact_message
        .mlkem_encapsulation_key
        .as_ref()
        .expect("validate_inputs guarantees mlkem_encapsulation_key is Some")
        .clone();
    let ecies_public_key = contact_message
        .ecies_public_key
        .as_ref()
        .expect("validate_inputs guarantees ecies_public_key is Some")
        .clone();

    let contact_pk = PairingContactMessageMaterial {
        mlkem_encapsulation_key,
        ecies_public_key,
    };
    let seed = generate_seed::<32>();
    cryptography_pairing::pairing_request_message(*seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e }.into())
}

fn generate_pairing_keys() -> Result<
    (
        PairingContactMessageMaterial,
        derec_cryptography::pairing::InitiatorSecretKeyMaterial,
    ),
    crate::Error,
> {
    let seed = generate_seed::<32>();
    cryptography_pairing::contact_message(*seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e }.into())
}
