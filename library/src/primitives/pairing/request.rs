// SPDX-License-Identifier: Apache-2.0

use crate::primitives::pairing::PairingError;
use crate::utils::verify_timestamps;
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
use prost_types::Timestamp;
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

pub struct ProducePrePairResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] wire bytes carrying a **plaintext**
    /// inner [`derec_proto::PrePairRequestMessage`]. Ready to send over transport.
    pub envelope: Vec<u8>,
}

pub struct PrePairExtractResult {
    /// Decoded inner plaintext [`derec_proto::PrePairRequestMessage`].
    pub request: PrePairRequestMessage,
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
/// * `contact_mode` - Selects how the initiator's public pairing material is delivered.
///   [`ContactMode::InlineKeys`] embeds the keys directly in the contact (current
///   behavior). [`ContactMode::HashedKeys`] omits the keys and embeds a SHA-384 binding
///   hash over them; the peer obtains the keys via a separate `PrePair` exchange and
///   verifies them against the hash. The contact stays small enough for a QR code.
///   `HashedKeys` requires the transport endpoint advertised here to be ephemeral —
///   the plaintext `PrePair*` traffic must not be linkable to a long-lived endpoint.
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
/// ```
/// use derec_library::primitives::pairing::request;
/// use derec_library::types::ChannelId;
/// use derec_proto::{ContactMode, Protocol, TransportProtocol};
///
/// let channel_id = ChannelId(42);
///
/// let request::CreateContactResult {
///     contact_message,
///     secret_key,
/// } = request::create_contact(
///     channel_id,
///     ContactMode::InlineKeys,
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
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, contact_mode = contact_mode as i32))
)]
pub fn create_contact(
    channel_id: ChannelId,
    contact_mode: ContactMode,
    transport_protocol: TransportProtocol,
) -> Result<CreateContactResult, crate::Error> {
    if transport_protocol.uri.trim().is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("transport URI is empty");

        return Err(PairingError::EmptyTransportUri.into());
    }

    let nonce = rng().next_u64();
    let timestamp = current_timestamp();
    let seed = generate_seed::<32>();

    let (pk, secret_key) = cryptography_pairing::contact_message(*seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e })?;

    let contact_message = match contact_mode {
        ContactMode::InlineKeys => {
            create_contact_inlined_keys(channel_id, nonce, timestamp, transport_protocol, pk)
        }
        ContactMode::HashedKeys => {
            create_contact_hashed_keys(channel_id, nonce, timestamp, transport_protocol, &pk)
        }
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
/// use derec_proto::{Protocol, SenderKind, TransportProtocol};
///
/// // Initiator side: create a contact message out-of-band.
/// let request::CreateContactResult { contact_message, .. } = request::create_contact(
///     ChannelId(42),
///     TransportProtocol {
///         uri: "https://relay.example/initiator".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
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
) -> Result<ProduceResult, crate::Error> {
    validate_inputs(
        &transport_protocol,
        contact_message,
        ContactMode::InlineKeys,
    )?;

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

    let contact_pk = cryptography_pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key,
        ecies_public_key,
    };

    let seed = generate_seed::<32>();

    let (req_pk, secret_key) = cryptography_pairing::pairing_request_message(*seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e })?;

    let timestamp = current_timestamp();

    let request = PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: req_pk.mlkem_ciphertext,
        ecies_public_key: req_pk.ecies_public_key,
        nonce: contact_message.nonce,
        communication_info,
        parameter_range: None,
        transport_protocol: Some(transport_protocol),
        timestamp: Some(timestamp),
    };

    let ecies_pk =
        contact_message
            .ecies_public_key
            .as_ref()
            .ok_or(PairingError::InvalidContactMessage(
                "ecies_public_key is missing",
            ))?;
    let envelope = DeRecMessageBuilder::pairing()
        .channel_id(contact_message.channel_id.into())
        .timestamp(timestamp)
        .message_body(MessageBody::PairRequest(request))
        .encrypt_pairing(ecies_pk)?
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
/// - [`PairingError::InvalidContactMessage`] if `contact_message.contact_mode` is not
///   [`ContactMode::HashedKeys`]
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
    validate_inputs(
        &transport_protocol,
        contact_message,
        ContactMode::HashedKeys,
    )?;

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
        // Correlation token is the higher-level orchestrator's concern;
        // the low-level PrePair primitive currently emits 0 (= "no
        // correlation"). The `auto_trace_id` helper on the builder
        // would produce a random one when callers want it.
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
/// # Example
///
/// ```
/// use derec_library::primitives::pairing::request;
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
/// let request::ProduceResult { envelope, .. } = request::produce(
///     SenderKind::Helper,
///     TransportProtocol {
///         uri: "https://relay.example/responder".to_owned(),
///         protocol: Protocol::Https.into(),
///     },
///     &contact_message,
///     None,
/// ).expect("produce failed");
///
/// // Initiator: decrypt the pairing request with the ECIES secret key.
/// let request::ExtractResult { request: pair_request } =
///     request::extract(&envelope, initiator_key.ecies_secret_key())
///         .expect("extract failed");
///
/// assert_eq!(pair_request.nonce, contact_message.nonce);
/// assert_eq!(pair_request.channel_id, u64::from(ChannelId(42)));
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

    #[cfg(feature = "logging")]
    tracing::info!("PrePair request envelope decoded and validated");

    Ok(PrePairExtractResult { request })
}

/// Shared inbound validation for producers that ingest a
/// [`ContactMessage`] ([`produce`], [`produce_pre_pair_request`]).
///
/// Three orthogonal checks:
///
/// 1. The caller's own `transport_protocol.uri` is non-empty.
/// 2. The contact's shape matches `expected_mode` (delegated to
///    [`validate_contact_for_mode`]).
/// 3. The contact's `transport_protocol` is present and has a non-empty
///    URI — required by both modes (it's where the next protocol message
///    is delivered: a `PairRequest` for `InlineKeys`, a `PrePairRequest`
///    for `HashedKeys`).
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

    validate_contact_for_mode(contact_message, expected_mode)?;

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

    Ok(())
}

/// Enforces the per-mode field-presence invariant on an incoming
/// [`ContactMessage`]. Called at every entry point that ingests a contact:
///
/// - `produce` requires [`ContactMode::InlineKeys`] (the responder needs
///   the keys inline).
/// - `produce_pre_pair_request` and `process_pre_pair_response` require
///   [`ContactMode::HashedKeys`] (the keys must be fetched via PrePair).
///
/// Rejects:
///
/// - `contact_mode` not matching `expected`.
/// - [`ContactMode::InlineKeys`]: missing/empty `mlkem_encapsulation_key`
///   or `ecies_public_key`, or a non-empty `contact_binding_hash` (would
///   mean the contact is misshaped — keys present AND a commitment).
/// - [`ContactMode::HashedKeys`]: any inline key set, or a missing,
///   empty, or wrong-length `contact_binding_hash` (must be exactly 48
///   bytes — SHA-384 digest size).
///
/// The bidirectional check matters most for `HashedKeys`: if a malformed
/// `HashedKeys` contact carried inline keys, downstream callers might
/// consume those keys without ever recomputing the binding hash, defeating
/// the commitment that's the whole point of the mode.
pub(crate) fn validate_contact_for_mode(
    contact: &ContactMessage,
    expected: ContactMode,
) -> Result<(), crate::Error> {
    if contact.contact_mode != expected as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(
            contact_mode = contact.contact_mode,
            expected = expected as i32,
            "contact_mode mismatch"
        );

        return Err(PairingError::InvalidContactMessage(match expected {
            ContactMode::InlineKeys => "expected INLINE_KEYS contact mode",
            ContactMode::HashedKeys => "expected HASHED_KEYS contact mode",
        })
        .into());
    }

    let mlkem_present = contact
        .mlkem_encapsulation_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    let ecies_present = contact
        .ecies_public_key
        .as_ref()
        .is_some_and(|v| !v.is_empty());
    let hash_present = contact
        .contact_binding_hash
        .as_ref()
        .is_some_and(|v| !v.is_empty());

    match expected {
        ContactMode::InlineKeys => {
            if !mlkem_present {
                return Err(PairingError::InvalidContactMessage(
                    "inline_keys contact missing mlkem_encapsulation_key",
                )
                .into());
            }
            if !ecies_present {
                return Err(PairingError::InvalidContactMessage(
                    "inline_keys contact missing ecies_public_key",
                )
                .into());
            }
            if hash_present {
                return Err(PairingError::InvalidContactMessage(
                    "inline_keys contact must not carry contact_binding_hash",
                )
                .into());
            }
        }
        ContactMode::HashedKeys => {
            if mlkem_present || ecies_present {
                return Err(PairingError::InvalidContactMessage(
                    "hashed_keys contact must not carry inline keys",
                )
                .into());
            }
            // SHA-384 digest length — the canonical binding-hash size. A
            // contact carrying a wrong-sized hash is malformed; refuse
            // rather than let the recomputation pretend it's valid.
            const BINDING_HASH_LEN: usize = 48;
            let hash = contact.contact_binding_hash.as_ref().ok_or(
                PairingError::InvalidContactMessage(
                    "hashed_keys contact missing contact_binding_hash",
                ),
            )?;
            if hash.is_empty() {
                return Err(PairingError::InvalidContactMessage(
                    "hashed_keys contact missing contact_binding_hash",
                )
                .into());
            }
            if hash.len() != BINDING_HASH_LEN {
                return Err(PairingError::InvalidContactMessage(
                    "hashed_keys contact_binding_hash is not a SHA-384 digest",
                )
                .into());
            }
        }
    }

    Ok(())
}

/// Builds a `ContactMessage` for [`ContactMode::InlineKeys`].
///
/// The initiator's ML-KEM encapsulation key and ECIES public key are placed
/// directly in the contact. The responder reads them and proceeds straight to
/// [`PairRequestMessage`] without any PrePair exchange.
fn create_contact_inlined_keys(
    channel_id: ChannelId,
    nonce: u64,
    timestamp: Timestamp,
    transport_protocol: TransportProtocol,
    pk: PairingContactMessageMaterial,
) -> ContactMessage {
    ContactMessage {
        channel_id: channel_id.into(),
        transport_protocol: Some(transport_protocol),
        contact_mode: ContactMode::InlineKeys as i32,
        mlkem_encapsulation_key: Some(pk.mlkem_encapsulation_key),
        ecies_public_key: Some(pk.ecies_public_key),
        contact_binding_hash: None,
        nonce,
        timestamp: Some(timestamp),
    }
}

/// Builds a `ContactMessage` for [`ContactMode::HashedKeys`].
///
/// The public keys are **not** placed in the contact. Instead, the contact
/// carries a SHA-384 commitment that binds them to this specific session, per
/// `contact.proto`:
///
/// ```text
/// contactBindingHash = SHA-384(
///     mlkemEncapsulationKey
///     || eciesPublicKey
///     || u64_be(nonce)
///     || u64_be(channelId)
/// )
/// ```
///
/// The responder later retrieves the actual keys via the `PrePair` exchange
/// and recomputes this hash to verify integrity before constructing the
/// [`PairRequestMessage`]. Because the keys are revealed through plaintext
/// `PrePair*` messages, the `transport_protocol` supplied here must be
/// ephemeral — see the security note on `PrePairRequestMessage`.
fn create_contact_hashed_keys(
    channel_id: ChannelId,
    nonce: u64,
    timestamp: Timestamp,
    transport_protocol: TransportProtocol,
    pk: &PairingContactMessageMaterial,
) -> ContactMessage {
    let binding_hash = derec_cryptography::pairing::contact_binding_hash(
        &pk.mlkem_encapsulation_key,
        &pk.ecies_public_key,
        nonce,
        channel_id.into(),
    );

    ContactMessage {
        channel_id: channel_id.into(),
        transport_protocol: Some(transport_protocol),
        contact_mode: ContactMode::HashedKeys as i32,
        mlkem_encapsulation_key: None,
        ecies_public_key: None,
        contact_binding_hash: Some(binding_hash.to_vec()),
        nonce,
        timestamp: Some(timestamp),
    }
}
