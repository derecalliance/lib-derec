// SPDX-License-Identifier: Apache-2.0

use crate::{
    pairing::PairingError,
    protos::derec_proto::{self, StatusEnum},
};
use derec_cryptography::pairing;
use rand::RngCore;

/// Creates a [`ContactMessage`] to bootstrap the DeRec *pairing* flow.
///
/// In DeRec, pairing starts with an **out-of-band “contact” transfer** (typically QR)
/// that is **not signed or encrypted**. The contact contains:
///
/// - The sender’s **public encryption material** (ML-KEM encapsulation key + ECIES public key)
/// - A **transport URI** that tells the counterparty *where/how* to send subsequent DeRec messages
/// - A fresh **nonce** that identifies this pairing session.
///
/// The returned [`ContactMessage`] is intended to be shared with the counterparty (e.g. encoded into
/// a QR code). The accompanying [`PairingSecretKeyMaterial`] must be stored locally and treated as
/// **secret state**; it is required later to finalize the pairing and derive the shared key.
///
/// # Arguments
///
/// * `channel_id` - Identifier for the generated public encryption key material (`public_key_id` in the
///   contact message). This value is echoed in later encrypted messages so the recipient can select
///   the correct private key for decryption. It should be stable for the key material you are generating
///   and unique within the scope of keys your app may hold.
/// * `transport_uri` - URI endpoint the counterparty will use to contact this party for the pairing
///   protocol and subsequent DeRec flows. Examples include an HTTPS endpoint, a relay URL, or another
///   application-defined transport scheme. Must not be empty.
///
/// # Returns
///
/// On success returns a tuple:
///
/// 1. [`derec_proto::ContactMessage`]: public contact payload to send out-of-band.
/// 2. [`pairing::PairingSecretKeyMaterial`]: secret key material that must be retained by the caller.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - `PairingError::EmptyTransportUri` if `transport_uri` is empty or whitespace.
/// - `PairingError::ContactMessageKeygen { .. }` if the underlying cryptographic key generation fails.
///
/// # Security Notes
///
/// - The contact message is **public** and may be transported (e.g. via QR); do not embed secrets in it.
/// - The returned secret key material must be protected (e.g., OS keychain / secure enclave / encrypted storage).
/// - The `nonce` is generated using the OS CSPRNG and is used to bind later messages to this pairing session.
///
/// # Example
///
/// ```rust
/// use derec_library::pairing;
///
/// let channel_id = 42u64;
/// let transport_uri = "https://relay.example/derec";
///
/// let (contact, secret_state) = pairing::create_contact_message(channel_id, transport_uri)?;
///
/// // Encode `contact` (e.g. QR code) and keep `secret_state` locally for later steps.
/// # Ok::<(), derec_library::Error>(())
/// ```
pub fn create_contact_message(
    channel_id: u64,
    transport_uri: &str,
) -> Result<
    (
        derec_proto::ContactMessage,
        pairing::PairingSecretKeyMaterial,
    ),
    crate::Error,
> {
    if transport_uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let mut rng = rand::rngs::OsRng;

    // generate the public key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let (pk, sk) = pairing::contact_message(seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e })?;

    let contact_msg = derec_proto::ContactMessage {
        public_key_id: channel_id,
        transport_uri: transport_uri.to_owned(),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        message_encoding_type: 0,
    };

    Ok((contact_msg, sk))
}

/// Produces a [`PairRequestMessage`] in response to a previously received
/// [`ContactMessage`], continuing the DeRec pairing flow.
///
/// This function is executed by the **responder** (the party that scanned or
/// received the contact message out-of-band).
///
/// The pairing flow proceeds as follows:
///
/// 1. The initiator generates and shares a [`ContactMessage`] containing
///    public key material and transport information.
/// 2. The responder calls this function to:
///     - Perform ML-KEM encapsulation against the contact’s public key,
///     - Generate fresh ECIES key material,
///     - Construct a [`PairRequestMessage`] to send back to the initiator.
/// 3. Both parties later derive a shared 256-bit pairing key.
///
/// The returned [`PairRequestMessage`] is sent to the initiator through the
/// transport specified in the contact message. The returned
/// [`PairingSecretKeyMaterial`] must be retained locally and used later
/// to finalize the pairing process.
///
/// # Arguments
///
/// * `channel_id` - Identifier for the newly generated public key material
///   of the responder. This value is embedded in the pairing request and
///   allows the initiator to select the correct private key for decryption.
/// * `kind` - Role of the sender within the DeRec protocol (e.g.
///   SharerNonRecovery, SharerRecovery, Helper). This determines how
///   the pairing is interpreted in later flows.
/// * `contact_message` - The contact message received from the initiator.
///   Must contain valid ML-KEM encapsulation and ECIES public key material.
///
/// # Returns
///
/// On success returns a tuple:
///
/// 1. [`derec_proto::PairRequestMessage`] – the pairing request to transmit
///    to the initiator.
/// 2. [`pairing::PairingSecretKeyMaterial`] – secret state required later
///    to derive the final shared pairing key.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - `PairingError::InvalidContactMessage` if the provided contact message
///   is malformed or missing required key material.
/// - `PairingError::PairRequestKeygen { .. }` if cryptographic key generation
///   or ML-KEM encapsulation fails.
///
/// # Security Notes
///
/// - The provided `contact_message` is considered untrusted input and must
///   be validated before use.
/// - The returned secret key material must be stored securely; loss of this
///   state prevents successful completion of the pairing.
/// - This function does not complete pairing; the shared key is derived only
///   after the initiator processes the request and both sides finalize.
///
/// # Example
///
/// ```rust
/// use derec_library::pairing;
///
/// let channel_id = 99u64;
/// let kind = derec_library::protos::derec_proto::SenderKind::Helper;
///
/// // This would normally come from QR decoding.
/// let (contact_msg, _contactor_state) = pairing::create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// )?;
///
/// let (request_msg, secret_state) =
///     pairing::produce_pairing_request_message(channel_id, kind, &contact_msg)?;
///
/// // Send `request_msg` via transport and retain `secret_state`.
/// # Ok::<(), derec_library::Error>(())
/// ```
pub fn produce_pairing_request_message(
    channel_id: u64,
    kind: derec_proto::SenderKind,
    contact_message: &derec_proto::ContactMessage,
) -> Result<
    (
        derec_proto::PairRequestMessage,
        pairing::PairingSecretKeyMaterial,
    ),
    crate::Error,
> {
    if contact_message.mlkem_encapsulation_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }
    if contact_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    // Extract PairingContactMessageMaterial from the contact message
    let contact_pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let mut rng = rand::rngs::OsRng;

    // Generate request key material
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    let (req_pk, sk) = pairing::pairing_request_message(seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e })?;

    let request_msg = derec_proto::PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: req_pk.mlkem_ciphertext,
        ecies_public_key: req_pk.ecies_public_key,
        public_key_id: channel_id,
        nonce: contact_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    Ok((request_msg, sk))
}

/// Produces a [`PairResponseMessage`] and derives the final pairing shared key on the
/// **initiator** (contactor) side.
///
/// This function is executed by the party that originally created and shared the
/// [`ContactMessage`]. After receiving the responder’s [`PairRequestMessage`], the
/// initiator calls this function to:
///
/// 1. Validate the pairing request message.
/// 2. Use the initiator’s previously stored [`PairingSecretKeyMaterial`] (from
///    [`create_contact_message`]) together with the request’s public material to
///    finalize the pairing protocol.
/// 3. Derive the final 256-bit [`PairingSharedKey`].
/// 4. Construct a [`PairResponseMessage`] acknowledging completion.
///
/// The returned shared key is the *session pairing key* that both parties should
/// derive identically after completing the flow; it is typically used as the symmetric
/// basis for encrypting subsequent DeRec protocol messages.
///
/// # Arguments
///
/// * `kind` - Role of the sender within the DeRec protocol (e.g. SharerNonRecovery,
///   SharerRecovery, Helper). This value is included in the response message.
/// * `pair_request_message` - The pairing request received from the responder.
///   Must contain the ML-KEM ciphertext and ECIES public key material.
/// * `pairing_secret_key_material` - Secret state generated earlier by
///   [`create_contact_message`]. This state must correspond to the contact message
///   that initiated the pairing session.
///
/// # Returns
///
/// On success returns a tuple:
///
/// 1. [`derec_proto::PairResponseMessage`] – response message to send back to the responder.
/// 2. [`pairing::PairingSharedKey`] – the derived 256-bit shared key.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - `PairingError::InvalidPairRequestMessage` if the provided request message is malformed
///   or missing required key material.
/// - `PairingError::FinishPairingContactor { .. }` if cryptographic finalization fails
///   (e.g. ML-KEM decapsulation failure, ECIES shared key derivation failure, or invalid state).
///
/// # Security Notes
///
/// - `pair_request_message` is untrusted input received from a peer and must be validated.
/// - The derived shared key should be handled as sensitive material and stored/used in a
///   secure manner appropriate for the host environment.
/// - This function derives the shared key on the initiator side; the responder derives the
///   same key after processing the pairing response and finalizing their side of the protocol.
///
/// # Example
///
/// ```rust
/// use derec_library::pairing;
///
/// let channel_id = 99u64;
/// let kind = derec_library::protos::derec_proto::SenderKind::Helper;
///
/// // This would normally come from QR decoding.
/// let (contact_msg, contactor_secret_state) = pairing::create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// )?;
///
/// let (pair_request_msg, _secret_state) =
///     pairing::produce_pairing_request_message(channel_id, kind, &contact_msg)?;
///
/// let (pair_response_msg, shared_key) = pairing::produce_pairing_response_message(
///     kind,
///     &pair_request_msg,
///     &contactor_secret_state,
/// )?;
///
/// // Send `pair_response_msg` back to the responder and keep/use `shared_key`.
/// # Ok::<(), derec_library::Error>(())
/// ```
pub fn produce_pairing_response_message(
    kind: derec_proto::SenderKind,
    pair_request_message: &derec_proto::PairRequestMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<(derec_proto::PairResponseMessage, pairing::PairingSharedKey), crate::Error> {
    if pair_request_message.mlkem_ciphertext.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("mlkem_ciphertext is empty").into());
    }
    if pair_request_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidPairRequestMessage("ecies_public_key is empty").into());
    }

    // Extract PairingRequestMessageMaterial from the request message
    let pairing_request = pairing::PairingRequestMessageMaterial {
        mlkem_ciphertext: pair_request_message.mlkem_ciphertext.clone(),
        ecies_public_key: pair_request_message.ecies_public_key.clone(),
    };

    // Generate the shared key material (contactor side)
    let sk = pairing::finish_pairing_contactor(pairing_secret_key_material, &pairing_request)
        .map_err(|e| PairingError::FinishPairingContactor { source: e })?;

    let response_msg = derec_proto::PairResponseMessage {
        sender_kind: kind.into(),
        result: Some(derec_proto::Result {
            status: derec_proto::StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: pair_request_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    Ok((response_msg, sk))
}

/// Processes a [`PairResponseMessage`] and derives the final pairing shared key on the
/// **responder** (requestor) side.
///
/// This function is executed by the party that previously:
///
/// 1. Received the initiator’s [`ContactMessage`] out-of-band, and
/// 2. Produced and sent a [`PairRequestMessage`] using [`produce_pairing_request_message`].
///
/// After receiving the initiator’s [`PairResponseMessage`], the responder calls this function to:
///
/// - Validate the response status and bind it to the pairing session (via the nonce),
/// - Use the responder’s previously stored [`PairingSecretKeyMaterial`] (from
///   [`produce_pairing_request_message`]) together with the initiator’s public material from
///   the original [`ContactMessage`],
/// - Derive the final 256-bit [`PairingSharedKey`].
///
/// Both sides should derive the *same* shared key if the pairing was performed correctly.
///
/// # Arguments
///
/// * `contact_message` - The original contact message received from the initiator. This provides
///   the initiator’s public key material and pairing session nonce.
/// * `pair_response_message` - The response message received from the initiator. This message is
///   expected to indicate success and to correspond to the same pairing session.
/// * `pairing_secret_key_material` - Secret state produced earlier by
///   [`produce_pairing_request_message`]. This state must correspond to the pairing request
///   that was sent for the provided contact message.
///
/// # Returns
///
/// On success returns the derived [`pairing::PairingSharedKey`] (a 256-bit shared key).
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Pairing(...)`) in the following cases:
///
/// - `PairingError::InvalidPairResponseMessage` if the response message is missing a result
///   or indicates a non-OK status.
/// - `PairingError::ProtocolViolation` if the response does not match the pairing session
///   (e.g., nonce mismatch).
/// - `PairingError::InvalidContactMessage` if the provided contact message is malformed or
///   missing required key material.
/// - `PairingError::FinishPairingRequestor { .. }` if cryptographic finalization fails
///   (e.g., invalid key material or missing requestor state).
///
/// # Security Notes
///
/// - `pair_response_message` is untrusted input received from a peer and must be validated.
/// - The nonce check is a critical session-binding measure to prevent replay or message mix-up.
/// - The derived shared key should be treated as sensitive material and protected accordingly.
///
/// # Example
///
/// ```rust
/// use derec_library::pairing;
///
/// let channel_id = 99u64;
/// let kind = derec_library::protos::derec_proto::SenderKind::Helper;
///
/// // This would normally come from QR decoding.
/// let (contact_msg, contactor_secret_state) = pairing::create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// )?;
///
/// let (pair_request_msg, requestor_secret_state) =
///     pairing::produce_pairing_request_message(channel_id, kind, &contact_msg)?;
///
/// let (pair_response_msg, shared_key) = pairing::produce_pairing_response_message(
///     kind,
///     &pair_request_msg,
///     &contactor_secret_state,
/// )?;
///
/// let shared_key = pairing::process_pairing_response_message(
///     &contact_msg,
///     &pair_response_msg,
///     &requestor_secret_state,
/// )?;
///
/// // `shared_key` can now be used as the basis for secure channels/messages.
/// # Ok::<(), derec_library::Error>(())
/// ```
pub fn process_pairing_response_message(
    contact_message: &derec_proto::ContactMessage,
    pair_response_message: &derec_proto::PairResponseMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<pairing::PairingSharedKey, crate::Error> {
    let res = pair_response_message
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

    if pair_response_message.nonce != contact_message.nonce {
        return Err(PairingError::ProtocolViolation("nonce mismatch").into());
    }

    if contact_message.mlkem_encapsulation_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }
    if contact_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let shared_key = pairing::finish_pairing_requestor(pairing_secret_key_material, &pk)
        .map_err(|e| PairingError::FinishPairingRequestor { source: e })?;

    Ok(shared_key)
}
