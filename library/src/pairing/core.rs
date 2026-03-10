// SPDX-License-Identifier: Apache-2.0

use crate::{
    pairing::{
        CreateContactMessageResult, PairingError, ProcessPairingResponseMessageResult,
        ProducePairingRequestMessageResult, ProducePairingResponseMessageResult,
    },
    types::ChannelId,
    utils::generate_seed,
};
use derec_cryptography::pairing;
use derec_proto::{
    ContactMessage, PairRequestMessage, PairResponseMessage, Result as DeRecResult, SenderKind,
    StatusEnum,
};
use rand::{Rng, rng};

/// Creates a [`ContactMessage`] used to bootstrap the DeRec *pairing* flow.
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
/// On success returns [`CreateContactMessageResult`] containing:
///
/// - `contact_message`: [`derec_proto::ContactMessage`] — public contact payload to send out-of-band.
/// - `secret_key`: [`pairing::PairingSecretKeyMaterial`] — secret key material that must be retained by the caller.
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
/// use derec_library::pairing::*;
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let transport_uri = "https://relay.example/derec";
///
/// let CreateContactMessageResult {
///     contact_message,
///     secret_key,
/// } = create_contact_message(
///     channel_id,
///     transport_uri
/// ).expect("Failed to create contact message");
/// ```
pub fn create_contact_message(
    channel_id: ChannelId,
    transport_uri: &str,
) -> Result<CreateContactMessageResult, crate::Error> {
    if transport_uri.trim().is_empty() {
        return Err(PairingError::EmptyTransportUri.into());
    }

    let mut rng = rng();

    // generate the public key material
    let seed = generate_seed::<32>();

    let (pk, sk) = pairing::contact_message(*seed)
        .map_err(|e| PairingError::ContactMessageKeygen { source: e })?;

    let contact_message = ContactMessage {
        public_key_id: channel_id.into(),
        transport_uri: transport_uri.to_owned(),
        mlkem_encapsulation_key: pk.mlkem_encapsulation_key,
        ecies_public_key: pk.ecies_public_key,
        nonce: rng.next_u64(),
        transport_protocol: 0,
    };

    Ok(CreateContactMessageResult {
        contact_message,
        secret_key: sk,
    })
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
/// On success returns [`ProducePairingRequestMessageResult`] containing:
///
/// - `pair_request_message`: [`derec_proto::PairRequestMessage`] — the pairing
///   request to transmit to the initiator.
/// - `secret_key`: [`pairing::PairingSecretKeyMaterial`] — secret
///   state required later to derive the final shared pairing key.
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
/// use derec_library::pairing::*;
/// use derec_library::types::ChannelId;
/// use derec_proto::SenderKind::Helper;
///
/// let channel_id = ChannelId(42);
/// let kind = Helper;
///
/// // This would normally come from QR decoding.
/// let CreateContactMessageResult {
///     contact_message,
///     ..
/// } = create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// ).expect("Failed to create contact message");
///
/// let ProducePairingRequestMessageResult {
///     pair_request_message,
///     secret_key,
/// } = produce_pairing_request_message(
///     channel_id,
///     kind,
///     &contact_message,
/// ).expect("Failed to produce pairing request message");
/// ```
pub fn produce_pairing_request_message(
    channel_id: ChannelId,
    kind: SenderKind,
    contact_message: &ContactMessage,
) -> Result<ProducePairingRequestMessageResult, crate::Error> {
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

    // Generate request key material
    let seed = generate_seed::<32>();

    let (req_pk, sk) = pairing::pairing_request_message(*seed, &contact_pk)
        .map_err(|e| PairingError::PairRequestKeygen { source: e })?;

    let pair_request_message = PairRequestMessage {
        sender_kind: kind.into(),
        mlkem_ciphertext: req_pk.mlkem_ciphertext,
        ecies_public_key: req_pk.ecies_public_key,
        public_key_id: channel_id.into(),
        nonce: contact_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    Ok(ProducePairingRequestMessageResult {
        pair_request_message,
        secret_key: sk,
    })
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
/// On success returns [`ProducePairingResponseMessageResult`] containing:
///
/// - `pair_response_message`: [`derec_proto::PairResponseMessage`] — response
///   message to send back to the responder.
/// - `shared_key`: [`pairing::PairingSharedKey`] — the derived 256-bit shared key.
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
/// use derec_library::pairing::*;
/// use derec_library::types::ChannelId;
/// use derec_proto::SenderKind::Helper;
///
/// let channel_id = ChannelId(42);
/// let kind = Helper;
///
/// // Initiator creates contact message.
/// let CreateContactMessageResult {
///     contact_message,
///     secret_key: contactor_secret_key,
/// } = create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// ).expect("Failed to create contact message");
///
/// // Responder produces pairing request.
/// let ProducePairingRequestMessageResult {
///     pair_request_message,
///     ..
/// } = produce_pairing_request_message(
///     channel_id,
///     kind,
///     &contact_message,
/// ).expect("Failed to produce pairing request message");
///
/// // Initiator finalizes pairing.
/// let ProducePairingResponseMessageResult {
///     pair_response_message,
///     shared_key,
/// } = produce_pairing_response_message(
///     kind,
///     &pair_request_message,
///     &contactor_secret_key,
/// ).expect("Failed to produce pairing response message");
/// ```
pub fn produce_pairing_response_message(
    kind: SenderKind,
    pair_request_message: &PairRequestMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<ProducePairingResponseMessageResult, crate::Error> {
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
    let shared_key =
        pairing::finish_pairing_contactor(pairing_secret_key_material, &pairing_request)
            .map_err(|e| PairingError::FinishPairingContactor { source: e })?;

    let pair_response_message = PairResponseMessage {
        sender_kind: kind.into(),
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        nonce: pair_request_message.nonce,
        communication_info: None,
        parameter_range: None,
    };

    Ok(ProducePairingResponseMessageResult {
        pair_response_message,
        shared_key,
    })
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
/// On success returns [`ProcessPairingResponseMessageResult`] containing:
///
/// - `shared_key`: the derived 256-bit pairing shared key (wrapped in a semantic type).
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
/// use derec_library::pairing::*;
/// use derec_library::types::ChannelId;
/// use derec_proto::SenderKind::Helper;
///
/// let channel_id = ChannelId(42);
/// let kind = Helper;
///
/// // This would normally come from QR decoding.
/// let CreateContactMessageResult {
///     contact_message,
///     secret_key: contactor_secret_key,
/// } = create_contact_message(
///     channel_id,
///     "https://relay.example/derec",
/// ).expect("Failed to create contact message");
///
/// // Responder produces pairing request.
/// let ProducePairingRequestMessageResult {
///     pair_request_message,
///     secret_key: requestor_secret_key,
/// } = produce_pairing_request_message(
///     channel_id,
///     kind,
///     &contact_message,
/// ).expect("Failed to produce pairing request message");
///
/// // Initiator finalizes pairing.
/// let ProducePairingResponseMessageResult {
///     pair_response_message,
///     shared_key,
/// } = produce_pairing_response_message(
///     kind,
///     &pair_request_message,
///     &contactor_secret_key,
/// ).expect("Failed to produce pairing response message");
///
/// let ProcessPairingResponseMessageResult { shared_key } = process_pairing_response_message(
///     &contact_message,
///     &pair_response_message,
///     &requestor_secret_key,
/// ).expect("Failed to process pairing response message");
/// ```
pub fn process_pairing_response_message(
    contact_message: &ContactMessage,
    pair_response_message: &PairResponseMessage,
    pairing_secret_key_material: &pairing::PairingSecretKeyMaterial,
) -> Result<ProcessPairingResponseMessageResult, crate::Error> {
    if contact_message.mlkem_encapsulation_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("mlkem_encapsulation_key is empty").into());
    }
    if contact_message.ecies_public_key.is_empty() {
        return Err(PairingError::InvalidContactMessage("ecies_public_key is empty").into());
    }

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

    let pk = pairing::PairingContactMessageMaterial {
        mlkem_encapsulation_key: contact_message.mlkem_encapsulation_key.clone(),
        ecies_public_key: contact_message.ecies_public_key.clone(),
    };

    let shared_key = pairing::finish_pairing_requestor(pairing_secret_key_material, &pk)
        .map_err(|e| PairingError::FinishPairingRequestor { source: e })?;

    Ok(ProcessPairingResponseMessageResult { shared_key })
}
