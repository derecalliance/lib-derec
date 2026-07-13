// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::verification::VerificationError,
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{
    DeRecMessage, DeRecResult, MessageBody, StatusEnum, VerifyShareRequestMessage,
    VerifyShareResponseMessage,
};
use prost::Message;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted response payload.
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    /// Decrypted inner [`derec_proto::VerifyShareResponseMessage`].
    pub response: VerifyShareResponseMessage,
}

/// Produces a verification response envelope answering a DeRec verification challenge.
///
/// The responder validates the incoming request and computes:
///
/// `hash = SHA384(share_content || request.nonce_be)`
///
/// and returns an encrypted [`derec_proto::VerifyShareResponseMessage`] carrying:
///
/// - `result.status = Ok`
/// - `secret_id = request.secret_id`
/// - `version = request.version`
/// - `nonce = request.nonce`
/// - `hash = SHA-384 digest`
///
/// The response is serialized, encrypted with the channel shared key, and wrapped in a
/// plain outer [`derec_proto::DeRecMessage`] envelope.
///
/// # Arguments
///
/// * `channel_id` - Channel identifier for the previously paired Helper.
/// * `request` - The decrypted [`derec_proto::VerifyShareRequestMessage`] previously
///   returned by [`super::request::extract`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to encrypt
///   the response.
/// * `share_content` - The share bytes whose possession is being proven.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`derec_proto::VerifyShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - outer response envelope construction or encryption fails
///
/// # Security Notes
///
/// - The proof is bound to the request nonce and therefore to a specific verification challenge.
/// - The outer response timestamp is set equal to the inner response timestamp to preserve
///   the invariant `envelope.timestamp == response.timestamp`.
///
/// # Example
///
/// ```
/// use derec_library::primitives::verification::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// // Owner: issue a verification challenge.
/// let request::ProduceResult { envelope: req_envelope, .. } =
///     request::produce(channel_id, 1, 1, &shared_key, None).expect("produce request failed");
///
/// // Helper: extract the challenge and answer it with the share bytes.
/// let request::ExtractResult { request: challenge } =
///     request::extract(&req_envelope, &shared_key).expect("extract request failed");
/// let response::ProduceResult { envelope } =
///     response::produce(channel_id, &challenge, &shared_key, b"example_share")
///         .expect("produce response failed");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(channel_id = channel_id.0, version = request.version, share_content_len = share_content.as_ref().len())
    )
)]
pub fn produce(
    channel_id: ChannelId,
    request: &VerifyShareRequestMessage,
    shared_key: &SharedKey,
    share_content: impl AsRef<[u8]>,
) -> Result<ProduceResult, crate::Error> {
    let hash = hash_content(share_content, request.nonce);
    let timestamp = current_timestamp();

    let message = VerifyShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        secret_id: request.secret_id,
        version: request.version,
        nonce: request.nonce,
        hash,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::VerifyShareResponse(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("verification response envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes a [`derec_proto::VerifyShareResponseMessage`] from an outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::VerifyShareResponseMessage`] using
///    `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **Owner** side after receiving the Helper's verification response.
/// The decrypted response can then be validated with [`process`].
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::VerifyShareResponseMessage`], as produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::VerifyShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::VerifyShareResponseMessage`]
///
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured ciphertext. Because
/// the channel key is long-lived, a recorded envelope stays
/// decryptable indefinitely. Callers MUST add a freshness window
/// and per-channel anti-replay (monotonic counter or nonce log) on
/// top before driving any side-effecting state off the parsed body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::verification::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
/// let share_content = b"the share bytes the Helper stores";
///
/// // Owner: issue a verification challenge.
/// let request::ProduceResult { envelope: req_envelope, .. } =
///     request::produce(channel_id, 1, 1, &shared_key, None).expect("produce request failed");
///
/// // Helper: extract the challenge and answer it.
/// let request::ExtractResult { request: challenge } =
///     request::extract(&req_envelope, &shared_key).expect("extract request failed");
/// let response::ProduceResult { envelope: resp_envelope } =
///     response::produce(channel_id, &challenge, &shared_key, share_content)
///         .expect("produce response failed");
///
/// // Owner: extract the response.
/// let response::ExtractResult { response } =
///     response::extract(&resp_envelope, &shared_key).expect("extract response failed");
///
/// assert_eq!(response.nonce, challenge.nonce);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(envelope_len = envelope_bytes.len()))
)]
pub fn extract(
    envelope_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<ExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let response = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::VerifyShareResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected VerifyShareResponseMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: VerifyShareResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("verification response extracted and validated");

    Ok(ExtractResult { response })
}

/// Verifies a DeRec verification response by recomputing the expected SHA-384 digest
/// AND binding the response back to the request that produced it.
///
/// This function:
///
/// 1. Asserts the response's `(nonce, secret_id, version)` triple matches the
///    corresponding fields on `request`. Anything else (a stale response,
///    a replay, or a response intended for a different challenge) is rejected
///    with [`VerificationError::ResponseBindingMismatch`] BEFORE any hash
///    work happens. This is the anti-replay gate.
/// 2. Requires `response.result.status == Ok`.
/// 3. Recomputes `expected = SHA384(share_content || request.nonce_be)` using
///    the **owner's** request nonce (not the helper-controlled response nonce),
///    so a helper that crafted a self-consistent `(nonce, hash)` pair from
///    a different `share_content` cannot pass verification.
/// 4. Returns whether `expected == response.hash` using constant-time comparison.
///
/// # Arguments
///
/// * `request` — The [`derec_proto::VerifyShareRequestMessage`] originally
///   produced by [`super::super::request::produce`]. Carries the
///   authoritative `(nonce, secret_id, version)` the response is expected
///   to echo. The owner is expected to retain this — see
///   [`super::super::request::ProduceResult::nonce`] for the wiring.
/// * `response` — The decrypted [`derec_proto::VerifyShareResponseMessage`]
///   previously returned by [`extract`].
/// * `share_content` — The expected share bytes. The digest is recomputed
///   over these bytes plus `request.nonce`.
///
/// # Returns
///
/// On success returns:
///
/// - `Ok(true)` if every binding check passes, the status is `Ok`, and the
///   recomputed digest matches `response.hash`.
/// - `Ok(false)` if every binding check passes and status is `Ok`, but the
///   digest does not match — i.e. the helper claims the share but cannot
///   prove possession over the owner's nonce.
///
/// # Errors
///
/// Returns [`crate::Error`] wrapping:
///
/// - [`VerificationError::ResponseBindingMismatch`] if `response.nonce`,
///   `response.secret_id`, or `response.version` does not match `request`.
/// - `response.result` is absent (returned as `crate::Error::Invariant`).
/// - [`VerificationError::NonOkStatus`] if `response.result.status != Ok`,
///   carrying the Helper's status code and memo string.
///
/// # Security Notes
///
/// - Anti-replay: by hashing against `request.nonce` (the owner's value,
///   which the helper cannot influence) rather than `response.nonce`, a
///   captured-and-replayed response is rejected even if its self-consistent
///   `(nonce, hash)` pair would have passed the cryptographic check on its
///   own. The owner is responsible for tracking outstanding requests (see
///   `pending_verification` on [`crate::protocol::DeRecProtocol`]); if no
///   matching outstanding entry exists, the response should be dropped
///   before reaching this function.
/// - Status validation: the function asserts the responder explicitly
///   marked the operation as successful.
/// - The hash comparison is done using constant-time equality to prevent
///   timing side-channels.
///
/// # Example
///
/// ```
/// use derec_library::primitives::verification::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
/// let share_content = b"example_share";
///
/// // Owner: issue a verification challenge and remember the request body
/// // so we can bind the eventual response back to this specific challenge.
/// let request::ProduceResult { envelope: req_envelope, nonce: _expected_nonce } =
///     request::produce(channel_id, 1, 1, &shared_key, None).expect("produce request failed");
///
/// // Helper: answer the challenge with the share bytes.
/// let request::ExtractResult { request: challenge } =
///     request::extract(&req_envelope, &shared_key).expect("extract request failed");
/// let response::ProduceResult { envelope: resp_envelope } =
///     response::produce(channel_id, &challenge, &shared_key, share_content)
///         .expect("produce response failed");
///
/// // Owner: extract the response and verify the proof against the original
/// // request (which carries the nonce we issued).
/// let response::ExtractResult { response: resp } =
///     response::extract(&resp_envelope, &shared_key).expect("extract response failed");
///
/// assert!(response::process(&challenge, &resp, share_content).expect("process failed"));
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(share_content_len = share_content.as_ref().len()))
)]
pub fn process(
    request: &derec_proto::VerifyShareRequestMessage,
    response: &VerifyShareResponseMessage,
    share_content: impl AsRef<[u8]>,
) -> Result<bool, crate::Error> {
    // Anti-replay / cross-binding gate — runs BEFORE the status and
    // hash checks so a stale/replayed response is rejected even on a
    // structurally-OK envelope.
    if response.nonce != request.nonce {
        return Err(VerificationError::ResponseBindingMismatch {
            field: "nonce",
            expected: request.nonce,
            got: response.nonce,
        }
        .into());
    }
    if response.secret_id != request.secret_id {
        return Err(VerificationError::ResponseBindingMismatch {
            field: "secret_id",
            expected: request.secret_id,
            got: response.secret_id,
        }
        .into());
    }
    if response.version != request.version {
        return Err(VerificationError::ResponseBindingMismatch {
            field: "version",
            expected: u64::from(request.version),
            got: u64::from(response.version),
        }
        .into());
    }

    let result = response.result.as_ref().ok_or(crate::Error::Invariant(
        "VerifyShareResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(
            status = result.status,
            memo = %result.memo,
            "verification response status is not Ok"
        );
        return Err(VerificationError::NonOkStatus {
            status: result.status,
            memo: result.memo.to_owned(),
        }
        .into());
    }

    // Hash against the OWNER'S nonce (from `request`), not the helper-
    // controlled `response.nonce`. The binding gate above guarantees
    // they are equal here, but reading from `request` explicitly
    // documents the security invariant: the proof material is bound
    // to the owner's challenge value.
    let expected_hash = hash_content(share_content, request.nonce);

    let matched: bool = expected_hash.ct_eq(response.hash.as_slice()).into();

    #[cfg(feature = "logging")]
    tracing::info!(verified = matched, "verification proof checked");

    Ok(matched)
}

fn hash_content(share_content: impl AsRef<[u8]>, nonce: u64) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(share_content.as_ref());
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().to_vec()
}
