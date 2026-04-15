// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::verification::VerificationError,
    types::*,
};
use derec_proto::{
    DeRecMessage, DeRecResult, MessageBody, StatusEnum, VerifyShareRequestMessage,
    VerifyShareResponseMessage,
};
use prost::Message;
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

// ─── Types ────────────────────────────────────────────────────────────────────

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope with the encrypted response payload.
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// Decrypted inner [`derec_proto::VerifyShareResponseMessage`].
    pub response: VerifyShareResponseMessage,
}

// ─── Functions ────────────────────────────────────────────────────────────────

/// Creates a verification response envelope answering a DeRec verification challenge.
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
/// * `channel_id` - Channel identifier for the previously paired helper.
/// * `request` - The decrypted [`derec_proto::VerifyShareRequestMessage`] previously
///   returned by the request module's `extract` function.
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
/// ```no_run
/// use derec_library::primitives::verification::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// // After extracting the incoming request:
/// // let request::ExtractResult { request } = request::extract(&envelope_bytes, &shared_key)?;
/// // let response::ProduceResult { envelope } =
/// //     response::produce(channel_id, &request, &shared_key, b"example_share")?;
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
        secret_id: request.secret_id.clone(),
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

    if envelope.timestamp != response.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("verification response extracted and validated");

    Ok(ExtractResult { response })
}

/// Verifies a DeRec verification response by recomputing the expected SHA-384 digest.
///
/// This function:
///
/// 1. Requires `response.result.status == Ok`
/// 2. Recomputes:
///
/// `expected = SHA384(share_content || response.nonce_be)`
///
/// 3. Returns whether `expected == response.hash` using constant-time comparison
///
/// # Arguments
///
/// * `response` - The decrypted [`derec_proto::VerifyShareResponseMessage`] previously
///   returned by [`extract`].
/// * `share_content` - The expected share bytes. The digest is recomputed over these bytes.
///
/// # Returns
///
/// On success returns:
///
/// - `Ok(true)` if the response status is `Ok` and the recomputed digest matches `response.hash`
/// - `Ok(false)` if the response status is `Ok` but the digest does not match
///
/// # Errors
///
/// Returns [`crate::Error`] wrapping:
///
/// - [`VerificationError::MissingResult`] if `response.result` is absent
/// - [`VerificationError::NonOkStatus`] if `response.result.status != Ok`
///
/// # Security Notes
///
/// - This function validates that the responder explicitly marked the operation as successful.
/// - This function does **not** compare the response against the original request bytes, so it
///   does not independently verify that the returned `version` or `nonce` match a specific
///   previously issued request. It only verifies the cryptographic proof against the nonce
///   present in the response itself.
/// - The hash comparison is done using constant-time equality to prevent timing side-channels.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::verification::{request, response};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
/// let share_content = b"example_share";
///
/// // After extracting the response:
/// // let response::ExtractResult { response: resp } = response::extract(&envelope_bytes, &shared_key)?;
/// // let ok = response::process(&resp, share_content)?;
/// // assert!(ok);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(share_content_len = share_content.as_ref().len()))
)]
pub fn process(
    response: &VerifyShareResponseMessage,
    share_content: impl AsRef<[u8]>,
) -> Result<bool, crate::Error> {
    let result = response
        .result
        .as_ref()
        .ok_or(VerificationError::MissingResult)?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = result.status, "verification response status is not Ok");
        return Err(VerificationError::NonOkStatus { status: result.status }.into());
    }

    let expected_hash = hash_content(share_content, response.nonce);

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
