// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{self, DeRecMessageBuilder, current_timestamp},
    types::*,
    verification::{GenerateVerificationRequestResult, GenerateVerificationResponseResult},
};
use derec_proto::{DeRecResult, StatusEnum, VerifyShareRequestMessage, VerifyShareResponseMessage};
use prost::Message;
use rand::{Rng, rng};
use sha2::{Digest, Sha384};
use subtle::ConstantTimeEq;

/// Creates a verification request envelope to initiate the DeRec *verification* flow.
///
/// In DeRec, verification allows an Owner to challenge a Helper to prove it still holds
/// the expected share bytes. The Owner sends an encrypted
/// [`VerifyShareRequestMessage`] containing:
///
/// - a `version` identifying the share-distribution version being verified
/// - a fresh `nonce` used to bind the later proof to this specific request
///
/// The request is serialized, encrypted with the already established channel shared key,
/// and wrapped in an outer plain [`derec_proto::DeRecMessage`] envelope.
///
/// The Helper is expected to compute:
///
/// `SHA384(share_content || nonce_be)`
///
/// and return that digest in a [`VerifyShareResponseMessage`].
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API
///   consistency and future extensibility.
/// * `channel_id` - Channel identifier for the previously paired helper.
/// * `version` - Distribution version to embed in the request. The responder is expected to
///   echo this value in the response.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to encrypt the
///   inner verification request.
///
/// # Returns
///
/// On success returns [`GenerateVerificationRequestResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`VerifyShareRequestMessage`]
///
/// The inner request contains:
///
/// - `version`: the provided version
/// - `nonce`: a fresh randomly generated `u64`
/// - `timestamp`: the request creation timestamp
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric encryption fails.
///
/// # Security Notes
///
/// - The nonce is generated using the crate's RNG source via `rand::rng()` and must be
///   unpredictable to prevent replay of previously captured responses.
/// - The outer envelope is not encrypted; only the inner protobuf message is encrypted.
/// - The outer envelope timestamp is set equal to the inner request timestamp to preserve
///   the invariant `envelope.timestamp == request.timestamp`.
///
/// # Example
///
/// ```rust
/// use derec_library::types::ChannelId;
/// use derec_library::verification::generate_verification_request;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let result = generate_verification_request(
///     b"secret_id",
///     channel_id,
///     7,
///     &shared_key,
/// )
/// .expect("failed to build verification request");
///
/// assert!(!result.wire_bytes.is_empty());
/// ```
pub fn generate_verification_request(
    _secret_id: impl AsRef<[u8]>,
    channel_id: ChannelId,
    version: i32,
    shared_key: &[u8; 32],
) -> Result<GenerateVerificationRequestResult, crate::Error> {
    let mut rng = rng();

    let timestamp = current_timestamp();
    let nonce = rng.next_u64();

    let message = VerifyShareRequestMessage {
        version,
        nonce,
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(GenerateVerificationRequestResult { wire_bytes })
}

/// Creates a verification response envelope answering a DeRec verification request.
///
/// The responder decrypts the incoming request, validates the invariant
/// `envelope.timestamp == request.timestamp`, computes:
///
/// `hash = SHA384(share_content || request.nonce_be)`
///
/// and returns an encrypted [`VerifyShareResponseMessage`] carrying:
///
/// - `result.status = Ok`
/// - `version = request.version`
/// - `nonce = request.nonce`
/// - `hash = SHA-384 digest`
///
/// The response is serialized, encrypted with the channel shared key, and wrapped in a
/// plain outer [`derec_proto::DeRecMessage`] envelope.
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API
///   consistency and future extensibility.
/// * `channel_id` - Channel identifier for the previously paired helper.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the request and encrypt the response.
/// * `share_content` - The share bytes whose possession is being proven.
/// * `request_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying the
///   encrypted inner [`VerifyShareRequestMessage`].
///
/// # Returns
///
/// On success returns [`GenerateVerificationResponseResult`] containing:
///
/// - `wire_bytes`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an encrypted
///   inner [`VerifyShareResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - request decryption or protobuf decoding fails
/// - `envelope.timestamp != request.timestamp`
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
/// ```rust
/// use derec_library::types::ChannelId;
/// use derec_library::verification::{
///     generate_verification_request,
///     generate_verification_response,
/// };
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let request = generate_verification_request(
///     b"secret_id",
///     channel_id,
///     7,
///     &shared_key,
/// )
/// .expect("failed to generate verification request");
///
/// let response = generate_verification_response(
///     b"secret_id",
///     channel_id,
///     &shared_key,
///     b"example_share",
///     &request.wire_bytes,
/// )
/// .expect("failed to generate verification response");
///
/// assert!(!response.wire_bytes.is_empty());
/// ```
pub fn generate_verification_response(
    _secret_id: impl AsRef<[u8]>,
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    share_content: impl AsRef<[u8]>,
    request_bytes: impl AsRef<[u8]>,
) -> Result<GenerateVerificationResponseResult, crate::Error> {
    let (envelope, request) = derec_message::extract_inner_message::<VerifyShareRequestMessage>(
        request_bytes,
        shared_key,
    )?;

    if envelope.timestamp != request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    let hash = hash_content(share_content, request.nonce);
    let timestamp = current_timestamp();

    let message = VerifyShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version: request.version,
        nonce: request.nonce,
        hash,
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&message)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(GenerateVerificationResponseResult { wire_bytes })
}

/// Verifies a DeRec verification response by decrypting it and recomputing the expected
/// SHA-384 digest.
///
/// This function:
///
/// 1. decrypts and decodes the inner [`VerifyShareResponseMessage`]
/// 2. checks the invariant `envelope.timestamp == response.timestamp`
/// 3. requires `response.result.status == Ok`
/// 4. recomputes:
///
/// `expected = SHA384(share_content || response.nonce_be)`
///
/// 5. returns whether `expected == response.hash` using constant-time comparison
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API
///   consistency and future extensibility.
/// * `_channel_id` - Channel identifier (currently unused by this helper). Included for API
///   consistency and future extensibility.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt the
///   response.
/// * `share_content` - The expected share bytes. The digest is recomputed over these bytes.
/// * `response_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying the
///   encrypted inner [`VerifyShareResponseMessage`].
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
/// Returns [`crate::Error`] if:
///
/// - response decryption or protobuf decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - `response.result` is missing
/// - `response.result.status != Ok`
///
/// # Security Notes
///
/// - This function validates the response envelope/message timestamp invariant.
/// - This function validates that the responder explicitly marked the operation as successful.
/// - This function does **not** compare the response against the original request bytes, so it
///   does not independently verify that the returned `version` or `nonce` match a specific
///   previously issued request. It only verifies the cryptographic proof against the nonce
///   present in the response itself.
///
/// # Example
///
/// ```rust
/// use derec_library::types::ChannelId;
/// use derec_library::verification::{
///     generate_verification_request,
///     generate_verification_response,
///     verify_share_response,
/// };
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
/// let share_content = b"example_share";
///
/// let request = generate_verification_request(
///     b"secret_id",
///     channel_id,
///     7,
///     &shared_key,
/// )
/// .expect("failed to generate verification request");
///
/// let response = generate_verification_response(
///     b"secret_id",
///     channel_id,
///     &shared_key,
///     share_content,
///     &request.wire_bytes,
/// )
/// .expect("failed to generate verification response");
///
/// let ok = verify_share_response(
///     b"secret_id",
///     channel_id,
///     &shared_key,
///     share_content,
///     &response.wire_bytes,
/// )
/// .expect("failed to verify response");
///
/// assert!(ok);
/// ```
pub fn verify_share_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: ChannelId,
    shared_key: &[u8; 32],
    share_content: impl AsRef<[u8]>,
    response_bytes: impl AsRef<[u8]>,
) -> Result<bool, crate::Error> {
    let (envelope, response) = derec_message::extract_inner_message::<VerifyShareResponseMessage>(
        response_bytes,
        shared_key,
    )?;

    if envelope.timestamp != response.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    let result = response.result.ok_or(crate::Error::Invariant(
        "Verification response is missing result",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        return Err(crate::Error::Invariant(
            "Verification response status is not Ok",
        ));
    }

    let expected_hash = hash_content(share_content, response.nonce);

    Ok(expected_hash.ct_eq(response.hash.as_slice()).into())
}

fn hash_content(share_content: impl AsRef<[u8]>, nonce: u64) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(share_content.as_ref());
    hasher.update(nonce.to_be_bytes());
    hasher.finalize().to_vec()
}
