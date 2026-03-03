// SPDX-License-Identifier: Apache-2.0

use crate::protos::derec_proto::{
    Result as DerecResult, StatusEnum, VerifyShareRequestMessage, VerifyShareResponseMessage,
};
use crate::types::*;
use crate::verification::VerificationError;
use rand::RngCore;
use sha2::*;

const VERIFICATION_NONCE_LEN: usize = 32;

/// Creates a [`VerifyShareRequestMessage`] to initiate the DeRec *verification* flow.
///
/// In DeRec, verification allows an Owner to challenge a Helper to prove it still holds the
/// expected share bytes. The Owner sends a request containing:
///
/// - A `version` identifying the share-distribution version being verified
/// - A fresh, unpredictable `nonce` that prevents replay of previously captured responses
///
/// The Helper is expected to compute a SHA-384 digest over `(share_content || nonce)` and return it
/// in a [`VerifyShareResponseMessage`].
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API consistency
///   and for future extensions where the secret context may influence verification.
/// * `version` - Distribution version to embed in the request. The responder should echo this value
///   in the response.
///
/// # Returns
///
/// On success returns a [`VerifyShareRequestMessage`] containing:
///
/// - `version`: the provided version
/// - `nonce`: 32 bytes generated using the OS CSPRNG (`rand::rngs::OsRng`)
///
/// # Errors
///
/// This function currently returns no verification-specific errors. The return type is
/// `Result<_, crate::Error>` for API stability and to allow future validations.
///
/// # Security Notes
///
/// - The nonce is generated using the OS CSPRNG and MUST be unique/unpredictable to mitigate replay.
/// - The request is not itself a proof; the proof is the responder’s hash bound to the nonce.
///
/// # Example
///
/// ```rust
/// use derec_library::verification::*;
///
/// let secret_id = "secret_id";
/// let version = 7;
///
/// let request = generate_verification_request(secret_id, version)
///     .expect("failed to build verification request");
///
/// assert_eq!(request.version, 7);
/// assert_eq!(request.nonce.len(), 32);
/// ```
pub fn generate_verification_request(
    _secret_id: impl AsRef<[u8]>,
    version: i32,
) -> Result<VerifyShareRequestMessage, crate::Error> {
    // Generate a nonce using a secure random number generator
    let mut rng = rand::rngs::OsRng;
    let mut nonce = vec![0u8; VERIFICATION_NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    Ok(VerifyShareRequestMessage { version, nonce })
}

/// Creates a [`VerifyShareResponseMessage`] to answer a DeRec *verification* request.
///
/// The response proves possession of the provided `share_content` by computing:
///
/// `hash = SHA384(share_content || request.nonce)`
///
/// The returned [`VerifyShareResponseMessage`] includes:
///
/// - `result.status = Ok`
/// - `version = request.version`
/// - `nonce = request.nonce`
/// - `hash = SHA-384 digest`
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API consistency
///   and future extensions.
/// * `_channel_id` - Channel identifier (currently unused by this helper). Included for API consistency
///   and future extensions.
/// * `share_content` - The share bytes to be proven/verified. The digest is computed over these bytes.
/// * `request` - The original [`VerifyShareRequestMessage`] containing `version` and the challenge `nonce`.
///
/// # Returns
///
/// On success returns a [`VerifyShareResponseMessage`] containing:
///
/// - `result`: [`DerecResult`] with `status = StatusEnum::Ok`
/// - `version`: echoed from `request.version`
/// - `nonce`: echoed from `request.nonce`
/// - `hash`: `SHA384(share_content || request.nonce)`
///
/// # Errors
///
/// Returns [`VerificationError`] in the following cases:
///
/// - [`VerificationError::Invariant`] if `request.nonce.len() != 32`.
///
/// # Security Notes
///
/// - This response is only meaningful when the verifier binds it to the original request nonce.
/// - The `result` field indicates protocol-level success; verifiers may additionally enforce that
///   `result` is present and `status == Ok` (this crate’s current `verify_share_response` does not).
///
/// # Example
///
/// ```rust
/// use derec_library::verification::*;
///
/// let secret_id = "secret_id";
/// let version = 7;
/// let channel_id = 1;
/// let share_content = b"example_share";
///
/// let request = generate_verification_request(secret_id, version)
///     .expect("Failed to generate verification request");
///
/// let response = generate_verification_response(secret_id, &channel_id, share_content, &request)
///     .expect("Failed to generate verification response");
///
/// assert_eq!(response.version, request.version);
/// assert_eq!(response.nonce, request.nonce);
/// assert!(!response.hash.is_empty());
/// ```
pub fn generate_verification_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &ChannelId,
    share_content: impl AsRef<[u8]>,
    request: &VerifyShareRequestMessage,
) -> Result<VerifyShareResponseMessage, crate::Error> {
    if request.nonce.len() != VERIFICATION_NONCE_LEN {
        return Err(VerificationError::Invariant("request nonce must be 32 bytes").into());
    }

    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(request.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    Ok(VerifyShareResponseMessage {
        result: Some(DerecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version: request.version,
        nonce: request.nonce.clone(),
        hash,
    })
}

/// Verifies a [`VerifyShareResponseMessage`] by recomputing the expected SHA-384 digest.
///
/// This helper recomputes:
///
/// `expected = SHA384(share_content || response.nonce)`
///
/// and returns `true` if `expected == response.hash`.
///
/// # Arguments
///
/// * `_secret_id` - Secret identifier (currently unused by this helper). Included for API consistency
///   and future extensions.
/// * `_channel_id` - Channel identifier (currently unused by this helper). Included for API consistency
///   and future extensions.
/// * `share_content` - The expected share bytes. The digest is recomputed over these bytes.
/// * `response` - The [`VerifyShareResponseMessage`] containing the nonce and hash to verify.
///
/// # Returns
///
/// On success returns:
///
/// - `Ok(true)` if the recomputed digest matches `response.hash`
/// - `Ok(false)` otherwise
///
/// # Errors
///
/// This function currently returns no verification-specific errors. The return type is
/// `Result<_, crate::Error>` for API stability and to allow future validations.
///
/// # Security Notes
///
/// - **Limitation:** this function does *not* validate `response.result`, `response.version`, or that
///   `response.nonce` matches the original request nonce. It only checks that the hash matches the
///   nonce included in the response.
///
/// # Example
///
/// ```rust
/// use derec_library::verification::*;
///
/// let secret_id = "secret_id";
/// let version = 7;
/// let channel_id = 1;
/// let request = generate_verification_request(secret_id, version)
///     .expect("failed to build verification request");
///
/// let share_content = b"example_share";
///
/// let response = generate_verification_response(secret_id, &channel_id, share_content, &request)
///     .expect("failed to generate verification response");
///
/// let ok = verify_share_response(secret_id, &channel_id, share_content, &response)
///     .expect("failed to verify response");
///
/// assert!(ok);
/// ```
pub fn verify_share_response(
    _secret_id: impl AsRef<[u8]>,
    _channel_id: &ChannelId,
    share_content: impl AsRef<[u8]>,
    response: &VerifyShareResponseMessage,
) -> Result<bool, crate::Error> {
    // compute the Sha384 hash of the share content
    let mut hasher = Sha384::new();
    hasher.update(share_content);
    hasher.update(response.nonce.as_slice());
    let hash = hasher.finalize().to_vec();

    Ok(hash == response.hash)
}
