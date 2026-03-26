// SPDX-License-Identifier: Apache-2.0

/// Input required to process a single share response during the recovery flow.
///
/// Each entry represents one helper's response and the cryptographic material
/// needed to decrypt and validate it.
///
/// In the DeRec recovery protocol:
///
/// - Each helper returns a response message containing its share
/// - That response is wrapped in a [`DeRecMessage`] envelope and encrypted
///   using the per-channel shared key established during pairing
/// - The caller must provide both the raw response bytes and the corresponding
///   shared key so the library can decrypt and extract the share
///
/// This struct pairs those two pieces of information for use in
/// [`recover_from_share_responses`].
///
/// # Fields
///
/// * `bytes` - The serialized [`DeRecMessage`] containing an encrypted
///   `GetShareResponseMessage`, as received from a helper
///
/// * `shared_key` - The 32-byte symmetric key associated with the helper's
///   channel, derived during the pairing flow. This key is used to decrypt
///   `bytes`
///
/// # Notes
///
/// - The `shared_key` must match the key used by the helper to encrypt the response
/// - Passing a mismatched key will result in decryption failure
/// - The struct does not include `ChannelId`, as it is not required for
///   decryption or reconstruction; however, callers may track it externally
///   if needed for logging or validation
///
/// [`DeRecMessage`]: derec_proto::DeRecMessage
pub struct RecoveryResponseInput<'a> {
    pub bytes: &'a [u8],
    pub shared_key: &'a [u8; 32],
}

/// Result of [`generate_share_request`].
///
/// This type contains the serialized outer [`derec_proto::DeRecMessage`] envelope
/// carrying an encrypted inner [`GetShareRequestMessage`].
pub struct GenerateShareRequestResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes.
    pub wire_bytes: Vec<u8>,
}

/// Result of [`generate_share_response`].
///
/// This type contains the serialized outer [`derec_proto::DeRecMessage`] envelope
/// carrying an encrypted inner [`GetShareResponseMessage`].
pub struct GenerateShareResponseResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes.
    pub wire_bytes: Vec<u8>,
}

/// Result of [`recover_from_share_responses`].
///
/// This type contains the reconstructed secret bytes recovered from helper responses.
pub struct RecoverFromResponsesResult {
    /// Reconstructed secret bytes.
    pub secret_data: Vec<u8>,
}
