// SPDX-License-Identifier: Apache-2.0

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
