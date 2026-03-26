// SPDX-License-Identifier: Apache-2.0

/// Result of [`generate_verification_request`].
///
/// This type contains the serialized outer [`derec_proto::DeRecMessage`] envelope
/// carrying an encrypted inner [`VerifyShareRequestMessage`].
pub struct GenerateVerificationRequestResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes.
    pub wire_bytes: Vec<u8>,
}

/// Result of [`generate_verification_response`].
///
/// This type contains the serialized outer [`derec_proto::DeRecMessage`] envelope
/// carrying an encrypted inner [`VerifyShareResponseMessage`].
pub struct GenerateVerificationResponseResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] bytes.
    pub wire_bytes: Vec<u8>,
}
