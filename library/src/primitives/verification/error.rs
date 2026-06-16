// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerificationError {
    #[error("verification response indicates a non-OK status (status={status}): {memo}")]
    NonOkStatus { status: i32, memo: String },

    /// The response's `(nonce, secret_id, version)` triple does not
    /// match the request the owner had outstanding for this channel.
    /// Surfaced when a stale/replayed response or one targeting a
    /// different challenge reaches
    /// [`crate::primitives::verification::response::process`].
    #[error(
        "verification response does not match the outstanding request: \
         field={field} expected={expected} got={got}"
    )]
    ResponseBindingMismatch {
        /// Which scalar disagreed — one of `"nonce"`, `"secret_id"`,
        /// or `"version"`. Kept as a static string so the variant is
        /// cheap to construct and easy to match on.
        field: &'static str,
        expected: u64,
        got: u64,
    },
}
