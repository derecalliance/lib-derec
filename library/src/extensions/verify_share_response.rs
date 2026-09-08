// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// The anti-replay gate binding a `VerifyShareResponse` to the request it
/// answers, attached as a method so a new call site cannot process a
/// response without running it.
///
/// A verification response is only meaningful against the challenge that
/// produced it: the nonce is what makes the helper's hash unforgeable, and
/// `secret_id`/`version` are what stop a valid answer about one share being
/// replayed as an answer about another. Checking that inline made the gate a
/// block of code someone could forget to copy into the next reader.
pub(crate) trait VerifyShareResponseExt {
    /// `Ok(())` when the response names the same `(nonce, secret_id,
    /// version)` triple as `request`.
    ///
    /// Takes the whole request rather than the three values: they are all
    /// integers, so a call site passing them individually can transpose two
    /// and still compile, and the check would then pass on a response it
    /// should reject.
    ///
    /// Run this **before** the status and hash checks — a replayed response
    /// can be structurally sound and still be answering a different
    /// question.
    fn validate_binding(
        &self,
        request: &derec_proto::VerifyShareRequestMessage,
    ) -> Result<(), crate::Error>;
}

impl VerifyShareResponseExt for derec_proto::VerifyShareResponseMessage {
    fn validate_binding(
        &self,
        request: &derec_proto::VerifyShareRequestMessage,
    ) -> Result<(), crate::Error> {
        use crate::primitives::verification::VerificationError;

        let mismatch = |field: &'static str, expected: u64, got: u64| {
            crate::Error::from(VerificationError::ResponseBindingMismatch {
                field,
                expected,
                got,
            })
        };
        if self.nonce != request.nonce {
            return Err(mismatch("nonce", request.nonce, self.nonce));
        }
        if self.secret_id != request.secret_id {
            return Err(mismatch("secret_id", request.secret_id, self.secret_id));
        }
        if self.version != request.version {
            return Err(mismatch(
                "version",
                u64::from(request.version),
                u64::from(self.version),
            ));
        }
        Ok(())
    }
}
