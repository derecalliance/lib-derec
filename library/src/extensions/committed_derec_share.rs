// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// Structural validation for a decoded [`CommittedDeRecShare`], attached as
/// a method the same way [`ContactMessageExt`] attaches it to
/// [`ContactMessage`].
///
/// [`CommittedDeRecShare`]: derec_proto::CommittedDeRecShare
pub(crate) trait CommittedDeRecShareExt {
    /// Enforces the field-presence invariants the proto schema documents
    /// but cannot express: the wrapped share, its commitment and the Merkle
    /// path must all be present.
    ///
    /// An absent commitment or path is not recoverable later — the share
    /// cannot be proven to belong to the set it claims — so it is refused
    /// on the way in rather than stored and failed at recovery time.
    fn validate(&self) -> Result<(), crate::Error>;
}

impl CommittedDeRecShareExt for derec_proto::CommittedDeRecShare {
    fn validate(&self) -> Result<(), crate::Error> {
        if self.de_rec_share.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("CommittedDeRecShare.de_rec_share is empty");
            return Err(crate::Error::Invariant(
                "CommittedDeRecShare.de_rec_share is empty",
            ));
        }
        if self.commitment.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("CommittedDeRecShare.commitment is empty");
            return Err(crate::Error::Invariant(
                "CommittedDeRecShare.commitment is empty",
            ));
        }
        if self.merkle_path.is_empty() {
            #[cfg(feature = "logging")]
            tracing::warn!("CommittedDeRecShare.merkle_path is empty");
            return Err(crate::Error::Invariant(
                "CommittedDeRecShare.merkle_path is empty",
            ));
        }
        Ok(())
    }
}
