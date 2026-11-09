// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_cryptography::vss;
use derec_proto::{DeRecShare, de_rec_share};

use crate::Error;

/// Binds a decoded [`DeRecShare`] to the secret and version it is supposed
/// to be about.
///
/// [`DeRecShare`]: derec_proto::DeRecShare
pub(crate) trait DeRecShareExt {
    /// `Ok(())` when the share names `secret_id` and `version`.
    ///
    /// A share that decodes cleanly can still be the wrong share: recovery
    /// reads them from a helper that stores many, so the identifiers are
    /// what stop one secret's share being reconstructed into another's.
    fn validate(&self, secret_id: u64, version: u32) -> Result<(), Error>;
}

impl DeRecShareExt for DeRecShare {
    fn validate(&self, secret_id: u64, version: u32) -> Result<(), Error> {
        use crate::primitives::recovery::RecoveryError;

        if self.secret_id != secret_id {
            #[cfg(feature = "logging")]
            tracing::warn!("secret_id mismatch between request and stored share");
            return Err(RecoveryError::SecretIdMismatch.into());
        }

        if self.version != version {
            #[cfg(feature = "logging")]
            tracing::warn!(
                expected = version,
                got = self.version,
                "version mismatch between request and stored share"
            );
            return Err(RecoveryError::VersionMismatch {
                expected: version,
                got: self.version,
            }
            .into());
        }

        Ok(())
    }
}

/// A wire `DeRecShare`'s subshares as the [`vss`] subshares they encode.
///
/// [`vss`]: derec_cryptography::vss
pub(crate) fn into_vss_subshares(subshares: Vec<de_rec_share::Subshare>) -> Vec<vss::Subshare> {
    subshares
        .into_iter()
        .map(|p| vss::Subshare { x: p.x, y: p.y })
        .collect()
}

/// [`vss`] subshares as the subshares of a wire `DeRecShare`.
///
/// [`vss`]: derec_cryptography::vss
pub(crate) fn to_wire_subshares(subshares: &[vss::Subshare]) -> Vec<de_rec_share::Subshare> {
    subshares
        .iter()
        .map(|p| de_rec_share::Subshare {
            x: p.x.clone(),
            y: p.y.clone(),
        })
        .collect()
}
