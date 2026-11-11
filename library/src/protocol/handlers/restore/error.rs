// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::types::ChannelId;

/// Restore-specific failure modes surfaced via [`crate::Error::Restore`].
/// Every variant is reported **before any store mutation** — a
/// precondition error is exactly equivalent to never having called
/// restore. Store I/O failures mid-restore propagate as their
/// underlying [`crate::Error`] variant instead.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    /// A user-secret snapshot already exists for the protocol's
    /// `secret_id`. The application must clear it before retrying.
    #[error("user-secret snapshot already exists for secret_id")]
    AlreadyRestored,

    /// One or more channels already live at canonical helper ids
    /// carried by the recovered `Secret`. The contained
    /// list enumerates the collisions; the application clears them
    /// through its own store wrappers and retries.
    #[error("restore blocked by pre-existing channels at canonical ids")]
    Conflict(Vec<ChannelId>),

    /// The recovered [`Secret`](crate::protocol::types::Secret) is internally inconsistent. Only
    /// reachable when a `Secret` was hand-crafted — library-produced
    /// ones always satisfy the invariants (rebuilt inside the sharing
    /// handler during a `start(ProtectSecret)` round).
    #[error("recovered Secret is internally inconsistent: {0}")]
    Invariant(&'static str),

    /// A [`KeepRecoveryChannel`](crate::protocol::types::KeepRecoveryChannel) pair names this channel and cannot be
    /// honoured: its roster id is not a helper in the recovered roster, its
    /// recovery id is not a `Paired` channel to a Helper outside the roster,
    /// or the id is named by more than one pair. The first offending id, in
    /// the order the pairs were given.
    #[error("restore cannot keep channel {}: not a valid recovery channel pair", .0.0)]
    InvalidKeptChannel(ChannelId),
}
