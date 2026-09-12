// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_proto::SenderKind;

/// Extension trait that attaches pairing-role helpers as methods on the
/// proto [`SenderKind`].
///
/// Sidesteps the orphan rule the same way [`ContactMessageExt`] does for
/// [`ContactMessage`] and [`TransportProtocolExt`](super::transport_protocol::TransportProtocolExt) does
/// for [`derec_proto::TransportProtocol`].
pub(crate) trait SenderKindExt {
    /// The kind on the other side of a pairing, following the
    /// role-inversion rule:
    ///
    /// | this side             | other side            |
    /// |-----------------------|-----------------------|
    /// | `Owner`               | `Helper`              |
    /// | `Helper`              | `Owner`               |
    /// | `ReplicaSource`       | `ReplicaDestination`  |
    /// | `ReplicaDestination`  | `ReplicaSource`       |
    ///
    /// Self-inverse: `k.counterparty().counterparty() == k`. It reads in
    /// both directions, which matters because the wire declares the
    /// *sender's* own kind while
    /// [`Channel::peer_role`](crate::protocol::types::Channel::peer_role)
    /// records the *peer's* — converting either way is this one call.
    ///
    /// [`PairResponseMessage`] does not carry `sender_kind` over the wire,
    /// so the initiator recovers its own role from the channel record
    /// (committed at pairing-start time) through this helper.
    ///
    /// [`PairResponseMessage`]: derec_proto::PairResponseMessage
    fn counterparty(&self) -> SenderKind;

    /// Returns `true` for either replica-mode `SenderKind`
    /// ([`SenderKind::ReplicaSource`] or [`SenderKind::ReplicaDestination`]).
    ///
    /// Centralises the "is this any kind of replica?" check needed at
    /// several handler seams (channel-status assignment,
    /// `replica_id` gating, communication-info validation).
    fn is_replica(&self) -> bool;
}

impl SenderKindExt for SenderKind {
    fn counterparty(&self) -> SenderKind {
        match self {
            SenderKind::Owner => SenderKind::Helper,
            SenderKind::Helper => SenderKind::Owner,
            SenderKind::ReplicaSource => SenderKind::ReplicaDestination,
            SenderKind::ReplicaDestination => SenderKind::ReplicaSource,
        }
    }

    fn is_replica(&self) -> bool {
        matches!(
            self,
            SenderKind::ReplicaSource | SenderKind::ReplicaDestination
        )
    }
}
