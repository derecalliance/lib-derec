// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::transport::{TransportProtocol, TransportValidationError};

/// Extension trait that gives the prost wire type
/// [`derec_proto::TransportProtocol`] the same `validate()` shape as the
/// library wrapper [`TransportProtocol`]. Defined here because the wire
/// type lives in another crate — the orphan rule blocks adding an
/// inherent method.
///
/// Brought into scope at every boundary where a remotely-controlled or
/// application-supplied [`derec_proto::TransportProtocol`] surfaces:
/// peer-extracted `reply_to` / `transport_protocol` fields inside
/// `extract` primitives, the orchestrator's `on_request` handlers, and
/// the FFI seam helpers. Centralising the gate in one impl keeps the
/// rejection semantics uniform across SDKs through
/// [`crate::Error::Transport`].
pub trait TransportProtocolExt {
    /// Validate the endpoint's structural soundness + scheme/protocol
    /// consistency. Same rules as [`TransportProtocol::validate`]:
    /// non-empty URI ≤ [`MAX_TRANSPORT_URI_LEN`](crate::transport::MAX_TRANSPORT_URI_LEN) bytes, no control
    /// characters, known `protocol` discriminant, and the URI scheme
    /// matches the declared protocol.
    fn validate(&self) -> Result<(), TransportValidationError>;
}

impl TransportProtocolExt for derec_proto::TransportProtocol {
    fn validate(&self) -> Result<(), TransportValidationError> {
        TransportProtocol::try_from(self).map(|_| ())
    }
}
