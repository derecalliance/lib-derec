// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! What a handler needs to know beyond the stores: who this device is, and
//! which exchange it is answering.
//!
//! Three groupings, split by how long each stays true rather than by which
//! flow uses it. [`Local`] is fixed for the life of a protocol instance,
//! [`Exchange`] describes one request/response pair on one channel, and
//! [`PairingConfig`] carries what a peer is told at pairing time and is
//! meaningless outside it.

use crate::transport::TransportPolicy;
use crate::types::{ChannelId, SharedKey};
use derec_proto::TransportProtocol;
use std::collections::HashMap;

/// Identity and configuration constant for the lifetime of a protocol
/// instance.
///
/// Every handler takes this whether or not it reads all four fields, for the
/// same reason it takes every store: the shape of a signature should not
/// encode which values a flow happens to need today.
pub(crate) struct Local<'a> {
    /// The single secret this protocol instance manages.
    ///
    /// `recovery::start` is the one flow this does not settle: it recovers a
    /// *different* instance's secret, so it reads this for the local side and
    /// takes the target id separately.
    pub(crate) secret_id: u64,
    /// This device's group identity, or `None` when replica flows are off.
    ///
    /// Handlers previously spelled this `local_replica_id` on the group paths
    /// and `replica_id` on the pairing paths; both were always
    /// `DeRecProtocol::replica_id`.
    pub(crate) replica_id: Option<u64>,
    /// Every endpoint this device advertises, in preference order. Never
    /// empty — the typestate builder cannot reach `build()` with the slot
    /// unfilled.
    pub(crate) own_transports: &'a [TransportProtocol],
    /// Which peer-supplied endpoint schemes this device will accept.
    pub(crate) policy: TransportPolicy,
}

impl Local<'_> {
    /// This device's primary endpoint — the one a peer is told to answer on
    /// when only a single address fits the wire field.
    pub(crate) fn primary(&self) -> &TransportProtocol {
        &self.own_transports[0]
    }

    /// This device's own row, as a
    /// [`ReplicaFilter::exclude`](crate::protocol::types::ChannelFilter::exclude)
    /// list.
    ///
    /// Empty when replica flows are off, which excludes nothing — correctly,
    /// since a device with no group identity holds no row to leave out.
    pub(crate) fn exclude_self(&self) -> Vec<crate::types::ReplicaId> {
        self.replica_id
            .map(crate::types::ReplicaId)
            .into_iter()
            .collect()
    }
}

/// One request/response exchange on one channel.
///
/// Split from [`Local`] because a channel is not instance-wide: the flows
/// that open one (`start`, `restore`, `tear_down`) have no channel or key
/// yet, and folding these in would make all three fields `Option` and lie
/// about every one of them.
pub(crate) struct Exchange<'a> {
    pub(crate) channel_id: ChannelId,
    pub(crate) shared_key: &'a SharedKey,
    /// The correlation token for this exchange.
    ///
    /// One field for what handlers spelled two ways: `inbound_trace_id` when
    /// echoing a request's token back, `trace_id` when stamping one on an
    /// outbound envelope. It is the same token either way, and carrying it
    /// here is what stops a new call site from forgetting it.
    pub(crate) trace_id: u64,
}

/// What one [`DeRecProtocol::start`](crate::protocol::DeRecProtocol::start)
/// call needs to address and identify itself.
///
/// A round is every request a single `start` dispatches. Both fields are
/// properties of the round rather than of any one request in it, which is why
/// they travel together: every target is told the same place to reply, and
/// every target is sent the same token.
///
/// Split from [`Exchange`] because that describes an exchange already under
/// way — it has a `channel_id` and a key. A round has neither when it begins,
/// and a fan-out never has just one.
pub(crate) struct Round<'a> {
    /// The endpoints a peer should answer on, or empty to let it use the
    /// endpoints recorded at pairing. Governed by
    /// [`with_auto_reply_to`](crate::protocol::DeRecProtocolBuilder::with_auto_reply_to);
    /// pairing ignores it, carrying its endpoints in its own field instead.
    pub(crate) reply_to: &'a [derec_proto::TransportProtocol],
    /// The correlation token every request in this round carries, and that
    /// each peer echoes on its response. Drawn once per `start`, so a
    /// fan-out is one trace rather than one per target.
    pub(crate) trace_id: u64,
}

/// What a peer is told at pairing time, and validated against on the way in.
///
/// Separate from [`Local`] because it is read by the pairing entry points
/// alone; the other flows would carry two fields they can never use.
///
/// Deliberately not used by `update_channel_info::start`, whose
/// `communication_info` and `own_transports` are the *new* values a caller
/// asked to broadcast rather than the instance's current ones.
pub(crate) struct PairingConfig<'a> {
    pub(crate) communication_info: &'a HashMap<String, String>,
    pub(crate) parameter_range: Option<&'a derec_proto::ParameterRange>,
}

/// Borrow a [`DeRecProtocol`]'s identity into a [`Local`].
///
/// Reads `unsafe_http` directly rather than calling `transport_policy()`:
/// that method borrows the whole protocol, which would collide with the
/// store borrows [`borrow_stores!`](crate::protocol::stores::borrow_stores)
/// takes in the same call. Copying one `bool` field keeps the two disjoint.
///
/// [`DeRecProtocol`]: crate::protocol::DeRecProtocol
macro_rules! local {
    ($protocol:expr) => {
        $crate::protocol::context::Local {
            secret_id: $protocol.secret_id,
            replica_id: $protocol.replica_id,
            own_transports: &$protocol.own_transports,
            policy: $crate::transport::TransportPolicy::new($protocol.unsafe_http),
        }
    };
}

/// Borrow a [`DeRecProtocol`]'s pairing-time configuration.
///
/// [`DeRecProtocol`]: crate::protocol::DeRecProtocol
macro_rules! pairing_config {
    ($protocol:expr) => {
        $crate::protocol::context::PairingConfig {
            communication_info: &$protocol.communication_info,
            parameter_range: $protocol.parameter_range.as_ref(),
        }
    };
}

pub(crate) use local;
pub(crate) use pairing_config;
