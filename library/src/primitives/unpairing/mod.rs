// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Unpair flow primitives.
//!
//! Unpairing tears down one channel. It is a request/response pair with no
//! cryptographic content of its own: both messages ride the channel's existing
//! shared key, and the decision to honour a request is the responder's.
//!
//! The two sides are deliberately asymmetric. Only an Owner may initiate;
//! a Helper cannot dissolve the relationship from the protocol layer and may
//! only refuse an inbound request with a non-`Ok` status.
//!
//! Whether the initiator waits for that response is a local policy, not a wire
//! concern — see
//! [`UnpairAck`](crate::protocol::UnpairAck). Under `NotRequired` the
//! initiator drops its state as soon as the request is sent, which means a
//! late response arrives at a channel whose keys are already gone; the
//! orchestrator treats that as an ordinary no-op rather than an error.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
