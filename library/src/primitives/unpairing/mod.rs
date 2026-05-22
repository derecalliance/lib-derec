// SPDX-License-Identifier: Apache-2.0

//! # DeRec unpairing flow primitive
//!
//! Terminates a previously paired channel. Either party (Owner or Helper) may
//! initiate this flow; the counter-party is expected to delete any state it
//! holds for the channel (shared key, contact records, stored shares, …) and
//! send back a confirmation envelope.
//!
//! ## Wire shape
//!
//! Both messages are inner protobufs encrypted with the already-established
//! channel `shared_key`, wrapped in the standard outer
//! [`derec_proto::DeRecMessage`] envelope:
//!
//! | Direction         | Inner protobuf                              |
//! |-------------------|---------------------------------------------|
//! | initiator → peer  | [`derec_proto::UnpairRequestMessage`]       |
//! | peer → initiator  | [`derec_proto::UnpairResponseMessage`]      |
//!
//! ## Authority over local state
//!
//! The primitive itself is purely transport — it produces and verifies the
//! envelopes. **Deleting** local state (channel record, shared key, share
//! entries) is the [`crate::protocol`] orchestrator's concern, driven by the
//! [`crate::protocol::events::DeRecFlow::Unpair`] flow and the
//! [`crate::protocol::DeRecProtocol::accept`] / `process` paths.
//!
//! ## Idempotency
//!
//! Per the wire spec (`unpair.proto`) repeated unpair requests SHOULD produce
//! consistent results. The primitive is stateless, so callers can re-invoke
//! [`request::produce`] / [`response::produce`] freely.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
