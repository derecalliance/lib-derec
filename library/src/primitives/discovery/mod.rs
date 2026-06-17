// SPDX-License-Identifier: Apache-2.0

//! Discovery flow primitives.
//!
//! Discovery lets an Owner ask a paired Helper to enumerate which
//! `(secret_id, version)` tuples it currently holds. The request body
//! is empty save for a timestamp; the response carries the catalog the
//! Owner uses to reconcile its view with what the Helper still stores.
//!
//! Commonly the precursor an Owner uses to drive [`super::recovery`] —
//! after re-pairing in recovery mode, the Owner has no local record of
//! prior shares and discovers what's recoverable by asking each Helper
//! first — but the flow is general-purpose: any time an Owner wants to
//! confirm a Helper's vault inventory it can issue a discovery request.
//!
//! # Submodules
//!
//! - [`request`] — Owner-side: produce a discovery request envelope;
//!   Helper-side: extract the inbound request and surface it for
//!   accept/reject.
//! - [`response`] — Helper-side: produce a discovery response envelope
//!   carrying the catalog; Owner-side: extract the response and
//!   process it into a typed
//!   [`response::SecretVersionEntry`] list.
//!
//! # Layer choice
//!
//! Most applications drive discovery via the orchestrator
//! ([`crate::protocol::DeRecProtocol::start`] with
//! [`crate::protocol::events::DeRecFlow::Discovery`]) — the protocol
//! owns the request/response routing and surfaces a
//! [`crate::protocol::events::DeRecEvent::SecretsDiscovered`] event on
//! completion. The primitives here are the layer beneath that surface;
//! SDK authors or stateless integrations driving the wire bytes
//! directly use them. Both layers share the same on-wire schema and
//! the same `(secret_id, version)` semantics.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
