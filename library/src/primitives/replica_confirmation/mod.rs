// SPDX-License-Identifier: Apache-2.0

//! # Replica Confirmation primitive
//!
//! This module implements the DeRec **replica confirmation** flow, which
//! establishes trust between an Owner and a newly paired Replica device.
//!
//! ## Overview
//!
//! After an Owner and a Replica complete the pairing handshake (using
//! `SenderKind::Replica`), the channel is in an unconfirmed state. Before
//! the Replica can synchronise channels or secrets, both parties must
//! verify they share the same key by comparing a fingerprint derived from
//! the shared key (similar to Bluetooth pairing).
//!
//! ```text
//! Owner / Replica A                   Replica B
//!   │                                   │
//!   │── ReplicaConfirmationRequest ────▶│  (fingerprint + replica_id)
//!   │                                   │  verify fingerprint
//!   │                                   │  display for user confirmation
//!   │◀─ ReplicaConfirmationResponse ───│  (result + replica_id)
//!   │                                   │
//! channel confirmed                   channel confirmed
//! ```
//!
//! ## Entry points
//!
//! | Side      | Function                     | Purpose                                           |
//! |-----------|------------------------------|---------------------------------------------------|
//! | Initiator | [`request::produce`]         | Build the encrypted confirmation request envelope |
//! | Receiver  | [`request::extract`]         | Decrypt and decode the confirmation request       |
//! | Receiver  | [`request::verify_fingerprint`] | Verify the fingerprint matches the shared key  |
//! | Receiver  | [`response::produce`]        | Build the encrypted confirmation response         |
//! | Initiator | [`response::extract`]        | Decrypt and decode the confirmation response      |
//! | Initiator | [`response::process`]        | Validate the response and obtain peer replica_id  |
//!
//! ## Security
//!
//! The fingerprint provides a human-verifiable binding to the shared key,
//! protecting against man-in-the-middle attacks during pairing. Both messages
//! are encrypted with the shared key established during pairing.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
