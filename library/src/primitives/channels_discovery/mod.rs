// SPDX-License-Identifier: Apache-2.0

//! # Channels Discovery primitive
//!
//! This module implements the DeRec **channels discovery** flow, which allows a
//! newly confirmed Replica to learn about all existing Helper channels that the
//! Owner has established.
//!
//! ## Overview
//!
//! After an Owner and a Replica complete the confirmation flow, the Replica has
//! a shared key with the Owner but knows nothing about existing Helper channels.
//! The channels discovery flow synchronises this state by transferring channel
//! identifiers and their shared keys from the Owner to the Replica.
//!
//! ```text
//! Replica                               Owner
//!   │                                     │
//!   │── ChannelsDiscoveryRequest ────────▶│  (lastBatchIndex=0)
//!   │                                     │  enumerate channels
//!   │◀─ ChannelsDiscoveryResponse ───────│  (batch 1 of N)
//!   │                                     │
//!   │── ChannelsDiscoveryRequest ────────▶│  (lastBatchIndex=1)
//!   │◀─ ChannelsDiscoveryResponse ───────│  (batch 2 of N)
//!   │         ...                         │
//! ```
//!
//! ## Entry points
//!
//! | Side    | Function                  | Purpose                                           |
//! |---------|---------------------------|---------------------------------------------------|
//! | Replica | [`request::produce`]      | Build the encrypted discovery request envelope    |
//! | Owner   | [`request::extract`]      | Decrypt and decode the discovery request          |
//! | Owner   | [`response::produce`]     | Build the encrypted discovery response            |
//! | Replica | [`response::extract`]     | Decrypt and decode the discovery response         |
//! | Replica | [`response::process`]     | Validate the response and obtain channel entries  |
//!
//! ## Security
//!
//! The response carries shared keys for all Helper channels. Both messages are
//! encrypted with the Owner↔Replica shared key established during pairing. The
//! shared keys within each entry are therefore protected by the channel
//! encryption layer.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
