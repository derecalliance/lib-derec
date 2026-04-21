// SPDX-License-Identifier: Apache-2.0

//! # Discovery primitive
//!
//! This module implements the DeRec **discovery** flow, which allows a recovering
//! Owner to ask each Helper which secret IDs and share versions it currently holds
//! for that Owner.
//!
//! ## Overview
//!
//! During recovery an Owner may have lost all local state and therefore cannot know
//! which secrets each Helper stores. The discovery flow solves this by providing a
//! single request/response exchange that the Owner executes against each Helper
//! immediately after re-pairing in recovery mode:
//!
//! ```text
//! Owner                               Helper
//!   │                                   │
//!   │── GetSecretIdsVersionsRequest ────▶│
//!   │                                   │  enumerate stored (secret_id, versions)
//!   │◀─ GetSecretIdsVersionsResponse ───│
//!   │                                   │
//! parse secret list                     │
//! decide which secret to recover        │
//! ```
//!
//! ## Entry points
//!
//! | Side   | Function                  | Purpose                                        |
//! |--------|---------------------------|------------------------------------------------|
//! | Owner  | [`request::produce`]      | Build the encrypted discovery request envelope |
//! | Helper | [`request::extract`]      | Decrypt and decode the discovery request       |
//! | Helper | [`response::produce`]     | Build the encrypted discovery response         |
//! | Owner  | [`response::extract`]     | Decrypt and decode the discovery response      |
//! | Owner  | [`response::process`]     | Validate the response and obtain the secret list |
//!
//! ## Security
//!
//! The request contains no secret material — it is only a timestamped signal.
//! The response reveals metadata (secret IDs and version numbers) about secrets
//! stored on the Helper. Both messages are encrypted with the channel shared key
//! established during pairing. Helpers must authenticate the requester before
//! processing this flow.

mod error;
pub use error::*;

pub mod request;
pub mod response;

#[cfg(test)]
mod tests;
