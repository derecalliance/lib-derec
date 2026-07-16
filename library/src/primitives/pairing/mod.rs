// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod error;
pub use error::*;

pub mod parameter_range;
pub mod request;
pub mod response;

#[cfg(test)]
mod tests;

use crate::utils::ContactMessageExt as _;
use derec_proto::{ContactMessage, ContactMode};

/// Asserts the contact is structurally valid AND its declared
/// `contact_mode` matches the mode the calling flow expects. Used at every
/// orchestrator entry point that ingests a contact:
///
/// - [`request::produce`] requires [`ContactMode::InlineKeys`] (the
///   responder needs the keys inline).
/// - [`request::produce_pre_pair_request`] and
///   [`response::process_pre_pair`] require [`ContactMode::HashedKeys`]
///   (the keys must be fetched via PrePair).
/// - [`response::process_pre_pair_no_keys`] requires
///   [`ContactMode::NoKeys`] (no key material and no commitment;
///   OOB-trust-only).
///
/// Visible only inside the `primitives::pairing` module —
/// `pub(super)` limits it to `request.rs`, `response.rs`, and this file.
pub(super) fn validate_contact_for_mode(
    contact: &ContactMessage,
    expected: ContactMode,
) -> Result<(), crate::Error> {
    if contact.contact_mode != expected as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(
            contact_mode = contact.contact_mode,
            expected = expected as i32,
            "contact_mode mismatch"
        );

        return Err(PairingError::InvalidContactMessage(match expected {
            ContactMode::InlineKeys => "expected INLINE_KEYS contact mode",
            ContactMode::HashedKeys => "expected HASHED_KEYS contact mode",
            ContactMode::NoKeys => "expected NO_KEYS contact mode",
        })
        .into());
    }

    contact.validate()
}
