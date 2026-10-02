// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod error;
pub use error::*;

pub(crate) mod parameter_range;
pub mod request;
pub mod response;

#[cfg(test)]
mod tests;

/// The human-readable fingerprint of the shared key a pairing established.
///
/// Both ends derive the same value from the same key, so comparing it out of
/// band confirms nobody sat between them during the exchange. A
/// [`ContactMode::NoKeys`](derec_proto::ContactMode::NoKeys) pairing MUST be confirmed this way before the
/// channel is used: nothing else binds the keys it exchanged to the contact.
pub fn fingerprint(shared_key: &crate::types::SharedKey) -> String {
    derec_cryptography::replica::fingerprint(shared_key)
}
