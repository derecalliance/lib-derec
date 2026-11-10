// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use std::time::Duration;

use derec_proto::DeRecMessage;

/// Questions answered by reading an envelope's plaintext header.
pub(crate) trait DeRecMessageExt {
    /// Whether the envelope's timestamp is more than `max_age` before `now`
    /// (seconds since the Unix epoch). The boundary itself is not expired.
    ///
    /// An envelope without a timestamp is not expired: the timestamp
    /// invariant is enforced after decryption, and reading absence as stale
    /// here would hide that failure behind an ignore.
    fn is_expired(&self, now: u64, max_age: Duration) -> bool;
}

impl DeRecMessageExt for DeRecMessage {
    fn is_expired(&self, now: u64, max_age: Duration) -> bool {
        let Some(timestamp) = &self.timestamp else {
            return false;
        };
        now.saturating_sub(timestamp.seconds as u64) > max_age.as_secs()
    }
}

#[cfg(test)]
mod tests;
