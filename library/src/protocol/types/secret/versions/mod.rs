// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod v2;

use super::codec::SecretError;
use crate::protocol::types::Secret;

/// Latest encoding major version, used for all new encodes. Bump only on a
/// breaking format change, adding the matching `vN` module and match arm.
pub const LATEST: u8 = 2;

/// Encode a payload (no version prefix) with the latest version's format.
pub fn encode(secret: &Secret) -> Vec<u8> {
    v2::encode(secret)
}

/// Decode a payload (no version prefix) previously produced by major `major`.
pub fn decode(major: u8, payload: &[u8]) -> Result<Secret, SecretError> {
    match major {
        2 => v2::decode(payload),
        // v1 is not decoded. A v1 roster cannot name its source member — it
        // carries no entry for the writer — so it cannot be upgraded
        // losslessly, and there is nothing to upgrade it for.
        other => Err(SecretError::UnsupportedVersion(other)),
    }
}
