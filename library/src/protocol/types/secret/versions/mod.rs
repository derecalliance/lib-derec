// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod v1;

use super::codec::SecretError;
use crate::protocol::types::Secret;

/// Latest encoding major version, used for all new encodes. Bump only on a
/// breaking format change, adding the matching `vN` module and match arm.
pub const LATEST: u8 = 1;

/// Encode a payload (no version prefix) with the latest version's format.
pub fn encode(secret: &Secret) -> Vec<u8> {
    v1::encode(secret)
}

/// Decode a payload (no version prefix) previously produced by major `major`.
pub fn decode(major: u8, payload: &[u8]) -> Result<Secret, SecretError> {
    match major {
        1 => v1::decode(payload),
        other => Err(SecretError::UnsupportedVersion(other)),
    }
}
