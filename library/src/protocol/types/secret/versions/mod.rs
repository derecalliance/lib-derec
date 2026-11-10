// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

mod v2;
mod v3;

#[cfg(test)]
mod tests;

use std::io::{BufReader, Read};

use flate2::read::GzDecoder;
use serde::de::DeserializeOwned;

use super::codec::SecretError;
use crate::protocol::types::Secret;

/// Latest encoding major version, used for all new encodes. Bump only on a
/// breaking format change, adding the matching `vN` module and match arm.
pub const LATEST: u8 = 3;

/// Encode a payload (no version prefix) with the latest version's format.
pub fn encode(secret: &Secret) -> Vec<u8> {
    v3::encode(secret)
}

/// Decode a payload (no version prefix) previously produced by major `major`.
pub fn decode(major: u8, payload: &[u8]) -> Result<Secret, SecretError> {
    match major {
        3 => v3::decode(payload),
        // v2 stored one endpoint per peer as a bare URI. Still decoded, and
        // lifted into the current shape — an owner who protected a secret
        // before multi-endpoint support must still be able to recover it.
        2 => v2::decode(payload),
        // v1 is not decoded. A v1 roster cannot name its source member — it
        // carries no entry for the writer — so it cannot be upgraded
        // losslessly, and there is nothing to upgrade it for.
        other => Err(SecretError::UnsupportedVersion(other)),
    }
}

/// Parse the JSON inside a gzip payload while it is being inflated.
///
/// The payload is untrusted: recovery decrypts it from shares that nothing
/// authenticates, and the version byte that routed it here is part of it.
/// Parsing the stream means a payload that is not JSON is refused after its
/// first bytes, and padding around the JSON passes through without being
/// buffered. Memory then follows the largest single value in the JSON, which
/// is not bounded here: gzip lets a payload claim up to about 1030 times its
/// own size. See the module documentation.
fn decode_gzip_json<T: DeserializeOwned>(payload: &[u8]) -> Result<T, SecretError> {
    read_json(GzDecoder::new(payload))
}

/// Parse JSON from an inflating stream. A failure to read the stream is a
/// [`SecretError::Decompression`]; anything else wrong is [`SecretError::Json`].
fn read_json<T: DeserializeOwned>(json: impl Read) -> Result<T, SecretError> {
    serde_json::from_reader(BufReader::new(json)).map_err(|error| {
        if error.is_io() {
            SecretError::Decompression
        } else {
            SecretError::Json(error)
        }
    })
}
