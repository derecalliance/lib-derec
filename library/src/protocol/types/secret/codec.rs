// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::versions;
use crate::protocol::types::Secret;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    #[error("empty encoded secret")]
    Empty,
    #[error("unsupported secret encoding version: {0}")]
    UnsupportedVersion(u8),
    #[error("failed to decompress the encoded secret")]
    Decompression,
    #[error("malformed encoded secret")]
    Json(#[from] serde_json::Error),
}

pub fn encode(secret: &Secret) -> Vec<u8> {
    let payload = versions::encode(secret);
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.push(versions::LATEST);
    out.extend_from_slice(&payload);
    out
}

pub fn decode(bytes: &[u8]) -> Result<Secret, SecretError> {
    let (&major, payload) = bytes.split_first().ok_or(SecretError::Empty)?;
    versions::decode(major, payload)
}
