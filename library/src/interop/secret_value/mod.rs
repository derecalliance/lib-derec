// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading a secret an application's store handed back as raw bytes.
//!
//! A binding stores each [`SecretValue`] as its kind plus opaque bytes. Turning
//! those bytes back into the value happens here, once, for every binding.

use prost::Message as _;

use crate::protocol::{PairingKeyMaterial, SecretKind, SecretValue};

/// Decodes `bytes` as a value of `kind`. Bytes that are not a valid value of
/// that kind are refused rather than guessed at.
pub(crate) fn decode(kind: SecretKind, bytes: &[u8]) -> Result<SecretValue, String> {
    match kind {
        SecretKind::SharedKey => crate::types::SharedKey::try_from(bytes)
            .map(SecretValue::SharedKey)
            .map_err(|_| format!("shared key must be 32 bytes, got {}", bytes.len())),
        SecretKind::PairingSecret => Ok(SecretValue::PairingSecret(
            PairingKeyMaterial::from_bytes(bytes.to_vec()),
        )),
        SecretKind::PairingContact => derec_proto::ContactMessage::decode(bytes)
            .map(SecretValue::PairingContact)
            .map_err(|e| format!("failed to decode ContactMessage: {e}")),
        SecretKind::KeyRing => crate::protocol::KeyRing::from_bytes(bytes)
            .map(SecretValue::KeyRing)
            .map_err(|e| format!("failed to decode KeyRing: {e}")),
    }
}

#[cfg(test)]
mod tests;
