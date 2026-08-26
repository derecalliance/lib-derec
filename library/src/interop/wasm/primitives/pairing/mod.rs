// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

pub mod request;
pub mod response;

use crate::interop::wasm::ts_bindings_utils::js_error;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::SenderKind;
use wasm_bindgen::prelude::*;

/// Shared with the C FFI boundary — see [`crate::interop::dto`], which
/// owns every definition below so the two SDK families cannot drift.
pub use crate::interop::dto::{
    CommunicationInfo, CommunicationInfoKeyValue, ContactMessage, PairRequestMessage,
    PairResponseMessage, ParameterRange, PrePairRequestMessage, PrePairResponseMessage,
    TransportProtocol,
};

pub(super) fn serialize_pairing_secret_key_material(
    sk: &PairingSecretKeyMaterial,
) -> Result<Vec<u8>, JsValue> {
    let mut buf = Vec::new();
    sk.serialize_uncompressed(&mut buf)
        .map_err(|e| js_error("SERIALIZATION_ERROR", format!("{e:?}")))?;
    Ok(buf)
}

pub(super) fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, JsValue> {
    PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..])
        .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))
}

pub(super) fn get_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!(
                "invalid sender kind: {kind}, valid values are 0 (Owner), 1 (Helper), 3 (ReplicaSource), 4 (ReplicaDestination)"
            ),
        )),
    }
}
