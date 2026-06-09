// SPDX-License-Identifier: Apache-2.0

use crate::primitives::{
    discovery::DiscoveryError, pairing::PairingError, recovery::RecoveryError,
    sharing::SharingError, unpairing::UnpairingError, verification::VerificationError,
};
use serde::Serialize;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize)]
struct TsError {
    category: &'static str,
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    got: Option<u32>,
}

pub(crate) fn js_error(code: &'static str, message: impl Into<String>) -> JsValue {
    let payload = TsError {
        category: "wasm",
        code,
        message: message.into(),
        status: None,
        memo: None,
        expected: None,
        got: None,
    };
    serde_wasm_bindgen::to_value(&payload)
        .unwrap_or_else(|_| JsValue::from_str("failed to serialize error"))
}

pub(crate) fn js_error_from_lib(err: crate::Error) -> JsValue {
    let (category, code) = categorize(&err);
    let message = err.to_string();
    let (status, memo) = err
        .as_non_ok_status()
        .map(|(s, m)| (Some(s), Some(m.to_owned())))
        .unwrap_or((None, None));
    let (expected, got) = match &err {
        crate::Error::Sharing(SharingError::VersionMismatch { expected, got })
        | crate::Error::Recovery(RecoveryError::VersionMismatch { expected, got }) => {
            (Some(*expected), Some(*got))
        }
        _ => (None, None),
    };
    let payload = TsError {
        category,
        code,
        message,
        status,
        memo,
        expected,
        got,
    };
    serde_wasm_bindgen::to_value(&payload)
        .unwrap_or_else(|_| JsValue::from_str("failed to serialize error"))
}

fn categorize(err: &crate::Error) -> (&'static str, &'static str) {
    match err {
        crate::Error::Pairing(e) => ("pairing", pairing_code(e)),
        crate::Error::Recovery(e) => ("recovery", recovery_code(e)),
        crate::Error::Discovery(e) => ("discovery", discovery_code(e)),
        crate::Error::Sharing(e) => ("sharing", sharing_code(e)),
        crate::Error::Verification(e) => ("verification", verification_code(e)),
        crate::Error::Unpairing(e) => ("unpairing", unpairing_code(e)),
        crate::Error::DeRecMessage(_) => ("derec_message", "BUILDER_ERROR"),
        crate::Error::SecretStore(e) => match e {
            crate::protocol::SecretStoreError::MissingEntries {
                kind: crate::protocol::SecretKind::SharedKey,
                ..
            } => ("secret_store", "MISSING_SHARED_KEY"),
            _ => ("secret_store", "STORE_ERROR"),
        },
        crate::Error::ChannelStore(_) => ("channel_store", "STORE_ERROR"),
        crate::Error::ShareStore(_) => ("share_store", "STORE_ERROR"),
        crate::Error::InvalidInput(_) => ("input", "INVALID_INPUT"),
        crate::Error::ProtobufDecode(_) => ("protobuf", "DECODE_ERROR"),
        crate::Error::ProtobufEncode(_) => ("protobuf", "ENCODE_ERROR"),
        crate::Error::Invariant(_) => ("invariant", "INVARIANT_VIOLATED"),
        crate::Error::RoleMismatch { .. } => ("input", "ROLE_MISMATCH"),
        crate::Error::ReplicaIdNotConfigured => ("input", "REPLICA_ID_NOT_CONFIGURED"),
    }
}

fn pairing_code(e: &PairingError) -> &'static str {
    match e {
        PairingError::EmptyTransportUri => "EMPTY_TRANSPORT_URI",
        PairingError::InvalidContactMessage(_) => "INVALID_CONTACT_MESSAGE",
        PairingError::InvalidPairRequestMessage(_) => "INVALID_PAIR_REQUEST_MESSAGE",
        PairingError::InvalidPairResponseMessage(_) => "INVALID_PAIR_RESPONSE_MESSAGE",
        PairingError::NonOkStatus { .. } => "NON_OK_STATUS",
        PairingError::ProtocolViolation(_) => "PROTOCOL_VIOLATION",
        PairingError::PrePairHashMismatch => "PREPAIR_HASH_MISMATCH",
        PairingError::MissingReplicaId { .. } => "MISSING_REPLICA_ID",
        PairingError::UnexpectedReplicaId { .. } => "UNEXPECTED_REPLICA_ID",
        PairingError::Invariant(_) => "INVARIANT",
        PairingError::ContactMessageKeygen { .. } => "CONTACT_MESSAGE_KEYGEN",
        PairingError::PairRequestKeygen { .. } => "PAIR_REQUEST_KEYGEN",
        PairingError::FinishPairingInitiator { .. } => "FINISH_PAIRING_INITIATOR",
        PairingError::FinishPairingResponder { .. } => "FINISH_PAIRING_RESPONDER",
        PairingError::PairingEncryption(_) => "PAIRING_ENCRYPTION",
    }
}

fn recovery_code(e: &RecoveryError) -> &'static str {
    match e {
        RecoveryError::EmptyResponses => "EMPTY_RESPONSES",
        RecoveryError::NonOkStatus { .. } => "NON_OK_STATUS",
        RecoveryError::EmptyCommittedDeRecShare => "EMPTY_COMMITTED_DEREC_SHARE",
        RecoveryError::DecodeCommittedDeRecShare { .. } => "DECODE_COMMITTED_DEREC_SHARE",
        RecoveryError::DecodeDeRecShare { .. } => "DECODE_DEREC_SHARE",
        RecoveryError::SecretIdMismatch => "SECRET_ID_MISMATCH",
        RecoveryError::VersionMismatch { .. } => "VERSION_MISMATCH",
        RecoveryError::ReconstructionFailed { .. } => "RECONSTRUCTION_FAILED",
    }
}

fn discovery_code(e: &DiscoveryError) -> &'static str {
    match e {
        DiscoveryError::NonOkStatus { .. } => "NON_OK_STATUS",
    }
}

fn sharing_code(e: &SharingError) -> &'static str {
    match e {
        SharingError::EmptyChannels => "EMPTY_CHANNELS",
        SharingError::DuplicateChannelId(_) => "DUPLICATE_CHANNEL_ID",
        SharingError::InvalidThreshold { .. } => "INVALID_THRESHOLD",
        SharingError::EmptySecretData => "EMPTY_SECRET_DATA",
        SharingError::VssShareFailed { .. } => "VSS_SHARE_FAILED",
        SharingError::NonOkStatus { .. } => "NON_OK_STATUS",
        SharingError::VersionMismatch { .. } => "VERSION_MISMATCH",
    }
}

fn verification_code(e: &VerificationError) -> &'static str {
    match e {
        VerificationError::NonOkStatus { .. } => "NON_OK_STATUS",
    }
}

fn unpairing_code(e: &UnpairingError) -> &'static str {
    match e {
        UnpairingError::NonOkStatus { .. } => "NON_OK_STATUS",
    }
}

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}
