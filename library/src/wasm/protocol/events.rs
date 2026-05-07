// SPDX-License-Identifier: Apache-2.0

//! Converts [`DeRecEvent`] values to plain JS objects for TypeScript consumers.

use std::collections::HashMap;

use serde::Serialize;

use crate::protocol::{DeRecEvent, PendingAction};
use crate::wasm::ts_bindings_utils::js_error;
use wasm_bindgen::JsValue;

use super::pending_action_wire;

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum DeRecEventJs {
    PairingCompleted {
        channel_id: String,
        kind: u32,
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        peer_communication_info: HashMap<String, String>,
    },
    ShareStored {
        channel_id: String,
        version: i32,
    },
    ShareConfirmed {
        channel_id: String,
        version: i32,
    },
    ShareVerified {
        channel_id: String,
        version: i32,
    },
    SecretsDiscovered {
        channel_id: String,
        secrets: Vec<SecretVersionEntryJs>,
    },
    RecoveryShareReceived {
        channel_id: String,
        shares_received: usize,
    },
    RecoveryShareError {
        channel_id: String,
        shares_received: usize,
        error: String,
    },
    SecretRecovered {
        secret: Vec<u8>,
    },
    ActionRequired {
        channel_id: String,
        /// Opaque serialized PendingAction — pass back to accept() or reject().
        action: Vec<u8>,
        /// Human-readable tag: "Pairing", "StoreShare", "VerifyShare", "Discovery", "GetShare".
        action_kind: String,
        /// For Pairing actions: key-value pairs from the peer's CommunicationInfo.
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        peer_communication_info: HashMap<String, String>,
        /// For StoreShare actions: the share version number.
        #[serde(skip_serializing_if = "Option::is_none")]
        share_version: Option<i32>,
        /// For StoreShare actions: human-readable description of the secret version.
        #[serde(skip_serializing_if = "Option::is_none")]
        share_description: Option<String>,
        /// For StoreShare actions: the secret identifier (opaque bytes).
        #[serde(skip_serializing_if = "Option::is_none")]
        share_secret_id: Option<Vec<u8>>,
    },
    NoOp,
}

#[derive(serde::Serialize)]
struct SecretVersionEntryJs {
    secret_id: Vec<u8>,
    versions: Vec<VersionEntryJs>,
}

#[derive(serde::Serialize)]
struct VersionEntryJs {
    version: i32,
    description: String,
}

/// Extract `peer_communication_info` from a `PendingAction::Pairing`, or empty map otherwise.
fn extract_peer_communication_info(action: &PendingAction) -> HashMap<String, String> {
    match action {
        PendingAction::Pairing { peer_communication_info, .. } => peer_communication_info.clone(),
        _ => HashMap::new(),
    }
}

/// Extract share version and description from a `PendingAction::StoreShare`, or `(None, None)` otherwise.
fn extract_share_metadata(action: &PendingAction) -> (Option<i32>, Option<String>, Option<Vec<u8>>) {
    match action {
        PendingAction::StoreShare { request, .. } => {
            let desc = if request.version_description.is_empty() {
                None
            } else {
                Some(request.version_description.clone())
            };
            let secret_id = if request.secret_id.is_empty() {
                None
            } else {
                Some(request.secret_id.clone())
            };
            (Some(request.version), desc, secret_id)
        }
        _ => (None, None, None),
    }
}

/// Returns a human-readable tag for the PendingAction variant.
fn action_kind_label(action: &PendingAction) -> &'static str {
    match action {
        PendingAction::Pairing { .. } => "Pairing",
        PendingAction::StoreShare { .. } => "StoreShare",
        PendingAction::VerifyShare { .. } => "VerifyShare",
        PendingAction::Discovery { .. } => "Discovery",
        PendingAction::GetShare { .. } => "GetShare",
    }
}

pub fn event_to_js(event: DeRecEvent) -> Result<JsValue, JsValue> {
    let js_event = match event {
        DeRecEvent::PairingCompleted { channel_id, kind, peer_communication_info } => DeRecEventJs::PairingCompleted {
            channel_id: channel_id.0.to_string(),
            kind: kind as u32,
            peer_communication_info,
        },
        DeRecEvent::ShareStored { channel_id, version } => DeRecEventJs::ShareStored {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::ShareConfirmed { channel_id, version } => DeRecEventJs::ShareConfirmed {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::ShareVerified { channel_id, version } => DeRecEventJs::ShareVerified {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::SecretsDiscovered { channel_id, secrets } => DeRecEventJs::SecretsDiscovered {
            channel_id: channel_id.0.to_string(),
            secrets: secrets
                .into_iter()
                .map(|e| SecretVersionEntryJs {
                    secret_id: e.secret_id,
                    versions: e
                        .versions
                        .into_iter()
                        .map(|v| VersionEntryJs {
                            version: v.version,
                            description: v.description,
                        })
                        .collect(),
                })
                .collect(),
        },
        DeRecEvent::RecoveryShareReceived { channel_id, shares_received } => {
            DeRecEventJs::RecoveryShareReceived {
                channel_id: channel_id.0.to_string(),
                shares_received,
            }
        }
        DeRecEvent::RecoveryShareError { channel_id, shares_received, error } => {
            DeRecEventJs::RecoveryShareError {
                channel_id: channel_id.0.to_string(),
                shares_received,
                error,
            }
        }
        DeRecEvent::SecretRecovered { secret } => DeRecEventJs::SecretRecovered { secret },
        DeRecEvent::ActionRequired { channel_id, action } => {
            let kind = action_kind_label(&action).to_owned();
            let peer_communication_info = extract_peer_communication_info(&action);
            let (share_version, share_description, share_secret_id) = extract_share_metadata(&action);
            let action_bytes = pending_action_wire::serialize(action)
                .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e))?;
            DeRecEventJs::ActionRequired {
                channel_id: channel_id.0.to_string(),
                action: action_bytes,
                action_kind: kind,
                peer_communication_info,
                share_version,
                share_description,
                share_secret_id,
            }
        }
        DeRecEvent::NoOp => DeRecEventJs::NoOp,
        // `#[non_exhaustive]` — future variants become NoOp so bindings don't break.
        #[allow(unreachable_patterns)]
        _ => DeRecEventJs::NoOp,
    };
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    js_event.serialize(&serializer)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
