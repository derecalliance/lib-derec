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
        version: u32,
    },
    ShareConfirmed {
        channel_id: String,
        version: u32,
    },
    ShareRejected {
        channel_id: String,
        version: u32,
        status: i32,
        memo: String,
    },
    SharingComplete {
        version: u32,
        confirmed_count: usize,
        failed_count: usize,
        threshold_met: bool,
    },
    ShareVerified {
        channel_id: String,
        version: u32,
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
    Unpaired {
        channel_id: String,
    },
    UnpairRejected {
        channel_id: String,
        status: i32,
        memo: String,
    },
    /// The contact creator answered our `PrePairRequest` with a non-Ok
    /// status (scanner side, `HashedKeys` flow). Distinct from a
    /// cryptographic hash mismatch, which surfaces as an `Err` from
    /// `process()` rather than as an event.
    PrePairRejected {
        channel_id: String,
        status: i32,
        memo: String,
    },
    ChannelInfoUpdated {
        channel_id: String,
        /// New communication info, if the update carried it (only populated
        /// on the responder side after `accept`).
        #[serde(skip_serializing_if = "Option::is_none")]
        communication_info: Option<HashMap<String, String>>,
        /// New transport URI, if the update carried it (only populated on
        /// the responder side after `accept`).
        #[serde(skip_serializing_if = "Option::is_none")]
        transport_uri: Option<String>,
        /// New transport protocol (i32 of `Protocol` enum) accompanying
        /// `transport_uri`.
        #[serde(skip_serializing_if = "Option::is_none")]
        transport_protocol: Option<i32>,
    },
    ChannelInfoUpdateRejected {
        channel_id: String,
        status: i32,
        memo: String,
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
        /// For Pairing actions: the sender_kind from the incoming PairRequestMessage.
        /// Mirrors the `kind` field on PairingCompleted so callers can distinguish
        /// Owner, Helper, Replica, etc.
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_kind: Option<u32>,
        /// For StoreShare actions: the share version number.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<u32>,
        /// For StoreShare actions: human-readable description of the secret version.
        #[serde(skip_serializing_if = "Option::is_none")]
        share_description: Option<String>,
        /// For StoreShare/VerifyShare actions: the secret identifier (u64) as a
        /// decimal string. A string (not a JS number) because a u64 can exceed
        /// `Number.MAX_SAFE_INTEGER`; mirrors the share-store JS convention.
        #[serde(skip_serializing_if = "Option::is_none")]
        share_secret_id: Option<String>,
    },
    NoOp,
}

#[derive(serde::Serialize)]
struct SecretVersionEntryJs {
    /// Secret identifier (u64) as a decimal string — see `share_secret_id`.
    secret_id: String,
    versions: Vec<VersionEntryJs>,
}

#[derive(serde::Serialize)]
struct VersionEntryJs {
    version: u32,
    description: String,
}

/// Extract `peer_communication_info` from a `PendingAction::Pairing`, or empty map otherwise.
fn extract_peer_communication_info(action: &PendingAction) -> HashMap<String, String> {
    match action {
        PendingAction::Pairing { peer_communication_info, .. } => peer_communication_info.clone(),
        _ => HashMap::new(),
    }
}

/// Returns the `sender_kind` from the incoming `PairRequestMessage` for Pairing actions,
/// or `None` for all other action types.
fn extract_pairing_sender_kind(action: &PendingAction) -> Option<u32> {
    match action {
        PendingAction::Pairing { request, .. } => Some(request.sender_kind as u32),
        _ => None,
    }
}

/// Extract share version and description from a `PendingAction::StoreShare`, or `(None, None)` otherwise.
fn extract_share_metadata(action: &PendingAction) -> (Option<u32>, Option<String>, Option<String>) {
    match action {
        PendingAction::StoreShare { request, .. } => {
            let desc = if request.version_description.is_empty() {
                None
            } else {
                Some(request.version_description.to_owned())
            };
            (Some(request.version), desc, Some(request.secret_id.to_string()))
        }
        PendingAction::VerifyShare { request, .. } => {
            (Some(request.version), None, Some(request.secret_id.to_string()))
        }
        _ => (None, None, None),
    }
}

/// Returns a human-readable tag for the PendingAction variant.
fn action_kind_label(action: &PendingAction) -> &'static str {
    match action {
        PendingAction::Pairing { .. } => "Pairing",
        PendingAction::PrePair { .. } => "PrePair",
        PendingAction::StoreShare { .. } => "StoreShare",
        PendingAction::VerifyShare { .. } => "VerifyShare",
        PendingAction::Discovery { .. } => "Discovery",
        PendingAction::GetShare { .. } => "GetShare",
        PendingAction::Unpair { .. } => "Unpair",
        PendingAction::UpdateChannelInfo { .. } => "UpdateChannelInfo",
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
        DeRecEvent::ShareRejected { channel_id, version, status, memo } => DeRecEventJs::ShareRejected {
            channel_id: channel_id.0.to_string(),
            version,
            status,
            memo,
        },
        DeRecEvent::SharingComplete { version, confirmed_count, failed_count, threshold_met } => DeRecEventJs::SharingComplete {
            version,
            confirmed_count,
            failed_count,
            threshold_met,
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
                    secret_id: e.secret_id.to_string(),
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
        DeRecEvent::Unpaired { channel_id } => DeRecEventJs::Unpaired {
            channel_id: channel_id.0.to_string(),
        },
        DeRecEvent::PrePairRejected { channel_id, status, memo } => DeRecEventJs::PrePairRejected {
            channel_id: channel_id.0.to_string(),
            status,
            memo,
        },
        DeRecEvent::UnpairRejected { channel_id, status, memo } => DeRecEventJs::UnpairRejected {
            channel_id: channel_id.0.to_string(),
            status,
            memo,
        },
        DeRecEvent::ChannelInfoUpdated {
            channel_id,
            communication_info,
            transport_protocol,
        } => {
            let (transport_uri, transport_protocol_i32) = match transport_protocol {
                Some(tp) => (Some(tp.uri), Some(tp.protocol)),
                None => (None, None),
            };
            DeRecEventJs::ChannelInfoUpdated {
                channel_id: channel_id.0.to_string(),
                communication_info,
                transport_uri,
                transport_protocol: transport_protocol_i32,
            }
        }
        DeRecEvent::ChannelInfoUpdateRejected { channel_id, status, memo } => {
            DeRecEventJs::ChannelInfoUpdateRejected {
                channel_id: channel_id.0.to_string(),
                status,
                memo,
            }
        }
        DeRecEvent::ActionRequired { channel_id, action } => {
            let kind = action_kind_label(&action).to_owned();
            let peer_communication_info = extract_peer_communication_info(&action);
            let sender_kind = extract_pairing_sender_kind(&action);
            let (version, share_description, share_secret_id) = extract_share_metadata(&action);
            let action_bytes = pending_action_wire::serialize(action)
                .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e))?;
            DeRecEventJs::ActionRequired {
                channel_id: channel_id.0.to_string(),
                action: action_bytes,
                action_kind: kind,
                peer_communication_info,
                sender_kind,
                version,
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
