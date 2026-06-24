// SPDX-License-Identifier: Apache-2.0

//! Wire-shape mirror of [`super::DeRecEvent`] shared by the FFI and
//! WASM bridges. Internal — bridges import these types to drive
//! `serde_json` / `serde_wasm_bindgen`. The shape is not part of the
//! public Rust API and may change as the SDK wire formats evolve.
//!
//! Field-name conventions:
//! - All `u64` identifiers (`channel_id`, `secret_id`, `replica_id`,
//!   `from_replica_id`, `owner_replica_id`) cross the boundary as
//!   **decimal strings** to dodge JS `Number.MAX_SAFE_INTEGER` without
//!   forcing callers to track which id uses which encoding.
//! - `peer_communication_info` / `communication_info` are
//!   `#[serde(skip_serializing_if = "HashMap::is_empty")]` so callers
//!   never see noise from empty maps.
//! - Enum variants use serde's default tag (`#[serde(tag = "type")]`)
//!   with the Rust variant name as the discriminator value.

use std::collections::HashMap;

use serde::Serialize;

use crate::protocol::{
    pending_action_wire,
    reserved_keys::encode_replica_id,
    types::{ChannelShare, Secret},
    DeRecEvent, PendingAction,
};

/// Canonical wire-shape of [`super::DeRecEvent`]. Consumed by the FFI
/// and WASM bridges only. See module docs for the field conventions.
#[derive(Serialize)]
#[serde(tag = "type")]
pub(crate) enum Event {
    PairingCompleted {
        channel_id: String,
        kind: i32,
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        peer_communication_info: HashMap<String, String>,
    },
    ReplicaPaired {
        channel_id: String,
        peer_replica_id: String,
    },
    ReplicaSecretReceived {
        channel_id: String,
        from_replica_id: String,
        secret_id: String,
        version: u32,
        secret: SecretWire,
        shares: Vec<Share>,
    },
    ReplicaSecretAcked {
        channel_id: String,
        from_replica_id: String,
        secret_id: String,
        version: u32,
        status: i32,
        memo: String,
    },
    ShareStored {
        channel_id: String,
        version: u32,
        /// Decimal-encoded `replica_id` of the writer, or `None` for a
        /// non-replica `Owner`. Matches the proto's optional shape so
        /// JS/.NET callers receive `null` for the absent case.
        replica_id: Option<String>,
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
        confirmed_count: u32,
        failed_count: u32,
        threshold_met: bool,
    },
    ShareVerified {
        channel_id: String,
        version: u32,
    },
    SecretsDiscovered {
        channel_id: String,
        secrets: Vec<DiscoveredSecret>,
    },
    RecoveryShareReceived {
        channel_id: String,
        shares_received: u32,
    },
    RecoveryShareError {
        channel_id: String,
        shares_received: u32,
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
    PrePairRejected {
        channel_id: String,
        status: i32,
        memo: String,
    },
    ChannelInfoUpdated {
        channel_id: String,
    },
    ChannelInfoUpdateRejected {
        channel_id: String,
        status: i32,
        memo: String,
    },
    ActionRequired {
        channel_id: String,
        /// Opaque serialized [`PendingAction`] — pass back to
        /// `accept` / `reject` verbatim.
        action: Vec<u8>,
        /// Human-readable tag (e.g. `"Pairing"`, `"StoreShare"`) so JS
        /// callers can route on action kind without decoding `action`.
        action_kind: String,
        /// Populated for `PendingAction::Pairing`; empty otherwise.
        #[serde(skip_serializing_if = "HashMap::is_empty")]
        peer_communication_info: HashMap<String, String>,
        /// `sender_kind` from the inbound `PairRequestMessage` (Pairing
        /// only).
        #[serde(skip_serializing_if = "Option::is_none")]
        sender_kind: Option<i32>,
        /// Share version (StoreShare / VerifyShare only).
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<u32>,
        /// Description of the secret version (StoreShare only).
        #[serde(skip_serializing_if = "Option::is_none")]
        share_description: Option<String>,
        /// Secret identifier as decimal string (StoreShare / VerifyShare
        /// only).
        #[serde(skip_serializing_if = "Option::is_none")]
        share_secret_id: Option<String>,
    },
    AutoAccepted {
        channel_id: String,
        /// Same label vocabulary as `ActionRequired.action_kind`
        /// (`"Pairing"`, `"StoreShare"`, …) so JS/.NET listeners can
        /// route on a single string field.
        action_kind: String,
    },
    NoOp,
}

#[derive(Serialize)]
pub struct DiscoveredSecret {
    pub secret_id: String,
    pub versions: Vec<DiscoveredVersion>,
}

#[derive(Serialize)]
pub struct DiscoveredVersion {
    pub version: u32,
    pub description: String,
}

#[derive(Serialize)]
pub struct SecretWire {
    pub helpers: Vec<Helper>,
    pub secrets: Vec<UserSecret>,
    pub replicas: Vec<Replica>,
    pub owner_replica_id: String,
}

#[derive(Serialize)]
pub struct Helper {
    pub channel_id: String,
    pub transport_uri: String,
    pub shared_key: Vec<u8>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub communication_info: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct Replica {
    pub channel_id: String,
    pub transport_uri: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub communication_info: HashMap<String, String>,
    pub replica_id: String,
    pub sender_kind: i32,
}

#[derive(Serialize)]
pub struct UserSecret {
    pub id: Vec<u8>,
    pub name: String,
    pub data: Vec<u8>,
}

#[derive(Serialize)]
pub struct Share {
    pub channel_id: String,
    pub committed_share: Vec<u8>,
}

impl From<Secret> for SecretWire {
    fn from(v: Secret) -> Self {
        Self {
            helpers: v
                .helpers
                .into_iter()
                .map(|h| Helper {
                    channel_id: h.channel_id.to_string(),
                    transport_uri: h.transport_uri,
                    shared_key: h.shared_key,
                    communication_info: h.communication_info,
                })
                .collect(),
            secrets: v
                .secrets
                .into_iter()
                .map(|s| UserSecret {
                    id: s.id,
                    name: s.name,
                    data: s.data,
                })
                .collect(),
            replicas: v
                .replicas
                .into_iter()
                .map(|r| Replica {
                    channel_id: r.channel_id.to_string(),
                    transport_uri: r.transport_uri,
                    communication_info: r.communication_info,
                    replica_id: encode_replica_id(r.replica_id),
                    sender_kind: r.sender_kind,
                })
                .collect(),
            owner_replica_id: encode_replica_id(v.owner_replica_id),
        }
    }
}

impl From<ChannelShare> for Share {
    fn from(v: ChannelShare) -> Self {
        Self {
            channel_id: v.channel_id.to_string(),
            committed_share: v.committed_share,
        }
    }
}

impl Event {
    /// Map a [`DeRecEvent`] into its wire DTO. Returns `Err` only when
    /// [`pending_action_wire::serialize`] fails (`ActionRequired`); all
    /// other variants are infallible.
    pub fn from_event(event: DeRecEvent) -> Result<Self, String> {
        Ok(match event {
            DeRecEvent::PairingCompleted {
                channel_id,
                kind,
                peer_communication_info,
            } => Self::PairingCompleted {
                channel_id: channel_id.0.to_string(),
                kind: kind as i32,
                peer_communication_info,
            },
            DeRecEvent::ReplicaPaired {
                channel_id,
                peer_replica_id,
            } => Self::ReplicaPaired {
                channel_id: channel_id.0.to_string(),
                peer_replica_id: encode_replica_id(peer_replica_id),
            },
            DeRecEvent::ReplicaSecretReceived {
                channel_id,
                from_replica_id,
                secret_id,
                version,
                secret,
                shares,
            } => Self::ReplicaSecretReceived {
                channel_id: channel_id.0.to_string(),
                from_replica_id: encode_replica_id(from_replica_id),
                secret_id: secret_id.to_string(),
                version,
                secret: secret.into(),
                shares: shares.into_iter().map(Into::into).collect(),
            },
            DeRecEvent::ReplicaSecretAcked {
                channel_id,
                from_replica_id,
                secret_id,
                version,
                status,
                memo,
            } => Self::ReplicaSecretAcked {
                channel_id: channel_id.0.to_string(),
                from_replica_id: encode_replica_id(from_replica_id),
                secret_id: secret_id.to_string(),
                version,
                status,
                memo,
            },
            DeRecEvent::ShareStored {
                channel_id,
                version,
                replica_id,
            } => Self::ShareStored {
                channel_id: channel_id.0.to_string(),
                version,
                replica_id: replica_id.map(encode_replica_id),
            },
            DeRecEvent::ShareConfirmed { channel_id, version } => Self::ShareConfirmed {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::ShareRejected {
                channel_id,
                version,
                status,
                memo,
            } => Self::ShareRejected {
                channel_id: channel_id.0.to_string(),
                version,
                status,
                memo,
            },
            DeRecEvent::SharingComplete {
                version,
                confirmed_count,
                failed_count,
                threshold_met,
            } => Self::SharingComplete {
                version,
                confirmed_count: confirmed_count as u32,
                failed_count: failed_count as u32,
                threshold_met,
            },
            DeRecEvent::ShareVerified { channel_id, version } => Self::ShareVerified {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::SecretsDiscovered { channel_id, secrets } => Self::SecretsDiscovered {
                channel_id: channel_id.0.to_string(),
                secrets: secrets
                    .into_iter()
                    .map(|s| DiscoveredSecret {
                        secret_id: s.secret_id.to_string(),
                        versions: s
                            .versions
                            .into_iter()
                            .map(|v| DiscoveredVersion {
                                version: v.version,
                                description: v.description,
                            })
                            .collect(),
                    })
                    .collect(),
            },
            DeRecEvent::RecoveryShareReceived {
                channel_id,
                shares_received,
            } => Self::RecoveryShareReceived {
                channel_id: channel_id.0.to_string(),
                shares_received: shares_received as u32,
            },
            DeRecEvent::RecoveryShareError {
                channel_id,
                shares_received,
                error,
            } => Self::RecoveryShareError {
                channel_id: channel_id.0.to_string(),
                shares_received: shares_received as u32,
                error,
            },
            DeRecEvent::SecretRecovered { secret } => Self::SecretRecovered { secret },
            DeRecEvent::Unpaired { channel_id } => Self::Unpaired {
                channel_id: channel_id.0.to_string(),
            },
            DeRecEvent::UnpairRejected {
                channel_id,
                status,
                memo,
            } => Self::UnpairRejected {
                channel_id: channel_id.0.to_string(),
                status,
                memo,
            },
            DeRecEvent::PrePairRejected {
                channel_id,
                status,
                memo,
            } => Self::PrePairRejected {
                channel_id: channel_id.0.to_string(),
                status,
                memo,
            },
            DeRecEvent::ChannelInfoUpdated { channel_id } => Self::ChannelInfoUpdated {
                channel_id: channel_id.0.to_string(),
            },
            DeRecEvent::ChannelInfoUpdateRejected {
                channel_id,
                status,
                memo,
            } => Self::ChannelInfoUpdateRejected {
                channel_id: channel_id.0.to_string(),
                status,
                memo,
            },
            DeRecEvent::AutoAccepted {
                channel_id,
                action_kind,
            } => Self::AutoAccepted {
                channel_id: channel_id.0.to_string(),
                action_kind: pending_action_kind_label(action_kind).to_owned(),
            },
            DeRecEvent::ActionRequired { channel_id, action } => {
                let action_kind = action_kind_label(&action).to_owned();
                let peer_communication_info = extract_peer_communication_info(&action);
                let sender_kind = extract_pairing_sender_kind(&action);
                let (version, share_description, share_secret_id) =
                    extract_share_metadata(&action);
                let action_bytes = pending_action_wire::serialize(action)?;
                Self::ActionRequired {
                    channel_id: channel_id.0.to_string(),
                    action: action_bytes,
                    action_kind,
                    peer_communication_info,
                    sender_kind,
                    version,
                    share_description,
                    share_secret_id,
                }
            }
            DeRecEvent::NoOp => Self::NoOp,
            // `#[non_exhaustive]` — future variants degrade to NoOp so
            // bridges don't break on a re-genned enum.
            #[allow(unreachable_patterns)]
            _ => Self::NoOp,
        })
    }
}

fn action_kind_label(action: &PendingAction) -> &'static str {
    pending_action_kind_label(action.kind())
}

pub(crate) fn pending_action_kind_label(
    kind: crate::protocol::events::PendingActionKind,
) -> &'static str {
    use crate::protocol::events::PendingActionKind as K;
    match kind {
        K::Pairing => "Pairing",
        K::PrePair => "PrePair",
        K::StoreShare => "StoreShare",
        K::VerifyShare => "VerifyShare",
        K::Discovery => "Discovery",
        K::GetShare => "GetShare",
        K::Unpair => "Unpair",
        K::UpdateChannelInfo => "UpdateChannelInfo",
    }
}

fn extract_peer_communication_info(action: &PendingAction) -> HashMap<String, String> {
    match action {
        PendingAction::Pairing { peer_communication_info, .. } => {
            peer_communication_info.clone()
        }
        _ => HashMap::new(),
    }
}

fn extract_pairing_sender_kind(action: &PendingAction) -> Option<i32> {
    match action {
        PendingAction::Pairing { request, .. } => Some(request.sender_kind),
        _ => None,
    }
}

fn extract_share_metadata(
    action: &PendingAction,
) -> (Option<u32>, Option<String>, Option<String>) {
    match action {
        PendingAction::StoreShare { request, .. } => {
            let desc = if request.version_description.is_empty() {
                None
            } else {
                Some(request.version_description.clone())
            };
            (Some(request.version), desc, Some(request.secret_id.to_string()))
        }
        PendingAction::VerifyShare { request, .. } => (
            Some(request.version),
            None,
            Some(request.secret_id.to_string()),
        ),
        _ => (None, None, None),
    }
}
