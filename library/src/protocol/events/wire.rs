// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

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

use crate::protocol::utils::{pending_action_wire, reserved_keys::encode_replica_id};
use crate::protocol::{
    DeRecEvent, PendingAction,
    types::{ChannelShare, Secret},
};

/// Canonical wire-shape of [`super::DeRecEvent`]. Consumed by the FFI
/// and WASM bridges only. See module docs for the field conventions.
#[derive(Serialize)]
#[serde(tag = "type")]
pub(crate) enum Event {
    PairingCompleted {
        channel_id: String,
        pairing_channel_id: String,
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
    /// The first sync for a `secret_id` this device had no snapshot for.
    /// Same payload as `ReplicaSecretReceived`; the distinct name is what
    /// tells an application the set of secrets on the device changed.
    ReplicaSecretInstalled {
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
    /// A member refused a secret sync. Keyed by `replica_id`, not
    /// `channel_id`: every member answers on the one group channel.
    ReplicaSyncRejected {
        replica_id: String,
        secret_id: String,
        version: u32,
        status: i32,
        memo: String,
    },
    /// A secret sync could not be delivered to a member at all.
    ReplicaSyncFailed {
        replica_id: String,
        version: u32,
        reason: String,
    },
    /// A member left the group; its roster row was dropped. Fires on the
    /// members that remain.
    ReplicaRemoved {
        replica_id: String,
    },
    /// The group's source role moved to another member because the previous
    /// source is leaving. Fires on the device that chose, and on the successor.
    ReplicaSourceChanged {
        replica_id: String,
    },
    /// This device left the group and dropped its whole `secret_id` partition.
    SelfRemovedFromGroup {
        version: u32,
    },
    /// A replica catch-up finished. `fetched_from` is absent when this device
    /// was already current, in which case no hydration event follows.
    SyncCheckComplete {
        local_version: u32,
        group_version: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        fetched_from: Option<String>,
    },
    /// The replica leg of a publishing round finished. Reported separately
    /// from `SharingComplete`: replicas are best-effort, so a member in
    /// `behind` does not fail the round.
    ReplicaSyncComplete {
        version: u32,
        synced: Vec<String>,
        behind: Vec<String>,
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
        /// Same nested wire shape as
        /// [`Self::ReplicaSecretReceived::secret`] — the typed
        /// `Secret` snapshot the owner originally protected.
        secret: SecretWire,
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
    PairingStarted {
        channel_id: String,
        kind: i32,
    },
    DiscoveryStarted {
        channel_id: String,
    },
    DiscoveryFailed {
        channel_id: String,
        error: String,
    },
    ProtectSecretStarted {
        channel_id: String,
        version: u32,
    },
    ProtectSecretFailed {
        channel_id: String,
        version: u32,
        error: String,
    },
    VerifySharesStarted {
        channel_id: String,
        version: u32,
    },
    VerifySharesFailed {
        channel_id: String,
        version: u32,
        error: String,
    },
    RecoverSecretStarted {
        channel_id: String,
        version: u32,
    },
    RecoverSecretFailed {
        channel_id: String,
        version: u32,
        error: String,
    },
    UnpairFailed {
        channel_id: String,
        error: String,
    },
    UnpairStarted {
        channel_id: String,
    },
    UpdateChannelInfoStarted {
        channel_id: String,
    },
    UpdateChannelInfoFailed {
        channel_id: String,
        error: String,
    },
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
    /// The replica group. Absent when this `secret_id` has no replica
    /// setup. Carries the full member roster and the 32-byte group key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<ReplicasWire>,
}

#[derive(Serialize)]
pub struct ReplicasWire {
    /// The one channel every member is addressed on.
    pub channel_id: String,
    /// Every member of the group, including the source and the writer. The
    /// source is the member whose `role` is `Source`.
    pub members: Vec<Replica>,
    /// 32-byte replica group key. Required by `DeRecProtocol::restore`
    /// to rebuild replica channel state.
    pub shared_key: Vec<u8>,
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
    pub replica_id: String,
    pub transport_uri: String,
    /// `"Source"` or `"Destination"` — the member's role in the group.
    pub role: String,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub communication_info: HashMap<String, String>,
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
            replicas: v.replicas.map(|g| ReplicasWire {
                channel_id: g.channel_id.to_string(),
                members: g
                    .members
                    .into_iter()
                    .map(|r| Replica {
                        replica_id: encode_replica_id(r.replica_id),
                        transport_uri: r.transport_uri,
                        role: crate::protocol::types::ReplicaRole::from_i32(r.role)
                            .map(|role| format!("{role:?}"))
                            .unwrap_or_default(),
                        communication_info: r.communication_info,
                    })
                    .collect(),
                shared_key: g.shared_key,
            }),
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
                pairing_channel_id,
                kind,
                peer_communication_info,
            } => Self::PairingCompleted {
                channel_id: channel_id.0.to_string(),
                pairing_channel_id: pairing_channel_id.0.to_string(),
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
            DeRecEvent::ReplicaSecretInstalled {
                channel_id,
                from_replica_id,
                secret_id,
                version,
                secret,
                shares,
            } => Self::ReplicaSecretInstalled {
                channel_id: channel_id.0.to_string(),
                from_replica_id: encode_replica_id(from_replica_id),
                secret_id: secret_id.to_string(),
                version,
                secret: secret.into(),
                shares: shares.into_iter().map(Into::into).collect(),
            },
            DeRecEvent::ReplicaSyncRejected {
                replica_id,
                secret_id,
                version,
                status,
                memo,
            } => Self::ReplicaSyncRejected {
                replica_id: encode_replica_id(replica_id),
                secret_id: secret_id.to_string(),
                version,
                status,
                memo,
            },
            DeRecEvent::ReplicaSyncFailed {
                replica_id,
                version,
                reason,
            } => Self::ReplicaSyncFailed {
                replica_id: encode_replica_id(replica_id),
                version,
                reason,
            },
            DeRecEvent::ReplicaRemoved { replica_id } => Self::ReplicaRemoved {
                replica_id: encode_replica_id(replica_id),
            },
            DeRecEvent::ReplicaSourceChanged { replica_id } => Self::ReplicaSourceChanged {
                replica_id: encode_replica_id(replica_id),
            },
            DeRecEvent::SelfRemovedFromGroup { version } => Self::SelfRemovedFromGroup { version },
            DeRecEvent::SyncCheckComplete {
                local_version,
                group_version,
                fetched_from,
            } => Self::SyncCheckComplete {
                local_version,
                group_version,
                fetched_from: fetched_from.map(encode_replica_id),
            },
            DeRecEvent::ReplicaSyncComplete {
                version,
                synced,
                behind,
            } => Self::ReplicaSyncComplete {
                version,
                synced: synced.into_iter().map(encode_replica_id).collect(),
                behind: behind.into_iter().map(encode_replica_id).collect(),
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
            DeRecEvent::ShareConfirmed {
                channel_id,
                version,
            } => Self::ShareConfirmed {
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
            DeRecEvent::ShareVerified {
                channel_id,
                version,
            } => Self::ShareVerified {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::SecretsDiscovered {
                channel_id,
                secrets,
            } => Self::SecretsDiscovered {
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
            DeRecEvent::SecretRecovered { secret } => Self::SecretRecovered {
                secret: secret.into(),
            },
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
                let (version, share_description, share_secret_id) = extract_share_metadata(&action);
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
            DeRecEvent::PairingStarted { channel_id, kind } => Self::PairingStarted {
                channel_id: channel_id.0.to_string(),
                kind: kind as i32,
            },
            DeRecEvent::DiscoveryStarted { channel_id } => Self::DiscoveryStarted {
                channel_id: channel_id.0.to_string(),
            },
            DeRecEvent::DiscoveryFailed { channel_id, error } => Self::DiscoveryFailed {
                channel_id: channel_id.0.to_string(),
                error,
            },
            DeRecEvent::ProtectSecretStarted {
                channel_id,
                version,
            } => Self::ProtectSecretStarted {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::ProtectSecretFailed {
                channel_id,
                version,
                error,
            } => Self::ProtectSecretFailed {
                channel_id: channel_id.0.to_string(),
                version,
                error,
            },
            DeRecEvent::VerifySharesStarted {
                channel_id,
                version,
            } => Self::VerifySharesStarted {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::VerifySharesFailed {
                channel_id,
                version,
                error,
            } => Self::VerifySharesFailed {
                channel_id: channel_id.0.to_string(),
                version,
                error,
            },
            DeRecEvent::RecoverSecretStarted {
                channel_id,
                version,
            } => Self::RecoverSecretStarted {
                channel_id: channel_id.0.to_string(),
                version,
            },
            DeRecEvent::RecoverSecretFailed {
                channel_id,
                version,
                error,
            } => Self::RecoverSecretFailed {
                channel_id: channel_id.0.to_string(),
                version,
                error,
            },
            DeRecEvent::UnpairStarted { channel_id } => Self::UnpairStarted {
                channel_id: channel_id.0.to_string(),
            },
            DeRecEvent::UnpairFailed { channel_id, error } => Self::UnpairFailed {
                channel_id: channel_id.0.to_string(),
                error,
            },
            DeRecEvent::UpdateChannelInfoStarted { channel_id } => Self::UpdateChannelInfoStarted {
                channel_id: channel_id.0.to_string(),
            },
            DeRecEvent::UpdateChannelInfoFailed { channel_id, error } => {
                Self::UpdateChannelInfoFailed {
                    channel_id: channel_id.0.to_string(),
                    error,
                }
            }
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
        PendingAction::Pairing {
            peer_communication_info,
            ..
        } => peer_communication_info.clone(),
        _ => HashMap::new(),
    }
}

fn extract_pairing_sender_kind(action: &PendingAction) -> Option<i32> {
    match action {
        PendingAction::Pairing { request, .. } => Some(request.sender_kind),
        _ => None,
    }
}

fn extract_share_metadata(action: &PendingAction) -> (Option<u32>, Option<String>, Option<String>) {
    match action {
        PendingAction::StoreShare { request, .. } => {
            let desc = if request.version_description.is_empty() {
                None
            } else {
                Some(request.version_description.clone())
            };
            (
                Some(request.version),
                desc,
                Some(request.secret_id.to_string()),
            )
        }
        PendingAction::VerifyShare { request, .. } => (
            Some(request.version),
            None,
            Some(request.secret_id.to_string()),
        ),
        _ => (None, None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ChannelId;

    /// Both the FFI and WASM bridges serialize through
    /// [`Event::from_event`], so mapping a variant here is what makes it
    /// visible to every SDK. An unmapped variant silently degrades to
    /// `NoOp`, which is indistinguishable from "nothing happened".
    #[test]
    fn unpair_failed_maps_to_the_wire_instead_of_degrading_to_noop() {
        let mapped = Event::from_event(DeRecEvent::UnpairFailed {
            channel_id: ChannelId(99),
            error: "transport unreachable".to_owned(),
        })
        .expect("UnpairFailed must map");

        let json = serde_json::to_value(&mapped).expect("serializes");
        assert_eq!(json["type"], "UnpairFailed");
        assert_eq!(json["channel_id"], "99");
        assert_eq!(json["error"], "transport unreachable");
    }
}
