// SPDX-License-Identifier: Apache-2.0

//! JSON encoder for [`DeRecEvent`] streams emitted by the orchestrator
//! across the FFI boundary.
//!
//! Wire shape mirrors the WASM `DeRecEventJs` enum so the dotnet side
//! can deserialize each event with `System.Text.Json` against a single
//! shared schema. Each event is a JSON object with a `"type"`
//! discriminator (one of the variant names) and the variant payload as
//! sibling fields.

use std::collections::HashMap;

use serde::Serialize;

use crate::protocol::reserved_keys::encode_replica_id;
use crate::protocol::{pending_action_wire, DeRecEvent};

/// Encode an event stream to a UTF-8 JSON array (`[ {...}, {...}, ... ]`)
/// ready to ship over the FFI boundary as a `DeRecBuffer`. Consumes the
/// vec so we can move owned data (e.g. `PendingAction`) out of each
/// event without requiring `Clone`.
pub fn encode_events(events: Vec<DeRecEvent>) -> Vec<u8> {
    let mapped: Vec<EventJson> = events.into_iter().map(EventJson::from_event).collect();
    serde_json::to_vec(&mapped).expect("DeRecEvent JSON encoding is infallible")
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum EventJson {
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
    /// Surfaced for every inbound request that needs the app's
    /// explicit consent before the orchestrator acts. `action` is the
    /// `pending_action_wire`-serialized PendingAction blob — the
    /// caller hands it back verbatim to accept / reject.
    ActionRequired {
        channel_id: String,
        action: Vec<u8>,
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
        secrets: Vec<DiscoveredSecretJson>,
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
    ReplicaVaultReceived {
        channel_id: String,
        from_replica_id: String,
        secret_id: String,
        version: u32,
        vault: SecretContainerJson,
        shares: Vec<ChannelShareJson>,
    },
    ReplicaVaultAcked {
        channel_id: String,
        from_replica_id: String,
        secret_id: String,
        version: u32,
        status: i32,
        memo: String,
    },
    ChannelInfoUpdated {
        channel_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_communication_info: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_transport_uri: Option<String>,
    },
    ChannelInfoUpdateRejected {
        channel_id: String,
        status: i32,
        memo: String,
    },
    NoOp {},
}

#[derive(Serialize)]
struct DiscoveredSecretJson {
    secret_id: String,
    versions: Vec<DiscoveredVersionJson>,
}

#[derive(Serialize)]
struct DiscoveredVersionJson {
    version: u32,
    description: String,
}

#[derive(Serialize)]
struct SecretContainerJson {
    helpers: Vec<HelperInfoJson>,
    secrets: Vec<UserSecretJson>,
    replicas: Vec<ReplicaInfoJson>,
    owner_replica_id: String,
}

#[derive(Serialize)]
struct HelperInfoJson {
    channel_id: String,
    transport_uri: String,
    shared_key: Vec<u8>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    communication_info: HashMap<String, String>,
}

#[derive(Serialize)]
struct ReplicaInfoJson {
    channel_id: String,
    transport_uri: String,
    shared_key: Vec<u8>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    communication_info: HashMap<String, String>,
    replica_id: String,
    sender_kind: i32,
}

#[derive(Serialize)]
struct UserSecretJson {
    id: Vec<u8>,
    name: String,
    data: Vec<u8>,
}

#[derive(Serialize)]
struct ChannelShareJson {
    channel_id: String,
    committed_share: Vec<u8>,
}

impl EventJson {
    fn from_event(event: DeRecEvent) -> Self {
        match event {
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
            DeRecEvent::ActionRequired { channel_id, action } => {
                let channel_id_s = channel_id.0.to_string();
                match pending_action_wire::serialize(action) {
                    Ok(bytes) => Self::ActionRequired {
                        channel_id: channel_id_s,
                        action: bytes,
                    },
                    Err(_) => Self::NoOp {},
                }
            }
            DeRecEvent::ShareStored { channel_id, version } => Self::ShareStored {
                channel_id: channel_id.0.to_string(),
                version,
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
                    .map(|s| DiscoveredSecretJson {
                        secret_id: s.secret_id.to_string(),
                        versions: s
                            .versions
                            .into_iter()
                            .map(|v| DiscoveredVersionJson {
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
            DeRecEvent::ReplicaVaultReceived {
                channel_id,
                from_replica_id,
                secret_id,
                version,
                vault,
                shares,
            } => Self::ReplicaVaultReceived {
                channel_id: channel_id.0.to_string(),
                from_replica_id: encode_replica_id(from_replica_id),
                secret_id: secret_id.to_string(),
                version,
                vault: container_to_json(vault),
                shares: shares
                    .into_iter()
                    .map(|s| ChannelShareJson {
                        channel_id: s.channel_id.to_string(),
                        committed_share: s.committed_share,
                    })
                    .collect(),
            },
            DeRecEvent::ReplicaVaultAcked {
                channel_id,
                from_replica_id,
                secret_id,
                version,
                status,
                memo,
            } => Self::ReplicaVaultAcked {
                channel_id: channel_id.0.to_string(),
                from_replica_id: encode_replica_id(from_replica_id),
                secret_id: secret_id.to_string(),
                version,
                status,
                memo,
            },
            DeRecEvent::ChannelInfoUpdated {
                channel_id,
                communication_info,
                transport_protocol,
            } => Self::ChannelInfoUpdated {
                channel_id: channel_id.0.to_string(),
                peer_communication_info: communication_info,
                peer_transport_uri: transport_protocol.map(|t| t.uri),
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
            DeRecEvent::NoOp => Self::NoOp {},
        }
    }
}

fn container_to_json(c: crate::types::SecretContainer) -> SecretContainerJson {
    SecretContainerJson {
        helpers: c
            .helpers
            .into_iter()
            .map(|h| HelperInfoJson {
                channel_id: h.channel_id.to_string(),
                transport_uri: h.transport_uri,
                shared_key: h.shared_key,
                communication_info: h.communication_info,
            })
            .collect(),
        secrets: c
            .secrets
            .into_iter()
            .map(|s| UserSecretJson {
                id: s.id,
                name: s.name,
                data: s.data,
            })
            .collect(),
        replicas: c
            .replicas
            .into_iter()
            .map(|r| ReplicaInfoJson {
                channel_id: r.channel_id.to_string(),
                transport_uri: r.transport_uri,
                shared_key: r.shared_key,
                communication_info: r.communication_info,
                replica_id: encode_replica_id(r.replica_id),
                sender_kind: r.sender_kind,
            })
            .collect(),
        owner_replica_id: encode_replica_id(c.owner_replica_id),
    }
}
