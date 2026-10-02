// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Serializable projections of [`StateKey`] and [`StateItem`].
//!
//! [`StateItem`] holds prost message types ([`derec_proto::VerifyShareRequestMessage`],
//! [`derec_proto::GetShareResponseMessage`]) that carry no serde impls, so it
//! cannot itself be serialized. These records are the projection that can:
//! prost-encode the embedded messages into byte fields and stringify every
//! `u64` so JSON consumers do not silently round ids above 2^53.
//!
//! This is the **one** encoding of orchestrator state. The FFI store shim, the
//! WASM store shim and any out-of-process backend (the `sqlite` and `postgres`
//! bindings, for instance) all go through it, so a row written by one backend
//! is readable by another and the contract cannot drift between them.
//!
//! Gated on `serde` because it exists only to be serialized; `wasm32` gets it
//! unconditionally since the WASM store shim always needs it.

use super::{StateItem, StateKey};
use crate::types::ChannelId;
use prost::Message;

/// JSON-on-the-wire shape of a [`StateKey`]. `kind` matches
/// [`crate::protocol::StateKind`]:
/// - `0` = PendingVerification — `channel_id` present (stringified u64)
/// - `1` = PendingRecovery — `secret_id` (stringified u64, the secret
///   being recovered) and `version` present
/// - `2` = PendingUnpair — `channel_id` present (stringified u64)
/// - `3` = SharingRound — `version` present (the round's version, which is
///   its secondary key)
///
/// Absent fields are serialized as JSON `null` on outbound and are
/// required-per-kind on inbound.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StateKeyRecord {
    pub kind: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
}

impl From<&StateKey> for StateKeyRecord {
    fn from(k: &StateKey) -> Self {
        match k {
            StateKey::PendingVerification { channel_id } => Self {
                kind: 0,
                channel_id: Some(channel_id.0.to_string()),
                secret_id: None,
                version: None,
            },
            StateKey::PendingRecovery { secret_id, version } => Self {
                kind: 1,
                channel_id: None,
                secret_id: Some(secret_id.to_string()),
                version: Some(*version),
            },
            StateKey::PendingUnpair { channel_id } => Self {
                kind: 2,
                channel_id: Some(channel_id.0.to_string()),
                secret_id: None,
                version: None,
            },
            StateKey::PendingReplicaDiscovery => Self {
                kind: 4,
                channel_id: None,
                secret_id: None,
                version: None,
            },
            StateKey::SharingRound { version } => Self {
                kind: 3,
                channel_id: None,
                secret_id: None,
                version: Some(*version),
            },
        }
    }
}

/// JSON-on-the-wire shape of a [`StateItem`]. `kind` matches
/// [`crate::protocol::StateKind`] (identical numbering to [`StateKeyRecord::kind`]):
/// - `0` = PendingVerification — `channel_id`, `bytes` (prost-encoded
///   [`derec_proto::VerifyShareRequestMessage`])
/// - `1` = PendingRecovery — `secret_id` (stringified u64, the secret
///   being recovered), `version`, `shares` (each entry is a
///   prost-encoded [`derec_proto::GetShareResponseMessage`])
/// - `2` = PendingUnpair — `channel_id`, `started_at` (stringified u64
///   unix-seconds)
/// - `3` = SharingRound — `version`, `pending`, `confirmed`, `failed`
///   (each channel-id set is stringified u64s), `started_at`
///   (stringified u64 unix-seconds)
/// - `4` = PendingReplicaDiscovery — `local_version`, `started_at`,
///   `pending_replicas`, `reported`
///
/// The fields a [`StateKeyRecord`] carries (`channel_id`, `secret_id`,
/// `version`) are present on an item exactly when its key has them, with the
/// same values, so a store can derive the row key from either.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StateItemRecord {
    pub kind: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// PendingReplicaDiscovery only: the version this device held when the
    /// catch-up started. Kept out of `version`, which is a key field, because
    /// the catch-up's key has none. Rows written before 0.0.6 carry it in
    /// `version`, which is still read when this field is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<Vec<u8>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<Vec<String>>,
    /// Replica-leg accounting, keyed by `replica_id`. Absent on rows written
    /// before the leg existed, which decode as empty rather than failing —
    /// an in-flight round predating the split simply has no member state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_replicas: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synced_replicas: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behind_replicas: Option<Vec<String>>,
    /// Catch-up accounting: members still to answer, and what those that
    /// have answered reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported: Option<Vec<ReplicaDiscoveryReport>>,
}
/// One member's answer in an in-flight catch-up. A nested record rather than
/// a packed string so the pair stays self-describing for every binding.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ReplicaDiscoveryReport {
    pub replica_id: String,
    pub version: u32,
}

impl From<&StateItem> for StateItemRecord {
    fn from(v: &StateItem) -> Self {
        match v {
            StateItem::PendingVerification {
                channel_id,
                request,
            } => Self {
                kind: 0,
                channel_id: Some(channel_id.0.to_string()),
                secret_id: None,
                version: None,
                started_at: None,
                local_version: None,
                bytes: Some(request.encode_to_vec()),
                shares: None,
                pending: None,
                confirmed: None,
                failed: None,
                pending_replicas: None,
                synced_replicas: None,
                behind_replicas: None,
                reported: None,
            },
            StateItem::PendingRecovery {
                secret_id,
                version,
                shares,
            } => Self {
                kind: 1,
                channel_id: None,
                secret_id: Some(secret_id.to_string()),
                version: Some(*version),
                started_at: None,
                local_version: None,
                bytes: None,
                shares: Some(shares.iter().map(|s| s.encode_to_vec()).collect()),
                pending: None,
                confirmed: None,
                failed: None,
                pending_replicas: None,
                synced_replicas: None,
                behind_replicas: None,
                reported: None,
            },
            StateItem::PendingUnpair {
                channel_id,
                started_at,
            } => Self {
                kind: 2,
                channel_id: Some(channel_id.0.to_string()),
                secret_id: None,
                version: None,
                started_at: Some(started_at.to_string()),
                local_version: None,
                bytes: None,
                shares: None,
                pending: None,
                confirmed: None,
                failed: None,
                pending_replicas: None,
                synced_replicas: None,
                behind_replicas: None,
                reported: None,
            },
            StateItem::PendingReplicaDiscovery {
                local_version,
                pending,
                reported,
                started_at,
            } => Self {
                kind: 4,
                channel_id: None,
                secret_id: None,
                version: None,
                started_at: Some(started_at.to_string()),
                local_version: Some(*local_version),
                bytes: None,
                shares: None,
                pending: None,
                confirmed: None,
                failed: None,
                pending_replicas: Some(pending.iter().map(|r| r.0.to_string()).collect()),
                synced_replicas: None,
                behind_replicas: None,
                reported: Some(
                    reported
                        .iter()
                        .map(|(id, version)| ReplicaDiscoveryReport {
                            replica_id: id.0.to_string(),
                            version: *version,
                        })
                        .collect(),
                ),
            },
            StateItem::SharingRound(round) => Self {
                kind: 3,
                channel_id: None,
                secret_id: None,
                version: Some(round.version),
                started_at: Some(round.started_at.to_string()),
                local_version: None,
                bytes: None,
                shares: None,
                pending: Some(round.pending.iter().map(|c| c.0.to_string()).collect()),
                confirmed: Some(round.confirmed.iter().map(|c| c.0.to_string()).collect()),
                failed: Some(round.failed.iter().map(|c| c.0.to_string()).collect()),
                pending_replicas: Some(
                    round
                        .pending_replicas
                        .iter()
                        .map(|r| r.0.to_string())
                        .collect(),
                ),
                synced_replicas: Some(
                    round
                        .synced_replicas
                        .iter()
                        .map(|r| r.0.to_string())
                        .collect(),
                ),
                behind_replicas: Some(
                    round
                        .behind_replicas
                        .iter()
                        .map(|r| r.0.to_string())
                        .collect(),
                ),
                reported: None,
            },
        }
    }
}

/// Decode a replica-id set. An absent field is an empty set, not an error:
/// the replica leg postdates the helper one, so a row written by an older
/// build carries no member state and has none to recover.
fn parse_replica_id_set(
    raw: Option<Vec<String>>,
    field: &str,
) -> Result<std::collections::HashSet<crate::types::ReplicaId>, String> {
    raw.unwrap_or_default()
        .into_iter()
        .map(|s| {
            s.parse::<u64>()
                .map_err(|e| format!("{field} entry not a decimal u64: {e}"))
                .and_then(|v| {
                    crate::types::ReplicaId::try_from(v)
                        .map_err(|e| format!("{field} entry is not a valid replica_id: {e}"))
                })
        })
        .collect()
}

fn parse_channel_id_set(
    raw: Option<Vec<String>>,
    field: &str,
) -> Result<std::collections::HashSet<ChannelId>, String> {
    raw.ok_or_else(|| format!("SharingRound requires {field}"))?
        .into_iter()
        .map(|s| {
            s.parse::<u64>()
                .map(ChannelId)
                .map_err(|e| format!("{field} entry not a decimal u64: {e}"))
        })
        .collect()
}

impl StateItemRecord {
    pub fn into_item(self) -> Result<StateItem, String> {
        match self.kind {
            0 => {
                let channel_id_str = self
                    .channel_id
                    .ok_or_else(|| "PendingVerification requires channel_id".to_string())?;
                let channel_id = channel_id_str
                    .parse::<u64>()
                    .map(ChannelId)
                    .map_err(|e| format!("channel_id not a decimal u64: {e}"))?;
                let bytes = self
                    .bytes
                    .ok_or_else(|| "PendingVerification requires bytes".to_string())?;
                let request = derec_proto::VerifyShareRequestMessage::decode(bytes.as_slice())
                    .map_err(|e| format!("VerifyShareRequestMessage decode: {e}"))?;
                Ok(StateItem::PendingVerification {
                    channel_id,
                    request,
                })
            }
            1 => {
                let secret_id = self
                    .secret_id
                    .ok_or_else(|| "PendingRecovery requires secret_id".to_string())?
                    .parse::<u64>()
                    .map_err(|e| format!("secret_id not a decimal u64: {e}"))?;
                let version = self
                    .version
                    .ok_or_else(|| "PendingRecovery requires version".to_string())?;
                let raw_shares = self
                    .shares
                    .ok_or_else(|| "PendingRecovery requires shares".to_string())?;
                let mut shares = Vec::with_capacity(raw_shares.len());
                for (i, blob) in raw_shares.into_iter().enumerate() {
                    let msg = derec_proto::GetShareResponseMessage::decode(blob.as_slice())
                        .map_err(|e| format!("GetShareResponseMessage[{i}] decode: {e}"))?;
                    shares.push(msg);
                }
                Ok(StateItem::PendingRecovery {
                    secret_id,
                    version,
                    shares,
                })
            }
            2 => {
                let channel_id_str = self
                    .channel_id
                    .ok_or_else(|| "PendingUnpair requires channel_id".to_string())?;
                let channel_id = channel_id_str
                    .parse::<u64>()
                    .map(ChannelId)
                    .map_err(|e| format!("channel_id not a decimal u64: {e}"))?;
                let started_at_str = self
                    .started_at
                    .ok_or_else(|| "PendingUnpair requires started_at".to_string())?;
                let started_at = started_at_str
                    .parse::<u64>()
                    .map_err(|e| format!("started_at not a decimal u64: {e}"))?;
                Ok(StateItem::PendingUnpair {
                    channel_id,
                    started_at,
                })
            }
            3 => {
                let version = self
                    .version
                    .ok_or_else(|| "SharingRound requires version".to_string())?;
                let started_at_str = self
                    .started_at
                    .ok_or_else(|| "SharingRound requires started_at".to_string())?;
                let started_at = started_at_str
                    .parse::<u64>()
                    .map_err(|e| format!("started_at not a decimal u64: {e}"))?;
                let pending = parse_channel_id_set(self.pending, "pending")?;
                let confirmed = parse_channel_id_set(self.confirmed, "confirmed")?;
                let failed = parse_channel_id_set(self.failed, "failed")?;
                let pending_replicas =
                    parse_replica_id_set(self.pending_replicas, "pending_replicas")?;
                let synced_replicas =
                    parse_replica_id_set(self.synced_replicas, "synced_replicas")?;
                let behind_replicas =
                    parse_replica_id_set(self.behind_replicas, "behind_replicas")?;
                Ok(StateItem::SharingRound(Box::new(
                    crate::protocol::types::SharingRoundState {
                        version,
                        pending,
                        confirmed,
                        failed,
                        pending_replicas,
                        synced_replicas,
                        behind_replicas,
                        started_at,
                    },
                )))
            }
            4 => {
                let local_version = self
                    .local_version
                    .or(self.version)
                    .ok_or_else(|| "PendingReplicaDiscovery requires local_version".to_string())?;
                let started_at = self
                    .started_at
                    .ok_or_else(|| "PendingReplicaDiscovery requires started_at".to_string())?
                    .parse::<u64>()
                    .map_err(|e| format!("started_at not a decimal u64: {e}"))?;
                let pending = parse_replica_id_set(self.pending_replicas, "pending_replicas")?;
                let mut reported = std::collections::HashMap::new();
                for entry in self.reported.unwrap_or_default() {
                    let id = entry
                        .replica_id
                        .parse::<u64>()
                        .map_err(|e| format!("reported.replica_id not a decimal u64: {e}"))
                        .and_then(|v| {
                            crate::types::ReplicaId::try_from(v)
                                .map_err(|e| format!("reported.replica_id invalid: {e}"))
                        })?;
                    reported.insert(id, entry.version);
                }
                Ok(StateItem::PendingReplicaDiscovery {
                    local_version,
                    pending,
                    reported,
                    started_at,
                })
            }
            other => Err(format!("unknown StateKind: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChannelId, ReplicaId};

    fn every_kind() -> Vec<StateItem> {
        vec![
            StateItem::PendingVerification {
                channel_id: ChannelId(7),
                request: derec_proto::VerifyShareRequestMessage::default(),
            },
            StateItem::PendingRecovery {
                secret_id: 11,
                version: 3,
                shares: Vec::new(),
            },
            StateItem::PendingUnpair {
                channel_id: ChannelId(9),
                started_at: 100,
            },
            StateItem::PendingReplicaDiscovery {
                local_version: 5,
                pending: [ReplicaId(21)].into_iter().collect(),
                reported: [(ReplicaId(22), 6)].into_iter().collect(),
                started_at: 100,
            },
            StateItem::SharingRound(Box::new(crate::protocol::types::SharingRoundState {
                version: 4,
                pending: Default::default(),
                confirmed: Default::default(),
                failed: Default::default(),
                pending_replicas: Default::default(),
                synced_replicas: Default::default(),
                behind_replicas: Default::default(),
                started_at: 100,
            })),
        ]
    }

    #[test]
    fn an_item_carries_exactly_its_keys_fields() {
        for item in every_kind() {
            let record = StateItemRecord::from(&item);
            let key = StateKeyRecord::from(&item.key());
            assert_eq!(record.kind, key.kind, "{item:?}");
            assert_eq!(record.channel_id, key.channel_id, "channel_id of {item:?}");
            assert_eq!(record.secret_id, key.secret_id, "secret_id of {item:?}");
            assert_eq!(record.version, key.version, "version of {item:?}");
        }
    }

    #[test]
    fn a_catch_up_row_round_trips() {
        let item = &every_kind()[3];
        let json = serde_json::to_string(&StateItemRecord::from(item)).expect("encodes");
        let back: StateItemRecord = serde_json::from_str(&json).expect("decodes");
        match back.into_item().expect("valid row") {
            StateItem::PendingReplicaDiscovery {
                local_version,
                pending,
                reported,
                started_at,
            } => {
                assert_eq!(local_version, 5);
                assert!(pending.contains(&ReplicaId(21)));
                assert_eq!(reported.get(&ReplicaId(22)), Some(&6));
                assert_eq!(started_at, 100);
            }
            other => panic!("decoded as {other:?}"),
        }
    }

    #[test]
    fn a_catch_up_row_from_before_0_0_6_still_decodes() {
        let json =
            r#"{"kind":4,"version":5,"started_at":"100","pending_replicas":["21"],"reported":[]}"#;
        let row: StateItemRecord = serde_json::from_str(json).expect("decodes");
        assert!(matches!(
            row.into_item(),
            Ok(StateItem::PendingReplicaDiscovery {
                local_version: 5,
                ..
            })
        ));
    }

    /// Bindings forward state rows verbatim, so every per-kind requirement
    /// is enforced here: a missing required field or an unknown kind is
    /// refused, never defaulted.
    #[test]
    fn a_row_missing_what_its_kind_requires_is_refused() {
        for json in [
            r#"{"kind":0,"bytes":[]}"#,
            r#"{"kind":0,"channel_id":"7"}"#,
            r#"{"kind":1,"version":3,"shares":[]}"#,
            r#"{"kind":1,"secret_id":"11","shares":[]}"#,
            r#"{"kind":1,"secret_id":"11","version":3}"#,
            r#"{"kind":2,"started_at":"100"}"#,
            r#"{"kind":2,"channel_id":"9"}"#,
            r#"{"kind":3,"started_at":"100","pending":[],"confirmed":[],"failed":[]}"#,
            r#"{"kind":3,"version":2,"started_at":"100","confirmed":[],"failed":[]}"#,
            r#"{"kind":4,"started_at":"100"}"#,
            r#"{"kind":4,"local_version":5}"#,
            r#"{"kind":9}"#,
        ] {
            let row: StateItemRecord = serde_json::from_str(json).expect("parses");
            assert!(row.into_item().is_err(), "{json} must be refused");
        }
    }
}
