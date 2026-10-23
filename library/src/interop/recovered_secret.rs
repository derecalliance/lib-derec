// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Inbound shape of the recovered [`Secret`] a binding hands back to
//! [`crate::protocol::DeRecProtocol::restore`].
//!
//! It is the deserializing counterpart of the `SecretRecovered` event's
//! `secret` field: an application passes that object back verbatim, so every
//! field name and encoding here matches what the event emits. Both the WASM
//! and FFI bindings decode through this one type so the two cannot disagree on
//! what a well-formed recovered secret is.
//!
//! Every `u64` identifier (`channel_id`, `replica_id`) is a decimal string, the
//! encoding the event emits. It is required and parsed strictly: an absent,
//! empty, signed, or out-of-range id is rejected rather than read as `0`,
//! which would restore state under an id the recovered secret never named.

use std::collections::HashMap;

use crate::protocol::types::{HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret};

/// One advertised endpoint: a URI plus the protocol name (`"https"`,
/// `"grpc"`), the same shape `SecretRecovered` carries, so no protocol is
/// inferred from a scheme.
#[derive(serde::Deserialize)]
struct EndpointIn {
    uri: String,
    #[serde(deserialize_with = "crate::interop::protocol_names::protocol_from_name")]
    protocol: i32,
}

impl From<EndpointIn> for derec_proto::TransportProtocol {
    fn from(e: EndpointIn) -> Self {
        derec_proto::TransportProtocol {
            uri: e.uri,
            protocol: e.protocol,
        }
    }
}

/// `transports` absent, `null` or `[]` all decode to an empty list: an
/// entry with no endpoint is the core's to judge, and `restore` skips it
/// with a `PeerNotRestored` event rather than refusing the secret.
#[derive(serde::Deserialize)]
struct HelperIn {
    channel_id: String,
    #[serde(default)]
    transports: Option<Vec<EndpointIn>>,
    shared_key: Vec<u8>,
    /// Absent, `null` or `{}` decode to an empty map.
    #[serde(default)]
    communication_info: Option<HashMap<String, String>>,
    /// The Helper's subshare count. Absent or `null` is `1`.
    #[serde(default)]
    weight: Option<u32>,
}

#[derive(serde::Deserialize)]
struct ReplicaIn {
    replica_id: String,
    /// Absent, `null` or `[]` decode to an empty list, as on [`HelperIn`].
    #[serde(default)]
    transports: Option<Vec<EndpointIn>>,
    /// `"Source"` or `"Destination"`.
    role: String,
    /// Absent, `null` or `{}` decode to an empty map, as on [`HelperIn`].
    #[serde(default)]
    communication_info: Option<HashMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct ReplicasIn {
    channel_id: String,
    #[serde(default)]
    members: Vec<ReplicaIn>,
    #[serde(default)]
    shared_key: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct UserSecretIn {
    id: Vec<u8>,
    name: String,
    data: Vec<u8>,
}

/// The recovered secret as a binding receives it. Decode with serde, then
/// call [`RecoveredSecretIn::into_secret`].
#[derive(serde::Deserialize)]
pub(crate) struct RecoveredSecretIn {
    #[serde(default)]
    helpers: Vec<HelperIn>,
    #[serde(default)]
    secrets: Vec<UserSecretIn>,
    #[serde(default)]
    replicas: Option<ReplicasIn>,
    /// The threshold the secret was split with. Absent or `null` is none.
    #[serde(default)]
    threshold: Option<u32>,
}

fn endpoints(transports: Option<Vec<EndpointIn>>) -> Vec<derec_proto::TransportProtocol> {
    transports
        .unwrap_or_default()
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Parse a decimal `u64` identifier. `field` names the offending field in the
/// error.
pub(crate) fn parse_decimal_u64(s: &str, field: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{field} must be a decimal u64 string, got {s:?}"));
    }
    s.parse::<u64>()
        .map_err(|e| format!("{field} must be a decimal u64 string, got {s:?}: {e}"))
}

impl RecoveredSecretIn {
    /// Convert into the typed [`Secret`]. The error names the first field
    /// that is malformed.
    pub(crate) fn into_secret(self) -> Result<Secret, String> {
        let helpers = self
            .helpers
            .into_iter()
            .map(|h| -> Result<_, String> {
                let weight = match h.weight {
                    None => 1,
                    Some(0) => return Err("helper.weight must be at least 1, got 0".to_owned()),
                    Some(w) => w,
                };
                Ok(HelperInfo {
                    channel_id: parse_decimal_u64(&h.channel_id, "helper.channel_id")?,
                    transports: endpoints(h.transports),
                    shared_key: h.shared_key,
                    communication_info: h.communication_info.unwrap_or_default(),
                    weight,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        let replicas = self
            .replicas
            .map(|g| -> Result<_, String> {
                let members = g
                    .members
                    .into_iter()
                    .map(|r| -> Result<_, String> {
                        let role = match r.role.as_str() {
                            "Source" => ReplicaRole::Source,
                            "Destination" => ReplicaRole::Destination,
                            other => {
                                return Err(format!(
                                    "replica.role must be \"Source\" or \"Destination\", got {other:?}"
                                ));
                            }
                        };
                        Ok(ReplicaInfo {
                            replica_id: parse_decimal_u64(&r.replica_id, "replica.replica_id")?,
                            transports: endpoints(r.transports),
                            role: role as i32,
                            communication_info: r.communication_info.unwrap_or_default(),
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(Replicas {
                    channel_id: parse_decimal_u64(&g.channel_id, "replicas.channel_id")?,
                    members,
                    shared_key: g.shared_key,
                })
            })
            .transpose()?;

        let secrets = self
            .secrets
            .into_iter()
            .map(|s| UserSecret {
                id: s.id,
                name: s.name,
                data: s.data,
            })
            .collect();

        let threshold = match self.threshold {
            Some(t) if t < 2 => return Err(format!("threshold must be at least 2, got {t}")),
            other => other,
        };

        Ok(Secret {
            helpers,
            secrets,
            replicas,
            threshold,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(json: &str) -> Result<Secret, String> {
        serde_json::from_str::<RecoveredSecretIn>(json)
            .map_err(|e| e.to_string())?
            .into_secret()
    }

    const KEY: &str = "[1,2,3]";

    fn helper(channel_id: &str) -> String {
        format!(
            r#"{{"helpers":[{{"channel_id":{channel_id},"transports":[],"shared_key":{KEY}}}]}}"#
        )
    }

    #[test]
    fn decimal_ids_round_trip_the_full_u64_range() {
        let s = decode(&helper("\"18446744073709551615\"")).unwrap();
        assert_eq!(s.helpers[0].channel_id, u64::MAX);
        let s = decode(&helper("\"0\"")).unwrap();
        assert_eq!(s.helpers[0].channel_id, 0);
    }

    #[test]
    fn an_empty_id_is_rejected_not_read_as_zero() {
        let err = decode(&helper("\"\"")).unwrap_err();
        assert!(err.contains("helper.channel_id"), "{err}");
    }

    #[test]
    fn malformed_ids_are_rejected() {
        for bad in [
            "\"-1\"",
            "\"+1\"",
            "\" 1\"",
            "\"1.0\"",
            "\"0x10\"",
            "\"18446744073709551616\"",
        ] {
            assert!(decode(&helper(bad)).is_err(), "{bad} must be rejected");
        }
    }

    /// Endpoints are read by protocol name, the shape `SecretRecovered`
    /// carries; a discriminant or an unknown name is malformed.
    #[test]
    fn endpoint_protocols_are_read_by_name() {
        let with = |protocol: &str| {
            format!(
                r#"{{"helpers":[{{"channel_id":"1","transports":[{{"uri":"grpcs://h","protocol":{protocol}}}],"shared_key":{KEY}}}]}}"#
            )
        };
        let secret = decode(&with(r#""grpc""#)).unwrap();
        assert_eq!(
            secret.helpers[0].transports[0].protocol,
            derec_proto::Protocol::Grpc as i32
        );
        assert!(decode(&with("1")).is_err());
        assert!(decode(&with(r#""ftp""#)).is_err());
    }

    #[test]
    fn an_absent_id_is_rejected() {
        let json = format!(r#"{{"helpers":[{{"transports":[],"shared_key":{KEY}}}]}}"#);
        assert!(decode(&json).is_err());
        let json = format!(r#"{{"replicas":{{"members":[],"shared_key":{KEY}}}}}"#);
        assert!(decode(&json).is_err());
    }

    #[test]
    fn replica_ids_and_roles_decode() {
        let json = format!(
            r#"{{"replicas":{{"channel_id":"21","shared_key":{KEY},"members":[
                {{"replica_id":"51966","transports":[{{"uri":"https://a","protocol":"https"}}],"role":"Source"}},
                {{"replica_id":"7","transports":[],"role":"Destination"}}]}}}}"#
        );
        let g = decode(&json).unwrap().replicas.unwrap();
        assert_eq!(g.channel_id, 21);
        assert_eq!(g.members[0].replica_id, 51966);
        assert_eq!(g.members[0].role, ReplicaRole::Source as i32);
        assert_eq!(g.members[1].role, ReplicaRole::Destination as i32);
        assert_eq!(
            g.members[0].transports[0].protocol,
            derec_proto::Protocol::Https as i32
        );
        let json = format!(
            r#"{{"replicas":{{"channel_id":"21","shared_key":{KEY},"members":[
                {{"replica_id":"","transports":[],"role":"Source"}}]}}}}"#
        );
        assert!(decode(&json).unwrap_err().contains("replica.replica_id"));
    }

    /// An empty endpoint list is the core's to judge, so absent, `null` and
    /// `[]` all reach it as the same empty list. Go encodes a nil slice as
    /// `null`.
    #[test]
    fn absent_null_and_empty_transports_all_decode_to_no_endpoint() {
        for transports in [r#""#, r#""transports":null,"#, r#""transports":[],"#] {
            let json = format!(
                r#"{{"helpers":[{{"channel_id":"1",{transports}"shared_key":{KEY}}}],
                    "replicas":{{"channel_id":"21","shared_key":{KEY},"members":[
                    {{"replica_id":"7",{transports}"role":"Source"}}]}}}}"#
            );
            let secret = decode(&json).unwrap_or_else(|e| panic!("{transports}: {e}"));
            assert!(secret.helpers[0].transports.is_empty(), "{transports}");
            assert!(
                secret.replicas.unwrap().members[0].transports.is_empty(),
                "{transports}"
            );
        }
    }

    /// `communication_info` absent, `null` and `{}` all decode to an empty
    /// map on both a Helper and a replica member; a populated map is kept.
    #[test]
    fn absent_null_empty_and_populated_communication_info_decode() {
        for (info, expected) in [
            (r#""#, 0),
            (r#""communication_info":null,"#, 0),
            (r#""communication_info":{},"#, 0),
            (r#""communication_info":{"name":"Alice"},"#, 1),
        ] {
            let json = format!(
                r#"{{"helpers":[{{"channel_id":"1",{info}"shared_key":{KEY}}}],
                    "replicas":{{"channel_id":"21","shared_key":{KEY},"members":[
                    {{"replica_id":"7",{info}"role":"Source"}}]}}}}"#
            );
            let secret = decode(&json).unwrap_or_else(|e| panic!("{info}: {e}"));
            let helper = &secret.helpers[0].communication_info;
            let member = &secret.replicas.unwrap().members[0].communication_info;
            assert_eq!(helper.len(), expected, "{info}");
            assert_eq!(member.len(), expected, "{info}");
            if expected == 1 {
                assert_eq!(helper.get("name").map(String::as_str), Some("Alice"));
                assert_eq!(member.get("name").map(String::as_str), Some("Alice"));
            }
        }
    }

    /// `weight` is the roster's subshare count: absent or `null` reads as
    /// `1`, the value `SecretRecovered` omits nothing for, and `0` is
    /// malformed.
    #[test]
    fn a_helper_weight_decodes_and_defaults_to_one() {
        let with = |weight: &str| {
            format!(
                r#"{{"helpers":[{{"channel_id":"1","transports":[],"shared_key":{KEY}{weight}}}]}}"#
            )
        };
        assert_eq!(decode(&with("")).unwrap().helpers[0].weight, 1);
        assert_eq!(
            decode(&with(r#","weight":null"#)).unwrap().helpers[0].weight,
            1
        );
        assert_eq!(
            decode(&with(r#","weight":3"#)).unwrap().helpers[0].weight,
            3
        );
        assert!(
            decode(&with(r#","weight":0"#))
                .unwrap_err()
                .contains("helper.weight")
        );
    }

    /// The restore params every SDK builds byte-for-byte decode here with the
    /// weights and the threshold they carry.
    #[test]
    fn the_shared_restore_golden_carries_its_weights() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/wire_golden.json"))
                .expect("fixture parses");
        let secret = serde_json::from_value::<RecoveredSecretIn>(
            fixture["restore"]["recovered_secret"].clone(),
        )
        .expect("golden decodes")
        .into_secret()
        .expect("golden is well formed");
        let weights: Vec<u32> = secret.helpers.iter().map(|h| h.weight).collect();
        assert_eq!(weights, vec![1, 2]);
        assert_eq!(secret.threshold, Some(3));
    }

    /// `threshold` is the `t` the secret was split with: absent or `null` is
    /// none, and a value below `2` is malformed.
    #[test]
    fn a_threshold_decodes_and_a_value_below_two_is_rejected() {
        let with = |threshold: &str| format!(r#"{{"helpers":[]{threshold}}}"#);
        assert_eq!(decode(&with("")).unwrap().threshold, None);
        assert_eq!(
            decode(&with(r#","threshold":null"#)).unwrap().threshold,
            None
        );
        assert_eq!(
            decode(&with(r#","threshold":3"#)).unwrap().threshold,
            Some(3)
        );
        for bad in ["0", "1"] {
            let err = decode(&with(&format!(r#","threshold":{bad}"#))).unwrap_err();
            assert!(err.contains("threshold"), "{err}");
        }
    }

    #[test]
    fn an_unknown_role_is_rejected() {
        let json = format!(
            r#"{{"replicas":{{"channel_id":"21","shared_key":{KEY},"members":[
                {{"replica_id":"1","transports":[],"role":"source"}}]}}}}"#
        );
        assert!(decode(&json).unwrap_err().contains("replica.role"));
    }
}
