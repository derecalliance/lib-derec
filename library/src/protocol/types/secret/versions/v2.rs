// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Version 2 payload: gzip-compressed JSON. Byte fields are standard-padded
//! base64 (RFC 4648 §4), `u64` fields are decimal strings, keys are snake_case,
//! optional keys are omitted when absent/empty.

use std::collections::HashMap;
use std::io::Read as _;
#[cfg(test)]
use std::io::Write as _;

use flate2::read::GzDecoder;
#[cfg(test)]
use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};

use crate::protocol::types::secret::SecretError;
use crate::protocol::types::{HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret};

/// Only the tests build v2 payloads now — decoding is v2's whole remaining
/// job, so nothing in production compresses one.
#[cfg(test)]
fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)
        .expect("gzip write into Vec is infallible");
    enc.finish().expect("gzip finish into Vec is infallible")
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, SecretError> {
    let mut out = Vec::new();
    GzDecoder::new(data)
        .read_to_end(&mut out)
        .map_err(|_| SecretError::Decompression)?;
    Ok(out)
}

mod base64_bytes {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize as _, Deserializer, Serializer};

    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

mod u64_string {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

fn de_map<'de, D>(d: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<HashMap<String, String>>::deserialize(d)?.unwrap_or_default())
}

#[derive(Serialize, Deserialize)]
struct SecretJson {
    #[serde(default)]
    helpers: Vec<HelperJson>,
    #[serde(default)]
    secrets: Vec<UserSecretJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replicas: Option<ReplicasJson>,
}

#[derive(Serialize, Deserialize)]
struct HelperJson {
    #[serde(with = "u64_string")]
    channel_id: u64,
    transport_uri: String,
    #[serde(with = "base64_bytes")]
    shared_key: Vec<u8>,
    #[serde(
        default,
        deserialize_with = "de_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    communication_info: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct UserSecretJson {
    #[serde(with = "base64_bytes")]
    id: Vec<u8>,
    name: String,
    #[serde(with = "base64_bytes")]
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct ReplicasJson {
    #[serde(with = "u64_string")]
    channel_id: u64,
    #[serde(with = "base64_bytes")]
    shared_key: Vec<u8>,
    members: Vec<ReplicaInfoJson>,
}

#[derive(Serialize, Deserialize)]
struct ReplicaInfoJson {
    #[serde(with = "u64_string")]
    replica_id: u64,
    transport_uri: String,
    role: ReplicaRole,
    #[serde(
        default,
        deserialize_with = "de_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    communication_info: HashMap<String, String>,
}

impl From<SecretJson> for Secret {
    fn from(j: SecretJson) -> Self {
        Secret {
            helpers: j.helpers.into_iter().map(HelperInfo::from).collect(),
            secrets: j.secrets.into_iter().map(UserSecret::from).collect(),
            replicas: j.replicas.map(Replicas::from),
        }
    }
}

impl From<HelperJson> for HelperInfo {
    fn from(j: HelperJson) -> Self {
        HelperInfo {
            channel_id: j.channel_id,
            transports: lift_endpoint(&j.transport_uri),
            shared_key: j.shared_key,
            communication_info: j.communication_info,
        }
    }
}

impl From<UserSecretJson> for UserSecret {
    fn from(j: UserSecretJson) -> Self {
        UserSecret {
            id: j.id,
            name: j.name,
            data: j.data,
        }
    }
}

impl From<ReplicasJson> for Replicas {
    fn from(j: ReplicasJson) -> Self {
        Replicas {
            members: j.members.into_iter().map(ReplicaInfo::from).collect(),
            shared_key: j.shared_key,
            channel_id: j.channel_id,
        }
    }
}

impl From<ReplicaInfoJson> for ReplicaInfo {
    fn from(j: ReplicaInfoJson) -> Self {
        ReplicaInfo {
            replica_id: j.replica_id,
            transports: lift_endpoint(&j.transport_uri),
            role: j.role as i32,
            communication_info: j.communication_info,
        }
    }
}

/// Decode a v2 payload (no version prefix) back into a [`Secret`].
pub fn decode(payload: &[u8]) -> Result<Secret, SecretError> {
    let json = gunzip(payload)?;
    let dto: SecretJson = serde_json::from_slice(&json)?;
    Ok(Secret::from(dto))
}

/// Lift a v2 single-URI endpoint into the current list-of-endpoints shape.
///
/// v2 stored a bare `transport_uri`, so the protocol discriminant has to be
/// recovered from the scheme. That reconstruction is exactly what this
/// format's successor exists to retire — v3 stores the discriminant — but it
/// is sound here because a v2 roster could only ever have been written when
/// HTTPS was the only transport, or by a writer whose scheme still names its
/// protocol unambiguously.
///
/// An unparseable URI yields an empty list rather than a guessed endpoint:
/// a peer with no reachable endpoint is recoverable information, a peer with
/// a *wrong* one is not.
fn lift_endpoint(uri: &str) -> Vec<derec_proto::TransportProtocol> {
    match crate::transport::TransportProtocol::try_from(uri) {
        Ok(tp) => vec![tp.into()],
        Err(_error) => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                uri = %uri,
                error = %_error,
                "v2 roster entry has an unusable transport uri; recovering the \
                 peer without an endpoint rather than guessing one",
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::Protocol;

    /// Build a v2 payload the way a pre-0.0.3 writer would have: gzipped
    /// JSON with a single `transport_uri` string per roster entry.
    ///
    /// Written by hand rather than by a v2 encoder, because v2 can no longer
    /// encode — a multi-endpoint roster has no faithful v2 representation,
    /// and an encoder that silently dropped endpoints would be worse than
    /// none.
    fn v2_payload(helper_uri: &str, member_uri: &str) -> Vec<u8> {
        let json = format!(
            r#"{{
                "helpers": [{{
                    "channel_id": "7",
                    "transport_uri": "{helper_uri}",
                    "shared_key": "AAAA",
                    "communication_info": {{"name": "helper-a"}}
                }}],
                "secrets": [],
                "replicas": {{
                    "channel_id": "9",
                    "shared_key": "AAAA",
                    "members": [{{
                        "replica_id": "3",
                        "transport_uri": "{member_uri}",
                        "role": "Source",
                        "communication_info": {{}}
                    }}]
                }}
            }}"#
        );
        gzip(json.as_bytes())
    }

    /// The compatibility guarantee: a secret protected before multi-endpoint
    /// support still decodes, and each single URI becomes a one-element list.
    #[test]
    fn v2_payload_lifts_into_the_current_shape() {
        let secret = decode(&v2_payload(
            "https://helper-a.example/derec",
            "https://replica.example/derec",
        ))
        .expect("a v2 payload must still decode");

        assert_eq!(secret.helpers.len(), 1);
        assert_eq!(secret.helpers[0].channel_id, 7);
        assert_eq!(
            secret.helpers[0].transports,
            vec![derec_proto::TransportProtocol {
                uri: "https://helper-a.example/derec".to_owned(),
                protocol: Protocol::Https as i32,
            }],
        );

        let members = &secret.replicas.as_ref().expect("replicas present").members;
        assert_eq!(members.len(), 1);
        assert_eq!(
            members[0].transports[0].uri,
            "https://replica.example/derec"
        );
    }

    /// The discriminant comes from the scheme, so a v2 roster written by a
    /// gRPC-capable peer lifts to `Grpc` rather than being flattened to
    /// HTTPS — the failure that made v3 store the discriminant outright.
    #[test]
    fn v2_lift_derives_the_discriminant_from_the_scheme() {
        let secret = decode(&v2_payload(
            "grpcs://helper-a.example:443",
            "grpcs://replica.example:443",
        ))
        .expect("decodes");

        assert_eq!(
            secret.helpers[0].transports[0].protocol,
            Protocol::Grpc as i32
        );
        assert_eq!(
            secret.replicas.as_ref().unwrap().members[0].transports[0].protocol,
            Protocol::Grpc as i32,
        );
    }

    /// A URI whose scheme names no known transport cannot be lifted into a
    /// truthful endpoint. Recover the peer without one rather than inventing
    /// a protocol for it.
    #[test]
    fn v2_lift_drops_an_unusable_uri_rather_than_guessing() {
        let secret = decode(&v2_payload(
            "ws://helper-a.example",
            "https://replica.example",
        ))
        .expect("decodes");

        assert!(secret.helpers[0].transports.is_empty());
        assert_eq!(
            secret.replicas.as_ref().unwrap().members[0]
                .transports
                .len(),
            1,
            "one bad entry must not affect the others"
        );
    }

    #[test]
    fn a_truncated_payload_is_an_error_not_a_panic() {
        assert!(decode(b"not gzip").is_err());
    }
}
