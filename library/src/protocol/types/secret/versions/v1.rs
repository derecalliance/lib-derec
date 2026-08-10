// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Version 1 payload: gzip-compressed JSON. Byte fields are standard-padded
//! base64 (RFC 4648 §4), `u64` fields are decimal strings, keys are snake_case,
//! optional keys are omitted when absent/empty.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};

use crate::protocol::types::secret::SecretError;
use crate::protocol::types::{HelperInfo, ReplicaInfo, Replicas, Secret, UserSecret};

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
    #[serde(with = "u64_string")]
    owner_replica_id: u64,
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
    #[serde(with = "base64_bytes")]
    shared_key: Vec<u8>,
    replicas: Vec<ReplicaInfoJson>,
}

#[derive(Serialize, Deserialize)]
struct ReplicaInfoJson {
    #[serde(with = "u64_string")]
    channel_id: u64,
    transport_uri: String,
    #[serde(with = "u64_string")]
    replica_id: u64,
    sender_kind: i32,
    #[serde(
        default,
        deserialize_with = "de_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    communication_info: HashMap<String, String>,
}

impl From<&Secret> for SecretJson {
    fn from(s: &Secret) -> Self {
        SecretJson {
            owner_replica_id: s.owner_replica_id,
            helpers: s.helpers.iter().map(HelperJson::from).collect(),
            secrets: s.secrets.iter().map(UserSecretJson::from).collect(),
            replicas: s.replicas.as_ref().map(ReplicasJson::from),
        }
    }
}

impl From<SecretJson> for Secret {
    fn from(j: SecretJson) -> Self {
        Secret {
            helpers: j.helpers.into_iter().map(HelperInfo::from).collect(),
            secrets: j.secrets.into_iter().map(UserSecret::from).collect(),
            replicas: j.replicas.map(Replicas::from),
            owner_replica_id: j.owner_replica_id,
        }
    }
}

impl From<&HelperInfo> for HelperJson {
    fn from(h: &HelperInfo) -> Self {
        HelperJson {
            channel_id: h.channel_id,
            transport_uri: h.transport_uri.clone(),
            shared_key: h.shared_key.clone(),
            communication_info: h.communication_info.clone(),
        }
    }
}
impl From<HelperJson> for HelperInfo {
    fn from(j: HelperJson) -> Self {
        HelperInfo {
            channel_id: j.channel_id,
            transport_uri: j.transport_uri,
            shared_key: j.shared_key,
            communication_info: j.communication_info,
        }
    }
}

impl From<&UserSecret> for UserSecretJson {
    fn from(u: &UserSecret) -> Self {
        UserSecretJson {
            id: u.id.clone(),
            name: u.name.clone(),
            data: u.data.clone(),
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

impl From<&Replicas> for ReplicasJson {
    fn from(r: &Replicas) -> Self {
        ReplicasJson {
            shared_key: r.shared_key.clone(),
            replicas: r.replicas.iter().map(ReplicaInfoJson::from).collect(),
        }
    }
}
impl From<ReplicasJson> for Replicas {
    fn from(j: ReplicasJson) -> Self {
        Replicas {
            replicas: j.replicas.into_iter().map(ReplicaInfo::from).collect(),
            shared_key: j.shared_key,
        }
    }
}

impl From<&ReplicaInfo> for ReplicaInfoJson {
    fn from(r: &ReplicaInfo) -> Self {
        ReplicaInfoJson {
            channel_id: r.channel_id,
            transport_uri: r.transport_uri.clone(),
            replica_id: r.replica_id,
            sender_kind: r.sender_kind,
            communication_info: r.communication_info.clone(),
        }
    }
}
impl From<ReplicaInfoJson> for ReplicaInfo {
    fn from(j: ReplicaInfoJson) -> Self {
        ReplicaInfo {
            channel_id: j.channel_id,
            transport_uri: j.transport_uri,
            communication_info: j.communication_info,
            replica_id: j.replica_id,
            sender_kind: j.sender_kind,
        }
    }
}

/// Encode the v1 payload (no version prefix): gzip-compressed JSON.
pub fn encode(secret: &Secret) -> Vec<u8> {
    let dto = SecretJson::from(secret);
    let json =
        serde_json::to_vec(&dto).expect("Secret JSON serialization is infallible for owned data");
    gzip(&json)
}

/// Decode a v1 payload (no version prefix) back into a [`Secret`].
pub fn decode(payload: &[u8]) -> Result<Secret, SecretError> {
    let json = gunzip(payload)?;
    let dto: SecretJson = serde_json::from_slice(&json)?;
    Ok(Secret::from(dto))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_secret() -> Secret {
        Secret {
            helpers: vec![HelperInfo {
                channel_id: 1_000_000,
                transport_uri: "https://helper-0.example.org/derec".to_owned(),
                shared_key: vec![0xAA; 32],
                communication_info: HashMap::from([("name".to_owned(), "Helper 0".to_owned())]),
            }],
            secrets: vec![UserSecret {
                id: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                name: "Gmail".to_owned(),
                data: b"correct horse battery staple".to_vec(),
            }],
            replicas: Some(Replicas {
                replicas: vec![ReplicaInfo {
                    channel_id: 2_000_000,
                    transport_uri: "https://replica-0.example.org/derec".to_owned(),
                    communication_info: HashMap::new(),
                    replica_id: 900_000,
                    sender_kind: 0,
                }],
                shared_key: vec![0x55; 32],
            }),
            owner_replica_id: 0xAAAA_BBBB,
        }
    }

    #[test]
    fn payload_round_trips() {
        let secret = full_secret();
        assert_eq!(decode(&encode(&secret)).unwrap(), secret);
    }

    #[test]
    fn u64_fields_survive_beyond_2_pow_53() {
        let mut secret = full_secret();
        secret.owner_replica_id = u64::MAX;
        secret.helpers[0].channel_id = (1u64 << 53) + 7;
        let decoded = decode(&encode(&secret)).expect("large u64 must round-trip");
        assert_eq!(decoded.owner_replica_id, u64::MAX);
        assert_eq!(decoded.helpers[0].channel_id, (1u64 << 53) + 7);
    }

    #[test]
    fn omits_absent_and_empty_fields() {
        let mut secret = full_secret();
        secret.replicas = None;
        secret.helpers[0].communication_info.clear();
        let json = String::from_utf8(gunzip(&encode(&secret)).unwrap()).unwrap();
        assert!(
            !json.contains("replicas"),
            "absent replicas must be omitted"
        );
        assert!(
            !json.contains("communication_info"),
            "empty communication_info must be omitted"
        );
        assert!(
            !json.contains("version"),
            "v1 JSON must not carry a version field"
        );
    }

    #[test]
    fn payload_rejects_non_gzip() {
        let err = decode(&[0x01, 0x02, 0x03]).expect_err("non-gzip must fail");
        assert!(matches!(err, SecretError::Decompression));
    }

    #[test]
    fn decoder_tolerates_null_and_missing_optional_fields() {
        let json = br#"{"owner_replica_id":"5","helpers":[{"channel_id":"2","transport_uri":"u","shared_key":"qqqqqg==","communication_info":null}]}"#;
        let decoded = decode(&gzip(json)).expect("null/absent optionals must decode");
        assert!(decoded.replicas.is_none());
        assert!(decoded.secrets.is_empty());
        assert!(decoded.helpers[0].communication_info.is_empty());
    }
}
