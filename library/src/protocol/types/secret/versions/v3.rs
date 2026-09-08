// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Version 3 payload: gzip-compressed JSON, same conventions as v2 — byte
//! fields are standard-padded base64 (RFC 4648 §4), `u64` fields are decimal
//! strings, keys are snake_case, optional keys omitted when absent/empty.
//!
//! # What changed from v2
//!
//! A roster entry carries `transports`: every endpoint the peer advertised,
//! each with its protocol discriminant, instead of v2's single
//! `transport_uri` string.
//!
//! Two reasons. A peer reachable on several transports could not be
//! represented at all, so recovery silently narrowed it to one. And storing
//! a bare URI forced the discriminant to be *reconstructed* from the scheme
//! on every rehydration — which quietly rewrote every non-HTTPS peer. The
//! discriminant now travels with the endpoint, so nothing infers it.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};

use crate::protocol::types::secret::SecretError;
use crate::protocol::types::{HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret};

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

#[derive(Serialize, Deserialize)]
struct SecretJson {
    #[serde(default)]
    helpers: Vec<HelperJson>,
    #[serde(default)]
    secrets: Vec<UserSecretJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replicas: Option<ReplicasJson>,
}

/// One advertised endpoint. `protocol` is the `Protocol` discriminant, the
/// same `i32` the wire type carries, so no mapping is inferred on either side.
#[derive(Serialize, Deserialize)]
struct EndpointJson {
    uri: String,
    protocol: i32,
}

impl From<&derec_proto::TransportProtocol> for EndpointJson {
    fn from(t: &derec_proto::TransportProtocol) -> Self {
        EndpointJson {
            uri: t.uri.clone(),
            protocol: t.protocol,
        }
    }
}

impl From<EndpointJson> for derec_proto::TransportProtocol {
    fn from(j: EndpointJson) -> Self {
        derec_proto::TransportProtocol {
            uri: j.uri,
            protocol: j.protocol,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct HelperJson {
    #[serde(with = "u64_string")]
    channel_id: u64,
    #[serde(default)]
    transports: Vec<EndpointJson>,
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
    #[serde(default)]
    transports: Vec<EndpointJson>,
    role: ReplicaRole,
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
        }
    }
}

impl From<&HelperInfo> for HelperJson {
    fn from(h: &HelperInfo) -> Self {
        HelperJson {
            channel_id: h.channel_id,
            transports: h.transports.iter().map(EndpointJson::from).collect(),
            shared_key: h.shared_key.clone(),
            communication_info: h.communication_info.clone(),
        }
    }
}

impl From<HelperJson> for HelperInfo {
    fn from(j: HelperJson) -> Self {
        HelperInfo {
            channel_id: j.channel_id,
            transports: j.transports.into_iter().map(Into::into).collect(),
            shared_key: j.shared_key,
            communication_info: j.communication_info,
        }
    }
}

impl From<&UserSecret> for UserSecretJson {
    fn from(s: &UserSecret) -> Self {
        UserSecretJson {
            id: s.id.clone(),
            name: s.name.clone(),
            data: s.data.clone(),
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
            channel_id: r.channel_id,
            shared_key: r.shared_key.clone(),
            members: r.members.iter().map(ReplicaInfoJson::from).collect(),
        }
    }
}

impl From<ReplicasJson> for Replicas {
    fn from(j: ReplicasJson) -> Self {
        Replicas {
            channel_id: j.channel_id,
            shared_key: j.shared_key,
            members: j.members.into_iter().map(ReplicaInfo::from).collect(),
        }
    }
}

impl From<&ReplicaInfo> for ReplicaInfoJson {
    fn from(r: &ReplicaInfo) -> Self {
        ReplicaInfoJson {
            replica_id: r.replica_id,
            transports: r.transports.iter().map(EndpointJson::from).collect(),
            // An out-of-range discriminant cannot reach the wire: the roster
            // is built from `ReplicaMember` rows, whose role is typed.
            role: ReplicaRole::from_i32(r.role).unwrap_or(ReplicaRole::Destination),
            communication_info: r.communication_info.clone(),
        }
    }
}

impl From<ReplicaInfoJson> for ReplicaInfo {
    fn from(j: ReplicaInfoJson) -> Self {
        ReplicaInfo {
            replica_id: j.replica_id,
            transports: j.transports.into_iter().map(Into::into).collect(),
            role: j.role as i32,
            communication_info: j.communication_info,
        }
    }
}

/// Encode the v3 payload (no version prefix): gzip-compressed JSON.
pub fn encode(secret: &Secret) -> Vec<u8> {
    let dto = SecretJson::from(secret);
    let json =
        serde_json::to_vec(&dto).expect("Secret JSON serialization is infallible for owned data");
    gzip(&json)
}

/// Decode a v3 payload (no version prefix) back into a [`Secret`].
pub fn decode(payload: &[u8]) -> Result<Secret, SecretError> {
    let json = gunzip(payload)?;
    let dto: SecretJson = serde_json::from_slice(&json)?;
    Ok(Secret::from(dto))
}

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

fn de_map<'de, D>(d: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<HashMap<String, String>>::deserialize(d)?.unwrap_or_default())
}
