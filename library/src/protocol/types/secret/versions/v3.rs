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
    /// Absent on a roster written before the threshold was recorded.
    #[serde(
        default,
        deserialize_with = "de_threshold",
        skip_serializing_if = "Option::is_none"
    )]
    threshold: Option<u32>,
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
    /// Absent means `1`, so a roster written before weights existed and one
    /// where every Helper holds one subshare encode identically.
    #[serde(
        default,
        deserialize_with = "de_weight",
        skip_serializing_if = "Option::is_none"
    )]
    weight: Option<u32>,
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
            threshold: s.threshold,
        }
    }
}

impl From<SecretJson> for Secret {
    fn from(j: SecretJson) -> Self {
        Secret {
            helpers: j.helpers.into_iter().map(HelperInfo::from).collect(),
            secrets: j.secrets.into_iter().map(UserSecret::from).collect(),
            replicas: j.replicas.map(Replicas::from),
            threshold: j.threshold,
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
            weight: Some(h.effective_weight()).filter(|&w| w != 1),
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
            weight: j.weight.unwrap_or(1),
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

/// A present `weight` must be at least `1`: a Helper that received no
/// subshare is not part of the roster.
fn de_weight<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    match Option::<u32>::deserialize(d)? {
        Some(0) => Err(serde::de::Error::custom("helper weight must be at least 1")),
        other => Ok(other),
    }
}

/// A present `threshold` must be at least `2`: below that, a single subshare
/// reconstructs the secret.
fn de_threshold<'de, D>(d: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    match Option::<u32>::deserialize(d)? {
        Some(t) if t < 2 => Err(serde::de::Error::custom("threshold must be at least 2")),
        other => Ok(other),
    }
}

fn de_map<'de, D>(d: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    Ok(Option::<HashMap<String, String>>::deserialize(d)?.unwrap_or_default())
}

#[cfg(test)]
mod weight_tests {
    use super::*;

    fn helper(weight: u32) -> HelperInfo {
        HelperInfo {
            channel_id: 2,
            transports: vec![derec_proto::TransportProtocol {
                uri: "https://h.example/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            shared_key: vec![1, 2, 3],
            communication_info: HashMap::new(),
            weight,
        }
    }

    fn secret_with(weight: u32) -> Secret {
        Secret {
            helpers: vec![helper(weight)],
            secrets: Vec::new(),
            replicas: None,
            threshold: None,
        }
    }

    fn json_of(secret: &Secret) -> serde_json::Value {
        serde_json::from_slice(&gunzip(&encode(secret)).unwrap()).unwrap()
    }

    fn decode_json(json: &str) -> Result<Secret, SecretError> {
        decode(&gzip(json.as_bytes()))
    }

    const HELPER_PREFIX: &str =
        r#"{"helpers":[{"channel_id":"2","transports":[],"shared_key":"AQID""#;

    #[test]
    fn a_weight_of_one_is_omitted() {
        let json = json_of(&secret_with(1));
        assert!(json["helpers"][0].get("weight").is_none(), "{json}");
    }

    #[test]
    fn a_weight_above_one_round_trips() {
        let secret = secret_with(3);
        assert_eq!(json_of(&secret)["helpers"][0]["weight"], 3);
        assert_eq!(decode(&encode(&secret)).unwrap(), secret);
    }

    #[test]
    fn an_absent_weight_decodes_as_one() {
        let secret = decode_json(&format!("{HELPER_PREFIX}}}]}}")).unwrap();
        assert_eq!(secret.helpers[0].weight, 1);
        let secret = decode_json(&format!("{HELPER_PREFIX},\"weight\":null}}]}}")).unwrap();
        assert_eq!(secret.helpers[0].weight, 1);
    }

    #[test]
    fn a_weight_of_zero_is_malformed() {
        let err = decode_json(&format!("{HELPER_PREFIX},\"weight\":0}}]}}"))
            .expect_err("a helper holding no subshare is not a roster entry");
        assert!(matches!(err, SecretError::Json(_)), "{err:?}");
    }
}

#[cfg(test)]
mod threshold_tests {
    use super::*;

    fn secret_with(threshold: Option<u32>) -> Secret {
        Secret {
            helpers: Vec::new(),
            secrets: Vec::new(),
            replicas: None,
            threshold,
        }
    }

    fn json_of(secret: &Secret) -> serde_json::Value {
        serde_json::from_slice(&gunzip(&encode(secret)).unwrap()).unwrap()
    }

    fn decode_json(json: &str) -> Result<Secret, SecretError> {
        decode(&gzip(json.as_bytes()))
    }

    #[test]
    fn an_absent_threshold_is_omitted_and_decodes_as_none() {
        let json = json_of(&secret_with(None));
        assert!(json.get("threshold").is_none(), "{json}");
        assert_eq!(decode_json(r#"{"helpers":[]}"#).unwrap().threshold, None);
        assert_eq!(
            decode_json(r#"{"helpers":[],"threshold":null}"#)
                .unwrap()
                .threshold,
            None
        );
    }

    #[test]
    fn a_threshold_round_trips() {
        let secret = secret_with(Some(3));
        assert_eq!(json_of(&secret)["threshold"], 3);
        assert_eq!(decode(&encode(&secret)).unwrap(), secret);
    }

    #[test]
    fn a_threshold_below_two_is_malformed() {
        for t in [0, 1] {
            let err = decode_json(&format!(r#"{{"helpers":[],"threshold":{t}}}"#))
                .expect_err("a threshold below 2 lets one subshare recover the secret");
            assert!(matches!(err, SecretError::Json(_)), "{err:?}");
        }
    }
}
