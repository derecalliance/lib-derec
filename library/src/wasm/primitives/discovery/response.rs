// SPDX-License-Identifier: Apache-2.0

use crate::{
    primitives::discovery::response::{
        self, SecretVersionEntry as DomainSecretVersionEntry, VersionEntry as DomainVersionEntry,
    },
    wasm::{
        primitives::{
            helpers::{from_js, parse_shared_key, to_js},
            types::{DeRecResult, Timestamp},
        },
        ts_bindings_utils::js_error_from_lib,
    },
};
use derec_proto::get_secret_ids_versions_response_message::{
    VersionList as VersionListProto, version_list::VersionEntry as VersionListEntryProto,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionListEntry {
    pub version: u32,
    pub version_description: String,
    /// Optional `replica_id` of the writer. `null` on the JS side
    /// means a non-replica Owner produced this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<VersionListEntryProto> for VersionListEntry {
    fn from(value: VersionListEntryProto) -> Self {
        Self {
            version: value.version,
            version_description: value.version_description,
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionList {
    pub secret_id: u64,
    pub versions: Vec<VersionListEntry>,
}

impl From<VersionListProto> for VersionList {
    fn from(value: VersionListProto) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetSecretIdsVersionsResponseMessage {
    pub result: Option<DeRecResult>,
    pub secret_list: Vec<VersionList>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::GetSecretIdsVersionsResponseMessage>
    for GetSecretIdsVersionsResponseMessage
{
    fn from(value: derec_proto::GetSecretIdsVersionsResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_list: value.secret_list.into_iter().map(Into::into).collect(),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<GetSecretIdsVersionsResponseMessage>
    for derec_proto::GetSecretIdsVersionsResponseMessage
{
    fn from(value: GetSecretIdsVersionsResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_list: value
                .secret_list
                .into_iter()
                .map(|v| VersionListProto {
                    secret_id: v.secret_id,
                    versions: v
                        .versions
                        .into_iter()
                        .map(|e| VersionListEntryProto {
                            version: e.version,
                            version_description: e.version_description,
                            replica_id: e.replica_id,
                        })
                        .collect(),
                })
                .collect(),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionEntry {
    pub version: u32,
    pub description: String,
    /// Optional `replica_id` of the writer. `null` on the JS side means
    /// a non-replica Owner produced this version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<DomainVersionEntry> for VersionEntry {
    fn from(value: DomainVersionEntry) -> Self {
        Self {
            version: value.version,
            description: value.description,
            replica_id: value.replica_id,
        }
    }
}

impl From<VersionEntry> for DomainVersionEntry {
    fn from(value: VersionEntry) -> Self {
        Self {
            version: value.version,
            description: value.description,
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretVersionEntry {
    pub secret_id: u64,
    pub versions: Vec<VersionEntry>,
}

impl From<DomainSecretVersionEntry> for SecretVersionEntry {
    fn from(value: DomainSecretVersionEntry) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SecretVersionEntry> for DomainSecretVersionEntry {
    fn from(value: SecretVersionEntry) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ProduceResult {
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtractResult {
    pub response: GetSecretIdsVersionsResponseMessage,
}

#[derive(Serialize, Deserialize)]
pub struct ProcessResult {
    pub secret_list: Vec<SecretVersionEntry>,
}

#[wasm_bindgen(js_name = "discovery_response_produce")]
pub fn produce(
    channel_id: u64,
    secret_list: JsValue,
    shared_key: &[u8],
) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;

    let entries: Vec<SecretVersionEntry> = from_js(secret_list)?;
    let secret_list: Vec<DomainSecretVersionEntry> = entries.into_iter().map(Into::into).collect();

    let result = response::produce(channel_id.into(), &secret_list, &shared_key)
        .map_err(js_error_from_lib)?;

    to_js(&ProduceResult {
        envelope: result.envelope,
    })
}

#[wasm_bindgen(js_name = "discovery_response_extract")]
pub fn extract(envelope_bytes: &[u8], shared_key: &[u8]) -> Result<JsValue, JsValue> {
    let shared_key = parse_shared_key(shared_key)?;
    let result = response::extract(envelope_bytes, &shared_key).map_err(js_error_from_lib)?;
    to_js(&ExtractResult {
        response: result.response.into(),
    })
}

#[wasm_bindgen(js_name = "discovery_response_process")]
pub fn process(response: JsValue) -> Result<JsValue, JsValue> {
    let response: GetSecretIdsVersionsResponseMessage = from_js(response)?;
    let response_proto: derec_proto::GetSecretIdsVersionsResponseMessage = response.into();

    let result = response::process(&response_proto).map_err(js_error_from_lib)?;

    let secret_list: Vec<SecretVersionEntry> =
        result.secret_list.into_iter().map(Into::into).collect();

    to_js(&ProcessResult { secret_list })
}
