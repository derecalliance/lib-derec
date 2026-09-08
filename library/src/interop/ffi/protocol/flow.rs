// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! JSON decoder for [`DeRecFlow`] params passed via the FFI
//! `derec_protocol_start` entry point.
//!
//! The dotnet caller serializes the flow params as a JSON object with
//! shape matching the per-variant struct below. The Rust side decodes
//! and constructs the matching `DeRecFlow` value.
//!
//! Targeting convention (mirrors the WASM bridge): the `target` JSON
//! field is either `null` (= [`Target::All`]), a single u64 string
//! (= [`Target::Single`]), or an array of u64 strings
//! (= [`Target::Many`]). u64s travel as decimal strings to dodge
//! JavaScript's 53-bit integer ceiling — dotnet just serialises them
//! the same way.

use std::collections::HashMap;

use derec_proto::{ContactMessage, SenderKind, TransportProtocol};
use prost::Message as _;
use serde::Deserialize;
use serde_json::Value;

use crate::protocol::DeRecFlow;
use crate::protocol::types::{Target, UserSecret};
use crate::types::ChannelId;

/// Numeric flow-kind identifiers — must match the dotnet `FlowKind` enum.
pub const FLOW_KIND_PAIRING: u32 = 0;
pub const FLOW_KIND_DISCOVERY: u32 = 1;
pub const FLOW_KIND_PROTECT_SECRET: u32 = 2;
pub const FLOW_KIND_VERIFY_SHARES: u32 = 3;
pub const FLOW_KIND_RECOVER_SECRET: u32 = 4;
pub const FLOW_KIND_UNPAIR: u32 = 5;
pub const FLOW_KIND_UPDATE_CHANNEL_INFO: u32 = 6;
/// Replica catch-up. Takes no parameters: the group and this device's own
/// version are both read from the stores.
pub const FLOW_KIND_REPLICA_DISCOVERY: u32 = 7;
/// Remove a member from the replica group. Params:
/// `{ "replica_id": "<decimal>", "memo": "<optional>" }`.
pub const FLOW_KIND_UNPAIR_REPLICA: u32 = 8;

/// Top-level dispatcher — picks the right decoder based on `flow_kind`.
pub fn parse_flow(flow_kind: u32, params_json: &[u8]) -> Result<DeRecFlow, String> {
    match flow_kind {
        FLOW_KIND_PAIRING => parse_pairing_flow(params_json),
        FLOW_KIND_DISCOVERY => parse_discovery_flow(params_json),
        FLOW_KIND_PROTECT_SECRET => parse_protect_secret_flow(params_json),
        FLOW_KIND_VERIFY_SHARES => parse_verify_shares_flow(params_json),
        FLOW_KIND_RECOVER_SECRET => parse_recover_secret_flow(params_json),
        FLOW_KIND_UNPAIR => parse_unpair_flow(params_json),
        FLOW_KIND_UPDATE_CHANNEL_INFO => parse_update_channel_info_flow(params_json),
        FLOW_KIND_REPLICA_DISCOVERY => Ok(DeRecFlow::ReplicaDiscovery),
        FLOW_KIND_UNPAIR_REPLICA => parse_unpair_replica_flow(params_json),
        other => Err(format!("unknown FlowKind: {other}")),
    }
}

fn parse_pairing_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: PairingParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid PairingParams JSON: {e}"))?;
    let kind = sender_kind_from_i32(raw.kind)?;
    let contact = ContactMessage::decode(raw.contact.as_slice())
        .map_err(|e| format!("invalid ContactMessage proto bytes: {e}"))?;
    let peer_communication_info = raw.peer_communication_info.unwrap_or_default();
    Ok(DeRecFlow::Pairing {
        kind,
        contact,
        peer_communication_info,
    })
}

fn parse_discovery_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: DiscoveryParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid DiscoveryParams JSON: {e}"))?;
    Ok(DeRecFlow::Discovery {
        target: parse_target(raw.target)?,
    })
}

fn parse_protect_secret_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: ProtectSecretParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid ProtectSecretParams JSON: {e}"))?;
    let secrets: Vec<UserSecret> = raw
        .secrets
        .into_iter()
        .map(|s| UserSecret {
            id: s.id,
            name: s.name,
            data: s.data,
        })
        .collect();
    Ok(DeRecFlow::ProtectSecret {
        secrets,
        description: raw.description,
    })
}

fn parse_verify_shares_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: VerifySharesParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid VerifySharesParams JSON: {e}"))?;
    Ok(DeRecFlow::VerifyShares {
        secret_id: parse_u64_string(&raw.secret_id)?,
        version: raw.version,
        target: parse_target(raw.target)?,
    })
}

fn parse_recover_secret_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: RecoverSecretParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid RecoverSecretParams JSON: {e}"))?;
    Ok(DeRecFlow::RecoverSecret {
        secret_id: parse_u64_string(&raw.secret_id)?,
        version: raw.version,
    })
}

fn parse_unpair_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: UnpairParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid UnpairParams JSON: {e}"))?;
    Ok(DeRecFlow::Unpair {
        channel_id: ChannelId(parse_u64_string(&raw.channel_id)?),
        memo: raw.memo,
    })
}

fn parse_update_channel_info_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: UpdateChannelInfoParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid UpdateChannelInfoParams JSON: {e}"))?;
    // The list wins when present; the singular field is the compatibility
    // spelling an SDK predating it still sends.
    let own_transports: Vec<TransportProtocol> = if raw.own_transports.is_empty() {
        raw.transport_protocol
            .into_iter()
            .map(|t| TransportProtocol {
                uri: t.uri,
                protocol: t.protocol,
            })
            .collect()
    } else {
        raw.own_transports
            .into_iter()
            .map(|t| TransportProtocol {
                uri: t.uri,
                protocol: t.protocol,
            })
            .collect()
    };
    Ok(DeRecFlow::UpdateChannelInfo {
        target: parse_target(raw.target)?,
        communication_info: raw.communication_info,
        own_transports,
    })
}

fn sender_kind_from_i32(kind: i32) -> Result<SenderKind, String> {
    match kind {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        3 => Ok(SenderKind::ReplicaSource),
        4 => Ok(SenderKind::ReplicaDestination),
        other => Err(format!("invalid SenderKind: {other}")),
    }
}

fn parse_u64_string(s: &str) -> Result<u64, String> {
    s.parse::<u64>()
        .map_err(|e| format!("expected decimal u64 string, got {s:?}: {e}"))
}

fn parse_target(value: Option<Value>) -> Result<Target, String> {
    match value {
        None | Some(Value::Null) => Ok(Target::All),
        Some(Value::String(s)) => Ok(Target::Single(ChannelId(parse_u64_string(&s)?))),
        Some(Value::Number(n)) => {
            let id = n
                .as_u64()
                .ok_or_else(|| format!("Target number {n} is not a u64"))?;
            Ok(Target::Single(ChannelId(id)))
        }
        Some(Value::Array(arr)) => {
            let mut ids = Vec::with_capacity(arr.len());
            for item in arr {
                let id = match item {
                    Value::String(s) => parse_u64_string(&s)?,
                    Value::Number(n) => n
                        .as_u64()
                        .ok_or_else(|| format!("Target array item {n} is not a u64"))?,
                    other => return Err(format!("Target array item must be u64, got {other:?}")),
                };
                ids.push(ChannelId(id));
            }
            Ok(Target::Many(ids))
        }
        Some(other) => Err(format!(
            "Target must be null, u64 string, or u64 array — got {other:?}"
        )),
    }
}

#[derive(Deserialize)]
struct PairingParamsJson {
    kind: i32,
    contact: Vec<u8>,
    #[serde(default)]
    peer_communication_info: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
struct DiscoveryParamsJson {
    #[serde(default)]
    target: Option<Value>,
}

#[derive(Deserialize)]
struct ProtectSecretParamsJson {
    secrets: Vec<UserSecretJson>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Deserialize)]
struct UserSecretJson {
    id: Vec<u8>,
    name: String,
    data: Vec<u8>,
}

#[derive(Deserialize)]
struct VerifySharesParamsJson {
    secret_id: String,
    version: u32,
    #[serde(default)]
    target: Option<Value>,
}

#[derive(Deserialize)]
struct RecoverSecretParamsJson {
    secret_id: String,
    version: u32,
}

#[derive(Deserialize)]
struct UnpairParamsJson {
    channel_id: String,
    #[serde(default)]
    memo: Option<String>,
}

#[derive(Deserialize)]
struct UpdateChannelInfoParamsJson {
    #[serde(default)]
    target: Option<Value>,
    #[serde(default)]
    communication_info: Option<HashMap<String, String>>,
    /// Deprecated: superseded by `own_transports`. Accepted so an SDK
    /// predating the list keeps working; removal is scheduled for v0.0.5.
    #[serde(default)]
    transport_protocol: Option<TransportProtocolJson>,
    /// Every endpoint this device can now be reached on, in preference
    /// order. Takes precedence over the singular field above.
    #[serde(default)]
    own_transports: Vec<TransportProtocolJson>,
}

#[derive(Deserialize)]
struct TransportProtocolJson {
    uri: String,
    protocol: i32,
}

/// `{ "replica_id": "<decimal u64>", "memo": "<optional>" }` — `replica_id` is
/// a decimal string so values above 2^53 survive a JSON round trip through
/// hosts whose numbers are doubles.
fn parse_unpair_replica_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    #[derive(serde::Deserialize)]
    struct Params {
        replica_id: String,
        #[serde(default)]
        memo: Option<String>,
    }
    let p: Params = serde_json::from_slice(params_json)
        .map_err(|e| format!("UnpairReplica params JSON: {e}"))?;
    let replica_id = p
        .replica_id
        .parse::<u64>()
        .map_err(|e| format!("replica_id must be a decimal u64: {e}"))?;
    Ok(DeRecFlow::UnpairReplica {
        replica_id,
        memo: p.memo,
    })
}
