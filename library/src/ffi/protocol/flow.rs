// SPDX-License-Identifier: Apache-2.0

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
use crate::types::{ChannelId, Target, UserSecret};

/// Numeric flow-kind identifiers — must match the dotnet `FlowKind` enum.
pub const FLOW_KIND_PAIRING: u32 = 0;
pub const FLOW_KIND_DISCOVERY: u32 = 1;
pub const FLOW_KIND_PROTECT_SECRET: u32 = 2;
pub const FLOW_KIND_VERIFY_SHARES: u32 = 3;
pub const FLOW_KIND_RECOVER_SECRET: u32 = 4;
pub const FLOW_KIND_UNPAIR: u32 = 5;
pub const FLOW_KIND_UPDATE_CHANNEL_INFO: u32 = 6;

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
    let secret_id = parse_u64_string(&raw.secret_id)?;
    let target = parse_target(raw.target)?;
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
        secret_id,
        target,
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
        target: parse_target(raw.target)?,
        memo: raw.memo,
    })
}

fn parse_update_channel_info_flow(params_json: &[u8]) -> Result<DeRecFlow, String> {
    let raw: UpdateChannelInfoParamsJson = serde_json::from_slice(params_json)
        .map_err(|e| format!("invalid UpdateChannelInfoParams JSON: {e}"))?;
    let transport = raw
        .transport_protocol
        .map(|t| TransportProtocol {
            uri: t.uri,
            protocol: t.protocol,
        });
    Ok(DeRecFlow::UpdateChannelInfo {
        target: parse_target(raw.target)?,
        communication_info: raw.communication_info,
        transport_protocol: transport,
    })
}

// ─── Helpers ─────────────────────────────────────────────────────────

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

// ─── JSON wire shapes ────────────────────────────────────────────────

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
    secret_id: String,
    #[serde(default)]
    target: Option<Value>,
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
    #[serde(default)]
    target: Option<Value>,
    #[serde(default)]
    memo: Option<String>,
}

#[derive(Deserialize)]
struct UpdateChannelInfoParamsJson {
    #[serde(default)]
    target: Option<Value>,
    #[serde(default)]
    communication_info: Option<HashMap<String, String>>,
    #[serde(default)]
    transport_protocol: Option<TransportProtocolJson>,
}

#[derive(Deserialize)]
struct TransportProtocolJson {
    uri: String,
    protocol: i32,
}
