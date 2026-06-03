// SPDX-License-Identifier: Apache-2.0

pub mod request;
pub mod response;

use crate::wasm::{primitives::types::Timestamp, ts_bindings_utils::js_error};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::SenderKind;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Clone)]
pub struct TransportProtocol {
    pub uri: String,
    pub protocol: i32,
}

impl From<derec_proto::TransportProtocol> for TransportProtocol {
    fn from(value: derec_proto::TransportProtocol) -> Self {
        Self {
            uri: value.uri,
            protocol: value.protocol,
        }
    }
}

impl From<TransportProtocol> for derec_proto::TransportProtocol {
    fn from(value: TransportProtocol) -> Self {
        Self {
            uri: value.uri,
            protocol: value.protocol,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommunicationInfoKeyValue {
    pub key: String,
    pub string_value: Option<String>,
    #[serde(with = "serde_bytes", default)]
    pub bytes_value: Option<Vec<u8>>,
}

impl From<derec_proto::CommunicationInfoKeyValue> for CommunicationInfoKeyValue {
    fn from(value: derec_proto::CommunicationInfoKeyValue) -> Self {
        use derec_proto::communication_info_key_value::Value as OneofValue;
        let (string_value, bytes_value) = match value.value {
            Some(OneofValue::StringValue(s)) => (Some(s), None),
            Some(OneofValue::BytesValue(b)) => (None, Some(b)),
            None => (None, None),
        };
        Self {
            key: value.key,
            string_value,
            bytes_value,
        }
    }
}

impl From<CommunicationInfoKeyValue> for derec_proto::CommunicationInfoKeyValue {
    fn from(value: CommunicationInfoKeyValue) -> Self {
        use derec_proto::communication_info_key_value::Value as OneofValue;
        let oneof = match (value.string_value, value.bytes_value) {
            (Some(s), _) => Some(OneofValue::StringValue(s)),
            (None, Some(b)) => Some(OneofValue::BytesValue(b)),
            (None, None) => None,
        };
        Self {
            key: value.key,
            value: oneof,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommunicationInfo {
    pub communication_info_entries: Vec<CommunicationInfoKeyValue>,
}

impl From<derec_proto::CommunicationInfo> for CommunicationInfo {
    fn from(value: derec_proto::CommunicationInfo) -> Self {
        Self {
            communication_info_entries: value
                .communication_info_entries
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl From<CommunicationInfo> for derec_proto::CommunicationInfo {
    fn from(value: CommunicationInfo) -> Self {
        Self {
            communication_info_entries: value
                .communication_info_entries
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ParameterRange {
    pub min_share_size: i64,
    pub max_share_size: i64,
    pub min_time_between_verifications: i64,
    pub max_time_between_verifications: i64,
    pub min_time_between_share_updates: i64,
    pub max_time_between_share_updates: i64,
    pub min_unresponsive_deletion_timeout: i64,
    pub max_unresponsive_deletion_timeout: i64,
    pub min_unresponsive_deactivation_timeout: i64,
    pub max_unresponsive_deactivation_timeout: i64,
}

impl From<derec_proto::ParameterRange> for ParameterRange {
    fn from(value: derec_proto::ParameterRange) -> Self {
        Self {
            min_share_size: value.min_share_size,
            max_share_size: value.max_share_size,
            min_time_between_verifications: value.min_time_between_verifications,
            max_time_between_verifications: value.max_time_between_verifications,
            min_time_between_share_updates: value.min_time_between_share_updates,
            max_time_between_share_updates: value.max_time_between_share_updates,
            min_unresponsive_deletion_timeout: value.min_unresponsive_deletion_timeout,
            max_unresponsive_deletion_timeout: value.max_unresponsive_deletion_timeout,
            min_unresponsive_deactivation_timeout: value.min_unresponsive_deactivation_timeout,
            max_unresponsive_deactivation_timeout: value.max_unresponsive_deactivation_timeout,
        }
    }
}

impl From<ParameterRange> for derec_proto::ParameterRange {
    fn from(value: ParameterRange) -> Self {
        Self {
            min_share_size: value.min_share_size,
            max_share_size: value.max_share_size,
            min_time_between_verifications: value.min_time_between_verifications,
            max_time_between_verifications: value.max_time_between_verifications,
            min_time_between_share_updates: value.min_time_between_share_updates,
            max_time_between_share_updates: value.max_time_between_share_updates,
            min_unresponsive_deletion_timeout: value.min_unresponsive_deletion_timeout,
            max_unresponsive_deletion_timeout: value.max_unresponsive_deletion_timeout,
            min_unresponsive_deactivation_timeout: value.min_unresponsive_deactivation_timeout,
            max_unresponsive_deactivation_timeout: value.max_unresponsive_deactivation_timeout,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContactMessage {
    pub channel_id: u64,
    pub transport_protocol: Option<TransportProtocol>,
    pub nonce: u64,
    /// `i32` matching `derec_proto::ContactMode` (0 = INLINE_KEYS, 1 = HASHED_KEYS).
    pub contact_mode: i32,
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub mlkem_encapsulation_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub ecies_public_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub contact_binding_hash: Option<Vec<u8>>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::ContactMessage> for ContactMessage {
    fn from(value: derec_proto::ContactMessage) -> Self {
        Self {
            channel_id: value.channel_id,
            transport_protocol: value.transport_protocol.map(Into::into),
            nonce: value.nonce,
            contact_mode: value.contact_mode,
            mlkem_encapsulation_key: value.mlkem_encapsulation_key,
            ecies_public_key: value.ecies_public_key,
            contact_binding_hash: value.contact_binding_hash,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<ContactMessage> for derec_proto::ContactMessage {
    fn from(value: ContactMessage) -> Self {
        Self {
            channel_id: value.channel_id,
            transport_protocol: value.transport_protocol.map(Into::into),
            nonce: value.nonce,
            contact_mode: value.contact_mode,
            mlkem_encapsulation_key: value.mlkem_encapsulation_key,
            ecies_public_key: value.ecies_public_key,
            contact_binding_hash: value.contact_binding_hash,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PairRequestMessage {
    pub sender_kind: i32,
    #[serde(with = "serde_bytes")]
    pub mlkem_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ecies_public_key: Vec<u8>,
    pub nonce: u64,
    pub communication_info: Option<CommunicationInfo>,
    pub parameter_range: Option<ParameterRange>,
    pub transport_protocol: Option<TransportProtocol>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::PairRequestMessage> for PairRequestMessage {
    fn from(value: derec_proto::PairRequestMessage) -> Self {
        Self {
            sender_kind: value.sender_kind,
            mlkem_ciphertext: value.mlkem_ciphertext,
            ecies_public_key: value.ecies_public_key,
            nonce: value.nonce,
            communication_info: value.communication_info.map(Into::into),
            parameter_range: value.parameter_range.map(Into::into),
            transport_protocol: value.transport_protocol.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<PairRequestMessage> for derec_proto::PairRequestMessage {
    fn from(value: PairRequestMessage) -> Self {
        Self {
            sender_kind: value.sender_kind,
            mlkem_ciphertext: value.mlkem_ciphertext,
            ecies_public_key: value.ecies_public_key,
            nonce: value.nonce,
            communication_info: value.communication_info.map(Into::into),
            parameter_range: value.parameter_range.map(Into::into),
            transport_protocol: value.transport_protocol.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PairResponseMessage {
    pub result: Option<crate::wasm::primitives::types::DeRecResult>,
    pub nonce: u64,
    pub communication_info: Option<CommunicationInfo>,
    pub parameter_range: Option<ParameterRange>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::PairResponseMessage> for PairResponseMessage {
    fn from(value: derec_proto::PairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            nonce: value.nonce,
            communication_info: value.communication_info.map(Into::into),
            parameter_range: value.parameter_range.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<PairResponseMessage> for derec_proto::PairResponseMessage {
    fn from(value: PairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            nonce: value.nonce,
            communication_info: value.communication_info.map(Into::into),
            parameter_range: value.parameter_range.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrePairRequestMessage {
    pub nonce: u64,
    pub transport_protocol: Option<TransportProtocol>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::PrePairRequestMessage> for PrePairRequestMessage {
    fn from(value: derec_proto::PrePairRequestMessage) -> Self {
        Self {
            nonce: value.nonce,
            transport_protocol: value.transport_protocol.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<PrePairRequestMessage> for derec_proto::PrePairRequestMessage {
    fn from(value: PrePairRequestMessage) -> Self {
        Self {
            nonce: value.nonce,
            transport_protocol: value.transport_protocol.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrePairResponseMessage {
    pub result: Option<crate::wasm::primitives::types::DeRecResult>,
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub mlkem_encapsulation_key: Option<Vec<u8>>,
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Option::is_none")]
    pub ecies_public_key: Option<Vec<u8>>,
    pub nonce: u64,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::PrePairResponseMessage> for PrePairResponseMessage {
    fn from(value: derec_proto::PrePairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            mlkem_encapsulation_key: value.mlkem_encapsulation_key,
            ecies_public_key: value.ecies_public_key,
            nonce: value.nonce,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<PrePairResponseMessage> for derec_proto::PrePairResponseMessage {
    fn from(value: PrePairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            mlkem_encapsulation_key: value.mlkem_encapsulation_key,
            ecies_public_key: value.ecies_public_key,
            nonce: value.nonce,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

pub(super) fn serialize_pairing_secret_key_material(
    sk: &PairingSecretKeyMaterial,
) -> Result<Vec<u8>, JsValue> {
    let mut buf = Vec::new();
    sk.serialize_uncompressed(&mut buf)
        .map_err(|e| js_error("SERIALIZATION_ERROR", format!("{e:?}")))?;
    Ok(buf)
}

pub(super) fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, JsValue> {
    PairingSecretKeyMaterial::deserialize_uncompressed(&mut &bytes[..])
        .map_err(|e| js_error("SERIALIZATION_ERROR", e.to_string()))
}

pub(super) fn get_sender_kind(kind: u32) -> Result<SenderKind, JsValue> {
    match kind {
        0 => Ok(SenderKind::Owner),
        1 => Ok(SenderKind::Helper),
        2 => Ok(SenderKind::Replica),
        _ => Err(js_error(
            "INVALID_SENDER_KIND",
            format!(
                "invalid sender kind: {kind}, valid values are 0 (Owner), 1 (Helper), 2 (Replica)"
            ),
        )),
    }
}
