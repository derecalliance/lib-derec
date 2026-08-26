// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Serde mirrors of the primitives-layer protobuf messages that the SDK
//! boundaries hand to application code.
//!
//! The `derec_proto` types are prost-generated and are not serializable in
//! the shape a host language expects, so each boundary converts through the
//! structs below. They live under [`crate::interop`] rather than in either
//! binding because the WASM bindings and the C FFI both need them and the two
//! are compiled under mutually exclusive `cfg`s;
//! [`crate::interop::wasm::primitives`] re-exports them under their original paths so
//! the WASM binding code is unaffected.
//!
//! Two prost shapes are deliberately not mirrored one-for-one:
//!
//! - [`CommunicationInfoKeyValue`] flattens the generated `value` oneof into
//!   two `Option` fields. A host language sees `string_value` / `bytes_value`
//!   rather than serde's externally tagged enum encoding of the oneof.
//! - `prost_types::Timestamp` is replaced by [`Timestamp`], since a type from
//!   another crate cannot be given serde derives here.
//!
//! Byte fields carry `#[serde(with = "serde_bytes")]`. Under
//! `serde-wasm-bindgen` that is what surfaces them to JavaScript as
//! `Uint8Array` instead of an array of numbers; `serde_json` draws no such
//! distinction and encodes them as arrays of numbers either way, so the C
//! FFI's host bindings convert byte fields themselves to keep the object an
//! application sees identical across SDKs.
//!
//! `u64` fields serialize as JSON numbers here. Every C FFI boundary that
//! emits one of these types runs `u64_id_fields_to_strings` over the value
//! afterwards, because a host whose numbers are doubles cannot represent an
//! id above 2^53 exactly.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Shared scalars
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl From<prost_types::Timestamp> for Timestamp {
    fn from(value: prost_types::Timestamp) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

impl From<Timestamp> for prost_types::Timestamp {
    fn from(value: Timestamp) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

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
pub struct DeRecResult {
    pub status: i32,
    pub memo: String,
}

impl From<derec_proto::DeRecResult> for DeRecResult {
    fn from(value: derec_proto::DeRecResult) -> Self {
        Self {
            status: value.status,
            memo: value.memo,
        }
    }
}

impl From<DeRecResult> for derec_proto::DeRecResult {
    fn from(value: DeRecResult) -> Self {
        Self {
            status: value.status,
            memo: value.memo,
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing-adjacent shared messages
// ---------------------------------------------------------------------------

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
    /// `i32` matching `derec_proto::ContactMode` (0 = INLINE_KEYS,
    /// 1 = HASHED_KEYS, 2 = NO_KEYS).
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

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

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
    pub result: Option<DeRecResult>,
    pub nonce: u64,
    pub communication_info: Option<CommunicationInfo>,
    pub parameter_range: Option<ParameterRange>,
    pub timestamp: Option<Timestamp>,
    /// Post-handshake rekey channel id; both sides switch their local
    /// channel record to this value once the response is accepted.
    pub channel_id: u64,
}

impl From<derec_proto::PairResponseMessage> for PairResponseMessage {
    fn from(value: derec_proto::PairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            nonce: value.nonce,
            communication_info: value.communication_info.map(Into::into),
            parameter_range: value.parameter_range.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            channel_id: value.channel_id,
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
            channel_id: value.channel_id,
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
    pub result: Option<DeRecResult>,
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

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionListEntry {
    pub version: u32,
    pub version_description: String,
}

impl From<derec_proto::get_secret_ids_versions_response_message::version_list::VersionEntry>
    for VersionListEntry
{
    fn from(
        value: derec_proto::get_secret_ids_versions_response_message::version_list::VersionEntry,
    ) -> Self {
        Self {
            version: value.version,
            version_description: value.version_description,
        }
    }
}

impl From<VersionListEntry>
    for derec_proto::get_secret_ids_versions_response_message::version_list::VersionEntry
{
    fn from(value: VersionListEntry) -> Self {
        Self {
            version: value.version,
            version_description: value.version_description,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VersionList {
    pub secret_id: u64,
    pub versions: Vec<VersionListEntry>,
}

impl From<derec_proto::get_secret_ids_versions_response_message::VersionList> for VersionList {
    fn from(value: derec_proto::get_secret_ids_versions_response_message::VersionList) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<VersionList> for derec_proto::get_secret_ids_versions_response_message::VersionList {
    fn from(value: VersionList) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetSecretIdsVersionsRequestMessage {
    pub timestamp: Option<Timestamp>,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
    /// Identity of the replica-group member this message concerns, present
    /// only on the replica catch-up path. `null` on the owner ↔ helper path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::GetSecretIdsVersionsRequestMessage> for GetSecretIdsVersionsRequestMessage {
    fn from(value: derec_proto::GetSecretIdsVersionsRequestMessage) -> Self {
        Self {
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<GetSecretIdsVersionsRequestMessage> for derec_proto::GetSecretIdsVersionsRequestMessage {
    fn from(value: GetSecretIdsVersionsRequestMessage) -> Self {
        Self {
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetSecretIdsVersionsResponseMessage {
    pub result: Option<DeRecResult>,
    pub secret_list: Vec<VersionList>,
    pub timestamp: Option<Timestamp>,
    /// Identity of the replica-group member this message concerns, present
    /// only on the replica catch-up path. `null` on the owner ↔ helper path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::GetSecretIdsVersionsResponseMessage>
    for GetSecretIdsVersionsResponseMessage
{
    fn from(value: derec_proto::GetSecretIdsVersionsResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_list: value.secret_list.into_iter().map(Into::into).collect(),
            timestamp: value.timestamp.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<GetSecretIdsVersionsResponseMessage>
    for derec_proto::GetSecretIdsVersionsResponseMessage
{
    fn from(value: GetSecretIdsVersionsResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_list: value.secret_list.into_iter().map(Into::into).collect(),
            timestamp: value.timestamp.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

/// Mirror of [`crate::primitives::discovery::response::VersionEntry`].
///
/// Unlike the types above this one has no protobuf counterpart: it is a
/// domain type carried in and out of the discovery response helpers, and the
/// SDK boundaries need a serializable shape for it.
#[derive(Serialize, Deserialize, Clone)]
pub struct VersionEntry {
    pub version: u32,
    pub description: String,
}

impl From<crate::primitives::discovery::response::VersionEntry> for VersionEntry {
    fn from(value: crate::primitives::discovery::response::VersionEntry) -> Self {
        Self {
            version: value.version,
            description: value.description,
        }
    }
}

impl From<VersionEntry> for crate::primitives::discovery::response::VersionEntry {
    fn from(value: VersionEntry) -> Self {
        Self {
            version: value.version,
            description: value.description,
        }
    }
}

/// Mirror of [`crate::primitives::discovery::response::SecretVersionEntry`].
/// See [`VersionEntry`] for why this has no protobuf counterpart.
#[derive(Serialize, Deserialize, Clone)]
pub struct SecretVersionEntry {
    pub secret_id: u64,
    pub versions: Vec<VersionEntry>,
}

impl From<crate::primitives::discovery::response::SecretVersionEntry> for SecretVersionEntry {
    fn from(value: crate::primitives::discovery::response::SecretVersionEntry) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SecretVersionEntry> for crate::primitives::discovery::response::SecretVersionEntry {
    fn from(value: SecretVersionEntry) -> Self {
        Self {
            secret_id: value.secret_id,
            versions: value.versions.into_iter().map(Into::into).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Sharing
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct SiblingHash {
    pub is_left: bool,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
}

impl From<derec_proto::committed_de_rec_share::SiblingHash> for SiblingHash {
    fn from(value: derec_proto::committed_de_rec_share::SiblingHash) -> Self {
        Self {
            is_left: value.is_left,
            hash: value.hash,
        }
    }
}

impl From<SiblingHash> for derec_proto::committed_de_rec_share::SiblingHash {
    fn from(value: SiblingHash) -> Self {
        Self {
            is_left: value.is_left,
            hash: value.hash,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CommittedDeRecShare {
    #[serde(with = "serde_bytes")]
    pub de_rec_share: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    pub merkle_path: Vec<SiblingHash>,
}

impl From<derec_proto::CommittedDeRecShare> for CommittedDeRecShare {
    fn from(value: derec_proto::CommittedDeRecShare) -> Self {
        Self {
            de_rec_share: value.de_rec_share,
            commitment: value.commitment,
            merkle_path: value.merkle_path.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CommittedDeRecShare> for derec_proto::CommittedDeRecShare {
    fn from(value: CommittedDeRecShare) -> Self {
        Self {
            de_rec_share: value.de_rec_share,
            commitment: value.commitment,
            merkle_path: value.merkle_path.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreShareRequestMessage {
    #[serde(with = "serde_bytes")]
    pub share: Vec<u8>,
    pub share_algorithm: i32,
    pub version: u32,
    pub keep_list: Vec<u32>,
    pub version_description: String,
    pub timestamp: Option<Timestamp>,
    pub secret_id: u64,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
    /// Optional `replica_id` of the writer. See the proto's `replicaId`
    /// field for the disambiguation contract.
    pub replica_id: Option<u64>,
}

impl From<derec_proto::StoreShareRequestMessage> for StoreShareRequestMessage {
    fn from(value: derec_proto::StoreShareRequestMessage) -> Self {
        Self {
            share: value.share,
            share_algorithm: value.share_algorithm,
            version: value.version,
            keep_list: value.keep_list,
            version_description: value.version_description,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<StoreShareRequestMessage> for derec_proto::StoreShareRequestMessage {
    fn from(value: StoreShareRequestMessage) -> Self {
        Self {
            share: value.share,
            share_algorithm: value.share_algorithm,
            version: value.version,
            keep_list: value.keep_list,
            version_description: value.version_description,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoreShareResponseMessage {
    pub result: Option<DeRecResult>,
    pub version: u32,
    pub timestamp: Option<Timestamp>,
    pub secret_id: u64,
    /// The member that produced this acknowledgement. Every member of a
    /// replica group answers on the same channel, so the responder names
    /// itself here. Absent on a helper's acknowledgement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::StoreShareResponseMessage> for StoreShareResponseMessage {
    fn from(value: derec_proto::StoreShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            version: value.version,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            replica_id: value.replica_id,
        }
    }
}

impl From<StoreShareResponseMessage> for derec_proto::StoreShareResponseMessage {
    fn from(value: StoreShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            version: value.version,
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            replica_id: value.replica_id,
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct GetShareRequestMessage {
    pub secret_id: u64,
    pub version: u32,
    pub timestamp: Option<Timestamp>,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
    /// Identity of the replica-group member this message concerns, present
    /// only on the replica catch-up path. `null` on the owner ↔ helper path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::GetShareRequestMessage> for GetShareRequestMessage {
    fn from(value: derec_proto::GetShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<GetShareRequestMessage> for derec_proto::GetShareRequestMessage {
    fn from(value: GetShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetShareResponseMessage {
    pub share_algorithm: i32,
    #[serde(with = "serde_bytes")]
    pub committed_de_rec_share: Vec<u8>,
    pub result: Option<DeRecResult>,
    pub timestamp: Option<Timestamp>,
    pub secret_id: u64,
    pub version: u32,
    /// Identity of the replica-group member this message concerns, present
    /// only on the replica catch-up path. `null` on the owner ↔ helper path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::GetShareResponseMessage> for GetShareResponseMessage {
    fn from(value: derec_proto::GetShareResponseMessage) -> Self {
        Self {
            share_algorithm: value.share_algorithm,
            committed_de_rec_share: value.committed_de_rec_share,
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            replica_id: value.replica_id,
        }
    }
}

impl From<GetShareResponseMessage> for derec_proto::GetShareResponseMessage {
    fn from(value: GetShareResponseMessage) -> Self {
        Self {
            share_algorithm: value.share_algorithm,
            committed_de_rec_share: value.committed_de_rec_share,
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            replica_id: value.replica_id,
        }
    }
}

// ---------------------------------------------------------------------------
// Unpairing
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct UnpairRequestMessage {
    pub memo: String,
    pub timestamp: Option<Timestamp>,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
    /// The replica-group member that initiated this unpair. Present exactly
    /// when the unpair is replica-originated — its presence is what tells the
    /// receiver which path the message belongs to, so it must survive a
    /// decode/encode round trip rather than being dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_id: Option<u64>,
}

impl From<derec_proto::UnpairRequestMessage> for UnpairRequestMessage {
    fn from(value: derec_proto::UnpairRequestMessage) -> Self {
        Self {
            memo: value.memo,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

impl From<UnpairRequestMessage> for derec_proto::UnpairRequestMessage {
    fn from(value: UnpairRequestMessage) -> Self {
        Self {
            memo: value.memo,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
            replica_id: value.replica_id,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct UnpairResponseMessage {
    pub result: Option<DeRecResult>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::UnpairResponseMessage> for UnpairResponseMessage {
    fn from(value: derec_proto::UnpairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<UnpairResponseMessage> for derec_proto::UnpairResponseMessage {
    fn from(value: UnpairResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyShareRequestMessage {
    pub secret_id: u64,
    pub version: u32,
    pub nonce: u64,
    pub timestamp: Option<Timestamp>,
    /// Optional ephemeral response endpoint. See `replyTo` on the request
    /// proto for the routing semantics.
    pub reply_to: Option<TransportProtocol>,
}

impl From<derec_proto::VerifyShareRequestMessage> for VerifyShareRequestMessage {
    fn from(value: derec_proto::VerifyShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
        }
    }
}

impl From<VerifyShareRequestMessage> for derec_proto::VerifyShareRequestMessage {
    fn from(value: VerifyShareRequestMessage) -> Self {
        Self {
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            timestamp: value.timestamp.map(Into::into),
            reply_to: value.reply_to.map(Into::into),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VerifyShareResponseMessage {
    pub result: Option<DeRecResult>,
    pub secret_id: u64,
    pub version: u32,
    pub nonce: u64,
    #[serde(with = "serde_bytes")]
    pub hash: Vec<u8>,
    pub timestamp: Option<Timestamp>,
}

impl From<derec_proto::VerifyShareResponseMessage> for VerifyShareResponseMessage {
    fn from(value: derec_proto::VerifyShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            hash: value.hash,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}

impl From<VerifyShareResponseMessage> for derec_proto::VerifyShareResponseMessage {
    fn from(value: VerifyShareResponseMessage) -> Self {
        Self {
            result: value.result.map(Into::into),
            secret_id: value.secret_id,
            version: value.version,
            nonce: value.nonce,
            hash: value.hash,
            timestamp: value.timestamp.map(Into::into),
        }
    }
}
