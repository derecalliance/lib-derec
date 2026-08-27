// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! JSON codecs for the primitive-layer protobuf messages.
//!
//! Every `extract_*` entry point in this FFI hands back raw protobuf bytes,
//! and every `produce_*` / `process_*` entry point that takes a message takes
//! the same. That suits a host language with generated protobuf bindings of
//! its own — Go and .NET both have them — but leaves one that does not with
//! an opaque buffer it cannot read.
//!
//! These two functions close that gap without giving each host its own copy
//! of the wire format: the crate decodes the protobuf and re-emits it as the
//! JSON mirror in [`crate::interop::dto`], which is the same shape the
//! WASM bindings surface to JavaScript. A host binding marshals JSON and
//! nothing else, so the message layout stays a single Rust-side decision.
//!
//! # Numeric representation
//!
//! The fields listed in [`U64_ID_FIELDS`] and [`I64_RANGE_FIELDS`] are
//! rewritten to decimal strings on the way out and parsed back on the way in.
//! A host whose numbers are IEEE doubles cannot hold a `u64` above 2^53
//! exactly, and every one of these carries an identifier or a size bound
//! where a silently rounded value would be worse than an error. The rewrite
//! is recursive: `GetSecretIdsVersionsResponseMessage` nests `secret_id`
//! inside `secret_list`, so a top-level-only pass would miss it.

use crate::interop::dto;
use crate::interop::ffi::common::{DeRecBuffer, empty_buffer, vec_into_buffer};
use crate::interop::ffi::error::{
    DEREC_CODE_FFI_BAD_PROTO, DEREC_CODE_FFI_NULL_PTR, DeRecError, ffi_error, success,
};

/// Discriminants selecting which message [`derec_decode_message_json`] and
/// [`derec_encode_message_json`] operate on.
///
/// Mirrored in the shared enum fixture, which every SDK asserts against, so a
/// message added here cannot reach a binding as a silently unhandled value.
pub const DEREC_MESSAGE_KIND_PAIR_REQUEST: i32 = 0;
pub const DEREC_MESSAGE_KIND_PAIR_RESPONSE: i32 = 1;
pub const DEREC_MESSAGE_KIND_PRE_PAIR_REQUEST: i32 = 2;
pub const DEREC_MESSAGE_KIND_PRE_PAIR_RESPONSE: i32 = 3;
pub const DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_REQUEST: i32 = 4;
pub const DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE: i32 = 5;
pub const DEREC_MESSAGE_KIND_GET_SHARE_REQUEST: i32 = 6;
pub const DEREC_MESSAGE_KIND_GET_SHARE_RESPONSE: i32 = 7;
pub const DEREC_MESSAGE_KIND_STORE_SHARE_REQUEST: i32 = 8;
pub const DEREC_MESSAGE_KIND_STORE_SHARE_RESPONSE: i32 = 9;
pub const DEREC_MESSAGE_KIND_UNPAIR_REQUEST: i32 = 10;
pub const DEREC_MESSAGE_KIND_UNPAIR_RESPONSE: i32 = 11;
pub const DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST: i32 = 12;
pub const DEREC_MESSAGE_KIND_VERIFY_SHARE_RESPONSE: i32 = 13;
/// Not a standalone message on the wire, but it crosses this FFI on its own
/// as the `transport_protocol` argument of `create_contact_message` and the
/// `peer_transport_protocol` result of `produce_pair_response_message`.
pub const DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL: i32 = 14;
/// Crosses on its own as the `communication_info` argument of the pairing
/// produce calls. See [`DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL`].
pub const DEREC_MESSAGE_KIND_COMMUNICATION_INFO: i32 = 15;
/// Crosses on its own as the `parameter_range` argument of the pairing
/// produce calls. See [`DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL`].
pub const DEREC_MESSAGE_KIND_PARAMETER_RANGE: i32 = 16;
/// Crosses on its own as the `committed_share` argument of
/// `produce_store_share_request_message` and as the `committed_share_bytes`
/// result of `produce_store_share_response_message`.
pub const DEREC_MESSAGE_KIND_COMMITTED_DEREC_SHARE: i32 = 17;

/// Result of a message JSON codec call. `bytes` is UTF-8 JSON for
/// [`derec_decode_message_json`] and protobuf wire bytes for
/// [`derec_encode_message_json`]; it is empty when `error` is non-zero.
#[repr(C)]
pub struct DeRecMessageJsonResult {
    pub error: DeRecError,
    pub bytes: DeRecBuffer,
}

/// `u64` fields that cross this seam as decimal strings. Every one is an
/// identifier: a rounded value names a different channel, secret or member.
const U64_ID_FIELDS: [&str; 4] = ["channel_id", "nonce", "secret_id", "replica_id"];

/// `ParameterRange`'s `i64` bounds. Surfaced as `bigint` by the WASM SDKs,
/// so they cross as decimal strings here for the same reason.
const I64_RANGE_FIELDS: [&str; 10] = [
    "min_share_size",
    "max_share_size",
    "min_time_between_verifications",
    "max_time_between_verifications",
    "min_time_between_share_updates",
    "max_time_between_share_updates",
    "min_unresponsive_deletion_timeout",
    "max_unresponsive_deletion_timeout",
    "min_unresponsive_deactivation_timeout",
    "max_unresponsive_deactivation_timeout",
];

/// Recursively rewrites the wide numeric fields to decimal strings.
pub(crate) fn wide_numbers_to_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                wide_numbers_to_strings(item);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, field) in object.iter_mut() {
                if U64_ID_FIELDS.contains(&key.as_str())
                    && let Some(n) = field.as_u64()
                {
                    *field = serde_json::Value::String(n.to_string());
                    continue;
                }
                if I64_RANGE_FIELDS.contains(&key.as_str())
                    && let Some(n) = field.as_i64()
                {
                    *field = serde_json::Value::String(n.to_string());
                    continue;
                }
                wide_numbers_to_strings(field);
            }
        }
        _ => {}
    }
}

/// Reverse of [`wide_numbers_to_strings`]. A field already holding a JSON
/// number is left untouched, so a host that never widened them still works.
pub(crate) fn wide_numbers_to_numbers(value: &mut serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                wide_numbers_to_numbers(item)?;
            }
        }
        serde_json::Value::Object(object) => {
            for (key, field) in object.iter_mut() {
                let is_u64 = U64_ID_FIELDS.contains(&key.as_str());
                let is_i64 = I64_RANGE_FIELDS.contains(&key.as_str());
                if let serde_json::Value::String(raw) = field {
                    if is_u64 {
                        let parsed: u64 = raw.parse().map_err(|e| {
                            format!("{key} must be a decimal u64 string, got {raw:?}: {e}")
                        })?;
                        *field = serde_json::Value::Number(parsed.into());
                        continue;
                    }
                    if is_i64 {
                        let parsed: i64 = raw.parse().map_err(|e| {
                            format!("{key} must be a decimal i64 string, got {raw:?}: {e}")
                        })?;
                        *field = serde_json::Value::Number(parsed.into());
                        continue;
                    }
                }
                wide_numbers_to_numbers(field)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_buffer<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], DeRecError> {
    if ptr.is_null() && len > 0 {
        return Err(ffi_error(
            DEREC_CODE_FFI_NULL_PTR,
            format!("{name} is null"),
        ));
    }
    if len == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
    }
}

fn bad_proto(message: impl Into<String>) -> DeRecMessageJsonResult {
    DeRecMessageJsonResult {
        error: ffi_error(DEREC_CODE_FFI_BAD_PROTO, message.into()),
        bytes: empty_buffer(),
    }
}

/// Decodes `proto` as the message named by `Proto`, converts it through
/// `Dto`, and serializes it as JSON with the wide numeric fields widened to
/// strings.
fn decode_as<Proto, Dto>(proto: &[u8], name: &str) -> DeRecMessageJsonResult
where
    Proto: prost::Message + Default,
    Dto: serde::Serialize + From<Proto>,
{
    let message = match Proto::decode(proto) {
        Ok(m) => m,
        Err(e) => return bad_proto(format!("bytes are not a valid {name}: {e}")),
    };
    let dto: Dto = message.into();
    let mut json = match serde_json::to_value(&dto) {
        Ok(v) => v,
        Err(e) => return bad_proto(format!("failed to encode {name} as JSON: {e}")),
    };
    wide_numbers_to_strings(&mut json);
    match serde_json::to_vec(&json) {
        Ok(bytes) => DeRecMessageJsonResult {
            error: success(),
            bytes: vec_into_buffer(bytes),
        },
        Err(e) => bad_proto(format!("failed to serialize {name} JSON: {e}")),
    }
}

/// Inverse of [`decode_as`].
fn encode_as<Proto, Dto>(json: &[u8], name: &str) -> DeRecMessageJsonResult
where
    Proto: prost::Message + From<Dto>,
    Dto: serde::de::DeserializeOwned,
{
    let mut value: serde_json::Value = match serde_json::from_slice(json) {
        Ok(v) => v,
        Err(e) => return bad_proto(format!("{name} JSON is not valid JSON: {e}")),
    };
    if let Err(e) = wide_numbers_to_numbers(&mut value) {
        return bad_proto(format!("{name} JSON has an invalid numeric field: {e}"));
    }
    let dto: Dto = match serde_json::from_value(value) {
        Ok(d) => d,
        Err(e) => return bad_proto(format!("{name} JSON does not match the message shape: {e}")),
    };
    let message: Proto = dto.into();
    DeRecMessageJsonResult {
        error: success(),
        bytes: vec_into_buffer(message.encode_to_vec()),
    }
}

/// Dispatches `$body` over every message kind. Keeping the table in one macro
/// is what makes the two entry points provably cover the same set.
macro_rules! dispatch_message_kind {
    ($kind:expr, $bytes:expr, $op:ident) => {
        match $kind {
            DEREC_MESSAGE_KIND_PAIR_REQUEST => $op::<
                derec_proto::PairRequestMessage,
                dto::PairRequestMessage,
            >($bytes, "PairRequestMessage"),
            DEREC_MESSAGE_KIND_PAIR_RESPONSE => $op::<
                derec_proto::PairResponseMessage,
                dto::PairResponseMessage,
            >($bytes, "PairResponseMessage"),
            DEREC_MESSAGE_KIND_PRE_PAIR_REQUEST => $op::<
                derec_proto::PrePairRequestMessage,
                dto::PrePairRequestMessage,
            >($bytes, "PrePairRequestMessage"),
            DEREC_MESSAGE_KIND_PRE_PAIR_RESPONSE => $op::<
                derec_proto::PrePairResponseMessage,
                dto::PrePairResponseMessage,
            >($bytes, "PrePairResponseMessage"),
            DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_REQUEST => {
                $op::<
                    derec_proto::GetSecretIdsVersionsRequestMessage,
                    dto::GetSecretIdsVersionsRequestMessage,
                >($bytes, "GetSecretIdsVersionsRequestMessage")
            }
            DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE => {
                $op::<
                    derec_proto::GetSecretIdsVersionsResponseMessage,
                    dto::GetSecretIdsVersionsResponseMessage,
                >($bytes, "GetSecretIdsVersionsResponseMessage")
            }
            DEREC_MESSAGE_KIND_GET_SHARE_REQUEST => $op::<
                derec_proto::GetShareRequestMessage,
                dto::GetShareRequestMessage,
            >($bytes, "GetShareRequestMessage"),
            DEREC_MESSAGE_KIND_GET_SHARE_RESPONSE => $op::<
                derec_proto::GetShareResponseMessage,
                dto::GetShareResponseMessage,
            >($bytes, "GetShareResponseMessage"),
            DEREC_MESSAGE_KIND_STORE_SHARE_REQUEST => $op::<
                derec_proto::StoreShareRequestMessage,
                dto::StoreShareRequestMessage,
            >($bytes, "StoreShareRequestMessage"),
            DEREC_MESSAGE_KIND_STORE_SHARE_RESPONSE => {
                $op::<derec_proto::StoreShareResponseMessage, dto::StoreShareResponseMessage>(
                    $bytes,
                    "StoreShareResponseMessage",
                )
            }
            DEREC_MESSAGE_KIND_UNPAIR_REQUEST => $op::<
                derec_proto::UnpairRequestMessage,
                dto::UnpairRequestMessage,
            >($bytes, "UnpairRequestMessage"),
            DEREC_MESSAGE_KIND_UNPAIR_RESPONSE => $op::<
                derec_proto::UnpairResponseMessage,
                dto::UnpairResponseMessage,
            >($bytes, "UnpairResponseMessage"),
            DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST => {
                $op::<derec_proto::VerifyShareRequestMessage, dto::VerifyShareRequestMessage>(
                    $bytes,
                    "VerifyShareRequestMessage",
                )
            }
            DEREC_MESSAGE_KIND_VERIFY_SHARE_RESPONSE => {
                $op::<derec_proto::VerifyShareResponseMessage, dto::VerifyShareResponseMessage>(
                    $bytes,
                    "VerifyShareResponseMessage",
                )
            }
            DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL => $op::<
                derec_proto::TransportProtocol,
                dto::TransportProtocol,
            >($bytes, "TransportProtocol"),
            DEREC_MESSAGE_KIND_COMMUNICATION_INFO => $op::<
                derec_proto::CommunicationInfo,
                dto::CommunicationInfo,
            >($bytes, "CommunicationInfo"),
            DEREC_MESSAGE_KIND_PARAMETER_RANGE => {
                $op::<derec_proto::ParameterRange, dto::ParameterRange>($bytes, "ParameterRange")
            }
            DEREC_MESSAGE_KIND_COMMITTED_DEREC_SHARE => $op::<
                derec_proto::CommittedDeRecShare,
                dto::CommittedDeRecShare,
            >($bytes, "CommittedDeRecShare"),
            other => bad_proto(format!("unknown message kind {other}")),
        }
    };
}

/// Decodes protobuf wire bytes into the JSON mirror of `kind`.
///
/// The returned buffer is UTF-8 JSON and must be released with
/// `derec_free_buffer`.
///
/// # Safety
///
/// `proto_ptr` must point to `proto_len` readable bytes, or be null with
/// `proto_len` zero.
#[unsafe(no_mangle)]
pub extern "C" fn derec_decode_message_json(
    kind: i32,
    proto_ptr: *const u8,
    proto_len: usize,
) -> DeRecMessageJsonResult {
    let proto = match parse_buffer(proto_ptr, proto_len, "proto_ptr") {
        Ok(b) => b,
        Err(error) => {
            return DeRecMessageJsonResult {
                error,
                bytes: empty_buffer(),
            };
        }
    };
    dispatch_message_kind!(kind, proto, decode_as)
}

/// Encodes the JSON mirror of `kind` into protobuf wire bytes.
///
/// The returned buffer must be released with `derec_free_buffer`.
///
/// # Safety
///
/// `json_ptr` must point to `json_len` readable bytes, or be null with
/// `json_len` zero.
#[unsafe(no_mangle)]
pub extern "C" fn derec_encode_message_json(
    kind: i32,
    json_ptr: *const u8,
    json_len: usize,
) -> DeRecMessageJsonResult {
    let json = match parse_buffer(json_ptr, json_len, "json_ptr") {
        Ok(b) => b,
        Err(error) => {
            return DeRecMessageJsonResult {
                error,
                bytes: empty_buffer(),
            };
        }
    };
    dispatch_message_kind!(kind, json, encode_as)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::ffi::common::derec_free_buffer;
    use prost::Message as _;

    /// Every kind this FFI accepts, paired with the name
    /// `library/tests/fixtures/enums.json` records for it. The round-trip test
    /// walks this list and `fixture_matches_the_dispatch_table` compares it to
    /// the fixture, so a kind added to the dispatch table without being added
    /// here is caught either way.
    const ALL_KINDS: [(&str, i32); 18] = [
        ("PairRequest", DEREC_MESSAGE_KIND_PAIR_REQUEST),
        ("PairResponse", DEREC_MESSAGE_KIND_PAIR_RESPONSE),
        ("PrePairRequest", DEREC_MESSAGE_KIND_PRE_PAIR_REQUEST),
        ("PrePairResponse", DEREC_MESSAGE_KIND_PRE_PAIR_RESPONSE),
        (
            "GetSecretIdsVersionsRequest",
            DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_REQUEST,
        ),
        (
            "GetSecretIdsVersionsResponse",
            DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE,
        ),
        ("GetShareRequest", DEREC_MESSAGE_KIND_GET_SHARE_REQUEST),
        ("GetShareResponse", DEREC_MESSAGE_KIND_GET_SHARE_RESPONSE),
        ("StoreShareRequest", DEREC_MESSAGE_KIND_STORE_SHARE_REQUEST),
        (
            "StoreShareResponse",
            DEREC_MESSAGE_KIND_STORE_SHARE_RESPONSE,
        ),
        ("UnpairRequest", DEREC_MESSAGE_KIND_UNPAIR_REQUEST),
        ("UnpairResponse", DEREC_MESSAGE_KIND_UNPAIR_RESPONSE),
        (
            "VerifyShareRequest",
            DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST,
        ),
        (
            "VerifyShareResponse",
            DEREC_MESSAGE_KIND_VERIFY_SHARE_RESPONSE,
        ),
        ("TransportProtocol", DEREC_MESSAGE_KIND_TRANSPORT_PROTOCOL),
        ("CommunicationInfo", DEREC_MESSAGE_KIND_COMMUNICATION_INFO),
        ("ParameterRange", DEREC_MESSAGE_KIND_PARAMETER_RANGE),
        (
            "CommittedDeRecShare",
            DEREC_MESSAGE_KIND_COMMITTED_DEREC_SHARE,
        ),
    ];

    /// The fixture is what the SDKs assert against, so it drifting behind this
    /// table is exactly the failure the fixture exists to prevent — the same
    /// shape as `ChannelStatus::Unpairing` reaching Go and .NET as an
    /// unhandled value. See `library/tests/enum_fixture.rs`.
    #[test]
    fn fixture_matches_the_dispatch_table() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/enums.json"
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture"))
                .expect("parse fixture");
        let variants = doc["enums"]["MessageKind"]["variants"]
            .as_array()
            .expect("fixture has MessageKind variants");

        let recorded: Vec<(String, i64)> = variants
            .iter()
            .map(|v| {
                (
                    v["name"].as_str().expect("variant name").to_owned(),
                    v["wire"].as_i64().expect("numeric wire value"),
                )
            })
            .collect();
        let declared: Vec<(String, i64)> = ALL_KINDS
            .iter()
            .map(|(name, kind)| ((*name).to_owned(), i64::from(*kind)))
            .collect();

        assert_eq!(
            recorded, declared,
            "library/tests/fixtures/enums.json MessageKind is out of step with \
             the constants in this module"
        );
    }

    fn take(result: DeRecMessageJsonResult) -> Vec<u8> {
        assert_eq!(result.error.code, 0, "unexpected FFI error");
        let bytes =
            unsafe { std::slice::from_raw_parts(result.bytes.ptr, result.bytes.len) }.to_vec();
        derec_free_buffer(result.bytes.ptr, result.bytes.len);
        bytes
    }

    fn decode(kind: i32, proto: &[u8]) -> serde_json::Value {
        let json = take(derec_decode_message_json(kind, proto.as_ptr(), proto.len()));
        serde_json::from_slice(&json).expect("decoded output is JSON")
    }

    fn encode(kind: i32, json: &serde_json::Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(json).unwrap();
        take(derec_encode_message_json(kind, bytes.as_ptr(), bytes.len()))
    }

    /// An empty message of each kind still has to survive the round trip:
    /// prost encodes defaults as absent fields, so this is the case where a
    /// missing `#[serde(default)]` on the DTO would surface.
    #[test]
    fn every_kind_round_trips_an_empty_message() {
        for (name, kind) in ALL_KINDS {
            let json = decode(kind, &[]);
            let reencoded = encode(kind, &json);
            assert!(
                reencoded.is_empty(),
                "{name} did not round-trip an empty message, got {reencoded:?}"
            );
        }
    }

    #[test]
    fn every_kind_is_listed() {
        // A kind outside the dispatch table must be rejected, which is what
        // makes ALL_KINDS a complete list rather than an arbitrary sample.
        let result = derec_decode_message_json(ALL_KINDS.len() as i32, std::ptr::null(), 0);
        assert_ne!(result.error.code, 0, "an unknown kind must be rejected");
        derec_free_buffer(result.bytes.ptr, result.bytes.len);
    }

    /// The whole reason the wide fields cross as strings: these values are
    /// above 2^53 and must come back bit-for-bit.
    #[test]
    fn wide_ids_survive_as_decimal_strings() {
        let message = derec_proto::VerifyShareRequestMessage {
            secret_id: u64::MAX,
            version: 7,
            nonce: 9_007_199_254_740_993,
            timestamp: None,
            reply_to: None,
        };
        let json = decode(
            DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST,
            &message.encode_to_vec(),
        );

        assert_eq!(json["secret_id"], serde_json::json!("18446744073709551615"));
        assert_eq!(json["nonce"], serde_json::json!("9007199254740993"));
        assert_eq!(json["version"], serde_json::json!(7));

        let reencoded = encode(DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST, &json);
        let decoded = derec_proto::VerifyShareRequestMessage::decode(&reencoded[..]).unwrap();
        assert_eq!(decoded.secret_id, u64::MAX);
        assert_eq!(decoded.nonce, 9_007_199_254_740_993);
    }

    /// `secret_id` is nested two levels down here, which a top-level-only
    /// rewrite would miss.
    #[test]
    fn nested_secret_ids_are_widened() {
        use derec_proto::get_secret_ids_versions_response_message::{VersionList, version_list};

        let message = derec_proto::GetSecretIdsVersionsResponseMessage {
            result: None,
            secret_list: vec![VersionList {
                secret_id: u64::MAX,
                versions: vec![version_list::VersionEntry {
                    version: 3,
                    version_description: "v3".to_owned(),
                }],
            }],
            timestamp: None,
            replica_id: None,
        };
        let json = decode(
            DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE,
            &message.encode_to_vec(),
        );

        assert_eq!(
            json["secret_list"][0]["secret_id"],
            serde_json::json!("18446744073709551615")
        );

        let reencoded = encode(DEREC_MESSAGE_KIND_GET_SECRET_IDS_VERSIONS_RESPONSE, &json);
        let decoded =
            derec_proto::GetSecretIdsVersionsResponseMessage::decode(&reencoded[..]).unwrap();
        assert_eq!(decoded.secret_list[0].secret_id, u64::MAX);
    }

    /// `ParameterRange`'s bounds are `i64` and are surfaced as `bigint` by
    /// the WASM SDKs, so they cross this seam as strings too.
    #[test]
    fn parameter_range_bounds_are_widened() {
        let message = derec_proto::PairRequestMessage {
            sender_kind: 0,
            mlkem_ciphertext: vec![1, 2, 3],
            ecies_public_key: vec![4, 5, 6],
            nonce: 42,
            communication_info: None,
            parameter_range: Some(derec_proto::ParameterRange {
                min_share_size: 1,
                max_share_size: i64::MAX,
                ..Default::default()
            }),
            transport_protocol: None,
            timestamp: None,
        };
        let json = decode(DEREC_MESSAGE_KIND_PAIR_REQUEST, &message.encode_to_vec());

        assert_eq!(
            json["parameter_range"]["max_share_size"],
            serde_json::json!("9223372036854775807")
        );

        let reencoded = encode(DEREC_MESSAGE_KIND_PAIR_REQUEST, &json);
        let decoded = derec_proto::PairRequestMessage::decode(&reencoded[..]).unwrap();
        assert_eq!(
            decoded.parameter_range.unwrap().max_share_size,
            i64::MAX,
            "an i64 bound must survive the JSON seam"
        );
    }

    /// A host that leaves the wide fields as JSON numbers still encodes, so
    /// the widening is a capability rather than a new requirement.
    #[test]
    fn plain_numbers_are_still_accepted_on_encode() {
        let json = serde_json::json!({
            "secret_id": 12u64,
            "version": 1,
            "nonce": 34u64,
            "timestamp": null,
            "reply_to": null,
        });
        let bytes = encode(DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST, &json);
        let decoded = derec_proto::VerifyShareRequestMessage::decode(&bytes[..]).unwrap();
        assert_eq!(decoded.secret_id, 12);
        assert_eq!(decoded.nonce, 34);
    }

    #[test]
    fn a_non_numeric_id_string_is_rejected() {
        let json = serde_json::json!({
            "secret_id": "not-a-number",
            "version": 1,
            "nonce": "0",
            "timestamp": null,
            "reply_to": null,
        });
        let bytes = serde_json::to_vec(&json).unwrap();
        let result = derec_encode_message_json(
            DEREC_MESSAGE_KIND_VERIFY_SHARE_REQUEST,
            bytes.as_ptr(),
            bytes.len(),
        );
        assert_ne!(result.error.code, 0);
        derec_free_buffer(result.bytes.ptr, result.bytes.len);
    }

    #[test]
    fn malformed_proto_is_rejected_rather_than_panicking() {
        // A wire type that cannot appear in this message.
        let result = derec_decode_message_json(
            DEREC_MESSAGE_KIND_PAIR_REQUEST,
            [0xffu8, 0xff, 0xff].as_ptr(),
            3,
        );
        assert_ne!(result.error.code, 0);
        derec_free_buffer(result.bytes.ptr, result.bytes.len);
    }

    /// `UnpairRequestMessage.replica_id` decides which protocol path the
    /// message belongs to, so dropping it on a round trip would silently
    /// convert a replica departure into an owner-originated unpair.
    #[test]
    fn unpair_replica_id_survives_the_round_trip() {
        let message = derec_proto::UnpairRequestMessage {
            memo: "leaving".to_owned(),
            timestamp: None,
            reply_to: None,
            replica_id: Some(u64::MAX),
        };
        let json = decode(DEREC_MESSAGE_KIND_UNPAIR_REQUEST, &message.encode_to_vec());
        assert_eq!(
            json["replica_id"],
            serde_json::json!("18446744073709551615")
        );

        let reencoded = encode(DEREC_MESSAGE_KIND_UNPAIR_REQUEST, &json);
        let decoded = derec_proto::UnpairRequestMessage::decode(&reencoded[..]).unwrap();
        assert_eq!(decoded.replica_id, Some(u64::MAX));
    }
}
