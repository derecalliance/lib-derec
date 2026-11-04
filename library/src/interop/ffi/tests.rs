// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Holds `library/tests/fixtures/ffi_layout.json` to the C ABI.
//!
//! Every `#[repr(C)]` struct the FFI passes across the boundary is listed with
//! its size, alignment and the byte offset of each field, as compiled for a
//! 64-bit target. A binding that declares these structs itself instead of
//! compiling against `derec_ffi.h` (Go, through purego) checks its own
//! declarations against this table, so a field added, removed or reordered
//! here fails that binding's tests instead of corrupting memory at run time.
//!
//! Each struct is destructured without `..`, so a new field fails to compile
//! until it is listed. Regenerate with
//! `DEREC_BLESS_FIXTURES=1 cargo test -p derec-library --features ffi --lib interop::ffi::tests`.

use std::{env, fs};

use super::common::DeRecBuffer;
use super::discovery::{
    ExtractGetSecretIdsVersionsRequestResult, ExtractGetSecretIdsVersionsResponseResult,
    ProcessGetSecretIdsVersionsResponseMessageResult,
    ProduceGetSecretIdsVersionsRequestMessageResult,
    ProduceGetSecretIdsVersionsResponseMessageResult,
};
use super::envelope::{ApplyTraceIdResult, ReadTraceIdResult};
use super::error::DeRecError;
use super::message_json::DeRecMessageJsonResult;
use super::pairing::{
    CreateContactMessageResult, DecodeContactMessageResult, EncodeContactMessageResult,
    ExtractPairRequestResult, ExtractPairResponseResult, ExtractPrePairRequestResult,
    ExtractPrePairResponseResult, PairingFingerprintResult, ProcessPairResponseMessageResult,
    ProcessPrePairResponseMessageResult, ProducePairRequestMessageResult,
    ProducePairResponseMessageResult, ProducePrePairNoKeysResponseMessageResult,
    ProducePrePairRequestMessageResult, ProducePrePairResponseMessageResult,
};
use super::protocol::handle::DeRecProtocolNewResult;
use super::protocol::handle::config::DeRecRemovedChannelsResult;
use super::protocol::handle::flow::{
    DeRecProtocolEventsResult, DeRecProtocolProcessResult, DeRecProtocolRestoreResult,
};
use super::protocol::handle::pairing::{
    DeRecProtocolCreateContactResult, DeRecProtocolFingerprintResult,
};
use super::protocol::stores::{
    ChannelStoreCallbacks, SecretStoreCallbacks, ShareStoreCallbacks, StateStoreCallbacks,
    TransportCallbacks, UserSecretStoreCallbacks,
};
use super::protocol_version::DeRecProtocolVersion;
use super::recovery::{
    ExtractGetShareRequestResult, ExtractGetShareResponseResult,
    ProduceGetShareRequestMessageResult, ProduceGetShareResponseMessageResult,
    RecoverFromShareResponsesResult,
};
use super::sharing::{
    ExtractStoreShareRequestResult, ExtractStoreShareResponseResult,
    ProcessStoreShareResponseMessageResult, ProduceStoreShareRequestMessageResult,
    ProduceStoreShareResponseMessageResult, ProtectSecretResult,
};
use super::unpairing::{
    ExtractUnpairRequestResult, ExtractUnpairResponseResult, ProcessUnpairResponseResult,
    ProduceUnpairRequestMessageResult, ProduceUnpairResponseMessageResult,
};
use super::verification::{
    ExtractVerifyShareRequestResult, ExtractVerifyShareResponseResult,
    ProduceVerifyShareRequestMessageResult, ProduceVerifyShareResponseMessageResult,
    VerifyShareResponseResult,
};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/ffi_layout.json"
);

macro_rules! layouts {
    ($($path:path { $($field:ident),* $(,)? }),* $(,)?) => {{
        let mut out = Vec::new();
        $(
            {
                #[allow(dead_code)]
                fn exhaustive(value: $path) {
                    let $path { $($field: _),* } = value;
                }
                type T = $path;
                let name = stringify!($path).rsplit("::").next().expect("a path has a last segment").trim();
                out.push(serde_json::json!({
                    "name": name,
                    "size": std::mem::size_of::<T>(),
                    "align": std::mem::align_of::<T>(),
                    "fields": [$(serde_json::json!({
                        "name": stringify!($field),
                        "offset": std::mem::offset_of!(T, $field),
                    })),*],
                }));
            }
        )*
        out
    }};
}

fn generated() -> serde_json::Value {
    let mut structs = layouts![
        DeRecBuffer { ptr, len },
        ProduceGetSecretIdsVersionsRequestMessageResult {
            error,
            envelope_wire_bytes
        },
        ExtractGetSecretIdsVersionsRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProduceGetSecretIdsVersionsResponseMessageResult {
            error,
            envelope_wire_bytes
        },
        ExtractGetSecretIdsVersionsResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        ProcessGetSecretIdsVersionsResponseMessageResult {
            error,
            secret_list_bytes
        },
        ApplyTraceIdResult { error, wire_bytes },
        ReadTraceIdResult { error, trace_id },
        DeRecError {
            category,
            code,
            message,
            peer_status,
            peer_memo,
            expected,
            got
        },
        DeRecMessageJsonResult { error, bytes },
        CreateContactMessageResult {
            error,
            contact_wire_bytes,
            secret_key_material
        },
        EncodeContactMessageResult { error, wire_bytes },
        DecodeContactMessageResult {
            error,
            contact_json
        },
        ProducePairRequestMessageResult {
            error,
            request_wire_bytes,
            initiator_contact_message_wire_bytes,
            secret_key_material
        },
        ExtractPairRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProducePairResponseMessageResult {
            error,
            response_wire_bytes,
            peer_transports,
            shared_key,
            channel_id
        },
        ExtractPairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        ProcessPairResponseMessageResult {
            error,
            shared_key,
            channel_id
        },
        ProducePrePairRequestMessageResult {
            error,
            envelope_wire_bytes
        },
        ExtractPrePairRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProducePrePairResponseMessageResult {
            error,
            envelope_wire_bytes
        },
        ExtractPrePairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        ProducePrePairNoKeysResponseMessageResult {
            error,
            envelope_wire_bytes,
            secret_key_material
        },
        PairingFingerprintResult { error, fingerprint },
        ProcessPrePairResponseMessageResult {
            error,
            mlkem_encapsulation_key,
            ecies_public_key,
            nonce,
            fingerprint_commitment
        },
        DeRecRemovedChannelsResult { error, channels },
        DeRecProtocolEventsResult { error, events_json },
        DeRecProtocolRestoreResult {
            error,
            events_json,
            conflicting_channel_ids_json
        },
        DeRecProtocolProcessResult {
            error,
            events_json,
            has_channel_id,
            channel_id
        },
        DeRecProtocolNewResult { error, handle },
        DeRecProtocolFingerprintResult { error, fingerprint },
        DeRecProtocolCreateContactResult {
            error,
            contact_wire_bytes
        },
        ChannelStoreCallbacks {
            user_data,
            load,
            save,
            remove,
            list_helpers,
            list_replicas,
            link_channel,
            linked_channels,
            free_buffer
        },
        SecretStoreCallbacks {
            user_data,
            load,
            load_many,
            save,
            remove,
            free_buffer
        },
        ShareStoreCallbacks {
            user_data,
            load,
            load_many,
            load_all,
            latest_version,
            save,
            remove_channel,
            remove_versions,
            keep_version,
            record_verification,
            free_buffer
        },
        UserSecretStoreCallbacks {
            user_data,
            load_latest,
            save_latest,
            remove,
            free_buffer
        },
        StateStoreCallbacks {
            user_data,
            save,
            load,
            remove,
            load_all,
            free_buffer
        },
        TransportCallbacks { user_data, send },
        DeRecProtocolVersion { major, minor },
        ProduceGetShareRequestMessageResult {
            error,
            request_wire_bytes
        },
        ExtractGetShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProduceGetShareResponseMessageResult {
            error,
            response_wire_bytes
        },
        ExtractGetShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        RecoverFromShareResponsesResult { error, secret_data },
        ProtectSecretResult {
            error,
            shares_wire_bytes
        },
        ProduceStoreShareRequestMessageResult { error, wire_bytes },
        ExtractStoreShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProduceStoreShareResponseMessageResult {
            error,
            wire_bytes,
            committed_share_bytes,
            secret_id,
            version
        },
        ExtractStoreShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        ProcessStoreShareResponseMessageResult { error },
        ProduceUnpairRequestMessageResult {
            error,
            request_wire_bytes
        },
        ExtractUnpairRequestResult {
            error,
            channel_id,
            memo,
            request_proto_bytes
        },
        ProduceUnpairResponseMessageResult {
            error,
            response_wire_bytes
        },
        ExtractUnpairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        ProcessUnpairResponseResult { error },
        ProduceVerifyShareRequestMessageResult {
            error,
            request_wire_bytes
        },
        ExtractVerifyShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        ProduceVerifyShareResponseMessageResult {
            error,
            response_wire_bytes
        },
        ExtractVerifyShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        VerifyShareResponseResult { error, is_valid },
    ];
    structs.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    serde_json::json!({
        "$schema_note": "Size, alignment and field offsets of every #[repr(C)] struct the FFI passes across the boundary, compiled for a 64-bit target. Rust generates this file (library/src/interop/ffi/tests.rs); a binding that declares these structs itself (Go) asserts its declarations match. Do not edit by hand.",
        "pointer_width": usize::BITS,
        "structs": structs,
    })
}

#[test]
fn the_ffi_layout_fixture_matches_the_c_abi() {
    assert_eq!(usize::BITS, 64, "the fixture records the 64-bit layout");
    let generated = generated();
    if env::var_os("DEREC_BLESS_FIXTURES").is_some() {
        let text = serde_json::to_string_pretty(&generated).expect("fixture serializes") + "\n";
        fs::write(FIXTURE, text).expect("fixture is writable");
        return;
    }
    let checked_in: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(FIXTURE)
            .expect("ffi_layout.json exists; regenerate with DEREC_BLESS_FIXTURES=1"),
    )
    .expect("ffi_layout.json is valid JSON");
    assert_eq!(
        checked_in, generated,
        "ffi_layout.json is out of step with the C ABI; regenerate with \
         DEREC_BLESS_FIXTURES=1 and update the bindings that declare these structs"
    );
}
