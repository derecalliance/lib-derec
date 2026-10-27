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
        super::common::DeRecBuffer { ptr, len },
        super::discovery::ProduceGetSecretIdsVersionsRequestMessageResult {
            error,
            envelope_wire_bytes
        },
        super::discovery::ExtractGetSecretIdsVersionsRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::discovery::ProduceGetSecretIdsVersionsResponseMessageResult {
            error,
            envelope_wire_bytes
        },
        super::discovery::ExtractGetSecretIdsVersionsResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::discovery::ProcessGetSecretIdsVersionsResponseMessageResult {
            error,
            secret_list_bytes
        },
        super::envelope::ApplyTraceIdResult { error, wire_bytes },
        super::envelope::ReadTraceIdResult { error, trace_id },
        super::error::DeRecError {
            category,
            code,
            message,
            peer_status,
            peer_memo,
            expected,
            got
        },
        super::message_json::DeRecMessageJsonResult { error, bytes },
        super::pairing::CreateContactMessageResult {
            error,
            contact_wire_bytes,
            secret_key_material
        },
        super::pairing::EncodeContactMessageResult { error, wire_bytes },
        super::pairing::DecodeContactMessageResult {
            error,
            contact_json
        },
        super::pairing::ProducePairRequestMessageResult {
            error,
            request_wire_bytes,
            initiator_contact_message_wire_bytes,
            secret_key_material
        },
        super::pairing::ExtractPairRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::pairing::ProducePairResponseMessageResult {
            error,
            response_wire_bytes,
            peer_transports,
            shared_key,
            channel_id
        },
        super::pairing::ExtractPairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::pairing::ProcessPairResponseMessageResult {
            error,
            shared_key,
            channel_id
        },
        super::pairing::ProducePrePairRequestMessageResult {
            error,
            envelope_wire_bytes
        },
        super::pairing::ExtractPrePairRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::pairing::ProducePrePairResponseMessageResult {
            error,
            envelope_wire_bytes
        },
        super::pairing::ExtractPrePairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::pairing::ProducePrePairNoKeysResponseMessageResult {
            error,
            envelope_wire_bytes,
            secret_key_material
        },
        super::pairing::PairingFingerprintResult { error, fingerprint },
        super::pairing::ProcessPrePairResponseMessageResult {
            error,
            mlkem_encapsulation_key,
            ecies_public_key,
            nonce,
            fingerprint_commitment
        },
        super::protocol::handle::config::DeRecRemovedChannelsResult { error, channels },
        super::protocol::handle::flow::DeRecProtocolEventsResult { error, events_json },
        super::protocol::handle::flow::DeRecProtocolRestoreResult {
            error,
            events_json,
            conflicting_channel_ids_json
        },
        super::protocol::handle::flow::DeRecProtocolProcessResult {
            error,
            events_json,
            has_channel_id,
            channel_id
        },
        super::protocol::handle::DeRecProtocolNewResult { error, handle },
        super::protocol::handle::pairing::DeRecProtocolFingerprintResult { error, fingerprint },
        super::protocol::handle::pairing::DeRecProtocolCreateContactResult {
            error,
            contact_wire_bytes
        },
        super::protocol::stores::ChannelStoreCallbacks {
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
        super::protocol::stores::SecretStoreCallbacks {
            user_data,
            load,
            load_many,
            save,
            remove,
            free_buffer
        },
        super::protocol::stores::ShareStoreCallbacks {
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
        super::protocol::stores::UserSecretStoreCallbacks {
            user_data,
            load_latest,
            save_latest,
            remove,
            free_buffer
        },
        super::protocol::stores::StateStoreCallbacks {
            user_data,
            save,
            load,
            remove,
            load_all,
            free_buffer
        },
        super::protocol::stores::TransportCallbacks { user_data, send },
        super::protocol_version::DeRecProtocolVersion { major, minor },
        super::recovery::ProduceGetShareRequestMessageResult {
            error,
            request_wire_bytes
        },
        super::recovery::ExtractGetShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::recovery::ProduceGetShareResponseMessageResult {
            error,
            response_wire_bytes
        },
        super::recovery::ExtractGetShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::recovery::RecoverFromShareResponsesResult { error, secret_data },
        super::sharing::ProtectSecretResult {
            error,
            shares_wire_bytes
        },
        super::sharing::ProduceStoreShareRequestMessageResult { error, wire_bytes },
        super::sharing::ExtractStoreShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::sharing::ProduceStoreShareResponseMessageResult {
            error,
            wire_bytes,
            committed_share_bytes,
            secret_id,
            version
        },
        super::sharing::ExtractStoreShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::sharing::ProcessStoreShareResponseMessageResult { error },
        super::unpairing::ProduceUnpairRequestMessageResult {
            error,
            request_wire_bytes
        },
        super::unpairing::ExtractUnpairRequestResult {
            error,
            channel_id,
            memo,
            request_proto_bytes
        },
        super::unpairing::ProduceUnpairResponseMessageResult {
            error,
            response_wire_bytes
        },
        super::unpairing::ExtractUnpairResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::unpairing::ProcessUnpairResponseResult { error },
        super::verification::ProduceVerifyShareRequestMessageResult {
            error,
            request_wire_bytes
        },
        super::verification::ExtractVerifyShareRequestResult {
            error,
            channel_id,
            request_proto_bytes
        },
        super::verification::ProduceVerifyShareResponseMessageResult {
            error,
            response_wire_bytes
        },
        super::verification::ExtractVerifyShareResponseResult {
            error,
            channel_id,
            response_proto_bytes
        },
        super::verification::VerifyShareResponseResult { error, is_valid },
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
    if std::env::var_os("DEREC_BLESS_FIXTURES").is_some() {
        let text = serde_json::to_string_pretty(&generated).expect("fixture serializes") + "\n";
        std::fs::write(FIXTURE, text).expect("fixture is writable");
        return;
    }
    let checked_in: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(FIXTURE)
            .expect("ffi_layout.json exists; regenerate with DEREC_BLESS_FIXTURES=1"),
    )
    .expect("ffi_layout.json is valid JSON");
    assert_eq!(
        checked_in, generated,
        "ffi_layout.json is out of step with the C ABI; regenerate with \
         DEREC_BLESS_FIXTURES=1 and update the bindings that declare these structs"
    );
}
