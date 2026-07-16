// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let proto_root = manifest_dir.join("protobufs");

    let proto_files = [
        proto_root.join("committedderecshare.proto"),
        proto_root.join("communicationinfo.proto"),
        proto_root.join("contact.proto"),
        proto_root.join("derecmessage.proto"),
        proto_root.join("derecsecret.proto"),
        proto_root.join("error.proto"),
        proto_root.join("getshare.proto"),
        proto_root.join("pair.proto"),
        proto_root.join("parameterrange.proto"),
        proto_root.join("result.proto"),
        proto_root.join("secretidsversions.proto"),
        proto_root.join("storeshare.proto"),
        proto_root.join("unpair.proto"),
        proto_root.join("verify.proto"),
    ];

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Re-run if proto changes
    println!("cargo:rerun-if-changed={}", proto_root.display());
    for proto in &proto_files {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    // `crate::protocol::types::Channel` in derec-library embeds
    // `TransportProtocol` and `SenderKind` as fields and itself derives
    // `serde::Serialize` / `Deserialize` so the FFI and WASM bridges
    // can ship channel records as JSON across the language boundary
    // without a separate DTO type. Inject serde derives onto those two
    // prost-generated types so `Channel`'s derives compile. Field names
    // round-trip as-is; the `SenderKind` enum uses serde's default
    // representation (variant name as a string).
    prost_build::Config::new()
        .type_attribute(
            ".org.derecalliance.derec.protobuf.TransportProtocol",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            ".org.derecalliance.derec.protobuf.SenderKind",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .out_dir(&out_dir)
        .file_descriptor_set_path(out_dir.join("derec_descriptor.bin"))
        .compile_protos(&proto_files, &[proto_root])
        .expect("Failed to compile .proto files");
}
