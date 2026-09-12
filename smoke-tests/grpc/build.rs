// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=../../protobufs/grpc/derectransport.proto");
    println!("cargo:rerun-if-changed=../../protobufs/protobufs/derecmessage.proto");

    // The DeRec message types already exist as Rust types in `derec-proto`.
    // Mapping the proto name onto that crate keeps a single `DeRecMessage`
    // in the build: the generated service speaks exactly the type the
    // library hands to `DeRecTransport::send`, with no re-encode across a
    // duplicate definition.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .extern_path(".org.derecalliance.derec.protobuf", "::derec_proto")
        .compile_protos(
            &["../../protobufs/grpc/derectransport.proto"],
            // Both roots: the service contract lives under `grpc/`, the
            // `DeRecMessage` it imports under `protobufs/`.
            &["../../protobufs/grpc", "../../protobufs/protobufs"],
        )?;
    Ok(())
}
