// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The schema arrives as a descriptor carried inside `derec-proto`, so
    // there is nothing on disk to watch and no include path to resolve.
    // Cargo reruns this script when that crate changes.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .extern_path(".org.derecalliance.derec.protobuf", "::derec_proto")
        .compile_fds(derec_proto::descriptor::transport_descriptor())?;
    Ok(())
}
