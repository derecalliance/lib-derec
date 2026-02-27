// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from("../protobufs");

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
    for proto in &proto_files {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    prost_build::Config::new()
        .out_dir(out_dir.clone())
        .compile_protos(&proto_files, &[proto_root])
        .expect("Failed to compile .proto files");
}
