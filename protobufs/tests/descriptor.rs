// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

#![cfg(feature = "descriptor")]

use derec_proto::descriptor::{FILE_DESCRIPTOR_SET, transport_descriptor};
use prost::Message as _;
use prost_types::FileDescriptorSet;

/// Every `.proto` the crate is compiled from.
const SCHEMA_FILES: [&str; 18] = [
    "committedderecshare.proto",
    "communicationinfo.proto",
    "contact.proto",
    "derecmessage.proto",
    "derecsecret.proto",
    "derectransport.proto",
    "error.proto",
    "getshare.proto",
    "pair.proto",
    "parameterrange.proto",
    "prepair.proto",
    "result.proto",
    "secretidsversions.proto",
    "storeshare.proto",
    "transportprotocol.proto",
    "unpair.proto",
    "updatechannelinfo.proto",
    "verify.proto",
];

fn decoded() -> FileDescriptorSet {
    FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("descriptor must decode")
}

#[test]
fn descriptor_decodes() {
    assert!(!decoded().file.is_empty());
}

#[test]
fn closure_contains_every_schema_file() {
    let fds = decoded();
    let names: Vec<&str> = fds.file.iter().map(|f| f.name()).collect();
    for expected in SCHEMA_FILES {
        assert!(names.contains(&expected), "missing {expected} from closure");
    }
}

#[test]
fn closure_contains_well_known_types() {
    let fds = decoded();
    let names: Vec<&str> = fds.file.iter().map(|f| f.name()).collect();
    assert!(names.contains(&"google/protobuf/timestamp.proto"));
    assert!(names.contains(&"google/protobuf/empty.proto"));
}

#[test]
fn transport_descriptor_is_only_the_transport_file() {
    let fds = transport_descriptor();
    assert_eq!(fds.file.len(), 1);
    assert_eq!(fds.file[0].name(), "derectransport.proto");
}
