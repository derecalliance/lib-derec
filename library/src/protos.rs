// SPDX-License-Identifier: Apache-2.0

pub mod derec_proto {
    include!(concat!(
        env!("OUT_DIR"),
        "/org.derecalliance.derec.protobuf.rs"
    ));
}
