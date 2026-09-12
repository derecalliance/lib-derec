// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use derec_proto::Protocol;

#[test]
fn grpc_discriminant_is_one() {
    assert_eq!(Protocol::Grpc as i32, 1);
}

#[test]
fn grpc_round_trips_through_i32() {
    assert_eq!(Protocol::try_from(1), Ok(Protocol::Grpc));
}

#[test]
fn https_discriminant_is_unchanged() {
    assert_eq!(Protocol::Https as i32, 0);
}
