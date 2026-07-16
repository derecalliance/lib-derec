// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

impl From<prost_types::Timestamp> for Timestamp {
    fn from(value: prost_types::Timestamp) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

impl From<Timestamp> for prost_types::Timestamp {
    fn from(value: Timestamp) -> Self {
        Self {
            seconds: value.seconds,
            nanos: value.nanos,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DeRecResult {
    pub status: i32,
    pub memo: String,
}

impl From<derec_proto::DeRecResult> for DeRecResult {
    fn from(value: derec_proto::DeRecResult) -> Self {
        Self {
            status: value.status,
            memo: value.memo,
        }
    }
}

impl From<DeRecResult> for derec_proto::DeRecResult {
    fn from(value: DeRecResult) -> Self {
        Self {
            status: value.status,
            memo: value.memo,
        }
    }
}
