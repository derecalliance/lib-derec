// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

pub mod channel_key;
pub mod envelope;
pub mod primitives;
pub mod protocol;
pub mod protocol_version;
pub mod replica_id;
pub(crate) mod ts_bindings_utils;

use js_sys::Date;

pub(crate) fn now_secs() -> u64 {
    (Date::now() / 1000.0) as u64
}
