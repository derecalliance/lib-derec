// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use crate::primitives::{recovery::RecoveryError, sharing::SharingError};
use serde::Serialize;
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Serialize)]
struct TsError {
    category: &'static str,
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    got: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_ids: Option<Vec<String>>,
}

pub(crate) fn js_error(code: &'static str, message: impl Into<String>) -> JsValue {
    let payload = TsError {
        category: "wasm",
        code,
        message: message.into(),
        status: None,
        memo: None,
        expected: None,
        got: None,
        channel_ids: None,
    };
    serde_wasm_bindgen::to_value(&payload)
        .unwrap_or_else(|_| JsValue::from_str("failed to serialize error"))
}

pub(crate) fn js_error_from_lib(err: crate::Error) -> JsValue {
    let (category, code) = categorize(&err);
    let message = err.to_string();
    let (status, memo) = err
        .as_non_ok_status()
        .map(|(s, m)| (Some(s), Some(m.to_owned())))
        .unwrap_or((None, None));
    let (expected, got) = match &err {
        crate::Error::Sharing(SharingError::VersionMismatch { expected, got })
        | crate::Error::Recovery(RecoveryError::VersionMismatch { expected, got }) => {
            (Some(*expected), Some(*got))
        }
        _ => (None, None),
    };
    let channel_ids = match &err {
        crate::Error::Restore(crate::protocol::RestoreError::Conflict(ids)) => {
            Some(ids.iter().map(|c| c.0.to_string()).collect())
        }
        _ => None,
    };
    let payload = TsError {
        category,
        code,
        message,
        status,
        memo,
        expected,
        got,
        channel_ids,
    };
    serde_wasm_bindgen::to_value(&payload)
        .unwrap_or_else(|_| JsValue::from_str("failed to serialize error"))
}

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}

fn categorize(err: &crate::Error) -> (&'static str, &'static str) {
    let (category, code) = crate::interop::error_codes::classify(err);
    (category.name(), code.name())
}
