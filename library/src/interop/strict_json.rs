// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading a binding-supplied settings object strictly: it must be a JSON
//! object, and every key in it, at every level, must be one the target type
//! defines.
//!
//! A JS object handed to the WASM builder is first turned into a
//! [`serde_json::Value`], which keeps every key the object carries, and only
//! then read as the target type. Deserializing the JS object directly reads
//! only the keys the target names, so `deny_unknown_fields` would never see a
//! misspelled one.

/// `value` read as `T`, refusing anything but a JSON object and every key
/// `T` does not define.
pub(crate) fn object_into<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, String> {
    if !value.is_object() {
        return Err(format!("expected an object, got {}", kind(&value)));
    }
    serde_json::from_value(value).map_err(|e| e.to_string())
}

fn kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::object_into;
    use crate::protocol::{DeRecProtocolConfig, TimeoutsConfig};

    #[test]
    fn a_valid_config_object_is_read() {
        let config: DeRecProtocolConfig = object_into(json!({
            "threshold": 3,
            "timeouts": { "sharing_round_secs": 30 },
            "replica_id": "7"
        }))
        .expect("valid config");
        assert_eq!(config.threshold, Some(3));
        assert_eq!(config.replica_id, Some(7));
        assert_eq!(config.timeouts.and_then(|t| t.sharing_round_secs), Some(30));
    }

    #[test]
    fn a_misspelled_top_level_key_is_refused() {
        let err = object_into::<DeRecProtocolConfig>(json!({ "treshold": 3 }))
            .expect_err("misspelled key");
        assert!(err.contains("unknown field `treshold`"), "{err}");
    }

    #[test]
    fn a_misspelled_nested_key_is_refused() {
        let err = object_into::<DeRecProtocolConfig>(json!({
            "timeouts": { "sharing_round": 30 }
        }))
        .expect_err("misspelled nested key");
        assert!(err.contains("unknown field `sharing_round`"), "{err}");

        let err = object_into::<TimeoutsConfig>(json!({ "sharing_round": 30 }))
            .expect_err("misspelled timeouts key");
        assert!(err.contains("unknown field `sharing_round`"), "{err}");
    }

    #[test]
    fn anything_but_an_object_is_refused() {
        for value in [json!([3]), json!(null), json!("threshold"), json!(3)] {
            let err = object_into::<DeRecProtocolConfig>(value.clone()).expect_err("not an object");
            assert!(err.starts_with("expected an object"), "{value}: {err}");
        }
    }
}
