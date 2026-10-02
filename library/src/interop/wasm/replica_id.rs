use wasm_bindgen::prelude::*;

/// A fresh replica identity. See [`crate::generate_replica_id`]: the caller
/// persists it once per device and passes the same value on every protocol
/// init. Never `0`.
#[wasm_bindgen(js_name = "generate_replica_id")]
pub fn generate_replica_id() -> u64 {
    crate::generate_replica_id()
}
