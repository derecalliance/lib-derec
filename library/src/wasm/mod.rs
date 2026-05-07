pub mod primitives;
pub mod protocol;
pub(crate) mod ts_bindings_utils;

/// Returns the current unix timestamp in seconds (WASM variant).
pub(crate) fn now_secs() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
