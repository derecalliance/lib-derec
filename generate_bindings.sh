mkdir -p bindings/swift
cargo r --features=uniffi/cli --bin uniffi-bindgen -- generate --language swift --library target/release/libderec_library.dylib --out-dir bindings/swift