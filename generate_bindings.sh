cargo b --release

mkdir -p library/bindings/swift
cargo r --features=uniffi/cli --bin uniffi-bindgen -- generate --language swift --library target/release/libderec_library.dylib --out-dir library/bindings/swift

bunx wasm-pack build --out-dir bindings/typescript --mode normal --release --target bundler library --no-default-features --features ffi_wasm
