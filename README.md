# lib-rust
Reference implementation of the [DeRec Protocol](https://github.com/derecalliance/protocol/blob/main/protocol.md) in Rust.

## Building the WASM package

From the `library/` directory run `make` to produce the native library as well as WebAssembly bundles for both Node.js and browser environments. The build now emits two separate wasm-bindgen packages:

* `library/target/pkg-node` – optimized for Node.js tooling and still relies on Node built-ins such as `fs`.
* `library/target/pkg-web` – targeted at the browser and free of Node-specific modules, making it safe to import in front-end applications.

Point your browser builds at `library/target/pkg-web` to avoid bundlers pulling in Node-only modules like `fs`, `path`, or `util`.
