# lib-derec

Reference implementation of the **[DeRec Protocol](https://github.com/derecalliance/protocol/blob/main/protocol.md)** in Rust.

This repository provides the Rust SDK and supporting crates required to build
applications that implement the DeRec protocol, including native Rust environments
and WebAssembly targets.

Typical applications include:

- Cryptocurrency wallets
- Digital identity systems
- Secure backup and recovery systems
- Key management infrastructure

---

## Repository Structure

This repository contains multiple crates forming the Rust implementation of DeRec.

```bash
lib-derec/
├── protobufs      # Generated protobuf message types
├── cryptography   # Cryptographic primitives used by the protocol
├── library        # Main SDK exposed to application developers
├── bindings/      # Example bindings and integration samples
```

Most developers should interact only with `derec-library` crate. Other crates are internal components used by the SDK.

---

## Development Setup

See [DEVELOPMENT.md](DEVELOPMENT.md) for instructions on setting up the development environment.

---

## Installation

Add the crate to your project via `cargo`:

```bash
cargo add derec-library
```

Or manually in your `Cargo.toml`

```toml
[dependencies]
derec-library = "0.0.1-alpha.1"
```

> [!WARNING]
> Note: this is a pre-release version. APIs may change until 0.1.0.

---

## Building the project

Build all crates in the workspace:

```bash
cargo build --workspace
```

Run tests:

```bash
carto test --workspace
```

---

## Building WebAssembly Packages

The `derec-library` crate supports WebAssembly builds for both Node.js and browser environments.

From the library/ directory run:

```bash
make
```

This produces two wasm-bindgen packages:

```bash
library/target/pkg-node
library/target/pkg-web
```

### Node.js package

```bash
library/target/pkg-node
```

Optimized for Node.js and may rely on built-in modules such as:

* `fs`
* `path`
* `util`

### Browser packege

```bash
library/target/pkg-web
```

Targeted for browser environments and avoids Node-specific modules.

Front-end applications should import from this directory to prevent bundlers from
including Node-only dependencies.

---

## Example Node.js Binding

A simple Node.js example can be found in `bindings/node/index.ts`.
Run it with:

```bash
cd bindings/node
npm install
./run_test.sh
```

---

## Protocol Documentation

* [Full protocol specification](https://github.com/derecalliance/protocol)
* [Developer documentation](https://derecalliance.gitbook.io/docs)

---

## Contributing

Contributions are welcome.

Development guidelines, publishing procedures, and workspace structure are
documented in `CONTRIBUTING.md`.

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.

---

## DeRec Alliance

The DeRec Alliance is an open initiative focused on creating standards for decentralized secret recovery.

More information at https://derecalliance.org
