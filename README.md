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
├── smoke-tests/      # End-to-end tests for every SDK
├── packages/      # Package wrappers for each SDK supported
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
derec-library = "0.0.2"
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
cargo test --workspace
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
library/target/pkg-nodejs
library/target/pkg-web
```

### Node.js package

```bash
library/target/pkg-nodejs
```

Optimized for Node.js and may rely on built-in modules such as:

* `fs`
* `path`
* `util`

### Browser package

```bash
library/target/pkg-web
```

Targeted for browser environments and avoids Node-specific modules.

Front-end applications should import from this directory to prevent bundlers from
including Node-only dependencies.

---

## End-to-end test coverage

End-to-end smoke tests live under `smoke-tests/` and exercise every primitive
flow plus the high-level `DeRecProtocol` orchestrator (Owner↔Helper pair,
ProtectSecret, Discovery, Recovery, replica secret sync) across every SDK:

- `smoke-tests/rust` — Rust primitive + protocol tests. Run with `cargo run -p derec-rust-binding-smoke-test`.
- `smoke-tests/nodejs` — Node.js WASM tests. `cd smoke-tests/nodejs && npm install && npx tsc && node index.js`.
- `smoke-tests/web` — Browser WASM tests. `cd smoke-tests/web && npm install && npm run build` and open via `npm run dev`.
- `smoke-tests/dotnet` — .NET P/Invoke tests against the C ABI, including the orchestrator. `cd smoke-tests/dotnet && dotnet run`.
- `smoke-tests/react-native` — React Native JSI tests against the C ABI on an iOS simulator
  and an Android emulator, including the orchestrator. Run with
  `smoke-tests/react-native/run_test.sh` (booted devices are not required; it starts them).
- `smoke-tests/go` — Go purego (no cgo) tests against the C ABI, including the orchestrator. `cd smoke-tests/go && go run .`.

Two reference storage backends implementing all six store traits over a real
database also live here and run the full protocol suite:

- `smoke-tests/sqlite` — SQLite-backed stores. `cd smoke-tests/sqlite && cargo run`.
- `smoke-tests/postgres` — Postgres-backed stores (needs a Postgres reachable at `DATABASE_URL`, default `postgres://postgres:postgres@localhost:15432/derec_test`). `cd smoke-tests/postgres && cargo run`.

## Replica feature

Replicas mirror an Owner's secret onto a second device so the same secrets
remain reachable after device loss. Pairings are **unidirectional** — one
side runs as `SenderKind::ReplicaSource` (owns the secret), the other as
`SenderKind::ReplicaDestination` (receives it). After a fingerprint
cross-confirmation, the Source includes the Destination as a
`ProtectSecret` target alongside helpers. Helpers receive the usual VSS
share; the Destination receives the full `Secret` + per-helper
share map and surfaces it as a typed `ReplicaSecretReceived` event. Each
SDK README has a focused "Replica flows" section with a runnable example.

---

## Protocol Documentation

* [Full protocol specification](https://github.com/derecalliance/protocol)
* [Developer documentation](https://derec-alliance.gitbook.io/docs)

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

More information at https://derec.org
