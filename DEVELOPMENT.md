# DeRec installation instructions

This document describes the tools required to build the DeRec Rust SDK
from source.

Users installing the SDK from crates.io **do not need these tools**.

## Rust

Install Rust using [Rustup](https://rustup.rs).

Verify installation:

```bash
rustc --version
cargo --version
```

---

## Unused-dependency check (`cargo-shear`)

`make all` fails if a crate declares a dependency its code does not use.
The check is [`cargo-shear`](https://crates.io/crates/cargo-shear). Its
dependencies need a newer compiler than the one this workspace builds with,
so install it with a recent stable toolchain:

```bash
rustup toolchain install 1.99
cargo +1.99 install cargo-shear --locked
cargo shear --version
```

Once installed it runs under any toolchain. A dependency that is needed but
never named in code (one that only enables a feature, or is used only by
generated code) goes in that crate's `Cargo.toml`:

```toml
[package.metadata.cargo-shear]
ignored = ["crate-name"]
```

---

## Protobuf (`protoc`)

The **Protocol Buffers compiler** (`protoc`) compiler is required to generate Rust types from the
protocol `.proto` definitions when building the workspace.

Verify it's available:

```bash
protoc --version
```

If `protoc` is installed but not on your `PATH`, you can set:
```bash
export PROTOC=/path/to/protoc
```

### macOS

- Homebrew

```bash
brew install protobuf
protoc --version
```

### Linux

- Debian/Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y protobuf-compiler
protoc --version
```

- Fedora

```bash
sudo dnf install -y protobuf-compiler
protoc --version
```

### Windows

- Chocolatey

```ps
choco install protoc
protoc --version
```

- Scoop

```ps
scoop install protobuf
protoc --version
```

---

## WASM Targets

Building WebAssembly packages requires `wasm-pack`.

```bash
cargo install wasm-pack
wasm-pack --version
```

---

## Typescript bindings

The TypeScript examples and bindings tooling use **bun**.

Install bun:

```bash
curl -fsSL https://bun.sh/install | bash
```

Verify:

```bash
bun --version
bunx --version
```
