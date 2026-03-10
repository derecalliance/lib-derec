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
