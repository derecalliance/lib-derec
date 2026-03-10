# Contributing Guide

Thank you for your interest in contributing to the **DeRec Rust implementation**.

This repository contains the reference Rust implementation of the
[DeRec Protocol](https://github.com/derecalliance/protocol/blob/main/protocol.md).

All contributions are welcome.

---

# Repository Overview

This repository is organized as a Rust workspace containing several crates.

```
lib-derec/
├── protobufs      # Generated protobuf protocol types
├── cryptography   # Cryptographic primitives used by the protocol
├── library        # Main SDK used by applications
├── bindings/      # Example bindings and integration samples
```

Crate responsibilities:

| Crate | Purpose |
|------|--------|
| `derec-proto` | Generated protobuf message definitions |
| `derec-cryptography` | Cryptographic primitives used by the protocol |
| `derec-library` | Main SDK implementing the DeRec protocol |

Most application developers will interact only with **`derec-library`**.

---

# Development Setup

Before building the project, install the required development tools.

See:

```
INSTALL.md
```

This document explains how to install:

- Rust
- `protoc` (Protocol Buffers compiler)
- `wasm-pack`
- `bun` (for TypeScript bindings)

---

# Building the Workspace

Build all crates:

```bash
cargo build --workspace
```

Run tests:

```bash
cargo test --workspace
```

Format the code:

```bash
cargo fmt
```

---

# WebAssembly Builds

The WebAssembly builds are produced from the `derec-library` crate.

From the `derec-library/` directory run:

```bash
make
```

This produces two WASM packages:

```
target/pkg-node
target/pkg-web
```

- `pkg-node` → optimized for Node.js environments
- `pkg-web` → optimized for browser environments

---

# Reporting Issues

If you find a bug or want to request a feature, please open an issue including:

- A clear and descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Logs, screenshots, or examples if applicable

---

# Submitting Contributions

1. Fork the repository.

2. Clone your fork:

```bash
git clone https://github.com/<your-username>/lib-derec
cd lib-derec
```

3. Add the upstream repository:

```bash
git remote add upstream https://github.com/derecalliance/lib-derec
```

4. Create a new branch:

```bash
git checkout -b my-feature
```

5. Implement your changes.

6. Ensure the project builds and tests pass:

```bash
cargo build --workspace
cargo test --workspace
```

7. Push your branch:

```bash
git push origin my-feature
```

8. Open a Pull Request.

---

# Code Style

Please follow existing project conventions:

- Use `rustfmt` formatting
- Prefer clear and descriptive names
- Document public APIs using `rustdoc`
- Add tests for new functionality

Run formatting locally:

```bash
cargo fmt
```

---

# Release Process

Publishing crates is documented in:

```
RELEASE.md
```

This document describes:

- crate version updates
- dependency ordering
- publishing procedures

---

# Getting Help

If you need help:

- Check the README and documentation
- Search existing issues
- Open a new issue or discussion if necessary

---

Thank you for contributing to the **DeRec ecosystem**.
