# derec-proto

![Crates.io](https://img.shields.io/crates/v/derec-proto)
![Docs.rs](https://docs.rs/derec-proto/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Generated Rust protobuf types for the DeRec protocol.

This crate contains the Rust structures generated from the DeRec `.proto`
schema files using `prost`.

These types represent the wire-level protocol messages exchanged by
DeRec participants.

This crate is primarily intended for:

- SDK developers
- low-level protocol integrations
- tooling that needs direct access to DeRec message structures

Most application developers should depend on `derec-library`,
which provides a higher-level API and complete protocol flows.

> [!INFO]
> The Rust types in this crate are generated from `.proto` schema files.
> Changes should be made in the schema definitions rather than editing the generated code directly.

---

## Example

```rust
use derec_proto::ContactMessage;

// Constructing a message directly (typically handled by derec-library)
let msg = ContactMessage::default();
```

> [!NOTE]
> In the current SDK design, applications should not construct or manipulate
> protobuf messages directly. Instead, use `derec-library`, which produces
> and consumes opaque `wire_bytes`.

---

## Relationship with other crates

The DeRec Rust implementation is composed of multiple crates:

- `derec-library` – main SDK used by applications
- `derec-cryptography` – internal cryptographic primitives
- `derec-proto` – generated protocol message types

Most developers should only interact with `derec-library`.

---

## Protocol specification

Full protocol documentation:

https://derec-alliance.gitbook.io/docs/protocol-specification/messages

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.

---

## Contributing

Contributions are welcome.

Repository: https://github.com/derecalliance/lib-derec

Please open issues or pull requests to discuss improvements.

---

## DeRec Alliance

The DeRec Alliance is an open initiative focused on creating standards for decentralized secret recovery.

More information at https://derecalliance.org
