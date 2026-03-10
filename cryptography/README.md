# derec-cryptography

![Crates.io](https://img.shields.io/crates/v/derec-cryptography)
![Docs.rs](https://docs.rs/derec-cryptography/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Low-level cryptographic primitives used by the **DeRec protocol implementation**.

This crate contains the low-level cryptographic building blocks required by
`derec-library`, including key generation, encapsulation, and serialization
utilities used by the DeRec pairing and recovery flows.

This crate is **not intended to be used directly by application developers**.
Instead, most users should depend on the higher level SDK `derec-library`
which provides the complete protocol implementation and developer-facing APIs.

---

## Scope

This crate provides implementations and utilities for:

- ML-KEM key encapsulation mechanisms (KEM)
- ECIES key generation and shared secret derivation
- Serialization helpers for elliptic curve keys
- Cryptographic hashing utilities used in the protocol
- Primitives required by DeRec pairing flows

The cryptographic constructions rely on well-established cryptographic libraries,
including:

- `arkworks` (elliptic curve arithmetic)
- `ml-kem` (post-quantum key encapsulation)
- `aes-gcm` (authenticated encryption)
- `sha2` (cryptographic hashing)

These libraries are used to implement the cryptographic mechanisms specified
by the DeRec protocol.

---

## Relationship with other crates

The DeRec Rust implementation is composed of multiple crates:

- `derec-library` – main SDK used by applications
- `derec-cryptography` – internal cryptographic primitives
- `derec-proto` – generated protocol message types

Most developers should only interact with `derec-library`.

---

## Security notice

This crate exposes **low-level cryptographic functionality** and does not enforce
the protocol-level safety guarantees required by applications.

Misuse of these primitives may lead to insecure implementations.

Applications should rely on the higher-level SDK provided by `derec-library`,
which implements the full DeRec protocol flows and safety checks.

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.

---

## Documentation

Full protocol documentation is available at:

https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview

---

## DeRec Alliance

The DeRec Alliance is an open initiative focused on creating standards for decentralized secret recovery.

More information at https://derecalliance.org
