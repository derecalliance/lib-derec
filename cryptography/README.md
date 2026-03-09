# derec-cryptography

Cryptographic primitives used by the **DeRec protocol implementation**.

This crate contains the low-level cryptographic building blocks required by
`derec-library`, including key generation, encapsulation, and serialization
utilities used by the DeRec pairing and recovery flows.

This crate is **not intended to be used directly by application developers**.
Instead, most users should depend on the higher level SDK `derec-library`
which provides the complete protocol implementation and developer-facing APIs.

---

## Scope

This crate provides implementations and utilities for:

- ML-KEM key encapsulation mechanisms
- ECIES key generation and shared secret derivation
- serialization helpers for elliptic curve keys
- cryptographic hashing utilities used in the protocol
- primitives required by DeRec pairing flows

The cryptographic constructions rely heavily on well-established libraries
including:

- `arkworks`
- `ml-kem`
- `aes-gcm`
- `sha2`

These libraries are used to implement the cryptographic mechanisms specified
by the DeRec protocol.

---

## Security notice

This crate exposes **low-level cryptographic functionality** and does not
provide the protocol-level safety guarantees expected by applications.

Application developers should **not construct protocol messages manually**
using this crate.

Instead, use the higher-level APIs provided by `derec-library`.

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.

---

## Documentation

Full protocol documentation is available at:

https://derecalliance.gitbook.io/protocol
