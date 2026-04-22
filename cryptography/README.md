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
- Envelope encryption for message payload protection
- Replica fingerprint derivation for device-to-device confirmation

The cryptographic constructions rely on well-established cryptographic libraries,
including:

- `arkworks` (elliptic curve arithmetic)
- `ml-kem` (post-quantum key encapsulation)
- `aes-gcm` (authenticated encryption)
- `sha2` (cryptographic hashing)

These libraries are used to implement the cryptographic mechanisms specified
by the DeRec protocol.

---

## Envelope Encryption

The module `pairing::envelope` provides ECIES-style hybrid encryption used to
protect DeRec message payloads.

It combines:

- secp256k1 ECDH (via internal `pairing_ecies`)
- AES-256-GCM authenticated encryption (via `channel`)

### Design

Encryption follows a standard ECIES pattern:

1. Generate ephemeral keypair
2. Derive shared key via ECDH
3. Encrypt payload using AES-256-GCM
4. Output:

```
[u32 epk_len][epk_bytes][ciphertext]
```

Decryption performs the inverse operation using the recipient secret key.

### Responsibilities

This module:

- encrypts arbitrary byte payloads to a recipient public key
- decrypts ciphertext using a recipient secret key

This module does **not**:

- enforce protocol semantics
- perform signing
- know about higher-level DeRec flows

### Example

```rust
use derec_cryptography::pairing::envelope;

let ciphertext = envelope::encrypt(b"hello", &receiver_pk).unwrap();
let plaintext = envelope::decrypt(&ciphertext, &receiver_sk).unwrap();
```

---

## Replica Fingerprint

The module `replica` derives a 16-digit decimal fingerprint from the 32-byte
shared key established during Replica pairing. Both devices display this
fingerprint so the user can visually confirm they are pairing with the correct
peer (similar to Bluetooth pairing).

### Algorithm

1. Compute `H = SHA-256(K)` where `K` is the 32-byte shared key.
2. Split `H` into 16 consecutive 2-byte chunks.
3. Interpret each chunk as a big-endian `u16`, then compute `digit = value % 10`.
4. The result is a 16-element array where each element is a single decimal digit (`0..=9`).

Applications may choose any user-friendly rendering format, for example
`XXXX-XXXX-XXXX-XXXX`.

### Properties

- **Deterministic** — both peers derive the same fingerprint from the same key.
- **No secret material leaked** — the fingerprint is a lossy hash of the key;
  it cannot be reversed to recover the shared key.

### Example

```rust
use derec_cryptography::replica;

let shared_key = [0xABu8; 32];
let digits = replica::fingerprint(&shared_key);

assert_eq!(digits.len(), 16);
assert!(digits.iter().all(|&d| d < 10));
```

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
