# DeRec Rust SDK

![Crates.io](https://img.shields.io/crates/v/derec-library)
![Docs.rs](https://docs.rs/derec-library/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Rust implementation of the **DeRec protocol**, providing tools to securely distribute, store, verify, and recover secret shares across trusted helpers.

This crate implements the protocol defined by the **DeRec Alliance** and provides APIs for building applications that support decentralized secret recovery.

Typical applications include:

- Cryptocurrency wallets
- Digital identity systems
- Secure backup systems
- Key management infrastructure

The library supports both **native Rust environments** and **WebAssembly targets**, enabling use in backend services, mobile apps, and browser-based applications.

---

## What is DeRec?

The **DeRec protocol** allows a secret to be split into multiple shares and stored by independent helpers.

When recovery is required, a sufficient number of helpers can provide their shares to reconstruct the original secret.

Key properties:

- **Threshold secret sharing**
- **Helper-based recovery**
- **Verifiable share storage**
- **Transport-agnostic protocol**

This SDK implements the message flows and cryptographic mechanisms required by the protocol.

---

## Installation

Add the crate to your project via `cargo`:

```bash
cargo add derec-library
```

Or manually in your `Cargo.toml`

```toml
[dependencies]
derec-library = "0.0.1-alpha.6"
```

> [!WARNING]
> Note: this is a pre-release version. APIs may change until 0.1.0.

## Basic Concepts

The protocol involves two primary roles: **Owner** and **Helper**.

### Owner

The party that wants to protect a secret.

Responsibilities:
* Split the secret into shares
* Distribute shares to helpers
* Verify helpers still possess the shares
* Recover the secret when necessary

### Helper

A trusted entity that stores a share for the Owner.

Responsibilities:
* Store the share
* Respond to verification challenges
* Provide shares during recovery

---

## Protocol Flows

The SDK provides building blocks for the main protocol flows.

| Flow | Purpose |
|------|--------|
| Pairing | Establish secure communication between owner and helper |
| Share Distribution | Split and distribute secret shares |
| Verification | Ensure helpers still possess shares |
| Recovery | Retrieve shares and reconstruct the secret |
| Unpairing | Terminate the helper relationship |


## Quick Intro

```rust
use derec_library::verification::*;

let secret_id = b"example_secret";

let request = generate_verification_request(secret_id, 1).unwrap();
```

See the examples down below for complete protocol flows.

---

## WebAssembly Support

The library also provides WebAssembly bindings so the protocol can run in:
* Browsers
* Mobile wallets
* Web applications

Example JavaScript usage:

```ts
import * as derec from "derec-library";

const request = derec.generate_verification_request(secretId, version);
```

Bindings are generated using `wasm-bindgen`.

---

## Transport Layer

The DeRec protocol is transport agnostic.

Applications may use any communication channel including:

* HTTPS
* WebSockets
* Message queues
* Custom relay servers

> [!INFO]
> Currently, only the HTTPS transport protocol is supported.

The `transportUri` in protocol messages identifies the helper endpoint.

---

## Examples

### Pairing Flow

```rust
use derec_library::pairing::*;
use derec_proto::SenderKind;

let channel_id = 42.into();

// Step 1
let CreateContactMessageResult {
    wire_bytes: contact_message_bytes,
    secret_key: contactor_secret_key,
} = create_contact_message(
    channel_id,
    "https://relay.example/derec",
).unwrap();

// Step 2
let ProducePairingRequestMessageResult {
    wire_bytes: pair_request_wire_bytes,
    secret_key: requestor_secret_key,
} = produce_pairing_request_message(
    SenderKind::Helper,
    "https://example-helper.com/derec",
    &contact_message_bytes,
).unwrap();

// Step 3
let ProducePairingResponseMessageResult {
    wire_bytes: pair_response_wire_bytes,
    shared_key,
    ..
} = produce_pairing_response_message(
    SenderKind::SharerNonRecovery,
    &pair_request_wire_bytes,
    &contactor_secret_key,
).unwrap();

// Step 4
let ProcessPairingResponseMessageResult { shared_key } =
    process_pairing_response_message(
        &contact_message_bytes,
        &pair_response_wire_bytes,
        &requestor_secret_key,
    ).unwrap();
```

The `ContactMessage` is exchanged out-of-band, typically using:

* QR codes
* Existing communication channels

---

### Sharing Flow

```rust
use derec_library::sharing::*;

let secret_id = b"my_secret";
let secret_data = b"super_secret_value";
let channels = [1.into(), 2.into(), 3.into()];
let threshold = 2;
let version = 1;

let ProtectSecretResult {
    share_message_wire_bytes_array,
} = protect_secret(
    secret_id,
    secret_data,
    &channels,
    threshold,
    version,
    None,
    None,
).unwrap();
```

---

### Verification Flow

```rust
use derec_library::verification::*;

let secret_id = b"secret_id";
let version = 7;

let request = generate_verification_request(secret_id, version).unwrap();

let response = generate_verification_response(
    b"example_share",
    &request.wire_bytes,
).unwrap();

let ok = verify_share_response(
    b"example_share",
    &request.wire_bytes,
    &response.wire_bytes,
).unwrap();

assert!(ok);
```

---

### Recovery Flow

```rust
use derec_library::recovery::*;

let secret_id = b"secret_id";
let version = 1;

let request = generate_share_request(secret_id, version).unwrap();

let response = generate_share_response(
    &request.wire_bytes,
    b"example_share",
).unwrap();

let _ = recover_from_share_responses(
    b"...aggregated responses...",
    secret_id,
    version,
).unwrap();
```

---

## Protocol specification

Full protocol documentation:

https://derec-alliance.gitbook.io/docs/protocol-specification/messages

---

## Security Considerations

Applications using this SDK should ensure:
* Secure storage of secret material
* Proper authentication of helpers
* Safe transport channels
* Protection against replay attacks

The DeRec protocol design assumes helpers are independent and trusted entities.

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
