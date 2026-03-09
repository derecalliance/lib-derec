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

# What is DeRec?

The **DeRec protocol** allows a secret to be split into multiple shares and stored by independent helpers.

When recovery is required, a sufficient number of helpers can provide their shares to reconstruct the original secret.

Key properties:

- **Threshold secret sharing**
- **Helper-based recovery**
- **Verifiable share storage**
- **Transport-agnostic protocol**

This SDK implements the message flows and cryptographic mechanisms required by the protocol.

---

# Installation

Add the crate to your project:

```toml
[dependencies]
derec-library = "0.0.1-alpha.1"
```

# Basic Concepts

The protocol involves two primary roles.

## Owner

The party that wants to protect a secret.

Responsibilities:
* Split the secret into shares
* Distribute shares to helpers
* Verify helpers still possess the shares
* Recover the secret when necessary

## Helper

A trusted entity that stores a share for the sharer.

Responsibilities:
* Store the share
* Respond to verification challenges
* Provide shares during recovery

---

# Protocol Flows

The SDK provides building blocks for the main protocol flows.

Flow | Purpose
Pairing | Establish secure communication between sharer and helper
Share Distribution | Split and distribute secret shares
Verification | Ensure helpers still possess shares
Recovery | Retrieve shares and reconstruct the secret
Unpairing | Terminate the helper relationship

# Example: Pairing Flow

```rust
use derec_library::pairing::*;
use derec_library::types::ChannelId;

// Alternatively:
// let channel_id: ChannelId = 42.into();
let channel_id = ChannelId(42);
let transport_uri = "https://example-helper.com/derec";

let kind = derec_library::protos::derec_proto::SenderKind::Helper;

// This would normally come from QR decoding.
let CreateContactMessageResult {
    contact_message,
    secret_key: contactor_secret_key,
} = create_contact_message(
    channel_id,
    "https://relay.example/derec",
).expect("Failed to create contact message");

// Responder produces pairing request.
let ProducePairingRequestMessageResult {
    pair_request_message,
    secret_key: requestor_secret_key,
} = produce_pairing_request_message(
    channel_id,
    kind,
    &contact_message,
).expect("Failed to produce pairing request message");

// Initiator finalizes pairing.
let ProducePairingResponseMessageResult {
    pair_response_message,
    shared_key,
} = produce_pairing_response_message(
    kind,
    &pair_request_message,
    &contactor_secret_key,
).expect("Failed to produce pairing response message");

let ProcessPairingResponseMessageResult { shared_key } = process_pairing_response_message(
    &contact_message,
    &pair_response_message,
    &requestor_secret_key,
).expect("Failed to process pairing response message");
```

The ContactMessage is exchanged out-of-band, typically using:
* QR codes
* Existing communication channels

---

# Example: Sharing

```rust
use derec_library::sharing::*;
use derec_library::types::ChannelId;

let secret_id = b"my_secret";
let secret_data = b"super_secret_value";
let channels: Vec<ChannelId> = [1, 2, 3].into_iter().map(ChannelId::from).collect();
let threshold = 2;
let version = 1;

let ProtectSecretResult { shares } = protect_secret(
    secret_id,
    secret_data,
    &channels,
    threshold,
    version,
    None,
    None,
).expect("sharing failed");

assert_eq!(shares.len(), 3);
```

---

# Example: Verification

```rust
use derec_library::verification::*;
use derec_library::types::ChannelId;

let channel_id = ChannelId(42);
let secret_id = "secret_id";
let version = 7;
let request = generate_verification_request(secret_id, version)
    .expect("failed to build verification request");

let share_content = b"example_share";

let response = generate_verification_response(secret_id, channel_id, share_content, &request)
    .expect("failed to generate verification response");

let ok = verify_share_response(secret_id, channel_id, share_content, &response)
    .expect("failed to verify response");

assert!(ok);
```

---

# Example: Recovery

```rust
use derec_library::recovery::*;
use derec_library::protos::derec_proto::StoreShareRequestMessage;
use derec_library::types::ChannelId;

let channel_id = ChannelId(42);
let secret_id = b"secret_id";
let version = 1;
let request = generate_share_request(channel_id, secret_id, version).unwrap();

// In a real helper, this comes from secure storage.
let stored = StoreShareRequestMessage { share: vec![1, 2, 3], ..Default::default() };

let resp = generate_share_response(channel_id, secret_id, &request, &stored)
    .expect("failed to build response");

// Responses should contain at least t responses
let responses = vec![resp];

let _ = recover_from_share_responses(&responses, secret_id, version).unwrap_err();
```

---

# WebAssembly Support

The library also provides WebAssembly bindings so the protocol can run in:
* Browser-based
* Mobile wallets
* Web applications

Example JavaScript usage:

```ts
import * as derec from "derec-library";

const request = derec.generate_verification_request(secretId, version);
```

Bindings are generated using wasm-bindgen.

---

# Transport Layer

The DeRec protocol is transport agnostic.

Applications may use any communication channel including:

* HTTPS
* WebSockets
* Message queues
* Custom relay servers

> [!INFO]
> Currently, only the HTTPS transport protocol is supported.

The transportUri in protocol messages identifies the helper endpoint.

---

# Documentation

Full protocol documentation: https://derecalliance.gitbook.io/protocol

API documentation: https://docs.rs/derec-library

---

# Security Considerations

Applications using this SDK should ensure:
* Secure storage of secret material
* Proper authentication of helpers
* Safe transport channels
* Protection against replay attacks

The DeRec protocol design assumes helpers are independent and trusted entities.

---

License

Licensed under the Apache License, Version 2.0.

See the LICENSE file for details.

---

Contributing

Contributions are welcome.

Repository: https://github.com/derecalliance/lib-derec

Please open issues or pull requests to discuss improvements.

---

DeRec Alliance

The DeRec Alliance is an open initiative focused on creating standards for decentralized secret recovery.

More information:

https://derecalliance.org
