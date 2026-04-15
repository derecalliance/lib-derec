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
use derec_library::primitives::verification::request;
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let secret_id = b"example_secret";
let version = 1;
// shared_key: [u8; 32] established during pairing

let result = request::produce(channel_id, secret_id, version, &shared_key).unwrap();
// result.envelope is already serialized wire bytes, ready to send over transport
let wire_bytes = result.envelope;
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
import { primitives } from "@derec-alliance/nodejs"; // or @derec-alliance/web

const result = primitives.verification.request.produce(channelId, secretId, version, sharedKey);
// result carries the encoded DeRecMessage envelope, ready to send over transport
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
use derec_library::primitives::pairing::{request, response};
use derec_library::types::ChannelId;
use derec_proto::{Protocol, SenderKind, TransportProtocol};

let channel_id = ChannelId(42);

// Step 1 — Initiator creates the contact message (sent out-of-band).
let request::CreateContactResult {
    contact_message,
    secret_key: initiator_secret_key,
} = request::create_contact(
    channel_id,
    TransportProtocol {
        uri: "https://relay.example/derec".to_owned(),
        protocol: Protocol::Https.into(),
    },
).unwrap();
// Serialize for out-of-band transfer (QR code, deep link, etc.)
// let contact_bytes = contact_message.encode_to_vec();

// Step 2 — Responder decodes the contact and produces the request envelope.
let contact = contact_message;
let request::ProduceResult {
    envelope: pair_request_envelope,
    initiator_contact_message,
    secret_key: responder_secret_key,
} = request::produce(
    SenderKind::Helper,
    TransportProtocol {
        uri: "https://example-helper.com/derec".to_owned(),
        protocol: Protocol::Https.into(),
    },
    &contact,
).unwrap();

// Step 3 — Initiator extracts the request and produces the response envelope.
let request::ExtractResult { request } =
    request::extract(&pair_request_envelope, initiator_secret_key.ecies_secret_key()).unwrap();
let response::ProduceResult {
    envelope: pair_response_envelope,
    shared_key: initiator_shared_key,
    ..
} = response::produce(
    SenderKind::OwnerNonRecovery,
    &request,
    &initiator_secret_key,
).unwrap();

// Step 4 — Responder extracts the response and finalizes pairing.
let response::ExtractResult { response } =
    response::extract(&pair_response_envelope, responder_secret_key.ecies_secret_key()).unwrap();
let response::ProcessResult { shared_key: responder_shared_key } =
    response::process(
        &initiator_contact_message,
        &response,
        &responder_secret_key,
    ).unwrap();

// Both sides now hold the same shared key.
assert_eq!(initiator_shared_key, responder_shared_key);
```

The `ContactMessage` is exchanged out-of-band, typically using:

* QR codes
* Existing communication channels

---

### Sharing Flow

```rust
use derec_library::primitives::sharing::request;
use derec_library::types::ChannelId;

let secret_id = b"my_secret";
let secret_data = b"super_secret_value";
let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
let threshold = 2;
let version = 1;

let request::SplitResult { shares } = request::split(
    &channels,
    secret_id,
    version,
    secret_data,
    threshold,
).unwrap();
// shares: HashMap<ChannelId, CommittedDeRecShare>
// Pass each share to request::produce() to create encrypted delivery envelopes.
```

---

### Verification Flow

```rust
use derec_library::primitives::verification::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let secret_id = b"secret_id";
let version = 7;
// shared_key: [u8; 32] established during pairing

// Owner side: produce and send the verification request.
let result = request::produce(channel_id, secret_id, version, &shared_key).unwrap();
let request_wire_bytes = result.envelope;

// Helper side: decrypt and extract the challenge fields.
let request::ExtractResult { request } =
    request::extract(&request_wire_bytes, &shared_key).unwrap();

// Helper side: produce the response.
let resp_result = response::produce(channel_id, &request, &shared_key, b"example_share").unwrap();
let response_wire_bytes = resp_result.envelope;

// Owner side: decrypt and verify the proof.
let response::ExtractResult { response } =
    response::extract(&response_wire_bytes, &shared_key).unwrap();
let ok = response::process(&response, b"example_share").unwrap();

assert!(ok);
```

---

### Recovery Flow

```rust
use derec_library::primitives::recovery::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let secret_id = b"secret_id";
let version = 1;
// shared_key: [u8; 32] established during pairing

// Owner side: produce the recovery request.
let request::ProduceResult { envelope: request_envelope } =
    request::produce(channel_id, secret_id, version, &shared_key).unwrap();

// Helper side: extract the request, then produce the response.
let request::ExtractResult { request } =
    request::extract(&request_envelope, &shared_key).unwrap();
let response::ProduceResult { envelope: response_envelope } =
    response::produce(channel_id, secret_id, &request, &stored_share_request, &shared_key).unwrap();

// Owner side: aggregate responses from a threshold of helpers and reconstruct the secret.
let response::RecoverResult { secret_data } = response::recover(
    secret_id,
    version,
    &[response::RecoveryResponseInput {
        share_response: &share_response,
        shared_key: &shared_key,
    }],
).unwrap();
```

---

## Observability

The library emits structured [tracing](https://docs.rs/tracing) spans and events for every protocol step. Instrumentation is **off by default** and opt-in via the `logging` feature flag — enabling it adds no overhead when no subscriber is active.

### Enabling the feature

```toml
[dependencies]
derec-library = { version = "0.0.1-alpha.6", features = ["logging"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

### Wiring up a subscriber

Initialize a subscriber once, early in your application (e.g. in `main`):

```rust
tracing_subscriber::fmt()
    .with_env_filter(
        tracing_subscriber::EnvFilter::from_env("DEREC_LOG")
    )
    .init();
```

### Controlling the log level at runtime

Set `DEREC_LOG` before running your application:

```bash
# Protocol milestones only (contact created, pairing complete, share stored, …)
DEREC_LOG=info ./my-app

# Intermediate state — sizes, versions, channel IDs
DEREC_LOG=debug ./my-app

# Full detail including byte lengths from the cryptography layer
DEREC_LOG=trace ./my-app

# Only DeRec events, silence everything else
DEREC_LOG=derec_library=debug,derec_cryptography=debug ./my-app

# Mix: DeRec at trace, all other crates at warn
DEREC_LOG=warn,derec_library=trace,derec_cryptography=trace ./my-app
```

### What is logged

| Level | Content |
|-------|---------|
| `info` | Protocol milestones — contact created, pairing complete, share split, share stored, verification result, secret reconstructed |
| `debug` | Intermediate state — channel IDs, versions, thresholds, response counts |
| `trace` | Low-level byte lengths from the cryptography layer |

**Security guarantee**: secret bytes, symmetric keys, and share content are never emitted. Only non-sensitive metadata (lengths, identifiers, roles) appears in events.

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
