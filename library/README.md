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

The protocol involves three roles: **Owner**, **Helper**, and **Replica**.

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

### Replica

Another device belonging to the same Owner. A Replica keeps in sync with the
Owner so that the same secrets are accessible from multiple devices without
each application inventing its own synchronisation mechanism.

Responsibilities:
* Pair with the Owner using `SenderKind::Replica`
* Confirm the pairing via a fingerprint-based manual verification step
* Discover existing Helper channels and secrets from the Owner

---

## Protocol Flows

The SDK provides building blocks for the main protocol flows.

| Flow | Purpose |
|------|--------|
| Pairing | Establish secure communication between Owner and Helper (or Replica) |
| Share Distribution | Split and distribute secret shares |
| Verification | Ensure helpers still possess shares |
| Discovery | Ask helpers which secrets and versions they store |
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

### Discovery Flow

```rust
use derec_library::primitives::discovery::{request, response};
use derec_library::primitives::discovery::response::{SecretVersionEntry, VersionEntry};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
// shared_key: [u8; 32] established during pairing (in recovery mode)

// Owner side: produce the discovery request.
let request::ProduceResult { envelope: request_envelope } =
    request::produce(channel_id, &shared_key).unwrap();

// Helper side: extract the request, enumerate stored secrets, produce the response.
let _req = request::extract(&request_envelope, &shared_key).unwrap();

let stored: Vec<SecretVersionEntry> = vec![
    SecretVersionEntry {
        secret_id: b"wallet_seed".to_vec(),
        versions: vec![VersionEntry { version: 1, description: "Main wallet".to_owned() }],
    },
    SecretVersionEntry {
        secret_id: b"ssh_key".to_vec(),
        versions: vec![
            VersionEntry { version: 1, description: "Work SSH key".to_owned() },
            VersionEntry { version: 2, description: "Work SSH key v2".to_owned() },
        ],
    },
];
let response::ProduceResult { envelope: response_envelope } =
    response::produce(channel_id, &stored, &shared_key).unwrap();

// Owner side: extract and process the response to get the secret list.
let response::ExtractResult { response } =
    response::extract(&response_envelope, &shared_key).unwrap();
let response::ProcessResult { secret_list } =
    response::process(&response).unwrap();

// Owner now knows which (secret_id, version, description) tuples to request during recovery.
for entry in &secret_list {
    for v in &entry.versions {
        println!("secret_id={:?}  version={}  description={:?}", entry.secret_id, v.version, v.description);
    }
}
```

---

### Recovery Flow

Recovery is a three-step process: **pairing** (re-establish a channel with each Helper in recovery
mode), **discovery** (ask each Helper which secrets it holds), and **share collection**
(reconstruct the secret).

The application drives each step explicitly. Discovery is only triggered after any required
out-of-band authentication has been completed.

#### Step 1 — Pair with Helpers in recovery mode

```rust
use derec_library::protocol::{DeRecEvent, DeRecProtocol};
use derec_proto::{ContactMessage, SenderKind};

// helper_contacts: Vec<ContactMessage> obtained out-of-band (QR code, deep link, etc.)
// The application pairs with each Helper individually — recovery can take days.

for contact in helper_contacts {
    owner.start_pairing(SenderKind::OwnerRecovery, contact).await.unwrap();
}

// Process incoming messages. PairingComplete { kind: SenderKind::OwnerRecovery, .. }
// signals that recovery pairing with a Helper is done.
// loop { let events = owner.process(&incoming_bytes).await?; ... }
```

#### Step 2 — Request discovery after authentication

```rust
// Once the Helper has authenticated the Owner (out-of-band), request discovery.
// The Helper reports all (secret_id, version, description) pairs it holds.
owner.request_discovery(channel_id).await.unwrap();

// Process incoming messages until SecretsDiscovered is received.
// loop { let events = owner.process(&incoming_bytes).await?; ... }
//
// DeRecEvent::SecretsDiscovered { channel_id, secrets } carries
// Vec<SecretVersionEntry> — each entry has a secret_id and a list of
// VersionEntry { version, description } so the Owner can identify secrets
// by their human-readable labels.
```

#### Step 3 — Reconstruct the secret

```rust
// After collecting discovery results from enough Helpers, request the shares.
owner
    .recover_secret(secret_id, version, &helper_channel_ids)
    .await
    .unwrap();

// The library accumulates responses; SecretRecovered is emitted once a
// threshold of shares have been collected.
// loop { let events = owner.process(&incoming_bytes).await?; ... }
```

#### Primitive-level reference (Helper side)

```rust
use derec_library::primitives::recovery::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
// shared_key: [u8; 32] established during pairing

// Helper side: extract the share request and produce a response.
let request::ExtractResult { request } =
    request::extract(&request_envelope, &shared_key).unwrap();
let response::ProduceResult { envelope: response_envelope } =
    response::produce(channel_id, secret_id, &request, &stored_share_request, &shared_key).unwrap();

// Owner side: aggregate responses from a threshold of helpers and reconstruct.
let response::RecoverResult { secret_data } = response::recover(
    secret_id,
    version,
    &[response::RecoveryResponseInput {
        share_response: &share_response,
    }],
).unwrap();
```

---

### Unpairing

Either party may end the relationship for a channel by initiating an
**unpair flow**. The recipient deletes its state (shared key, channel
record, stored shares) and acknowledges with an `UnpairResponseMessage`.

The orchestrator exposes two acknowledgement policies via the builder:

- `UnpairAck::Required` (default) — the initiator keeps local state until
  the peer acknowledges with `Ok` (or the configured protocol timeout
  elapses, at which point the state is dropped anyway and the `Unpaired`
  event surfaces).
- `UnpairAck::NotRequired` — fire-and-forget. State is dropped immediately
  on `start(Unpair)` and any later response is ignored.

Both policies emit a `DeRecEvent::Unpaired { channel_id }` event on the
local side once the local state is gone. A peer that refuses to comply
returns a non-`Ok` status; the initiator surfaces this as
`DeRecEvent::UnpairRejected { channel_id, status, memo }` and leaves the
local state intact.

```rust
use derec_library::primitives::unpairing::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
// shared_key: [u8; 32] established during pairing

// Initiator side: produce and send the unpair request.
let request = request::produce(channel_id, "decommissioning", &shared_key).unwrap();
let wire_bytes = request.envelope;

// Responder side: extract the request, drop local state, send Ok response.
let extracted = request::extract(&wire_bytes, &shared_key).unwrap();
let response = response::produce(channel_id, &shared_key).unwrap();

// Initiator side: validate the response.
let ok = response::process(
    &response::extract(&response.envelope, &shared_key).unwrap().response,
).unwrap();
assert!(ok.acknowledged);
```

When driven through the high-level [`DeRecProtocol`] orchestrator the same
flow is one call:

```rust,ignore
use derec_library::protocol::{DeRecFlow, UnpairAck};
use derec_library::types::Target;

let protocol = DeRecProtocolBuilder::new()
    .with_unpair_ack(UnpairAck::Required)
    // … other setters …
    .build();

protocol.start(DeRecFlow::Unpair {
    target: Target::Single(channel_id),
    memo: Some("decommissioning".to_owned()),
}).await?;
```

When the peer's `UnpairRequest` arrives on the responder side, the
orchestrator emits an `ActionRequired { action_kind: "Unpair", .. }`
event. The application calls `accept(action)` to drop local state and
send back an `Ok` acknowledgement, or `reject(action, status, memo)` to
keep local state and reply with a non-`Ok` status.

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
