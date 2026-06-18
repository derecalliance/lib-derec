# DeRec Rust SDK

![Crates.io](https://img.shields.io/crates/v/derec-library)
![Docs.rs](https://docs.rs/derec-library/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Rust implementation of the **DeRec protocol** — split a secret into shares,
distribute them across independent helpers, verify possession over time, and
reconstruct the secret from a threshold of shares when needed. The library is
transport- and storage-agnostic, supports both native Rust and WebAssembly
targets, and is the reference implementation maintained by the **DeRec
Alliance**.

> [!WARNING]
> This is a pre-release version. APIs may change until 0.1.0.

---

## Contents

- [What is DeRec?](#what-is-derec)
- [Installation](#installation)
- [Two API layers](#two-api-layers)
- [Quick start (Protocol layer)](#quick-start-protocol-layer)
- [Builder configuration](#builder-configuration)
- [Event-driven model](#event-driven-model)
- [Protocol flows](#protocol-flows)
- [Replica flows](#replica-flows)
- [Storage and transport traits](#storage-and-transport-traits)
- [Errors](#errors)
- [Async and executors](#async-and-executors)
- [WebAssembly support](#webassembly-support)
- [Transport layer](#transport-layer)
- [Observability](#observability)
- [Primitives (advanced)](#primitives-advanced)
- [Protocol specification](#protocol-specification)
- [Security considerations](#security-considerations)
- [License](#license)
- [Contributing](#contributing)
- [DeRec Alliance](#derec-alliance)

---

## What is DeRec?

DeRec is a **threshold secret-sharing** protocol for decentralized recovery.
The Owner splits a secret using Verifiable Secret Sharing, distributes the
shares across trusted Helpers, and can later reconstruct the secret from any
threshold-sized subset of shares.

Three roles participate:

- **Owner** — the party that wants to protect a secret. Splits the secret,
  distributes shares, verifies that helpers still hold them, and drives
  recovery when needed.
- **Helper** — a trusted entity that stores one share. Responds to
  verification challenges, returns the share during recovery, and acknowledges
  unpair requests.
- **Replica** — a second device belonging to the same Owner that mirrors
  the Source's secret. Replica pairings are **unidirectional**, just like
  Owner↔Helper: one side scans as `SenderKind::ReplicaSource` (writes the
  secret), the other as `SenderKind::ReplicaDestination` (receives it).
  Pairing is confirmed out of band with a human-readable fingerprint
  (`DeRecProtocol::get_fingerprint` / `verify_fingerprint`), then
  `ProtectSecret` distributes the full secret (helpers + secrets +
  replicas + `owner_replica_id`) to every Destination via a
  [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html).
  Destinations surface the typed
  [`DeRecEvent::ReplicaSecretReceived`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html#variant.ReplicaSecretReceived).
  Configure via `DeRecProtocolBuilder::with_replica_id`.

The protocol is transport-agnostic and produces wire-compatible protobuf
messages; the library never assumes a specific delivery channel.

Typical applications: cryptocurrency wallets, digital identity, secure backup,
key management.

---

## Installation

```bash
cargo add derec-library
```

The badge above shows the latest published version.

---

## Two API layers

The library exposes two surfaces:

- **Protocol layer (`derec_library::protocol`)** — **start here.** A stateful
  orchestrator ([`DeRecProtocol`](https://docs.rs/derec-library/latest/derec_library/protocol/struct.DeRecProtocol.html))
  that owns your storage/transport implementations, manages session state, and
  drives every flow through a single `start` / `process` / `accept` / `reject`
  surface. Returns [`DeRecEvent`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html)
  values the application reacts to.

- **Primitives layer (`derec_library::primitives`)** — the lower-level surface:
  one module per flow exposing `produce` / `extract` / `process` functions that
  build and decode individual protocol messages. Use this **only when** the
  protocol layer cannot fit (e.g. you are implementing your own orchestrator,
  integrating into a system whose event loop you don't control, or need to
  manipulate messages directly).

Most consumers should only use the protocol layer. The primitives section at
the bottom of this README is provided for the cases that need it.

---

## Quick start (Protocol layer)

Three steps: implement the storage and transport traits for your environment,
build a `DeRecProtocol`, drive it with `start` / `process`.

```rust,ignore
use derec_library::protocol::{
    DeRecEvent, DeRecFlow, DeRecProtocolBuilder, PendingAction,
};
use derec_proto::{Protocol, TransportProtocol};

// 1. Implement the four storage/transport traits for your environment.
//    See the trait docs:
//    - DeRecChannelStore  — paired channels
//    - DeRecShareStore    — secret shares
//    - DeRecSecretStore   — per-channel key material (sensitive)
//    - DeRecTransport     — outbound message delivery
let my_channel_store = /* ... */;
let my_share_store   = /* ... */;
let my_secret_store  = /* ... */;
let my_transport     = /* ... */;

// 2. Build a protocol instance.
let mut protocol = DeRecProtocolBuilder::new()
    .with_channel_store(my_channel_store)
    .with_share_store(my_share_store)
    .with_secret_store(my_secret_store)
    .with_transport(my_transport)
    .with_own_transport(TransportProtocol {
        uri: "https://my-node.example/derec".to_owned(),
        protocol: Protocol::Https.into(),
    })
    // Optional setters — see "Builder configuration" below.
    .build()?;

// 3. Drive flows.
//
//    `start` initiates an outbound flow (pairing, sharing, recovery, …).
//    `process` feeds incoming wire bytes and returns events.
//    `accept` / `reject` resolve `ActionRequired` events the app must confirm.

// Initiate a pairing flow from a contact message received out-of-band:
let _channel_id = protocol
    .start(DeRecFlow::Pairing {
        kind: derec_proto::SenderKind::Helper,
        contact: contact_message,
        peer_communication_info: Default::default(),
    })
    .await?;

// Inbound message processing loop:
loop {
    let wire_bytes = my_transport_recv().await?;
    for event in protocol.process(&wire_bytes).await? {
        match event {
            DeRecEvent::ActionRequired { action, .. } => {
                // The peer asked us to do something (pair, store a share, ...).
                // Confirm with accept, refuse with reject(action, status, memo).
                protocol.accept(action).await?;
            }
            DeRecEvent::SecretRecovered { secret } => {
                // Recovery completed — use the reconstructed bytes here.
            }
            // ... handle other events the application cares about.
            _ => {}
        }
    }
}
```

A complete working example lives at `bindings/rust/src/protocol.rs` in the
repository.

---

## Builder configuration

`DeRecProtocolBuilder` enforces required-slot completion at compile time
(missing a required setter is a type error, not a runtime panic). Runtime
invariants — currently `threshold >= 2` — are checked inside
[`build()`](https://docs.rs/derec-library/latest/derec_library/protocol/struct.DeRecProtocolBuilder.html#method.build),
which returns `Result<DeRecProtocol, crate::Error>` so invalid
configurations surface as `Error::InvalidInput` instead of panicking.
Optional setters have defaults:

| Setter | Default | Purpose |
|--------|---------|---------|
| `with_threshold(n)` | `3` | Minimum shares required to reconstruct the secret. |
| `with_keep_versions_count(n)` | `3` | Number of recent versions each helper must retain. |
| `with_timeout(duration)` | `5 minutes` | Staleness boundary for inbound envelopes and pending state. One-second granularity. |
| `with_communication_info(map)` | empty | Key-value identity metadata embedded in pairing messages. |
| `with_auto_respond_on_failure(bool)` | `false` | If `true`, the protocol replies to the peer on inbound processing failures; if `false`, errors only surface as events. |
| `with_unpair_ack(ack)` | `UnpairAck::Required` | Whether the unpair initiator waits for the peer's `Ok` before dropping local state. |
| `with_auto_reply_to(bool)` | `false` | If `true`, every outbound request stamps `replyTo = own_transport` so the responder routes the reply back to this node — even if the channel's stored peer endpoint points elsewhere. Useful for replica scenarios. See [Correlation and routing on the wire](#correlation-and-routing-on-the-wire). |

See the [builder rustdoc](https://docs.rs/derec-library/latest/derec_library/protocol/struct.DeRecProtocolBuilder.html)
for the full per-setter contract.

---

## Event-driven model

`process` returns `Vec<DeRecEvent>`. The application reacts to events; the
protocol owns the state. The main variants are:

- `ActionRequired { channel_id, action }` — an incoming request needs
  application confirmation. The app calls `protocol.accept(action)` or
  `protocol.reject(action, status, memo)` to complete the flow.
- `PairingCompleted { channel_id, kind, peer_communication_info }`
- `ShareStored { channel_id, version }` / `ShareConfirmed { … }` /
  `ShareRejected { … }`
- `ShareVerified { channel_id, version }`
- `SecretsDiscovered { channel_id, secrets }`
- `RecoveryShareReceived { … }` / `SecretRecovered { secret }` /
  `RecoveryShareError { … }`
- `Unpaired { channel_id }` / `UnpairRejected { channel_id, status, memo }`
- `PrePairRejected { channel_id, status, memo }` — the contact creator
  answered our `PrePairRequest` with a non-`Ok` status (scanner side,
  `HashedKeys` flow). Distinct from a cryptographic binding-hash mismatch,
  which surfaces as `Error::Pairing(PairingError::PrePairHashMismatch)`
  from `process()` rather than as an event. See [Pairing modes](#pairing-modes).
- `NoOp` — emitted when an inbound message was processed but had no
  application-visible consequence.

See [`DeRecEvent`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html)
for the complete enum and per-variant docs.

### Channel roles

Each paired channel carries the local node's role — `SenderKind::Owner`,
`SenderKind::Helper`, `SenderKind::ReplicaSource`, or
`SenderKind::ReplicaDestination` — fixed at pairing time and stored on
[`Channel.role`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.Channel.html).
The orchestrator enforces flow directionality against this value:

- Outbound: `ProtectSecret`, `VerifyShares`, `Discovery`, `RecoverSecret`,
  and `Unpair` require the local role to be `Owner` (or `ReplicaSource`
  for `ProtectSecret`) on every targeted channel.
- Inbound: a `StoreShareRequest` / `VerifyShareRequest` /
  `GetSecretIdsVersionsRequest` / `GetShareRequest` / `UnpairRequest` is
  only honored on a channel where the local role is `Helper`; the
  corresponding responses require `Owner`. A `StoreShareRequest` on a
  `ReplicaDestination` channel is decoded as a
  [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html)
  and surfaces as
  [`DeRecEvent::ReplicaSecretReceived`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html#variant.ReplicaSecretReceived).
- `UpdateChannelInfo` is symmetric — either side may initiate it, and the
  role is not consulted.

A mismatch surfaces as `Error::RoleMismatch { channel_id, expected, actual }`.

---

## Protocol flows

| Flow | Purpose |
|------|---------|
| Pairing | Establish a secure channel between any two SenderKinds (Owner↔Helper or ReplicaSource↔ReplicaDestination). Two contact modes — see [Pairing modes](#pairing-modes). |
| Share Distribution | Split a secret and distribute the shares to helpers; replica destinations receive the full secret as a [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html). |
| Verification | Challenge helpers to prove they still hold their shares. |
| Discovery | Ask helpers which secrets and versions they store. |
| Recovery | Re-pair, collect shares, reconstruct the secret. |
| Unpairing | Tear down a paired channel and drop local state. |
| Update channel info | Propagate post-pairing changes to communication info and/or transport endpoint. |

### Pairing modes

`DeRecProtocol::create_contact` takes a `ContactMode` argument; the choice
travels in the `ContactMessage` and tells the scanner which handshake to run.

| `ContactMode` | Contact carries | When to use |
|---|---|---|
| `InlineKeys` | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry ~1.2 KB (NFC, deep link, direct messaging). |
| `HashedKeys` | Only a 48-byte SHA-384 commitment to the keys | Out-of-band channel is size-constrained (QR codes). The scanner fetches the real keys over the wire via a plaintext `PrePair` round-trip and verifies them against the commitment. |

The library's primitives section below documents the [`InlineKeys`](#inlinekeys-flow)
and [`HashedKeys`](#hashedkeys-flow-prepair) message-level handshakes. At
the orchestrator layer, the choice is invisible to most application code
after `create_contact` — the difference surfaces only in the events the
two sides observe during the `HashedKeys` handshake:

- **Contact creator** (the side that called `create_contact`):
  receives an `ActionRequired { action_kind: "PrePair" }` event when the
  scanner's `PrePairRequest` arrives. Call `protocol.accept(action)` to
  publish the keys (the orchestrator builds the response and routes it
  back to the scanner's transport endpoint), or `protocol.reject(action,
  status, memo)` to refuse. After accepting, the next inbound message is
  a regular `PairRequest` — its `ActionRequired` event is identical to
  the `InlineKeys` path.
- **Scanner** (the side that called `start(Pairing { contact, .. })`):
  `PrePair` is silent on success. The library validates the published
  keys against `contact.contact_binding_hash`, synthesizes an
  `InlineKeys`-shaped contact, and auto-sends the regular `PairRequest`.
  The application sees `PairingCompleted` only after the
  `PairResponse` round-trip lands. Failure modes:
    - Contact creator rejected → `DeRecEvent::PrePairRejected
      { channel_id, status, memo }`.
    - Cryptographic binding-hash mismatch → `process()` returns
      `Err(Error::Pairing(PairingError::PrePairHashMismatch))`. This
      is a security-relevant signal — the keys published by the peer do
      not match the commitment the scanner originally accepted, so the
      contact may have been swapped or tampered between creation and
      scan.

Security caveat — the `PrePair` envelopes cross the wire **plaintext**.
The `TransportProtocol` passed to `create_contact` (HashedKeys) MUST be
an ephemeral endpoint that an observer cannot link to a long-lived
identity. After pairing completes, propagate a long-term endpoint via
`DeRecFlow::UpdateChannelInfo`; retire the ephemeral one.

End-to-end smoke tests covering both happy path and tampered-hash:
- Rust orchestrator level — `bindings/rust/src/protocol.rs::run_hashed_keys_pairing_flow`.
- nodejs / web orchestrator level — `bindings/nodejs/protocol.ts::runHashedKeysPairingFlow`
  and `bindings/web/src/protocol.ts::runHashedKeysPairingFlow`.
- Primitives level — `bindings/{rust,dotnet,nodejs,web}/{primitives.*,Program.cs}` cover
  the same flow without an orchestrator (the .NET binding is primitives-only).

---

## Replica flows

Replicas mirror the Owner's secret onto a second device so the same
secrets remain accessible after device loss without going through full
helper-based recovery. The model is **unidirectional**, exactly like
Owner↔Helper:

| SenderKind            | Role on the pair                                                |
|-----------------------|-----------------------------------------------------------------|
| `ReplicaSource`       | Owns the secret. Drives `ProtectSecret` and pushes updates.     |
| `ReplicaDestination`  | Receives the secret. Stores `Secret` + share map.               |

### Configuring replica identity

Replica pairings carry a stable per-device `u64` id under the reserved
`derec.replica_id` key in `CommunicationInfo`. Pass it once at builder
time and the orchestrator handles injection / validation automatically:

```rust
let mut protocol = DeRecProtocolBuilder::new()
    .with_replica_id(0xAAAA_AAAA_AAAA_AAAA)
    // ... other slots ...
    .build()?;
```

Attempting any replica-mode flow on a protocol built without
`with_replica_id` returns
[`Error::ReplicaIdNotConfigured`](https://docs.rs/derec-library/latest/derec_library/enum.Error.html#variant.ReplicaIdNotConfigured).

The reserved `derec.*` `CommunicationInfo` namespace — including
`derec.replica_id` and its wire encoding — is documented in
[`protocol::reserved_keys`](https://docs.rs/derec-library/latest/derec_library/protocol/reserved_keys/index.html).
Apps should not write to this namespace; the orchestrator strips and
re-injects entries at the protocol boundary.

### Fingerprint confirmation

Replica channels start in `ChannelStatus::Pending` after the handshake
and are not eligible as `ProtectSecret` targets until both sides confirm
the pair out of band. The protocol derives a deterministic
human-readable fingerprint from the shared key — same on both
devices — that users compare visually before each side calls
`verify_fingerprint`:

```rust
let local = source.get_fingerprint(channel_id).await?;
let peer  = destination.get_fingerprint(channel_id).await?; // out of band

source.verify_fingerprint(channel_id, &peer).await?;        // → true
destination.verify_fingerprint(channel_id, &local).await?;  // → true
```

`verify_fingerprint` returns `true` on match and transitions the channel
to `Paired`. A mismatch returns `false` and leaves the channel `Pending`
so the app can retry.

### Secret distribution

Once the destination is paired (status `Paired`), the source includes it
as a `ProtectSecret` target alongside helpers. The orchestrator routes
two payload shapes from the same `start` call:

- Helpers receive the usual VSS share via `StoreShareRequest`.
- Destinations receive a typed
  [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html)
  `{ secret: Secret, shares: Vec<ChannelShare> }` — the full
  secret plus every helper's share keyed by `channel_id`. This is what
  lets a destination act in the source's place during recovery without
  re-running the share collection.

On the destination, the inbound envelope decodes into
[`DeRecEvent::ReplicaSecretReceived`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html#variant.ReplicaSecretReceived)
with `secret: Secret` and `shares: Vec<ChannelShare>` already
parsed — the app just installs the secrets.

---

## Correlation and routing on the wire

Two metadata fields cut across every channel-mode exchange:

### `traceId` — request/response correlation

`DeRecMessage.traceId` is an opaque `uint64` correlation token on the
**plaintext outer envelope**. The requester sets it; the responder echoes it
verbatim. The orchestrator (`DeRecProtocol`) handles both sides
automatically — every outbound request gets a fresh random token via
[`fresh_trace_id`](https://docs.rs/derec-library/latest/derec_library/protocol/handlers/fn.fresh_trace_id.html);
every response is stamped with the inbound trace id via
[`apply_trace_id`](https://docs.rs/derec-library/latest/derec_library/derec_message/fn.apply_trace_id.html).

Consumers driving the protocol through **primitives** (not the
orchestrator) get `trace_id = 0` (the protobuf default) by default and can
opt in manually using the envelope helpers:

```rust
use derec_library::derec_message::{apply_trace_id, read_trace_id};

let outbound = apply_trace_id(&envelope_bytes, my_token)?;
// …send outbound…

let inbound_token = read_trace_id(&response_bytes)?;
// match `inbound_token` against `my_token` to correlate
```

The same helpers are surfaced as `envelope.apply_trace_id` /
`envelope.read_trace_id` on the nodejs/web packages and as
`apply_trace_id_to_envelope` / `read_trace_id_from_envelope` on the FFI
(plus a `Envelope.ApplyTraceId` / `Envelope.ReadTraceId` static class on
the dotnet package). The encrypted inner message is never touched, so
re-stamping has no crypto cost.

### `replyTo` — ephemeral response routing

`replyTo` is an optional `TransportProtocol` on **request bodies**
(`StoreShareRequest`, `VerifyShareRequest`, `GetSecretIdsVersionsRequest`,
`GetShareRequest`, `UnpairRequest`). It tells the responder to route this
exchange's response to an alternate endpoint — without persisting it (use
`UpdateChannelInfo` for a permanent change).

The motivating case is replicas: when Replica A sends a request on a
channel the helper paired with sibling Replica B, the helper's stored peer
endpoint points at B. `replyTo` lets A say "send the response back to me,"
without rewriting channel state.

Two ways to set it:

- **Per call (primitives):** every `*::request::produce` takes a trailing
  `reply_to: Option<TransportProtocol>` parameter.
- **Protocol-wide:** `DeRecProtocolBuilder::with_auto_reply_to(true)` makes
  the orchestrator stamp `replyTo = own_transport` on every outbound
  request automatically.

The responder honours an inbound `replyTo` regardless of how it was set —
the flag only governs **outbound** population. `PairRequest`,
`PrePairRequest`, and `UpdateChannelInfoRequest` are intentionally
excluded: each already carries its own `transportProtocol` field serving
the same role.

---

## Storage and transport traits

The library does **not** ship a default backend for storage or transport.
Consumers implement four traits — the protocol holds them by `&mut self`, so
implementations need no internal synchronization:

| Trait | Stores |
|-------|--------|
| [`DeRecChannelStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecChannelStore.html) | Paired channel records and the channel-link graph. |
| [`DeRecShareStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecShareStore.html) | Encoded share entries keyed by `(channel_id, secret_id, version)`. |
| [`DeRecSecretStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecSecretStore.html) | Per-channel cryptographic material (shared keys, pairing secrets, pairing contacts). |
| [`DeRecTransport`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecTransport.html) | Outbound envelope delivery to peers. |

Each trait's rustdoc states its contract, idempotency expectations, and the
security classification of the data it holds (`DeRecSecretStore` content is
keychain-grade; the others need durable storage only).

---

## Errors

Public errors are structured and typed:

- [`Error`](https://docs.rs/derec-library/latest/derec_library/enum.Error.html) — the library-level error type returned by most calls.
- [`ProcessError`](https://docs.rs/derec-library/latest/derec_library/protocol/error/struct.ProcessError.html) — wraps `Error` with the `channel_id` an inbound message was processed against (if known).
- [`ChannelStoreError`](https://docs.rs/derec-library/latest/derec_library/protocol/error/enum.ChannelStoreError.html), [`ShareStoreError`](https://docs.rs/derec-library/latest/derec_library/protocol/error/enum.ShareStoreError.html), [`SecretStoreError`](https://docs.rs/derec-library/latest/derec_library/protocol/error/enum.SecretStoreError.html) — surfaced by storage trait implementations.

The protocol never panics on malformed input. Inbound parsing or decryption
failures surface as events (or as a typed `Error::ProtobufDecode` /
`Error::DecryptionFailed` etc.); see `with_auto_respond_on_failure` for
controlling whether such failures are replied to.

---

## Async and executors

Storage and transport methods return type-erased futures
([`SecretStoreFuture`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/type.SecretStoreFuture.html)
and friends). No specific executor is prescribed:

- **Native targets** — futures are `Send`, so they can be spawned on
  multi-threaded executors such as `tokio::spawn`.
- **`ffi` feature or `wasm32` target** — the `Send` bound is dropped because
  the host runs single-threaded or callbacks cross an FFI boundary.

Sync backends can implement the trait methods with
`Box::pin(std::future::ready(...))` at zero cost; async backends use
`Box::pin(async move { ... })`.

---

## WebAssembly support

The same protocol layer is exposed to JavaScript/TypeScript via
[`wasm-bindgen`](https://crates.io/crates/wasm-bindgen). Packages:

- [`@derec-alliance/nodejs`](https://www.npmjs.com/package/@derec-alliance/nodejs)
- [`@derec-alliance/web`](https://www.npmjs.com/package/@derec-alliance/web)

```ts
import { primitives } from "@derec-alliance/nodejs"; // or @derec-alliance/web

const result = primitives.verification.request.produce(
  channelId, secretId, version, sharedKey,
);
// result carries the encoded DeRecMessage envelope, ready to send over transport
```

The TypeScript bindings expose both the protocol layer (via the
`DeRecProtocol` class) and the primitives surface. See the package READMEs
for full TypeScript examples.

---

## Transport layer

The protocol is transport-agnostic. The `TransportProtocol` value carried in
contact and pairing messages identifies the peer endpoint; the application's
[`DeRecTransport`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecTransport.html)
implementation decides how to deliver bytes (HTTPS, WebSocket, message queue,
custom relay, …).

> [!NOTE]
> The on-the-wire `TransportProtocol.protocol` enum currently defines
> `Https` as the only supported value. New transports can be added by
> extending the protobuf enum.

### Updating channel info post-pairing

A peer's `communication_info` and transport endpoint are exchanged at pairing
time. To propagate later changes, mutate local state with
`DeRecProtocol::set_communication_info` / `set_own_transport` and then run
`start(DeRecFlow::UpdateChannelInfo { ... })` against the target channels.
Per-field semantics:

- `communication_info: Option<HashMap<String, String>>` — `None` leaves the
  peer's stored map untouched. `Some(_)` replaces it; an empty map clears it.
- `transport_protocol: Option<TransportProtocol>` — `None` leaves it
  untouched. `Some(_)` updates both URI and protocol.

The flow is symmetric — either Owner or Helper may initiate it — and
auto-applies on the receiver via the standard `ActionRequired` → `accept`
path. Outcome surfaces as `DeRecEvent::ChannelInfoUpdated` (or
`ChannelInfoUpdateRejected` if the peer refused).

> [!WARNING]
> **Endpoint changeover discipline.** When `transport_protocol` is updated,
> the receiving peer sends its response to the **new** endpoint. The
> application MUST bring up the new endpoint and start listening on it
> **before** initiating the flow, and MUST keep the old endpoint
> operational until every targeted peer has emitted
> `ChannelInfoUpdated` / `ChannelInfoUpdateRejected` (plus a grace window
> for in-flight messages from peers not yet aware of the update). Failing
> to keep both endpoints reachable during this window will cause messages
> to be lost. See the rustdoc on `set_own_transport` for details.

---

## Observability

The library emits structured [`tracing`](https://docs.rs/tracing) spans and
events for every protocol step. Instrumentation is **off by default** and
opt-in via the `logging` feature flag — enabling it adds no overhead when no
subscriber is active.

### Enabling

```toml
[dependencies]
derec-library = { version = "*", features = ["logging"] }
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

### Wiring up a subscriber

```rust,ignore
tracing_subscriber::fmt()
    .with_env_filter(
        tracing_subscriber::EnvFilter::from_env("DEREC_LOG")
    )
    .init();
```

### Controlling the log level at runtime

```bash
# Protocol milestones only (contact created, pairing complete, share stored, …)
DEREC_LOG=info ./my-app

# Intermediate state — sizes, versions, channel IDs
DEREC_LOG=debug ./my-app

# Full detail including byte lengths from the cryptography layer
DEREC_LOG=trace ./my-app

# Only DeRec events, silence everything else
DEREC_LOG=derec_library=debug,derec_cryptography=debug ./my-app
```

### What is logged

| Level | Content |
|-------|---------|
| `info` | Protocol milestones — contact created, pairing complete, share split, share stored, verification result, secret reconstructed. |
| `debug` | Intermediate state — channel IDs, versions, thresholds, response counts. |
| `trace` | Low-level byte lengths from the cryptography layer. |

**Security guarantee**: secret bytes, symmetric keys, and share content are
never emitted. Only non-sensitive metadata (lengths, identifiers, roles)
appears in events.

---

## Primitives (advanced)

> Use the [protocol layer](#quick-start-protocol-layer) unless you have a
> specific reason not to. The primitives surface is documented here for
> embedders who need to construct/parse individual messages directly or are
> integrating into an orchestrator they already own.

Each flow has a `primitives::<flow>` module with `request` and `response`
submodules. The general pattern is:

- `produce(...)` — construct an outbound envelope, returning encoded wire
  bytes.
- `extract(envelope_bytes, ...)` — decrypt and decode an inbound envelope into
  the typed inner message.
- `process(...)` — interpret the decoded inner message (when there's logic
  beyond decoding).

### Pairing

The contact message is exchanged out-of-band (QR codes, existing messaging
channels, etc.). Two modes select how the initiator's public encryption
material is delivered:

| `ContactMode` | What's in the contact | When to use |
|---|---|---|
| `InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry the keys (e.g. NFC, direct messaging). |
| `HashedKeys` | Only a SHA-384 commitment to the keys (`contact_binding_hash`) | The out-of-band channel is size-constrained (QR codes). The scanner fetches the actual keys over the wire via a `PrePair` round-trip, then verifies them against the hash. |

After the handshake completes, **both modes** rekey the channel id. The
responder includes
`channel_id = u64::from_be_bytes( SHA-384(u64_be(originalId) || sharedKey)[..8] )`
in the encrypted `PairResponseMessage`; both sides switch their local channel
record to that value and route all future traffic on it. Because the new id
travels encrypted, a passive observer who only saw the pre-rekey traffic
cannot link the long-running channel back to its pairing-time id.

#### `InlineKeys` flow

```rust,ignore
use derec_library::primitives::pairing::{request, response};
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, Protocol, SenderKind, TransportProtocol};

let channel_id = ChannelId(42);

// Step 1 — Initiator creates the contact message (sent out-of-band).
let request::CreateContactResult {
    contact_message,
    secret_key: initiator_secret_key,
} = request::create_contact(
    channel_id,
    ContactMode::InlineKeys,
    TransportProtocol {
        uri: "https://relay.example/derec".to_owned(),
        protocol: Protocol::Https.into(),
    },
).unwrap();

// Step 2 — Responder decodes the contact and produces the request envelope.
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
    &contact_message,
    None, // optional CommunicationInfo
).unwrap();

// Step 3 — Initiator extracts the request and produces the response.
let request::ExtractResult { request: pair_request } =
    request::extract(&pair_request_envelope, initiator_secret_key.ecies_secret_key()).unwrap();
let response::ProduceResult {
    envelope: pair_response_envelope,
    shared_key: initiator_shared_key,
    channel_id: rekeyed_channel_id,
    ..
} = response::produce(
    channel_id,
    &pair_request,
    &initiator_secret_key,
    None,
).unwrap();

// Step 4 — Responder extracts the response and finalizes pairing.
let response::ExtractResult { response: pair_response } =
    response::extract(&pair_response_envelope, responder_secret_key.ecies_secret_key()).unwrap();
let response::ProcessResult {
    shared_key: responder_shared_key,
    channel_id: responder_rekeyed_id,
} = response::process(
    &initiator_contact_message,
    &pair_response,
    &responder_secret_key,
).unwrap();

// Both sides now hold the same shared key and the same rekeyed channel id;
// rename local channel state from `channel_id` to `rekeyed_channel_id`
// before sending any further traffic.
assert_eq!(initiator_shared_key, responder_shared_key);
assert_eq!(rekeyed_channel_id, responder_rekeyed_id);
assert_ne!(rekeyed_channel_id, channel_id);
```

To reject the request, build a `PairResponseMessage` with a non-`Ok`
`StatusEnum` and encrypt it with `DeRecMessageBuilder::pairing()` against the
peer's `request.ecies_public_key`. The protocol-layer `reject` method does
this for you. Rejected responses do not carry a meaningful `channel_id` —
the rekey only takes effect on `Ok` responses.

#### `HashedKeys` flow (PrePair)

`HashedKeys` adds one plaintext round-trip before the regular `InlineKeys`
handshake. The scanner fetches the keys via `PrePair`, verifies them against
`contact.contact_binding_hash`, and then runs the normal pairing flow on a
synthesized `ContactMessage` with the keys filled in.

```rust,ignore
use derec_library::primitives::pairing::{request, response};
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, ContactMessage, Protocol, SenderKind, TransportProtocol};

let channel_id = ChannelId(7);

// Initiator: HASHED_KEYS contact (no inline keys, only the binding hash).
// The transport URI MUST be ephemeral — PrePair envelopes are plaintext.
let request::CreateContactResult {
    contact_message: contact,
    secret_key: initiator_secret_key,
} = request::create_contact(
    channel_id,
    ContactMode::HashedKeys,
    TransportProtocol {
        uri: "https://relay.example/ephemeral".to_owned(),
        protocol: Protocol::Https.into(),
    },
).unwrap();

// Scanner: fetch keys via PrePair.
let request::ProducePrePairResult { envelope: pre_pair_req_env } =
    request::produce_pre_pair_request(
        TransportProtocol {
            uri: "https://relay.example/scanner-ephemeral".to_owned(),
            protocol: Protocol::Https.into(),
        },
        &contact,
    ).unwrap();
let request::PrePairExtractResult { request: pre_pair_req } =
    request::extract_pre_pair(&pre_pair_req_env).unwrap();
let response::ProducePrePairResult { envelope: pre_pair_resp_env } =
    response::produce_pre_pair(channel_id, &pre_pair_req, &initiator_secret_key).unwrap();
let response::PrePairExtractResult { response: pre_pair_resp } =
    response::extract_pre_pair(&pre_pair_resp_env).unwrap();

// Scanner validates the published keys against `contact.contact_binding_hash`;
// returns the keys + nonce on match, errors with
// `PairingError::PrePairHashMismatch` on mismatch.
let validated = response::process_pre_pair(&contact, &pre_pair_resp).unwrap();

// Synthesize a "filled-in" contact and run the regular pairing flow. The
// mode flip is required — `request::produce` enforces `InlineKeys` and
// rejects a contact that still advertises `HashedKeys`.
let filled_in_contact = ContactMessage {
    mlkem_encapsulation_key: Some(validated.mlkem_encapsulation_key),
    ecies_public_key: Some(validated.ecies_public_key),
    contact_mode: ContactMode::InlineKeys as i32,
    contact_binding_hash: None,
    ..contact.clone()
};
// ... continue with request::produce / extract / response::produce / process
// against `filled_in_contact` exactly as in the InlineKeys example.
```

After the PrePair exchange the application **must** swap the transport
endpoint to a long-term one via `UpdateChannelInfo`. The ephemeral endpoint
advertised in the `HashedKeys` contact is intended to be retired immediately
after pairing.

### Share Distribution

```rust,ignore
use derec_library::primitives::sharing::request;
use derec_library::types::ChannelId;

let secret_id: u64 = 42;
let secret_data = b"super_secret_value";
let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
let threshold = 2; // 2 <= threshold <= channels.len()
let version: u32 = 1;

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

### Verification

```rust,ignore
use derec_library::primitives::verification::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let secret_id: u64 = 42;
let version: u32 = 7;
let shared_key = [0u8; 32]; // established during pairing

// Owner side: produce and send the verification request.
let result = request::produce(channel_id, secret_id, version, &shared_key).unwrap();
let request_wire_bytes = result.envelope;

// Helper side: decrypt and extract the inner request.
let request::ExtractResult { request: verify_request } =
    request::extract(&request_wire_bytes, &shared_key).unwrap();

// Helper side: produce the response, proving possession of the share.
let resp_result =
    response::produce(channel_id, &verify_request, &shared_key, b"example_share").unwrap();
let response_wire_bytes = resp_result.envelope;

// Owner side: decrypt and verify the proof.
let response::ExtractResult { response: verify_response } =
    response::extract(&response_wire_bytes, &shared_key).unwrap();
let ok = response::process(&verify_response, b"example_share").unwrap();

assert!(ok);
```

### Discovery

```rust,ignore
use derec_library::primitives::discovery::{
    request,
    response::{self, SecretVersionEntry, VersionEntry},
};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let shared_key = [0u8; 32]; // established during pairing

// Owner side: produce the discovery request.
let request::ProduceResult { envelope: request_envelope } =
    request::produce(channel_id, &shared_key).unwrap();

// Helper side: extract the request, enumerate stored secrets, produce the response.
let _req = request::extract(&request_envelope, &shared_key).unwrap();

let stored: Vec<SecretVersionEntry> = vec![
    SecretVersionEntry {
        secret_id: 1,
        versions: vec![VersionEntry { version: 1, description: "Main wallet".to_owned() }],
    },
    SecretVersionEntry {
        secret_id: 2,
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

for entry in &secret_list {
    for v in &entry.versions {
        println!(
            "secret_id={}  version={}  description={:?}",
            entry.secret_id, v.version, v.description,
        );
    }
}
```

### Recovery

Recovery is a three-step process: **pairing** (re-establish a channel with
each helper in recovery mode), **discovery** (ask each helper which secrets it
holds), and **share collection** (reconstruct the secret). The end-to-end
flow is orchestrated by the protocol layer; see `bindings/rust/src/protocol.rs`
in the repository for the full driver loop.

Helper-side primitive surface:

```rust,ignore
use derec_library::primitives::recovery::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let shared_key = [0u8; 32]; // established during pairing
// request_envelope:        outer DeRecMessage bytes carrying a GetShareRequest
// stored_share_request:    StoreShareRequestMessage the helper persisted at sharing time

let request::ExtractResult { request: get_share_request } =
    request::extract(&request_envelope, &shared_key).unwrap();
let response::ProduceResult { envelope: response_envelope } = response::produce(
    channel_id,
    &get_share_request,
    &stored_share_request,
    &shared_key,
).unwrap();
```

Owner side — decrypt each helper response, reconstruct the secret once enough
have arrived:

```rust,ignore
use derec_library::primitives::recovery::response;

let secret_id: u64 = 42;
let version: u32 = 1;
// responses: Vec<GetShareResponseMessage> collected from `response::extract` per helper.
let inputs: Vec<&_> = responses.iter().collect();
let recovered = response::recover(secret_id, version, &inputs).unwrap();
// recovered.secret_data contains the reconstructed payload.
```

### Unpairing

Either party may end a channel by initiating an unpair flow. The recipient
drops its state (shared key, channel record, stored shares) and acknowledges
with an `UnpairResponseMessage`. Through the protocol layer this is one call;
the primitive surface is below.

```rust,ignore
use derec_library::primitives::unpairing::{request, response};
use derec_library::types::ChannelId;

let channel_id = ChannelId(1);
let shared_key = [0u8; 32]; // established during pairing

// Initiator side: produce and send the unpair request.
let req_result = request::produce(channel_id, "decommissioning", &shared_key).unwrap();

// Responder side: extract the request, drop local state, send Ok response.
let _extracted = request::extract(&req_result.envelope, &shared_key).unwrap();
let resp_result = response::produce(channel_id, &shared_key).unwrap();

// Initiator side: extract and validate the response.
let response::ExtractResult { response: unpair_response } =
    response::extract(&resp_result.envelope, &shared_key).unwrap();
let outcome = response::process(&unpair_response).unwrap();
assert!(outcome.acknowledged);
```

Through the protocol layer:

```rust,ignore
use derec_library::protocol::{DeRecFlow, UnpairAck};
use derec_library::types::Target;

let mut protocol = DeRecProtocolBuilder::new()
    .with_unpair_ack(UnpairAck::Required)
    // … other setters …
    .build()?;

protocol.start(DeRecFlow::Unpair {
    target: Target::Single(channel_id),
    memo: Some("decommissioning".to_owned()),
}).await?;
```

`UnpairAck::Required` (default) keeps local state until the peer replies
`Ok`, or until the configured timeout elapses; the `Unpaired` event surfaces
in either case. `UnpairAck::NotRequired` drops local state immediately on
`start(Unpair)` and ignores any later response.

When the peer's `UnpairRequest` arrives on the responder side, the
orchestrator emits `DeRecEvent::ActionRequired { channel_id, action }` with
`action` set to `PendingAction::Unpair { .. }`. The application calls
`protocol.accept(action)` to drop local state and reply `Ok`, or
`protocol.reject(action, status, memo)` to keep local state and reply with a
non-`Ok` status.

---

## Protocol specification

Full protocol documentation:
<https://derec-alliance.gitbook.io/docs/protocol-specification/messages>

---

## Security considerations

Applications using this SDK should ensure:

- Secure storage of secret material (`DeRecSecretStore` content is
  keychain-grade — see the trait doc).
- Proper authentication of helpers.
- Safe transport channels.
- Protection against replay attacks beyond the protocol's own timestamp-based
  staleness check.

The DeRec protocol assumes helpers are independent and trusted entities.

### Replica destinations inherit Source trust

A `ReplicaDestination` receives the full
[`Secret`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.Secret.html),
which embeds every helper's `channel_id` and `shared_key` under
[`HelperInfo`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.HelperInfo.html).
Anyone with the secret can therefore authenticate as the Source toward
every helper. This is intentional — it is what makes Destination-driven
recovery work — but it means a compromised Destination can impersonate
the Source against every helper that was paired at the time the secret
was sent. Pick Destinations with at least the trust level of the Source
device itself; do not treat them as opaque backups.

### `HashedKeys` requires an ephemeral transport URI

`ContactMode::HashedKeys` ships only a SHA-384 binding hash in the
contact and serves the actual public keys through a plaintext PrePair
round-trip on the contact creator's `own_transport`. Any party that can
reach that URI before the legitimate scanner gets the keys. Use
`HashedKeys` only with a transport endpoint that is freshly minted for
this pairing and that you can retire as soon as the PrePair leg
completes. `ContactMode::InlineKeys` has no such constraint because the
keys are embedded directly in the (already binding-hash-validated)
contact bytes.

The recommended pattern is: pair on the ephemeral URI, then — as soon
as the pairing completes on the contact creator side — call
`set_own_transport` with the permanent endpoint and start an
`UpdateChannelInfo` flow against the peer to announce the swap. Once
the peer acknowledges, retire the ephemeral URI. This keeps the
plaintext PrePair window tight while letting subsequent traffic ride
on the long-lived endpoint.

### Replica fingerprint verification is mandatory

Replica channels are created in `ChannelStatus::Pending` and remain
there until both sides call `verify_fingerprint` with the value the
peer derived from the shared key — confirmed out of band, the same way
helper pairings are. The orchestrator enforces this:
`start(ProtectSecret)` returns
[`Error::InvalidInput`](https://docs.rs/derec-library/latest/derec_library/enum.Error.html#variant.InvalidInput)
when a target is still `Pending`. Treat verification as a required step
in the pairing UX, not an optional confirmation — a scanner that
auto-pairs without it accepts a MITM-vulnerable replica.

### The `derec.*` namespace in `CommunicationInfo` is library-owned

`CommunicationInfo` is otherwise an opaque app-defined map, but every
key under the `derec.` prefix is reserved for the protocol. Today the
library owns `derec.replica_id`; future protocol additions will use the
same namespace. Application code must not write any `derec.*` entry —
the orchestrator silently overwrites or strips library-owned keys at
the protocol boundary, and app-set values are lost without warning.

---

## License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file for
details.

---

## Contributing

Contributions are welcome. Repository:
<https://github.com/derecalliance/lib-derec>. Please open issues or pull
requests to discuss improvements.

---

## DeRec Alliance

The DeRec Alliance is an open initiative focused on standards for
decentralized secret recovery. <https://derecalliance.org>
