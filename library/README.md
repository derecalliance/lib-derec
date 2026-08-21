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
- [Cargo features](#cargo-features)
- [Two API layers](#two-api-layers)
- [Quick start (Protocol layer)](#quick-start-protocol-layer)
- [Builder configuration](#builder-configuration)
- [Event-driven model](#event-driven-model)
- [Helper-side admission control](#helper-side-admission-control)
- [Protocol flows](#protocol-flows)
- [Replica flows](#replica-flows)
- [Correlation and routing on the wire](#correlation-and-routing-on-the-wire)
- [Storage and transport traits](#storage-and-transport-traits)
- [Choosing backends at run time](#choosing-backends-at-run-time)
- [Errors](#errors)
- [Async and executors](#async-and-executors)
- [WebAssembly support](#webassembly-support)
- [Transport layer](#transport-layer)
- [Observability](#observability)
- [Primitives (advanced)](#primitives-advanced)
- [Secret format](#secret-format)
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
  replicas) to every Destination via a
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

## Cargo features

Every feature is **off by default** — a default build compiles no serde, no
FFI layer, and no logging, so a pure-Rust consumer pays for none of them.

| Feature | Enables |
| --- | --- |
| `serde` | `serde::Serialize` / `Deserialize` on the public store and channel types (`SecretValue`, `PairingKeyMaterial`, `ChannelRecord`, `HelperChannel`, `ReplicaMember`, `ChannelStatus`, `TransportProtocol`), so a store implementation can persist them with any serde format. Without it, use the byte-level accessors (e.g. `PairingKeyMaterial::as_bytes` / `from_bytes`) or your own codec. Also pulls the matching `derec-proto/serde`. The serde wire format is not part of the public API and may change. |
| `logging` | `tracing` spans and events across the protocol and primitives layers. Adds no overhead when no subscriber is installed. |
| `ffi` | The native C-ABI bridge for host languages that link the shared library. Implies `serde` + `serde_json`. Pure-Rust consumers do not need this. |
| `unsafe-http` | **Development only.** Lets `TransportProtocol::validate` accept plaintext `http://` endpoints. Production builds MUST leave this off — enabling it also lets a peer-supplied `replyTo` downgrade the reply path to plaintext. |

```toml
[dependencies]
derec-library = { version = "*", features = ["serde"] }
```

The `wasm32` target pulls serde in automatically, so WebAssembly builds need
no extra feature flags.

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
//    - DeRecChannelStore  — helper channels + replica-group members
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

// Initiate a pairing flow from a contact message received out-of-band.
// `start` returns per-target `*Started` / `*Failed` events describing
// what was dispatched — for pairing that's one `PairingStarted` with
// the fresh `channel_id`. Fan-out flows (ProtectSecret, VerifyShares,
// RecoverSecret, Discovery, UpdateChannelInfo) return one event per
// targeted channel. Follow-up events (`PairingCompleted`,
// `ShareConfirmed`, `SecretRecovered`, …) still surface from
// `process()` on the peer's response.
for event in protocol
    .start(DeRecFlow::Pairing {
        kind: derec_proto::SenderKind::Helper,
        contact: contact_message,
        peer_communication_info: Default::default(),
    })
    .await?
{
    if let DeRecEvent::PairingStarted { channel_id, .. } = event {
        println!("dispatched pair on channel {}", channel_id.0);
    }
}

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
                // Recovery completed — `secret` is the typed `Secret` snapshot
                // the owner originally protected. The user-facing entries live
                // in `secret.secrets: Vec<UserSecret>`; `helpers`, `replicas`
                // carry the roster captured at
                // distribution time.
                for entry in &secret.secrets {
                    println!("recovered {} ({}B)", entry.name, entry.data.len());
                }
                // Commit the recovered Secret into this fresh protocol's
                // stores. Wipes the throwaway recovery-mode channels and
                // reseats canonical helper / replica state at the recovered
                // version. See `DeRecProtocol::restore`.
                protocol.restore(&secret, recovered_version).await?;
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
| `with_timeout(duration)` | `5 minutes` | Staleness boundary for inbound envelopes, sharing-round timeouts and unpair timeouts. One-second granularity. |
| `with_remove_expired_channels(policy)` | `Enabled { timeout_in_secs: 300 }` | Automatic removal of expired `Pending` channels during `process()`. `Disabled` leaves it to the application via `remove_expired_channels`. Replica pairings and `NoKeys` pairings await human fingerprint confirmation while `Pending`, so deployments using either should raise the timeout or disable it — the default gives a user five minutes to compare a fingerprint out of band. |
| `with_communication_info(map)` | empty | Key-value identity metadata embedded in pairing messages. |
| `with_auto_respond_on_failure(bool)` | `false` | If `true`, the protocol replies to the peer on inbound processing failures; if `false`, errors only surface as events. |
| `with_unpair_ack(ack)` | `UnpairAck::Required` | Whether the unpair initiator waits for the peer's `Ok` before dropping local state. |
| `with_auto_reply_to(bool)` | `false` | If `true`, every outbound request stamps `replyTo = own_transport` so the responder routes the reply back to this node — even if the channel's stored peer endpoint points elsewhere. Useful for replica scenarios. See [Correlation and routing on the wire](#correlation-and-routing-on-the-wire). |

See the [builder rustdoc](https://docs.rs/derec-library/latest/derec_library/protocol/struct.DeRecProtocolBuilder.html)
for the full per-setter contract.

---

## Event-driven model

Both `start` and `process` return `Vec<DeRecEvent>`. The application
reacts to events; the protocol owns the state.

`start` emits per-target **dispatch** events describing what was just
sent — `PairingStarted`, `DiscoveryStarted`, `ProtectSecretStarted`,
`VerifySharesStarted`, `RecoverSecretStarted`, `UnpairStarted`,
`UpdateChannelInfoStarted`. Fan-out flows also surface per-target
failures with the matching `*Failed { channel_id, error }` variant when
a single target's send hits a transport / store error — those failures
don't short-circuit the rest of the fan-out. Single-channel flows
(`Pairing`, `Unpair`) don't have `*Failed` variants; a dispatch error
returns `Err` from `start` instead. Programmer errors (invalid input,
missing preconditions, role mismatch) always return `Err` up-front,
before any target-level events are emitted.

`process` emits the **settlement** events driven by peer responses:

- `ActionRequired { channel_id, action }` — an incoming request needs
  application confirmation. The app calls `protocol.accept(action)` or
  `protocol.reject(action, status, memo)` to complete the flow.
- `PairingCompleted { channel_id, kind, peer_communication_info }`
- `ShareStored { channel_id, version }` / `ShareConfirmed { … }` /
  `ShareRejected { … }` / `SharingComplete { … }`
- `ShareVerified { channel_id, version }`
- `SecretsDiscovered { channel_id, secrets }`
- `RecoveryShareReceived { … }` /
  `SecretRecovered { secret: Secret }` (typed; `secret.secrets` is the
  list of `UserSecret` the owner protected, alongside the captured
  helper/replica roster) /
  `RecoveryShareError { … }`
- `Unpaired { channel_id }` / `UnpairRejected { channel_id, status, memo }` /
  `UnpairFailed { channel_id, error }` — emitted by `restore` when an
  ephemeral recovery channel's teardown could not be delivered. The
  teardown is fire-and-forget, so local state is dropped anyway and an
  `Unpaired` for the same channel follows; the pair means "gone locally,
  peer not told"

- `ChannelInfoUpdated { channel_id }` /
  `ChannelInfoUpdateRejected { channel_id, status, memo }`
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

A channel row describes the participant on the other end, so each paired
channel carries the **peer's** role — `SenderKind::Owner`,
`SenderKind::Helper`, `SenderKind::ReplicaSource`, or
`SenderKind::ReplicaDestination` — fixed at pairing time and stored on
[`HelperChannel.peer_role`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.HelperChannel.html).
The two sides of one channel therefore hold opposite values: an Owner's
row for its helper reads `Helper`, and that helper's row for the Owner
reads `Owner`. This node's own role is always the inverse
(`Owner` ↔ `Helper`, `ReplicaSource` ↔ `ReplicaDestination`).

The orchestrator enforces flow directionality against this value:

- Outbound: `ProtectSecret`, `VerifyShares`, `Discovery`, `RecoverSecret`,
  and `Unpair` require the peer to be a `Helper` (or a
  `ReplicaDestination` for `ProtectSecret`) on every targeted channel.
- Inbound: a `StoreShareRequest` / `VerifyShareRequest` /
  `GetSecretIdsVersionsRequest` / `GetShareRequest` / `UnpairRequest` is
  only honored when it arrives from a peer recorded as `Owner`; the
  corresponding responses require a `Helper` peer. A `StoreShareRequest`
  on a `ReplicaSource` channel is decoded as a
  [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html)
  and surfaces as
  [`DeRecEvent::ReplicaSecretReceived`](https://docs.rs/derec-library/latest/derec_library/protocol/events/enum.DeRecEvent.html#variant.ReplicaSecretReceived).
- `UpdateChannelInfo` is symmetric — either side may initiate it, and the
  peer role is not consulted.

A mismatch surfaces as `Error::RoleMismatch { channel_id, expected, actual }`.

---

## Helper-side admission control

**The protocol enforces no limits of its own on inbound shares.** It does
not bound share size, storage consumed per sharer, or how often an owner
may push updates. A helper that needs those limits enforces them itself,
and this section is how.

`ParameterRange.maxShareSize` does not do this for you. It is exchanged
during pairing and checked for *range overlap* between the two peers'
advertised ranges; the negotiated value is never compared against an
actual share afterwards. Treat it as a compatibility handshake, not an
enforced ceiling.

### Where the decision belongs

Not before `process()`. Reading a share's size from raw wire bytes would
mean decoding the envelope, resolving the channel's shared key,
decrypting the inner message and parsing the protobuf — reimplementing
the protocol's receive path outside the protocol.

Instead, `process()` does that work and hands back the decoded request in
an `ActionRequired` event. `PendingAction::StoreShare` carries the
already-decrypted `StoreShareRequestMessage`, so the application inspects
the share without touching wire bytes or key material:

```rust,ignore
for event in protocol.process(&wire_bytes).await? {
    let DeRecEvent::ActionRequired { action, channel_id } = event else { continue };
    match &action {
        PendingAction::StoreShare { request, .. } => {
            // `channel_id` maps to a user in the application's own store,
            // so the limit can be per-user, per-plan, or whatever the
            // deployment needs.
            let limit = my_app.share_limit_for(channel_id);
            if request.share.len() > limit {
                protocol
                    .reject(
                        action,
                        StatusEnum::SizeLimitExceeded,
                        &format!("share exceeds the {limit}-byte limit"),
                    )
                    .await?;
            } else {
                protocol.accept(action).await?;
            }
        }
        _ => { protocol.accept(action).await?; }
    }
}
```

The owner receives a `StoreShareResponse` carrying that status and memo,
surfacing as `ShareRejected { channel_id, version, status, memo }` on its
side — so a refusal is attributable rather than a silent timeout.

Status codes for the common cases:

| Status | Use for |
|--------|---------|
| `SizeLimitExceeded` | share too large, or storage quota for this sharer exhausted |
| `TooFrequent` | rate limiting — the owner is updating faster than the helper allows |
| `Rejected` | a user or operator declined the request |
| `Fail` | anything else; put the detail in `memo` |

### `auto_accept.store_share` removes this gate

> [!IMPORTANT]
> Setting `AutoAcceptPolicy::store_share = true` means `process()`
> accepts and stores every inbound share internally. No `ActionRequired`
> is emitted, so **there is no opportunity to reject** — every share from
> every paired Owner is stored unconditionally, at whatever size it
> arrives.

Keep it `false` in any deployment with per-user storage limits. It is
`false` by default; only an explicit
`with_auto_accept(...)` turns it on, including via
`AutoAcceptPolicy::all()`.

### This is policy, not DoS protection

By the time `ActionRequired` fires, the message has already been
received, decrypted and parsed. Rejecting here protects your *storage*,
not the CPU and memory spent getting there.

`process()` deliberately imposes no upper bound on inbound message size —
legitimate envelopes range from tens of bytes to many megabytes, and any
cap tight enough to resist abuse risks truncating a legitimate replica
sync, which can render a secret unrecoverable. Applications must bound
inbound message size at the **transport** layer (max HTTP body,
WebSocket frame size) sized to their deployment's secret size, helper
count and replica fan-out. The two mechanisms are complementary: the
transport cap protects resources, `reject` enforces policy.

---

## Protocol flows

| Flow | Purpose |
|------|---------|
| Pairing | Establish a secure channel between any two SenderKinds (Owner↔Helper or ReplicaSource↔ReplicaDestination). Two contact modes — see [Pairing modes](#pairing-modes). |
| Share Distribution | Split a secret and distribute the shares to helpers; replica destinations receive the full secret as a [`ReplicaSecretPayload`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html). |
| Verification | Challenge helpers to prove they still hold their shares. |
| Discovery | Ask helpers which secrets and versions they store. |
| Recovery | Re-pair, collect shares, reconstruct the secret. |
| Restore | Commit a recovered [`Secret`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.Secret.html) into an empty protocol — reseats canonical helper / replica channels at the recovered version and wipes the throwaway recovery-mode channels. Called once, after `Recovery`, via [`DeRecProtocol::restore`](https://docs.rs/derec-library/latest/derec_library/protocol/struct.DeRecProtocol.html#method.restore). |
| Unpairing | Tear down a paired channel and drop local state. |
| Update channel info | Propagate post-pairing changes to communication info and/or transport endpoint. |

### Pairing modes

`DeRecProtocol::create_contact` takes a `ContactMode` argument; the choice
travels in the `ContactMessage` and tells the scanner which handshake to run.

| `ContactMode` | Contact carries | When to use |
|---|---|---|
| `InlineKeys` | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry ~1.2 KB (NFC, deep link, direct messaging). |
| `HashedKeys` | Only a 48-byte SHA-384 commitment to the keys | Out-of-band channel is size-constrained (QR codes). The scanner fetches the real keys over the wire via a plaintext `PrePair` round-trip and verifies them against the commitment. |
| `NoKeys` | `channel_id`, `nonce` and the transport endpoint — nothing else | Out-of-band channel is a human one: hand-typed, dictated over the phone, or an institutional email. Requires a caller-supplied `nonce`. **The channel stays unusable until the fingerprint is confirmed** — see below. |

> **`NoKeys` is the one mode with no cryptographic binding to the keys.**
> `InlineKeys` carries them in the contact; `HashedKeys` carries a commitment
> the scanner checks the fetched keys against. `NoKeys` carries neither, and
> its `PrePair` leg is plaintext, so an attacker who intercepts that exchange
> can substitute their own keys — the nonce does not prevent it, because the
> nonce is in the same plaintext.
>
> The library therefore holds a `NoKeys` channel in `ChannelStatus::Pending`
> until [`verify_fingerprint`](#fingerprint-confirmation) succeeds: it is not
> a `ProtectSecret` target, not a recovery source, and inbound messages on it
> are ignored. A man-in-the-middle leaves the two sides with different shared
> keys and so different fingerprints, which is exactly what the comparison
> catches. Applications MUST also rate-limit inbound `PrePairRequest`s per
> `channel_id` and expire outstanding `NoKeys` contacts on a short timer.

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
[`protocol::utils::reserved_keys`](https://docs.rs/derec-library/latest/derec_library/protocol/utils/reserved_keys/index.html).
Apps should not write to this namespace; the orchestrator strips and
re-injects entries at the protocol boundary.

### Fingerprint confirmation

Two kinds of channel start in `ChannelStatus::Pending` after the handshake
and are not eligible as `ProtectSecret` targets until both sides confirm the
pair out of band:

- **Every replica channel**, whatever the contact mode — admitting another
  device to the group is a human decision.
- **Every `NoKeys` channel**, including owner↔helper ones. That mode commits
  to nothing, so the fingerprint is the only check that catches a key
  substituted on its plaintext `PrePair` leg.

A `Pending` channel fails closed: nothing is published to it, it is not used
as a recovery source, and inbound messages on it are ignored.

The protocol derives a deterministic human-readable fingerprint from the
shared key — same on both devices — that users compare visually before each
side calls `verify_fingerprint`:

```rust
let local = source.get_fingerprint(channel_id).await?;
let peer  = destination.get_fingerprint(channel_id).await?; // out of band

source.verify_fingerprint(channel_id, &peer).await?;        // → true
destination.verify_fingerprint(channel_id, &local).await?;  // → true
```

`verify_fingerprint` returns `true` on match and transitions the channel
to `Paired`. A mismatch returns `false` and leaves the channel `Pending`
so the app can retry.

Confirmation is also the moment the peer becomes reachable, so the current
snapshot is published to it then — a `NoKeys` helper was not an eligible
target at handshake time, and the pairing-time auto-publish skipped it.

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

#### When a mixed round reports

A round that targets both helpers and replica members reports **only once
both populations have settled**. `SharingComplete` and `ReplicaSyncComplete`
are emitted together, at that moment.

The counts on `SharingComplete` describe helpers only and are known the
instant the helpers answer — but the event is held until every member has
acknowledged, refused, or timed out. So **one unreachable member delays it by
up to `with_timeout`**, even though the helpers confirmed in milliseconds.

Nothing is lost and the round always terminates: the timeout sweep closes it,
and a member that never answered is reported in `behind` rather than failing
the round. The application is simply told late, which is easy to mistake for a
hang.

Two things follow for application authors:

- **Do not drive a "your secret is protected" indicator from
  `SharingComplete` alone** if replicas are in play. Watch the per-peer
  `ShareConfirmed` events instead — those land as each helper answers, with no
  cross-population wait.
- **Call `tick()` on a schedule.** Timeouts only advance inside `process` and
  `tick`, so an idle protocol with a stranded round never closes it at all.

A helpers-only round is unaffected and completes as soon as the helpers
answer.

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
Consumers implement six traits — five stores plus the transport. All are
required to build a protocol instance. The protocol holds them by `&mut self`,
so implementations need no internal synchronization:

| Trait | Stores |
|-------|--------|
| [`DeRecChannelStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecChannelStore.html) | Helper channels (keyed by `channel_id`), replica-group members (keyed by `replica_id`), and the channel-link graph. |
| [`DeRecShareStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecShareStore.html) | Encoded share entries keyed by `(channel_id, secret_id, version)`. |
| [`DeRecSecretStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecSecretStore.html) | Per-channel cryptographic material (shared keys, pairing secrets, pairing contacts). |
| [`DeRecUserSecretStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecUserSecretStore.html) | The latest user-facing secret snapshot per `secret_id` — what a freshly-paired peer is sent. |
| [`DeRecStateStore`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecStateStore.html) | In-flight orchestrator state: verification challenges, recovery accumulators, pending unpairs, the active sharing round and catch-up. Must be durable in any deployment that can restart mid-flow. |
| [`DeRecTransport`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecTransport.html) | Outbound envelope delivery to peers. |

Each trait's rustdoc states its contract, idempotency expectations, and the
security classification of the data it holds (`DeRecSecretStore` content is
keychain-grade; the others need durable storage only).

### Choosing backends at run time

`DeRecProtocol` is generic over all six, so by default the concrete backends
are baked into its type. To pick one at run time — Postgres in production,
in-memory under test — box the trait objects; the library implements every
trait for `Box<T>` and `&mut T`, so an erased protocol satisfies the builder's
bounds without any wrapper of your own:

```rust,ignore
type AnyProtocol = DeRecProtocol<
    Box<dyn DeRecChannelStore>,
    Box<dyn DeRecShareStore>,
    Box<dyn DeRecSecretStore>,
    Box<dyn DeRecUserSecretStore>,
    Box<dyn DeRecStateStore>,
    Arc<dyn DeRecTransport>,
>;

let protocol = DeRecProtocolBuilder::new(secret_id)
    .with_channel_store(Box::new(PostgresChannelStore::new(db)) as Box<dyn DeRecChannelStore>)
    // ...the rest of the stores, then a transport shared across requests:
    .with_transport(Arc::clone(&http))
    .build()?;
```

`Arc<T>` is implemented for `DeRecTransport` only. Every store has `&mut self`
methods and `Arc` never yields `&mut T`, so a store behind an `Arc` cannot
compile. The transport is the one `&self`-only trait — which is also the one
worth sharing, since it is typically a pooled client.

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

### Serving DeRec over request/response transports

The protocol is a **mailbox**: every participant has an address, and answering
someone means posting to their address. A reply produced while handling an
inbound message is not returned to the caller — it is handed to
`DeRecTransport::send`, addressed to the peer's endpoint, while `process()`
returns only the `DeRecEvent`s describing what happened.

When both sides are reachable services, that is all you need. The transport is
a one-way push and an HTTP handler acknowledges rather than answers:

```rust,ignore
async fn inbound(State(app): State<App>, body: Bytes) -> StatusCode {
    let mut protocol = app.build_protocol(HttpPush(app.http.clone()));
    let events = protocol.process(&body).await.expect("process");
    app.on_events(events).await;
    StatusCode::ACCEPTED // the reply is already on its way, separately
}
```

**A peer with no address breaks this silently.** A phone, a browser tab or
anything behind NAT advertised an endpoint at pairing time that nothing can
actually reach, so a push-style `send` drops the reply on the floor. Nothing
errors — `process` returned events and the handler looks successful — the peer
just never hears back.

Those deployments must answer on the connection the request arrived on, which
means capturing what the protocol emits instead of pushing it:

```rust,ignore
async fn inbound(State(app): State<App>, body: Bytes) -> Result<Bytes, StatusCode> {
    // 1. Build per request, with a transport that collects rather than sends.
    let collector = Collector::default();
    let mut protocol = app.build_protocol(collector.clone());

    let events = protocol
        .process(&body)
        .await
        .map_err(|_| StatusCode::UNPROCESSABLE_ENTITY)?;
    app.on_events(events).await;

    // 2. One `process` can emit several messages. Only the one echoing this
    //    request's trace_id answers the caller; the rest is real fan-out and
    //    still has to reach its own endpoint.
    let (reply, elsewhere) = split_reply(&body, collector.take());
    for (endpoint, bytes) in elsewhere {
        app.deliver_out_of_band(endpoint, bytes).await;
    }

    Ok(reply.map(Bytes::from).unwrap_or_default())
}
```

Two details carry this, and both are easy to miss:

- **Per-request construction.** The collector's buffer must belong to exactly
  one exchange, or concurrent requests mix their replies. This is the same
  per-request pattern a stateless deployment uses anyway.
- **Correlation by `trace_id`.** Admitting a helper also republishes to every
  *other* helper, so the buffer routinely holds messages for several peers.
  Responses echo the inbound envelope's `trace_id`;
  `derec_message::read_trace_id` tells them apart. Returning the whole buffer —
  or blindly returning its first entry — is the mistake to avoid.

`Collector` and `split_reply` are about twenty lines each; a complete, compiled
version of both is in the [`DeRecTransport` rustdoc][transport-doc].

Every SDK exposes the same correlation primitive: `Envelope.ReadTraceId`
(.NET), `envelope.ReadTraceID` (Go), `envelope_read_trace_id`
(TypeScript/WASM), `read_trace_id_from_envelope` (C FFI).

[transport-doc]: https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecTransport.html

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
channels, etc.). Three modes select how the initiator's public encryption
material is delivered:

| `ContactMode` | What's in the contact | When to use |
|---|---|---|
| `InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry the keys (e.g. NFC, direct messaging). |
| `HashedKeys` | Only a SHA-384 commitment to the keys (`contact_binding_hash`) | The out-of-band channel is size-constrained (QR codes). The scanner fetches the actual keys over the wire via a `PrePair` round-trip, then verifies them against the hash. |
| `NoKeys` | `channel_id`, `nonce` and the transport endpoint only | The out-of-band channel is human — hand-typed or dictated. Nothing commits to the keys, so the channel stays `Pending` until the fingerprint is confirmed. See [Pairing modes](#pairing-modes). |

After the handshake completes, **every mode** rekeys the channel id. The
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

## Secret format

The recoverable secret — the bytes reconstructed from a threshold of shares
(`recovered.secret_data` in [Recovery](#recovery) above) — is `[version byte]
· payload`. The leading byte is the format major version; for v1 the payload
is **gzip (RFC 1952) compressed JSON**. Within that JSON:

- every byte-array field (`shared_key`, `id`, `data`, …) is **standard base64
  with padding (RFC 4648 §4)** — never base64url;
- every `u64` field is a JSON **decimal string** (e.g. `"1000000"`), not a
  JSON number, to avoid precision loss;
- object keys are `snake_case`.

This format is deliberately independent of the DeRec wire protocol: transport
messages (`DeRecMessage`, `StoreShareRequest`, `ReplicaSecretPayload`, etc.)
remain protobuf and are unaffected. Only the recoverable secret placed in
`secret_data` uses this versioned envelope (v1: JSON + base64 + gzip), which
makes it a self-describing, cross-application interoperability surface — any
implementation can read the version byte, gunzip, parse the JSON, and
base64-decode the byte fields without sharing code or a compiled schema with
the producer.

The full field-by-field schema, encoding pipeline, and versioning rules are
normatively defined in the crate documentation for the
`derec_library::protocol::types::secret` module.

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

The replica group also shares a single **group channel key**: every
`(secret_id, channel_id)` entry in
[`DeRecSecretStore`](https://docs.rs/derec-library/latest/derec_library/protocol/trait.DeRecSecretStore.html)
for a paired replica channel holds the same 32-byte key, established at
the first replica pair and handed over to every subsequent joiner via
[`ReplicaSecretPayload.shared_key`](https://docs.rs/derec-library/latest/derec_library/protocol/types/struct.ReplicaSecretPayload.html)
on its first sync round. Compromise of any one Destination therefore
exposes that single key to the attacker; the protocol does not provide
per-pair forward secrecy across replicas.

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
decentralized secret recovery. <https://derec.org>
