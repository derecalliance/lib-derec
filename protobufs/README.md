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

> [!IMPORTANT]
> Code generation runs in this crate's build script, so the Protocol Buffers
> compiler (`protoc`) must be installed and on your `PATH` (or located via the
> `PROTOC` environment variable) to build this crate.

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

## Schema Overview

### Roles

The protocol defines three roles via the `SenderKind` enum:

| Value | Role | Description |
|-------|------|-------------|
| `OWNER_NON_RECOVERY` | Owner | Standard pairing and sharing flows |
| `OWNER_RECOVERY` | Owner | Re-pairing with Helpers to recover lost secrets |
| `HELPER` | Helper | Stores shares and responds to Owner requests |
| `REPLICA` | Replica | Another device belonging to the same Owner |

### Message Files

| File | Messages | Purpose |
|------|----------|---------|
| `contact.proto` | `ContactMessage`, `ContactMode` | Out-of-band bootstrap for the pairing flow. `ContactMode` selects between inline keys and a SHA-384 commitment that the recipient resolves via `prepair.proto`. |
| `pair.proto` | `PairRequestMessage`, `PairResponseMessage`, `SenderKind` | Pairing handshake between Owner and Helper (or Replica). `PairResponseMessage.channelId` carries the post-handshake rekey id both sides switch to. |
| `prepair.proto` | `PrePairRequestMessage`, `PrePairResponseMessage` | Plaintext key fetch step used only with `ContactMode = HASHED_KEYS`; the recipient verifies the published keys against the contact's `contactBindingHash` before proceeding to `pair.proto`. |
| `unpair.proto` | `UnpairRequestMessage`, `UnpairResponseMessage` | Terminate a channel relationship |
| `storeshare.proto` | `StoreShareRequestMessage`, `StoreShareResponseMessage` | Distribute secret shares to Helpers |
| `verify.proto` | `VerifyShareRequestMessage`, `VerifyShareResponseMessage` | Challenge-response share verification |
| `secretidsversions.proto` | `GetSecretIdsVersionsRequestMessage`, `GetSecretIdsVersionsResponseMessage` | Discovery of stored secrets and versions |
| `getshare.proto` | `GetShareRequestMessage`, `GetShareResponseMessage` | Retrieve shares during recovery |
| `derecmessage.proto` | `DeRecMessage`, `MessageBody` | Top-level envelope wrapping all protocol messages |
| `result.proto` | `DeRecResult`, `StatusEnum` | Shared result/status types |
| `error.proto` | `ErrorResponseMessage` | Generic error response |
| `communicationinfo.proto` | `CommunicationInfo` | Application-level identity information |
| `parameterrange.proto` | `ParameterRange` | Configuration negotiation during pairing |
| `transportprotocol.proto` | `TransportProtocol` | Endpoint and protocol for message delivery |
| `committedderecshare.proto` | `CommittedDeRecShare` | Share data with Merkle proof commitment |
| `derecsecret.proto` | `DeRecSecret` | Secret metadata |

### Transport service contracts — `grpc/`

Everything above lives in `protobufs/` and defines the DeRec **message
vocabulary**: what the protocol says. `grpc/` holds contracts describing how
those envelopes are **delivered**, which is a separate concern — an
implementation reaching its peers over HTTPS needs nothing from this
directory.

| File | Defines | Purpose |
|---|---|---|
| `grpc/derectransport.proto` | `DeRecTransport` service (`Send` RPC) | gRPC delivery service contract: `rpc Send(DeRecMessage) returns (google.protobuf.Empty)`. |

The service shares the `org.derecalliance.derec.protobuf` package with the
message vocabulary, so its full name — and therefore the method path on the
wire — is unaffected by living in its own directory.

This crate ships the `.proto` definition only and generates **no service
stubs**. Consumers who want stubs run their own `tonic-prost-build`, as
`smoke-tests/grpc/build.rs` does.

### `DeRecSecret.secretData`

`secretData` is `bytes` and opaque to this crate — this schema only describes
its envelope, not its contents. When produced by `derec-library`, those bytes
are the recoverable secret: a **1-byte version prefix** followed by a
versioned payload (v1 = **gzip (RFC 1952)** compressed **JSON**, with byte
fields as **standard base64 with padding (RFC 4648 §4)** and `u64` fields as
decimal strings). This format is independent of the protobuf wire protocol
described in this crate; its full field schema is defined in the
`derec-library` documentation (the `protocol::types::secret` module).

### MessageBody Envelope

All protocol messages are wrapped in the `MessageBody` oneof inside
`DeRecMessage`. The current variants are:

| Field number | Variant |
|:---:|---------|
| 1 | `PairRequestMessage` |
| 2 | `PairResponseMessage` |
| 3 | `UnpairRequestMessage` |
| 4 | `UnpairResponseMessage` |
| 5 | `StoreShareRequestMessage` |
| 6 | `StoreShareResponseMessage` |
| 7 | `VerifyShareRequestMessage` |
| 8 | `VerifyShareResponseMessage` |
| 9 | `GetSecretIdsVersionsRequestMessage` |
| 10 | `GetSecretIdsVersionsResponseMessage` |
| 11 | `GetShareRequestMessage` |
| 12 | `GetShareResponseMessage` |
| 13 | `ErrorResponseMessage` |
| 14 | `UpdateChannelInfoRequestMessage` |
| 15 | `UpdateChannelInfoResponseMessage` |
| 16 | `PrePairRequestMessage` |
| 17 | `PrePairResponseMessage` |

---

## Cargo features

Off by default — a default build compiles no serde.

| Feature | Enables |
| --- | --- |
| `serde` | `serde::Serialize` / `Deserialize` on the hand-written wrapper types the SDKs exchange — `TransportProtocol` and `SenderKind`. The generated prost message types are unaffected; they cross process boundaries as protobuf. Enabled automatically by `derec-library`'s own `serde` feature, so consumers of the library rarely set it directly. |

```toml
[dependencies]
derec-proto = { version = "*", features = ["serde"] }
```

The serde shapes are an implementation detail of the SDK bridges, not a
stable wire format — protobuf encoding is the contract between peers.

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

### Store-share schema revision

The two store-share messages were revised after this schema was first
derived, so an implementation built against an earlier revision will not
interoperate with them. Field numbers and scalar types are both wire-
significant, and all three kinds of change below affect the encoding.

`StoreShareRequestMessage`:

| field | before | now |
| --- | --- | --- |
| `secretId` | *(absent — read from the enclosing `DeRecMessage`)* | `uint64` = 3 |
| `version` | `int32` = 3 | `uint32` = 4 |
| `keepList` | `repeated int32` = 4 | `repeated uint32` = 5 |
| `versionDescription` | = 5 | = 6 |
| `timestamp` | = 6 | = 7 |

`StoreShareResponseMessage`:

| field | before | now |
| --- | --- | --- |
| `secretId` | *(absent)* | `uint64` = 2 |
| `version` | `int32` = 2 | `uint32` = 3 |
| `timestamp` | = 3 | = 4 |

`secretId` was added so the store-share messages identify their own secret
rather than depending on the envelope, which every other message family
already did — `GetShare`, `VerifyShare` and `DeRecShare` all carry
`secretId` immediately before `version`. The remaining fields were
renumbered to make room, and the two counters became unsigned because
neither a version nor a retained-version list is ever negative.

`replyTo` (8) and `replicaId` (9) on the request, and `replicaId` (5) on the
response, were added afterwards in free slots and are backward compatible:
both are `optional`, and a reader that does not know them ignores them.

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

More information at https://derec.org
