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
