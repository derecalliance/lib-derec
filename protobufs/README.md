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
| `REPLICA` | Replica | Another device belonging to the same Owner, synchronised via dedicated flows |

### Message Files

| File | Messages | Purpose |
|------|----------|---------|
| `contact.proto` | `ContactMessage` | Out-of-band bootstrap for the pairing flow |
| `pair.proto` | `PairRequestMessage`, `PairResponseMessage`, `SenderKind` | Pairing handshake between Owner and Helper (or Replica) |
| `unpair.proto` | `UnpairRequestMessage`, `UnpairResponseMessage` | Terminate a channel relationship |
| `storeshare.proto` | `StoreShareRequestMessage`, `StoreShareResponseMessage` | Distribute secret shares to Helpers |
| `verify.proto` | `VerifyShareRequestMessage`, `VerifyShareResponseMessage` | Challenge-response share verification |
| `secretidsversions.proto` | `GetSecretIdsVersionsRequestMessage`, `GetSecretIdsVersionsResponseMessage` | Discovery of stored secrets and versions |
| `getshare.proto` | `GetShareRequestMessage`, `GetShareResponseMessage` | Retrieve shares during recovery |
| `replicaconfirmation.proto` | `ReplicaConfirmationRequestMessage`, `ReplicaConfirmationResponseMessage` | Replica fingerprint confirmation |
| `replicachannelsdiscovery.proto` | `ReplicaChannelsDiscoveryRequestMessage`, `ReplicaChannelsDiscoveryResponseMessage` | Initial sync of Helper channels |
| `replicasecretsdiscovery.proto` | `ReplicaSecretsDiscoveryRequestMessage`, `ReplicaSecretsDiscoveryResponseMessage` | Initial sync of secrets |
| `replicachannelsync.proto` | `ReplicaChannelSyncRequestMessage`, `ReplicaChannelSyncResponseMessage` | Notify Replicas of new Helper pairings |
| `replicasecretsync.proto` | `ReplicaSecretSyncRequestMessage`, `ReplicaSecretSyncResponseMessage` | Notify Replicas of new secrets |
| `replica.proto` | _(empty, kept for backward compatibility)_ | Previously contained all Replica messages |
| `derecmessage.proto` | `DeRecMessage`, `MessageBody` | Top-level envelope wrapping all protocol messages |
| `result.proto` | `DeRecResult`, `StatusEnum` | Shared result/status types |
| `error.proto` | `ErrorResponseMessage` | Generic error response |
| `communicationinfo.proto` | `CommunicationInfo` | Application-level identity information |
| `parameterrange.proto` | `ParameterRange` | Configuration negotiation during pairing |
| `transportprotocol.proto` | `TransportProtocol` | Endpoint and protocol for message delivery |
| `committedderecshare.proto` | `CommittedDeRecShare` | Share data with Merkle proof commitment |
| `derecsecret.proto` | `DeRecSecret` | Secret metadata |

### Replica Messages

The Replica role introduces five flows, each with its own request/response
pair. All messages travel inside the encrypted `DeRecMessage` envelope using
the Owner↔Replica shared key established during pairing.

#### Replica Confirmation (`replicaconfirmation.proto`)

After pairing with `SenderKind::REPLICA`, both devices must verify they share
the same key by comparing a fingerprint. This flow formalises that exchange.

| Message | Fields | Direction |
|---------|--------|-----------|
| `ReplicaConfirmationRequestMessage` | `fingerprint`, `replica_id`, `timestamp` | Initiator → Receiver |
| `ReplicaConfirmationResponseMessage` | `result`, `replica_id`, `timestamp` | Receiver → Initiator |

The `fingerprint` is a 16-byte value where each byte is a single decimal digit
(`0`–`9`), derived from the shared key using SHA-256 (see `derec-cryptography`
for the algorithm). The library formats this as `XXXX-XXXX-XXXX-XXXX` for
display; the wire format remains raw bytes.

#### Channels Discovery (`replicachannelsdiscovery.proto`)

Once the Replica channel is confirmed, the Replica requests the list of all
active Helper channels from the Owner so it can synchronise its local state.

| Message | Fields | Direction |
|---------|--------|-----------|
| `ReplicaChannelsDiscoveryRequestMessage` | `last_batch_index`, `timestamp` | Replica → Owner |
| `ReplicaChannelsDiscoveryResponseMessage` | `total_batches`, `current_batch`, `repeated entries`, `timestamp` | Owner → Replica |
| `ReplicaChannelsEntry` | `channel_id`, `shared_key` | (nested in response) |

Responses are paginated. The Replica sets `last_batch_index` to `0` for the
initial request and increments it as batches are received. Each
`ReplicaChannelsEntry` carries the Helper channel's identifier and its 32-byte
shared key.

#### Secrets Discovery (`replicasecretsdiscovery.proto`)

After the Replica channel is confirmed, the Replica requests the list of all
protected secrets from the Owner. Combined with Channels Discovery, this
enables a full initial sync so that Replicas reach the same state as the Owner.

| Message | Fields | Direction |
|---------|--------|-----------|
| `ReplicaSecretsDiscoveryRequestMessage` | `last_batch_index`, `timestamp` | Replica → Owner |
| `ReplicaSecretsDiscoveryResponseMessage` | `total_batches`, `current_batch`, `repeated entries`, `timestamp` | Owner → Replica |
| `ReplicaSecretsEntry` | `secret_id`, `version`, `description`, `channel_ids` | (nested in response) |

Responses are paginated using the same batching scheme as Channels Discovery.
Each `ReplicaSecretsEntry` optionally includes the list of Helper channel IDs
that participated in the sharing flow for that secret.

#### Channel Sync (`replicachannelsync.proto`)

When a Replica pairs with a new Helper, it notifies peer Replicas about the
new channel so they can also interact with the Helper transparently.

| Message | Fields | Direction |
|---------|--------|-----------|
| `ReplicaChannelSyncRequestMessage` | `channel_id`, `shared_key`, `timestamp` | Replica → Replica |
| `ReplicaChannelSyncResponseMessage` | `result`, `timestamp` | Replica → Replica |

#### Secret Sync (`replicasecretsync.proto`)

When a Replica creates a new secret or a new version of a secret, it notifies
peer Replicas so they can maintain a consistent view of all protected secrets.

| Message | Fields | Direction |
|---------|--------|-----------|
| `ReplicaSecretSyncRequestMessage` | `secret_id`, `version`, `description`, `channel_ids`, `timestamp` | Replica → Replica |
| `ReplicaSecretSyncResponseMessage` | `result`, `timestamp` | Replica → Replica |

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
| 14 | `ReplicaConfirmationRequestMessage` |
| 15 | `ReplicaConfirmationResponseMessage` |
| 16 | `ReplicaChannelsDiscoveryRequestMessage` |
| 17 | `ReplicaChannelsDiscoveryResponseMessage` |
| 18 | `ReplicaSecretsDiscoveryRequestMessage` |
| 19 | `ReplicaSecretsDiscoveryResponseMessage` |
| 20 | `ReplicaChannelSyncRequestMessage` |
| 21 | `ReplicaChannelSyncResponseMessage` |
| 22 | `ReplicaSecretSyncRequestMessage` |
| 23 | `ReplicaSecretSyncResponseMessage` |

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
