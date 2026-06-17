# DeRec NodeJS SDK

Node.js bindings for `derec-library`, the Rust SDK implementing the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares across trusted helpers.

---

## Installation

```bash
npm install @derec-alliance/nodejs
```

or with yarn:

```bash
yarn add @derec-alliance/nodejs
```

---

## Requirements

- Node.js 18+
- TypeScript (optional)

No native dependencies are required.

---

## Design Overview

The NodeJS SDK is a **thin binding layer** over the Rust implementation.

All core logic is executed in Rust:

- Protobuf serialization / deserialization
- Cryptography (pairing, encryption, verification)
- DeRecMessage envelope construction
- Protocol validation

The JavaScript / TypeScript API operates exclusively on:

```ts
Uint8Array
```

These represent **opaque wire-level protocol messages**.

---

## Quick Example

```ts
import { primitives } from "@derec-alliance/nodejs";

const channelId = 1n;            // u64 → bigint
const secretId = 42n;            // u64 → bigint
const version = 1;               // u32 → number
const sharedKey = new Uint8Array(32); // established during pairing

const result = primitives.verification.request.produce(channelId, secretId, version, sharedKey);
// result carries the encoded DeRecMessage envelope, ready to send over transport.
```

---

## Pairing Flow

The `ContactMessage` is exchanged out-of-band (QR codes, existing messaging
channels, etc.). Two `ContactMode` values select how the public encryption
material is delivered:

| Mode | What the contact carries | Use when |
|---|---|---|
| `InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry the keys (NFC, messaging). |
| `HashedKeys` | Only a SHA-384 commitment to the keys | Channel is size-constrained (QR codes). Scanner fetches the actual keys via a plaintext `PrePair` round-trip and verifies them against the hash. |

After the handshake completes, **both modes** rekey the channel id. The
responder derives `SHA-384(u64_be(originalId) || sharedKey)[..8]` as a
`bigint`, includes it in the encrypted `PairResponseMessage`, and both sides
switch their local state to the new id. The new id never appears in plaintext
on the wire, so a passive observer who only saw pre-rekey traffic cannot link
the long-running channel to its pairing-time id.

### `InlineKeys` flow

```ts
import { ContactMode, primitives, SenderKind } from "@derec-alliance/nodejs";

const channelId = 1n;

// Step 1: Initiator creates the out-of-band ContactMessage.
const contact = primitives.pairing.request.create_contact(
  channelId,
  ContactMode.InlineKeys,
  { protocol: 0, uri: "https://owner.example.com" },
);

// Step 2: Responder produces a pairing request from the contact.
const request = primitives.pairing.request.produce(
  SenderKind.Helper,
  { protocol: 0, uri: "https://helper.example.com" },
  contact.contact_message,
  null, // optional CommunicationInfo
);

// Step 3: Initiator extracts the request and produces the response.
const { request: pairRequest } =
  primitives.pairing.request.extract(request.envelope, contact.secret_key);
const produced = primitives.pairing.response.produce(
  channelId,
  pairRequest,
  contact.secret_key,
  null,
);

// Step 4: Responder extracts and processes the response.
const { response: pairResponse } =
  primitives.pairing.response.extract(produced.envelope, request.secret_key);
const processed = primitives.pairing.response.process(
  request.initiator_contact_message,
  pairResponse,
  request.secret_key,
);

// Both sides hold the same shared key and rekeyed channel id.
// produced.shared_key  ==  processed.shared_key
// produced.channel_id  ==  processed.channel_id  !==  channelId
//
// Rename local channel state from `channelId` to `produced.channel_id`
// before sending any further traffic.
```

To reject the request, build a `PairResponseMessage` with a non-OK status and
encrypt it against `request.ecies_public_key` using the WASM-exposed pairing
envelope helpers. The higher-level `DeRecProtocol` orchestrator's `reject`
method does this for you. Rejected responses do not carry a meaningful
`channel_id` — the rekey only takes effect on `Ok` responses.

### `HashedKeys` flow (PrePair)

`HashedKeys` adds one plaintext round-trip before the regular `InlineKeys`
handshake. The scanner fetches the actual keys via `PrePair`, verifies them
against `contact.contact_binding_hash`, and then runs the normal pairing
flow on a synthesized contact with the keys filled in.

```ts
import { ContactMode, primitives, SenderKind, type ContactMessage } from "@derec-alliance/nodejs";

const channelId = 7n;

// Initiator: HASHED_KEYS contact (no inline keys, only the binding hash).
// Transport URI MUST be ephemeral — PrePair envelopes are plaintext.
const contact = primitives.pairing.request.create_contact(
  channelId,
  ContactMode.HashedKeys,
  { protocol: 0, uri: "https://relay.example.com/ephemeral" },
);

// Scanner: fetch keys via PrePair.
const prePairReqEnv = primitives.pairing.request.produce_pre_pair(
  { protocol: 0, uri: "https://scanner.example.com/ephemeral" },
  contact.contact_message,
);
const { request: prePairReq } =
  primitives.pairing.request.extract_pre_pair(prePairReqEnv.envelope);
const prePairRespEnv = primitives.pairing.response.produce_pre_pair(
  channelId, prePairReq, contact.secret_key,
);
const { response: prePairResp } =
  primitives.pairing.response.extract_pre_pair(prePairRespEnv.envelope);

// Scanner validates the published keys against contact.contact_binding_hash.
// Throws on mismatch (returns the keys + echoed nonce on match).
const validated = primitives.pairing.response.process_pre_pair(
  contact.contact_message, prePairResp,
);

// Synthesize a "filled-in" contact and run the regular pairing flow. The
// mode flip is required — `primitives.pairing.request.produce` enforces
// `InlineKeys` and rejects a contact that still advertises `HashedKeys`.
const { contact_binding_hash: _omitBindingHash, ...contactBase } =
  contact.contact_message;
const filledInContact: ContactMessage = {
  ...contactBase,
  contact_mode: ContactMode.InlineKeys,
  mlkem_encapsulation_key: validated.mlkem_encapsulation_key,
  ecies_public_key: validated.ecies_public_key,
};
// ... continue with primitives.pairing.request.produce / extract /
// primitives.pairing.response.produce / process against `filledInContact`
// exactly as in the InlineKeys example.
```

After the PrePair exchange the application **must** swap the transport
endpoint to a long-term one via `UpdateChannelInfo`. The ephemeral endpoint
advertised in the `HashedKeys` contact is intended to be retired immediately
after pairing.

#### Using `DeRecProtocol` instead

The orchestrator handles the whole chain automatically:

- **Contact creator** — `protocol.createContact(channelId, ContactMode.HashedKeys)`
  returns the small contact (binding hash only). When the scanner's
  `PrePairRequest` arrives, `protocol.process(bytes)` emits an
  `ActionRequired` event with `action_kind: "PrePair"`. Call
  `protocol.accept(action)` to publish the keys (the library builds the
  response and routes it), or `protocol.reject(action, status, memo)` to
  refuse.
- **Scanner** — `protocol.start(FlowKind.Pairing, { kind, contact })` kicks
  off the plaintext PrePair leg. On success, no event surfaces and the
  scanner auto-proceeds to `PairRequest`; the application sees
  `PairingCompleted` only when the final response lands. Failure modes:
    - Contact creator rejected → `DeRecEvent` with
      `type: "PrePairRejected"`, plus `status` / `memo`.
    - Binding-hash mismatch → `protocol.process(...)` throws a
      `DeRecException`-shape error whose `message` carries
      `"contact binding hash mismatch"`. This is security-relevant — the
      keys published by the peer do not match the commitment the scanner
      originally accepted.

End-to-end orchestrator-level coverage is in
`bindings/nodejs/protocol.ts::runHashedKeysPairingFlow` (happy path +
tampered-hash assertion).

---

## Share Distribution (Sharing Flow)

```ts
import { primitives } from "@derec-alliance/nodejs";

const secretId = 42n;                                  // u64
const secretData = new TextEncoder().encode("super-secret");
const channelIds = [1n, 2n, 3n];
const threshold = 2;                                   // must be 2 <= threshold <= channelIds.length
const version = 1;
// sharedKeys: Map<bigint, Uint8Array> with the 32-byte channel keys

const splitResult = primitives.sharing.request.split(
  secretId,
  secretData,
  channelIds,
  threshold,
  version,
);
// splitResult.value: Map<bigint, Uint8Array> — one CommittedDeRecShare per helper.

// Wrap each share into an encrypted delivery envelope.
for (const [channelId, committedShare] of splitResult.value) {
  const envelope = primitives.sharing.request.produce(
    channelId, version, secretId, committedShare, [], "", sharedKeys.get(channelId)!,
  );
}
```

---

## Recovery Flow

```ts
import { primitives } from "@derec-alliance/nodejs";

const secretId = 42n;          // u64
const version = 1;             // u32

// Owner side: produce the recovery request.
const shareRequest = primitives.recovery.request.produce(
  1n,                          // channel ID
  secretId,
  version,
  sharedKey,
);

// Helper side: produce the response using the StoreShareRequest it persisted
// at sharing time.
const shareResponse = primitives.recovery.response.produce(
  secretId,
  1n,                          // channel ID
  storedShareEnvelope,
  shareRequest,
  sharedKey,
);

// Owner side: collect at least `threshold` responses and reconstruct.
const recovered = primitives.recovery.response.recover(
  [
    { response: shareResponse, shared_key: sharedKey },
    // …additional helper responses…
  ],
  secretId,
  version,
);
// `recovered` is a Uint8Array carrying the reconstructed secret payload.
```

---

## Verification Flow

```ts
import { primitives } from "@derec-alliance/nodejs";

// Owner side: produce the verification request.
const requestEnvelope = primitives.verification.request.produce(channelId, secretId, version, sharedKey);

// Helper side: decrypt and extract the challenge fields.
const req = primitives.verification.request.extract(requestEnvelope, sharedKey);
// req.channel_id, req.secret_id, req.version, req.nonce

// Helper side: produce the response.
const responseEnvelope = primitives.verification.response.produce(
  channelId,
  req.secret_id,
  req.version,
  req.nonce,
  sharedKey,
  storedShareEnvelope
);

// Owner side: verify the response.
const isValid = primitives.verification.response.process(responseEnvelope, sharedKey, storedShareEnvelope);

console.log("Valid:", isValid);
```

---

## Key Principles

- All protocol messages are opaque `Uint8Array`
- No protobuf types are exposed
- No cryptographic operations occur in JavaScript
- Rust is the single source of truth

---

## Replica flows

Replicas mirror an Owner's vault onto a second device so the same secrets
remain reachable after device loss. Pairings are **unidirectional** — one
side runs as `SenderKind.ReplicaSource` (owns the vault), the other as
`SenderKind.ReplicaDestination` (receives it). Both must be constructed
with a stable `replicaId`:

```ts
const owner = new DeRecProtocol(
  channelStore, shareStore, secretStore, transport,
  "https://owner.example.com", "https",
  /* threshold */ 2, /* keepVersionsCount */ 3,
  { name: "Owner" },
  null, null, null, null,
  /* replicaId */ 0xAAAA_AAAA_AAAA_AAAAn,
);
```

A typical Source↔Destination handshake:

```ts
const contact = await owner.createContact(channelId, ContactMode.InlineKeys);
await destination.start(FlowKind.Pairing, {
  kind: SenderKind.ReplicaDestination,
  contact,
});
// pump messages between the two protocols (drain transport → process)
```

The channel ends up in `Pending` and is NOT eligible as a
`ProtectSecret` target until both sides confirm a deterministic
fingerprint derived from the shared key:

```ts
const localFp = await owner.getFingerprint(channelId);
const peerFp  = await destination.getFingerprint(channelId); // out of band

await owner.verifyFingerprint(channelId, peerFp);             // → true
await destination.verifyFingerprint(channelId, localFp);      // → true
```

Once paired, the Source includes the Destination as a `ProtectSecret`
target alongside helpers. Helpers receive the usual VSS share via
`StoreShareRequest`; the Destination receives the full vault as a
typed `ReplicaVaultReceived` event:

```ts
{
  type: "ReplicaVaultReceived",
  channel_id, from_replica_id, secret_id, version,
  vault: {
    helpers:  [...],   // every paired helper (channel_id, transport_uri, shared_key, ...)
    secrets:  [{ id, name, data }],
    replicas: [...],   // every paired destination (replica_id, sender_kind, ...)
    owner_replica_id,  // the Source's replica_id
  },
  shares: [{ channel_id, committed_share }, ...],  // helper channel_id → share bytes
}
```

`vault` + `shares` give the Destination everything it needs to act in the
Source's place during recovery.

End-to-end coverage lives in
[`runReplicaPairingAndVaultSyncFlow`](../../bindings/nodejs/protocol.ts).

---

## Correlation and routing

Two cross-cutting metadata fields appear on every channel-mode exchange:

- **`traceId`** — opaque `bigint` on the outer envelope, used to correlate
  responses with requests. The `DeRecProtocol` orchestrator handles this
  end-to-end (random token on every outbound request, echo on every
  response). Primitive-only callers can manipulate it directly via
  `envelope.apply_trace_id(bytes, traceId)` and `envelope.read_trace_id(bytes)`.
- **`replyTo`** — optional `TransportProtocol` on request bodies, telling
  the responder to route this exchange's response to an alternate endpoint.
  Set it per call (every `primitives.*.request.produce` takes a trailing
  `reply_to` arg) or protocol-wide with the `autoReplyTo` constructor flag
  on `DeRecProtocol` (stamps `replyTo = ownTransport` on every outbound
  request). Excludes pairing and `UpdateChannelInfo`, which already carry
  their own `transportProtocol` field.

The motivating case for `replyTo` is replicas: when Replica A sends a
request on a channel the helper paired with sibling Replica B, the
helper's stored peer endpoint points at B. `replyTo` lets A say "send the
response back to me," without rewriting channel state.

---

## Package Contents

```text
derec_library_bg.wasm
derec_library.js
derec_library.d.ts
index.js
index.d.ts
```

- `.wasm` — compiled Rust core
- `derec_library.js` / `derec_library.d.ts` — raw wasm-bindgen bindings
- `index.js` / `index.d.ts` — `primitives.*` namespace assembly and TypeScript declarations

---

## Security considerations

### Replica destinations inherit Source trust

`ReplicaVaultReceived.vault` carries the full secret container, which
embeds every helper's `channel_id` and `shared_key`. Anyone holding the
vault can therefore authenticate as the Source toward every helper.
This is intentional — it is what makes Destination-driven recovery
work — but it means a compromised Destination can impersonate the
Source against every helper paired at the time the vault was sent.
Pick Destinations with at least the trust level of the Source device
itself; do not treat them as opaque backups.

### `ContactMode.HashedKeys` requires an ephemeral transport URI

`HashedKeys` ships only a SHA-384 binding hash in the contact and
serves the actual public keys through a plaintext PrePair round-trip
on the contact creator's own transport. Any party that can reach that
URI before the legitimate scanner gets the keys. Use `HashedKeys` only
with a transport endpoint that is freshly minted for the pairing and
that you can retire as soon as the PrePair leg completes.
`ContactMode.InlineKeys` has no such constraint.

The recommended pattern is: pair on the ephemeral URI, then — as soon
as the pairing completes on the contact creator side — call
`setOwnTransport` with the permanent endpoint and start an
`UpdateChannelInfo` flow against the peer to announce the swap. Once
the peer acknowledges, retire the ephemeral URI. This keeps the
plaintext PrePair window tight while letting subsequent traffic ride
on the long-lived endpoint.

### Replica fingerprint verification is mandatory

Replica channels are created with `status: "Pending"` and remain there
until both sides call `verifyFingerprint` with the value the peer
derived from the shared key — confirmed out of band. The orchestrator
enforces this: `start(FlowKind.ProtectSecret, ...)` throws when a
target is still `Pending`. Treat verification as a required step in
the pairing UX — a scanner that auto-pairs without it accepts a
MITM-vulnerable replica.

### The `derec.*` namespace in `communicationInfo` is library-owned

`communicationInfo` is otherwise an opaque app-defined map, but every
key under the `derec.` prefix is reserved for the protocol. Today the
library owns `derec.replica_id`; future protocol additions will use
the same namespace. Application code must not write any `derec.*`
entry — the orchestrator silently overwrites or strips library-owned
keys at the protocol boundary, and app-set values are lost without
warning.

---

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
