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

// Synthesize a "filled-in" contact and run the regular pairing flow.
const filledInContact: ContactMessage = {
  ...contact.contact_message,
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

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
