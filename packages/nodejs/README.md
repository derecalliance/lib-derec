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

```ts
import { primitives, SenderKind } from "@derec-alliance/nodejs";

// Step 1: Initiator creates contact message (sent out-of-band).
const contact = primitives.pairing.request.create_contact(
  1n,
  { protocol: "https", uri: "https://owner.example.com" },
);

// Step 2: Responder produces a pairing request from the contact.
const request = primitives.pairing.request.produce(
  SenderKind.Helper,
  { protocol: "https", uri: "https://helper.example.com" },
  contact.contact_message,
);

// Step 3: Initiator accepts the request and derives the initiator-side shared key.
const accepted = primitives.pairing.response.accept(
  SenderKind.Owner,
  request.envelope,
  contact.secret_key_material,
);

// Step 4: Responder processes the response and derives the responder-side shared key.
const processed = primitives.pairing.response.process(
  request.initiator_contact_message,
  accepted.envelope,
  request.secret_key_material,
);

// Both sides hold the same key.
// accepted.pairing_shared_key  ==  processed.pairing_shared_key
```

Use `primitives.pairing.response.reject(kind, request_envelope, status, memo, communication_info)`
instead of `accept` to reply with a non-OK status. The trailing `communication_info` argument
may be `null`.

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
