# DeRec Web SDK

Browser WebAssembly bindings for `derec-library`, the Rust SDK implementing the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares across trusted helpers.

---

## Installation

```bash
npm install @derec-alliance/web
```

or with yarn:

```bash
yarn add @derec-alliance/web
```

---

## Requirements

- Modern browser with WebAssembly support
- ES module support
- TypeScript (optional)

No native dependencies are required.

---

## Design Overview

The Web SDK is a **thin binding layer** over the Rust implementation.

All core logic is executed in Rust:

- Protobuf serialization / deserialization
- Cryptography (pairing, encryption, verification)
- DeRecMessage envelope construction
- Protocol validation

The JavaScript API operates exclusively on:

```ts
Uint8Array
```

These represent **opaque wire-level protocol messages**.

---

## Initialization

```ts
import init from "@derec-alliance/web";

await init();
```

---

## Quick Example

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const channelId = 1n;            // u64 → bigint
  const secretId = 42n;            // u64 → bigint
  const version = 1;               // u32 → number
  const sharedKey = new Uint8Array(32); // established during pairing

  const result = primitives.verification.request.produce(channelId, secretId, version, sharedKey);
  // result carries the encoded DeRecMessage envelope, ready to send over transport.
}

main();
```

---

## Pairing Flow

```ts
import init, { primitives, SenderKind } from "@derec-alliance/web";

async function main() {
  await init();

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

  // Step 3: Initiator produces the response and derives the initiator-side shared key.
  const produced = primitives.pairing.response.produce(
    SenderKind.Owner,
    request.envelope,
    contact.secret_key_material,
  );

  // Step 4: Responder processes the response and derives its own shared key.
  const processed = primitives.pairing.response.process(
    request.initiator_contact_message,
    produced.envelope,
    request.secret_key_material,
  );

  // Both sides hold the same key now.
  // produced.pairing_shared_key  ==  processed.pairing_shared_key
}

main();
```

To reject the request, build a `PairResponseMessage` with a non-OK status and
encrypt it against `request.ecies_public_key` using the WASM-exposed pairing
envelope helpers. The higher-level `DeRecProtocol` orchestrator's `reject`
method does this for you.

---

## Share Distribution (Sharing Flow)

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const secretId = 42n;             // u64
  const secretData = new TextEncoder().encode("super-secret");
  const channelIds = [1n, 2n, 3n];
  const threshold = 2;              // must be 2 <= threshold <= channelIds.length
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
}

main();
```

---

## Recovery Flow

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const secretId = 42n;         // u64
  const version = 1;            // u32

  // Owner side: produce the recovery request.
  const shareRequest = primitives.recovery.request.produce(
    1n,                         // channel ID
    secretId,
    version,
    sharedKey,
  );

  // Helper side: produce the response using the StoreShareRequest it persisted
  // at sharing time.
  const shareResponse = primitives.recovery.response.produce(
    secretId,
    1n,                         // channel ID
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
}

main();
```

---

## Verification Flow

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

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
}

main();
```

---

## Usage with Bundlers

Compatible with:

- Vite
- Webpack
- Rollup
- Next.js
- Parcel

```ts
import init from "@derec-alliance/web";

await init();
```

---

## CDN Usage

```html
<script type="module">
  import init from "https://cdn.jsdelivr.net/npm/@derec-alliance/web/+esm";

  await init();
</script>
```

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

## Key Principles

- All protocol messages are opaque `Uint8Array`
- No protobuf types are exposed
- No cryptographic operations occur in JavaScript
- Rust is the single source of truth

---

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
