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

  const result = primitives.verification.request.produce(channelId, secretId, version, sharedKey);
  // result carries the encoded DeRecMessage envelope, ready to send over transport
}

main();
```

---

## Pairing Flow

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const contact = primitives.pairing.request.create_contact(
    1n,
    { protocol: "https", uri: "https://owner.example.com" }
  );

  const request = primitives.pairing.request.produce(
    2, // SenderKind.Helper
    { protocol: "https", uri: "https://helper.example.com" },
    contact.contact_message
  );

  const response = primitives.pairing.response.produce(
    0, // SenderKind.OwnerNonRecovery
    request.envelope,
    contact.secret_key_material
  );

  const result = primitives.pairing.response.process(
    request.initiator_contact_message,
    response.envelope,
    request.secret_key_material
  );

  console.log("Shared key length:", result.pairing_shared_key.length);
}

main();
```

---

## Share Distribution (Sharing Flow)

```ts
import init, { primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const splitResult = primitives.sharing.request.split(
    new Uint8Array([1, 2, 3]),                // secret ID
    new TextEncoder().encode("super-secret"), // secret bytes
    [1n, 2n, 3n],                             // helper channel IDs
    2,                                        // threshold
    1                                         // version
  );
  // splitResult.value: Map<bigint, Uint8Array> — one CommittedDeRecShare per helper

  // Wrap each share into an encrypted delivery envelope
  for (const [channelId, committedShare] of splitResult.value) {
    const envelope = primitives.sharing.request.produce(
      channelId, version, secretId, committedShare, [], "", sharedKeys.get(channelId)
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

  // Owner side: produce the recovery request
  const shareRequest = primitives.recovery.request.produce(
    1n,                        // channel ID
    new Uint8Array([1, 2, 3]), // secret ID
    1,                         // version
    sharedKey
  );

  // Helper side: produce the response
  const shareResponse = primitives.recovery.response.produce(
    new Uint8Array([1, 2, 3]), // secret ID
    1n,                        // channel ID
    storedShareEnvelope,
    shareRequest,
    sharedKey
  );

  // Owner side: aggregate responses and reconstruct the secret
  const recovered = primitives.recovery.response.recover(
    [{ response: shareResponse, shared_key: sharedKey }],
    new Uint8Array([1, 2, 3]),
    1
  );

  console.log(recovered);
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
