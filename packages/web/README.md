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
import init, * as derec from "@derec-alliance/web";

async function main() {
  await init();

  const version = derec.derec_protocol_version();

  console.log(version.major, version.minor);
}

main();
```

---

## Pairing Flow

```ts
import init, * as derec from "@derec-alliance/web";

async function main() {
  await init();

  const contact = derec.create_contact_message(
    1n,
    { protocol: "https", uri: "https://owner.example.com" }
  );

  const request = derec.produce_pairing_request_message(
    2,
    { protocol: "https", uri: "https://helper.example.com" },
    contact.wire_bytes
  );

  const response = derec.produce_pairing_response_message(
    0,
    request.wire_bytes,
    contact.secret_key_material
  );

  const result = derec.process_pairing_response_message(
    request.initiator_contact_message,
    response.wire_bytes,
    request.secret_key_material
  );

  console.log("Shared key length:", result.shared_key.length);
}

main();
```

---

## Share Distribution (Sharing Flow)

```ts
import init, * as derec from "@derec-alliance/web";

async function main() {
  await init();

  const result = derec.protect_secret(
    new Uint8Array([1, 2, 3]),
    new TextEncoder().encode("super-secret"),
    [1n, 2n, 3n],
    2,
    1
  );

  const shareMessages = result.share_message_wire_bytes_array;

  console.log(shareMessages);
}

main();
```

---

## Recovery Flow

```ts
import init, * as derec from "@derec-alliance/web";

async function main() {
  await init();

  const request = derec.generate_share_request(
    new Uint8Array([1, 2, 3]),
    1
  );

  const response = derec.generate_share_response(
    request,
    new Uint8Array()
  );

  const secret = derec.recover_from_share_responses(
    new Uint8Array(),
    new Uint8Array([1, 2, 3]),
    1
  );

  console.log(secret);
}

main();
```

---

## Verification Flow

```ts
import init, * as derec from "@derec-alliance/web";

async function main() {
  await init();

  const request = derec.generate_verification_request(
    new Uint8Array([1, 2, 3]),
    1
  );

  const response = derec.generate_verification_response(
    new Uint8Array(),
    request
  );

  const isValid = derec.verify_share_response(
    new Uint8Array(),
    request,
    response
  );

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
```

- `.wasm` — compiled Rust core
- `.js` — WASM bindings
- `.d.ts` — TypeScript definitions

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
