# DeRec Web SDK

Browser WebAssembly bindings for `derec-library`, the Rust SDK for the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares to trusted helpers.

---

## Installation

```bash
npm install @derecalliance/derec-web
```

or with yarn:

```bash
yarn add @derecalliance/derec-web
```

---

## Requirements

- Modern browser with WebAssembly support
- ES module support
- TypeScript optional

No additional native dependencies are required.

---

## Design Overview

The Web SDK is a **thin binding layer** over the Rust implementation.

All of the following are handled internally in Rust:

- Protobuf serialization / deserialization
- Encryption / decryption
- DeRecMessage envelope construction
- Protocol validation

The JavaScript API operates exclusively on **opaque `Uint8Array` wire payloads**.

---

## Quick Example

```ts
import init, * as derec from "@derecalliance/derec-web";

async function main() {
  await init();

  const version = derec.derec_protocol_version();
  console.log(version.major, version.minor);
}

main();
```

---

## Example: Pairing Flow

```ts
import init, * as derec from "@derecalliance/derec-web";

async function main() {
  await init();

  // Step 1: Owner creates contact message
  const contact = derec.create_contact_message(
    1n,
    new TextEncoder().encode("wss://example.com")
  );

  // Step 2: Helper produces pairing request
  const request = derec.produce_pairing_request_message(
    2, // SenderKind.Helper
    new TextEncoder().encode("wss://helper.com"),
    contact.wire_bytes
  );

  // Step 3: Owner produces pairing response
  const response = derec.produce_pairing_response_message(
    0, // SenderKind.SharerNonRecovery
    request.wire_bytes,
    request.secret_key_material
  );

  // Step 4: Helper processes response
  const final = derec.process_pairing_response_message(
    contact.wire_bytes,
    response.wire_bytes,
    request.secret_key_material
  );

  console.log("Shared key length:", final.shared_key.length);
}

main();
```

---

## Example: Share Distribution

```ts
import init, * as derec from "@derecalliance/derec-web";

async function main() {
  await init();

  const result = derec.protect_secret(
    new Uint8Array([1,2,3]),
    new TextEncoder().encode("super-secret"),
    [1n, 2n, 3n],
    2,
    1
  );

  // Opaque wire bytes containing all share messages
  const shareMessages = result.share_message_wire_bytes_array;

  console.log(shareMessages);
}

main();
```

---

## Example: Recovery Flow

```ts
import init, * as derec from "@derecalliance/derec-web";

async function main() {
  await init();

  const request = derec.generate_share_request(
    new Uint8Array([1,2,3]),
    1
  );

  const response = derec.generate_share_response(
    request,
    new Uint8Array() // shareContent
  );

  const secret = derec.recover_from_share_responses(
    new Uint8Array(), // aggregated responses
    new Uint8Array([1,2,3]),
    1
  );

  console.log(secret);
}

main();
```

---

## Example: Verification Flow

```ts
import init, * as derec from "@derecalliance/derec-web";

async function main() {
  await init();

  const request = derec.generate_verification_request(
    new Uint8Array([1,2,3]),
    1
  );

  const response = derec.generate_verification_response(
    new Uint8Array(), // shareContent
    request
  );

  const isValid = derec.verify_share_response(
    new Uint8Array(), // shareContent
    request,
    response
  );

  console.log("Valid:", isValid);
}

main();
```

---

## Usage with Bundlers

Works with:

- Vite
- Webpack
- Rollup
- Next.js
- Parcel

Example:

```ts
import init from "@derecalliance/derec-web";

await init();
```

---

## Loading from CDN

```html
<script type="module">
import init from "https://cdn.jsdelivr.net/npm/@derecalliance/derec-web/+esm";

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

- `.wasm` – compiled Rust SDK
- `.js` – bindings
- `.d.ts` – TypeScript definitions

---

## Key Principles

- All protocol messages are opaque `Uint8Array`
- No protobuf types are exposed
- No cryptography is performed in JavaScript
- Rust is the single source of truth for protocol logic

---

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK repository: https://github.com/derecalliance/lib-derec

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.

