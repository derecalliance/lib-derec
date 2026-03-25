# DeRec NodeJS SDK

Node.js bindings for `derec-library`, the Rust SDK for the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares to trusted helpers.

---

## Installation

```bash
npm install @derecalliance/derec-nodejs
```

or with yarn:

```bash
yarn add @derecalliance/derec-nodejs
```

---

## Requirements

- Node.js 18+
- TypeScript optional

No additional native dependencies are required.

---

## Design Overview

The NodeJS SDK is a **thin binding layer** over the Rust implementation.

All of the following are handled internally in Rust:

- Protobuf serialization / deserialization
- Encryption / decryption
- DeRecMessage envelope construction
- Protocol validation

The JavaScript/TypeScript API operates exclusively on **opaque `Uint8Array` wire payloads**.

---

## Quick Example

```ts
import * as derec from "@derecalliance/derec-nodejs";

const version = derec.derec_protocol_version();

console.log(version.major, version.minor);
```

---

## Example: Pairing Flow

```ts
import * as derec from "@derecalliance/derec-nodejs";

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
```

---

## Example: Share Distribution

```ts
import * as derec from "@derecalliance/derec-nodejs";

const result = derec.protect_secret(
  new Uint8Array([1,2,3]),
  new TextEncoder().encode("super-secret"),
  [1n, 2n, 3n],
  2,
  1
);

// Opaque wire bytes containing all share messages
const shareMessages = result.share_message_wire_bytes_array;
```

---

## Example: Recovery Flow

```ts
import * as derec from "@derecalliance/derec-nodejs";

// Request a share
const request = derec.generate_share_request(
  new Uint8Array([1,2,3]),
  1
);

// Helper responds with share content
const response = derec.generate_share_response(
  request,
  /* shareContent */ new Uint8Array()
);

// Owner aggregates responses and recovers secret
const secret = derec.recover_from_share_responses(
  /* aggregated responses */ new Uint8Array(),
  new Uint8Array([1,2,3]),
  1
);
```

---

## Example: Verification Flow

```ts
import * as derec from "@derecalliance/derec-nodejs";

// Owner generates verification request
const request = derec.generate_verification_request(
  new Uint8Array([1,2,3]),
  1
);

// Helper produces response
const response = derec.generate_verification_response(
  /* shareContent */ new Uint8Array(),
  request
);

// Owner verifies response
const isValid = derec.verify_share_response(
  /* shareContent */ new Uint8Array(),
  request,
  response
);

console.log("Valid:", isValid);
```

---

## Key Principles

- All protocol messages are opaque `Uint8Array`
- No protobuf types are exposed
- No cryptography is performed in JavaScript
- Rust is the single source of truth for protocol logic

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

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK repository: https://github.com/derecalliance/lib-derec

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.
