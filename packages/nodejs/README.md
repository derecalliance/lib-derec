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
import * as derec from "@derec-alliance/nodejs";

const version = derec.derec_protocol_version();

console.log(version.major, version.minor);
```

---

## Pairing Flow

```ts
import * as derec from "@derec-alliance/nodejs";

// Step 1: Owner creates contact message (out-of-band)
const contact = derec.create_contact_message(
  1n,
  { protocol: "https", uri: "https://owner.example.com" }
);

// Step 2: Helper produces pairing request
const request = derec.produce_pairing_request_message(
  2, // SenderKind.Helper
  { protocol: "https", uri: "https://helper.example.com" },
  contact.wire_bytes
);

// Step 3: Owner produces pairing response
const response = derec.produce_pairing_response_message(
  0, // SenderKind.SharerNonRecovery
  request.wire_bytes,
  request.secret_key_material
);

// Step 4: Helper processes response and derives shared key
const result = derec.process_pairing_response_message(
  contact.wire_bytes,
  response.wire_bytes,
  request.secret_key_material
);

console.log("Shared key length:", result.shared_key.length);
```

---

## Share Distribution (Sharing Flow)

```ts
import * as derec from "@derec-alliance/nodejs";

const result = derec.protect_secret(
  new Uint8Array([1, 2, 3]),                // secret ID
  new TextEncoder().encode("super-secret"), // secret bytes
  [1n, 2n, 3n],                             // helper channel IDs
  2,                                        // threshold
  1                                         // version
);

const shareMessages = result.share_message_wire_bytes_array;

console.log(shareMessages);
```

---

## Recovery Flow

```ts
import * as derec from "@derec-alliance/nodejs";

// Owner requests shares from helpers
const request = derec.generate_share_request(
  new Uint8Array([1, 2, 3]), // secret ID
  1                          // version
);

// Helper responds with its share
const response = derec.generate_share_response(
  request,
  new Uint8Array() // share content
);

// Owner reconstructs secret from aggregated responses
const secret = derec.recover_from_share_responses(
  new Uint8Array(), // aggregated responses
  new Uint8Array([1, 2, 3]),
  1
);

console.log(secret);
```

---

## Verification Flow

```ts
import * as derec from "@derec-alliance/nodejs";

// Owner challenges helper
const request = derec.generate_verification_request(
  new Uint8Array([1, 2, 3]),
  1
);

// Helper proves it still holds the share
const response = derec.generate_verification_response(
  new Uint8Array(), // share content
  request
);

const isValid = derec.verify_share_response(
  new Uint8Array(), // share content
  request,
  response
);

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
```

- `.wasm` — compiled Rust core
- `.js` — bindings
- `.d.ts` — TypeScript definitions

---

## Documentation

- DeRec Alliance: https://derecalliance.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
