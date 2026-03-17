# DeRec Rust SDK

![Crates.io](https://img.shields.io/crates/v/derec-library)
![Docs.rs](https://docs.rs/derec-library/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

Rust implementation of the **DeRec protocol**, providing tools to securely distribute, store, verify, and recover secret shares across trusted helpers.

This crate implements the protocol defined by the **DeRec Alliance** and provides APIs for building applications that support decentralized secret recovery.

Typical applications include:

- Cryptocurrency wallets
- Digital identity systems
- Secure backup systems
- Key management infrastructure

The library supports both **native Rust environments** and **WebAssembly targets**, enabling use in backend services, mobile apps, and browser-based applications.

---

## What is DeRec?

The **DeRec protocol** allows a secret to be split into multiple shares and stored by independent helpers.

When recovery is required, a sufficient number of helpers can provide their shares to reconstruct the original secret.

Key properties:

- **Threshold secret sharing**
- **Helper-based recovery**
- **Verifiable share storage**
- **Transport-agnostic protocol**

This SDK implements the message flows and cryptographic mechanisms required by the protocol.

---

## Installation

Add the crate to your project via `cargo`:

```bash
cargo add derec-library
```

Or manually in your `Cargo.toml`

```toml
[dependencies]
derec-library = "0.0.1-alpha.1"
```

> [!WARNING]
> Note: this is a pre-release version. APIs may change until 0.1.0.

## Basic Concepts

The protocol involves two primary roles: **Owner** and **Helper**.

### Owner

The party that wants to protect a secret.

Responsibilities:
* Split the secret into shares
* Distribute shares to helpers
* Verify helpers still possess the shares
* Recover the secret when necessary

### Helper

A trusted entity that stores a share for the Owner.

Responsibilities:
* Store the share
* Respond to verification challenges
* Provide shares during recovery

---

## Protocol Flows

The SDK provides building blocks for the main protocol flows.

| Flow | Purpose |
|------|--------|
| Pairing | Establish secure communication between owner and helper |
| Share Distribution | Split and distribute secret shares |
| Verification | Ensure helpers still possess shares |
| Recovery | Retrieve shares and reconstruct the secret |
| Unpairing | Terminate the helper relationship |


## Quick Intro

```rust
use derec_library::verification::*;
use derec_library::types::ChannelId;

let channel_id = ChannelId(42);
let secret_id = b"example_secret";

let request = generate_verification_request(secret_id, 1).unwrap();
```

See the examples down below for complete protocol flows.

---

## WebAssembly Support

The library also provides WebAssembly bindings so the protocol can run in:
* Browsers
* Mobile wallets
* Web applications

Example JavaScript usage:

```ts
import * as derec from "derec-library";

const request = derec.generate_verification_request(secretId, version);
```

Bindings are generated using `wasm-bindgen`.

---

## Transport Layer

The DeRec protocol is transport agnostic.

Applications may use any communication channel including:

* HTTPS
* WebSockets
* Message queues
* Custom relay servers

> [!INFO]
> Currently, only the HTTPS transport protocol is supported.

The `transportUri` in protocol messages identifies the helper endpoint.

---

## Examples

### DeRecMessage Envelope

All DeRec protocol messages except `ContactMessage` must be wrapped in a `DeRecMessage`
before being signed, encrypted, and transmitted through the wire.

The example below shows the full lifecycle using:

* the pairing flow to produce a `PairRequestMessage`
* `DeRecMessageBuilder` to wrap it into a `DeRecMessage`
* `DeRecMessageCodec` to encode and decode the wire payload
* **dummy** signing and encryption backends for demonstration purposes

> [!WARNING]
> The signing and encryption implementations below are intentionally fake and **not secure**.
> They exist only to demonstrate how to use `DeRecMessageBuilder` and `DeRecMessageCodec`.

```rust,ignore
use derec_library::derec_message::{
    DeRecMessageBuilder,
    DeRecMessageCodec,
    DeRecMessageCodecError,
    DeRecMessageDecrypter,
    DeRecMessageEncrypter,
    DeRecMessageSigner,
    DeRecMessageVerifier,
    VerifiedPayload,
};
use derec_library::pairing::*;
use derec_library::types::ChannelId;
use derec_proto::SenderKind;

#[derive(Clone)]
struct DummySigner {
    sender_key_hash: Vec<u8>,
}

impl DeRecMessageSigner for DummySigner {
    fn sender_key_hash(&self) -> &[u8] {
        &self.sender_key_hash
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        // Fake "signature": just prefix a marker
        let mut out = b"SIGNED:".to_vec();
        out.extend_from_slice(payload);
        Ok(out)
    }
}

#[derive(Clone)]
struct DummyVerifier {
    sender_key_hash: Vec<u8>,
}

impl DeRecMessageVerifier for DummyVerifier {
    fn verify(&self, signed_payload: &[u8]) -> Result<VerifiedPayload, DeRecMessageCodecError> {
        let prefix = b"SIGNED:";
        let payload = signed_payload
            .strip_prefix(prefix)
            .ok_or_else(|| DeRecMessageCodecError::Verification("missing SIGNED prefix".into()))?;

        Ok(VerifiedPayload {
            payload: payload.to_vec(),
            signer_key_hash: self.sender_key_hash.clone(),
        })
    }
}

#[derive(Clone)]
struct DummyEncrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
}

impl DeRecMessageEncrypter for DummyEncrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn encrypt(&self, signed_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        // Fake "encryption": just prefix a marker
        let mut out = b"ENCRYPTED:".to_vec();
        out.extend_from_slice(signed_payload);
        Ok(out)
    }
}

#[derive(Clone)]
struct DummyDecrypter {
    recipient_key_id: i32,
    recipient_key_hash: Vec<u8>,
}

impl DeRecMessageDecrypter for DummyDecrypter {
    fn recipient_key_id(&self) -> i32 {
        self.recipient_key_id
    }

    fn recipient_key_hash(&self) -> &[u8] {
        &self.recipient_key_hash
    }

    fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
        let prefix = b"ENCRYPTED:";
        let payload = encrypted_payload
            .strip_prefix(prefix)
            .ok_or_else(|| DeRecMessageCodecError::Decryption("missing ENCRYPTED prefix".into()))?;

        Ok(payload.to_vec())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel_id = ChannelId(42);
    let kind = SenderKind::Helper;

    // In a real implementation these are SHA-384 hashes of the sender's and
    // receiver's public keys.
    let sender_key_hash = vec![0x11; 48];
    let receiver_key_hash = vec![0x22; 48];

    let signer = DummySigner {
        sender_key_hash: sender_key_hash.clone(),
    };

    let verifier = DummyVerifier {
        sender_key_hash: sender_key_hash.clone(),
    };

    let encrypter = DummyEncrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_key_hash.clone(),
    };

    let decrypter = DummyDecrypter {
        recipient_key_id: 7,
        recipient_key_hash: receiver_key_hash.clone(),
    };

    // This would normally come from QR decoding.
    let CreateContactMessageResult {
        contact_message,
        secret_key: _contactor_secret_key,
    } = create_contact_message(
        channel_id,
        "https://relay.example/derec",
    )?;

    // Produce an Owner-side flow message.
    let ProducePairingRequestMessageResult {
        pair_request_message,
        secret_key: _requestor_secret_key,
    } = produce_pairing_request_message(
        channel_id,
        kind,
        &contact_message,
    )?;

    // Wrap the flow message in a DeRecMessage envelope.
    let derec_message = DeRecMessageBuilder::new()
        .sender(sender_key_hash.clone())
        .receiver(receiver_key_hash.clone())
        .secret_id([1, 2, 3, 4])?
        .message(pair_request_message)?
        .build()?;

    // Encode into wire bytes:
    //   1. serialize protobuf
    //   2. sign
    //   3. encrypt
    //   4. prefix recipient key id
    let wire_bytes = DeRecMessageCodec::encode_to_bytes(
        &derec_message,
        &signer,
        &encrypter,
    )?;

    // Decode from wire bytes:
    //   1. parse recipient key id
    //   2. decrypt
    //   3. verify signature
    //   4. decode protobuf
    let decoded = DeRecMessageCodec::decode_from_bytes(
        &wire_bytes,
        &decrypter,
        &verifier,
    )?;

    assert_eq!(decoded.protocol_version_major, derec_message.protocol_version_major);
    assert_eq!(decoded.protocol_version_minor, derec_message.protocol_version_minor);
    assert_eq!(decoded.sender, derec_message.sender);
    assert_eq!(decoded.receiver, derec_message.receiver);
    assert_eq!(decoded.secret_id, derec_message.secret_id);

    println!("Successfully encoded and decoded a DeRecMessage envelope");

    Ok(())
}
```

### Pairing Flow

```rust
use derec_library::pairing::*;
use derec_library::types::ChannelId;

// Alternatively:
// let channel_id: ChannelId = 42.into();
let channel_id = ChannelId(42);
let transport_uri = "https://example-helper.com/derec";

let kind = derec_library::protos::derec_proto::SenderKind::Helper;

// This would normally come from QR decoding.
let CreateContactMessageResult {
    contact_message,
    secret_key: contactor_secret_key,
} = create_contact_message(
    channel_id,
    "https://relay.example/derec",
).expect("Failed to create contact message");

// Responder produces pairing request.
let ProducePairingRequestMessageResult {
    pair_request_message,
    secret_key: requestor_secret_key,
} = produce_pairing_request_message(
    channel_id,
    kind,
    &contact_message,
).expect("Failed to produce pairing request message");

// Initiator finalizes pairing.
let ProducePairingResponseMessageResult {
    pair_response_message,
    shared_key,
} = produce_pairing_response_message(
    kind,
    &pair_request_message,
    &contactor_secret_key,
).expect("Failed to produce pairing response message");

let ProcessPairingResponseMessageResult { shared_key } = process_pairing_response_message(
    &contact_message,
    &pair_response_message,
    &requestor_secret_key,
).expect("Failed to process pairing response message");
```

The `ContactMessage` is exchanged out-of-band, typically using:

* QR codes
* Existing communication channels

---

### Sharing Flow

```rust
use derec_library::sharing::*;
use derec_library::types::ChannelId;

let secret_id = b"my_secret";
let secret_data = b"super_secret_value";
let channels: Vec<ChannelId> = [1, 2, 3].into_iter().map(ChannelId::from).collect();
let threshold = 2;
let version = 1;

let ProtectSecretResult { shares } = protect_secret(
    secret_id,
    secret_data,
    &channels,
    threshold,
    version,
    None,
    None,
).expect("sharing failed");

assert_eq!(shares.len(), 3);
```

---

### Verification Flow

```rust
use derec_library::verification::*;
use derec_library::types::ChannelId;

let channel_id = ChannelId(42);
let secret_id = "secret_id";
let version = 7;
let request = generate_verification_request(secret_id, version)
    .expect("failed to build verification request");

let share_content = b"example_share";

let response = generate_verification_response(secret_id, channel_id, share_content, &request)
    .expect("failed to generate verification response");

let ok = verify_share_response(secret_id, channel_id, share_content, &response)
    .expect("failed to verify response");

assert!(ok);
```

---

### Recovery Flow

```rust
use derec_library::recovery::*;
use derec_library::protos::derec_proto::StoreShareRequestMessage;
use derec_library::types::ChannelId;

let channel_id = ChannelId(42);
let secret_id = b"secret_id";
let version = 1;
let request = generate_share_request(channel_id, secret_id, version).unwrap();

// In a real helper, this comes from secure storage.
let stored = StoreShareRequestMessage { share: vec![1, 2, 3], ..Default::default() };

let resp = generate_share_response(channel_id, secret_id, &request, &stored)
    .expect("failed to build response");

// Responses should contain at least t responses
let responses = vec![resp];

let _ = recover_from_share_responses(&responses, secret_id, version).unwrap_err();
```

---

## Protocol specification

Full protocol documentation:

https://derec-alliance.gitbook.io/docs/protocol-specification/messages

---

## Security Considerations

Applications using this SDK should ensure:
* Secure storage of secret material
* Proper authentication of helpers
* Safe transport channels
* Protection against replay attacks

The DeRec protocol design assumes helpers are independent and trusted entities.

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
