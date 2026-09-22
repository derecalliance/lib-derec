# DeRec Library

## Purpose

The DeRec library implements a **threshold-based secret recovery protocol** where:

- An **Owner** splits a secret into shares
- **Helpers** store shares
- A threshold of shares reconstructs the secret

Core flows:

- Pairing
- Sharing
- Verification
- Recovery

Reference: DeRec Protocol (see protocol.md)

---

## Core Design Principles

### 1. Transport-Agnostic

- Library operates on **raw bytes (`Vec<u8>`)** or Protobuf encoded messages
- No assumptions about transport (HTTP, WebSocket, email, etc.)
- All APIs produce/consume **wire-compatible protobuf messages** or DeRecEnvelop message
- Exception: the *recoverable secret* placed in `secretData` is `[version byte] · payload` (v1 = gzip-compressed JSON), not protobuf (its format is defined in the `protocol::types::secret` module docs); it is distinct from, and does not change, the protobuf transport messages above

---

### 2. Envelope Pattern

All messages follow are wrapped into a DeRecMessage

- Outer envelope: **plain**
- Inner message: **encrypted**

---

### 3. Cryptographic Model

- Pairing establishes:
  - `PairingSecretKeyMaterial`
  - `PairingSharedKey`
- After pairing:
  - All communication uses **shared symmetric encryption**

Security guarantees:

- Confidentiality
- Authenticity
- Replay protection via timestamps

---

## Critical Invariants

These must **always hold**:

### Envelope

- `envelope.timestamp == inner_message.timestamp`
- Reject otherwise

### Pairing

- Nonce must match contact message
- Public keys must be validated post-decryption

### Sharing

- Shares are versioned
- New version must be confirmed before deleting old

### Verification

- Response must prove possession of **exact share bytes**
- Hash includes:
  - share
  - challenge nonce

### Recovery

- All shares must:
  - Match same `root` (Merkle commitment)
  - Match same `ciphertext`
- Reject inconsistent sets

---

## Flow Overview

### 1. Pairing

create_contact_message()
→ produce_pairing_request_message()
→ produce_pairing_response_message()
→ process_pairing_response_message()

Output:

- `shared_key` (used for all future messages)

---

### 2. Sharing

- Secret encrypted (AES-GCM)
- Key split via Shamir Secret Sharing
- Each share includes:
  - (x, y)
  - ciphertext
  - Merkle root
  - Merkle proof

---

### 3. Verification

Challenge-response:

Owner → nonce  
Helper → hash(share || nonce)

Used to detect:

- Data corruption
- Helper inactivity

---

### 4. Recovery

Steps:

1. Pair in recovery mode
2. Request shares
3. Validate:
   - Merkle proofs
   - Root majority
4. Reconstruct key
5. Decrypt secret

---

## API Design Rules

### Inputs / Outputs

- Always use **raw bytes**
- Never expose protobuf structs in public API
- The recoverable secret (`secretData`) is `[major byte] · gzip(JSON)` (v1), not protobuf, defined in the `protocol::types::secret` module docs; other transport messages remain protobuf

### Determinism

- Same input → same output (except randomness where required)

### Idempotency

- All request/response flows must be safe to retry

---

## Error Handling

Use structured errors:

- `InvalidMessage`
- `InvariantViolation`
- `DecryptionFailed`
- `VerificationFailed`

Never panic on malformed input.

---

## Versioning

- Shares are versioned (`i32`)
- Always operate on **latest confirmed version**
- Old versions removed only after quorum confirmation

---

## SDKs

The library is developed in Rust but ported to other languages and frameworks using FFI ro WASM (NodeJS and Web)
The source of truth is always the Rust SDK

All specific components needed for package generation that are not rust are placed at ./packages
For each SDK ported, there must be the corresponding smoke test at ./bindings

---

## State Expectations (Library vs App)

### Library

- Stateless (preferred)
- Pure message processing

### Application Layer

Responsible for:

- Storage (shares, keys)
- Transport
- Retry logic
- Authentication (out of scope for protocol)

---

## Testing Requirements

Must cover:

- Full pairing roundtrip
- Timestamp invariant enforcement
- Share verification correctness
- Recovery with:
  - valid shares
  - corrupted shares
  - insufficient shares

---

## Non-Goals

- No transport implementation
- No persistent storage
- No user authentication
- No UI concerns

---

## Mental Model

Think of DeRec as:

A stateless cryptographic message processor implementing a client-server protocol over arbitrary transport, where correctness depends on strict invariant enforcement.

