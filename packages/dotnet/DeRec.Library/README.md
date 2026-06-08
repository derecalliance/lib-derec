# DeRec .NET SDK

.NET bindings for `derec-library`, the Rust SDK for the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares to trusted helpers.

---

## Installation

```bash
dotnet add package DeRec.Library
```

---

## Requirements

- .NET 6 or later

No additional native dependencies are required. The package includes the native DeRec library.

---

## Design Overview

The .NET SDK is a **thin interop layer** over the Rust implementation.

All of the following are handled internally in Rust:

- Protobuf serialization / deserialization
- Encryption / decryption
- DeRecMessage envelope construction
- Protocol validation

The .NET API operates on `byte[]` wire payloads and a small set of typed
result objects. Errors surface as [`DeRecException`](#error-handling).

---

## Quick Example

```csharp
using DeRec.Library;

var version = ProtocolVersion.Current();
Console.WriteLine($"DeRec {version.Major}.{version.Minor}");
```

---

## Example: Pairing Flow

The `ContactMessage` is exchanged out-of-band (QR codes, existing messaging
channels, etc.). Two `ContactMode` values select how the public encryption
material is delivered:

| Mode | What the contact carries | Use when |
|---|---|---|
| `ContactMode.InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry the keys (NFC, messaging). |
| `ContactMode.HashedKeys` | Only a SHA-384 commitment to the keys | Channel is size-constrained (QR codes). Scanner fetches the actual keys via a plaintext `PrePair` round-trip and verifies them against the hash. |

After the handshake completes, **both modes** rekey the channel id. The
responder derives `SHA-384(u64_be(originalId) || sharedKey)[..8]` as a
`ulong`, includes it in the encrypted `PairResponseMessage`, and both sides
switch their local state to the new id. The new id never appears in plaintext
on the wire, so a passive observer who only saw pre-rekey traffic cannot link
the long-running channel to its pairing-time id.

### `InlineKeys` flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong channelId = 1;

// Step 1: Contact initiator creates the out-of-band ContactMessage.
var contact = Pairing.Request.CreateContact(
    channelId,
    ContactMode.InlineKeys,
    new TransportProtocol("https://example.com/alice"));

// Step 2: Contact responder produces the pairing request envelope.
var pairRequest = Pairing.Request.Produce(
    Pairing.SenderKind.Helper,
    new TransportProtocol("https://example.com/helper"),
    contact.ContactMessage);

// Step 3: Initiator extracts the request, then produces the response and derives the shared key.
var extractedRequest = Pairing.Request.Extract(pairRequest.Envelope, contact.SecretKeyMaterial);
var produced = Pairing.Response.Produce(
    channelId,
    extractedRequest.RequestProtoBytes,
    contact.SecretKeyMaterial);

// Step 4: Responder extracts the response, then derives the same shared key.
var extractedResponse = Pairing.Response.Extract(produced.Envelope, pairRequest.SecretKeyMaterial);
var processed = Pairing.Response.Process(
    pairRequest.InitiatorContactMessage,
    extractedResponse.ResponseProtoBytes,
    pairRequest.SecretKeyMaterial);

// Both sides hold the same shared key and rekeyed channel id.
// produced.SharedKey  ==  processed.SharedKey
// produced.ChannelId  ==  processed.ChannelId  !=  channelId
//
// Rename local channel state from `channelId` to `produced.ChannelId`
// before sending any further traffic.
```

To reject a pairing request, build a `PairResponseMessage` with a non-OK
`StatusEnum` and encrypt it against `request.ecies_public_key` using the
pairing envelope primitives. The higher-level `DeRecProtocol` orchestrator's
`reject` method does this for you. A typed `DeRecException`
(`Code == DeRecCode.NonOkStatus`, plus `PeerStatus` / `PeerMemo`) is thrown
from `Process` when the peer rejected. Rejected responses do not carry a
meaningful `ChannelId` — the rekey only takes effect on `Ok` responses.

### `HashedKeys` flow (PrePair)

`HashedKeys` adds one plaintext round-trip before the regular `InlineKeys`
handshake. The scanner fetches the actual keys via `PrePair`, verifies them
against `contact.ContactBindingHash`, and then runs the normal pairing flow
on a synthesized contact with the keys filled in.

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong channelId = 7;

// Initiator: HASHED_KEYS contact (no inline keys, only the binding hash).
// Transport URI MUST be ephemeral — PrePair envelopes are plaintext.
var contact = Pairing.Request.CreateContact(
    channelId,
    ContactMode.HashedKeys,
    new TransportProtocol("https://relay.example.com/ephemeral"));

// Scanner: fetch keys via PrePair.
var prePairReqEnv = Pairing.Request.ProducePrePair(
    new TransportProtocol("https://scanner.example.com/ephemeral"),
    contact.ContactMessage);
var prePairReq = Pairing.Request.ExtractPrePair(prePairReqEnv.Envelope);
var prePairRespEnv = Pairing.Response.ProducePrePair(
    channelId, prePairReq.RequestProtoBytes, contact.SecretKeyMaterial);
var prePairResp = Pairing.Response.ExtractPrePair(prePairRespEnv.Envelope);

// Scanner validates the published keys against contact.ContactBindingHash.
// Throws DeRecException with Category=Pairing, Code=PrePairHashMismatch on
// mismatch (returns the keys + echoed nonce on match).
var validated = Pairing.Response.ProcessPrePair(
    contact.ContactMessage, prePairResp.ResponseProtoBytes);

// Synthesize a "filled-in" contact and run the regular pairing flow. The
// mode flip is required — `Pairing.Request.Produce` enforces `InlineKeys`
// and rejects a contact that still advertises `HashedKeys`.
var filledInContact = contact.ContactMessage with
{
    ContactMode = ContactMode.InlineKeys,
    MlkemEncapsulationKey = validated.MlkemEncapsulationKey,
    EciesPublicKey = validated.EciesPublicKey,
    ContactBindingHash = null,
};
// ... continue with Pairing.Request.Produce / Extract /
// Pairing.Response.Produce / Process against `filledInContact` exactly as
// in the InlineKeys example.
```

After the PrePair exchange the application **must** swap the transport
endpoint to a long-term one via `UpdateChannelInfo`. The ephemeral endpoint
advertised in the `HashedKeys` contact is intended to be retired immediately
after pairing.

Catch the security-relevant binding-hash mismatch with a typed code:

```csharp
try
{
    var validated = Pairing.Response.ProcessPrePair(
        contact.ContactMessage, prePairResp.ResponseProtoBytes);
}
catch (DeRecException e)
    when (e.Category == DeRecCategory.Pairing
       && e.Code == DeRecCode.PrePairHashMismatch)
{
    // The keys published by the peer do not match the commitment the
    // scanner originally accepted — surface to the user as a failed scan,
    // do NOT proceed to a regular PairRequest.
}
```

The .NET package is intentionally scoped to the primitive layer — the
`DeRecProtocol` orchestrator is not surfaced here. End-to-end primitive-level
coverage (including the tampered-hash assertion) lives at
`bindings/dotnet/Program.cs::RunPairingFlowHashedKeysTest`.

---

## Example: Share Distribution

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong secretId = 42;
byte[] secretData = System.Text.Encoding.UTF8.GetBytes("super-secret");
ulong[] channelIds = { 1, 2, 3 };
ulong threshold = 2;  // must satisfy 2 <= threshold <= channelIds.Length
uint version = 1;

var splitResult = Sharing.Request.Split(secretId, secretData, channelIds, threshold, version);

// channel ID → committed share bytes
var shares = splitResult.DeserializeShares();

// Wrap each share into an encrypted delivery envelope.
foreach (var (channelId, committedShare) in shares)
{
    var envelope = Sharing.Request.Produce(
        channelId,
        version,
        secretId,
        committedShare,
        keepList: Array.Empty<uint>(),
        description: string.Empty,
        sharedKey: sharedKeys[channelId]);

    // Send envelope.Envelope over your transport. The helper extracts and
    // produces an acknowledgement; the owner extracts and processes it.
}
```

---

## Example: Verification Flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong channelId = 1;
ulong secretId = 42;
uint version = 1;
// sharedKey: 32 bytes established during pairing.
// storedShare: byte[] of the inner StoreShareRequestMessage the helper persisted.

// Owner side: produce the verification request.
DeRecMessage requestEnvelope =
    Verification.Request.Produce(channelId, secretId, version, sharedKey);

// Helper side: extract and produce the proof response.
var req = Verification.Request.Extract(requestEnvelope, sharedKey);
DeRecMessage responseEnvelope = Verification.Response.Produce(
    channelId,
    req.RequestProtoBytes,
    sharedKey,
    shareContent: storedShare);

// Owner side: extract and verify the SHA-384 proof.
var resp = Verification.Response.Extract(responseEnvelope, sharedKey);
bool isValid = Verification.Response.Process(resp.ResponseProtoBytes, storedShare);
```

`Process` returns `true` only when the proof matches the given share content.
A peer-side non-OK status surfaces as a `DeRecException`.

---

## Example: Recovery Flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong secretId = 42;
uint version = 1;

// Owner side: produce one GetShareRequest per paired helper channel.
DeRecMessage shareRequest = Recovery.Request.Produce(channelId, secretId, version, sharedKey);

// Helper side: extract, then produce the response using the StoreShareRequest
// proto bytes the helper persisted at sharing time (see `extract_store_share_request`).
var helperReq = Recovery.Request.Extract(shareRequest, sharedKey);
DeRecMessage shareResponse = Recovery.Response.Produce(
    channelId,
    helperReq.RequestProtoBytes,
    storedShareProtoBytes,
    sharedKey);

// Owner side: extract each response, then reconstruct the secret from a
// threshold-sized set.
var helperResp = Recovery.Response.Extract(shareResponse, sharedKey);
byte[] recovered = Recovery.Response.Recover(
    new[] { helperResp.ResponseProtoBytes, /* …more helpers… */ },
    secretId,
    version);
```

---

## Error Handling

All primitive methods throw `DeRecException` on failure. The exception carries
the typed FFI error envelope:

```csharp
try
{
    Pairing.Response.Process(contactMessage, responseProtoBytes, secretKeyMaterial);
}
catch (DeRecException ex) when (ex.Code == DeRecCode.NonOkStatus)
{
    // Peer rejected the pairing; details are on the exception.
    Console.WriteLine($"peer status={ex.PeerStatus}  memo={ex.PeerMemo}");
}
catch (DeRecException ex) when (ex.Code == DeRecCode.VersionMismatch)
{
    Console.WriteLine($"version mismatch: expected={ex.Expected}  got={ex.Got}");
}
```

`DeRecCategory` identifies the protocol phase (`Pairing`, `Sharing`, …);
`DeRecCode` identifies the specific reason (`NonOkStatus`, `VersionMismatch`,
`Invariant`, `ProtobufDecode`, …). Both are global — the same value means the
same thing across categories.

---

## Key Principles

- Protocol messages cross the boundary as opaque `byte[]` / `DeRecMessage`
- No protobuf types are exposed in .NET
- No cryptography is performed in .NET
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
