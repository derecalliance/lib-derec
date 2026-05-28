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

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong channelId = 1;

// Step 1: Contact initiator creates the out-of-band ContactMessage.
var contact = Pairing.Request.CreateContact(
    channelId,
    new TransportProtocol("https://example.com/alice"));

// Step 2: Contact responder produces the pairing request envelope.
var pairRequest = Pairing.Request.Produce(
    Pairing.SenderKind.Helper,
    new TransportProtocol("https://example.com/helper"),
    contact.ContactMessage);

// Step 3: Initiator extracts the request, then accepts to derive the shared key.
var extractedRequest = Pairing.Request.Extract(pairRequest.Envelope, contact.SecretKeyMaterial);
var accepted = Pairing.Response.Accept(
    Pairing.SenderKind.Owner,
    extractedRequest.RequestProtoBytes,
    contact.SecretKeyMaterial);

// Step 4: Responder extracts the response, then derives the same shared key.
var extractedResponse = Pairing.Response.Extract(accepted.Envelope, pairRequest.SecretKeyMaterial);
var processed = Pairing.Response.Process(
    pairRequest.InitiatorContactMessage,
    extractedResponse.ResponseProtoBytes,
    pairRequest.SecretKeyMaterial);

// accepted.SharedKey  ==  processed.SharedKey
```

To reject instead of accept, call `Pairing.Response.Reject(kind, requestProtoBytes, statusEnum, memo)`.
A typed `DeRecException` (with `Code == DeRecCode.NonOkStatus`, plus `PeerStatus` / `PeerMemo`)
is thrown from `Process` when the peer rejected.

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
