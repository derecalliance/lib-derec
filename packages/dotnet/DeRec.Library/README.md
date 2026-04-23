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

The .NET API operates exclusively on **opaque `byte[]` wire payloads**.

---

## Quick Example

```csharp
using DeRec.Library;

var version = ProtocolVersion.Current();

Console.WriteLine(version.Major);
Console.WriteLine(version.Minor);
```

---

## Example: Pairing Flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

// Step 1: Owner creates contact message
var contact = Pairing.Request.CreateContact(
    channelId: 1,
    transportProtocol: new TransportProtocol("https://example.com")
);

// Step 2: Helper produces pairing request
var request = Pairing.Request.Produce(
    kind: Pairing.SenderKind.Helper,
    transportProtocol: new TransportProtocol("https://helper.com"),
    contactMessage: contact.ContactMessage
);

// Step 3: Owner produces pairing response
var response = Pairing.Response.Produce(
    kind: Pairing.SenderKind.OwnerNonRecovery,
    pairRequest: request.Envelope,
    pairingSecretKeyMaterial: contact.SecretKeyMaterial
);

// Step 4: Helper processes response
var final = Pairing.Response.Process(
    contactMessage: request.InitiatorContactMessage,
    pairResponse: response.Envelope,
    pairingSecretKeyMaterial: request.SecretKeyMaterial
);

Console.WriteLine($"Shared key length: {final.SharedKey.Length}");
```

---

## Example: Share Distribution

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

var splitResult = Sharing.Request.Split(
    secretId: new byte[] {1,2,3},
    secretData: System.Text.Encoding.UTF8.GetBytes("super-secret"),
    channelIds: new ulong[] {1,2,3},
    threshold: 2,
    version: 1
);

// Unpack into a channel ID → committed share map
var shares = splitResult.DeserializeShares();

// Wrap each share into an encrypted delivery envelope
foreach (var (channelId, committedShare) in shares)
{
    var envelope = Sharing.Request.Produce(
        channelId: channelId,
        version: 1,
        secretId: new byte[] {1,2,3},
        committedShare: committedShare,
        keepList: Array.Empty<int>(),
        description: string.Empty,
        sharedKey: sharedKeys[channelId]
    );
}
```

---

## Example: Recovery Flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

// Owner side: produce the recovery request
DeRecMessage shareRequest = Recovery.Request.Produce(
    channelId: 1,
    secretId: new byte[] {1,2,3},
    version: 1,
    sharedKey: sharedKey
);

// Helper side: produce the response
DeRecMessage shareResponse = Recovery.Response.Produce(
    channelId: 1,
    secretId: new byte[] {1,2,3},
    request: shareRequest,
    storedShareRequest: storedShareRequest,
    sharedKey: sharedKey
);

// Owner side: aggregate responses and reconstruct the secret
byte[] secret = Recovery.Response.Recover(
    responses: new[]
    {
        new Recovery.Response.RecoveryInput { Envelope = shareResponse, SharedKey = sharedKey },
    },
    secretId: new byte[] {1,2,3},
    version: 1
);
```

---

## Example: Verification Flow

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

// Owner side: produce the verification request.
DeRecMessage requestEnvelope = Verification.Request.Produce(
    channelId: 1,
    secretId: new byte[] {1,2,3},
    version: 1,
    sharedKey: sharedKey
);

// Helper side: decrypt and extract the challenge fields.
var req = Verification.Request.Extract(
    request: requestEnvelope,
    sharedKey: sharedKey
);
// req.ChannelId, req.SecretId, req.Version, req.Nonce

// Helper side: produce the response.
DeRecMessage responseEnvelope = Verification.Response.Produce(
    channelId: req.ChannelId,
    secretId: req.SecretId,
    version: req.Version,
    nonce: req.Nonce,
    sharedKey: sharedKey,
    storedRequest: storedShareRequest
);

// Owner side: verify the response.
bool isValid = Verification.Response.Process(
    response: responseEnvelope,
    sharedKey: sharedKey,
    storedRequest: storedShareRequest
);

Console.WriteLine($"Valid: {isValid}");
```

---

## Example: Replica Confirmation Flow

After pairing with `SenderKind.Replica`, both sides must confirm the channel by comparing fingerprints out-of-band.

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

// Initiator side: produce the confirmation request
var request = ReplicaConfirmation.Request.Produce(
    channelId: 1,
    sharedKey: sharedKey,
    replicaId: 42
);
// request.Envelope  — the encrypted message to send
// request.Fingerprint — display this to the user for comparison

// Receiver side: extract and verify the request
var extracted = ReplicaConfirmation.Request.Extract(
    request: request.Envelope,
    sharedKey: sharedKey
);
// extracted.ReplicaId — the replica identifier
// extracted.Fingerprint — display this to the user; must match the initiator's

// Receiver side: send confirmation response after user approval
DeRecMessage response = ReplicaConfirmation.Response.Produce(
    channelId: 1,
    sharedKey: sharedKey,
    replicaId: extracted.ReplicaId
);

// Initiator side: process the confirmation response
var result = ReplicaConfirmation.Response.Process(
    response: response,
    sharedKey: sharedKey
);
// result.ReplicaId — confirmed replica identifier
```

---

## Example: Channels Discovery Flow

After replica confirmation, the Replica can request the Owner's Helper channels in paginated batches.

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

// Replica side: request channels starting from batch 0
DeRecMessage request = ChannelsDiscovery.Request.Produce(
    channelId: 1,
    sharedKey: sharedKey,
    lastBatchIndex: 0
);

// Owner side: extract the request
var extracted = ChannelsDiscovery.Request.Extract(
    request: request,
    sharedKey: sharedKey
);
// extracted.LastBatchIndex — the batch index the Replica already has

// Owner side: respond with a batch of channel entries
var entries = new List<ChannelsDiscovery.Response.ChannelEntry>
{
    new() { ChannelId = 10, SharedKey = helperSharedKey1 },
    new() { ChannelId = 20, SharedKey = helperSharedKey2 },
};

DeRecMessage response = ChannelsDiscovery.Response.Produce(
    channelId: 1,
    sharedKey: sharedKey,
    entries: entries,
    totalBatches: 1,
    currentBatch: 0
);

// Replica side: process the response
var result = ChannelsDiscovery.Response.Process(
    response: response,
    sharedKey: sharedKey
);
// result.TotalBatches — total number of batches
// result.CurrentBatch — index of this batch
// result.Entries — List<ChannelEntry> with ChannelId and SharedKey
```

---

## Key Principles

- All protocol messages are opaque `byte[]`
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
