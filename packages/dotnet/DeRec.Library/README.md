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

var version = DeRec.Library.Native.ProtocolVersion.derec_protocol_version();

Console.WriteLine(version.Major);
Console.WriteLine(version.Minor);
```

---

## Example: Pairing Flow

```csharp
using DeRec.Library;

// Step 1: Owner creates contact message
var contact = Pairing.CreateContactMessage(
    channelId: 1,
    transportProtocol: new TransportProtocol("https://example.com")
);

// Step 2: Helper produces pairing request
var request = Pairing.ProducePairingRequestMessage(
    kind: Pairing.SenderKind.Helper,
    transportProtocol: new TransportProtocol("https://helper.com"),
    contactMessageBytes: contact.WireBytes
);

// Step 3: Owner produces pairing response
var response = Pairing.ProducePairingResponseMessage(
    kind: Pairing.SenderKind.SharerNonRecovery,
    pairRequestWireBytes: request.WireBytes,
    pairingSecretKeyMaterial: contact.SecretKeyMaterial
);

// Step 4: Helper processes response
var final = Pairing.ProcessPairingResponseMessage(
    contactMessage: request.InitiatorContactMessage,
    pairResponseWireBytes: response.WireBytes,
    pairingSecretKeyMaterial: request.SecretKeyMaterial
);

Console.WriteLine($"Shared key length: {final.SharedKey.Length}");
```

---

## Example: Share Distribution

```csharp
using DeRec.Library;

var result = Sharing.ProtectSecret(
    secretId: new byte[] {1,2,3},
    secretData: System.Text.Encoding.UTF8.GetBytes("super-secret"),
    channels: new ulong[] {1,2,3},
    threshold: 2,
    version: 1
);

// Opaque wire bytes containing all share messages
byte[] shareMessages = result.ShareMessageWireBytesArray;
```

---

## Example: Recovery Flow

```csharp
using DeRec.Library;

// Request a share
byte[] request = Recovery.GenerateShareRequest(
    secretId: new byte[] {1,2,3},
    version: 1
);

// Helper responds with share content
byte[] response = Recovery.GenerateShareResponse(
    shareRequestWireBytes: request,
    shareContent: /* stored share bytes */
);

// Owner aggregates responses and recovers secret
byte[] secret = Recovery.RecoverFromShareResponses(
    shareResponseWireBytesArray: /* aggregated responses */,
    secretId: new byte[] {1,2,3},
    version: 1
);
```

---

## Example: Verification Flow

```csharp
using DeRec.Library;

// Owner generates verification request
byte[] request = Verification.GenerateVerificationRequest(
    secretId: new byte[] {1,2,3},
    version: 1
);

// Helper produces response
byte[] response = Verification.GenerateVerificationResponse(
    shareContent: /* stored share */,
    requestWireBytes: request
);

// Owner verifies response
bool isValid = Verification.VerifyShareResponse(
    shareContent: /* stored share */,
    requestWireBytes: request,
    responseWireBytes: response
);

Console.WriteLine($"Valid: {isValid}");
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
