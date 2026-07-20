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

End-to-end primitive-level coverage (including the tampered-hash assertion)
lives at `bindings/dotnet/Program.cs::RunPairingFlowHashedKeysTest`. The
higher-level `DeRecProtocol` orchestrator is also available — see
[Using `DeRecProtocol` (orchestrator)](#using-derecprotocol-orchestrator).

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

When driving the orchestrator instead of the primitives, the recovering
device receives a `SecretRecoveredEvent` carrying the typed `Secret`. Pass it
to `protocol.RestoreAsync(secret, version)` on a fresh `DeRecProtocol` to
commit canonical helper / replica state and wipe the throwaway recovery-mode
channels. Errors throw `DeRecException` with `Code` in
{`AlreadyRestored`, `RestoreConflict`, `Invariant`, store-category code}.

---

## Using `DeRecProtocol` (orchestrator)

The `DeRec.Library.Orchestrator` namespace provides a stateful
`DeRecProtocol` class that mirrors the Rust orchestrator and the
`@derec-alliance/nodejs` / `@derec-alliance/web` packages. It owns the
storage / transport callbacks and drives every flow through a single
`StartAsync` / `ProcessAsync` / `AcceptAsync` / `RejectAsync` surface —
events surface as typed `DeRecEvent` subclasses.

`StartAsync` returns `IReadOnlyList<DeRecEvent>` describing the requests
that were dispatched — a single `PairingStartedEvent` for
`FlowKind.Pairing`, or one `*StartedEvent` per targeted channel for
fan-out flows (`ProtectSecret`, `VerifyShares`, `RecoverSecret`,
`Discovery`, `UpdateChannelInfo`). Per-target transport failures on
fan-out flows surface as `*FailedEvent { ChannelId, Error }` in the
same list — a single failing target does not short-circuit the round.
Programmer errors (invalid input, missing preconditions, role
mismatch) throw `DeRecException` before any target-level event is
emitted. Follow-up peer-response events (`PairingCompletedEvent`,
`ShareConfirmedEvent`, `SecretRecoveredEvent`, …) still surface from
`ProcessAsync`.

```csharp
using DeRec.Library;
using DeRec.Library.Orchestrator;
using DeRec.Library.Primitives;

var channelStore = new InMemoryChannelStore();
var shareStore   = new InMemoryShareStore();
var secretStore  = new InMemorySecretStore();
var transport    = new RecordingTransport();

using var owner = new DeRecProtocol(
    channelStore, shareStore, secretStore, transport,
    ownTransportUri: "https://owner.example.com");

// Pair (mirror this on the peer side).
byte[] contact = await helper.CreateContactAsync(channelId, ContactMode.InlineKeys);
var startEvents = await owner.StartAsync(FlowKind.Pairing, new PairingParams
{
    Kind = (int)Pairing.SenderKind.Owner,
    Contact = contact,
});
var started = startEvents.OfType<PairingStartedEvent>().First();
Console.WriteLine($"dispatched pair on channel {started.ChannelId}");
// Hand the queued PairRequest from `owner`'s transport to `helper.ProcessAndAcceptAllAsync`,
// then the PairResponse back to `owner.ProcessAndAcceptAllAsync`.
// Both sides surface `PairingCompletedEvent` when done.

// Protect a secret across one or more helpers.
var protectEvents = await owner.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
{
    SecretId = "0xCAFE",
    TargetValue = Target.Many(helperAId, helperBId).ToJsonValue(),
    Secrets = new[]
    {
        new UserSecret { Id = new byte[] { 1 }, Name = "secret", Data = secretBytes },
    },
});
// One ProtectSecretStartedEvent per targeted channel (helper + replica);
// any ProtectSecretFailedEvent { ChannelId, Version, Error } here means
// that specific target's request could not be dispatched — the rest are
// still in flight.
// Peer responses arrive via ProcessAsync as ShareStoredEvent /
// ShareConfirmedEvent per helper + SharingCompleteEvent once the round
// closes.
```

App-side responsibilities (mirrors the other SDKs):

- Implement `IChannelStore`, `IShareStore`, `ISecretStore`, `ITransport`
  with persistent backends. `InMemoryChannelStore` / `InMemoryShareStore`
  / `InMemorySecretStore` / `RecordingTransport` ship for tests.
- After pairing, link old↔new channel IDs on the helper side
  (`channelStore.LinkChannel(oldId, newId)`) so recovery can fan out on
  the new pair while still surfacing shares stored under the old one.

End-to-end coverage:
`bindings/dotnet/Program.cs::RunOrchestratorPairFlowTest`,
`RunOrchestratorShareAndDiscoverFlowTest`,
`RunOrchestratorReplicaPairAndSecretSyncTest`.

---

## Replica flows

Replicas mirror an Owner's secret onto a second device so the same secrets
remain reachable after device loss. Pairings are **unidirectional** —
one side runs as `SenderKind.ReplicaSource` (owns the secret), the other
as `SenderKind.ReplicaDestination` (receives it). Both `DeRecProtocol`
instances must be constructed with a stable `replicaId`:

```csharp
using var owner = new DeRecProtocol(
    channelStore, shareStore, secretStore, transport,
    ownTransportUri: "https://owner.example.com",
    replicaId: 0xAAAA_AAAA_AAAA_AAAAUL);
```

After the handshake, channels start in `Pending` and are not eligible as
`ProtectSecret` targets until both sides confirm a deterministic
fingerprint derived from the shared key:

```csharp
string localFp = await owner.GetFingerprintAsync(channelId);
string peerFp  = await destination.GetFingerprintAsync(channelId); // out of band

await owner.VerifyFingerprintAsync(channelId, peerFp);             // → true
await destination.VerifyFingerprintAsync(channelId, localFp);      // → true
```

The Source then includes the Destination in any `ProtectSecret` target
alongside helpers. Helpers receive the usual VSS share via
`StoreShareRequest`; the Destination receives the full secret as a typed
`ReplicaSecretReceivedEvent`:

```csharp
var ev = events.OfType<ReplicaSecretReceivedEvent>().First();
// ev.Secret.Helpers          — every paired helper (channel_id, transport_uri, shared_key, ...)
// ev.Secret.Secrets[i].Data  — the actual UserSecret bytes
// ev.Secret.Replicas         — every paired destination (replica_id, sender_kind, ...)
// ev.Secret.OwnerReplicaId   — the Source's replica_id
// ev.Shares                  — { ChannelId, CommittedShare } pairs keyed by helper channel id
```

`ev.Secret` + `ev.Shares` give the Destination everything it needs to act
in the Source's place during recovery. Smoke parity reference:
`bindings/dotnet/Program.cs::RunOrchestratorReplicaPairAndSecretSyncTest`.

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

## Security considerations

### Replica destinations inherit Source trust

`ReplicaSecretReceivedEvent.Secret` carries the full `Secret`,
which embeds every helper's `ChannelId` and `SharedKey` under
`HelperInfo`. Anyone holding the secret can therefore authenticate as the
Source toward every helper. This is intentional — it is what makes
Destination-driven recovery work — but it means a compromised
Destination can impersonate the Source against every helper paired at
the time the secret was sent. Pick Destinations with at least the trust
level of the Source device itself; do not treat them as opaque backups.

All replicas of one `SecretId` also share a single **group channel
key**: every replica channel's `SharedKey` entry in the secret store
holds the same 32 bytes, established at the first replica pair and
handed to every subsequent joiner via the
`ReplicaSecretPayload.SharedKey` field on its first sync round.
Compromise of any one Destination therefore exposes that single key;
the protocol does not provide per-pair forward secrecy across replicas.

### `ContactMode.HashedKeys` requires an ephemeral transport URI

`HashedKeys` ships only a SHA-384 binding hash in the contact and
serves the actual public keys through a plaintext PrePair round-trip on
the contact creator's own transport. Any party that can reach that URI
before the legitimate scanner gets the keys. Use `HashedKeys` only with
a transport endpoint that is freshly minted for the pairing and that
you can retire as soon as the PrePair leg completes.
`ContactMode.InlineKeys` has no such constraint.

The recommended pattern is: pair on the ephemeral URI, then — as soon
as the pairing completes on the contact creator side — call
`SetOwnTransport` with the permanent endpoint and start an
`UpdateChannelInfo` flow against the peer to announce the swap. Once
the peer acknowledges, retire the ephemeral URI. This keeps the
plaintext PrePair window tight while letting subsequent traffic ride
on the long-lived endpoint.

### Replica fingerprint verification is mandatory

Replica channels are created in `ChannelStatus.Pending` and remain
there until both sides call `VerifyFingerprintAsync` with the value the
peer derived from the shared key — confirmed out of band. The
orchestrator enforces this: `StartAsync(FlowKind.ProtectSecret, ...)`
throws a `DeRecException(Category = DeRecCategory.InvalidInput)` when a
target is still `Pending`. Treat verification as a required step in the
pairing UX — a scanner that auto-pairs without it accepts a
MITM-vulnerable replica.

### The `derec.*` namespace in `CommunicationInfo` is library-owned

`CommunicationInfo` is otherwise an opaque app-defined map, but every
key under the `derec.` prefix is reserved for the protocol. Today the
library owns `derec.replica_id`; future protocol additions will use the
same namespace. Application code must not write any `derec.*` entry —
the orchestrator silently overwrites or strips library-owned keys at
the protocol boundary, and app-set values are lost without warning.

---

## Documentation

- DeRec Alliance: https://derec.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK repository: https://github.com/derecalliance/lib-derec

---

## License

Licensed under the Apache License, Version 2.0.

See the `LICENSE` file for details.
