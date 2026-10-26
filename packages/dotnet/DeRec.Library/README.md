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

### Platform support

| Platform | Architectures | Status |
| --- | --- | --- |
| macOS | arm64, x64 | ✅ Supported — native library ships in the package |
| Linux | arm64, x64 | ✅ Supported — native library ships in the package |
| Windows | x64 | ⚠️ Not yet supported — see below |

**Windows is not supported by the published package yet.** The release build does
not produce a Windows native library, so no `win-x64` binary ships today. Package
support is *wired but dormant*: the `.csproj` already declares the
`runtimes/win-x64/native/derec_library.dll` slot behind an `Exists(...)` guard, so
it stays a no-op until a DLL is staged there. Automated Windows artifacts are
planned.

To produce and pack the Windows DLL yourself (no Windows machine is needed to
*build* it — only to *validate* that it loads):

1. Cross-compile the Rust core to Windows from any OS — e.g.
   `x86_64-pc-windows-msvc` via [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin),
   or `x86_64-pc-windows-gnu` via MinGW.
2. Stage the resulting `derec_library.dll` at
   `packages/dotnet/DeRec.Library/runtimes/win-x64/native/`.
3. Run `dotnet pack` — the DLL is included automatically, and the produced package
   gains a `win-x64` runtime alongside the four Unix RIDs.

Cross-building alone does not confirm the artifact works at runtime; loading and
running it is only validated on a Windows environment (e.g. a Windows CI runner).

---

## Protocol schema

The package ships the DeRec `.proto` schema under `schema/` so you can
generate code for any language without a `lib-derec` checkout:

- `schema/proto/` — the 18 schema files, flat. Every import is a bare
  filename, so a single include root resolves the whole closure:
  `protoc --proto_path=<nuget-package-root>/schema/proto <nuget-package-root>/schema/proto/*.proto`
- `schema/derec_descriptor.bin` — the same closure precompiled, well-known
  types included. Needs no include path at all. Compiled with
  `--include_source_info`, so code generated from it keeps the protocol's doc
  comments instead of emitting bare type declarations.

The schema is versioned with the package: `vX.Y.Z` carries exactly the schema
`vX.Y.Z` was built from.

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
channels, etc.). Three `ContactMode` values select how the public encryption
material is delivered:

| Mode | What the contact carries | Use when |
|---|---|---|
| `ContactMode.InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key + a 32-byte fingerprint commitment | Out-of-band channel can carry the keys (NFC, messaging). |
| `ContactMode.HashedKeys` | Only a SHA-384 commitment to the keys | Channel is size-constrained (QR codes). Scanner fetches the actual keys via a plaintext `PrePair` round-trip and verifies them against the hash. |
| `ContactMode.NoKeys` | Neither keys nor a commitment — only channel id, nonce and transports | Contact must be hand-typed or dictated, over a fully trusted out-of-band channel. Keys arrive via `PrePair` with nothing to check them against, so both sides confirm a fingerprint before the channel is usable. |

`Pairing.Request.EncodeContact` turns a `ContactMessage` into the bytes that
travel out of band, and `Pairing.Request.DecodeContact` turns them back. Both
refuse a contact whose fields do not match its mode.

After the handshake completes, **every mode** rekeys the channel id. The
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
    new[] { new TransportProtocol("https://example.com/alice") });

// Step 2: Contact responder produces the pairing request envelope.
var pairRequest = Pairing.Request.Produce(
    Pairing.SenderKind.Helper,
    new[] { new TransportProtocol("https://example.com/helper") },
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

// Request.Extract, Response.Produce and Response.Process each take an optional
// serialized ParameterRange this side accepts, and refuse a peer range that does
// not overlap it with DeRecCode.IncompatibleParameterRange.
//
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
    new[] { new TransportProtocol("https://relay.example.com/ephemeral") });

// Scanner: fetch keys via PrePair.
var prePairReqEnv = Pairing.Request.ProducePrePair(
    new[] { new TransportProtocol("https://scanner.example.com/ephemeral") },
    contact.ContactMessage);
var prePairReq = Pairing.Request.ExtractPrePair(prePairReqEnv.Envelope);
var prePairRespEnv = Pairing.Response.ProducePrePair(
    channelId, prePairReq.RequestProtoBytes, contact.SecretKeyMaterial);
var prePairResp = Pairing.Response.ExtractPrePair(prePairRespEnv.Envelope);

// Scanner validates the published keys against contact.ContactBindingHash.
// Throws DeRecException with Category=Pairing, Code=PrePairHashMismatch on
// mismatch (returns the keys, echoed nonce and fingerprint commitment on match).
var validated = Pairing.Response.ProcessPrePair(
    contact.ContactMessage, prePairResp.ResponseProtoBytes);

// Synthesize a "filled-in" contact and run the regular pairing flow. The
// mode flip is required — `Pairing.Request.Produce` enforces `InlineKeys`
// and rejects a contact that still advertises `HashedKeys`. The fingerprint
// commitment travels with the keys: `Pairing.Response.Process` checks the
// nonce the creator reveals in its PairResponse against it.
var filledInContact = contact.ContactMessage with
{
    ContactMode = ContactMode.InlineKeys,
    MlkemEncapsulationKey = validated.MlkemEncapsulationKey,
    EciesPublicKey = validated.EciesPublicKey,
    ContactBindingHash = null,
    FingerprintCommitment = validated.FingerprintCommitment,
};
// ... continue with Pairing.Request.Produce / Extract /
// Pairing.Response.Produce / Process against `filledInContact` exactly as
// in the InlineKeys example.
```

After the PrePair exchange the application **must** swap the transport
endpoint to a long-term one via `UpdateChannelInfo`. The ephemeral endpoint
advertised in the `HashedKeys` contact is intended to be retired immediately
after pairing.

`UpdateChannelInfo` reaches helper channels only. A replica member that
changes its endpoint or `CommunicationInfo` publishes a new version first,
then updates its helpers; see [On a replica member](https://github.com/derecalliance/lib-derec/tree/main/library#on-a-replica-member).

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

### `NoKeys` flow (PrePair + fingerprint)

`NoKeys` uses the same `PrePair` round-trip, but the contact creator
generates its keys only when the request arrives, and the scanner has no
commitment to check them against. A man-in-the-middle on the plaintext leg
leaves the two sides with different shared keys, so both sides compare a
fingerprint of the shared key out of band before trusting the channel.
The creator's `PrePair` response also carries a commitment to a nonce it
reveals only in its `PairResponse`, and the channel key depends on that
nonce, so whoever answers the scanner cannot search offline for keys that
make the two fingerprints agree. `Pairing.Response.Process` refuses a nonce
that does not open the commitment with `DeRecCode.FingerprintCommitmentMismatch`.

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong channelId = 4;
ulong nonce = 424242; // short enough to dictate; required for NoKeys

// Initiator: a NO_KEYS contact carries no keys and no secret key material.
var contact = Pairing.Request.CreateContact(
    channelId,
    ContactMode.NoKeys,
    new[] { new TransportProtocol("https://relay.example.com/ephemeral") },
    nonce);

// Scanner: ask for keys.
var prePairReqEnv = Pairing.Request.ProducePrePair(
    new[] { new TransportProtocol("https://scanner.example.com/ephemeral") },
    contact.ContactMessage);

// Initiator: match the request's nonce against the contact it issued, then
// generate keys. The returned SecretKeyMaterial is the initiator's for the
// rest of the handshake.
var prePairReq = Pairing.Request.ExtractPrePair(prePairReqEnv.Envelope);
var prePairResp = Pairing.Response.ProducePrePairNoKeys(
    channelId, prePairReq.RequestProtoBytes);
byte[] initiatorKeyMaterial = prePairResp.SecretKeyMaterial;

// Scanner: accept the keys (nothing to verify them against).
var extracted = Pairing.Response.ExtractPrePair(prePairResp.Envelope);
var accepted = Pairing.Response.ProcessPrePairNoKeys(
    contact.ContactMessage, extracted.ResponseProtoBytes);

var filledInContact = contact.ContactMessage with
{
    ContactMode = ContactMode.InlineKeys,
    MlkemEncapsulationKey = accepted.MlkemEncapsulationKey,
    EciesPublicKey = accepted.EciesPublicKey,
    ContactBindingHash = null,
    FingerprintCommitment = accepted.FingerprintCommitment,
};
// ... continue with the regular pairing flow against `filledInContact`,
// using `initiatorKeyMaterial` on the initiator side.

// Both sides then derive the fingerprint from their shared key and compare
// the two strings out of band (read aloud, shown on screen).
string fingerprint = Pairing.Fingerprint(sharedKey);
```

With the orchestrator, a `NoKeys` channel stays `ChannelStatus.Pending` —
not a publish target, not a recovery source, inbound traffic ignored —
until `VerifyFingerprintAsync` succeeds on both sides. Rate-limit inbound
`PrePairRequest`s per channel and expire outstanding `NoKeys` contacts on a
short timer.

This flow is covered end to end, including the tampered-hash assertion — see
[End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage). The
higher-level `DeRecProtocol` orchestrator is also available — see
[Using `DeRecProtocol` (orchestrator)](#using-derecprotocol-orchestrator).

---

## Example: Share Distribution

```csharp
using DeRec.Library;
using DeRec.Library.Primitives;

ulong secretId = 42;
byte[] secretData = System.Text.Encoding.UTF8.GetBytes("super-secret");
// Every channel is listed with its weight — the number of subshares its
// committed share carries. An ordinary Helper carries weight 1.
var channels = new[]
{
    new Sharing.WeightedChannel(1UL, 1),
    new Sharing.WeightedChannel(2UL, 1),
    new Sharing.WeightedChannel(3UL, 1),
};
// threshold counts subshares, not channels: with every weight 1 this must
// satisfy 2 <= threshold <= channels.Length.
ulong threshold = 2;
uint version = 1;

var splitResult = Sharing.Request.Split(secretId, secretData, channels, threshold, version);

// Optionally hand a chosen channel more than one subshare — e.g. a device the
// owner trusts more than the others. Every weight must satisfy
// 1 <= weight < threshold.
var weighted = Sharing.Request.Split(secretId, secretData,
    new[]
    {
        new Sharing.WeightedChannel(1UL, 2),
        new Sharing.WeightedChannel(2UL, 1),
        new Sharing.WeightedChannel(3UL, 1),
    },
    threshold: 3, version);

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
        keepVersion: 0,
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

When driving the orchestrator instead of the primitives, a helper that
answers with a share that cannot be part of the secret is reported as a
`RecoveryShareCorruptedEvent` (`Reason` is a `CorruptionReason` constant:
`Malformed`, `InvalidProof` or `Inconsistent`); the share is set aside and
never blocks the recovery from the others. An honest helper never sends one,
so treat it as a sign of a damaged or compromised helper — for example, offer
to unpair it.

### Helpers and shares

- Each share goes to a **different** helper. Threshold security depends on it:
  compromising one helper must yield at most one share.
- The library hands out one share per channel per version, and every pairing
  produces its own channel. It cannot tell whether two channels lead to the
  same party; keeping helpers distinct is the application's job.
- **Discouraged:** a single guardian acting as several helpers for the same
  owner. It is against the protocol's recommendation, since one compromise
  yields several shares. The library does not prevent it, but channel linking
  then needs the application's help (below).
- **Channel linking is expected to be one-to-one.** After an owner re-pairs in
  recovery mode, the helper application links the new channel to the old one
  with `IChannelStore.LinkChannel`. Linking assumes a helper holds **at most one share per owner
  for a given `secretId` and version**, so each recovery channel is linked to the
  single old channel it replaces. On `GetShare` the helper answers with
  **one** share from the linked set: the first whose `secretId` matches the
  request, in the order `IShareStore.LoadMany` returns. The library imposes no order. If
  several channels holding shares for the same owner are linked to one
  recovery channel and every recovery channel is answered from the same
  share, the owner receives it more than once (it counts once) and can fall
  below the threshold. An application that runs such a helper keeps each
  recovery channel resolving to a distinct share: either links stay
  one-to-one, or its share store returns, for each requesting channel, the
  share intended for it first, in a deterministic order.

The recovering device receives a `SecretRecoveredEvent` carrying the typed
`Secret`. Pass it
to `protocol.RestoreAsync(secret, version)` — on the same `DeRecProtocol`
that ran recovery, since it is the one holding the recovery-mode channels
`RestoreAsync` unpairs — to
commit canonical helper / replica state and wipe the throwaway recovery-mode
channels. A helper or member with no endpoint in the recovered roster gets no
channel; `RestoreAsync` returns a `PeerNotRestoredEvent` for it (`Reason` is
`NotRestoredReason.NoTransports`) and restores the rest. Errors throw
`DeRecException` with `Code` in
{`AlreadyRestored`, `RestoreConflict`, `Invariant`, store-category code}.
On `RestoreConflict`, `DeRecException.ConflictingChannelIds`
(`IReadOnlyList<ulong>`, empty for every other code) lists the existing
channels that collide with ids in the recovered `Secret` — clear exactly
those and retry:

```csharp
try
{
    await protocol.RestoreAsync(recovered.Secret, version);
}
catch (DeRecException e) when (e.Code == DeRecCode.RestoreConflict)
{
    foreach (ulong channelId in e.ConflictingChannelIds)
    {
        // remove the stale channel at `channelId` from your stores, then retry
    }
}
```

**Restore or join.** `SecretRecoveredEvent` writes nothing, so decide first.
When `Secret.Replicas?.Members` names live members other than the lost
device, do not restore: tell the user and offer to join that group as a new
replica — pair with a live member, confirm the fingerprint, then run
`StartAsync(FlowKind.ReplicaDiscovery, new ReplicaDiscoveryParams())`. With no live member, restore. Neither path gives this device the proofs of
earlier versions, so it cannot verify them: restore writes none, and a
joining device gets only the share map of the single version each push or
catch-up carries. The live members keep the proofs they hold. A restored
device also cannot publish, or answer a member's catch-up, until the app
configures a `ReplicaId` the roster names. Joining adds the device as a new
member, while restoring next to live replicas makes a second device claim
the lost device's role. See
[Restore or join](https://derec-alliance.gitbook.io/docs/concepts/replicas/restore-or-join).

> **Secret format:** the `recovered` bytes above (and the recoverable secret
> data underlying `Secret`) are `[version byte] · payload` — v1's payload is
> **gzip (RFC 1952)** compressed **JSON**, with byte fields as **standard
> base64 with padding (RFC 4648 §4)** and `u64` fields as decimal strings.
> See the `derec-library` `protocol::types::secret` reference documentation
> for the full field schema.

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

Every u64 identifier an event or recovered `Secret` carries (`ChannelId`,
`PairingChannelId`, `SecretId`, `TraceId`, the replica ids, `Synced` /
`Behind`, `HelperInfo.ChannelId`, `ReplicaInfo.ReplicaId`) is a `ulong`, the
same type the methods take, and `ReplicaInfo.Role` is a `ReplicaRole`.
`RejectAsync` takes the protobuf `StatusEnum` the peer receives:

```csharp
await helper.RejectAsync(action.Action,
    Org.Derecalliance.Derec.Protobuf.StatusEnum.SizeLimitExceeded, "over quota");
```

The answer arrives typed the same way: `Status` on `ShareRejectedEvent`, `ShareRefusedEvent`,
`ShareVerifyRejectedEvent`, `RecoveryShareRefusedEvent`, `UnpairRejectedEvent`, `PrePairRejectedEvent`,
`ChannelInfoUpdateRejectedEvent`, `ReplicaSyncRejectedEvent`, `ReplicaSecretRefusedEvent` and
`ReplicaSecretAckedEvent` is that `StatusEnum`:

```csharp
if (ev is ShareRejectedEvent { Status: Org.Derecalliance.Derec.Protobuf.StatusEnum.SizeLimitExceeded } rejected)
    Console.WriteLine($"helper {rejected.ChannelId} is over quota: {rejected.Memo}");
```

```csharp
using DeRec.Library;
using DeRec.Library.Orchestrator;
using DeRec.Library.Primitives;

var channelStore = new InMemoryChannelStore();
var shareStore   = new InMemoryShareStore();
var secretStore  = new InMemorySecretStore();
var transport    = new RecordingTransport();

// WithStores sets all five stores in one call. Each With*Store setter is
// still available; the last call for a store wins.
using var owner = new DeRecProtocolBuilder(secretId)
    .WithStores(new DeRecStores(
        channelStore,
        shareStore,
        secretStore,
        new InMemoryUserSecretStore(),
        new InMemoryStateStore()))
    .WithTransport(transport)
    .WithOwnTransports(new[] { new TransportProtocol("https://owner.example.com") })
    .Build();

// Pair (mirror this on the peer side).
byte[] contact = await helper.CreateContactAsync(channelId, ContactMode.InlineKeys);
var startEvents = await owner.StartAsync(FlowKind.Pairing, new PairingParams
{
    Kind = Pairing.SenderKind.Owner,
    Contact = contact,
});
var started = startEvents.OfType<PairingStartedEvent>().First();
Console.WriteLine($"dispatched pair on channel {started.ChannelId}");
// Hand the queued PairRequest from `owner`'s transport to `helper.ProcessAsync`,
// then the PairResponse back to `owner.ProcessAsync`, accepting any
// `ActionRequiredEvent` each returns — or build with
// `WithAutoAccept(AutoAcceptPolicy.All())` to have the library do it.
// Both sides surface `PairingCompletedEvent` when done.

// Protect a secret. The secret id is the one the protocol was built with,
// and the round targets every paired helper and confirmed replica
// destination. Threshold (set via WithThreshold) counts subshares, not
// helpers: with no Weights every helper gets one subshare, so the threshold is
// the number of helpers needed, as before.
var protectEvents = await owner.StartAsync(FlowKind.ProtectSecret, new ProtectSecretParams
{
    Secrets = new[]
    {
        new UserSecret { Id = new byte[] { 1 }, Name = "secret", Data = secretBytes },
    },
    Description = "initial backup",
    // Optional: give a chosen helper's channel more than one subshare so it
    // alone can cover more of the threshold. The map is the full assignment:
    // a helper it does not name holds one subshare, so pass the stored
    // weights (below). Every value must satisfy 1 <= weight < threshold.
    // Weights = new Dictionary<ulong, uint> { [helperChannelId] = 2 },
});
// One ProtectSecretStartedEvent per targeted channel (helper + replica);
// its Weight is that channel's subshare count — the Weights entry, or 1 when
// the map does not name it. Any ProtectSecretFailedEvent { ChannelId, Version, Weight, Error }
// here means that specific target's request could not be dispatched — the
// rest are still in flight.
// Peer responses arrive via ProcessAsync as ShareStoredEvent /
// ShareConfirmedEvent per helper + SharingCompleteEvent once the round
// closes.
```

Weights are recorded. Each round writes the weight it gave every paired helper
to that helper's `HelperChannel.Weight` in your `IChannelStore` before anything
is sent, and the publishes the library starts on its own (after pairing, after
a fingerprint is confirmed) reuse those weights; a newly paired helper starts
at 1. The weights also travel in the recovered secret (`HelperInfo.Weight`), so
`RestoreAsync` and replica hydration write them back into the channel records
they create. When the builder's threshold applies (no threshold is stored),
lowering it to or below a stored weight makes the next publish fail with
`DeRecCode.InvalidWeight` (65) before anything is sent, until `StartAsync`
assigns valid weights.

The threshold is recorded too. A round splits at `ProtectSecretParams.Threshold` when
given, otherwise at the stored threshold (`UserSecrets.Threshold`), and only otherwise
at `WithThreshold`, which is therefore the starting threshold for a secret with
nothing stored. Every publish stores the threshold it used, the recovered
secret carries it (`Secret.Threshold`), and `RestoreAsync` and replica
hydration put it back, so the publishes the library starts on its own and
the follow-up after `RestoreAsync` keep it: leave `Threshold` unset there. To
change it, pass `Threshold` on `StartAsync(FlowKind.ProtectSecret, …)`. It must be at least 2,
above every weight, and no greater than a subshare cap; a round that fails
a check writes and sends nothing. Your `IUserSecretStore` must persist the
snapshot's threshold as given.

That failure surfaces where the library started the publish, and in each
case nothing is sent:

- `ProcessAsync` throws a `DeRecException` whose `Events` keep the message's
  events, `PairingCompletedEvent` included.
- `AcceptAsync` throws. The pairing has completed and its response was sent,
  but `PairingCompletedEvent` is not returned.
- `VerifyFingerprintAsync` throws. The promotion stands: calling it again
  succeeds and publishes nothing.

Call `StartAsync` with `ProtectSecretParams` and valid `Weights` to publish
to every helper.

The intended flow. Weights are the user's choice: before `StartAsync`, show
the user each paired helper's current weight, pre-filled from the stored
`HelperChannel.Weight` in your `IChannelStore`, and pass the user's final
choice as the whole `Weights` map. Reading the stored weights first is the
normal flow. Every other `StartAsync(FlowKind.ProtectSecret, ...)` the app
makes, such as a republish after editing the secrets or the follow-up after
`RestoreAsync`, must pass the stored weights unchanged: a helper left out
returns to 1, which silently undoes the user's choice. Only the publishes
the library starts on its own (after pairing, after a fingerprint is
confirmed) reuse the stored weights by themselves.

**Below the threshold.** When the paired helpers' total weight is below the
threshold, `StartAsync` skips the split: no helper receives anything, so no
`ProtectSecretStartedEvent` / `ProtectSecretFailedEvent` comes back for one.
A paired replica still gets its usual secret-only copy and events; with none
paired, `StartAsync` returns an empty list — this is not an error. The
version still advances and the secrets/description are saved as the latest
snapshot, so the next publish that reaches threshold (including one the
library starts on its own) shares it. Sum the weights you are about to
assign against the threshold beforehand, or count the returned helper
events afterward, to tell the two cases apart. This is more reachable with
weighted helpers than with the default of 1: two helpers at weight 2 against
a threshold of 3 (total weight 4) drop below it when a publish leaves both
out of the weights map, resetting each to weight 1 for a total of 2 —
exactly what a restore follow-up publish risks if it does not pass the
stored weights unchanged.

`WithMaxSubshares(max)` on the builder caps the total subshares one round
splits the secret into — the sum of every helper's weight. Unset means no cap.
Recovery time grows quadratically with that total (about 0.2 s at 200, 5.5 s
at 1,000 and 87 s at 4,000 subshares per attempt) while splitting stays cheap,
so this is the place to bound it. A round over the cap fails `StartAsync`
with a `DeRecException` whose `Code` is `DeRecCode.TooManySubshares` (66)
before anything is sent; publishes the library starts itself count the stored
weights and respect it too.
A cap below the threshold makes `Build()` throw (`InvalidInput`). The cap
applies at sharing only, never at recovery: a recovering device cannot know
the cap the shares were made under.

#### Verification outcomes

`StartAsync(FlowKind.VerifyShares, …)` challenges each targeted helper, and
every challenged channel ends with exactly one of:

- `ShareVerifiedEvent` — the helper proved it holds the exact share.
  `Subshares` is how many subshares that helper holds for `Version`, read from
  this device's stored share, so it is the weight of the round that published
  `Version`, not the helper's current weight; it is `null` when that share was
  stored before the count was recorded. `Threshold` is the threshold that version was split with, from the
  same stored share, not the current one; it is `null` when that share was
  stored before the threshold was recorded. To judge whether a version is
  recoverable, sum `Subshares` over its `ShareVerifiedEvent` events and compare the
  sum with their `Threshold`. If either is `null` on any of those events,
  the result is unknown: a `null` count is not `0` or `1`. The count lives on `Share.Subshares`, which the
  library sets on owner-side shares only (`null` on a helper's share and never
  backfilled): your `IShareStore` must persist it as given and return it
  unchanged. `Share.Threshold` follows the same rules, and must be
  persisted the same way.
- `ShareVerifyInvalidEvent { ChannelId, Version }` — the helper's proof does
  not match the share this device stored. It is an event; `ProcessAsync`
  does not throw.
- `ShareVerifyRejectedEvent { Status, Memo }` — the helper refused the
  challenge with a non-OK status.
- `VerifySharesFailedEvent { Reason, Error }` — no verdict could be reached
  on this device. `Reason` is a `VerifyFailureReason` constant:
  `NoSharedKey`, `NoProof` or `DispatchFailed`.

A stored proof is either confirmed by its helper or part of a sharing round
still open: when a round settles a channel as failed (a rejection or a
timeout), that channel's proof is deleted. A confirmation also deletes the
proofs of versions the helper dropped: a helper that stores a version
deletes every other version except that round's `keepVersion`, so when it
confirms, its proofs for those versions are deleted here too (the confirmed
version and `keepVersion` stay). A helper that rejects the round keeps its
older versions, and so do their proofs. A replica Destination never sees the helpers' answers, and it keeps every
proof it receives: it never deletes one on its own, and freeing that storage
is the app's concern. Verifying on a Destination a version that a helper
refused, or later dropped under a `keepVersion`, gets
`ShareVerifyRejectedEvent` (`UNKNOWN_SHARE_VERSION`) from that helper, where
the Source reports `NoProof`. The app may delete such rows from the
Destination's share store; verifying a version whose rows are gone then
gives `VerifySharesFailedEvent` with `VerifyFailureReason.NoProof`. Verify only versions whose round
completed (`SharingCompleteEvent`). Starting verification on a channel with
no proof sends nothing and returns `VerifySharesFailedEvent` with
`VerifyFailureReason.NoProof` at once.

A late response to an earlier challenge is ignored as `MessageIgnoredEvent`
with `IgnoreReason.StaleResponse`, and the current challenge stays open. A
response missing its `result` is still an error.

Every channel message carries one timestamp, its send time, in both the
envelope and the inner message. A message whose two timestamps differ, or
where either or both are absent, is ignored as `MessageIgnoredEvent` with
`IgnoreReason.TimestampMismatch`; this includes replies from 0.0.8 peers.

#### Filtered listings

`ListHelpers` and `ListReplicas` take a filter — `ids`, `status`, `role` and
`exclude`, where every empty value means "do not restrict on this", so an
all-empty filter selects everything. `exclude` is applied last, overriding
`ids`.

**Apply it in your query.** That is the point: a `WHERE` clause or a
key-condition expression instead of transferring rows the caller will discard.
That transfer costs bandwidth everywhere, and on a metered backing such as
DynamoDB, which bills by bytes read, it costs money.

**A store that ignores it is slow, not wrong.** The library re-applies the
filter to every listing before acting on it and drops anything the filter
excluded.

**That is a one-way guarantee, not a validation of your store.** Dropping rows
enforces an upper bound; it cannot recover a row you omitted. A store that
returns *fewer* rows than the filter selects is still wrong, in a way nothing
in the library can detect — the protocol simply fails to act. Applying the
filter faithfully is still your job.

App-side responsibilities (mirrors the other SDKs):

- Implement `IChannelStore`, `IShareStore`, `ISecretStore`, `ITransport`
  with persistent backends. `InMemoryChannelStore` / `InMemoryShareStore`
  / `InMemorySecretStore` / `RecordingTransport` ship for tests.
- Run a reachable endpoint. Delivery is push-only: a reply produced by
  `ProcessAsync` goes out through `ITransport`, addressed to the peer, and
  is never returned to the caller. Recommended HTTP conventions (not
  protocol requirements) are `POST`, an `application/octet-stream` body,
  `202 Accepted`, and `200 OK` with the reply body when answering an
  unreachable peer on the same connection. Only that `200 OK`
  same-connection answer needs matching: pick the reply that echoes the
  request's trace id with `Envelope.ReadTraceId`. See
  [Transports](https://derec-alliance.gitbook.io/docs/protocol-specification/transports).
- On an owner, `IShareStore.KeepVersion` chooses the one older version
  helpers keep besides the version being shared: return the newest version
  whose `SharingCompleteEvent` reported `ThresholdMet`, or `0` to keep no
  other version. An answer equal to or greater than the version being shared
  fails the round with `DeRecCode.InvalidKeepVersion` (67) before anything is
  sent; see
  [`DeRecShareStore::keep_version`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecShareStore.html#tymethod.keep_version).
- After pairing, link old↔new channel IDs on the helper side
  (`channelStore.LinkChannel(secretId, oldId, newId)`) so recovery can fan
  out on the new pair while still surfacing shares stored under the old one.
  Links are one-to-one; see [Helpers and shares](#helpers-and-shares).

### Configuration from a file or record

Applications usually load settings as a whole: general settings from the
environment or a config file, per-user settings from a user record.
`DeRecProtocolConfig` holds every data setting of the builder, each one
optional, and `WithConfig` applies it in one call:

```csharp
using System.Text.Json;
using DeRec.Library;
using DeRec.Library.Orchestrator;

var general = JsonSerializer.Deserialize<DeRecProtocolConfig>(generalJson, DeRecJsonOptions.Wire)!;
var perUser = JsonSerializer.Deserialize<DeRecProtocolConfig>(userRecordJson, DeRecJsonOptions.Wire)!;

using var protocol = new DeRecProtocolBuilder(secretId)
    .WithStores(stores)
    .WithTransport(transport)
    .WithConfig(general)  // 1. general settings
    .WithConfig(perUser)  // 2. per-user settings
    .WithThreshold(4)     // 3. individual setters
    .Build();
```

- **Only set properties are applied.** A `null` property leaves whatever the
  builder already holds.
- **Last write wins, per setting.** Nested values replace the builder's value
  as a whole, except `Timeouts`: each timeout is merged separately, so a
  per-user config that sets only `inbound_message_secs` keeps the
  `sharing_round_secs` the general config set.
- **Validation happens in `Build()`**, with the same rules as the setters. A
  `threshold` of `1` from a config file fails exactly as `WithThreshold(1)`
  does.
- **Stores, the transport and the secret id are not settings** and are not
  carried in the config.

The record reads and writes the canonical JSON shared by every SDK
(`library/tests/fixtures/protocol_config.json` holds a full example):

```json
{
  "threshold": 3,
  "max_subshares": "12",
  "timeouts": {
    "inbound_message_secs": 300,
    "sharing_round_secs": 60,
    "unpair_ack_secs": 60,
    "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
  },
  "parameter_range": { "min_share_size": 1, "max_share_size": 4096 },
  "auto_accept": { "pairing": true, "store_share": true },
  "auto_respond_on_failure": false,
  "auto_reply_to": false,
  "unpair_ack": "required",
  "unsafe_connection": false,
  "communication_info": { "name": "alice" },
  "own_transports": [{ "uri": "https://me.example.com/derec", "protocol": "https" }],
  "replica_id": "9007199254740993"
}
```

Keys are `snake_case` and every key is optional. `replica_id` and
`max_subshares` are decimal strings, so values above 2^53 survive. Timeouts
are whole seconds. **An unknown key fails the read** with a `JsonException`
naming it, at every level, so a misspelled setting is never silently dropped.
Serializing a `DeRecProtocolConfig` writes the same shape, which is also what
`Build()` sends to the library.

### Refusing a share or a verification

A helper enforces share size itself: with a parameter range configured, a
share outside its own `MinShareSize`/`MaxShareSize` (inclusive; a max of `0` means
unbounded) is answered with `SIZE_LIMIT_EXCEEDED` before any
`ActionRequired` or auto-accept. Frequency limits on share updates and
verifications are the application's to enforce, from its share store.

On a helper channel, throw `ShareStoreRefusedException` from
`IShareStore.Save` (a genuinely new share version) or
`IShareStore.RecordVerification` (an accepted verification challenge) to
refuse it:

```csharp
public void RecordVerification(ulong secretId, ulong channelId, uint version)
{
    if (rateLimiter.TooSoon(channelId))
        throw new ShareStoreRefusedException(ShareStoreRefusal.TooFrequent);
}
```

The library answers the owner with the mapped status (`TooFrequent` →
`TOO_FREQUENT`, `SizeLimitExceeded` → `SIZE_LIMIT_EXCEEDED`, `Rejected` →
`REJECTED`), and the owner sees `ShareRejectedEvent` or
`ShareVerifyRejectedEvent` with that status. Any other exception is an
ordinary store failure, reported as a `RequestFailedEvent` (see
[Failed requests](#failed-requests)). Every `IShareStore` implements `RecordVerification`;
an app with no limit leaves it empty. See
[Helper-side admission control](https://github.com/derecalliance/lib-derec/tree/main/library#helper-side-admission-control).

### Failed requests

Every request that arrives on an authenticated channel gets exactly one
response, even when handling it fails. Such a failure does not make
`ProcessAsync` or `AcceptAsync` throw: it is reported as a
`RequestFailedEvent`, and the call's other events are kept.

- `ActionKind` is the type of the request that failed, one of the
  `PendingActionKind` constants (`PendingActionKind.Failed` when its body
  could not be decoded, or was a request type the channel cannot carry).
- `Responded` is `true` when the library already sent the response.
- `Status` (`StatusEnum`) is the status that was sent, or would have been.
  It is always present. `Memo` is the wire-safe memo sent with it, or that
  would have been, so `RejectAsync(Action, Status, Memo)` sends exactly the
  response the library would have sent.
- `ErrorCode` is the error's stable code name and `Message` a local
  description; neither goes on the wire.
- `Action`, when `Responded` is `false`, is the token that answers the
  request. Pass it to `RejectAsync`, which sends the one response;
  `AcceptAsync` refuses it. The library never expires it. It is `null` only
  when `RejectAsync` could never answer it: a request on a replica group
  channel that names no member and carries no `replyTo`, which has no reply
  target, or, with `WithAutoRespondOnFailure` off, a replica copy that hands
  this device the group key and fails before that key is stored.

Resolve each token once. The library is stateless, so rejecting the same
token twice, or rejecting an action already accepted, sends a second
response.

`WithAutoRespondOnFailure` decides who answers. With it on, the library sends
the response itself (a known failure keeps its specific status; anything else
is `FAIL` with a generic memo). With it off (the default), nothing is sent and
the event carries the token:

```csharp
foreach (var failed in events.OfType<RequestFailedEvent>())
{
    if (!failed.Responded && failed.Action is byte[] token)
        await protocol.RejectAsync(token, failed.Status, failed.Memo);
}
```

A peer that answers with an `ErrorResponseMessage` (for example
`FORMAT_ERROR` for a body it could not decode) is reported as an
`ErrorResponseReceivedEvent` with `Status` and `Memo`; it is never answered.

An inbound `PairRequest` refused under a protocol rule (a parameter range that
does not overlap this device's, `INCOMPATIBLE_PARAMETER_RANGE`, or a replica id
already in the group, `REPLICA_ID_CONFLICT`) is answered with that status in
every mode and reported as a `PairingRefusedEvent` with `Status` and `Memo`,
the reason sent to the requester and written from its side. `ErrorCode`
(`incompatible_parameter_range` or `replica_id_conflict`) and `Message` carry
the local reason for logging or display, as on `RequestFailedEvent`; they are
never sent. `ProcessAsync` does not throw for it, and no channel is created.
The requester's `ProcessAsync` throws a `DeRecException` with code
`non_ok_status`, whose `PeerStatus` and `PeerMemo` hold the refusal.

End-to-end coverage: see [End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

---

## Replica flows

Replicas mirror an Owner's secret onto a second device so the same secrets
remain reachable after device loss. Pairings are **unidirectional** —
one side runs as `SenderKind.ReplicaSource` (owns the secret), the other
as `SenderKind.ReplicaDestination` (receives it). Both `DeRecProtocol`
instances must be constructed with a stable `replicaId`. Mint it once with
`DeRecProtocolBuilder.GenerateReplicaId()` (never `0`), persist it, and pass
the same value on every start:

```csharp
ulong replicaId = DeRecProtocolBuilder.GenerateReplicaId(); // persist this

using var source = new DeRecProtocolBuilder(secretId)
    .WithChannelStore(channelStore)
    .WithShareStore(shareStore)
    .WithSecretStore(secretStore)
    .WithUserSecretStore(new InMemoryUserSecretStore())
    .WithStateStore(new InMemoryStateStore())
    .WithTransport(transport)
    .WithOwnTransports(new[] { new TransportProtocol("https://source.example.com") })
    .WithReplicaId(replicaId)
    .Build();

// The Source issues the contact; the Destination pairs as ReplicaDestination.
byte[] contact = await source.CreateContactAsync(channelId, ContactMode.InlineKeys);
await destination.StartAsync(FlowKind.Pairing, new PairingParams
{
    Kind = Pairing.SenderKind.ReplicaDestination,
    Contact = contact,
});
```

After the handshake, channels start in `Pending` and are not eligible as
`ProtectSecret` targets until both sides confirm a deterministic
fingerprint derived from the shared key:

```csharp
string localFp = await source.GetFingerprintAsync(channelId);
string peerFp  = await destination.GetFingerprintAsync(channelId); // out of band

await source.VerifyFingerprintAsync(channelId, peerFp);
await destination.VerifyFingerprintAsync(channelId, localFp);
```

A mismatch throws `DeRecException` with `DeRecCode.FingerprintMismatch` — a
possible man-in-the-middle. The `Pending` pairing is revoked (its records,
channel key and pairing material are deleted), so the devices must pair again.

The Source's confirmation publishes the current secret to every paired peer
straight away, and every later `ProtectSecret` round includes the
Destination alongside the helpers. Helpers receive the usual VSS share via
`StoreShareRequest`; the Destination receives the full secret. The first
copy of a `SecretId` surfaces as `ReplicaSecretInstalledEvent`, later
versions as `ReplicaSecretReceivedEvent`; both carry the same fields and
are already written to the stores when they surface:

```csharp
var ev = events.OfType<ReplicaSecretInstalledEvent>().First();
// ev.Secret.Helpers            — every paired helper (ChannelId, Transports, SharedKey, CommunicationInfo)
// ev.Secret.Secrets[i].Data    — the actual UserSecret bytes
// ev.Secret.Replicas.Members   — every group member, writer included (ReplicaId, Transports, Role, CommunicationInfo)
// ev.Secret.Replicas.Members.Single(m => m.Role == ReplicaRole.Source) — the Source
// ev.FromReplicaId             — the member that sent this copy
// ev.Shares                    — { ChannelId, CommittedShare } pairs keyed by helper channel id
```

`ev.Secret` + `ev.Shares` give the Destination everything it needs to act
in the Source's place during recovery. This is covered end to end — see
[End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

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

### When `ProcessAsync` fails

`ProcessAsync` settles expired deadlines (sharing-round and unpair
timeouts) before it handles the message, and those are never reported
again. So a failed call still carries them: `DeRecException.Events` holds
every event produced before the failure, and `DeRecException.ChannelId`
(`ulong?`) names the channel the message came from (`null` when the bytes
were not a decodable envelope). Handle the events as you would a successful
call's, then the error:

```csharp
try
{
    Handle(await protocol.ProcessAsync(bytes));
}
catch (DeRecException e)
{
    Handle(e.Events);
    Report(e.ChannelId, e);
}
```

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
`SetOwnTransports` with the permanent endpoint and start an
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

Until a device confirms, it ignores everything the peer sends on that
channel: `ProcessAsync` changes no store, sends nothing back, and returns a
`MessageIgnoredEvent` whose `Reason` is `IgnoreReason.PendingVerification`,
with `ChannelId` and `TraceId`. This matters most for a replica destination.
The source's own confirmation publishes the vault immediately, so that copy
usually arrives before the destination's user has confirmed. Confirming does
not replay it: once the destination's `VerifyFingerprintAsync` succeeds,
call `StartAsync(FlowKind.ReplicaDiscovery, new ReplicaDiscoveryParams())` to
pull the copy from the source.

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
