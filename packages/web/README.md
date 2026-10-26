# DeRec Web SDK

Browser WebAssembly bindings for `derec-library`, the Rust SDK implementing the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares across trusted helpers.

---

## Installation

```bash
npm install @derec-alliance/web
```

or with yarn:

```bash
yarn add @derec-alliance/web
```

---

## Requirements

- Modern browser with WebAssembly support
- ES module support
- TypeScript (optional)

No native dependencies are required.

---

## Protocol schema

The package ships the DeRec `.proto` schema at its root so you can generate
code for any language without a `lib-derec` checkout:

- `proto/` — the 18 schema files, flat. Every import is a bare filename, so a
  single include root resolves the whole closure:
  `protoc --proto_path=node_modules/@derec-alliance/web/proto node_modules/@derec-alliance/web/proto/*.proto`
- `derec_descriptor.bin` — the same closure precompiled, well-known types
  included. Needs no include path at all. Compiled with
  `--include_source_info`, so code generated from it keeps the protocol's doc
  comments instead of emitting bare type declarations.

The schema is versioned with the package: `vX.Y.Z` carries exactly the schema
`vX.Y.Z` was built from.

---

## Design Overview

The Web SDK is a **thin binding layer** over the Rust implementation.

All core logic is executed in Rust:

- Protobuf serialization / deserialization
- Cryptography (pairing, encryption, verification)
- DeRecMessage envelope construction
- Protocol validation

The JavaScript API operates exclusively on:

```ts
Uint8Array
```

These represent **opaque wire-level protocol messages**.

---

## Initialization

```ts
import { init } from "@derec-alliance/web";

await init();
```

---

## Quick Example

```ts
import { init, primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const channelId = 1n;            // u64 → bigint
  const secretId = 42n;            // u64 → bigint
  const version = 1;               // u32 → number
  const sharedKey = new Uint8Array(32); // established during pairing

  const result = primitives.verification.request.produce(channelId, secretId, version, sharedKey);
  // result carries the encoded DeRecMessage envelope, ready to send over transport.
}

main();
```

---

## Pairing Flow

The `ContactMessage` is exchanged out-of-band (QR codes, existing messaging
channels, etc.). Two `ContactMode` values select how the public encryption
material is delivered:

| Mode | What the contact carries | Use when |
|---|---|---|
| `InlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key + a 32-byte fingerprint commitment | Out-of-band channel can carry the keys (NFC, messaging). |
| `HashedKeys` | Only a SHA-384 commitment to the keys | Channel is size-constrained (QR codes). Scanner fetches the actual keys via a plaintext `PrePair` round-trip and verifies them against the hash. |

After the handshake completes, **both modes** rekey the channel id. The
responder derives `SHA-384(u64_be(originalId) || sharedKey)[..8]` as a
`bigint`, includes it in the encrypted `PairResponseMessage`, and both sides
switch their local state to the new id. The new id never appears in plaintext
on the wire, so a passive observer who only saw pre-rekey traffic cannot link
the long-running channel to its pairing-time id.

### `InlineKeys` flow

```ts
import { init, ContactMode, primitives, SenderKind } from "@derec-alliance/web";

async function main() {
  await init();

  const channelId = 1n;

  // Step 1: Initiator creates the out-of-band ContactMessage.
  const contact = primitives.pairing.request.create_contact(
    channelId,
    ContactMode.InlineKeys,
    { protocol: 0, uri: "https://owner.example.com" },
  );

  // Step 2: Responder produces a pairing request from the contact.
  const request = primitives.pairing.request.produce(
    SenderKind.Helper,
    { protocol: 0, uri: "https://helper.example.com" },
    contact.contact_message,
    null, // optional CommunicationInfo
  );

  // Step 3: Initiator extracts the request and produces the response.
  const { request: pairRequest } =
    primitives.pairing.request.extract(request.envelope, contact.secret_key, null);
  const produced = primitives.pairing.response.produce(
    channelId,
    pairRequest,
    contact.secret_key,
    null,
  );

  // Step 4: Responder extracts and processes the response.
  const { response: pairResponse } =
    primitives.pairing.response.extract(produced.envelope, request.secret_key);
  const processed = primitives.pairing.response.process(
    request.initiator_contact_message,
    pairResponse,
    request.secret_key,
    null,
  );

  // Both sides hold the same shared key and rekeyed channel id.
  // produced.shared_key  ==  processed.shared_key
  // produced.channel_id  ==  processed.channel_id  !==  channelId
  //
  // Rename local channel state from `channelId` to `produced.channel_id`
  // before sending any further traffic.
}

main();
```

To reject the request, build a `PairResponseMessage` with a non-OK status and
encrypt it against `request.ecies_public_key` using the WASM-exposed pairing
envelope helpers. The higher-level `DeRecProtocol` orchestrator's `reject`
method does this for you. Rejected responses do not carry a meaningful
`channel_id` — the rekey only takes effect on `Ok` responses.

### `HashedKeys` flow (PrePair)

`HashedKeys` adds one plaintext round-trip before the regular `InlineKeys`
handshake. The scanner fetches the actual keys via `PrePair`, verifies them
against `contact.contact_binding_hash`, and then runs the normal pairing
flow on a synthesized contact with the keys filled in.

```ts
import {
  init,
  ContactMode,
  primitives,
  SenderKind,
  type ContactMessage,
} from "@derec-alliance/web";

async function main() {
  await init();

  const channelId = 7n;

  // Initiator: HASHED_KEYS contact (no inline keys, only the binding hash).
  // Transport URI MUST be ephemeral — PrePair envelopes are plaintext.
  const contact = primitives.pairing.request.create_contact(
    channelId,
    ContactMode.HashedKeys,
    { protocol: 0, uri: "https://relay.example.com/ephemeral" },
  );

  // Scanner: fetch keys via PrePair.
  const prePairReqEnv = primitives.pairing.request.produce_pre_pair(
    { protocol: 0, uri: "https://scanner.example.com/ephemeral" },
    contact.contact_message,
  );
  const { request: prePairReq } =
    primitives.pairing.request.extract_pre_pair(prePairReqEnv.envelope);
  const prePairRespEnv = primitives.pairing.response.produce_pre_pair(
    channelId, prePairReq, contact.secret_key,
  );
  const { response: prePairResp } =
    primitives.pairing.response.extract_pre_pair(prePairRespEnv.envelope);

  // Scanner validates the published keys against contact.contact_binding_hash.
  // Throws on mismatch (returns the keys, echoed nonce and fingerprint
  // commitment on match).
  const validated = primitives.pairing.response.process_pre_pair(
    contact.contact_message, prePairResp,
  );

  // Synthesize a "filled-in" contact and run the regular pairing flow. The
  // mode flip is required — `primitives.pairing.request.produce` enforces
  // `InlineKeys` and rejects a contact that still advertises `HashedKeys`.
  // The fingerprint commitment travels with the keys:
  // `primitives.pairing.response.process` checks the nonce the creator
  // reveals in its PairResponse against it (`fingerprint_commitment_mismatch`).
  const { contact_binding_hash: _omitBindingHash, ...contactBase } =
    contact.contact_message;
  const filledInContact: ContactMessage = {
    ...contactBase,
    contact_mode: ContactMode.InlineKeys,
    mlkem_encapsulation_key: validated.mlkem_encapsulation_key,
    ecies_public_key: validated.ecies_public_key,
    fingerprint_commitment: validated.fingerprint_commitment,
  };
  // ... continue with primitives.pairing.request.produce / extract /
  // primitives.pairing.response.produce / process against `filledInContact`
  // exactly as in the InlineKeys example.
}
```

After the PrePair exchange the application **must** swap the transport
endpoint to a long-term one via `UpdateChannelInfo`. The ephemeral endpoint
advertised in the `HashedKeys` contact is intended to be retired immediately
after pairing.

#### Using `DeRecProtocol` instead

The orchestrator handles the whole chain automatically:

- **Contact creator** — `protocol.createContact(channelId, ContactMode.HashedKeys)`
  returns the small contact (binding hash only). When the scanner's
  `PrePairRequest` arrives, `protocol.process(bytes)` emits an
  `ActionRequired` event with `action_kind: "PrePair"`. Call
  `protocol.accept(action)` to publish the keys (the library builds the
  response and routes it), or `protocol.reject(action, status, memo)` to
  refuse — `status` is a `StatusEnum` value such as `StatusEnum.Rejected`.
- **Scanner** — `protocol.start(FlowKind.Pairing, { kind, contact })` kicks
  off the plaintext PrePair leg. `start()` returns a `DeRecEvent[]`
  containing one `PairingStarted { channel_id, kind }` event that
  describes the dispatched handshake; the scanner auto-proceeds to
  `PairRequest`, and the application sees `PairingCompleted` only when
  the final response lands via `process()`. Failure modes:
    - Contact creator rejected → `DeRecEvent` with
      `type: "PrePairRejected"`, plus `status` / `memo`.
    - Binding-hash mismatch → `protocol.process(...)` throws a
      `DeRecException`-shape error whose `message` carries
      `"contact binding hash mismatch"`. This is security-relevant — the
      keys published by the peer do not match the commitment the scanner
      originally accepted.

This flow is covered end to end — happy path and tampered-hash — for every
SDK. See [End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

---

## Share Distribution (Sharing Flow)

```ts
import { init, primitives, type WeightedChannel } from "@derec-alliance/web";

async function main() {
  await init();

  const secretId = 42n;             // u64
  const secretData = new TextEncoder().encode("super-secret");
  const channelIds = [1n, 2n, 3n];
  // Every channel is listed with its own weight (how many subshares it
  // holds); 1 is an ordinary helper. threshold counts subshares, not
  // channels: with every weight at 1 this must satisfy
  // 2 <= threshold <= channelIds.length.
  const channels: WeightedChannel[] = channelIds.map((id) => [id, 1]);
  const threshold = 2;
  const version = 1;
  // sharedKeys: Map<bigint, Uint8Array> with the 32-byte channel keys

  const { shares } = primitives.sharing.request.split(
    channels,
    secretId,
    version,
    secretData,
    threshold,
  );
  // shares: Map<bigint, CommittedDeRecShare> — one committed share per helper.

  // Optionally hand a chosen channel more than one subshare — e.g. a device the
  // owner trusts more than the others. Every weight must satisfy
  // 1 <= weight < threshold.
  const weightedChannels: WeightedChannel[] = [[channelIds[0]!, 2], [channelIds[1]!, 1], [channelIds[2]!, 1]];
  const { shares: weighted } = primitives.sharing.request.split(
    weightedChannels,
    secretId,
    version,
    secretData,
    3,                               // threshold
  );

  // Wrap each share into an encrypted delivery envelope.
  for (const [channelId, committedShare] of shares) {
    const envelope = primitives.sharing.request.produce(
      channelId, version, secretId, committedShare, [], "", sharedKeys.get(channelId)!,
    );
  }
}

main();
```

---

### Helper weights

`ProtectSecretParams.weights` (`Map<bigint | string, number>`) sets how many
subshares each paired helper holds. The map is the **full assignment, not a
patch**: a paired helper it does not name holds one subshare.
`ProtectSecretStarted` and
`ProtectSecretFailed` report the `weight` each channel was given.

Weights are recorded. Each round writes the weight it gave every paired helper
to that helper's channel record before anything is sent, and the publishes the
library starts on its own (after pairing, after a fingerprint is confirmed)
reuse those weights; a newly paired helper starts at 1. The weights also travel
in the recovered secret (`helpers[].weight`), so `restore` and replica
hydration write them back into the channel records they create.

The threshold is recorded too. A round splits at `ProtectSecretParams.threshold` when
given, otherwise at the stored threshold (`UserSecrets.threshold`), and only otherwise
at `withThreshold`, which is therefore the starting threshold for a secret with
nothing stored. Every publish stores the threshold it used, the recovered
secret carries it (`secret.threshold`), and `restore` and replica
hydration put it back, so the publishes the library starts on its own and
the follow-up after `restore` keep it: leave `threshold` unset there. To
change it, pass `threshold` on `start(FlowKind.ProtectSecret, …)`. It must be at least 2,
above every weight, and no greater than a subshare cap; a round that fails
a check writes and sends nothing. Your `UserSecretStore` must persist the
snapshot's threshold as given.

The intended flow. Weights are the user's choice: before `start`, show the
user each paired helper's current weight, pre-filled from your `ChannelStore`,
and pass the user's final choice as the whole `weights` map. Reading the
stored weights first is the normal flow. Every other `start(FlowKind.ProtectSecret, ...)`
the app makes, such as a republish after editing the secrets or the follow-up
after `restore`, must pass the stored weights unchanged: a helper left out
returns to 1, which silently undoes the user's choice. Only the publishes the
library starts on its own (after pairing, after a fingerprint is confirmed)
reuse the stored weights by themselves.

A helper record is opaque JSON bytes, `{"Helper": {...}}`. Parsing one to read
`weight` is safe: it is a small integer, and the channel id comes from the
`channelId` argument your store received, never from the parsed object's
`channel_id` (a `u64` that `JSON.parse` can round). What the `ChannelStore`
docs forbid is re-serialising a parsed record; keep persisting the original
bytes.

```ts
const weight = JSON.parse(new TextDecoder().decode(helperRecordBytes)).Helper.weight || 1;
```

When the builder's threshold applies (no threshold is stored), lowering it to
or below a stored weight makes the next publish fail
with code `invalid_weight` before anything is sent, until
`start(FlowKind.ProtectSecret, ...)` assigns valid weights.

That failure surfaces where the library started the publish, and in each
case nothing is sent:

- `process()` throws a `DeRecError` whose `events` keep the message's
  events, `PairingCompleted` included.
- `accept()` throws. The pairing has completed and its response was sent,
  but `PairingCompleted` is not returned.
- `verifyFingerprint()` throws. The promotion stands: calling it again
  resolves `true` and publishes nothing.

Call `start(FlowKind.ProtectSecret, ...)` with valid weights to publish to
every helper.

**Below the threshold.** When the paired helpers' total weight is below the
threshold, `start` skips the split: no helper receives anything, so no
`ProtectSecretStarted` / `ProtectSecretFailed` comes back for one. A paired
replica still gets its usual secret-only copy and events; with none paired,
`start` resolves with no events at all — this is not an error. The version
still advances and the secrets/description are saved as the latest
snapshot, so the next publish that reaches threshold (including one the
library starts on its own) shares it. Sum the weights about to be assigned
against the threshold beforehand, or count the returned helper events
afterward, to tell the two cases apart. This is more reachable with
weighted helpers than with the default of 1: two helpers at weight 2 against
a threshold of 3 (total weight 4) drop below it when a publish leaves both
out of the weights map, resetting each to weight 1 for a total of 2 — a
risk for a restore follow-up publish that does not pass the stored weights
unchanged.

### Capping the total subshares

`DeRecProtocolBuilder.withMaxSubshares(max)` caps the total subshares one
`start(FlowKind.ProtectSecret, ...)` round splits the secret into — the sum of
every helper's weight (`ProtectSecretParams.weights`). Unset means no cap.
Recovery time grows quadratically with that total (about 0.2 s at 200, 5.5 s
at 1,000 and 87 s at 4,000 subshares per attempt) while splitting stays cheap,
so this is the place to bound it. A round over the cap fails with code
`too_many_subshares` before anything is sent; publishes the library starts
itself count the stored weights and respect it too. A cap below the threshold makes `build()` throw
`invalid_input`. The cap applies at sharing only, never at recovery: a
recovering device cannot know the cap the shares were made under. The
`split` primitive applies no cap.

## Recovery Flow

```ts
import { init, primitives } from "@derec-alliance/web";

async function main() {
  await init();

  const secretId = 42n;         // u64
  const version = 1;            // u32

  // Owner side: produce the recovery request.
  const shareRequest = primitives.recovery.request.produce(
    1n,                         // channel ID
    secretId,
    version,
    sharedKey,
  );

  // Helper side: produce the response using the StoreShareRequest it persisted
  // at sharing time.
  const shareResponse = primitives.recovery.response.produce(
    secretId,
    1n,                         // channel ID
    storedShareEnvelope,
    shareRequest,
    sharedKey,
  );

  // Owner side: collect at least `threshold` responses and reconstruct.
  const recovered = primitives.recovery.response.recover(
    [
      { response: shareResponse, shared_key: sharedKey },
      // …additional helper responses…
    ],
    secretId,
    version,
  );
  // `recovered` is a Uint8Array carrying the reconstructed secret payload.
}

main();
```

When driving the protocol layer instead of the primitives, a helper that
answers with a share that cannot be part of the secret is reported as a
`RecoveryShareCorrupted` event (`reason`: `"Malformed"`, `"InvalidProof"` or
`"Inconsistent"`); the share is set aside and never blocks the recovery from
the others. An honest helper never sends one, so treat it as a sign of a
damaged or compromised helper — for example, offer to unpair it.

The recovering device receives a `SecretRecovered` event carrying the typed
`secret`. Pass it
to `protocol.restore(secret, version)` — on the same `DeRecProtocol`
instance that ran recovery, since it is the one holding the recovery-mode
channels `restore` unpairs — to
commit canonical helper / replica state and wipe the throwaway recovery-mode
channels — at that point the device resumes normal operation as if the secret
had been protected here originally.
A helper or member with no endpoint in the recovered roster gets no channel;
`restore` returns a `PeerNotRestored` event for it (`reason: "NoTransports"`)
and restores the rest.

**Restore or join.** `SecretRecovered` writes nothing, so decide first. When
`secret.replicas?.members` names live members other than the lost device, do
not restore: tell the user and offer to join that group as a new replica —
pair with a live member, confirm the fingerprint, then run
`start(FlowKind.ReplicaDiscovery)`. With no live member, restore. Neither path gives this device the proofs of
earlier versions, so it cannot verify them: restore writes none, and a
joining device gets only the share map of the single version each push or
catch-up carries. The live members keep the proofs they hold. A restored
device also cannot publish, or answer a member's catch-up, until the app
configures a `replica_id` the roster names. Joining adds the device as a new
member, while restoring next to live replicas makes a second device claim
the lost device's role. See
[Restore or join](https://derec-alliance.gitbook.io/docs/concepts/replicas/restore-or-join).

```ts
const events = await protocol.process(responseBytes);
for (const ev of events) {
  if (ev.type === "SecretRecovered") {
    await protocol.restore(ev.secret, recoveredVersion);
  }
}
```

Errors surface as a `DeRecError` with a `category` and `code` —
`already_restored`, `restore_conflict` (with `channel_ids`), `invariant`,
`invalid_recovered_secret` (a malformed `secret`), or `store_error` (a store call failed; `category`
names the store). `code` is typed `DeRecErrorCode`, the full union of every
code the library can report plus the WASM-marshalling codes this binding
raises itself (e.g. `decode_error`, `invalid_timeouts`).

> **Secret format:** the recoverable secret (the bytes helpers store and
> recovery reconstructs) is `[version byte] · payload` — v1's payload is
> **gzip (RFC 1952)** compressed **JSON**, with byte fields as **standard
> base64 with padding (RFC 4648 §4)** and `u64` fields as decimal strings.
> See the `derec-library` `protocol::types::secret` reference documentation
> for the full field schema.

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
  with `ChannelStore.linkChannel`. Linking assumes a helper holds **at most one share per owner
  for a given `secretId` and version**, so each recovery channel is linked to the
  single old channel it replaces. On `GetShare` the helper answers with
  **one** share from the linked set: the first whose `secretId` matches the
  request, in the order `ShareStore.loadMany` returns. The library imposes no order. If
  several channels holding shares for the same owner are linked to one
  recovery channel and every recovery channel is answered from the same
  share, the owner receives it more than once (it counts once) and can fall
  below the threshold. An application that runs such a helper keeps each
  recovery channel resolving to a distinct share: either links stay
  one-to-one, or its share store returns, for each requesting channel, the
  share intended for it first, in a deterministic order.

---

## Verification Flow

```ts
import { init, primitives } from "@derec-alliance/web";

async function main() {
  await init();

  // Owner side: produce the verification request.
  const requestEnvelope = primitives.verification.request.produce(channelId, secretId, version, sharedKey);

  // Helper side: decrypt and extract the challenge fields.
  const req = primitives.verification.request.extract(requestEnvelope, sharedKey);
  // req.channel_id, req.secret_id, req.version, req.nonce

  // Helper side: produce the response.
  const responseEnvelope = primitives.verification.response.produce(
    channelId,
    req.secret_id,
    req.version,
    req.nonce,
    sharedKey,
    storedShareEnvelope
  );

  // Owner side: verify the response.
  const isValid = primitives.verification.response.process(responseEnvelope, sharedKey, storedShareEnvelope);

  console.log("Valid:", isValid);
}

main();
```

### Verification outcomes with `DeRecProtocol`

`protocol.start(FlowKind.VerifyShares, …)` challenges each targeted helper,
and every challenged channel ends with exactly one event:

- `ShareVerified` — the helper proved it holds the exact share. `subshares`
  is how many subshares that helper holds for `version`, read from this
  device's stored share, so it is the weight of the round that published
  `version`, not the helper's current weight; it is absent when that share was
  stored before the count was recorded. `threshold` is the threshold that version was split with, from the
  same stored share, not the current one; it is absent when that share was
  stored before the threshold was recorded. To judge whether a version is
  recoverable, sum `subshares` over its `ShareVerified` events and compare the
  sum with their `threshold`. If either is absent on any of those events,
  the result is unknown: a absent count is not `0` or `1`. The count lives on `Share.subshares`, which the
  library sets on owner-side shares only (absent on a helper's share and never
  backfilled): your `ShareStore` must persist it as given and return it
  unchanged. `Share.threshold` follows the same rules, and must be
  persisted the same way.
- `ShareVerifyInvalid { channel_id, version }` — the helper's proof does not
  match the share this device stored. It is an event; `process()` does not
  throw.
- `ShareVerifyRejected { status, memo }` — the helper refused the challenge
  with a non-OK status.
- `VerifySharesFailed { reason, error }` — no verdict could be reached on
  this device. `reason` is a `VerifyFailureReason`: `"NoSharedKey"`,
  `"NoProof"` or `"DispatchFailed"`.

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
refused, or later dropped under a `keepVersion`, gets `ShareVerifyRejected`
(`UNKNOWN_SHARE_VERSION`) from that helper, where the Source reports
`NoProof`. The app may delete such rows from the Destination's share store;
verifying a version whose rows are gone then gives `VerifySharesFailed` with
`reason: "NoProof"`. Verify only versions whose round
completed (`SharingComplete`). Starting verification on a channel with no
proof sends nothing and returns `VerifySharesFailed` with
`reason: "NoProof"` at once. A late response to an earlier challenge is
ignored as `MessageIgnored` with `reason: "StaleResponse"`, and the current
challenge stays open; a response missing its `result` is still an error.

Every channel message carries one timestamp, its send time, in both the
envelope and the inner message. A message whose two timestamps differ, or
where either or both are absent, is ignored as `MessageIgnored` with
`reason: "TimestampMismatch"`; this includes replies from 0.0.8 peers.

---

## Usage with Bundlers

Compatible with:

- Vite
- Webpack
- Rollup
- Next.js
- Parcel

```ts
import { init } from "@derec-alliance/web";

await init();
```

---

## CDN Usage

```html
<script type="module">
  import { init } from "https://cdn.jsdelivr.net/npm/@derec-alliance/web/+esm";

  await init();
</script>
```

---

## Refusing a share or a verification

A helper enforces share size itself: with a parameter range configured, a
share outside its own `min_share_size`/`max_share_size` (inclusive; a max of `0` means
unbounded) is answered with `SIZE_LIMIT_EXCEEDED` before any
`ActionRequired` or auto-accept. A share that does not decode
(`FORMAT_ERROR`), does not verify against its commitment
(`VERIFICATION_FAILED`) or differs from the one already stored at its version
(`VERSION_CONFLICT`) is refused the same way. Nothing is stored, and the
helper itself receives a `ShareRefused` event carrying the `status` and `memo`
the owner was answered with; the owner sees `ShareRejected`. Frequency limits
on share updates and verifications are the application's to enforce, from its
share store.

A replica destination checks a group member's copy of the secret the same
way: a copy that does not decode or is not self-consistent (`FORMAT_ERROR`), or
whose share map does not verify (`VERIFICATION_FAILED`), is refused before
anything is written, and the destination receives `ReplicaSecretRefused`. On a
push the publisher is answered with that `status` and `memo` and sees
`ReplicaSyncRejected`; a copy served by a catch-up is not answered.

On a helper channel, throw (or reject with) `shareStoreRefusal(reason)` from
`ShareStore.save` (a genuinely new share version) or
`ShareStore.recordVerification` (an accepted verification challenge) to
refuse it:

```ts
import { shareStoreRefusal } from "@derec-alliance/web";

async recordVerification(secretId: string, channelId: string, version: number) {
  if (limiter.tooSoon(channelId)) throw shareStoreRefusal("too_frequent");
}
```

The library answers the owner with the mapped status (`"too_frequent"` →
`TOO_FREQUENT`, `"size_limit_exceeded"` → `SIZE_LIMIT_EXCEEDED`,
`"rejected"` → `REJECTED`), and the owner sees `ShareRejected` or
`ShareVerifyRejected` with that `status`. Any other rejection is an ordinary
store failure, reported as a `RequestFailed` event (see
[Failed requests](#failed-requests)). Every `ShareStore` implements
`recordVerification`; an app with no limit resolves it. See
[Helper-side admission control](https://github.com/derecalliance/lib-derec/tree/main/library#helper-side-admission-control).

---

## Store filtered listings

`ChannelStore.listHelpers` and `ChannelStore.listReplicas` receive a filter
object — `ids`, `status`, `role` and `exclude`, where every empty value means
"do not restrict on this", so an all-empty filter selects everything.
`exclude` is applied last, overriding `ids`. Ids are decimal strings, like
every other `u64` on this bridge.

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

The backstop matters here in particular: TypeScript accepts a function of fewer
parameters where more are declared, so a store written before the filter
existed still satisfies this interface and compiles without a diagnostic.

---

## Configuration from a file or record

Applications usually load settings as a whole: general settings from the
environment or a config file, per-user settings from a user record.
`DeRecProtocolConfig` holds every data setting of the builder, each one
optional, and `withConfig` applies it in one call:

```ts
import { DeRecProtocolBuilder } from "@derec-alliance/web";
import type { DeRecProtocolConfig } from "@derec-alliance/web";

const general: DeRecProtocolConfig = JSON.parse(generalJson);
const perUser: DeRecProtocolConfig = JSON.parse(userRecordJson);

const protocol = new DeRecProtocolBuilder(secretId)
  .withStores(stores)
  .withTransport(myTransport)
  .withConfig(general)   // 1. general settings
  .withConfig(perUser)   // 2. per-user settings
  .withThreshold(4)      // 3. individual setters
  .build();
```

- **Only set fields are applied.** An absent or `null` field leaves whatever
  the builder already holds.
- **Last write wins, per field.** WASM holds one config and layers every
  `withConfig` and per-option setter call into it field by field, so the
  later call always wins regardless of which form it took. Nested objects
  replace the builder's value as a whole, except `timeouts`: each of its
  fields is merged separately, so a per-user config that sets only
  `inbound_message_secs` keeps the `sharing_round_secs` the general config
  set.
- **Most rules are checked in `build()`**, with the same result whether the
  value came from `withConfig` or its own setter. A `threshold` of `1` from
  a config file fails exactly as `withThreshold(1)` does. A value that
  needs parsing rather than range-checking — the protocol name in an
  `own_transports` entry, the `unpair_ack` string — is resolved as soon as
  it is supplied, so `withOwnTransports`/`withUnpairAck` can throw straight
  from the call, and the same `own_transports`/`unpair_ack` key inside a
  `withConfig` argument can throw from that call instead.
- **Stores, the transport and the constructor's `secretId` are not settings**
  and are not carried in the config.
- **Unknown keys throw**, at any level — `decode_error` — instead of being
  silently ignored, so a misspelled key in a config file fails loudly.

The canonical JSON, shared by every SDK, is:

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
`max_subshares` are `u64` values written as decimal strings — a `bigint`
throws `decode_error`; call `withReplicaId`/`withMaxSubshares` directly for a
`bigint`. Timeouts are whole seconds. See the `DeRecProtocolConfig` doc comment
in `index.d.ts` for every field's accepted forms.

---

## Package Contents

```text
derec_library_bg.wasm
derec_library.js
derec_library.d.ts
index.js
index.d.ts
```

- `.wasm` — compiled Rust core
- `derec_library.js` / `derec_library.d.ts` — raw wasm-bindgen bindings
- `index.js` / `index.d.ts` — `primitives.*` namespace assembly and TypeScript declarations

---

## Key Principles

- All protocol messages are opaque `Uint8Array`
- No protobuf types are exposed
- No cryptographic operations occur in JavaScript
- Rust is the single source of truth
- Every `DeRecProtocol` method that touches protocol state returns a
  `Promise`, including the `set*` setters. Overlapping calls on one
  instance — a `tick()` timer firing while `process()` handles a message —
  queue and run in the order they were made; they never collide. A store
  or transport callback must not await a call on the instance that
  invoked it, since that call waits behind the callback's own caller.

---

## Transport

`Transport.send(endpoints, message)` is a mailbox, not a request/response
call: a reply produced by `process()` is handed to `send`, addressed to the
peer, and is never returned by `process()`, so every participant needs a
reachable endpoint. Recommended HTTP conventions (not protocol requirements)
are `POST`, an `application/octet-stream` body, `202 Accepted`, and `200 OK`
with the reply body when answering an unreachable peer on the same
connection. Only that `200 OK` same-connection answer needs matching: pick
the reply that echoes the request's trace id with `envelope.read_trace_id`.
See [Transports](https://derec-alliance.gitbook.io/docs/protocol-specification/transports).

---

## Replica flows

Replicas mirror an Owner's secret onto a second device so the same secrets
remain reachable after device loss. Pairings are **unidirectional** — one
side runs as `SenderKind.ReplicaSource` (owns the secret), the other as
`SenderKind.ReplicaDestination` (receives it). Both must be constructed
with a stable `replicaId`:

```ts
// withStores sets all five stores in one call. Each with*Store setter is
// still available; the last call for a store wins.
const owner = new DeRecProtocolBuilder(secretId)
  .withStores({ channelStore, shareStore, secretStore, userSecretStore, stateStore })
  .withTransport(transport)
  .withOwnTransports([{ uri: "https://owner.example.com", protocol: "https" }])
  .withThreshold(2)
  .withCommunicationInfo({ name: "Owner" })
  .withReplicaId(0xAAAA_AAAA_AAAA_AAAAn)
  .build();
```

A typical Source↔Destination handshake:

```ts
const contact = await owner.createContact(channelId, ContactMode.InlineKeys);
await destination.start(FlowKind.Pairing, {
  kind: SenderKind.ReplicaDestination,
  contact,
});
// pump messages between the two protocols (drain transport → process)
```

The channel ends up in `Pending` and is NOT eligible as a
`ProtectSecret` target until both sides confirm a deterministic
fingerprint derived from the shared key:

```ts
const localFp = await owner.getFingerprint(channelId);
const peerFp  = await destination.getFingerprint(channelId); // out of band

await owner.verifyFingerprint(channelId, peerFp);
await destination.verifyFingerprint(channelId, localFp);
```

A mismatch rejects with code `fingerprint_mismatch` — a possible
man-in-the-middle. The `Pending` pairing is revoked (its records, channel key
and pairing material are deleted), so the devices must pair again.

Once paired, the Source includes the Destination as a `ProtectSecret`
target alongside helpers. Helpers receive the usual VSS share via
`StoreShareRequest`; the Destination receives the full secret as a
typed `ReplicaSecretReceived` event:

```ts
{
  type: "ReplicaSecretReceived",
  channel_id, from_replica_id, secret_id, version,
  secret: {
    helpers:  [...],   // every paired helper (channel_id, transport_uri, shared_key, ...)
    secrets:  [{ id, name, data }],
    replicas: [...],   // every paired destination (replica_id, sender_kind, ...)
    owner_replica_id,  // the Source's replica_id
  },
  shares: [{ channel_id, committed_share }, ...],  // helper channel_id → share bytes
}
```

`secret` + `shares` give the Destination everything it needs to act in the
Source's place during recovery.

End-to-end coverage lives in the repository's tests — see
[End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

---

## When `process()` fails

`process()` settles expired deadlines (sharing-round and unpair timeouts)
before it handles the message, and those are never reported again. So when
the message then fails, the thrown `DeRecError` carries them: `events` holds
every event produced before the failure, and `channel_id` names the channel
the message came from (absent when the bytes were not a decodable envelope).
Handle the events as you would a successful call's, then the error:

```ts
try {
  handle(await protocol.process(bytes));
} catch (error) {
  const failure = error as DeRecError;
  handle(failure.events ?? []);
  report(failure.channel_id, failure);
}
```

A request this device fails to handle does not reject the call; see
[Failed requests](#failed-requests).

---

## Failed requests

Every request that arrives on an authenticated channel gets exactly one
response, even when handling it fails. Such a failure does not make
`process()` or `accept()` reject: it is reported as a `RequestFailed` event,
and the call's other events are kept.

- `action_kind` is the type of the request that failed, a
  `PendingActionKind` label (`"Failed"` when its body could not be decoded,
  or was a request type the channel cannot carry).
- `responded` is `true` when the library already sent the response.
- `status` is the `StatusEnum` that was sent, or would have been. It is
  always present. `memo` is the wire-safe memo sent with it, or that would
  have been, so `reject(action, status, memo)` sends exactly the response
  the library would have sent.
- `error_code` is the error's `DeRecErrorCode` and `message` a local
  description; neither goes on the wire.
- `action`, when `responded` is `false`, is the token that answers the
  request. Pass it to `reject`, which sends the one response; `accept`
  refuses it. The library never expires it. It is absent only when `reject`
  could never answer it: a request on a replica group channel that names no
  member and carries no `replyTo`, which has no reply target, or, with
  `withAutoRespondOnFailure` off, a replica copy that hands this device the
  group key and fails before that key is stored.

Resolve each token once. The library is stateless, so rejecting the same
token twice, or rejecting an action already accepted, sends a second
response.

`withAutoRespondOnFailure` decides who answers. With it on, the library sends
the response itself (a known failure keeps its specific status; anything else
is `FAIL` with a generic memo). With it off (the default), nothing is sent and
the event carries the token:

```ts
for (const event of events) {
  if (event.type === "RequestFailed" && !event.responded && event.action) {
    await protocol.reject(event.action, event.status, event.memo);
  }
}
```

A message that decrypts under the channel key but whose body cannot be
decoded is answered with an `ErrorResponseMessage` (`FORMAT_ERROR` when the
library answers it; the status passed to `reject` otherwise). A peer that
answers this device that way is reported as an `ErrorResponseReceived` event
with `status` and `memo`; it is never answered.

An inbound `PairRequest` refused under a protocol rule (a parameter range that
does not overlap this device's, `INCOMPATIBLE_PARAMETER_RANGE`, or a replica id
already in the group, `REPLICA_ID_CONFLICT`) is answered with that status in
every mode and reported as a `PairingRefused` event with `status` and `memo`,
the reason sent to the requester and written from its side. `error_code`
(`incompatible_parameter_range` or `replica_id_conflict`) and `message` carry
the local reason for logging or display, as on `RequestFailed`; they are never
sent. `process()` does not reject for it, and no channel is created. The
requester's `process()` rejects with code `non_ok_status`, whose `status` and
`memo` hold the refusal.

---

## Correlation and routing

Two cross-cutting metadata fields appear on every channel-mode exchange:

- **`traceId`** — opaque `bigint` on the outer envelope, used to correlate
  responses with requests. The `DeRecProtocol` orchestrator handles this
  end-to-end (random token on every outbound request, echo on every
  response). Primitive-only callers can manipulate it directly via
  `envelope.apply_trace_id(bytes, traceId)` and `envelope.read_trace_id(bytes)`.
- **`replyTo`** — optional `TransportProtocol` list on request bodies, telling
  the responder to route this exchange's response to alternate endpoints.
  Set it per call (every `primitives.*.request.produce` takes a trailing
  `reply_to` arg) or protocol-wide with the `autoReplyTo` constructor flag
  on `DeRecProtocol` (stamps this node's own transports into `replyTo` on
  every outbound request). Excludes pairing and `UpdateChannelInfo`, which
  already carry their own `supportedTransports` field.

The motivating case for `replyTo` is replicas: when Replica A sends a
request on a channel the helper paired with sibling Replica B, the
helper's stored peer endpoint points at B. `replyTo` lets A say "send the
response back to me," without rewriting channel state.

---

## Security considerations

### Replica destinations inherit Source trust

`ReplicaSecretReceived.secret` carries the full secret, which
embeds every helper's `channel_id` and `shared_key`. Anyone holding the
secret can therefore authenticate as the Source toward every helper.
This is intentional — it is what makes Destination-driven recovery
work — but it means a compromised Destination can impersonate the
Source against every helper paired at the time the secret was sent.
Pick Destinations with at least the trust level of the Source device
itself; do not treat them as opaque backups.

All replicas of one `secret_id` also share a single **group channel
key**: every replica channel's `SharedKey` entry in the secret store
holds the same 32 bytes, established at the first replica pair and
handed to every subsequent joiner via the
`ReplicaSecretPayload.shared_key` field on its first sync round.
Compromise of any one Destination therefore exposes that single key;
the protocol does not provide per-pair forward secrecy across replicas.

### `ContactMode.HashedKeys` requires an ephemeral transport URI

`HashedKeys` ships only a SHA-384 binding hash in the contact and
serves the actual public keys through a plaintext PrePair round-trip
on the contact creator's own transport. Any party that can reach that
URI before the legitimate scanner gets the keys. Use `HashedKeys` only
with a transport endpoint that is freshly minted for the pairing and
that you can retire as soon as the PrePair leg completes.
`ContactMode.InlineKeys` has no such constraint.

The recommended pattern is: pair on the ephemeral URI, then — as soon
as the pairing completes on the contact creator side — call
`setOwnTransports` with the permanent endpoint and start an
`UpdateChannelInfo` flow against the peer to announce the swap. Once
the peer acknowledges, retire the ephemeral URI. This keeps the
plaintext PrePair window tight while letting subsequent traffic ride
on the long-lived endpoint.

`UpdateChannelInfo` reaches helper channels only. A replica member that
changes its endpoint or `communication_info` publishes a new version first,
then updates its helpers; see [On a replica member](https://github.com/derecalliance/lib-derec/tree/main/library#on-a-replica-member).

### Replica fingerprint verification is mandatory

Replica channels are created with `status: "Pending"` and remain there
until both sides call `verifyFingerprint` with the value the peer
derived from the shared key — confirmed out of band. The orchestrator
enforces this: `start(FlowKind.ProtectSecret, ...)` throws when a
target is still `Pending`. Treat verification as a required step in
the pairing UX — a scanner that auto-pairs without it accepts a
MITM-vulnerable replica.

Until a device confirms, it ignores everything the peer sends on that
channel: `process` changes no store, sends nothing back, and returns
`{ type: "MessageIgnored", channel_id, reason: "PendingVerification",
trace_id }`. This matters most for a replica destination. The source's own
confirmation publishes the vault immediately, so that copy usually arrives
before the destination's user has confirmed. Confirming does not replay it:
once the destination's `verifyFingerprint` resolves `true`, call
`start(FlowKind.ReplicaDiscovery)` to pull the copy from the source.

### The `derec.*` namespace in `communicationInfo` is library-owned

`communicationInfo` is otherwise an opaque app-defined map, but every
key under the `derec.` prefix is reserved for the protocol. Today the
library owns `derec.replica_id`; future protocol additions will use
the same namespace. Application code must not write any `derec.*`
entry — the orchestrator silently overwrites or strips library-owned
keys at the protocol boundary, and app-set values are lost without
warning.

---

## Documentation

- DeRec Alliance: https://derec.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
