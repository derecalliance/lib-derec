# DeRec React Native SDK

React Native bindings for `derec-library`, the Rust SDK implementing the
DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted
shares across trusted helpers. This package exposes the Rust core to
JavaScript/TypeScript through a JSI (JavaScript Interface) native module —
all cryptography, protobuf handling and protocol validation run in native
code; the JS side only marshals arguments and results.

---

## Installation

```bash
npm install @derec-alliance/react-native
```

or with yarn:

```bash
yarn add @derec-alliance/react-native
```

iOS additionally requires a pod install:

```bash
cd ios && pod install
```

Autolinking picks up the podspec and the Android Gradle module automatically
via `react-native.config.js` — no manual native project edits are needed on
either platform.

---

## Requirements

| | |
|---|---|
| `react-native` | >= 0.76.0 |
| `react` | >= 18.2.0 |
| iOS deployment target | 13.4+ |
| Android `minSdk` | 24 |

This package ships a compiled C++/JSI native module (an iOS XCFramework and
per-ABI Android static libraries). **It cannot run inside Expo Go.** Expo Go
is a fixed, pre-built binary that only contains the native modules Expo
shipped with it — any package with custom native code, this one included,
requires an [Expo dev build](https://docs.expo.dev/develop/development-builds/introduction/)
(`npx expo run:ios` / `npx expo run:android`, or `eas build --profile
development`) instead. This is not specific to DeRec; it is true of every
React Native library that ships native code.

Plain (non-Expo) React Native projects are unaffected — a normal debug or
release build already includes whatever native modules are linked in.

---

## Protocol schema

The package ships the DeRec `.proto` schema under `schema/` so you can
generate code for any language without a `lib-derec` checkout:

- `schema/proto/` — the 18 schema files, flat. Every import is a bare
  filename, so a single include root resolves the whole closure:
  `protoc --proto_path=node_modules/@derec-alliance/react-native/schema/proto node_modules/@derec-alliance/react-native/schema/proto/*.proto`
- `schema/derec_descriptor.bin` — the same closure precompiled, well-known
  types included. Needs no include path at all. Compiled with
  `--include_source_info`, so code generated from it keeps the protocol's doc
  comments instead of emitting bare type declarations.

The schema is versioned with the package: `vX.Y.Z` carries exactly the schema
`vX.Y.Z` was built from.

---

## Quickstart: pairing two devices

`DeRecProtocol` is the orchestrator: it owns protocol state, drives flows to
completion, and reports progress as `DeRecEvent`s. Build one with
`DeRecProtocolBuilder`, supplying an implementation of each store interface
and a `Transport` for sending outbound messages:

```ts
import {
  ContactMode,
  DeRecProtocolBuilder,
  FlowKind,
  SenderKind,
} from '@derec-alliance/react-native';

// withStores sets all five stores in one call. Each with*Store setter is
// still available; the last call for a store wins.
const protocol = new DeRecProtocolBuilder(secretId) // bigint | number
  .withStores({
    channelStore: myChannelStore,
    shareStore: myShareStore,
    secretStore: mySecretStore,
    userSecretStore: myUserSecretStore,
    stateStore: myStateStore,
  })
  .withTransport(myTransport)
  .withOwnTransports([{ uri: 'https://owner.example.com', protocol: 'https' }])
  .withThreshold(2)
  .build();

// Out-of-band: hand `contact` to the peer (QR code, deep link, ...).
const contact = await protocol.createContact(null, ContactMode.InlineKeys);

// Peer side, once it has `contact`:
// const events = await peerProtocol.start(FlowKind.Pairing, {
//   kind: SenderKind.Helper,
//   contact,
// });

// Owner side, once the peer's response arrives over your transport:
const events = await protocol.process(responseBytes);
for (const event of events) {
  if (event.type === 'PairingCompleted') {
    // event.channel_id is the long-term id both sides rotated to.
  }
}
```

`protocol.free()` releases the native handle once the protocol instance is no
longer needed (safe to call more than once).

---

## Verification outcomes

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
  reject.
- `ShareVerifyRejected { status, memo }` — the helper refused the challenge
  with a non-OK status.
- `VerifySharesFailed { reason, error }` — no verdict could be reached on
  this device. `reason` is a `VerifyFailureReason`: `'NoSharedKey'`,
  `'NoProof'` or `'DispatchFailed'`.

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
`reason: 'NoProof'`. Verify only versions whose round
completed (`SharingComplete`). Starting verification on a channel with no
proof sends nothing and returns `VerifySharesFailed` with
`reason: 'NoProof'` at once. A late response to an earlier challenge is
ignored as `MessageIgnored` with `reason: 'StaleResponse'`, and the current
challenge stays open; a response missing its `result` is still an error.

**After recovery: restore or join.** `SecretRecovered` writes nothing, so
decide before calling `restore`. When `secret.replicas?.members` names live
members other than the lost device, do not restore: tell the user and offer
to join that group as a new replica — pair with a live member, confirm the
fingerprint, then run `start(FlowKind.ReplicaDiscovery)`. With no live member, restore. Neither path gives this device the proofs of
earlier versions, so it cannot verify them: restore writes none, and a
joining device gets only the share map of the single version each push or
catch-up carries. The live members keep the proofs they hold. A restored
device also cannot publish, or answer a member's catch-up, until the app
configures a `replica_id` the roster names. Joining adds the device as a new
member, while restoring next to live replicas makes a second device claim
the lost device's role. See
[Restore or join](https://derec-alliance.gitbook.io/docs/concepts/replicas/restore-or-join).

Every channel message carries one timestamp, its send time, in both the
envelope and the inner message. A message whose two timestamps differ, or
where either or both are absent, is ignored as `MessageIgnored` with
`reason: 'TimestampMismatch'`; this includes replies from 0.0.8 peers.

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

An inbound share the library refuses before any `ActionRequired` (undecodable,
failing its commitment, outside this device's share-size range, or conflicting
with the share stored at that version) is reported as a `ShareRefused` event
with the `status` and `memo` sent; the owner observes it as `ShareRejected`.

A replica group member's copy of the secret that does not decode or verify is
refused, nothing is written, and it is reported as a `ReplicaSecretRefused`
event with `status` and `memo`; on a push the publisher observes it as
`ReplicaSyncRejected`.

---

## Store interfaces

The application layer owns all persistence; the library never writes to disk
directly. `DeRecProtocolBuilder` takes one implementation of each interface
declared in `src/types.ts`:

- **`ChannelStore`** — pairing state: helper channels and replica-group
  membership, keyed by `(channelId, replicaId)`.
- **`ShareStore`** — versioned VSS shares this device holds as a helper.
  On an owner, `keepVersion` chooses the one older version helpers keep
  besides the one being shared (`0` keeps none); an answer equal to or
  greater than that version fails the round with `invalid_keep_version`; see
  [`DeRecShareStore::keep_version`](https://docs.rs/derec-library/latest/derec_library/protocol/traits/trait.DeRecShareStore.html#tymethod.keep_version).
- **`SecretStore`** — small per-channel key material (shared keys, etc.),
  distinct from share bytes.
- **`UserSecretStore`** — the most recent user-facing secret snapshot per
  `secretId`, used to auto-publish to newly paired peers.
- **`StateStore`** — in-flight orchestrator bookkeeping (pending
  verifications, recoveries, unpairs, sharing rounds, replica discoveries) so a
  multi-round flow survives an app restart.
- **`Transport`** — outbound delivery.
  `send(endpoints: ReadonlyArray<{ protocol: string; uri: string }>, message: Uint8Array): Promise<void>`
  posts a wire-format envelope to a peer. `endpoints` is every address that
  peer advertised, in its own order (`protocol` is `"https"` or `"grpc"`);
  deliver once, to the first one that accepts it, and reject only when none
  did. `sequentialFailover` and `singleEndpointTransport` implement that
  choice for you. It is a mailbox, not a request/response call, since not
  every peer (e.g. a phone behind NAT) can be dialed back. Recommended HTTP
  conventions (`POST`, `application/octet-stream` body, `202 Accepted`) and
  the same-connection pattern for unreachable peers are in
  [Transports](https://derec-alliance.gitbook.io/docs/protocol-specification/transports);
  they are recommendations, not protocol requirements.

Every method is `async` and keyed by decimal-string ids — see the next
section for why that differs from `DeRecProtocol`'s own methods. Full field-
level contracts are documented as TSDoc on each interface in `src/types.ts`.

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

### Refusing a share or a verification

A helper enforces share size itself: with a parameter range configured, a
share outside its own `minShareSize`/`maxShareSize` (inclusive; a max of `0` means
unbounded) is answered with `SIZE_LIMIT_EXCEEDED` before any
`ActionRequired` or auto-accept. Frequency limits on share updates and
verifications are the application's to enforce, from its share store.

On a helper channel, throw (or reject with) `shareStoreRefusal(reason)` from
`ShareStore.save` (a genuinely new share version) or
`ShareStore.recordVerification` (an accepted verification challenge) to
refuse it:

```ts
import { shareStoreRefusal } from "@derec-alliance/react-native";

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

### Filtered listings

`listHelpers` and `listReplicas` receive a filter object — `ids`, `status`,
`role` and `exclude`, where every empty value means "do not restrict on this",
so an all-empty filter selects everything. `exclude` is applied last,
overriding `ids`. Ids are decimal strings, like every other `u64` here.

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

## Threading model

The native module runs each `DeRecProtocol` instance's flow logic (`start`,
`process`, `tick`, `accept`, `restore`, ...) on a dedicated worker thread, off
the JavaScript thread, precisely because that logic calls back into your
store and transport implementations — which are themselves JavaScript and
can take an unbounded amount of time (disk I/O, network requests). Those
methods return a `Promise`.

**Primitives are the exception.** The functions under `primitives.*` (and
`envelope.*`) are pure byte transforms with no store or transport callbacks,
so they run synchronously, in-line, on the calling JavaScript thread —
including `primitives.sharing.request.split` (`protect_secret`), which does
real cryptographic work: Shamir secret splitting, AES-GCM encryption, and
Merkle tree construction over the shares. For a handful of small shares this
is fast; for larger secrets or higher share counts it will block rendering
for its duration. Applications that need this work off the JS thread should
drive it through `DeRecProtocol` (e.g. `start(FlowKind.ProtectSecret, ...)`)
instead of calling the primitive directly.

`split`'s `channels` argument is a `WeightedChannel[]` — `[channelId,
weight]` tuples, one per channel, letting a chosen channel hold more than
one subshare (e.g. a device the owner trusts more than the others). A
weight of `1` is an ordinary helper holding a single subshare, so with every
weight at `1`, `threshold` counts helpers as before. `ProtectSecretParams`
accepts an equivalent `weights: Map<bigint, number>` when driving the flow
through `DeRecProtocol`; `ProtectSecretStarted` and `ProtectSecretFailed`
report the resulting `weight` for the channel they name.

That map is the **full assignment, not a patch**: a paired helper it does not
name holds one subshare. Weights are recorded: each round writes the weight it gave every paired helper
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
with code `invalid_weight` before anything is sent, until `ProtectSecret`
assigns valid weights.

That failure surfaces where the library started the publish, and in each
case nothing is sent:

- `process()` throws an error whose `events` keep the message's events,
  `PairingCompleted` included.
- `accept()` throws. The pairing has completed and its response was sent,
  but `PairingCompleted` is not returned.
- `verifyFingerprint()` throws. The promotion stands: calling it again
  resolves `true` and publishes nothing.

Call `start` with `ProtectSecret` and valid weights to publish to every
helper.

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

`withMaxSubshares(max)` on the builder caps the total subshares one round
splits the secret into — the sum of every helper's weight. Unset means no
cap. Recovery time grows quadratically with that total (about 0.2 s at 200,
5.5 s at 1,000 and 87 s at 4,000 subshares per attempt) while splitting stays
cheap, so this is the place to bound it. A round over the cap fails
`start(FlowKind.ProtectSecret, ...)` with code `too_many_subshares` before
anything is sent; publishes the library starts itself count the stored weights
and respect it too. A cap
below the threshold makes `build()` throw `invalid_input`. The cap applies at
sharing only, never at recovery: a recovering device cannot know the cap the
shares were made under.

**Do not call protocol methods from inside a store callback.** A store
method (`load`, `save`, `remove`, ...) is invoked as a callback into
JavaScript, with the protocol's worker blocked waiting for the promise that
callback returns. Calling a `DeRecProtocol` method from inside the body of
that callback would enqueue a new unit of work onto the very worker that is
already blocked waiting for you — an unbreakable deadlock. The binding
detects this and rejects the call with an explicit error instead of hanging.

The restriction is exactly that narrow: it applies to the store method's own
body, not to the whole window your returned promise is pending, and not to
other JavaScript code that merely runs at the same time. Protocol calls from
anywhere else are always safe — the worker is serial, so they simply run
after whatever is in flight.

---

## Known differences from `@derec-alliance/nodejs`

**The `DeRecErrorCategory` union differs from nodejs's.** This SDK's union
omits `"wasm"`, which a C-ABI binding can never emit, and adds `"ok"`,
`"ffi"` and `"state_store"`, which it can. A test pins the union to the crate's shared enum fixture so it stays in step
with the Rust enum.

**`DeRecError.code` is typed `DeRecErrorCode`.** It lists exactly the codes
`derec_error_code_name` can return — no WASM-only marshalling codes, since
this SDK never goes through WASM. A test pins it to the same shared enum
fixture as `DeRecErrorCategory`.

**Ids are decimal strings in stores, `bigint | number` on `DeRecProtocol`.**
Store interfaces (`ChannelStore`, `ShareStore`, event fields such as
`channel_id` / `replica_id`, etc.) use decimal strings for every `u64` id,
matching the TypeScript store contracts and avoiding the precision loss a
JS `number` would suffer above 2^53. `DeRecProtocol`'s own methods
(`createContact`, `getFingerprint`, `verifyFingerprint`, the builder's
`withReplicaId`, ...) instead take `bigint | number` directly, since those
call sites hand the id straight to the native layer rather than round-
tripping it through storage. Both conventions are deliberate; keep track of
which side of the boundary an id is on rather than assuming one form
everywhere.

---

## Configuration from a file or record

Applications usually load settings as a whole: general settings from the
environment or a config file, per-user settings from a user record.
`DeRecProtocolConfig` holds every data setting of the builder, each one
optional, and `withConfig` applies it in one call:

```ts
import { DeRecProtocolBuilder } from "@derec-alliance/react-native";
import type { DeRecProtocolConfig } from "@derec-alliance/react-native";

const general: DeRecProtocolConfig = JSON.parse(generalJson);
const perUser: DeRecProtocolConfig = JSON.parse(userRecordJson);

const protocol = new DeRecProtocolBuilder(secretId)
  .withChannelStore(channelStore)
  .withShareStore(shareStore)
  .withSecretStore(secretStore)
  .withUserSecretStore(userSecretStore)
  .withStateStore(stateStore)
  .withTransport(myTransport)
  .withConfig(general)   // 1. general settings
  .withConfig(perUser)   // 2. per-user settings
  .withThreshold(4)      // 3. individual setters
  .build();
```

- **Only set (present and non-`null`) fields are applied.** An absent or
  `null` field leaves whatever the builder already holds.
- **Last write wins, per field.** Nested objects replace the builder's value
  as a whole, except `timeouts`: each of its fields is merged separately, so
  a per-user config that sets only `inbound_message_secs` keeps the
  `sharing_round_secs` the general config set.
- **This binding assigns; it validates nothing.** Every key is forwarded
  verbatim, under its own spelling, into the same `snake_case` config JSON
  `build()` sends over the FFI. Rust applies the same rules a matching
  `with*` setter's value would and rejects an unknown key at any level — a
  misspelled key, or a value that fails validation, throws from `build()`
  rather than being silently ignored.
- **Stores, the transport and the constructor's `secretId` are not settings**
  and are not carried in the config.
- **A `secret_id` key in a config is ignored, not rejected.** `build()`
  assigns the constructor's `secretId` last, so a config carrying a
  `secret_id` key (for example a per-user record that includes it by
  mistake) never changes which secret this instance manages. Every other
  SDK rejects that key outright, since `DeRecProtocolConfig` has no
  `secret_id` field there and unknown keys fail.

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
`max_subshares` are `u64` values written as decimal strings. Timeouts are
whole seconds. See the `DeRecProtocolConfig` doc comment in `src/types.ts` for
every field's accepted forms.

---

## Package contents

```text
lib/            compiled TypeScript output (index.js, index.d.ts, ...)
src/            TypeScript source
cpp/            JSI native module (shared by iOS and Android)
ios/            DeRecFFI.xcframework, iOS module glue
android/        Gradle module, JNI glue
DeRec.podspec
react-native.config.js
```

---

## License

Apache License 2.0

See `LICENSE` for details.
