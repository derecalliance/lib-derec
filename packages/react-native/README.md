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

const protocol = new DeRecProtocolBuilder(secretId) // bigint | number
  .withChannelStore(myChannelStore)
  .withShareStore(myShareStore)
  .withSecretStore(mySecretStore)
  .withUserSecretStore(myUserSecretStore)
  .withStateStore(myStateStore)
  .withTransport(myTransport)
  .withOwnTransport({ uri: 'https://owner.example.com', protocol: 'https' })
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

## Store interfaces

The application layer owns all persistence; the library never writes to disk
directly. `DeRecProtocolBuilder` takes one implementation of each interface
declared in `src/types.ts`:

- **`ChannelStore`** — pairing state: helper channels and replica-group
  membership, keyed by `(channelId, replicaId)`.
- **`ShareStore`** — versioned VSS shares this device holds as a helper.
- **`SecretStore`** — small per-channel key material (shared keys, etc.),
  distinct from share bytes.
- **`UserSecretStore`** — the most recent user-facing secret snapshot per
  `secretId`, used to auto-publish to newly paired peers.
- **`StateStore`** — in-flight orchestrator bookkeeping (pending
  verifications, recoveries, unpairs, sharing rounds, sync checks) so a
  multi-round flow survives an app restart.
- **`Transport`** — outbound delivery. `send(endpoint, message)` posts a
  wire-format envelope to a peer; it is a mailbox, not a request/response
  call, since not every peer (e.g. a phone behind NAT) can be dialed back.

Every method is `async` and keyed by decimal-string ids — see the next
section for why that differs from `DeRecProtocol`'s own methods. Full field-
level contracts are documented as TSDoc on each interface in `src/types.ts`.

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

**`setCommunicationInfo()` and `setOwnTransport()` return a `Promise`.**
`@derec-alliance/nodejs` declares both `void`. Here they must not run on the
JavaScript thread: the underlying FFI setter takes the same handle lock a
running flow holds across its store callbacks, and those callbacks block the
worker until JavaScript settles them — so a synchronous setter would block
the JavaScript thread on a lock only the JavaScript thread can release. The
binding queues them onto the same serial worker every flow runs on instead.
The nodejs SDK is WASM and single-threaded, so it cannot hit this. Code that
ignores the return value — the way nodejs code calls these — is unaffected;
awaiting them additionally lets a failure surface instead of vanishing.

**The `DeRecErrorCategory` union differs from nodejs's.** This SDK's union
omits `"wasm"`, which a C-ABI binding can never emit, and adds `"ok"`,
`"ffi"` and `"state_store"`, which it can. A test pins the union to
`bindings/test_fixture/enums.json` so it stays in step with the Rust enum.

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
