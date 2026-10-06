# Changelog

Notable changes to `derec-library`, `derec-proto` and `derec-cryptography`,
and to the .NET, Go, Node, React Native and web SDKs built on them.

Breaking changes are called out explicitly, with the migration alongside
them. The three crates and the SDKs share a version, so an entry applies to
all of them unless it names a specific binding.

### Unreleased

Six defects found by the reference application's QA against 0.0.6.

- **Fixed: admitting a second replica moved the group to the joiner's
  channel.** *(bug fix; every SDK)*

  When an existing member initiated the pairing, completing it re-pointed
  that member's own roster row onto the joiner's channel, so every admission
  redefined the group channel and its key, and earlier members stopped
  receiving mirrors. A member already in a group now keeps its row; only a
  device joining its first group moves onto the new channel.

- **Fixed: `UpdateChannelInfo` refused a move to a transport the receiver
  does not serve itself.** *(bug fix; every SDK)*

  Following a peer to a new endpoint only needs the receiver to reach it, and
  pairing never compares a peer's endpoints with the receiver's own. A device
  serving only gRPC could pair with an HTTPS peer but not follow that peer's
  move to a new HTTPS endpoint. The peer's endpoints are now filtered by the
  transport policy alone, when the update is accepted, as in pairing.
  `UpdateChannelInfoFailed` is now only an outbound dispatch failure.

- **Fixed: one Pending channel aborted `UpdateChannelInfo`, `Discovery` and
  `VerifyShares`.** *(bug fix; every SDK)*

  A pairing that never completed leaves a Pending channel with no shared key,
  and these flows targeted it anyway, so every later rename, address change,
  discovery or verification failed with `missing_shared_key`. They now target
  Paired channels only, as their documentation said; a Pending id named in a
  target is dropped.

- **Fixed: a replica reported an identical copy as a conflict when the
  version it held had no author.** *(bug fix; every SDK)*

  A version restored from recovery, or published before the device had a
  replica id, carries no author, and a re-sent copy of it was reported as
  `ReplicaVersionConflict` — "two replicas published different copies" —
  though nothing differed. A held version with no author is now identified by
  its user secrets: the same secrets are a re-send, different ones are still
  a conflict. Versions with an author keep the author rule.

- **Fixed: helpers ignored `keepList`.** *(bug fix; breaking — every share
  store gains a method)*

  `StoreShareRequest.keepList` is the complete set of versions a helper
  should keep, and helpers kept every version forever instead. A helper now
  deletes the versions a request's `keepList` does not name, when that
  request is at least as new as anything it holds on the channel. An empty
  `keepList` keeps everything, an older (replayed) request's list is ignored,
  and the share the request carries is never deleted. Share stores implement
  the new idempotent `remove_versions(secret_id, channel_id, versions)` —
  .NET `IShareStore.RemoveVersions`, Go `ShareStore.RemoveVersions`,
  TypeScript `ShareStore.removeVersions` — and the C ABI
  `ShareStoreCallbacks` gains a `remove_versions` slot before `free_buffer`.

- **Added: `ShareVerifyRejected { channel_id, version, status, memo }`.**
  *(new event; every SDK)*

  A helper that refused a verification challenge surfaced only as an error
  from `process()`, with no event, so the owner could not tell which helper
  said no. The refusal is now this event, mirroring `ShareRejected`. The
  challenge is consumed; checking that helper again takes a new
  `VerifyShares` round.

- **Docs: what an application must do on a replica version conflict.**

  The library README and the `ReplicaVersionConflict` / `ReplicaSyncRejected`
  docs in every SDK now state the rule: once either event reports a conflict,
  the device must not publish again until the user has resolved it, because a
  further `ProtectSecret` is a higher version that replaces every other
  member's copy. The README gives the steps — get the rival copy, merge,
  publish once — and notes that a member that was offline while another
  published reaches the same conflict without any simultaneous edit.

- **Docs: where the application asks the user.**

  Two decisions belong to the application, and the docs in every SDK now say
  so. Recovery and restore are separate steps: `SecretRecovered` writes
  nothing, so the application shows the recovered secret, or asks, before
  calling `restore`. On a replica destination, confirming the fingerprint is
  also the decision to adopt the group's vault — its publishes are installed
  as they arrive — so the application asks before calling
  `verify_fingerprint`, and declines by never confirming.

- **Docs: who may remove a replica member, and what the removed one sees.**

  `UnpairReplica` and `SelfRemovedFromGroup` in every SDK now state that any
  member may remove any member, the source included — so a lost or stolen
  source can be removed — with no role check, and that the application should
  ask the user first. They name the successor rule (the first remaining member
  in the channel store's replica order) and that the removed member is not
  asked and gets no warning: its partition is dropped automatically when a
  roster excluding it arrives, while the secret survives on the remaining
  members and the helpers.

- **Docs: how a replica member announces a new endpoint or
  `communication_info`.**

  `UpdateChannelInfo` reaches helper channels only; a replica member's values
  travel in the roster. The library README now describes the procedure:
  publish a new version, so every replica and the recoverable roster carry
  the new values, then run `UpdateChannelInfo` against the helpers, keeping
  the old endpoint serving until enough peers have the update. The
  "Updating channel info post-pairing" section also drops its description of
  a servability refusal that no longer exists, and the removed
  `set_own_transport` / `transport_protocol` names. The SDK READMEs point to
  the procedure.

### 0.0.6

Two security fixes and fifteen defects. Every message on a channel was encrypted
under the same AES-GCM nonce, which exposes its contents and lets an attacker
forge messages. A replica destination acted on its source's roster before
confirming the fingerprint, so the check that stops a man-in-the-middle ran
after the fact. Replica catch-up did not work from any SDK but Rust, and a
pulled copy reported the wrong secret id. The Node.js and web SDKs could hang when two calls overlapped on one
`DeRecProtocol` instance, and the React Native SDK on iOS could silently produce
malformed messages. A published replica roster did not name, or list every
endpoint of, the device that published it. Dropped messages now surface as a
`MessageIgnored` event that says why. Replicas now detect two members
publishing the same version, instead of silently applying whichever copy
arrived last. A parity audit of every SDK against the core found eight more
defects: four that lose data or reachability (React Native helpers stored
shares under the wrong secret id and could not reach gRPC peers; .NET never
sent its `communication_info`; .NET and Go keyed every sharing round alike),
and four in error reporting and FFI signatures.

**Breaking:** the deprecation wave announced in 0.0.3 for removal at 0.0.5 is
removed, in every binding. See the first entry below for the migration.

- **Removed: the single-endpoint and `unsafe_http` spellings deprecated in
  0.0.3.** *(breaking; every SDK and the wire schema)*

  0.0.3 deprecated these for removal at 0.0.5, and 0.0.5 shipped them anyway.
  They are gone now, with nothing deprecated left behind.

  | Removed | Use instead |
  |---|---|
  | Rust `with_own_transport` · .NET `WithOwnTransport` · Go `Config.OwnTransportURI` / `OwnTransportProtocol` · Node.js / web / React Native `withOwnTransport` | `with_own_transports` · `WithOwnTransports` · `Config.OwnTransports` · `withOwnTransports`, with a one-element list |
  | Rust `set_own_transport` · .NET `SetOwnTransport` · Go `SetOwnTransport` · TS `setOwnTransport` · C `derec_protocol_set_own_transport` | `set_own_transports` and its counterparts, with the whole list |
  | Rust `with_unsafe_http` · .NET `WithUnsafeHttp` · Go `Config.UnsafeHTTP` · TS `withUnsafeHttp` | `with_unsafe_connection` and its counterparts, which gate both `http://` and `grpc://` |
  | `TransportValidationError::UnknownProtocol` | `TransportValidationError::UnsupportedProtocol` |
  | `transport_protocol` on the `UpdateChannelInfo` flow parameters | `own_transports` |

  `Error::ConflictingPlaintextOptIn` (FFI code `122`, `CONFLICTING_PLAINTEXT_OPT_IN`
  in TypeScript) existed only to reconcile `unsafe_http` with
  `unsafe_connection` and is removed with it; code `122` is retired and will
  not be reassigned. The FFI `derec_protocol_new` config no longer accepts
  `own_transport_uri`, `own_transport_protocol` or `unsafe_http`: pass
  `own_transports` and `unsafe_connection`.

  **On the wire,** the singular `transportProtocol` is gone from
  `ContactMessage`, `PairRequestMessage`, `PrePairRequestMessage` and
  `UpdateChannelInfoRequestMessage`, and the singular `replyTo` from the five
  request messages that carry `replyToTransports`. Their field numbers and
  names are `reserved`. The message DTOs drop their `transport_protocol` key
  accordingly. Peers on 0.0.3 through 0.0.5 already read the lists first, so
  they keep pairing and replying with 0.0.6; a peer older than 0.0.3, which
  reads only the singular fields, cannot. One exchange does not survive the
  mix: a 0.0.5-or-earlier peer refuses an `UpdateChannelInfo` that announces
  new endpoints without also carrying `communicationInfo`, because it decides
  whether the update is empty from the singular field. Upgrade both sides
  before moving endpoints, or send the update with `communication_info` set.

  The `advertisedEndpoints` and reply-to helpers stay in every SDK and now
  read the list alone.

- **Fixed (security): every message on a channel was encrypted with the same
  AES-GCM nonce.** *(bug fix; every SDK — wire-compatible)*

  Channel messages are encrypted under the pair's long-lived shared key, and
  the nonce was built from the channel id in bytes that the cipher never
  reads. So all messages on a channel used the same all-zero 96-bit nonce under
  the same key. With AES-GCM that is catastrophic: an eavesdropper learns the
  XOR of any two plaintexts, and can recover the authentication key and forge
  messages that pass the tag check. Each message now draws a fresh random
  nonce. Receivers already read the nonce from the ciphertext's first 12
  bytes, so old and new peers interoperate in both directions. Messages
  already exchanged under the reused nonce stay exposed; re-pairing rotates
  the key for any channel whose past traffic must be treated as compromised.

- **Fixed (security): a replica destination acted on its source before
  confirming the fingerprint.** *(bug fix; every SDK — wire-compatible)*

  The fingerprint comparison is the only defence against a man-in-the-middle on
  a replica channel. `process` ignored messages on a `Pending` channel, but it
  found the status only on a helper record. Replica members record theirs
  separately, so a replica channel was never gated. A destination that had not
  confirmed still took the source's first copy: it wrote the roster, helper
  keys and share map to its stores, marked every group member `Paired`, and
  acknowledged `Ok`. The source then reported the destination in sync. And
  because the roster marked the destination `Paired`, it became a full group
  member whether or not its user ever confirmed. This was easy to hit, because
  the source's own confirmation publishes the vault at once and that copy
  usually arrives first.

  A message on a channel with a `Pending` replica member is now ignored like
  one on a `Pending` helper channel: no store is written and nothing is sent
  back. Confirming does not replay the dropped copy. The destination pulls it
  after confirming, with `start(ReplicaDiscovery)`. Traffic on an established
  group channel is unaffected, because a pairing in progress leaves `Pending`
  rows only on its own pairing channel.

- **Added: `MessageIgnored { channel_id, reason, trace_id }`.** *(new event;
  every SDK — see the behavior change below)*

  A dropped message used to come back as a bare `NoOp`, which carries nothing
  and looks exactly like an acknowledgement. An application had no way to tell
  its user a copy was waiting on their confirmation. `reason` is
  `PendingVerification` or `Expired` (older than the inbound timeout).
  `trace_id` matches the peer's `*Started` event for the same round. The Rust
  type is `IgnoreReason`; the other SDKs get string labels, like
  `ActionRequired.action_kind` (Go `IgnoreReason*` constants, .NET
  `IgnoreReason` constants, a TypeScript `IgnoreReason` union).

  **Behavior change.** Messages dropped for either reason, including on a
  pending *helper* channel, now produce `MessageIgnored` instead of `NoOp`. Code
  that counted `NoOp`s to detect a drop should match `MessageIgnored` instead.
  `NoOp` remains for messages that genuinely have no effect, such as
  acknowledgements.

- **Fixed: a pulled replica copy reported the wrong `secret_id`.** *(bug fix;
  every SDK — wire-compatible)*

  `ReplicaSecretInstalled` and `ReplicaSecretReceived` carry the secret id of
  the vault being mirrored. A pushed copy reported the sender's id, but a copy
  pulled by `ReplicaDiscovery` reported the destination's own. An application
  that compares that id with its own to choose between "an update to my vault"
  and "an offer to take over another vault" therefore applied a pulled first
  copy silently, without the adoption prompt. With the fingerprint fix above, a
  pull is how a destination normally receives its first copy. Both paths now
  report the sender's id, which the serving member already put on the wire.

- **Fixed: replica catch-up (`ReplicaDiscovery`) never completed outside Rust.**
  *(bug fix; .NET, Go, Node.js, web and React Native — rows written by 0.0.5
  still decode)*

  An in-flight catch-up is stored as a state row. Its JSON put the device's
  local version in `version`, a field that is part of the row's key for other
  kinds but absent from this one's key. Every SDK store derives a row's key
  from those fields, as the store contract says, so the round was saved under
  one key and looked up under another. The answers then arrived as `NoOp` and
  the catch-up never finished. The Go and .NET SDKs had no support for this row
  kind at all: Go filed it under the sharing round's key and failed to encode
  it, and .NET threw on it.

  The local version now travels in its own `local_version` field, so an item's
  key fields always equal its key's. A test in the core pins that invariant for
  every state kind. Go and .NET decode and encode the row and key it correctly.
  Rust callers were unaffected, since Rust stores receive typed values.

- **Fixed: overlapping calls on one `DeRecProtocol` instance hung instead of
  queueing.** *(bug fix; Node.js and web only — **breaking** for the three
  `set*` setters, see below)*

  Every state-touching method took the instance mutably, and wasm-bindgen holds
  that borrow for the whole life of an async call. A second call issued while
  the first was awaiting a store or the transport — a `tick()` timer firing
  while `process()` handled an inbound message, which is the pattern `tick()`'s
  own documentation recommends — failed that borrow outside any promise. The
  page got an uncaught `recursive use of an object detected which would lead to
  unsafe aliasing in rust`, and the calls involved never settled, neither
  resolving nor rejecting, so a flow simply stalled until the application's own
  timeout. The FFI-based SDKs never had this: their handle has always
  serialized calls behind a mutex.

  Each instance now holds its state behind an async lock taken inside every
  call. Overlapping calls on one instance queue and run one at a time, in the
  order they were made. Applications that already serialized calls per instance
  keep working unchanged; that lock is now redundant. Distinct instances do not
  share the lock, so two instances bound to the same `secretId` and the same
  stores must still be serialized by the caller.

  Two consequences to be aware of:

  - A store or transport callback must not await a call on the instance that
    invoked it. That call queues behind the one waiting on the callback, and
    neither settles.
  - Calling `free()` while a call is in flight throws.

  **Breaking — migration.** `setCommunicationInfo`, `setOwnTransport` and
  `setOwnTransports` now return `Promise<void>`, because they queue behind
  in-flight calls like everything else. `await` them. A validation failure
  (`invalid_own_transport`, `invalid_protocol`, `invalid_communication_info`)
  now rejects the promise instead of throwing synchronously; a call site that
  does not await it turns that error into an unhandled rejection.

  ```ts
  // before
  protocol.setOwnTransports([{ uri, protocol: "https" }]);
  // after
  await protocol.setOwnTransports([{ uri, protocol: "https" }]);
  ```

  `secretId()` stays synchronous and never waits behind an in-flight call.

- **Fixed: the React Native SDK on iOS could emit malformed protocol
  messages.** *(bug fix; React Native iOS only — no API change)*

  The iOS static libraries were stripped of debug info with Apple's `strip -S`.
  Rust gives each copy of a symbol shared between codegen units a distinct
  `.llvm.<hash>` suffix; that tool drops the suffixes, so different function
  bodies ended up under one name and the app's linker bound some calls to the
  wrong one. The app still linked and ran, but some encodes came out wrong —
  most visibly a random `u64` written as a truncated protobuf varint — which
  the receiving side rejected with `protobuf_decode`. Which call failed varied
  from run to run with the random values involved, so the failure looked
  intermittent. Android was never affected: its libraries were already stripped
  with `llvm-strip`.

  The iOS libraries are now stripped with the same `llvm-strip --strip-debug`
  as Android, and packaging links every archive member into a stub executable
  (`-all_load`) per slice, so this failure mode stops the build instead of
  shipping. **React Native iOS apps on 0.0.5 or earlier should upgrade**;
  messages those builds sent may have been rejected by their peers.

- **Fixed: a replica roster described every member except the one that
  published it.** *(bug fix; every SDK — wire-compatible, no API change)*

  A device recorded each peer in its group with every endpoint and the
  `communication_info` that peer advertised at pairing, but recorded itself
  with only its primary endpoint and an empty `communication_info`. Each
  version's `Secret.replicas.members` is built from those records, so the
  member that wrote it had no name and a single address. Anything rebuilding
  the group from a `Secret` — a destination adopting a copy, a device
  restoring — could neither name that member nor reach it on its other
  endpoints. A device's own record now carries its full endpoint list and its
  `communication_info`, filtered as a peer would store it, and every publish
  fills both in from the instance's current configuration. Groups paired on
  an earlier version are corrected by their next publish.

- **Fixed: a replica silently replaced the version it held with a rival copy
  of it.** *(bug fix; every SDK — the replica wire payload gains a field, and
  `ShareStored` loses one)*

  Every member derives the next version from what it holds, so two members
  that change the group at the same time — one pairing a helper, another
  editing the secrets — both publish the same version. A replica applied
  whichever copy arrived last, and applied an older version over a newer one,
  without telling anyone. Helpers keep the first copy they receive, so the
  replica could end up tracking shares its helpers never held, and
  verification then reported healthy helpers as corrupt.

  Each version now records the member that published it. The replica payload
  carries `author_replica_id`, every publish sets it — whether the secrets or
  only the roster changed — and every member stores it with the version in its
  `UserSecrets` snapshot. A copy arriving by push or by catch-up is then
  compared with the one held:

  | Arriving copy | Result |
  |---|---|
  | Newer, or nothing held | Applied, as before |
  | Same version, same author | A re-send: acknowledged, nothing rewritten |
  | Same version, another or unknown author | Refused with `VERSION_CONFLICT`; the new `ReplicaVersionConflict` event reports both authors and the incoming state |
  | Older | Refused with `VERSION_CONFLICT`; nothing changes |

  Nothing is written on a conflict. The application resolves it by publishing
  the reconciled state with `ProtectSecret`, which writes the next version on
  every member and helper. The publisher whose copy was refused sees
  `ReplicaSyncRejected`.

  `ReplicaSecretReceived` and `ReplicaSecretInstalled` gain
  `author_replica_id`. `from_replica_id` keeps naming the member a copy came
  from, which on a catch-up is whoever answered rather than the author.

  **Store implementations must persist `author_replica_id`** on the
  `UserSecrets` snapshot (FFI and JavaScript stores: an optional decimal
  string). A store that drops it makes every copy of the held version look
  like a conflict. The SQLite and Postgres reference stores add it in a
  migration.

  `ShareStored` loses `replica_id`. A helper never learns which replica wrote
  a share — helper-bound requests carry no replica identity by design — so the
  field could only ever be empty.

- **SDK parity: what the core already offered is now reachable from every
  binding.** *(feature; breaking where noted)*

  | Change | SDKs |
  |---|---|
  | `StatusEnum`, and `reject(action, status: StatusEnum, memo)` — previously a bare number the docs could not name | Node.js, web, React Native |
  | `protocol_version()` / `CurrentProtocolVersion()` for audit and logs, read from the core | Go, Node.js, web, React Native (.NET already had `ProtocolVersion.Current()`) |
  | Readable error names from the core: `DeRecException.CategoryName` / `CodeName` (.NET), `Error.CategoryName()` / `CodeName()` (Go) | .NET, Go |
  | `reply_to` on the five request primitives — **breaking**: `Request.Produce` gains a trailing `replyTo` argument | Go |
  | `ContactMessage.FromProtoBytes` / `ToProtoBytes` are public, so an app can inspect a contact it received out of band; `ContactMessage` gains `Timestamp`, which encode/decode used to drop | .NET |
  | `nonce` on `primitives.pairing.request.create_contact` — typed in Node.js and web, and **fixed** in React Native, which ignored it, so a NoKeys contact could not be created there | Node.js, web, React Native |
  | `ActionRequired` carries what accepting would do: `trace_id` always; `share_size` on StoreShare (the size or quota decision `AutoAcceptPolicy.storeShare` defers to the application); the requested `share_secret_id` / `version` on GetShare; `unpair_memo` on Unpair; `updated_communication_info` / `updated_transports` on UpdateChannelInfo. .NET also gains the fields it dropped (`action_kind`, `peer_communication_info`, `sender_kind`, `version`, `share_description`, `share_secret_id`) and a `PendingActionKind` vocabulary | every SDK |
  | `generate_replica_id()`, minted by the core — which also stops it ever returning `0`, an invalid replica id. New C export: `derec_generate_replica_id` | every SDK |
  | A restore refused because channels already exist reports which ones as a list, not only in the message text: `derec_protocol_restore` returns `DeRecProtocolRestoreResult`, whose `conflicting_channel_ids_json` the SDKs surface on the restore error — **breaking** for direct C ABI callers | .NET, Go, React Native (Node.js and web already had `channel_ids`) |
  | NoKeys pre-pair primitives (`produce_pre_pair_no_keys`, `process_pre_pair_no_keys`) and a pairing `fingerprint(shared_key)` primitive, so a NoKeys pairing can be completed — and confirmed out of band, as the mode requires — without the protocol layer. New C exports: `produce_pre_pair_no_keys_response_message`, `process_pre_pair_no_keys_response_message`, `pairing_fingerprint` | every SDK |

  `derec.Error` in Go is now an alias of the same type, defined where the
  native layer can build it; fields, constants and `errors.As` are unchanged.

  `DeRecProtocol::replica_id()` is removed from the Rust API *(breaking:
  Rust)*. It returned the id the application itself passed to
  `with_replica_id`, which nothing in the protocol ever changes.

- **Fixed: a React Native helper stored every share under its own secret id.**
  *(bug fix; React Native)*

  A helper keeps the shares of other people's secrets in one partition and
  tells them apart by `Share.secretId`, the owner's id. The share store's
  `save` callback replaced it with the partition id, so discovery and recovery
  on a React Native helper could return the wrong secret, or none. The record's
  own `secret_id` now reaches the store unchanged.

- **Fixed: React Native could not reach gRPC peers.** *(bug fix; React Native)*

  Endpoints reached `Transport.send` with `protocol: "unknown"` for anything
  but HTTPS, because the binding kept its own name table. Protocol names now
  come from the core in both directions, through the new C exports
  `derec_transport_protocol_name` and `derec_transport_protocol_discriminant`;
  an endpoint whose protocol the core does not define fails the send instead of
  reaching the application with a name it cannot act on.

- **Fixed: .NET never told peers its `communication_info`.** *(bug fix; .NET)*

  `WithCommunicationInfo` was stored by the builder and never handed to the
  core, so pairing sent no name or contact details for a .NET device. It is now
  encoded and passed at construction, as the Go SDK already did.

- **Fixed: .NET and Go keyed every sharing round alike.** *(bug fix; .NET, Go —
  breaking for .NET: `StateKey.SharingRound()` now takes the round's version)*

  The core keys an in-flight sharing round by its version, so concurrent rounds
  keep separate rows. Both SDKs dropped the version from the key, so a store
  keyed on it let one round overwrite another and neither completed. The key
  now carries the version in both directions.

- **Fixed: .NET garbled non-ASCII text from the core on Windows.**
  *(bug fix; .NET)*

  Error messages and memos were decoded as ANSI rather than UTF-8.

- **Fixed: most Node.js and web methods reported every failure as
  `DEREC_ERROR`.** *(bug fix; Node.js, web)*

  `createContact`, `start`, `accept`, `reject`, `getFingerprint`,
  `verifyFingerprint`, `removeExpiredChannels` and `process` now raise the same
  structured `{ category, code }` error as `build` and `restore`. `process`
  errors keep their `channel_id`. `DeRecErrorCategory` gains `"state_store"`,
  which the core already emitted.

- **Fixed: error code 121 had no name.** *(bug fix; every FFI SDK)*

  `derec_error_code_name(121)` returned `"unknown"`; it now returns
  `"no_usable_endpoint"`. The test that guards this reads every code from the
  source instead of a hand-kept list, which is how 121 was missed.

- **Fixed: the .NET and Go store-share request passed two arguments the C
  function no longer takes.** *(bug fix; .NET, Go — breaking for .NET:
  `Sharing.Request.Produce` loses its unused `replicaId` argument)*

  It worked only because the calling convention ignores extra trailing
  arguments. Every other binding signature in both SDKs was checked against the
  generated header and matches.

- **Changed: the SDKs no longer decide anything the core decides.**
  *(behaviour change; every SDK — breaking for Go, see below)*

  Every default, range check and validation rule now lives only in the core,
  so a value the application passes reaches the library unchanged and every SDK
  rejects the same inputs with the same error.

  - **Defaults.** An optional builder setter that is not called leaves the
    library default in force. The .NET and web/Node.js builders no longer
    restate threshold and keep-versions (3), unpair-ack, the boolean flags or
    the auto-accept policy; React Native no longer fills in auto-accept or
    parameter-range fields.
  - **Go, breaking.** `Config.Threshold` and `Config.KeepVersionsCount` are
    `*uint32`: `nil` takes the default, and an explicit `0` reaches the
    library, which rejects it (it used to be dropped, and the default of 3 used
    instead). `Timeouts` takes whole seconds as `InboundMessageSecs`,
    `SharingRoundSecs` and `UnpairAckSecs` (`*uint64`) instead of
    `time.Duration`, which truncated sub-second values to 0.
  - **.NET timeouts.** `Timeouts` values cross unchanged; a negative or
    fractional number of seconds is refused at `Build()` (`FfiBadProto`)
    instead of being clamped to 0 or rounded down.
  - **Checks moved out of the wrappers.** .NET `SetOwnTransports([])` and a
    shared key that is not 32 bytes in the .NET sharing primitives now raise
    `DeRecException` (`InvalidInput`, `FfiBadSharedKey`) from the library
    instead of `ArgumentException`. Go store codecs no longer re-check
    records: shared-key length, per-kind required state fields, unknown kinds
    and channel-record variants are enforced only by the library, which now has
    tests for each.
  - **Legacy shapes.** .NET no longer reads `transport_uri`, a missing
    `protocol`, or `version` as a catch-up's `local_version`, and passes
    `StateItem` fields through as written (a null replica set stays null). The
    library never emits those shapes; reading rows written by older versions
    stays in the core.
  - **`unpairAck` names.** Web/Node.js `withUnpairAck` accepts exactly
    `"required"` or `"not_required"`; the aliases and case-insensitive matching
    are gone. React Native forwards the name and the library validates it.
  - **No logging from the library.** Web/Node.js `process()` no longer writes
    to `console.error`; failures arrive only through the rejected promise.

- **Changed: an application must give at least one own transport.**
  *(breaking for Go and React Native; every SDK now behaves alike)*

  A node with no endpoint cannot be reached by any peer: every pairing message
  advertises it, and every later reply is sent to it. The Rust builder, the
  Node.js/web SDKs and .NET already refused an empty list, but the FFI
  constructor used by Go and React Native accepted one and advertised a
  placeholder empty URI until `setOwnTransports` was called. `build()` / `New`
  now refuses an absent or empty list in every SDK with the library's
  `InvalidInput` error (.NET used to throw `InvalidOperationException`, and
  Node.js/web `BUILDER_MISSING`). `setOwnTransports` still replaces the list
  later, and still refuses an empty one.

- **Changed: every SDK reports the same error codes.** *(breaking; Node.js,
  web)*

  A library error is classified once, in the core, into a category and a
  code. The C ABI carries the numbers and the Node.js/web SDKs carry the names,
  both from that one table, so the same failure reads the same everywhere.
  Codes are lowercase snake_case, as React Native, .NET and Go already
  reported them. Node.js/web codes change:

  | Before | Now |
  |---|---|
  | Every code in `UPPER_SNAKE` | The same name in `lower_snake` (`INVALID_INPUT` → `invalid_input`) |
  | `CONFLICT` | `restore_conflict` |
  | `INVARIANT_VIOLATED` | `invariant` |
  | `DECODE_ERROR` / `ENCODE_ERROR` from the library (category `protobuf`) | `protobuf_decode` / `protobuf_encode` |
  | `PAIRING_ENCRYPTION` | `encryption` |
  | `CONTACT_MESSAGE_KEYGEN` / `PAIR_REQUEST_KEYGEN` | `keygen` |

  Errors a binding raises before a value reaches the library keep their own
  category: `wasm` in Node.js/web (for example `decode_error`,
  `invalid_unpair_ack`) and `ffi` in React Native, .NET and Go (the `ffi_*`
  codes).

- **Changed: a transport endpoint names its protocol everywhere an
  application sees one.** *(breaking; every SDK)*

  Node.js/web and React Native took `"https"` / `"grpc"` when building and in
  `setOwnTransports`, but `0` / `1` in `UpdateChannelInfo` params, in every
  event's `transports` / `updated_transports`, and in the `restore` input, so
  an endpoint read from an event could not be passed back as it was. Every
  app-facing endpoint is now `{ uri, protocol: "https" | "grpc" }`: the event
  JSON every SDK decodes carries the name, `restore` takes the name, and the
  TypeScript packages share one `Endpoint` type. .NET and Go decode the name
  into their typed protocol, through the core's
  `derec_transport_protocol_name` / `_discriminant`. FFI inputs
  (`own_transports`, `set_own_transports`, `UpdateChannelInfo` params) accept
  the name or the discriminant. Stored channel records and the primitives'
  message types keep the discriminant.

- **Changed: .NET and Go hand out typed ids, roles, statuses and sender
  kinds.** *(breaking;
  .NET, Go)*

  - Every `u64` id on an event, on the recovered `Secret` and on flow params
    is `ulong` / `uint64` instead of a decimal string, so an id from an event
    goes straight into a method that takes one. The JSON exchanged with the
    core is unchanged, and ids up to `u64::MAX` round-trip exactly.
  - A replica member's `Role` is the typed `ReplicaRole` instead of a
    string; any role other than `"Source"` / `"Destination"` fails to decode.
    .NET `ReplicaRole` serializes by name.
  - `RejectAsync` / `Reject` take the protobuf `StatusEnum` instead of a raw
    integer, as Rust and TypeScript do.
  - Go `PairingParams.Kind`, `Event.Kind` and `Event.SenderKind` are the typed
    `protocol.SenderKind` instead of `int32`, and `pairing.SenderKind` is the
    same type, as .NET and TypeScript have one `SenderKind`. The wire value is
    unchanged.
  - Go `Share` loses `ReplicaID`, which no other SDK has and the library
    never filled.
  - The `status` of `ShareRejected`, `UnpairRejected`, `PrePairRejected`,
    `ChannelInfoUpdateRejected`, `ReplicaSyncRejected` and `ReplicaSecretAcked`
    is the typed `StatusEnum` in every SDK (it was a raw integer in .NET, Go
    and the TypeScript typings), the same type `reject` takes.
  - .NET omits `communication_info` for a helper or member with no entries
    when it sends a recovered `Secret` to `RestoreAsync`, as the core does,
    instead of writing `{}`.
  - .NET and Go pass `CommunicationInfo` to the core as the config's
    `communication_info` JSON object instead of encoding the protobuf
    themselves, so only the core knows its wire format.

- **Changed: every secret store answers a broadcast in one call.**
  *(breaking; .NET, Go, React Native, FFI)*

  The core reads every channel's secret for a broadcast (protect-secret,
  discovery, verification, update-channel-info) through the store's batch
  read. Node.js/web already called the application's `loadMany`, but the C
  ABI had no slot for it: the FFI SDKs read one channel at a time, .NET and Go
  had no batch method, and React Native required a `loadMany` it never called.
  `SecretStoreCallbacks` now has a `load_many` slot right after `load`, and
  .NET `ISecretStore.LoadMany`, Go `SecretStore.LoadMany` and React Native
  `SecretStore.loadMany` are called once per broadcast. The store returns one
  entry per requested channel, in request order, with null where nothing is
  stored; the library pairs the entries with channels, refuses an answer of
  the wrong length, and decides whether a missing entry is an error.
  `loadMany` no longer takes a `missingPolicy` argument in TypeScript.

- **Fixed: Node.js/web could not release a protocol through the typings.**
  *(bug fix; Node.js, web, React Native)*

  `DeRecProtocol` and `DeRecProtocolBuilder` live in the library's memory,
  which the JavaScript garbage collector does not reclaim in time to rely on.
  The runtime had `free()`, but the TypeScript declarations omitted it, and a
  second call threw. Both classes now declare `free()` and
  `[Symbol.dispose]()` (so `using` works), releasing twice is a no-op as with
  .NET `Dispose` and Go `Close`, and React Native's `DeRecProtocol` gains
  `[Symbol.dispose]()` too.

- **Tests: the parity guards compare declarations, not names.** *(tests)*

  A guard passed when a name appeared anywhere in an SDK's file, which is how
  a secret-store `LoadMany` required by React Native but never called got
  through. The guards now read each declaration (interface, class, record,
  struct) and compare its members both ways against the Rust source: store
  interfaces and their parameter names, protocol and builder methods, and
  record fields. A store member an SDK declares but its bridge never calls
  fails. The expected surface is derived from the Rust `pub fn`s of the
  protocol, the builder and the primitives, so a public Rust item with no FFI
  or WASM export fails unless it is listed with a reason. The .NET smoke now
  checks every section of `wire_golden.json`, and every SDK fails when the
  fixture gains a section it does not check.
  TypeScript `ChannelStore.linkChannel` now names its edge ends `a`, `b`, as
  the Rust trait does; only the parameter names change.

  `make all` now also lints with every feature enabled, which reaches the C
  ABI layer and the logging call sites that the default-feature run skipped,
  and checks formatting and lints in the SQLite and Postgres smoke crates,
  which sit outside the workspace.

- **Changed: `restore` skips a peer it cannot reach instead of refusing the
  whole secret.** *(breaking; every SDK)*

  A channel with no transport endpoint is useless, and a recovered roster can
  legitimately carry one — a legacy v2 helper whose URI scheme this library
  does not serve. `restore` refused the whole secret for it. It now writes no
  channel for that helper or replica member, restores everything else, and
  reports each skipped peer as a new `PeerNotRestored { channel_id,
  replica_id?, reason: "NoTransports" }` event (.NET `PeerNotRestoredEvent`,
  Go `EventTypePeerNotRestored`). A channel already at a skipped peer's id is
  neither a conflict nor torn down. Skipped peers are still validated, and
  every key, replica id and role is now checked before any store write; a bad
  helper key used to be found after earlier helpers were saved. The restore
  input accepts an absent or `null` `transports` as an empty list.

- **Changed: the pairing primitives enforce parameter-range compatibility
  themselves.** *(breaking; every SDK)*

  Only the protocol handlers checked that two peers' parameter ranges
  overlap, so an application pairing through the primitives skipped a rule of
  the protocol. `request::extract` and `response::process` now take the local
  `ParameterRange` (C ABI: `extract_pair_request` /
  `process_pair_response_message` gain `parameter_range_ptr/len`; .NET, Go and
  TypeScript `Extract` / `Process` gain a parameter-range argument), and
  `response::produce` refuses a request whose range does not overlap. All
  refuse with `incompatible_parameter_range`. `check_compatibility` is no
  longer public, so no binding can skip it.

- **Changed: one contact codec, in the core, for every SDK.** *(breaking;
  every SDK)*

  The contact message leaves the device as bytes (a QR code) and comes back
  as the scanner's pairing input. The encoding lived in the bindings and
  differed by SDK: .NET encoded it with its own protobuf library, Go had only
  a validator and no typed contact. New `primitives::pairing::request::
  encode_contact` / `decode_contact` are the single codec, both refusing a
  contact that breaks its mode's invariants, exposed as
  `Pairing.Request.EncodeContact` / `DecodeContact` (.NET),
  `pairing.Request.EncodeContact` / `DecodeContact` with a typed
  `pairing.ContactMessage` (Go), and `primitives.pairing.request.
  encode_contact` / `decode_contact` (Node.js, web, React Native). Removed:
  `validate_contact_message` (C ABI), `pairing_contact_message_validate`
  (WASM), Go `pairing.Request.Validate`, and .NET `ContactMessage.
  ToProtoBytes` / `FromProtoBytes`. Bytes that are not a contact now fail with
  `protobuf_decode` everywhere.

- **Tests: the web smoke runs unattended in `make all`.** *(tests)*

  It ran only when someone opened it in a browser, so `make all` never
  exercised the web package. `smoke-tests/web/run_test.sh` now builds and
  type-checks the suite, serves it, and runs it in headless Chromium through
  Playwright — the page fetches the `.wasm` over HTTP as an application does —
  and fails unless the page reports `DEREC_SMOKE_RESULT: PASS`, the same
  convention as the React Native on-device run.

- **Removed: `UserSecrets.replicas`.** *(breaking; Rust)*

  The field was written on every publish, receive and restore but never read:
  the replica group a version carries is rebuilt from the channel store each
  round, and every binding already dropped it when loading a snapshot. It also
  carried the group's shared key, so a store persisting the whole snapshot
  kept a second copy of that key for nothing. No wire or storage format
  changes.

- **Fixed: Node.js/web `restore` errors had no or the wrong `category`.**
  *(bug fix; Node.js, web)*

  `restore_conflict` carried no `category`, and `already_restored` and
  `invariant` reported `wasm`. They now carry `input` / `invariant` like every
  other library error, and `DeRecError` declares the conflict's `channel_ids`.

- **Fixed: TypeScript declared `communication_info` as always present.**
  *(bug fix; Node.js, web, React Native)*

  The library omits an empty map, so the helper and replica-member
  `communication_info` fields of `SecretRecovered` and the replica events are
  now optional (`communication_info?:`). `restore` accepts the field absent.

- **Fixed: numeric ids were truncated or defaulted instead of rejected.**
  *(bug fix; Node.js, web, every FFI SDK)*

  `restore` read an empty `channel_id` or `replica_id` as 0; it now rejects an
  empty, absent or non-decimal id (`invalid_recovered_secret`), and WASM and
  FFI share one decoder. Node.js/web ids, flow kinds and versions given as a
  fractional, negative, non-finite or unsafe number now throw `decode_error`.
  `removeExpiredChannels` takes a `u64` (`bigint`, safe-integer `number` or
  decimal string) instead of a `u32`.

- **Fixed: React Native lost precision and set `communication_info` late.**
  *(bug fix; React Native)*

  `withParameterRange` bounds above 2^53 were rounded; they now cross as
  decimal strings. `withCommunicationInfo` applies at construction instead of
  through a setter queued after `build()`. The C++ layer no longer decodes
  `TransportProtocol` protobuf; endpoints arrive from the library as JSON.

- **Added: FFI config and transport helpers.** *(additive; FFI)*

  The `derec_protocol_new` config accepts a `communication_info` JSON object
  (rejected together with a non-empty proto buffer); `auto_accept` flows and
  `parameter_range` bounds are individually optional, and bounds may be decimal
  strings; `unpair_ack` accepts `"required"` / `"not_required"` as well as
  `0` / `1`. New `derec_transport_endpoints_json` decodes a transport `send`
  endpoint buffer into `[{ protocol, uri }]`.

- **Docs.** Corrected the FFI `derec_protocol_new` and `derec_protocol_restore`
  docs; the WASM API docs (example, flow kinds 0–8, event table, seven
  required setters); the restore error codes (`store_error`, not `STORAGE`);
  the web README's `init` import (a named export); the .NET README
  (`ContactMode.NoKeys`, replica example); the Go docs and README; and the
  React Native `Transport.send` signature.

### 0.0.5

Verification was reachable but not usable outside the simplest case: a replica
could not check the helpers holding the vault it mirrored, a member that caught
up by pulling could never check anything, and a restored owner accused healthy
helpers of holding corrupt data. Nothing here changes an API.

- **Fixed: a replica destination could not verify the helpers holding the vault
  it mirrored.** *(bug fix; no API change)*

  Verification is a round trip over exact bytes: a helper answers a challenge
  with `SHA-384(share ‖ nonce)` over the share it stores, and the owner
  recomputes that hash from the copy it recorded when it distributed. A
  destination records nothing when it distributes, because it never
  distributed — so the mirrored payload carries the per-helper share map for
  exactly this purpose.

  That map was decoded, surfaced on `ReplicaSecretReceived` /
  `ReplicaSecretInstalled`, and then dropped. Nothing wrote it to the share
  store. A destination that took over a mirrored vault could therefore
  challenge every helper and receive every answer, and reject all of them with
  `no committed share stored for this channel/version — cannot verify proof`.
  It held a secret it could read and recover from but not check — one of the
  four things an owner is expected to be able to do.

  `hydrate` now persists the map as owner-side tracking shares, under the
  local partition at the same `(channel_id, version)` keys the source used. A
  share naming a channel the roster does not list is refused rather than filed
  against a helper this device has no channel or key for.

  A second defect sat behind it. A helper holds exactly one endpoint per
  channel — the device that paired with it — so a challenge from a group member
  has to advertise its own endpoint or the answer is routed to whoever paired.
  For a destination verifying a mirrored vault that is the *source*, which
  drops the response as unsolicited while the challenger waits. `VerifyShares`
  now carries this device's endpoint whenever a replica group exists, matching
  what the helper leg of `ProtectSecret` has always done.

  An empty map stays legitimate: a round below `threshold` runs no split, so
  the source tracked nothing either and the version is equally unverifiable on
  both devices.

- **Fixed: a member that caught up by pulling could never verify its helpers.**
  *(bug fix; wire-compatible new field on the replica payload)*

  A member that falls behind pulls the current state from a peer instead of
  waiting for a push. That answer deliberately carried no share map, on the
  grounds that shares are derived per publishing round and a member does not
  persist them — which is no longer true, and made *how* a member became
  current decide whether it could verify anything.

  A catch-up answer now carries the share map, served from the answerer's own
  tracking rows. Whatever the answerer can verify, the asker can verify after
  hydrating.

  Fixing it exposed a version-keying hazard. A catch-up asks for one version
  and is answered with whatever the peer holds, so the two routinely differ,
  and `GetShareResponseMessage.version` echoes the *request*. Committing the
  answer under that value already mis-dated the snapshot; doing it to a share
  map would key a helper's share to a version it never held, and verification
  would then hash the wrong bytes and report a healthy helper as corrupt.
  `ReplicaSecretPayload` therefore gained a `version` field (tag 4) naming the
  version its `secret` and `shares` belong to, and the receiver commits that.
  A writer predating the field sends `0`, and the receiver falls back to the
  enclosing message's version — which is what that writer meant. On a push,
  where the sender writes both, a disagreement between the two is refused
  rather than guessed.

- **Fixed: `restore` wrote a fabricated tracking share, so verification accused
  healthy helpers of holding corrupt data.** *(bug fix; no API change)*

  Restore persisted an empty owner-side `Share` at the recovered version.
  Verification found that row, hashed zero bytes against the nonce, compared it
  with the helper's hash of the real share, and reported `verification proof is
  invalid` — blaming the helper for a mismatch the owner had manufactured. An
  application sweeping its helpers would mark every one of them corrupt and
  prompt the user to re-provision over nothing.

  The row is gone. Verification at the recovered version now reports honestly
  that this device holds no reference bytes. It cannot hold them: a proof is
  over the exact bytes a helper stores, and recovery cannot attribute a
  collected share to a canonical helper channel — the VSS x-coordinate is a
  random field element and `GetShareResponseMessage` carries no channel id.

  The way back to a verifiable state is to publish. `start(ProtectSecret)`
  derives `recovered_version + 1` from the snapshot restore commits, writes real
  tracking shares as it distributes, and verification at that version behaves
  as it does for an owner that never recovered. Note that a restored device
  whose roster carries a replica group cannot publish until the application
  configures a `replica_id` the roster names — restore does not adopt one,
  since claiming the lost device's identity is a takeover with its own
  convergence rules.

- **Fixed: `DeRecShareStore::save` documented an invariant that contradicted the
  rest of the trait, and three store implementations encoded it.**
  *(bug fix; no API change — but read this if you wrote a share store)*

  `save` said `share.secret_id` "must match the partition key `secret_id` —
  implementations may assert this". `load_many`, four methods above it, says the
  opposite and is the one that is right: `secret_id` is a **partition**, a
  helper holds shares belonging to other people's secrets, and
  `Share::secret_id` is the only thing that distinguishes them. The two are
  equal only when a device happens to hold its own secret.

  Both readings shipped. The SQLite and PostgreSQL reference stores added a
  `debug_assert_eq!` that fires on the ordinary case of a helper holding
  someone else's share. The Rust binding's in-memory store keyed rows on
  `share.secret_id` while every read filtered on the partition, so writes
  landed where no read looked — a store that silently discarded everything it
  was given, and with it every helper-side verification and recovery answer.

  The doc now states the rule the trait actually relies on, and all three
  implementations follow it. **If you wrote a share store, check that `save`
  keys on the `secret_id` argument and carries `share.secret_id` alongside as
  data.** An assertion that the two are equal should be removed.

### 0.0.4

- **The protocol schema now ships inside every published artifact.**
  *(new capability; no breaking change)*

  Nothing published before this release carried a usable copy of the `.proto`
  definitions. `derec-proto` did include them in its `.crate`, but nothing
  told a dependent where cargo had put them; the .NET, Go, Node, React Native
  and web packages shipped none at all. Anyone writing a gRPC transport, or
  generating types for a language with no DeRec SDK, had to copy the files
  out of a `lib-derec` checkout and keep them in step by hand — which is what
  the reference application ended up doing with fifteen of them.

  **Rust.** A default-off `descriptor` feature on `derec-proto` exposes the
  schema as a compiled file descriptor set: `descriptor::FILE_DESCRIPTOR_SET`
  is the full import closure, including the well-known types it imports, and
  `descriptor::transport_descriptor()` narrows that closure to
  `derectransport.proto`. Generating a `DeRecTransport` client and server no
  longer involves a `.proto` file at all:

  ```toml
  [dependencies]
  derec-proto = "0.0.4"

  [build-dependencies]
  derec-proto = { version = "0.0.4", features = ["descriptor"] }
  tonic-prost-build = "0.14"
  ```

  ```rust
  // build.rs
  tonic_prost_build::configure()
      .build_server(true)
      .build_client(true)
      .extern_path(".org.derecalliance.derec.protobuf", "::derec_proto")
      .compile_fds(derec_proto::descriptor::transport_descriptor())?;
  ```

  The `extern_path` is what binds the generated service to this crate's own
  `DeRecMessage`; without it you get a second, structurally identical message
  set that will not unify with the first. Because the feature carries bytes
  rather than file paths, it resolves the same way under `cargo vendor`, a
  relocated `CARGO_HOME`, registry mirrors and `--offline`.

  Enable it on the **build-dependency only**, as above. The descriptor is
  ~122 KB and `derec-library` compiles to WebAssembly for the Node.js and web
  SDKs; with resolver v2 or later, build-dependency features are not unified
  with normal-dependency ones, so the bytes stay in your build script and out
  of your binary. That is also why the feature is off by default.

  **Every other SDK.** Each package now carries the same schema as a flat
  directory of 18 `.proto` files plus the descriptor:

  | SDK | Where |
  |-----|-------|
  | Go | package `derecpb/schema` — `FileDescriptorSet []byte` and `Proto embed.FS` |
  | Node.js, web, React Native | `proto/` and `derec_descriptor.bin` at the package root |
  | .NET | `schema/proto/` and `schema/derec_descriptor.bin` in the `.nupkg` |

  Every import in the schema is a bare filename, so the flat directory
  resolves the whole closure with a single include root — `protoc -I proto`,
  with no second path to supply. The descriptor is compiled with source info,
  so code generated from it keeps the protocol's doc comments.

  The schema has no version of its own, deliberately: each bundle is
  generated from the sources of the artifact shipping it, so `0.0.4` of any
  package carries `0.0.4` of the schema and there is no second version line
  to reconcile.

### 0.0.3

> **Every symbol this release deprecates is removed in 0.0.5.** One horizon for
> the whole wave, in every binding: the singular `transportProtocol` proto field
> in all four messages, `with_own_transport` / `set_own_transport` and their SDK
> counterparts, `with_unsafe_http`, and
> `TransportValidationError::UnknownProtocol` (replaced by `UnsupportedProtocol`).
> Individual deprecation notes repeat the version so a compiler warning carries
> it, but there is only one date to plan against — nothing deprecated here
> survives past 0.0.5.
>
> *Correction:* 0.0.5 shipped with the wave still in place. It was removed in
> 0.0.6 — see that release.

- **Published binaries no longer embed the release machine's paths, and the
  React Native package is a quarter smaller.** *(no API change)*

  `panic!`, `unwrap()` and `expect()` compile their source location into the
  binary as ordinary read-only data, via `core::panic::Location`. For
  dependency and standard-library code that path is absolute, so every
  artifact carried strings like
  `/Users/<someone>/.cargo/registry/src/index.crates.io-*/serde_json-1.0.151/src/de.rs`
  — 63 in each wasm bundle, 70 in the Go shared libraries, over a thousand in
  each React Native archive. That leaks information about the build machine
  and is why two machines could not produce identical output from one commit.

  Every packaging script now passes `--remap-path-prefix`, from a shared
  `scripts/lib/build-env.sh` so a script run on its own behaves like the
  Makefile. All shipped artifacts now report zero.

  Separately, the React Native static archives ship without debug sections.
  Cargo's `profile.strip` cannot do this: it is a link-time setting, and a
  `.a` is an archive of object files that is never linked — which is why the
  Go and .NET shared libraries were already clean while the archives were not.
  The scripts strip them after staging instead, keeping the symbol table so
  the consuming app still links. The package goes from 171.8 MB unpacked
  (50.2 MB packed) to 129.0 MB (40.5 MB).

- **Removed `DeRecProtocol.ProcessAndAcceptAllAsync` from the .NET SDK.**
  *(breaking: .NET only)*

  It was a test helper on the shipped surface — its own doc said it mirrored
  the Node smoke suite's `processAll`, and that helper is private to the test
  in all four other SDKs. Every one of its 32 callers was in
  `smoke-tests/dotnet`, and it is now an extension method there, so those call
  sites are unchanged.

  It should not have been public. Accepting every `ActionRequired` whatever its
  kind defeats the point of that event, which is where an application applies
  its own admission control — share-size caps, rate limits, a user declining.
  `AutoAcceptPolicy` is the supported way to opt into automatic acceptance and
  is selective per flow kind, so this was also a second, weaker spelling of a
  feature the library already had.

  **Migration:** call `ProcessAsync` and accept the `ActionRequiredEvent`s you
  want, or build with `WithAutoAccept(AutoAcceptPolicy.All())` and let
  `ProcessAsync` handle them.

- **The SDK API surface is now guarded by a test.** *(no API change)*

  `enum_fixture.rs` holds the SDKs to the core's enum *members* and
  `dto_field_parity.rs` to its message *fields*. Neither covered the API — the
  protocol methods, builder options, flow parameter types and store methods —
  which is where the parity pass above found four divergences with every suite
  green, because nothing linked an SDK's method list to the core's.

  `api_surface_parity.rs` and `fixtures/api_surface.json` are that link, and
  check both directions. A method, option, flow or store method that exists in
  the core and is absent from the fixture fails; `DeRecFlow` is matched with no
  wildcard arm, so a new flow fails to *compile* there. Anything the fixture
  names and an SDK does not declare fails, naming the SDK.

  It matches declarations rather than identifiers, which is what makes it
  worth having: the gap that motivated it was Go holding `SecretID` as a field
  on the input `Config` while the constructed protocol had no such accessor, so
  a token search finds the name four times and reports a method that does not
  exist. For the TypeScript packages a helper must appear in *both* the
  declaration file and the runtime file — present in `index.d.ts` and absent
  from `index.js` type-checks and hands the caller `undefined`.

  **The same file now holds this document to the source.** Three further
  checks: every `SomeError::Variant` named in this changelog must resolve,
  every `#[deprecated]` must name the wave's single removal version, and every
  deprecated symbol must appear here at all. A retired spelling is allowed only
  where it explains its own rename, which the fixture records as a
  `replaced_by` that has to appear in the same paragraph — allowlisting the
  bare name would pass the defect this exists for, since describing
  `NoCommonTransport` as current behaviour was wrong precisely because it was
  named *alone*.

  Both defects it was written for shipped and were found by reading: a renamed
  error variant described as current, and a deprecation wave that named two
  removal versions because the notes were written weeks apart. On its first run
  it found a third — the deprecated C export
  `derec_protocol_set_own_transport` was absent from this document entirely, so
  a consumer hitting the compiler warning had nothing to search for.

  It reads this file and the deprecation notes; it does **not** read rustdoc.
  `cargo doc` catches broken intra-doc links but not names written in plain
  backticks, which is how the stale references fixed below were written.

- **SDK parity pass.** Four divergences closed after auditing every SDK's
  surface against the core.

  `channelFilterMatches` is now exported from the Node, web and React Native
  packages. .NET and Go already shipped a `Matches` helper on the filter; the
  three TypeScript surfaces did not, so a store that wanted to filter in memory
  had to re-derive the empty-means-unrestricted and exclude-after-`ids` rules by
  hand. That is the binding where a store is *most* likely to need it, since
  TypeScript cannot force the filter parameter to be taken at all.

  Go gained `DeRecProtocol.SecretID()`. The other four SDKs let you ask a
  constructed protocol which secret it manages; Go exposed it only on the
  `Config` you passed in, so a caller had to retain that value.

  Go gained `ReplicaDiscoveryParams`. .NET and the TypeScript surfaces each
  declare an empty params type for this flow deliberately, so that every
  `FlowKind` has one; Go took `nil` and nothing else. `Start` now accepts
  either.

  Go's `Start` doc comment listed the params types and omitted
  `UnpairReplicaParams` and `ReplicaDiscoveryParams`.

  Verified at parity and unchanged: all 14 protocol methods, all 15
  builder/config options, all 9 flow param types, all 6 store traits' methods,
  all 42 `DeRecEvent` variants, all 8 `AutoAcceptPolicy` fields, and the 6
  primitive families across all five SDKs.

- **The library now enforces `ChannelFilter` itself; a store that ignores it is
  slow, not wrong.** *(bug fix; the contract loosened, no API change)*

  0.0.3 shipped the filter with "implementations must apply it — it is not a
  hint", and the protocol then acted on the returned rows as though that held.
  It does not hold on the TypeScript bindings: TypeScript accepts a function of
  fewer parameters where more are declared, so a channel store written against
  0.0.2 satisfies the 0.0.3 `ChannelStore` interface and compiles clean under
  `--strict`. Rust, Go and .NET break at compile time; Node, web and React
  Native do not.

  Several call sites trusted the filter for correctness rather than speed:

  - the responding side of an unpair narrowed by `ids: vec![target]` and took
    the first row, so a non-filtering store would flag **a different member**
    as leaving — and the completing roster would then delete it. "Evict X"
    silently evicted Y.
  - `remove_expired_channels` narrowed by `status: [Pending]` and deleted what
    came back, so a non-filtering store would delete **paired** channels and
    their pairing secrets. It runs inside `process()` by default.
  - `reconcile` narrowed by `status: [Unpairing]`, which is half of the
    two-part removal safety rule; without it the rule was "absent" alone.
  - discovery's catch-up source and Source-election lookups took the first row
    of a by-id and a by-role listing.

  Every internal listing now goes through a wrapper that re-applies the filter
  to whatever the store returned. One mechanism, every binding, and a store
  that pushes the filter down loses nothing — the re-check is a no-op over rows
  that already satisfy it. Under the `logging` feature, a store that returns
  excluded rows is reported at `warn` — it only fires when a store is not
  honouring its contract, so it is silent for a correct one.

  **This is a one-way guarantee, not a validation of your store.** Dropping
  rows can enforce an upper bound — nothing the filter excluded is acted on —
  but it cannot recover a row you omitted. A store that returns *fewer* rows
  than the filter selects is still wrong, in a way nothing in the library can
  detect: the protocol simply fails to act, skipping a publish or missing a
  departure. Nor is the `secret_id` partition policed, since a record does not
  carry the key it is stored under.

  A JS store that deliberately ignores the filter is driven through the WASM
  bridge in the Node smoke suite, since the TypeScript hole is the case the
  backstop exists for and the Rust unit tests cannot reach it.

  **Nothing to change in your store**, and the guidance on what to write has
  been turned the right way up. The docs previously opened with "apply the
  filter in your query rather than listing everything and discarding rows",
  which points every implementer at the one direction that can fail silently.
  They now say what the backstop actually makes true: **returning every record
  under the `secret_id` is correct**, and pushing the filter into a query is an
  optimization to opt into when the transfer cost is worth re-expressing these
  semantics in a query language by hand.

  That asymmetry is the whole point. Returning too *many* rows costs only the
  transfer; returning too *few* is undetectable at runtime. Recommending the
  risky direction by default was backwards.

  **Conformance vectors ship for the direction that can go wrong.**
  `library/tests/fixtures/channel_filter.json` is a table of
  `(records, filter, expected)` cases covering the clauses a hand-written
  pushdown gets subtly wrong: empty-means-unrestricted per field, `role` as an
  optional rather than a list, `exclude` applied *after* and overriding `ids`,
  and ids above 2^53 where a binding that parses them as numbers matches the
  wrong record. Rust, Go, .NET and the TypeScript SDKs each drive the same
  table against their own predicate, so a binding that drifts fails against the
  fixture rather than against another binding. A store that pushes the filter
  down should be driven through it too — that is what makes the optimization
  checkable by the party who has to get it right.

- **Fixed: two deprecation notices showed no migration.** The `set_own_transport`
  and `with_own_transport` doc examples had an identical "before" and "after",
  from a search-and-replace that caught the wrong line too. Both now show the
  singular call being replaced by the plural one.

- **Fixed: two doc comments described an API that does not exist.** *(docs only)*

  `DeRecProtocol`'s `own_transports` and `auto_reply_to` fields both referred
  to a `first_own_transport()` accessor. It was planned during the
  transport-negotiation work and never landed, but the documentation written
  against it did. The `auto_reply_to` comment was stale twice over: it
  described the outbound `reply_to` as a single endpoint on the one field this
  release changed to a list, so it stated the opposite of what shipped.

- **Fixed: a replica destination reported every roster as a first install.**
  *(bug fix; no API change)*

  `ReplicaSecretInstalled` and `ReplicaSecretReceived` tell an application
  whether to run its first-install logic, and the choice is made by asking
  whether a user-secret snapshot already exists. That question was asked
  against the **sender's** `secret_id`, taken off the wire, while `hydrate`
  wrote the snapshot under the receiver's own `secret_id`. A destination is not
  required to have been configured with the sender's id — and typically is not
  — so the lookup landed in a partition this device never writes, came back
  empty every round, and every version arrived as `ReplicaSecretInstalled`.

  Two neighbouring reads had the same defect: the `was_source` check that
  decides whether a roster promoted this device, and the ephemeral-key cleanup
  after an admission handover. All three now use the local partition.

  Events and acknowledgements are unchanged: their `secret_id` is documented as
  echoing the inbound request, and still does.

- **Channel-store listings take a filter, so stores stop shipping rows the
  protocol discards.** *(breaking: `DeRecChannelStore` and every SDK's channel
  store, plus two FFI callback signatures)*

  `helpers()` and `replicas()` used to return everything under a `secret_id`,
  leaving the caller to filter by status and role — after the rows had already
  crossed the wire. Both now take a filter and push that work into the store:

  ```rust
  // before
  let members = channel_store.replicas(secret_id).await?;
  let targets: Vec<_> = members.into_iter()
      .filter(|m| m.status == ChannelStatus::Paired
                  && m.role == ReplicaRole::Destination
                  && Some(m.replica_id.0) != own)
      .collect();

  // after
  let targets = channel_store.replicas(secret_id, ReplicaFilter {
      status: vec![ChannelStatus::Paired],
      role: Some(ReplicaRole::Destination),
      exclude: own.map(ReplicaId).into_iter().collect(),
      ..Default::default()
  }).await?;
  ```

  The filter is one generic type with two aliases, so both listings have the
  same shape:

  ```rust
  pub struct ChannelFilter<Role, Id> {
      pub ids: Vec<Id>,                 // restrict to these; empty = all
      pub status: Vec<ChannelStatus>,   // allow-list; empty = any
      pub role: Option<Role>,           // None = any
      pub exclude: Vec<Id>,             // applied last, overrides `ids`
  }
  pub type ReplicaFilter = ChannelFilter<ReplicaRole, ReplicaId>;
  pub type HelperFilter  = ChannelFilter<SenderKind, ChannelId>;
  ```

  **Every empty value means "do not restrict", so `Default::default()` is the
  old unfiltered behaviour** — that is the whole migration for a caller that
  wants everything.

  **Returning everything and ignoring the filter is correct** — see the
  enforcement entry above, which is what makes that true. A store *may* express
  the filter as a query instead — a `WHERE` clause, a key-condition expression
  — to avoid moving rows the caller will drop, which costs bandwidth everywhere
  and real money on a metered backing such as DynamoDB that bills by bytes
  read. That is an optimization, and one to verify against the shipped
  conformance vectors: the library can drop rows you should not have returned
  but cannot recover one you never did. A backend that would rather not think
  about it can list and call `ChannelFilter::matches`, which is the same
  predicate the library re-checks with.

  Migrating an implementation:

  | binding | signature |
  | --- | --- |
  | Rust | `fn helpers(&self, secret_id: u64, filter: HelperFilter)` |
  | .NET | `IEnumerable<HelperChannel> ListHelpers(ulong secretId, HelperFilter filter)` |
  | Go | `ListHelpers(secretID uint64, filter HelperFilter) ([]HelperChannel, error)` |
  | Node / web / React Native | `listHelpers(secretId: string, filter: HelperFilter)` |

  `replicas` / `ListReplicas` / `listReplicas` change identically, taking a
  `ReplicaFilter`. Each binding ships a `Matches` helper and an unrestricted
  value (`Default::default()`, `HelperFilter.Any`, the zero struct, or an
  all-empty object).

  **FFI.** `list_helpers` and `list_replicas` gain a `(filter, filter_len)`
  pair carrying the filter as JSON, ahead of the existing out-parameters. The
  buffer is owned by the caller and valid only for the duration of the call.
  On the WASM bridges the filter arrives as a plain object, with ids as decimal
  strings.

  **Two lookups moved off listings entirely.** Where a caller wanted one member
  by id and had the channel to hand, it now calls `load(ChannelQuery::Replica)`
  rather than scanning a roster.

  The bundled SQLite and Postgres stores project `status` and `role` out of the
  record blob into indexed columns and filter in SQL, so the pushdown is real
  rather than a parameter nobody honours. **Their schemas changed**; the
  migrations in `smoke-tests/{sqlite,postgres}/migrations` are updated.


- **Two replica flows are renamed to the protocol's own vocabulary.**
  *(breaking: enum variants in every SDK, and one event's wire name)*

  Neither `SyncCheck` nor `RemoveReplica` named anything the protocol has.
  Each is an existing flow applied to the replica group rather than to a
  helper, and they are now named that way:

  | before | after |
  | --- | --- |
  | `DeRecFlow::SyncCheck` | `DeRecFlow::ReplicaDiscovery` |
  | `DeRecFlow::RemoveReplica` | `DeRecFlow::UnpairReplica` |
  | `DeRecEvent::SyncCheckComplete` | `DeRecEvent::ReplicaDiscoveryComplete` |
  | `StateKind::PendingSyncCheck` | `StateKind::PendingReplicaDiscovery` |
  | `SyncCheckReport` | `ReplicaDiscoveryReport` |

  A replica catch-up round travels as `GetSecretIdsVersions` — the discovery
  message family — and a replica removal travels as `UnpairRequest`. The names
  now say so, and match the `handlers/replicas/{discovery,unpairing}.rs`
  modules that implement them.

  Renamed to match across all five SDKs: `FlowKindReplicaDiscovery` /
  `FlowKindUnpairReplica` and `ReplicaDiscoveryParams` / `UnpairReplicaParams`
  (Go), the corresponding flow records and event types (.NET), and the
  `FlowKind` members, params interfaces and event union members (Node, web,
  React Native).

  **Wire impact is limited to one string.** The flow kind crosses the FFI as a
  number (`7` and `8`, unchanged), and `StateKind::PendingReplicaDiscovery`
  keeps discriminant `4`, so persisted state needs no migration. The one
  visible change is the event's `type` field: `"SyncCheckComplete"` becomes
  `"ReplicaDiscoveryComplete"`. Applications matching on that string must
  update it.

  `ReplicaRemoved` and `SelfRemovedFromGroup` keep their names: they describe
  what happened to the member, which is accurate whatever the flow that did it
  is called.


- **`parameter_range` is now configurable from every SDK.**

  The Rust builder has always had `with_parameter_range`, and the WASM
  builder bound it — but it was declared in no SDK's types, and the FFI
  config had no field for it at all. So the pair-negotiation bounds were
  reachable from Rust and nowhere else.

  `ProtocolConfig` gains an optional `parameter_range` object, and the
  setting surfaces as `WithParameterRange` (.NET), `Config.ParameterRange`
  (Go), and `withParameterRange` (Node, web, React Native).

  The WASM binding previously read camelCase keys (`minShareSize`); it now
  reads the snake_case keys of the `ParameterRange` interface every binding
  already declares, so one shape serves both transports. Nothing declared
  the camelCase form, so no typed consumer existed.

- **SDK parity fixes.**

  - `setOwnTransports` was missing from `packages/web`'s declarations. The
    runtime had it — web users just had no types for it.
  - .NET was missing the `StateStore` error category and five error codes:
    `RoleMismatch`, `ReplicaIdConflict`, `MalformedRecoveredSecret`,
    `TransportInvalid`, `NoUsableEndpoint`. Go was missing
    `ReplicaIDConflict` and `NoUsableEndpoint`. All three now enumerate the
    same 16 categories and 50 codes with the same values.
  - `action_kind` was typed as a bare `string` in Node, web and React
    Native, and had no constants in Go. Both now carry the eight-value
    vocabulary (`PendingActionKind` in TypeScript, `ActionKind*` in Go).


- **A device serves at most one endpoint per protocol.** *(breaking for
  configurations advertising two of the same)*

  The endpoint *is* the address peers reach that protocol on, so a second
  entry for the same protocol adds no reach — it contradicts the first, and
  nothing says two peers would resolve the contradiction alike. A list of
  endpoints is a preference order over *distinct* protocols.

  Enforced at two strengths. This device's own endpoints are **refused**:
  `DeRecProtocolBuilder::build` and `set_own_transports` return
  `Error::Transport(TransportValidationError::DuplicateProtocol { .. })`, a
  new variant. A duplicate there is a configuration mistake the application
  can fix, and dropping one silently would advertise something it never asked
  for. A peer's advertised endpoints are **filtered**, first entry winning,
  because the advertisement is untrusted input and failing a whole pairing
  over a resolvable contradiction would discard a usable endpoint.

  Applications advertising several addresses for one protocol must pick one.
  Advertising HTTPS *and* gRPC is unaffected — that is what the list is for.

- **`set_own_transport` now replaces only its own protocol's endpoint.**

  It previously replaced the entire list, so a device serving HTTPS and gRPC
  lost its gRPC endpoint when it re-pointed HTTPS. With one endpoint per
  protocol the argument identifies which entry it replaces, and the rest are
  left alone. The replaced entry keeps its position: changing an address is
  not a change of preference. An endpoint for a protocol not yet served is
  appended.

  This does not withdraw the deprecation — the method is still removed at
  0.0.5, and `set_own_transports` remains the way to change the whole set.
  It is now correct rather than a trap for whatever remains of its life.

  The deprecation reaches every binding in that binding's own mechanism, so
  the warning a consumer sees names a different symbol depending on where
  they stand: `derec_protocol_set_own_transport` in the C header, which
  carries a real `__attribute__((deprecated))` rather than a comment,
  `SetOwnTransport` in .NET and Go, and `setOwnTransport` in Node, web and
  React Native. All of them point at the plural form and all are removed at
  0.0.5.


- **Every `*Started` event now carries the `trace_id` of the round that
  produced it.** *(breaking for exhaustive `match` on `DeRecEvent`)*

  `start` draws one token per call and every request it dispatches carries
  that token on the wire, so a fan-out to five helpers is one trace rather
  than five. The peer echoes it on the response, which is what lets an
  application correlate a round end-to-end.

  Previously each dispatch drew its own token internally and dropped it: the
  caller was handed nothing, and a round had no identity. `ReplicaDiscovery`
  requests carried no `trace_id` at all and now do.

  Added to `PairingStarted`, `DiscoveryStarted`, `ProtectSecretStarted`,
  `VerifySharesStarted`, `RecoverSecretStarted`, `UnpairStarted` and
  `UpdateChannelInfoStarted`. Rust code matching these variants exhaustively
  must bind or ignore the new field; `..` in the pattern is the smallest
  change. On the SDKs the field is additive — it arrives as a decimal string
  (`trace_id` / `TraceId` / `TraceID`), following the same convention as
  `channel_id`, so it survives JS `Number.MAX_SAFE_INTEGER`.

  The `*Failed` events are unchanged: a request that never left carries no
  token to report.


- **`with_auto_respond_on_failure` now does something.**

  The setting shipped in 0.0.2 documented on all five SDKs and read by no
  code: enabling it changed nothing. It is now implemented.

  - **Disabled (the default)** — unchanged. An inbound failure returns
    `Err(ProcessError)` from `process()` and nothing goes on the wire; the
    application decides what to do.
  - **Enabled** — the peer is additionally sent a response carrying a non-`Ok`
    `DeRecResult`. `process()` still returns the same `Err`, so the setting
    governs a side effect rather than the local contract, and application
    error handling does not change with it.

  **Only authenticated failures are answered.** The reply is sent from a point
  where the request has already been decrypted under the channel key, which is
  what proves it came from the peer it names. A message that fails to decrypt
  gets no response at all: answering one would make the device an oracle for
  anyone able to send bytes at it. Role-gate and transport-policy refusals are
  answered, because those happen after decryption.

  Sending the response is best effort — if it fails, the original error still
  reaches the caller rather than being replaced by the delivery failure.

- **Fixed: three SDKs deprecated nothing where the others deprecated a
  symbol.** The single-endpoint setters were marked in some bindings and
  silently fine in others, so whether an application learned its call site
  disappears at 0.0.5 depended on which SDK it used. Now marked everywhere:
  `withOwnTransport` / `setOwnTransport` in the web package (`@deprecated`),
  `WithOwnTransport` in .NET (`[Obsolete]`), and `Config.OwnTransportURI` /
  `Config.OwnTransportProtocol` in Go (`Deprecated:`).

- **Fixed: `NoUsableEndpoint` reached the SDKs under two different names.**
  The WASM bridge reported it as the error code `NO_COMMON_TRANSPORT` while
  the C FFI — and therefore .NET and Go — reported
  `DEREC_CODE_NO_USABLE_ENDPOINT = 121`, so the same condition was
  unmatchable across bindings. The TypeScript code is now `NO_USABLE_ENDPOINT`
  to match the Rust variant and the FFI constant. Neither spelling shipped in
  0.0.2, so nothing depended on the old one.

- **Fixed (.NET): a contact lost its offer list when the SDK re-encoded it.**

  `DeRec.Library.ContactMessage` is the only place in any binding where a
  contact is decoded into a hand-written type and later serialized back — Go
  and the TypeScript SDKs pass the wire bytes through untouched. The record
  had no `SupportedTransports` member, so the round trip
  `CreateContact` → `ContactMessage` → `Request.Produce` silently dropped
  every endpoint but the deprecated singular one, and a .NET responder never
  learned more than one of the initiator's endpoints. `CreateContact` accepts
  a list, so the caller had every reason to believe it had advertised
  several.

  The record now carries `SupportedTransports`, populates it on decode and
  emits it on encode. Nothing detected this before because every test built
  contacts with a single endpoint, for which the lossy and correct paths
  agree; the .NET smoke suite now round-trips a two-endpoint contact and
  asserts both entries survive.

- **The legacy singular `transportProtocol` is deprecated everywhere, and
  `PrePairRequestMessage` gains `supportedTransports`.**

  A peer can serve more than one transport now that gRPC exists alongside
  HTTPS, and it discloses that at pairing. Every pairing message therefore
  carries the list: `ContactMessage` and `PairRequestMessage` already did,
  and `PrePairRequestMessage` joins them at tag 4.

  `UpdateChannelInfoRequestMessage` gains it too, at tag 4: announcing a move
  should be able to name every endpoint you moved to, not one. Its list
  replaces the receiver's stored set outright — unlike a request's `replyTo`,
  this one **is** persisted, because it is how a peer says it has moved.

  The singular `transportProtocol` on all four is marked
  `[deprecated = true]` and **scheduled for removal in v0.0.5**. Until then a
  sender populating the list MUST also fill the singular field with its first
  entry, which the library does for you. The deprecation surfaces as a real
  compiler warning in Rust (prost emits `#[deprecated]`) and in .NET
  (`CS0612`), and as `@deprecated` in the TypeScript declarations.

  **Reading the singular field is now a bug, and deprecation does not say
  so.** A deprecation notice communicates *this is going away*; it does not
  communicate *the meaning of reading this has changed*. This field's meaning
  narrowed from "the endpoint" to "one entry of a list, and possibly absent",
  so a reader that was correct in 0.0.2 now rejects — or fails to reach — a
  peer that advertises only `supportedTransports`. The name, type and runtime
  behaviour are all unchanged, so nothing in any type system points at the
  read sites.

  Every binding therefore ships the resolver the core already used
  internally, so there is a named thing to reach for instead of a field read:

  - **Rust** — `AdvertisedEndpoints::advertised_endpoints()`, implemented for
    all four message types.
  - **.NET** — `ContactMessage.AdvertisedEndpoints()`.
  - **Go** — `derecpb.AdvertisedEndpoints(msg)`, over any message satisfying
    `derecpb.EndpointAdvertiser`.
  - **Node / web / React Native** — `advertisedEndpoints(message)`.

  Each yields `supportedTransports` when non-empty and the singular field
  otherwise, reporting what was advertised rather than what is acceptable —
  the transport policy still decides what may be recorded. The per-field
  deprecation notes now state the reader obligation rather than only the
  removal date, and `api_surface_parity` holds every binding to declaring the
  resolver.

  **At least one of the two must be present.** A message naming no endpoint
  leaves the peer nowhere to reply, so it is refused at validation rather
  than failing later somewhere less obvious. This is enforced on
  `ContactMessage` and `PrePairRequestMessage`; `PairRequestMessage` already
  had it.

  Relatedly, a contact carrying **only** the list is now accepted.
  `validate_inputs` previously demanded the deprecated singular field and so
  refused a peer that had already moved past it — a forward-compatibility
  bug rather than a missing assertion.

  - **Rust** — `request::produce_pre_pair_request` takes
    `Vec<TransportProtocol>` instead of one endpoint.
  - **.NET** — `Pairing.Request.ProducePrePair` takes
    `IReadOnlyList<TransportProtocol>`.
  - **Node / web / React Native** — `pairing.request.produce_pre_pair` takes
    `TransportProtocol[]`.
  - **Go** — `Request.ProducePrePair`'s first argument is now a
    length-delimited sequence rather than one encoded message; the Go
    signature is unchanged (`[]byte`), only its contents.
  - **C FFI** — `produce_pre_pair_request_message` takes
    `transport_protocols_ptr` / `_len` carrying that sequence.

  For `UpdateChannelInfo` the flow parameters gain `own_transports` beside the
  deprecated `transport_protocol`, in every binding. The list takes precedence
  when both are set, and its first entry fills the singular field. Rust's
  `DeRecFlow::UpdateChannelInfo` renames the field to
  `own_transports: Vec<TransportProtocol>`; the JSON seam the SDKs use accepts
  either spelling, so an SDK predating the list keeps working until v0.0.5.

- **Breaking (request primitives): `reply_to` is a list.**

  A request could name only one address to be answered on, so enabling
  `with_auto_reply_to` actively *narrowed* delivery: without it a responder
  routes to every endpoint recorded for the channel, with it to exactly one.
  Turning on a convenience should not cost failover.

  Each of the five request types — `StoreShare`, `VerifyShare`,
  `GetSecretIdsVersions`, `GetShare`, `Unpair` — gains a
  `repeated TransportProtocol replyToTransports` on a **new tag** (10, 6, 6, 4
  and 5 respectively). The singular `replyTo` keeps its original tag, its
  original meaning, and is still populated with the list's **first** entry; it
  is `[deprecated = true]` and removed in v0.0.5.

  - **Rust** — `reply_to` on the message is `Vec<TransportProtocol>`; the
    `reply_to` parameter of every `request::produce` is
    `&[TransportProtocol]`. `&[]` replaces `None`, and
    `std::slice::from_ref(&endpoint)` reproduces `Some(endpoint)`.
  - **.NET** — `replyTo` is `IReadOnlyList<TransportProtocol>?`.
  - **Node / web / React Native** — `reply_to` takes `TransportProtocol[]`.
    It is a list, so it is omitted rather than `null` when unset; the JSON
    seam rejects `null` for it exactly as it does for `supported_transports`.
  - **C FFI** — `reply_to_ptr` / `reply_to_len` carry a length-delimited
    sequence rather than one encoded message. A zero length still means "no
    override".
  - **Go** — the primitives pass `reply_to` through as opaque bytes and are
    unaffected. `derecpb.ReplyToEndpoints` is available for an application
    that parses a request itself.

  Every binding's own surface still takes and returns **one list**. The wire
  pair is resolved on the way in and split on the way out inside the DTO
  layer, so no binding has to know the rule and none can get it wrong.

  **Wire compatibility.** A 0.0.2 peer reads tag 5 and skips the list tag it
  has never heard of, so it sees the first entry. A 0.0.2 peer *writing* one
  endpoint on tag 5 is read here as a one-element list, and an absent field
  stays absent — which means "route to the endpoints on file", not "answer me
  nowhere". All four behaviours are pinned by tests in `derec-proto`.

  **Why a new tag rather than re-tagging `replyTo` as repeated.** An earlier
  draft of this release did the latter, and it is wire-compatible in the read
  direction only. Protobuf merges a repeated submessage into a singular reader
  field-by-field, so a 0.0.2 peer decoding a multi-entry list sees the
  **last** entry — while the singular `transportProtocol` beside
  `supportedTransports`, and every other compatibility rule in this release,
  designates the **first** entry as the legacy-readable one. The same
  `own_transports` list feeds both paths when `with_auto_reply_to` is on, so
  no ordering an application chose could satisfy both: leading with HTTPS
  paired correctly and replied to an address a 0.0.2 peer could not dial;
  leading with gRPC did the reverse. Shipping that as an ordering convention
  for applications to follow was not a trade-off worth making when a new tag
  costs one field number. This is the shape `supportedTransports` (tag 9)
  already uses beside `transportProtocol` (tag 7).

  A reply-to still stands alone rather than joining the recorded endpoints.
  Those may belong to a different peer entirely — a replica talking to a
  helper paired with a sibling — so falling back to them would misroute
  rather than fail over.

- **Breaking (pairing primitives): `pairing.response.produce` no longer takes
  the responder's own transports, and returns every endpoint the requester
  advertised rather than one.**

  `produce` filters the requester's advertised endpoints and returns all the
  survivors, so it never needed the responder's own endpoints to rank them
  against. The result field is now a list:

  - **Rust** — `ProduceResult.peer_transport_protocol` → `peer_transports: Vec<TransportProtocol>`.
  - **.NET** — `ProduceResult.PeerTransportProtocol` → `PeerTransports: IReadOnlyList<TransportProtocol>`.
  - **Go** — `ProducedResponse.PeerTransportProtocol []byte` → `PeerTransports []Endpoint`,
    decoded rather than raw proto bytes; the `ownTransports` parameter is gone.
  - **Node / web / React Native** — the `own_transports` argument is gone and
    `peer_transport_protocol` → `peer_transports: TransportProtocol[]`.
  - **C FFI** — `produce_pair_response_message` drops `transport_protocols_ptr`
    / `transport_protocols_len`; the `peer_transports` result buffer carries a
    length-delimited sequence rather than a single encoded message.

  The Go and React Native bindings had not followed the FFI when it dropped
  those two arguments. Go passed them anyway, which left the library reading a
  stray pointer as its `unsafe_connection` flag and silently accepting
  plaintext peer endpoints in production builds; a regression test now covers
  the guardrail end to end. React Native was inconsistent with its own
  checked-in header and did not build. Regenerating that header is enforced by
  `scripts/prepare-react-native-package.sh`.

- **Breaking (all bindings): `DeRecTransport::send` takes a list of endpoints,
  and the library no longer chooses between them.**

  ```rust
  fn send(&self, endpoints: &[TransportProtocol], message: Vec<u8>) -> TransportFuture<'_>;
  ```

  A peer can advertise several endpoints. The library **filters** them —
  refusing plaintext and malformed ones through `TransportPolicy` — and hands
  the survivors over in the peer's own order. It does not rank them.

  Choosing which endpoint to dial, and failing over when one is unreachable,
  is transport mechanism and belongs to the application: only it knows which
  of its transports are healthy, cheap, or currently reachable. Delivery to
  any one endpoint is success; return an error only when the message reached
  none. `endpoints` is never empty, and every entry addresses the **same**
  peer — delivering to all of them sends one authenticated message several
  times, so stop at the first success.

  **Both adapters ship, so nobody writes that contract by hand.** The decision
  above stays with the application; the bookkeeping around it is identical
  everywhere and is now written and tested once per binding. Implement a
  one-endpoint dialer and wrap it:

  - `SequentialFailover` — tries each endpoint in the peer's order, stops at
    the first success, errors only when every endpoint failed. The default.
  - `SingleEndpointTransport` — uses the first and ignores the rest.

  Spelled `SendOne` + `SequentialFailover` / `SingleEndpointTransport` in Rust,
  .NET and Go, and `SendOne` + `sequentialFailover(dialer)` /
  `singleEndpointTransport(dialer)` in Node, web and React Native.

  The second adapter exists because `endpoints[0]` compiles, passes every
  test, and silently forfeits the failover the list was added to provide —
  and the migration note for this release said it "reproduces the old
  behaviour exactly", which reads as a green light. It still does reproduce
  it; the difference is that naming a type records the choice where an index
  reads as finished code, so a reviewer gets something to disagree with.

  An earlier draft of this release had the library pick one endpoint, ranking
  a peer's offers by the order the application had configured its *own*
  endpoints in. Those are unrelated decisions — "endpoints I serve" is not
  "my preference among a peer's" — and conflating them meant the library
  invented a policy the application never wrote. `Error::NoCommonTransport`
  became `Error::NoUsableEndpoint { offered }` for the same reason: with no
  intersection being computed, nothing is "common"; the error now means every
  endpoint a peer advertised was refused by policy.

  Reading what a peer advertised is `AdvertisedEndpoints::advertised_endpoints`
  (implemented for `ContactMessage` and `PairRequestMessage`, and falling back
  to the singular `transportProtocol` field for peers predating the offer
  list); filtering it is `TransportPolicy::admit_peer_endpoints`. Applications
  driving flows through `DeRecProtocol` never call either — they matter only
  when reaching past it to the primitives.

  Migration, per binding:
  - **Rust** — take `&[TransportProtocol]`; `endpoints[0]` reproduces the old
    behaviour exactly, and iterating them enables failover.
  - **.NET** — `ITransport.Send` takes `IReadOnlyList<TransportProtocol>`.
  - **Go** — `Transport.Send` takes `[]Endpoint`.
  - **Node / web / React Native** — the `send` callback's first argument is
    now an array of `{ uri, protocol }`.
  - **C FFI** — the `send` callback takes `(endpoints_ptr, endpoints_len)`
    carrying a length-delimited sequence of encoded `TransportProtocol`
    messages, replacing `(uri_ptr, uri_len, protocol)`.

  Channel records and the recovered-secret roster carry the full list too, so
  failover survives a restart. See the two format entries below.

- **Breaking (channel store): `HelperChannel.transport` and
  `ReplicaMember.transport` became `transports`, a list.**

  A peer can advertise several endpoints, so a channel records all of them
  in the order the peer offered. The library filters them through
  `TransportPolicy` and never ranks what survives — choosing between
  endpoints, and failing over when one is unreachable, belongs to the
  application implementing `DeRecTransport`.

  *Rust applications* get a compile error in their `DeRecChannelStore`
  implementation. The fix is mechanical: a stored single endpoint becomes
  `vec![endpoint]`, and a read that needed one takes the first.

  *SDK applications* store a JSON-encoded `ChannelRecord` produced by the
  library, so there is no compile error to catch this. **They do not have to
  migrate anything:** the deserializer accepts either spelling and lifts a
  lone `transport` object into a one-element list, so a record written by an
  older build loads unchanged.

  An earlier draft of this release left the old spelling unreadable, on the
  reasoning that a stale row must not deserialize into a channel that looks
  paired and has no endpoints. That reasoning is sound and is kept — it argues
  against defaulting the field to *empty*, which is a different thing from
  upcasting it. Lifting `transport` into `[transport]` yields a channel with
  the right endpoint; there was never a reason for the two to share an answer.
  A record naming no endpoint at all — absent under both spellings, or present
  and empty — is still a loud deserialization error, and now says which of the
  two it was. The same treatment the recoverable secret payload already got
  one type over, applied to the format that did not get it.

- **Channel records carry a schema version.**

  Every `HelperChannel` and `ReplicaMember` the library writes now leads with
  `"schema_version": 3`, and a record claiming a version this build does not
  understand is refused rather than read with the unknown fields dropped and
  written back truncated.

  Applications persist these records as opaque blobs whose shape the *library*
  owns, which is what made the `transport` → `transports` change a migration no
  application could write without knowing a schema it does not define. The
  marker is what lets the library keep doing that migration itself: a reader
  can tell a record apart by the shape it was written in rather than by
  guessing from which fields happen to be present. It has to exist *before*
  the next shape change, not after, which is why it lands now while it is free.

  A record written before the marker existed reads as version 0 and is
  upgraded on load, so nothing has to be rewritten ahead of time. The Go and
  .NET bridges rebuild this JSON from their own structs rather than passing
  the bytes through, so both stamp the marker too; the Rust test now asserts
  the exact serialized text, which is what makes a field added or reordered
  here fail on the core side instead of only in a hand-written SDK expectation
  that nothing cross-checked.

- **Recoverable secret payload format v3, with v2 still readable.**

  A roster entry now carries `transports`: every endpoint a peer advertised,
  each with its protocol discriminant, replacing v2's single `transport_uri`
  string. New secrets are written as v3.

  **v2 payloads keep decoding** — a secret protected before this release is
  still recoverable. Each stored URI is lifted into a one-element list, with
  the protocol derived from its scheme. A URI whose scheme names no known
  transport yields no endpoint rather than a guessed one.

  Storing the discriminant outright also retires a bug class: v2's bare URI
  forced recovery to *reconstruct* the protocol on every rehydration, which
  silently rewrote every non-HTTPS peer to HTTPS.

  The roster type follows in every binding. In .NET that is
  `HelperInfo.TransportUri` / `ReplicaInfo.TransportUri` becoming
  `Transports: IReadOnlyList<TransportProtocol>`; Go, Node, web and React
  Native already exposed `transports`. .NET's `TransportProtocol` now pins
  its JSON property names to `uri` / `protocol`, which is what the library
  reads when a recovered secret is handed back to `RestoreAsync`.

- **gRPC transport.** `Protocol` gains a second discriminant, `GRPC = 1`,
  alongside the existing `HTTPS = 0`. Recognized `TransportProtocol` URI
  schemes are, exactly: `https://`, `http://`, `grpcs://`, `grpc://`.
  `derec-proto` also gains a `DeRecTransport` gRPC service contract
  (`rpc Send(DeRecMessage) returns (google.protobuf.Empty)`) mirroring the
  library's existing `DeRecTransport` trait one-for-one, for applications
  that implement the gRPC side themselves — the library never opens a
  socket, and no `tonic` dependency enters `derec-proto` or `derec-library`.
- **Transport negotiation.** With two transports in the protocol, two peers
  need a way to land on one. `ContactMessage` and `PairRequestMessage` each
  gain a `repeated TransportProtocol supportedTransports` field carrying every
  endpoint the sender serves; the singular `transportProtocol` field stays and
  is what an implementation predating the list reads, so a peer that sends
  neither more nor less than it did before still pairs. Selection is local and
  needs no round trip: each side picks, from what the other offered, the first
  entry matching its **own** preference order —
  `DeRecProtocolBuilder::with_own_transports(…)` sets that order in Rust, and
  `WithOwnTransports` (.NET), `withOwnTransports` (Node.js / Web) and
  `Config.OwnTransports` (Go) are its equivalents. The existing
  single-endpoint `with_own_transport` and its SDK counterparts remain fully
  supported and mean a one-element list. Offers failing structure or scheme
  policy are skipped rather than fatal, so a peer advertising both a plaintext
  and a secure endpoint still pairs over the secure one; only an empty
  survivor set fails, as `Error::NoUsableEndpoint { offered }`, which names how
  many endpoints the peer actually sent rather than what survived filtering.
  SDKs surface that variant under one name in every binding: the error code
  `NO_USABLE_ENDPOINT` (Node / web / React Native) and
  `DEREC_CODE_NO_USABLE_ENDPOINT = 121` (C FFI, and therefore .NET and Go). At
  pairing the error is terminal — delivery is push-only, so a
  peer whose transport this application cannot speak also cannot be sent a
  rejection.
- **Behavior change: `UpdateChannelInfo` refuses an unservable transport
  switch.** An established peer announcing a move to a transport this side
  serves no endpoint for previously had that endpoint recorded verbatim,
  which silently pointed every later message at an address the application
  could not deliver to. It is now refused before the `ActionRequired` event:
  the handler returns `Error::NoUsableEndpoint` and the new
  `StatusEnum::UNSUPPORTED_TRANSPORT_PROTOCOL = 12` is sent back over the
  peer's still-working previous endpoint. Unlike the pairing case this is
  deliverable — the channel is already up — so the announcement fails loudly
  instead of silently. Applications relying on `UpdateChannelInfo` to record
  any endpoint a peer names must now serve the transport being switched to.
- **`unsafe_connection` supersedes `unsafe_http`, and setting both to
  disagreeing values is now an error.**
  `DeRecProtocolBuilder::with_unsafe_connection` is the new plaintext opt-in
  covering both gated schemes (`http://` and `grpc://`); the previous
  `with_unsafe_http` is deprecated but still functional. **Either flag alone
  is honored**, so an existing deployment that only knows the old one keeps
  its behavior after upgrading — that is the compatibility case, and it is
  undisturbed. The distinction is *presence*, not value: an SDK that never
  sets `unsafe_http` sends nothing, which must not override a deliberate
  `unsafe_connection`.

  Both present and disagreeing is refused at construction with
  `Error::ConflictingPlaintextOptIn { unsafe_http, unsafe_connection }`,
  naming both flags and the values given. An earlier draft resolved it by
  precedence — the deprecated flag won, with a `tracing` warning. That is
  right when a human wrote both values and wrong when a machine wrote one of
  them: generated config, defaults-merging and IaC layers routinely emit
  every field, so a defaulted `unsafe_http: false` would beat a deliberate
  `unsafe_connection: true`. Nothing would fail; plaintext endpoints would
  simply be refused, and the operator would be left debugging a flag that
  appeared to do nothing, with the only signal a log line a library consumer
  has probably not wired up. A five-second failure at startup is the better
  trade, and it disappears at 0.0.5 when `unsafe_http` is removed.

  Surfaced as `DEREC_CODE_CONFLICTING_PLAINTEXT_OPT_IN = 122` in the C FFI
  (and therefore `DeRecCode.ConflictingPlaintextOptIn` in .NET and
  `derec.CodeConflictingPlaintextOptIn` in Go), and as the error code
  `CONFLICTING_PLAINTEXT_OPT_IN` in Node, web and React Native.
- **Breaking (all bindings): the pairing primitives take a transport *list*,
  and there are no `_multi` siblings.** `request::create_contact`,
  `request::produce` and `response::produce` each take every endpoint the
  application serves, in its own preference order, rather than a single
  endpoint. The whole list is advertised in `supportedTransports`; the
  **first entry** also fills the legacy singular `transportProtocol` field
  for peers predating the offer list. That order is the application's and is
  never reinterpreted — an application that must pair with peers predating
  gRPC puts an HTTPS endpoint first, since those peers understand no other
  protocol discriminant.

  A transitional `create_contact_multi` / `produce_multi` split was
  considered and rejected. The singular-to-list change is not confined to
  these two functions: it touches the channel store trait, the transport
  trait, `HelperChannel` and `ReplicaMember`, the builder, and five proto
  messages. A deprecation train means carrying two spellings of all of that
  through 0.0.4 — to give a migration window to consumers of a version that
  has not shipped. The one consumer that exists migrated in 12 files against
  this working tree, and the `SequentialFailover` /
  `SingleEndpointTransport` adapters give an unmodified single-endpoint
  transport a working path without a parallel API surface. Had 0.0.3 been
  tagged, this would be a different answer.

  `response::produce` is the exception and moves the other way: it drops the
  responder's own transports entirely and takes a `TransportPolicy` instead,
  because it filters the requester's offers rather than ranking them against
  anything local. See the `pairing.response.produce` entry above for its full
  signature and per-binding result change.

  Migration (Rust): for `request::create_contact` and `request::produce`, wrap
  the existing argument — `transport` becomes `vec![transport]`. For
  `response::produce`, drop the endpoint argument and pass a policy;
  `TransportPolicy::new(false)` is the production posture.

  Migration (FFI / SDKs): the `create_contact_message` and
  `produce_pair_request_message` C entry points keep their shape but now
  read a **length-delimited** sequence of encoded `TransportProtocol`
  messages — each entry preceded by its protobuf varint byte length, the
  same framing protobuf uses for a repeated embedded message field.
  `produce_pair_response_message` moves the other way: it drops
  `transport_protocols_ptr` and `transport_protocols_len` and gains a
  `unsafe_connection` flag. The .NET, Go, Node, React Native and web surfaces
  were updated accordingly; each takes a list where it previously took one
  endpoint, except the pair-response entry point, which now takes none.

- **Breaking (Go SDK): `Config.UnsafeHTTP` changed from `bool` to `*bool`.**
  The `unsafe_connection` / `unsafe_http` conflict rule is presence-based —
  the library must be able to tell "the caller never set this field" apart
  from "the caller explicitly set it to false" — and a plain `bool` cannot
  represent that distinction: it would always serialize `false` when unset
  and silently override a deliberately-set `UnsafeConnection`. `Config.UnsafeHTTP`
  in `packages/go/protocol/protocol.go` is therefore `*bool`, matching the
  new `Config.UnsafeConnection` field. Existing code that writes
  `UnsafeHTTP: true` no longer compiles. Migration: take the address of a
  local bool, `allow := true; cfg.UnsafeHTTP = &allow`, or switch to the new
  field, `cfg.UnsafeConnection = &allow` (see `smoke-tests/go/protocol.go`
  for the updated call site).
- **Breaking (Rust): `DeRecProtocol::new`'s transport parameter changed from
  `TransportProtocol` to `Vec<TransportProtocol>`.** The builder now carries
  a preference-ordered list of every endpoint this application serves
  (`DeRecProtocolBuilder::with_own_transports`, alongside the existing
  single-endpoint `with_own_transport`), and `DeRecProtocol` stores that
  full list as `own_transports`. Constructing with a single endpoint and
  overwriting the field afterward was rejected as the fix, because it
  leaves a window where the protocol object is holding a one-element list
  it never actually validated against the caller's real configuration —
  worse than a compile-time break. Migration for a direct caller: wrap the
  existing argument, `TransportProtocol { .. }` becomes
  `vec![TransportProtocol { .. }]`. The documented construction path is
  `DeRecProtocolBuilder`, not this constructor, so direct callers of `new`
  should be rare.
- **Observable behavior change.** `TransportProtocol::try_from("ws://…")`,
  and any other URI whose scheme is outside `{https, http, grpcs, grpc}`,
  now returns `TransportValidationError::UnknownScheme` where it previously
  returned `SchemeMismatch { expected: "https://" }`. Both variants already
  existed, so this does not break compilation, but code that matches
  specifically on `SchemeMismatch` to detect an unsupported scheme now takes
  the `UnknownScheme` branch instead and should be updated.
