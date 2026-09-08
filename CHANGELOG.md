# Changelog

Notable changes to `derec-library`, `derec-proto` and `derec-cryptography`,
and to the .NET, Go, Node, React Native and web SDKs built on them.

Breaking changes are called out explicitly, with the migration alongside
them. The three crates and the SDKs share a version, so an entry applies to
all of them unless it names a specific binding.

### 0.0.3

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

  **Nothing to change in your store.** Keep applying the filter in your query:
  that is where the bandwidth and the metered-read cost are saved, and it is
  still your job to apply it faithfully. What changed is only that the library
  no longer trusts a listing it did not produce.

- **Fixed: two deprecation notices showed no migration.** The `set_own_transport`
  and `with_own_transport` doc examples had an identical "before" and "after",
  from a search-and-replace that caught the wrong line too. Both now show the
  singular call being replaced by the plural one.

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

  **Implementations must apply the filter.** It is not a hint. The point is
  that a store can express it as a query — a `WHERE` clause, a key-condition
  expression — instead of moving rows the caller will drop. That transfer costs
  bandwidth everywhere, and on a metered backing such as DynamoDB, which bills
  by bytes read, it costs money. A backend that cannot push it down can list
  and call `ChannelFilter::matches`, which is correct but gives up the saving.

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

  `replyTo` changes from a singular field to a repeated one **on the same
  tag**, on all five request types — `StoreShare`, `VerifyShare`,
  `GetSecretIdsVersions`, `GetShare`, `Unpair`. No new field is introduced.

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
  - **Go** — unaffected: it does not expose `reply_to`.

  **Wire compatibility.** Singular and repeated message fields share an
  encoding, so a 0.0.2 peer sending one endpoint decodes here as a
  one-element list, and an unset field decodes as empty. In the other
  direction a 0.0.2 reader *merges* a multi-entry list and sees only the
  **last** entry — so an application still talking to 0.0.2 peers should
  order its list with the endpoint those peers understand last. All three
  behaviours are pinned by tests in `derec-proto`.

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
  none. `endpoints` is never empty.

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
  library, so there is no compile error to catch this. A record written by
  an older build **fails to load** with a missing-field error for
  `transports`. That is deliberate — the field carries no `serde(default)`,
  precisely so a stale row cannot deserialize into a channel that looks
  paired and has no endpoints. Migrating a stored row means wrapping its
  `transport` object in an array; the rest of the record is unchanged.

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
  survivor set fails, as `Error::NoCommonTransport { offered, supported }`,
  which names what the peer actually sent rather than what survived
  filtering. At pairing that error is terminal — delivery is push-only, so a
  peer whose transport this application cannot speak also cannot be sent a
  rejection.
- **Behavior change: `UpdateChannelInfo` refuses an unservable transport
  switch.** An established peer announcing a move to a transport this side
  serves no endpoint for previously had that endpoint recorded verbatim,
  which silently pointed every later message at an address the application
  could not deliver to. It is now refused before the `ActionRequired` event:
  the handler returns `Error::NoCommonTransport` and the new
  `StatusEnum::UNSUPPORTED_TRANSPORT_PROTOCOL = 12` is sent back over the
  peer's still-working previous endpoint. Unlike the pairing case this is
  deliverable — the channel is already up — so the announcement fails loudly
  instead of silently. Applications relying on `UpdateChannelInfo` to record
  any endpoint a peer names must now serve the transport being switched to.
- **`unsafe_connection` supersedes `unsafe_http`.**
  `DeRecProtocolBuilder::with_unsafe_connection` is the new plaintext opt-in
  covering both gated schemes (`http://` and `grpc://`); the previous
  `with_unsafe_http` is deprecated but still functional. Both flags are
  honored, and when both are set and disagree, **the deprecated
  `unsafe_http` wins** — an existing deployment that only knows the old flag
  keeps its current behavior after upgrading. The distinction is
  *presence*, not value: an SDK that never sets `unsafe_http` sends nothing,
  which must not override a deliberate `unsafe_connection` setting.
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
  considered and rejected: it left the FFI primitives layer bound to the
  single-endpoint entry points, so SDK applications built on primitives
  silently kept pre-negotiation behaviour — no offer list advertised and no
  selection performed. One function per operation makes that impossible.

  `response::produce` additionally takes `own_transports` and a
  `TransportPolicy`, because it now selects the reply endpoint from the
  requester's offers instead of trusting the requester's singular field.

  Migration (Rust): wrap the existing argument, `transport` becomes
  `vec![transport]`. For `response::produce`, pass the endpoints you serve
  and a policy — `TransportPolicy::new(false)` is the production posture.

  Migration (FFI / SDKs): the `create_contact_message` and
  `produce_pair_request_message` C entry points keep their shape but now
  read a **length-delimited** sequence of encoded `TransportProtocol`
  messages — each entry preceded by its protobuf varint byte length, the
  same framing protobuf uses for a repeated embedded message field.
  `produce_pair_response_message` gains `transport_protocols_ptr`,
  `transport_protocols_len` and a `unsafe_connection` flag. The .NET, Go,
  Node, React Native and web surfaces were updated accordingly; each takes
  a list where it previously took one endpoint.

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
