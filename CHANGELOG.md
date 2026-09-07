# Changelog

Notable changes to `derec-library`, `derec-proto` and `derec-cryptography`,
and to the .NET, Go, Node, React Native and web SDKs built on them.

Breaking changes are called out explicitly, with the migration alongside
them. The three crates and the SDKs share a version, so an entry applies to
all of them unless it names a specific binding.

### 0.0.3

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
