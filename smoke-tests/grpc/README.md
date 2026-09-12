# DeRec over gRPC — transport reference

`derec-library` never opens a socket. It hands finished envelope bytes to a
`DeRecTransport` you supply and expects inbound bytes back through
`DeRecProtocol::process`. Everything between those two points — sockets,
retries, TLS, authentication — belongs to the application.

This crate is a working implementation of that seam over gRPC. Its sibling
directories (`../rust`, `../go`, `../nodejs`, `../dotnet`, …) smoke-test
*language bindings*; this one tests no binding at all. It exists so an
application author has something concrete to copy.

Run it:

```bash
cargo run -p derec-grpc-transport-smoke-test
```

Three nodes come up on loopback — an owner and two helpers — pair over the
wire, distribute a threshold-split secret, and prove possession of it:

```
[owner] listening on grpc://127.0.0.1:50051
[helper-a] listening on grpc://127.0.0.1:50052
[helper-b] listening on grpc://127.0.0.1:50053
[pair] owner and helper-a paired ✓
[pair] owner and helper-b paired ✓
[protect] share v1 stored and confirmed by both helpers ✓
[verify] both helpers proved possession of v1 ✓
```

### Why two helpers, and the silent failure behind it

**Pairing fewer than `threshold` helpers stores nothing, and tells you
nothing.** `start(ProtectSecret)` returns `Ok(())`, no helper is contacted,
and no `ShareStored` or `ShareConfirmed` event ever arrives. The flow just
does not happen. The library gates the split on `helpers.len() >=
threshold`; below that it skips distribution entirely and raises no error.

That is the clause that costs an afternoon, because there is nothing to
debug — no exception, no failed event, no log line. If a `ProtectSecret`
looks like it did nothing, count your paired helpers first.

The other clause is loud and you meet it immediately: `build()` rejects any
`threshold` below `2`, since a lone helper who can reconstruct the secret is
not threshold sharing.

Put together, two paired helpers is the floor before a single share moves.
Setting `threshold = 2` and pairing one helper satisfies the builder and
still silently stores nothing — which is why this test runs three nodes
rather than two.

## The service

`protobufs/protobufs/derectransport.proto` defines the whole contract:

```protobuf
service DeRecTransport {
  rpc Send(DeRecMessage) returns (google.protobuf.Empty);
}
```

One method. One envelope in, nothing out.

## Delivery is push-only — both sides must run a server

`Send` returns `Empty`, so **a request never carries its reply**. When a
helper answers a `StoreShareRequest`, it does so by opening a *new* `Send`
against the owner's own advertised endpoint. Requests and responses are
correlated by the envelope's `traceId`, not by the RPC that delivered them.

Three consequences worth internalising before you write any code:

1. **Every participant is a server.** A node that can dial but not be dialled
   can send requests and will never see the answers. There is no
   client-only mode.
2. **Your endpoint must be reachable by peers, not just by you.** The URI
   passed to `with_own_transport` is embedded in contacts and pairing
   messages; it is the address peers will dial. Behind NAT or a load
   balancer, advertise the externally reachable address, not the bind
   address.
3. **Return from the handler quickly, and process afterwards.** See below.

## Do not process inbound envelopes inside the handler

The server handler in `src/main.rs` pushes the envelope onto a queue and
returns immediately; a separate task drains that queue into
`DeRecProtocol::process`. This is not an optimisation — processing inline
deadlocks:

- The owner holds its protocol lock while `start(ProtectSecret)` dials the
  helper.
- The helper's handler takes the helper's lock and calls `process`, which
  produces a response and dials the owner to deliver it.
- The owner's handler blocks waiting for the owner's lock, which the owner
  is still holding while it waits for the helper's call to return.

`Send` returning `Empty` is precisely what makes deferring correct: the
caller is being told the envelope was *accepted*, not that it was acted
upon. Acceptance is a transport fact; the protocol answer comes later, on
its own connection.

## `grpc://` is a DeRec spelling, not a URL scheme

DeRec validates exactly four schemes: `https://`, `http://`, `grpcs://`,
`grpc://`. The last two both map to `Protocol::Grpc`. No gRPC client dials a
`grpc://` URL, though — the wire underneath is ordinary HTTP/2 — so the
transport translates before connecting:

```rust
uri.replacen("grpcs://", "https://", 1)
   .replacen("grpc://", "http://", 1)
```

Advertise `grpc://` / `grpcs://` to peers; dial `http://` / `https://`.

## The `check_peer` loopback trap

**Every builder must set `.with_unsafe_connection(true)` — all three here —
even though everything is on `127.0.0.1`.** Skipping it fails pairing with:

```
plaintext transport endpoint refused (grpc://127.0.0.1:50052)
```

The reason is that plaintext is judged twice, under different rules:

- `TransportPolicy::check_own` exempts *your own* loopback endpoint. A node
  advertising `grpc://127.0.0.1:50051` builds fine with no opt-in.
- `TransportPolicy::check_peer` grants **no loopback exemption at all**. A
  peer-supplied endpoint may never be plaintext by default, wherever it
  points.

Every node in a local test receives the *other* nodes' `grpc://127.0.0.1:…`
as **peer** endpoints during pairing, so `check_peer` is what decides — and
it refuses. "It's all localhost" is not a reason to expect this to work.

`with_unsafe_connection` covers both plaintext schemes (`http://` and
`grpc://`). It supersedes the deprecated `with_unsafe_http`. It is a
development switch: in production, advertise `grpcs://` and leave it off.

## What to copy

`src/transport.rs` is the artifact. It is short and depends on nothing else
in this smoke test:

- `dial_uri` — the scheme translation above.
- `GrpcTransport` — a `DeRecTransport` that decodes the envelope bytes and
  delivers them as one unary call.

`build.rs` is worth copying too. It maps the proto package onto the
already-generated Rust types:

```rust
.extern_path(".org.derecalliance.derec.protobuf", "::derec_proto")
```

Without that, `tonic-prost-build` emits a second, structurally identical
copy of every DeRec message, and your transport ends up converting between
two `DeRecMessage` types that only differ by which crate defines them. With
it, the generated client and server speak exactly the `derec_proto` types
the library already hands you.

## Error reporting

`DeRecTransport::send` returns `derec_library::Result<()>`, whose error type
carries only `&'static str` messages — there is no delivery-failure variant
that can hold a connection error. `GrpcTransport` therefore returns a fixed
`Error::InvalidInput` and logs the underlying `tonic` detail through
`tracing` (behind this crate's `logging` feature). If you need the detail
at the call site, capture it in your transport before returning.

## Not covered here

**TLS.** `dial_uri` maps `grpcs://` to `https://`, but this crate depends on
`tonic` with default features, which ship no TLS backend — so the `grpcs://`
branch fails when it tries to connect, not when it compiles. Enable
`tls-ring` or `tls-aws-lc` plus a trust anchor set (`tls-native-roots` or
`tls-webpki-roots`) and configure the channel with `ClientTlsConfig` before
advertising a `grpcs://` endpoint. The same caveat is repeated on `dial_uri`
in `transport.rs`, since that file gets copied on its own.

Also absent: peer authentication, retry and backoff, connection pooling, and
message-size limits. `GrpcTransport` opens a fresh connection per envelope,
which is the clearest thing to read and the wrong thing to ship. Reuse a
`DeRecTransportClient` per endpoint in production.
