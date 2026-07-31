# DeRec Go SDK

Go bindings for `derec-library`, the Rust SDK implementing the DeRec protocol.

DeRec enables decentralized recovery of secrets by distributing encrypted shares across trusted helpers.

---

## Installation

```bash
go get github.com/derecalliance/lib-derec/packages/go
```

---

## Requirements

- Go 1.23+
- **No cgo.** The bridge to the Rust core is pure Go, via [`ebitengine/purego`](https://github.com/ebitengine/purego) — no C compiler is required to build or consume this module.
- Supported platforms: `darwin`/`linux` × `amd64`/`arm64`. The compiled Rust core is embedded per-platform in the module; there are no external native dependencies to install.

---

## Design Overview

The Go SDK is a **thin binding layer** over the Rust implementation. All core logic is executed in Rust:

- Protobuf serialization / deserialization
- Cryptography (pairing, encryption, verification)
- DeRecMessage envelope construction
- Protocol validation

The Go API operates on `[]byte` wire messages plus a small set of typed Go structs (proto-decoded results, store domain types, events) — no protocol logic lives in Go. Errors surface as `*derec.Error`, carrying a `Category` and `Code` from the [`derec`](derec/error.go) package.

---

## Quick Example

```go
package main

import (
	"fmt"

	"github.com/derecalliance/lib-derec/packages/go/primitives/verification"
)

func main() {
	var (
		channelID uint64 = 1
		secretID  uint64 = 42
		version   uint32 = 1
		sharedKey        = make([]byte, 32) // established during pairing
	)

	envelope, err := verification.Request.Produce(channelID, secretID, version, sharedKey)
	if err != nil {
		panic(err)
	}
	// envelope carries the encoded DeRecMessage, ready to send over transport.

	req, err := verification.Request.Extract(envelope, sharedKey)
	if err != nil {
		panic(err)
	}
	fmt.Printf("challenge for channel %d\n", req.ChannelID)
}
```

---

## Pairing Flow

The `ContactMessage` is exchanged out-of-band (QR codes, existing messaging channels, etc.). The `pairing.ContactMode` values select how the public encryption material is delivered:

| Mode | What the contact carries | Use when |
|---|---|---|
| `ContactModeInlineKeys` (default) | Full ML-KEM encapsulation key + ECIES public key | Out-of-band channel can carry the keys (NFC, messaging). |
| `ContactModeHashedKeys` | Only a SHA-384 commitment to the keys | Channel is size-constrained (QR codes). Scanner fetches the actual keys via a plaintext `PrePair` round-trip and verifies them against the hash. |

After the handshake completes, **both modes** rekey the channel id: the responder derives a new id from the shared key, includes it in the encrypted pairing response, and both sides switch their local state to it. The new id never appears in plaintext on the wire.

### `InlineKeys` flow

```go
package main

import (
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/pairing"
	"google.golang.org/protobuf/proto"
)

func transportBytes(uri string) []byte {
	wire, _ := proto.Marshal(&derecpb.TransportProtocol{
		Uri:      uri,
		Protocol: derecpb.Protocol_HTTPS,
	})
	return wire
}

func main() {
	const channelID = uint64(1)

	// Step 1: Initiator creates the out-of-band ContactMessage.
	aliceTransport := transportBytes("https://owner.example.com")
	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, aliceTransport, nil)
	must(err)

	// Step 2: Responder produces a pairing request from the contact.
	bobTransport := transportBytes("https://helper.example.com")
	producedReq, err := pairing.Request.Produce(pairing.SenderKindHelper, bobTransport, created.ContactWireBytes, nil, nil)
	must(err)

	// Step 3: Initiator extracts the request and produces the response.
	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial)
	must(err)
	producedResp, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil)
	must(err)

	// Step 4: Responder extracts and processes the response.
	extractedResp, err := pairing.Response.Extract(producedResp.Envelope, producedReq.SecretKeyMaterial)
	must(err)
	processed, err := pairing.Response.Process(producedReq.InitiatorContactMessage, extractedResp.ResponseProto, producedReq.SecretKeyMaterial)
	must(err)

	// Both sides hold the same shared key and rekeyed channel id.
	// producedResp.SharedKey   == processed.SharedKey
	// producedResp.ChannelID   == processed.ChannelID  !=  channelID
	//
	// Rename local channel state from `channelID` to the rekeyed id
	// before sending any further traffic.
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
```

To reject a pairing request, build a `PairResponseMessage` with a non-OK status encrypted against the peer's ECIES public key — the higher-level `protocol.DeRecProtocol`'s `Reject` method does this for you. A peer's non-OK response surfaces from `pairing.Response.Process` as a `*derec.Error` with `Code == derec.CodeNonOKStatus`, carrying `PeerStatus` / `PeerMemo`.

### `HashedKeys` flow (PrePair)

`ContactModeHashedKeys` adds one plaintext round-trip before the regular `InlineKeys` handshake: `pairing.Request.ProducePrePair` / `ExtractPrePair` and `pairing.Response.ProducePrePair` / `ExtractPrePair` / `ProcessPrePair`. The scanner fetches the real keys via `PrePair`, and `Response.ProcessPrePair` verifies them against the contact's binding hash before the caller synthesizes an `InlineKeys`-shaped contact and runs the normal handshake against it.

```go
validated, err := pairing.Response.ProcessPrePair(created.ContactWireBytes, extractedPrePairResp.ResponseProto)
if err != nil {
	var derecErr *derec.Error
	if errors.As(err, &derecErr) && derecErr.Code == derec.CodePrepairHashMismatch {
		// The keys published by the peer do not match the commitment the
		// scanner originally accepted. Do NOT proceed to a regular pairing
		// request — surface this to the user as a failed scan.
	}
	return err
}
// validated.MlkemEncapsulationKey / validated.EciesPublicKey / validated.Nonce
```

The transport URI used for the `PrePair` leg **must** be ephemeral — `PrePair` envelopes are plaintext. Swap to a long-term endpoint via an `UpdateChannelInfo` flow once pairing completes. See `bindings/go/primitives.go::runPairingFlow` for a complete, compiling handshake.

---

## Share Distribution (Sharing)

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/sharing"

secretID := uint64(42)
secretData := []byte("super-secret")
channelIDs := []uint64{1, 2, 3}
const threshold = 2 // must satisfy 2 <= threshold <= len(channelIDs)
const version = uint32(1)

shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
// shares: map[uint64][]byte — channel id -> one CommittedDeRecShare per helper.

for channelID, committedShare := range shares {
	envelope, err := sharing.Request.Produce(channelID, version, secretID, committedShare, nil, "", sharedKeys[channelID])
	// send envelope over your transport
}
```

The helper side extracts with `sharing.Request.Extract`, persists the request, and answers with `sharing.Response.Produce` (returning the `CommittedShare`, `SecretID`, and `Version` it stored). The owner confirms with `sharing.Response.Extract` + `sharing.Response.Process`.

---

## Verification Flow

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/verification"

// Owner side: produce the challenge.
requestEnvelope, err := verification.Request.Produce(channelID, secretID, version, sharedKey)

// Helper side: decrypt and answer with proof of possession.
req, err := verification.Request.Extract(requestEnvelope, sharedKey)
responseEnvelope, err := verification.Response.Produce(channelID, req.RequestProto, sharedKey, storedShareContent)

// Owner side: decrypt and verify the proof.
resp, err := verification.Response.Extract(responseEnvelope, sharedKey)
valid, err := verification.Response.Process(req.RequestProto, resp.ResponseProto, storedShareContent)
```

---

## Recovery Flow

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/recovery"

// Owner side: request the stored share from each paired helper.
requestEnvelope, err := recovery.Request.Produce(channelID, secretID, version, sharedKey)

// Helper side: answer using the StoreShareRequest proto it persisted at sharing time.
req, err := recovery.Request.Extract(requestEnvelope, sharedKey)
responseEnvelope, err := recovery.Response.Produce(channelID, req.RequestProto, storedShareProto, sharedKey)

// Owner side: collect at least `threshold` responses and reconstruct.
recovered, err := recovery.Response.Recover([]recovery.ShareResponse{
	{Response: responseEnvelope, SharedKey: sharedKey},
	// …additional helper responses…
}, secretID, version)
// recovered is the reconstructed secret's raw bytes.
```

`Recover` requires every response to agree on the same Merkle root and ciphertext; an inconsistent or below-threshold set is reported as a `*derec.Error`, not a corrupted result.

---

## Discovery Flow

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/discovery"

// Owner side: ask a helper which secret ids/versions it holds.
requestEnvelope, err := discovery.Request.Produce(channelID, sharedKey)

// Helper side: decrypt and advertise its stored versions.
_, err = discovery.Request.Extract(requestEnvelope, sharedKey)
responseEnvelope, err := discovery.Response.Produce(channelID, []discovery.SecretVersionEntry{
	{SecretID: 0xABCD, Versions: []discovery.VersionEntry{
		{Version: 1, Description: "wallet seed"},
	}},
}, sharedKey)

// Owner side: decrypt and read the advertised list.
resp, err := discovery.Response.Extract(responseEnvelope, sharedKey)
secretList, err := discovery.Response.Process(resp.ResponseProto)
```

---

## The `protocol.DeRecProtocol` Orchestrator

For applications that don't want to drive the primitive produce/extract/process surface by hand, `protocol.DeRecProtocol` is a stateful orchestrator that owns storage/transport callbacks and drives every flow through `Start` / `Process` / `Accept` / `Reject`. It mirrors the Rust orchestrator and the other DeRec SDKs.

### Store interfaces

`protocol.New` takes six application-supplied interfaces backing all persistence and transport:

- `protocol.ChannelStore` — paired channels, keyed by `(secretID, channelID)`
- `protocol.SecretStore` — pairing/session secret material
- `protocol.ShareStore` — stored shares
- `protocol.UserSecretStore` — the latest user-facing secret snapshot per `secretID`
- `protocol.StateStore` — in-flight orchestrator state (pending verification/recovery/unpair/sharing rounds)
- `protocol.Transport` — outbound delivery (`Send(uri string, protocol int32, message []byte) error`)

### Constructing an instance

```go
import (
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/protocol"
)

cfg := protocol.Config{
	SecretID:             secretID,
	OwnTransportURI:      "https://owner.example.com",
	OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
	Threshold:            2, // default 3
	KeepVersionsCount:    3, // default 3
}

p, err := protocol.New(channelStore, shareStore, secretStore, userSecretStore, stateStore, transport, cfg)
if err != nil {
	panic(err)
}
defer p.Close()
```

`channelStore`/`shareStore`/`secretStore`/`userSecretStore`/`stateStore`/`transport` are your application's implementations of the six interfaces above. See `bindings/go/protocol.go` for complete in-memory implementations (`memChannelStore`, `memShareStore`, `memSecretStore`, `memUserSecretStore`, `memStateStore`, `memTransport`) used by the SDK's own smoke test.

### Driving a flow

```go
// Contact creator (either Owner or Helper) mints a contact out-of-band.
contact, err := p.CreateContact(nil, protocol.ContactModeInlineKeys, nil)

// Peer starts the handshake from it.
events, err := peer.Start(protocol.FlowKindPairing, protocol.PairingParams{
	Kind:    int32(protocol.SenderKindHelper),
	Contact: contact.ContactBytes,
})

// Feed inbound wire bytes from your transport to Process; it returns the
// events produced (peer confirmations, ActionRequired prompts, ...).
events, err = p.Process(inboundBytes)
for _, ev := range events {
	switch ev.Type {
	case protocol.EventTypePairingCompleted:
		// ev.ChannelID now holds the rekeyed channel id.
	case protocol.EventTypeActionRequired:
		// Application decides: p.Accept(ev.Action) or p.Reject(ev.Action, status, memo).
		_, err = p.Accept(ev.Action)
	}
}
```

`Start` accepts a `FlowKind` plus the matching params struct: `protocol.PairingParams`, `protocol.DiscoveryParams`, `protocol.ProtectSecretParams`, `protocol.VerifySharesParams`, `protocol.RecoverSecretParams`, `protocol.UnpairParams`, or `protocol.UpdateChannelInfoParams`. Fan-out flows (`FlowKindDiscovery`, `FlowKindVerifyShares`, `FlowKindUpdateChannelInfo`) take a `protocol.Target`, built with `protocol.TargetAll()`, `protocol.TargetOne(channelID)`, or `protocol.TargetMany(channelIDs...)`.

`Process` returns `[]protocol.Event`, decoded from the same JSON event stream the Rust core emits — compare `Event.Type` against the `protocol.EventType*` constants (`EventTypePairingCompleted`, `EventTypeShareStored`, `EventTypeShareConfirmed`, `EventTypeSecretRecovered`, `EventTypeActionRequired`, …) rather than hand-typing the string.

When recovering a secret onto a fresh instance, pass the typed `Secret` from a `SecretRecovered` (or `ReplicaSecretReceived`) event to `p.Restore(secret, version)` to commit canonical helper state and wipe the throwaway recovery-mode channels.

Reference: `bindings/go/protocol.go` (`runProtocol`) drives a complete Owner + two Helpers pairing → protect-secret → `ShareStored`/`ShareConfirmed` flow using only the public `protocol` package.

---

## Package Layout

- [`derec`](derec/) — the shared error vocabulary: `derec.Error` (`Category`, `Code`, `Message`, `PeerStatus`, `PeerMemo`, `Expected`, `Got`) and the `Category*`/`Code*` constants every fallible call can return.
- [`derecpb`](derecpb/) — generated protobuf Go types for the DeRec wire messages (`TransportProtocol`, `CommunicationInfo`, `ContactMessage`, …).
- [`primitives`](primitives/) — one package per flow (`pairing`, `sharing`, `verification`, `recovery`, `discovery`, `unpairing`, `envelope`), each exposing stateless `Request`/`Response` produce/extract/process functions operating on raw bytes.
- [`protocol`](protocol/) — the stateful `DeRecProtocol` orchestrator, its six store interfaces, `Config`, `FlowKind`/`ContactMode` constants, and the `Event` type.

`internal/native` is the purego/C-ABI bridge to the compiled Rust core. It is a Go-internal package — not part of this module's public API — and is never imported directly by consumers; use `derec`, `derecpb`, `primitives/*`, and `protocol` only.

---

## Security Considerations

### Replica destinations inherit Source trust

A recovered/synced `Secret` (carried by `ReplicaSecretReceived` and `SecretRecovered` events) embeds every helper's channel id and shared key. Anyone holding it can therefore authenticate as the Source toward every helper. This is intentional — it is what makes Destination-driven recovery work — but it means a compromised replica Destination can impersonate the Source against every helper paired at the time the secret was synced. Pick Destinations with at least the trust level of the Source device itself; do not treat them as opaque backups.

All replicas of one `secretID` also share a single **group channel key**: every replica channel's shared-key entry holds the same 32 bytes, established at the first replica pair and handed to every subsequent joiner. Compromise of any one Destination therefore exposes that single key; the protocol does not provide per-pair forward secrecy across replicas.

### `ContactModeHashedKeys` requires an ephemeral transport URI

`HashedKeys` ships only a SHA-384 binding hash in the contact and serves the actual public keys through a plaintext `PrePair` round-trip on the contact creator's own transport. Any party that can reach that URI before the legitimate scanner gets the keys. Use `HashedKeys` only with a transport endpoint that is freshly minted for the pairing and retired as soon as the `PrePair` leg completes. `ContactModeInlineKeys` has no such constraint.

The recommended pattern: pair on the ephemeral URI, then — as soon as pairing completes on the contact-creator side — call `SetOwnTransport` with the permanent endpoint and start an `UpdateChannelInfo` flow to announce the swap. This keeps the plaintext `PrePair` window tight while subsequent traffic rides on the long-lived endpoint.

### Replica fingerprint verification is mandatory

Replica channels are created `Pending` and remain there until both sides call `VerifyFingerprint` with the value the peer derived from the shared key — confirmed out of band. The orchestrator enforces this: `Start(FlowKindProtectSecret, ...)` rejects a target that is still `Pending`. Treat verification as a required step in the pairing UX — a scanner that auto-pairs without it accepts a MITM-vulnerable replica.

### The `derec.*` `communicationInfo` namespace is library-owned

`CommunicationInfo` is otherwise an opaque application-defined map, but every key under the `derec.` prefix is reserved for the protocol. Application code must not write any `derec.*` entry — the orchestrator silently overwrites or strips library-owned keys at the protocol boundary, and app-set values are lost without warning.

---

## Documentation

- DeRec Alliance: https://derec.org
- Protocol specification: https://derec-alliance.gitbook.io/docs/protocol-specification/protocol-overview
- Rust SDK: https://github.com/derecalliance/lib-derec

---

## License

Apache License 2.0

See `LICENSE` for details.
