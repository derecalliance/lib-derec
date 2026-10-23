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

## Protocol schema

The module ships the DeRec `.proto` schema under `derecpb/schema/` so you can
generate code for any language without a `lib-derec` checkout:

- `derecpb/schema/proto/` — the 18 schema files, flat. Every import is a bare
  filename, so a single include root resolves the whole closure:
  `protoc --proto_path=derecpb/schema/proto derecpb/schema/proto/*.proto`
- `derecpb/schema/derec_descriptor.bin` — the same closure precompiled,
  well-known types included. Needs no include path at all. Compiled with
  `--include_source_info`, so code generated from it keeps the protocol's doc
  comments instead of emitting bare type declarations.

Both are also reachable in-process, without touching the filesystem:

```go
import "github.com/derecalliance/lib-derec/packages/go/derecpb/schema"

_ = schema.FileDescriptorSet // []byte
_ = schema.Proto             // embed.FS rooted at "proto"
```

The schema is versioned with the module: `vX.Y.Z` carries exactly the schema
`vX.Y.Z` was built from.

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

	envelope, err := verification.Request.Produce(channelID, secretID, version, sharedKey, nil)
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
| `ContactModeNoKeys` | No key material and no hash | The contact must be small enough for a person to read out or type. The creator generates keys when a `PrePair` request arrives (`Response.ProducePrePairNoKeys` / `Response.ProcessPrePairNoKeys`). Nothing binds those keys to the contact, so the pairing must be confirmed by comparing fingerprints out of band before use — the orchestrator keeps the channel `Pending` until `VerifyFingerprint` succeeds. |

`pairing.Request.EncodeContact` turns a typed `pairing.ContactMessage` into the bytes that travel out of band, and `pairing.Request.DecodeContact` turns them back. Both refuse a contact whose fields do not match its mode.

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
	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial, nil)
	must(err)
	producedResp, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, false)
	must(err)

	// Step 4: Responder extracts and processes the response.
	extractedResp, err := pairing.Response.Extract(producedResp.Envelope, producedReq.SecretKeyMaterial)
	must(err)
	processed, err := pairing.Response.Process(producedReq.InitiatorContactMessage, extractedResp.ResponseProto, producedReq.SecretKeyMaterial, nil)
	must(err)

	// The nil arguments to Request.Extract, Response.Produce and
	// Response.Process are the serialized ParameterRange this side accepts.
	// Each of them refuses a peer range that does not overlap it with
	// derec.CodeIncompatibleParameterRange.
	//
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

The transport URI used for the `PrePair` leg **must** be ephemeral — `PrePair` envelopes are plaintext. Swap to a long-term endpoint via an `UpdateChannelInfo` flow once pairing completes. The repository's end-to-end tests carry a complete, compiling handshake — see [End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

---

## Share Distribution (Sharing)

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/sharing"

secretID := uint64(42)
secretData := []byte("super-secret")
// Every channel is listed with its weight — the number of subshares its
// committed share carries. An ordinary helper carries weight 1.
channels := []sharing.WeightedChannel{
	{ChannelID: 1, Weight: 1},
	{ChannelID: 2, Weight: 1},
	{ChannelID: 3, Weight: 1},
}
const threshold = 2 // the number of subshares that reconstruct the secret
const version = uint32(1)

shares, err := sharing.Request.Split(secretID, secretData, channels, threshold, version)
// shares: map[uint64][]byte — channel id -> one CommittedDeRecShare per helper.
```

`threshold` counts **subshares**, not helpers: with every weight 1, threshold is also the number of helpers needed to recover. Giving a channel a weight greater than 1 gives it that many subshares instead — a device the owner trusts more than the others. A channel's weight must fall within `1..threshold`; Split returns a `*derec.Error` with `Code == derec.CodeInvalidWeight` otherwise.

```go
// channel 1 holds 2 of the threshold's subshares
weighted := []sharing.WeightedChannel{
	{ChannelID: 1, Weight: 2},
	{ChannelID: 2, Weight: 1},
	{ChannelID: 3, Weight: 1},
}
shares, err := sharing.Request.Split(secretID, secretData, weighted, threshold, version)

for channelID, committedShare := range shares {
	envelope, err := sharing.Request.Produce(channelID, version, secretID, committedShare, nil, "", sharedKeys[channelID], nil)
	// send envelope over your transport
}
```

The last argument of every request `Produce` (sharing, verification, recovery, discovery, unpairing) is `replyTo []Endpoint`: the endpoints, in preference order, the peer should answer on. `nil` means answer on the endpoints recorded for the channel.

The helper side extracts with `sharing.Request.Extract`, persists the request, and answers with `sharing.Response.Produce` (returning the `CommittedShare`, `SecretID`, and `Version` it stored). The owner confirms with `sharing.Response.Extract` + `sharing.Response.Process`.

---

## Verification Flow

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/verification"

// Owner side: produce the challenge.
requestEnvelope, err := verification.Request.Produce(channelID, secretID, version, sharedKey, nil)

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
requestEnvelope, err := recovery.Request.Produce(channelID, secretID, version, sharedKey, nil)

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

> **Secret format:** `recovered` is `[version byte] · payload` — v1's payload
> is **gzip (RFC 1952)** compressed **JSON**, with byte fields as **standard
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
  with `ChannelStore.LinkChannel`. Linking assumes a helper holds **at most one share per owner
  for a given `secretID` and version**, so each recovery channel is linked to the
  single old channel it replaces. On `GetShare` the helper answers with
  **one** share from the linked set: the first whose `secretID` matches the
  request, in the order `ShareStore.LoadMany` returns. The library imposes no order. If
  several channels holding shares for the same owner are linked to one
  recovery channel and every recovery channel is answered from the same
  share, the owner receives it more than once (it counts once) and can fall
  below the threshold. An application that runs such a helper keeps each
  recovery channel resolving to a distinct share: either links stay
  one-to-one, or its share store returns, for each requesting channel, the
  share intended for it first, in a deterministic order.

---

## Discovery Flow

```go
import "github.com/derecalliance/lib-derec/packages/go/primitives/discovery"

// Owner side: ask a helper which secret ids/versions it holds.
requestEnvelope, err := discovery.Request.Produce(channelID, sharedKey, nil)

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

`protocol.New` takes six application-supplied interfaces backing all persistence and transport — the five stores bundled in a `protocol.Stores`, plus the transport:

- `protocol.ChannelStore` — channel records, keyed by `(secretID, channelID, replicaID)`. A `replicaID` of `0` addresses the helper channel; any other value addresses that member of the replica group
- `protocol.SecretStore` — pairing/session secret material
- `protocol.ShareStore` — stored shares. On an owner, `KeepList` chooses which versions helpers keep, and `ok=false` sends no keepList so helpers keep every version; see [the owner's keep list](https://github.com/derecalliance/lib-derec/tree/main/library#share-store-the-owners-keep-list)
- `protocol.UserSecretStore` — the latest user-facing secret snapshot per `secretID`
- `protocol.StateStore` — in-flight orchestrator state (pending verification/recovery/unpair/sharing rounds)
- `protocol.Transport` — outbound delivery (`Send(endpoints []protocol.Endpoint, message []byte) error`). Implement `protocol.SendOne` for a single endpoint and wrap it in `protocol.SequentialFailover` (or `protocol.SingleEndpointTransport`); when every endpoint fails, the adapter returns the last dialer error unchanged, so `errors.Is` / `errors.As` against your own dialer errors keep working

Delivery is push-only: a reply produced by `Process` is handed to `Transport.Send`, addressed to the peer's endpoint, and is never returned by `Process`, so every participant needs a reachable endpoint. Recommended HTTP conventions (not protocol requirements) are `POST`, an `application/octet-stream` body, `202 Accepted`, and `200 OK` with the reply body when answering an unreachable peer on the same connection. Only that `200 OK` same-connection answer needs matching: pick the reply that echoes the request's trace id with `envelope.ReadTraceID`. See [Transports](https://derec-alliance.gitbook.io/docs/protocol-specification/transports).

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

#### Refusing a share or a verification

A helper enforces share size itself: with a parameter range configured, a
share outside its own `MinShareSize`/`MaxShareSize` (inclusive; a max of `0` means
unbounded) is answered with `SIZE_LIMIT_EXCEEDED` before any
`ActionRequired` or auto-accept. Frequency limits on share updates and
verifications are the application's to enforce, from its share store.

On a helper channel, return a `*protocol.ShareStoreRefusedError` from
`ShareStore.Save` (a genuinely new share version) or
`ShareStore.RecordVerification` (an accepted verification challenge) to
refuse it:

```go
func (s *store) RecordVerification(secretID, channelID uint64, version uint32) error {
	if s.limiter.TooSoon(channelID) {
		return &protocol.ShareStoreRefusedError{Refusal: protocol.RefusalTooFrequent}
	}
	return nil
}
```

The library answers the owner with the mapped status (`RefusalTooFrequent` →
`TOO_FREQUENT`, `RefusalSizeLimitExceeded` → `SIZE_LIMIT_EXCEEDED`,
`RefusalRejected` → `REJECTED`), and the owner sees a `ShareRejected` or
`ShareVerifyRejected` event with that `Status`. Any other error is an
ordinary store failure, reported as an `EventTypeRequestFailed` event (see
[Failed requests](#failed-requests)). Every `ShareStore` implements `RecordVerification`;
an app with no limit returns `nil`. See
[Helper-side admission control](https://github.com/derecalliance/lib-derec/tree/main/library#helper-side-admission-control).

### Constructing an instance

```go
import (
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/protocol"
	"google.golang.org/protobuf/proto"
)

cfg := protocol.Config{
	SecretID: secretID,
	DeRecProtocolConfig: protocol.DeRecProtocolConfig{
		OwnTransports: []protocol.TransportProtocolParam{
			{URI: "https://owner.example.com", Protocol: int32(derecpb.Protocol_HTTPS)},
		},
		Threshold: proto.Uint32(2), // nil: library default (3)
		Timeouts: &protocol.Timeouts{
			SharingRoundSecs: proto.Uint64(30), // whole seconds; nil: library default
		},
	},
}

p, err := protocol.New(protocol.Stores{
	Channel:    channelStore,
	Share:      shareStore,
	Secret:     secretStore,
	UserSecret: userSecretStore,
	State:      stateStore,
}, transport, cfg)
if err != nil {
	panic(err)
}
defer p.Close()
```

`Config` is the per-instance `SecretID` plus an embedded `DeRecProtocolConfig` holding every data setting. Its fields are promoted, so `cfg.Threshold` reads and writes `cfg.DeRecProtocolConfig.Threshold`; only a composite literal has to name the embedded struct.

Every setting is optional and a pointer, so that "unset" and `0` (or `false`) stay distinct: `nil` takes the library default, and any value you set — `0` included — is passed to the library unchanged, which accepts or rejects it (a `Threshold` below 2 fails `protocol.New` with `derec.CodeInvalidInput`). `proto.Uint32` / `proto.Uint64` / `proto.Bool` build the pointer inline. `Timeouts` fields are whole seconds, the unit the library takes.

#### Configuration from a file or record

Applications usually load settings as a whole: general settings from the environment or a config file, per-user settings from a user record. `DeRecProtocolConfig` carries json tags for the canonical config JSON shared by every DeRec SDK, so each source is one `json.Unmarshal`. Go has no builder and no `WithConfig`; layering is one `json.Unmarshal` per layer into the same value, then plain assignments:

```go
cfg := protocol.Config{SecretID: secretID}
if err := json.Unmarshal(generalJSON, &cfg.DeRecProtocolConfig); err != nil { // 1. general settings
	return err
}
if err := json.Unmarshal(userRecordJSON, &cfg.DeRecProtocolConfig); err != nil { // 2. per-user settings
	return err
}
cfg.Threshold = proto.Uint32(4) // 3. individual settings

p, err := protocol.New(stores, transport, cfg)
```

- **Only the keys a layer carries are assigned.** An absent key, or `null`, leaves the value already held.
- **Last write wins, per setting**, exactly as the Rust `with_config` and the .NET / TypeScript `WithConfig` / `withConfig` layer. Nested values are replaced as a whole, except `timeouts`: each of its fields is merged separately, so a per-user record that sets only `inbound_message_secs` keeps the `sharing_round_secs` the general config set.
- **Validation happens in `protocol.New`**, with the same rules as setting the field directly. A `threshold` of `1` from a config file fails exactly as `cfg.Threshold = proto.Uint32(1)` does.
- **An unknown key fails `json.Unmarshal`** with an error naming it (`json: unknown field "treshold"`), at every level, so a misspelled setting is never silently dropped.
- **Marshal and unmarshal `cfg.DeRecProtocolConfig`, not `cfg`.** `json.Marshal(cfg)` writes `SecretID` beside the settings, and reading that back fails on `SecretID` as an unknown key: the secret id is per instance and is not part of the config JSON.
- **`encoding/json` matches keys case-insensitively.** A config with a wrong-case key (`"Threshold"` instead of `"threshold"`) still loads in Go — it matches the `Threshold` field — while every other SDK rejects it as an unknown key. Write the canonical `snake_case` keys even though Go would accept the wrong case.

The canonical JSON (`library/tests/fixtures/protocol_config.json` holds a full example):

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

Keys are `snake_case` and every key is optional. `replica_id` and `max_subshares` are decimal strings, so values above 2^53 survive. `json.Marshal` of a `DeRecProtocolConfig` writes the same shape, which is exactly what `protocol.New` sends to the library beside `secret_id`.

`channelStore`/`shareStore`/`secretStore`/`userSecretStore`/`stateStore`/`transport` are your application's implementations of the six interfaces above. The repository's end-to-end tests carry complete in-memory implementations of all six — see [End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

### Driving a flow

```go
// Contact creator (either Owner or Helper) mints a contact out-of-band.
contact, err := p.CreateContact(nil, protocol.ContactModeInlineKeys, nil)

// Peer starts the handshake from it.
events, err := peer.Start(protocol.FlowKindPairing, protocol.PairingParams{
	Kind:    protocol.SenderKindHelper,
	Contact: contact.ContactBytes,
})

// Feed inbound wire bytes from your transport to Process; it returns the
// events produced (peer confirmations, ActionRequired prompts, ...).
events, err = p.Process(inboundBytes)
for _, ev := range events {
	switch ev.Type {
	case protocol.EventTypePairingCompleted:
		// ev.ChannelID (uint64) now holds the rekeyed channel id.
	case protocol.EventTypeActionRequired:
		// Application decides: p.Accept(ev.Action), or
		// p.Reject(ev.Action, derecpb.StatusEnum_REJECTED, "not now").
		_, err = p.Accept(ev.Action)
	case protocol.EventTypeShareRejected:
		// ev.Status is the derecpb.StatusEnum the helper answered with,
		// e.g. derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED; ev.Memo explains it.
	}
}
```

#### Failed requests

Every request that arrives on an authenticated channel gets exactly one response, even when handling it fails. Such a failure does not make `Process` or `Accept` return an error: it is reported as an event with `Type == EventTypeRequestFailed`, and the call's other events are kept.

- `ActionKind` is the type of the request that failed, one of the `ActionKind*` constants (`ActionKindFailed` when its body could not be decoded, or was a request type the channel cannot carry).
- `Responded` is `true` when the library already sent the response.
- `Status` (`derecpb.StatusEnum`) is the status that was sent, or would have been. It is always present. `Memo` is the wire-safe memo sent with it, or that would have been, so `Reject(Action, Status, Memo)` sends exactly the response the library would have sent.
- `ErrorCode` is the error's stable code name and `Message` a local description; neither goes on the wire.
- `Action`, when `Responded` is `false`, is the token that answers the request. Pass it to `Reject`, which sends the one response; `Accept` refuses it. The library never expires it. It is `nil` only when `Reject` could never answer it: a request on a replica group channel that names no member and carries no `reply_to`, which has no reply target, or, with `AutoRespondOnFailure` off, a replica copy that hands this device the group key and fails before that key is stored.

Resolve each token once. The library is stateless, so rejecting the same token twice, or rejecting an action already accepted, sends a second response.

`Config.AutoRespondOnFailure` decides who answers. With it on, the library sends the response itself (a known failure keeps its specific status; anything else is `FAIL` with a generic memo). With it off (the default), nothing is sent and the event carries the token:

```go
for _, ev := range events {
	if ev.Type == protocol.EventTypeRequestFailed && !ev.Responded && ev.Action != nil {
		err = p.Reject(ev.Action, ev.Status, ev.Memo)
	}
}
```

A peer that answers with an `ErrorResponseMessage` (for example `FORMAT_ERROR` for a body it could not decode) is reported as `EventTypeErrorResponseReceived` with `Status` and `Memo`; it is never answered.

An inbound `PairRequest` refused under a protocol rule (a parameter range that does not overlap this device's, `INCOMPATIBLE_PARAMETER_RANGE`, or a replica id already in the group, `REPLICA_ID_CONFLICT`) is answered with that status in every mode and reported as `EventTypePairingRefused` with `Status` and `Memo`, the reason sent to the requester and written from its side. `ErrorCode` (`incompatible_parameter_range` or `replica_id_conflict`) and `Message` carry the local reason for logging or display, as on `EventTypeRequestFailed`; they are never sent. `Process` does not return an error for it, and no channel is created. The requester's `Process` fails with `CodeNonOKStatus`, and its `PeerStatus` and `PeerMemo` hold the status and memo.

When the core rejects a message, `Process` returns a `*protocol.ProcessError`. It settles expired deadlines (sharing-round and unpair timeouts) before it handles the message, and those are never reported again, so the error carries them: `Events` holds every event produced before the failure, and `ChannelID` (`*uint64`) names the channel the message came from (`nil` when the bytes were not a decodable envelope). Handle the events as you would a successful call's, then the error. The underlying `*derec.Error` is `Err`, and `errors.As` reaches it too:

```go
events, err = p.Process(inboundBytes)
var processErr *protocol.ProcessError
if errors.As(err, &processErr) {
	handle(processErr.Events)
	report(processErr.ChannelID, processErr.Err)
}
```

`Start` accepts a `FlowKind` plus the matching params struct: `protocol.PairingParams`, `protocol.DiscoveryParams`, `protocol.ProtectSecretParams`, `protocol.VerifySharesParams`, `protocol.RecoverSecretParams`, `protocol.UnpairParams`, or `protocol.UpdateChannelInfoParams`. Fan-out flows (`FlowKindDiscovery`, `FlowKindVerifyShares`, `FlowKindUpdateChannelInfo`) take a `protocol.Target`, built with `protocol.TargetAll()`, `protocol.TargetOne(channelID)`, or `protocol.TargetMany(channelIDs...)`.

`ProtectSecretParams.Weights` (`map[uint64]uint32`, nil by default) gives chosen paired channels more than one subshare — key by the long-term channel id (what `pairPeers`/pairing returns), never the transient pairing/contact id. Each resulting `EventTypeProtectSecretStarted` and `EventTypeProtectSecretFailed` carries that channel's subshare count on `Event.Weight` (`*uint32`): the `Weights` entry for it, or `1` when the map does not name it. The map is the **full assignment, not a patch**: a helper it does not name holds one subshare.

Weights are recorded. Each round writes the weight it gave every paired helper to that helper's `HelperChannel.Weight` in your `ChannelStore` before anything is sent, and the publishes the library starts on its own (after pairing, after a fingerprint is confirmed) reuse those weights; a newly paired helper starts at 1. The weights also travel in the recovered secret (`Helper.Weight`), so `Restore` and replica hydration write them back into the channel records they create. When `Config.Threshold` applies (no threshold is stored), lowering it to or below a stored weight makes the next publish fail with `derec.CodeInvalidWeight` (65) before anything is sent, until `Start(ProtectSecret)` assigns valid weights.

The threshold is recorded too. A round splits at `ProtectSecretParams.Threshold` when
given, otherwise at the stored threshold (`UserSecrets.Threshold`), and only otherwise
at `Config.Threshold`, which is therefore the starting threshold for a secret with
nothing stored. Every publish stores the threshold it used, the recovered
secret carries it (`Secret.Threshold`), and `Restore` and replica
hydration put it back, so the publishes the library starts on its own and
the follow-up after `Restore` keep it: leave `Threshold` unset there. To
change it, pass `Threshold` on `Start(FlowKindProtectSecret, ...)`. It must be at least 2,
above every weight, and no greater than a subshare cap; a round that fails
a check writes and sends nothing. Your `UserSecretStore` must persist the
snapshot's threshold as given.

That failure surfaces where the library started the publish, and in each case nothing is sent:

- `Process` returns a `*ProcessError` whose `Events` keep the message's events, `EventTypePairingCompleted` included.
- `Accept` returns an error. The pairing has completed and its response was sent, but `EventTypePairingCompleted` is not returned.
- `VerifyFingerprint` returns an error. The promotion stands: calling it again returns `true` and publishes nothing.

Call `Start(FlowKindProtectSecret, ...)` with valid `Weights` to publish to every helper.

The intended flow. Weights are the user's choice: before `Start`, show the user each paired helper's current weight, pre-filled from the stored `HelperChannel.Weight` in your `ChannelStore`, and pass the user's final choice as the whole `Weights` map. Reading the stored weights first is the normal flow. Every other `Start(FlowKindProtectSecret, ...)` the app makes, such as a republish after editing the secrets or the follow-up after `Restore`, must pass the stored weights unchanged: a helper left out returns to 1, which silently undoes the user's choice. Only the publishes the library starts on its own (after pairing, after a fingerprint is confirmed) reuse the stored weights by themselves.

**Below the threshold.** When the paired helpers' total weight is below `Threshold`, `Start` skips the split: no helper receives anything, so no `EventTypeProtectSecretStarted` / `EventTypeProtectSecretFailed` comes back for one. A paired replica still gets its usual secret-only copy and events; with none paired, `Start` returns no events at all — this is not an error. The version still advances and the secrets/description are saved as the latest snapshot, so the next publish that reaches threshold (including one the library starts on its own) shares it. Sum the weights about to be assigned against `Threshold` beforehand, or count the returned helper events afterward, to tell the two cases apart. This is more reachable with weighted helpers than with the default of 1: two helpers at weight 2 against a threshold of 3 (total weight 4) drop below it when a publish leaves both out of the weights map, resetting each to weight 1 for a total of 2 — a risk for a restore follow-up publish that does not pass the stored weights unchanged.

`Config.MaxSubshares` (`*uint64`, nil by default: no cap) caps the total subshares one round splits the secret into — the sum of every helper's weight. Recovery time grows quadratically with that total (about 0.2 s at 200, 5.5 s at 1,000 and 87 s at 4,000 subshares per attempt) while splitting stays cheap, so this is the place to bound it. A round over the cap fails `Start(ProtectSecret)` with a `*derec.Error` whose `Code` is `derec.CodeTooManySubshares` (66) before anything is sent; publishes the library starts itself count the stored weights and respect it too. A cap below `Threshold` makes `New` fail with `derec.CodeInvalidInput`. The cap applies at sharing only, never at recovery: a recovering device cannot know the cap the shares were made under.

`Process` returns `[]protocol.Event`, decoded from the same JSON event stream the Rust core emits — compare `Event.Type` against the `protocol.EventType*` constants (`EventTypePairingCompleted`, `EventTypeShareStored`, `EventTypeShareConfirmed`, `EventTypeSecretRecovered`, `EventTypeActionRequired`, …) rather than hand-typing the string. Every u64 identifier on an event (`ChannelID`, `PairingChannelID`, `SecretID`, `TraceID`, the replica ids, `Synced` / `Behind`) and inside the recovered `Secret` (`Helper.ChannelID`, `Replicas.ChannelID`, `Replica.ReplicaID`) is a `uint64`, `Replica.Role` is a `protocol.ReplicaRole` (`ReplicaRoleSource` / `ReplicaRoleDestination`), and `Event.Kind` / `Event.SenderKind` are a `protocol.SenderKind` (`SenderKindOwner` / `SenderKindHelper` / `SenderKindReplicaSource` / `SenderKindReplicaDestination`) — the same type as `pairing.SenderKind` and `PairingParams.Kind`.

`FlowKindVerifyShares` challenges each targeted helper, and every challenged channel ends with exactly one event:

- `EventTypeShareVerified` — the helper proved it holds the exact share.
  `Event.Subshares` is how many subshares that helper holds for `Version`,
  read from this device's stored share, so it is the weight of the round that
  published `Version`, not the helper's current weight; it is nil when that
  share was stored before the count was recorded. `Threshold` is the threshold that version was split with, from the
  same stored share, not the current one; it is nil when that share was
  stored before the threshold was recorded. To judge whether a version is
  recoverable, sum `Subshares` over its `ShareVerified` events and compare the
  sum with their `Threshold`. If either is nil on any of those events,
  the result is unknown: a nil count is not `0` or `1`. The count lives on `Share.Subshares`, which the
  library sets on owner-side shares only (nil on a helper's share and never
  backfilled): your `ShareStore` must persist it as given and return it
  unchanged. `Share.Threshold` follows the same rules, and must be
  persisted the same way.
- `EventTypeShareVerifyInvalid` (`ChannelID`, `Version`) — the helper's proof does not match the share this device stored. It is an event; `Process` returns no error.
- `EventTypeShareVerifyRejected` — the helper refused the challenge; `Status` and `Memo` say why.
- `EventTypeVerifySharesFailed` — no verdict could be reached on this device. `Reason` is one of `VerifyFailureReasonNoSharedKey`, `VerifyFailureReasonNoProof` or `VerifyFailureReasonDispatchFailed`, and `Error` carries the cause.

A stored proof is either confirmed by its helper or part of a sharing round still open: when a round settles a channel as failed (a rejection or a timeout), that channel's proof is deleted. A confirmation also deletes the proofs of versions the helper dropped: a helper that stores a version deletes every other version that round's keepList leaves out, so when it confirms, its proofs for those versions are deleted here too (the confirmed version stays). A helper that rejects the round keeps its older versions, and so do their proofs; with no keep list nothing is deleted. A replica Destination never sees the helpers' answers, and it keeps every proof it receives: it never deletes one on its own, and freeing that storage is the app's concern. Verifying on a Destination a version that a helper refused, or later dropped under the `keepList`, gets `EventTypeShareVerifyRejected` (`UNKNOWN_SHARE_VERSION`) from that helper, where the Source reports `NoProof`. The app may delete such rows from the Destination's share store; verifying a version whose rows are gone then gives `EventTypeVerifySharesFailed` with `VerifyFailureReasonNoProof`. Verify only versions whose round completed (`EventTypeSharingComplete`). Starting verification on a channel with no proof sends nothing and returns `EventTypeVerifySharesFailed` with `VerifyFailureReasonNoProof` at once. A late response to an earlier challenge is ignored as `EventTypeMessageIgnored` with `IgnoreReasonStaleResponse`, and the current challenge stays open; a response missing its `result` is still an error.

Every channel message carries one timestamp, its send time, in both the envelope and the inner message. A message whose two timestamps differ, or where either or both are absent, is ignored as `EventTypeMessageIgnored` with `IgnoreReasonTimestampMismatch`; this includes replies from 0.0.8 peers.

During recovery, a helper that answers with a share that cannot be part of the secret is reported as an event with `Type == EventTypeRecoveryShareCorrupted` and `Reason` one of `CorruptionReasonMalformed`, `CorruptionReasonInvalidProof` or `CorruptionReasonInconsistent`; the share is set aside and never blocks the recovery from the others. An honest helper never sends one, so treat it as a sign of a damaged or compromised helper — for example, offer to unpair it.

After recovery, pass the typed `Secret` from a `SecretRecovered` event to `p.Restore(secret, version)` on the same `*protocol.DeRecProtocol` that ran recovery — it is the one holding the recovery-mode channels `Restore` unpairs — to commit canonical helper state and wipe the throwaway recovery-mode channels. A helper or member with no endpoint in the recovered roster gets no channel; `Restore` returns an event with `Type == EventTypePeerNotRestored` and `Reason == NotRestoredReasonNoTransports` for it (`ReplicaID` is set for a replica member) and restores the rest. If channels already exist at ids `Restore` is about to write, `Restore` fails with a `*derec.Error` whose `Code` is `derec.CodeRestoreConflict` and whose `ConflictingChannelIDs` (`[]uint64`) lists exactly those ids — clear them and retry. Do not pass the `Secret` of a `ReplicaSecretReceived` event: the device that received it has already hydrated it, so `Restore` fails with `derec.CodeAlreadyRestored`.

**Restore or join.** `SecretRecovered` writes nothing, so decide first. When `Secret.Replicas.Members` names live members other than the lost device, do not restore: tell the user and offer to join that group as a new replica — pair with a live member, confirm the fingerprint, then run `Start(protocol.FlowKindReplicaDiscovery, nil)`. With no live member, restore. Neither path gives this device the proofs of earlier versions, so it cannot verify them: restore writes none, and a joining device gets only the share map of the single version each push or catch-up carries. The live members keep the proofs they hold. A restored device also cannot publish, or answer a member's catch-up, until the app configures a `ReplicaID` the roster names. Joining adds the device as a new member, while restoring next to live replicas makes a second device claim the lost device's role. See [Restore or join](https://derec-alliance.gitbook.io/docs/concepts/replicas/restore-or-join).

Reference: the repository's end-to-end tests drive a complete Owner + two Helpers pairing → protect-secret → recovery cycle — see [End-to-end test coverage](https://github.com/derecalliance/lib-derec#end-to-end-test-coverage).

---

## Package Layout

- [`derec`](derec/) — the shared error vocabulary: `derec.Error` (`Category`, `Code`, `Message`, `PeerStatus`, `PeerMemo`, `Expected`, `Got`, plus `CategoryName()`/`CodeName()` returning the library's stable names) and the `Category*`/`Code*` constants every fallible call can return; and `derec.CurrentProtocolVersion()`, the core's protocol version for audit logs.
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

The recommended pattern: pair on the ephemeral URI, then — as soon as pairing completes on the contact-creator side — call `SetOwnTransports` with the permanent endpoint and start an `UpdateChannelInfo` flow to announce the swap. This keeps the plaintext `PrePair` window tight while subsequent traffic rides on the long-lived endpoint.

`UpdateChannelInfo` reaches helper channels only. A replica member that changes its endpoint or `CommunicationInfo` publishes a new version first, then updates its helpers; see [On a replica member](https://github.com/derecalliance/lib-derec/tree/main/library#on-a-replica-member).

### Replica fingerprint verification is mandatory

Replica channels are created `Pending` and remain there until both sides call `VerifyFingerprint` with the value the peer derived from the shared key — confirmed out of band. The orchestrator enforces this: `Start(FlowKindProtectSecret, ...)` rejects a target that is still `Pending`. Treat verification as a required step in the pairing UX — a scanner that auto-pairs without it accepts a MITM-vulnerable replica.

Until a device confirms, it ignores everything the peer sends on that channel: `Process` changes no store, sends nothing back, and returns an event with `Type == EventTypeMessageIgnored` and `Reason == IgnoreReasonPendingVerification`, plus `ChannelID` and `TraceID`. This matters most for a replica destination. The source's own confirmation publishes the vault immediately, so that copy usually arrives before the destination's user has confirmed. Confirming does not replay it: once the destination's `VerifyFingerprint` returns `true`, call `Start(FlowKindReplicaDiscovery, nil)` to pull the copy from the source.

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
