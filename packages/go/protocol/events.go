// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// Event-type discriminator values, one per wire::Event variant in
// library/src/protocol/events/wire.rs. Compare against Event.Type instead
// of hand-typing the string literal.
const (
	EventTypePairingCompleted          = "PairingCompleted"
	EventTypeReplicaPaired             = "ReplicaPaired"
	EventTypeReplicaSecretReceived     = "ReplicaSecretReceived"
	EventTypeReplicaSecretInstalled    = "ReplicaSecretInstalled"
	EventTypeReplicaVersionConflict    = "ReplicaVersionConflict"
	EventTypeReplicaSyncRejected       = "ReplicaSyncRejected"
	EventTypeReplicaSyncFailed         = "ReplicaSyncFailed"
	EventTypeReplicaSyncComplete       = "ReplicaSyncComplete"
	EventTypeReplicaDiscoveryComplete  = "ReplicaDiscoveryComplete"
	EventTypeReplicaRemoved            = "ReplicaRemoved"
	EventTypeReplicaSourceChanged      = "ReplicaSourceChanged"
	EventTypeSelfRemovedFromGroup      = "SelfRemovedFromGroup"
	EventTypeReplicaSecretAcked        = "ReplicaSecretAcked"
	EventTypeShareStored               = "ShareStored"
	EventTypeShareConfirmed            = "ShareConfirmed"
	EventTypeShareRejected             = "ShareRejected"
	EventTypeSharingComplete           = "SharingComplete"
	EventTypeShareVerified             = "ShareVerified"
	EventTypeShareVerifyRejected       = "ShareVerifyRejected"
	EventTypeSecretsDiscovered         = "SecretsDiscovered"
	EventTypeRecoveryShareReceived     = "RecoveryShareReceived"
	EventTypeRecoveryShareError        = "RecoveryShareError"
	EventTypeRecoveryShareRefused      = "RecoveryShareRefused"
	EventTypeRecoveryShareCorrupted    = "RecoveryShareCorrupted"
	EventTypeSecretRecovered           = "SecretRecovered"
	EventTypeUnpaired                  = "Unpaired"
	EventTypeUnpairRejected            = "UnpairRejected"
	EventTypePrePairRejected           = "PrePairRejected"
	EventTypeChannelInfoUpdated        = "ChannelInfoUpdated"
	EventTypeChannelInfoUpdateRejected = "ChannelInfoUpdateRejected"
	EventTypeActionRequired            = "ActionRequired"
	EventTypeAutoAccepted              = "AutoAccepted"
	EventTypeNoOp                      = "NoOp"
	EventTypeMessageIgnored            = "MessageIgnored"
	EventTypePeerNotRestored           = "PeerNotRestored"
	EventTypePairingStarted            = "PairingStarted"
	EventTypeDiscoveryStarted          = "DiscoveryStarted"
	EventTypeDiscoveryFailed           = "DiscoveryFailed"
	EventTypeProtectSecretStarted      = "ProtectSecretStarted"
	EventTypeProtectSecretFailed       = "ProtectSecretFailed"
	EventTypeVerifySharesStarted       = "VerifySharesStarted"
	EventTypeVerifySharesFailed        = "VerifySharesFailed"
	EventTypeRecoverSecretStarted      = "RecoverSecretStarted"
	EventTypeRecoverSecretFailed       = "RecoverSecretFailed"
	EventTypeUnpairFailed              = "UnpairFailed"
	EventTypeUnpairStarted             = "UnpairStarted"
	EventTypeUpdateChannelInfoStarted  = "UpdateChannelInfoStarted"
	EventTypeUpdateChannelInfoFailed   = "UpdateChannelInfoFailed"
)

// Event is the decoded form of one member of the JSON event array
// DeRecProtocol.Process (and the other flow entry points) receives from
// derec_protocol_process. It mirrors wire::Event in
// library/src/protocol/events/wire.rs field-for-field: wire::Event is
// `#[serde(tag = "type")]` (internally tagged, the Rust variant name as
// the discriminator), so every JSON event object is `{"type": "...",
// ...sibling fields...}` with no nested payload object — Type carries the
// discriminator and every other field is a sibling for whichever variant
// Type names. Fields that do not apply to the current Type are left at
// their Go zero value (or nil, for pointer/slice/map fields) because the
// Rust encoder omits them from the JSON entirely.
//
// u64 identifiers (TraceID, ChannelID, PairingChannelID, PeerReplicaID,
// FromReplicaID, SecretID, the *ReplicaID fields, Synced, Behind,
// FetchedFrom, ShareSecretID) are uint64. The wire carries them as decimal
// strings so JavaScript keeps full precision; decoding parses them back to
// the exact u64 value.
//
// Fields that are `Option<T>` on the Rust side (and therefore genuinely
// absent — not just zero — on some variants) are Go pointers: Version,
// ReplicaID, AuthorReplicaID, HeldAuthorReplicaID, IncomingAuthorReplicaID,
// SenderKind, ShareDescription, ShareSecretID, ShareSize, UnpairMemo. Every other
// field is a plain value; a variant that does not carry it simply leaves
// it at the zero value, which callers should not read without first
// checking Type.
type Event struct {
	// Type is the wire discriminator — the Rust variant name verbatim
	// (e.g. "PairingCompleted", "ShareStored", "NoOp"). Compare against
	// the EventType* constants above.
	Type string `json:"type"`

	// Every *Started event: the token identifying the round this request
	// belongs to. One token is drawn per Start call, so a fan-out shares it
	// across all of its targets, and the peer echoes it on the response.
	//
	// ActionRequired, MessageIgnored: the correlation token of the inbound
	// request. Always present on ActionRequired.
	TraceID uint64 `json:"trace_id,string"`

	// PairingCompleted, PairingStarted, ShareStored (with Version), and
	// most other channel-scoped events.
	ChannelID             uint64            `json:"channel_id,string"`
	PairingChannelID      uint64            `json:"pairing_channel_id,string"`
	Kind                  SenderKind        `json:"-"`
	PeerCommunicationInfo map[string]string `json:"peer_communication_info"`

	// ReplicaPaired, ReplicaSecretReceived, ReplicaSecretInstalled,
	// ReplicaVersionConflict, ReplicaSecretAcked. FromReplicaID is the member
	// the copy came from: the publisher on a push, the responder on a
	// catch-up.
	PeerReplicaID uint64         `json:"peer_replica_id,string"`
	FromReplicaID uint64         `json:"from_replica_id,string"`
	SecretID      uint64         `json:"secret_id,string"`
	Version       *uint32        `json:"version"`
	Secret        *Secret        `json:"secret"`
	Shares        []ChannelShare `json:"shares"`

	// ReplicaSecretReceived, ReplicaSecretInstalled — the member that
	// published Version; nil when the serving member's snapshot records no
	// author.
	AuthorReplicaID *uint64 `json:"author_replica_id,string"`

	// ReplicaVersionConflict — a member offered a different copy of the
	// version this device holds. HeldAuthorReplicaID is the publisher of the
	// local copy, IncomingAuthorReplicaID the publisher of the offered one
	// (carried in Secret); either is nil when its copy records no author.
	//
	// On this event, or on ReplicaSyncRejected with status VERSION_CONFLICT,
	// do not publish from this device again until the conflict is resolved:
	// any further ProtectSecret is a higher version that every other member
	// applies over its own copy, losing the change it never merged. Get the
	// rival copy (Secret here; after ReplicaSyncRejected, run
	// ReplicaDiscovery), merge, and publish the result once with
	// ProtectSecret.
	HeldAuthorReplicaID     *uint64 `json:"held_author_replica_id,string"`
	IncomingAuthorReplicaID *uint64 `json:"incoming_author_replica_id,string"`

	// ReplicaSecretAcked, ReplicaSyncRejected, ShareRejected,
	// ShareVerifyRejected, RecoveryShareRefused, UnpairRejected,
	// PrePairRejected, ChannelInfoUpdateRejected. Status is the protocol
	// StatusEnum the peer answered with.
	//
	// RecoveryShareRefused is a helper answering a recovery share request
	// with a non-OK Status (e.g. UNKNOWN_SHARE_VERSION) instead of a share.
	// The refusal is not collected — it does not count towards
	// SharesReceived and the recovery stays open for the other helpers'
	// shares — but it does answer that helper's RecoverSecretStarted.
	Status derecpb.StatusEnum `json:"status"`
	Memo   string             `json:"memo"`

	// ReplicaSyncRejected, ReplicaSyncFailed, ReplicaRemoved,
	// ReplicaSourceChanged — the member the event is about. The sync events
	// are keyed by replicaID, not channelID, because every member answers on
	// the one group channel.
	//
	// PeerNotRestored — the replica group member Restore wrote no record for
	// (ChannelID is then the group's channel); nil when the entry is a helper,
	// whose channel ChannelID names.
	ReplicaID *uint64 `json:"replica_id,string"`

	// ReplicaSyncFailed — the transport or encoding failure, rendered for
	// display. Distinct from Error, which the flow-level *Failed events use.
	//
	// MessageIgnored — why the message was dropped, one of the IgnoreReason*
	// constants. The message changed no store and drew no reply.
	// IgnoreReasonPendingVerification means the peer sent it before this
	// device confirmed the channel's fingerprint; confirming does not replay
	// it, so a replica destination calls Start(FlowKindReplicaDiscovery)
	// after VerifyFingerprint succeeds to pull the copy itself. TraceID and
	// ChannelID are set too.
	//
	// PeerNotRestored — why Restore wrote no channel for a roster entry, one
	// of the NotRestoredReason* constants. Every other entry and the
	// user-secret snapshot were restored. The peer itself is untouched — a
	// helper still holds its share — and pairing with it again makes it
	// reachable.
	//
	// RecoveryShareCorrupted — why a helper's share was set aside, one of the
	// CorruptionReason* constants. CorruptionReasonMalformed and
	// CorruptionReasonInvalidProof are judged as the share arrives;
	// CorruptionReasonInconsistent (valid on its own, but disagreeing with
	// the shares the secret was rebuilt from) is reported alongside
	// SecretRecovered, once per helper. The share does not count towards
	// SharesReceived and never blocks the recovery. An honest helper never
	// sends one, so the application may treat it as a sign of a damaged or
	// compromised helper, e.g. offer to unpair it. ChannelID and Version are
	// set too, and the event answers that helper's RecoverSecretStarted.
	Reason string `json:"reason"`

	// ReplicaSyncComplete. Synced acknowledged; Behind refused, timed out, or
	// were unreachable. Behind is the application's retry list — the library
	// keeps no durable per-member sync state.
	Synced []uint64 `json:"synced"`
	Behind []uint64 `json:"behind"`

	// ReplicaDiscoveryComplete. LocalVersion is what this device held when the
	// catch-up ran, GroupVersion the newest any member reported, and
	// FetchedFrom names the member the state was pulled from — nil when this
	// device was already current, in which case no hydration event follows.
	LocalVersion *uint32 `json:"local_version"`
	GroupVersion *uint32 `json:"group_version"`
	FetchedFrom  *uint64 `json:"fetched_from,string"`

	// SharingComplete. These counts describe helpers only.
	//
	// A mixed round waits for the replica leg: the counts are known the
	// instant the helpers answer, but the event is withheld until every
	// replica member has also acknowledged, refused, or timed out. One
	// unreachable member therefore delays it by up to the configured timeout,
	// which is easy to mistake for a hang. Nothing is lost — the round always
	// terminates, and a silent member lands in ReplicaSyncComplete's Behind
	// rather than failing it. Drive per-helper progress from ShareConfirmed
	// instead; a helpers-only round is unaffected.
	ConfirmedCount uint32 `json:"confirmed_count"`
	FailedCount    uint32 `json:"failed_count"`
	ThresholdMet   bool   `json:"threshold_met"`

	// SecretsDiscovered.
	Secrets []DiscoveredSecret `json:"secrets"`

	// RecoveryShareReceived, RecoveryShareError.
	SharesReceived uint32 `json:"shares_received"`

	// RecoveryShareError, DiscoveryFailed, ProtectSecretFailed,
	// VerifySharesFailed, RecoverSecretFailed, UnpairFailed,
	// UpdateChannelInfoFailed.
	Error string `json:"error"`

	// ActionRequired, AutoAccepted. Action is the opaque pending action to
	// pass back to Accept/Reject verbatim; ActionKind is one of the
	// ActionKind* constants. The remaining fields are ActionRequired only and
	// set per ActionKind:
	//
	//   - SenderKind: Pairing.
	//   - Version, ShareSecretID: StoreShare, VerifyShare, GetShare (on
	//     GetShare they name the share being asked for).
	//   - ShareDescription, ShareSize: StoreShare. ShareSize is the length in
	//     bytes of the share the helper would store — what a size or quota
	//     decision is made on.
	//   - UnpairMemo: Unpair — the peer's memo.
	//   - UpdatedCommunicationInfo: UpdateChannelInfo — the map the peer is
	//     replacing its stored communication info with. nil means the update
	//     leaves it unchanged; a non-nil empty map means it clears it.
	//   - UpdatedTransports: UpdateChannelInfo — the endpoints the peer is
	//     moving to; nil when the update leaves its endpoints unchanged.
	Action                   []byte            `json:"action"`
	ActionKind               string            `json:"action_kind"`
	SenderKind               *SenderKind       `json:"-"`
	ShareDescription         *string           `json:"share_description"`
	ShareSecretID            *uint64           `json:"share_secret_id,string"`
	ShareSize                *uint64           `json:"share_size"`
	UnpairMemo               *string           `json:"unpair_memo"`
	UpdatedCommunicationInfo map[string]string `json:"updated_communication_info"`
	UpdatedTransports        []EndpointJSON    `json:"updated_transports"`
}

// The label vocabulary for Event.ActionKind, one value per pending-action
// kind the protocol can raise. Compare against these rather than writing the
// string literal — they match the Rust PendingActionKind discriminants
// one-for-one.
const (
	ActionKindPairing           = "Pairing"
	ActionKindPrePair           = "PrePair"
	ActionKindStoreShare        = "StoreShare"
	ActionKindVerifyShare       = "VerifyShare"
	ActionKindDiscovery         = "Discovery"
	ActionKindGetShare          = "GetShare"
	ActionKindUnpair            = "Unpair"
	ActionKindUpdateChannelInfo = "UpdateChannelInfo"
)

// The label vocabulary for Event.Reason on a MessageIgnored event. Matches
// the Rust IgnoreReason discriminants one-for-one.
const (
	IgnoreReasonPendingVerification = "PendingVerification"
	IgnoreReasonExpired             = "Expired"
)

// The label vocabulary for Event.Reason on a PeerNotRestored event. Matches
// the Rust NotRestoredReason discriminants one-for-one.
const (
	// NotRestoredReasonNoTransports: the recovered roster names no endpoint
	// for the peer.
	NotRestoredReasonNoTransports = "NoTransports"
)

// The label vocabulary for Event.Reason on a RecoveryShareCorrupted event.
// Matches the Rust CorruptionReason discriminants one-for-one.
const (
	// CorruptionReasonMalformed: the response carries no decodable share for
	// the requested secret and version.
	CorruptionReasonMalformed = "Malformed"
	// CorruptionReasonInvalidProof: the share fails its own Merkle proof,
	// e.g. a value altered after it was split.
	CorruptionReasonInvalidProof = "InvalidProof"
	// CorruptionReasonInconsistent: the share is valid on its own, but its
	// commitment root or ciphertext disagrees with the shares the secret was
	// rebuilt from.
	CorruptionReasonInconsistent = "Inconsistent"
)

// Secret mirrors SecretWire in wire.rs — the typed secret snapshot carried
// by ReplicaSecretReceived and SecretRecovered.
//
// Secrets reuses the UserSecret type stores.go already aliases from
// internal/native (ID/Name/Data) rather than declaring a duplicate —
// wire.rs's UserSecret DTO has the identical shape. That type carries
// explicit `json:"id"`/`"name"`/`"data"` tags that match the wire field
// names, so it decodes this event's secrets directly.
type Secret struct {
	Helpers  []Helper     `json:"helpers"`
	Secrets  []UserSecret `json:"secrets"`
	Replicas *Replicas    `json:"replicas"`
}

// MarshalJSON implements json.Marshaler. Secret decodes with the default
// unmarshaler (the `json` tags above already match wire.rs's SecretWire
// field-for-field), but re-marshaling it — e.g. to build Restore's
// recovered_secret params — needs the Replicas field omitted when nil
// (mirroring `#[serde(skip_serializing_if = "Option::is_none")]` on
// SecretWire.replicas) rather than emitted as a JSON null. Helpers/Secrets
// are normalized to non-nil so a nil slice marshals as `[]`, not `null` —
// Rust's `helpers`/`secrets` fields are plain (non-Option) Vecs and would
// reject a null.
func (s Secret) MarshalJSON() ([]byte, error) {
	helpers := s.Helpers
	if helpers == nil {
		helpers = []Helper{}
	}
	secrets := s.Secrets
	if secrets == nil {
		secrets = []UserSecret{}
	}
	return json.Marshal(struct {
		Helpers  []Helper     `json:"helpers"`
		Secrets  []UserSecret `json:"secrets"`
		Replicas *Replicas    `json:"replicas,omitempty"`
	}{
		Helpers:  helpers,
		Secrets:  secrets,
		Replicas: s.Replicas,
	})
}

// Replicas mirrors ReplicasWire in wire.rs — the full member roster plus
// the two things every member shares: one channel and one 32-byte group
// key. Present on Secret only when the secret_id has a replica setup.
//
// Members includes the writer and the source: the roster names its source
// by Role, so a reader can identify where the secret originated without a
// separate field.
type Replicas struct {
	ChannelID uint64    `json:"channel_id,string"`
	Members   []Replica `json:"members"`
	SharedKey []byte    `json:"shared_key"`
}

// MarshalJSON implements json.Marshaler, encoding SharedKey as the JSON
// number array serde_json's default Vec<u8> representation produces (see
// native.JSONByteArray) rather than Go's default base64 string. Replicas is
// normalized to non-nil so a nil slice marshals as `[]`, not `null` —
// Rust's `replicas` field is a plain (non-Option) Vec and would reject a
// null.
func (r Replicas) MarshalJSON() ([]byte, error) {
	members := r.Members
	if members == nil {
		members = []Replica{}
	}
	return json.Marshal(struct {
		ChannelID uint64               `json:"channel_id,string"`
		Members   []Replica            `json:"members"`
		SharedKey native.JSONByteArray `json:"shared_key"`
	}{
		ChannelID: r.ChannelID,
		Members:   members,
		SharedKey: native.JSONByteArray(r.SharedKey),
	})
}

// EndpointJSON is one advertised address — in the recovered-secret roster
// and in ActionRequired.UpdatedTransports: URI plus the protocol
// discriminant, so nothing is inferred from a scheme. On the wire the
// protocol travels as its name ("https", "grpc"); the name/discriminant
// mapping is the library's.
type EndpointJSON struct {
	URI      string `json:"uri"`
	Protocol int32  `json:"protocol"`
}

type endpointWire struct {
	URI      string `json:"uri"`
	Protocol string `json:"protocol"`
}

// MarshalJSON implements json.Marshaler, writing Protocol as its name.
func (e EndpointJSON) MarshalJSON() ([]byte, error) {
	name, ok := native.TransportProtocolName(e.Protocol)
	if !ok {
		return nil, fmt.Errorf("protocol: no transport protocol with discriminant %d", e.Protocol)
	}
	return json.Marshal(endpointWire{URI: e.URI, Protocol: name})
}

// UnmarshalJSON implements json.Unmarshaler, reading Protocol from its name.
// A name the library does not define is an error.
func (e *EndpointJSON) UnmarshalJSON(data []byte) error {
	var w endpointWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	d, ok := native.TransportProtocolDiscriminant(w.Protocol)
	if !ok {
		return fmt.Errorf("protocol: unknown transport protocol %q", w.Protocol)
	}
	*e = EndpointJSON{URI: w.URI, Protocol: d}
	return nil
}

// Helper mirrors the Helper wire DTO in wire.rs — one entry of Secret's
// helper roster.
type Helper struct {
	ChannelID         uint64            `json:"channel_id,string"`
	Transports        []EndpointJSON    `json:"transports"`
	SharedKey         []byte            `json:"shared_key"`
	CommunicationInfo map[string]string `json:"communication_info"`
}

// MarshalJSON implements json.Marshaler: SharedKey as a JSON number array
// (see native.JSONByteArray) instead of Go's default base64 string, and
// CommunicationInfo omitted when nil rather than emitted as a JSON null —
// matching the Helper wire DTO's `#[serde(skip_serializing_if =
// "Option::is_none")]` on communication_info.
func (h Helper) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ChannelID         uint64               `json:"channel_id,string"`
		Transports        []EndpointJSON       `json:"transports"`
		SharedKey         native.JSONByteArray `json:"shared_key"`
		CommunicationInfo map[string]string    `json:"communication_info,omitempty"`
	}{
		ChannelID:         h.ChannelID,
		Transports:        h.Transports,
		SharedKey:         native.JSONByteArray(h.SharedKey),
		CommunicationInfo: h.CommunicationInfo,
	})
}

// Replica mirrors the Replica wire DTO in wire.rs — one member of Secret's
// replica group. Exactly one member of a group has Role ReplicaRoleSource.
type Replica struct {
	ReplicaID         uint64            `json:"replica_id,string"`
	Transports        []EndpointJSON    `json:"transports"`
	Role              ReplicaRole       `json:"role"`
	CommunicationInfo map[string]string `json:"communication_info"`
}

// MarshalJSON implements json.Marshaler, omitting CommunicationInfo when
// nil rather than emitting a JSON null — matching the Replica wire DTO's
// `#[serde(skip_serializing_if = "Option::is_none")]` on
// communication_info. Replica has no []byte fields, so this exists purely
// for the omitempty behavior, not a number-array encoding.
func (r Replica) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ReplicaID         uint64            `json:"replica_id,string"`
		Transports        []EndpointJSON    `json:"transports"`
		Role              ReplicaRole       `json:"role"`
		CommunicationInfo map[string]string `json:"communication_info,omitempty"`
	}{
		ReplicaID:         r.ReplicaID,
		Transports:        r.Transports,
		Role:              r.Role,
		CommunicationInfo: r.CommunicationInfo,
	})
}

// ChannelShare mirrors the Share wire DTO in wire.rs (renamed here to
// avoid colliding with the store-facing Share type in stores.go, which
// mirrors a different Rust type) — one helper's committed share bytes, as
// carried by ReplicaSecretReceived.
type ChannelShare struct {
	ChannelID      uint64 `json:"channel_id,string"`
	CommittedShare []byte `json:"committed_share"`
}

// DiscoveredSecret mirrors the DiscoveredSecret wire DTO in wire.rs — one
// secret_id's stored versions, as reported by a Helper in response to a
// Discovery flow.
type DiscoveredSecret struct {
	SecretID uint64              `json:"secret_id,string"`
	Versions []DiscoveredVersion `json:"versions"`
}

// DiscoveredVersion mirrors the DiscoveredVersion wire DTO in wire.rs.
type DiscoveredVersion struct {
	Version     uint32 `json:"version"`
	Description string `json:"description"`
}

// UnmarshalJSON implements json.Unmarshaler. Every field decodes through
// its json tag except Synced and Behind, which the wire carries as arrays of
// decimal strings the `,string` option cannot express for a slice, and Kind
// and SenderKind, which the wire carries as the derec_proto::SenderKind
// numeric value.
func (e *Event) UnmarshalJSON(data []byte) error {
	type plain Event
	aux := struct {
		*plain
		Synced     []decimalU64 `json:"synced"`
		Behind     []decimalU64 `json:"behind"`
		Kind       int32        `json:"kind"`
		SenderKind *int32       `json:"sender_kind"`
	}{plain: (*plain)(e)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	e.Synced = decimalU64s(aux.Synced)
	e.Behind = decimalU64s(aux.Behind)
	e.Kind = SenderKind(aux.Kind)
	if aux.SenderKind != nil {
		sk := SenderKind(*aux.SenderKind)
		e.SenderKind = &sk
	}
	return nil
}

// decimalU64 is a u64 carried on the wire as a decimal string.
type decimalU64 uint64

func (d *decimalU64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("protocol: id %q is not a decimal u64: %w", s, err)
	}
	*d = decimalU64(v)
	return nil
}

func decimalU64s(in []decimalU64) []uint64 {
	if in == nil {
		return nil
	}
	out := make([]uint64, len(in))
	for i, v := range in {
		out[i] = uint64(v)
	}
	return out
}

// decodeEvents parses the UTF-8 JSON array emitted by
// derec_protocol_process (and the other flow entry points) into typed
// events. Every Event field has a json tag matching wire::Event's serde
// output, so a plain unmarshal into []Event is sufficient — no manual
// per-variant dispatch is needed; an unrecognized/NoOp object decodes into
// an Event whose only populated field is Type.
func decodeEvents(data []byte) ([]Event, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var events []Event
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}
