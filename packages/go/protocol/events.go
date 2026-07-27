// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"

	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// Event-type discriminator values, one per wire::Event variant in
// library/src/protocol/events/wire.rs. Compare against Event.Type instead
// of hand-typing the string literal.
const (
	EventTypePairingCompleted          = "PairingCompleted"
	EventTypeReplicaPaired             = "ReplicaPaired"
	EventTypeReplicaSecretReceived     = "ReplicaSecretReceived"
	EventTypeReplicaSecretAcked        = "ReplicaSecretAcked"
	EventTypeShareStored               = "ShareStored"
	EventTypeShareConfirmed            = "ShareConfirmed"
	EventTypeShareRejected             = "ShareRejected"
	EventTypeSharingComplete           = "SharingComplete"
	EventTypeShareVerified             = "ShareVerified"
	EventTypeSecretsDiscovered         = "SecretsDiscovered"
	EventTypeRecoveryShareReceived     = "RecoveryShareReceived"
	EventTypeRecoveryShareError        = "RecoveryShareError"
	EventTypeSecretRecovered           = "SecretRecovered"
	EventTypeUnpaired                  = "Unpaired"
	EventTypeUnpairRejected            = "UnpairRejected"
	EventTypePrePairRejected           = "PrePairRejected"
	EventTypeChannelInfoUpdated        = "ChannelInfoUpdated"
	EventTypeChannelInfoUpdateRejected = "ChannelInfoUpdateRejected"
	EventTypeActionRequired            = "ActionRequired"
	EventTypeAutoAccepted              = "AutoAccepted"
	EventTypeNoOp                      = "NoOp"
	EventTypePairingStarted            = "PairingStarted"
	EventTypeDiscoveryStarted          = "DiscoveryStarted"
	EventTypeDiscoveryFailed           = "DiscoveryFailed"
	EventTypeProtectSecretStarted      = "ProtectSecretStarted"
	EventTypeProtectSecretFailed       = "ProtectSecretFailed"
	EventTypeVerifySharesStarted       = "VerifySharesStarted"
	EventTypeVerifySharesFailed        = "VerifySharesFailed"
	EventTypeRecoverSecretStarted      = "RecoverSecretStarted"
	EventTypeRecoverSecretFailed       = "RecoverSecretFailed"
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
// u64 identifiers (ChannelID, PairingChannelID, PeerReplicaID,
// FromReplicaID, SecretID) stay decimal strings, a literal mirror of the
// wire shape — see the field-name-conventions doc comment atop wire.rs.
// Parse with strconv.ParseUint(id, 10, 64) if a numeric value is needed.
//
// Fields that are `Option<T>` on the Rust side (and therefore genuinely
// absent — not just zero — on some variants) are Go pointers: Version,
// ReplicaID, SenderKind, ShareDescription, ShareSecretID. Every other
// field is a plain value; a variant that does not carry it simply leaves
// it at the zero value, which callers should not read without first
// checking Type.
type Event struct {
	// Type is the wire discriminator — the Rust variant name verbatim
	// (e.g. "PairingCompleted", "ShareStored", "NoOp"). Compare against
	// the EventType* constants above.
	Type string `json:"type"`

	// PairingCompleted, PairingStarted.
	ChannelID             string            `json:"channel_id"`
	PairingChannelID      string            `json:"pairing_channel_id"`
	Kind                  int32             `json:"kind"`
	PeerCommunicationInfo map[string]string `json:"peer_communication_info"`

	// ReplicaPaired, ReplicaSecretReceived, ReplicaSecretAcked.
	PeerReplicaID string         `json:"peer_replica_id"`
	FromReplicaID string         `json:"from_replica_id"`
	SecretID      string         `json:"secret_id"`
	Version       *uint32        `json:"version"`
	Secret        *Secret        `json:"secret"`
	Shares        []ChannelShare `json:"shares"`

	// ReplicaSecretAcked, ShareRejected, UnpairRejected, PrePairRejected,
	// ChannelInfoUpdateRejected.
	Status int32  `json:"status"`
	Memo   string `json:"memo"`

	// ShareStored.
	ReplicaID *string `json:"replica_id"`

	// SharingComplete.
	ConfirmedCount uint32 `json:"confirmed_count"`
	FailedCount    uint32 `json:"failed_count"`
	ThresholdMet   bool   `json:"threshold_met"`

	// SecretsDiscovered.
	Secrets []DiscoveredSecret `json:"secrets"`

	// RecoveryShareReceived, RecoveryShareError.
	SharesReceived uint32 `json:"shares_received"`

	// RecoveryShareError, DiscoveryFailed, ProtectSecretFailed,
	// VerifySharesFailed, RecoverSecretFailed, UpdateChannelInfoFailed.
	Error string `json:"error"`

	// ActionRequired, AutoAccepted.
	Action           []byte  `json:"action"`
	ActionKind       string  `json:"action_kind"`
	SenderKind       *int32  `json:"sender_kind"`
	ShareDescription *string `json:"share_description"`
	ShareSecretID    *string `json:"share_secret_id"`
}

// Secret mirrors SecretWire in wire.rs — the typed secret snapshot carried
// by ReplicaSecretReceived and SecretRecovered.
//
// Secrets reuses the UserSecret type stores.go already aliases from
// internal/native (ID/Name/Data) rather than declaring a duplicate —
// wire.rs's UserSecret DTO has the identical shape. That type carries
// explicit `json:"id"`/`"name"`/`"data"` tags that match the wire field
// names, so it decodes this event's secrets directly.
type Secret struct {
	Helpers        []Helper     `json:"helpers"`
	Secrets        []UserSecret `json:"secrets"`
	Replicas       *Replicas    `json:"replicas"`
	OwnerReplicaID string       `json:"owner_replica_id"`
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
		Helpers        []Helper     `json:"helpers"`
		Secrets        []UserSecret `json:"secrets"`
		Replicas       *Replicas    `json:"replicas,omitempty"`
		OwnerReplicaID string       `json:"owner_replica_id"`
	}{
		Helpers:        helpers,
		Secrets:        secrets,
		Replicas:       s.Replicas,
		OwnerReplicaID: s.OwnerReplicaID,
	})
}

// Replicas mirrors ReplicasWire in wire.rs — the replica roster plus the
// 32-byte replica group key, present on Secret only when the secret_id has
// a replica setup.
type Replicas struct {
	Replicas  []Replica `json:"replicas"`
	SharedKey []byte    `json:"shared_key"`
}

// MarshalJSON implements json.Marshaler, encoding SharedKey as the JSON
// number array serde_json's default Vec<u8> representation produces (see
// native.JSONByteArray) rather than Go's default base64 string. Replicas is
// normalized to non-nil so a nil slice marshals as `[]`, not `null` —
// Rust's `replicas` field is a plain (non-Option) Vec and would reject a
// null.
func (r Replicas) MarshalJSON() ([]byte, error) {
	replicas := r.Replicas
	if replicas == nil {
		replicas = []Replica{}
	}
	return json.Marshal(struct {
		Replicas  []Replica            `json:"replicas"`
		SharedKey native.JSONByteArray `json:"shared_key"`
	}{
		Replicas:  replicas,
		SharedKey: native.JSONByteArray(r.SharedKey),
	})
}

// Helper mirrors the Helper wire DTO in wire.rs — one entry of Secret's
// helper roster.
type Helper struct {
	ChannelID         string            `json:"channel_id"`
	TransportURI      string            `json:"transport_uri"`
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
		ChannelID         string               `json:"channel_id"`
		TransportURI      string               `json:"transport_uri"`
		SharedKey         native.JSONByteArray `json:"shared_key"`
		CommunicationInfo map[string]string    `json:"communication_info,omitempty"`
	}{
		ChannelID:         h.ChannelID,
		TransportURI:      h.TransportURI,
		SharedKey:         native.JSONByteArray(h.SharedKey),
		CommunicationInfo: h.CommunicationInfo,
	})
}

// Replica mirrors the Replica wire DTO in wire.rs — one entry of Secret's
// replica-destination roster.
type Replica struct {
	ChannelID         string            `json:"channel_id"`
	TransportURI      string            `json:"transport_uri"`
	CommunicationInfo map[string]string `json:"communication_info"`
	ReplicaID         string            `json:"replica_id"`
	SenderKind        int32             `json:"sender_kind"`
}

// MarshalJSON implements json.Marshaler, omitting CommunicationInfo when
// nil rather than emitting a JSON null — matching the Replica wire DTO's
// `#[serde(skip_serializing_if = "Option::is_none")]` on
// communication_info. Replica has no []byte fields, so this exists purely
// for the omitempty behavior, not a number-array encoding.
func (r Replica) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ChannelID         string            `json:"channel_id"`
		TransportURI      string            `json:"transport_uri"`
		CommunicationInfo map[string]string `json:"communication_info,omitempty"`
		ReplicaID         string            `json:"replica_id"`
		SenderKind        int32             `json:"sender_kind"`
	}{
		ChannelID:         r.ChannelID,
		TransportURI:      r.TransportURI,
		CommunicationInfo: r.CommunicationInfo,
		ReplicaID:         r.ReplicaID,
		SenderKind:        r.SenderKind,
	})
}

// ChannelShare mirrors the Share wire DTO in wire.rs (renamed here to
// avoid colliding with the store-facing Share type in stores.go, which
// mirrors a different Rust type) — one helper's committed share bytes, as
// carried by ReplicaSecretReceived.
type ChannelShare struct {
	ChannelID      string `json:"channel_id"`
	CommittedShare []byte `json:"committed_share"`
}

// DiscoveredSecret mirrors the DiscoveredSecret wire DTO in wire.rs — one
// secret_id's stored versions, as reported by a Helper in response to a
// Discovery flow.
type DiscoveredSecret struct {
	SecretID string              `json:"secret_id"`
	Versions []DiscoveredVersion `json:"versions"`
}

// DiscoveredVersion mirrors the DiscoveredVersion wire DTO in wire.rs.
type DiscoveredVersion struct {
	Version     uint32 `json:"version"`
	Description string `json:"description"`
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
