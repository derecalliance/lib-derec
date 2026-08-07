// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"fmt"
)

// Channel is the post-pairing representation of a peer, persisted by a
// ChannelStore implementation. Mirrors the Rust-side
// derec_library::protocol::types::Channel shape field-for-field; the JSON
// produced by EncodeChannel is byte-compatible with what the derec-library
// FFI bridge decodes via serde on the Rust side (see
// library/src/ffi/protocol/stores.rs), since Channel crosses the C callback
// boundary as plain serde JSON rather than a wrapped record type.
type Channel struct {
	ID                uint64
	Transport         TransportEndpoint
	CommunicationInfo map[string]string
	Status            ChannelStatus
	CreatedAt         uint64
	PeerRole          SenderKind
	ReplicaID         *uint64
}

// TransportEndpoint is a peer's advertised transport, mirroring
// derec_proto::TransportProtocol.
type TransportEndpoint struct {
	URI      string
	Protocol int32
}

// ChannelStatus is a channel's lifecycle status, mirroring the Rust-side
// ChannelStatus enum. It marshals to/from the exact strings produced by
// Rust's default serde derive for a unit-variant enum ("Pending"/"Paired"),
// not the SCREAMING_SNAKE_CASE convention protobuf enums use.
type ChannelStatus int

const (
	// ChannelStatusPending marks a channel awaiting fingerprint
	// verification (replica pairing only).
	ChannelStatusPending ChannelStatus = iota
	// ChannelStatusPaired marks a channel fully paired and ready for
	// protocol messages.
	ChannelStatusPaired
)

func (s ChannelStatus) String() string {
	switch s {
	case ChannelStatusPending:
		return "Pending"
	case ChannelStatusPaired:
		return "Paired"
	default:
		return fmt.Sprintf("ChannelStatus(%d)", int(s))
	}
}

// MarshalJSON implements json.Marshaler.
func (s ChannelStatus) MarshalJSON() ([]byte, error) {
	str := s.String()
	if s != ChannelStatusPending && s != ChannelStatusPaired {
		return nil, fmt.Errorf("native: unknown ChannelStatus: %d", int(s))
	}
	return json.Marshal(str)
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *ChannelStatus) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "Pending":
		*s = ChannelStatusPending
	case "Paired":
		*s = ChannelStatusPaired
	default:
		return fmt.Errorf("native: unknown ChannelStatus: %q", str)
	}
	return nil
}

// SenderKind identifies the role a node holds on a Channel, mirroring the
// Rust-side derec_proto::SenderKind protobuf enum. Numeric values match the
// proto enum exactly (note the gap: ReplicaSource is 3, not 2). On the wire
// as part of a Channel, it marshals as the Rust identifier string
// ("Owner"/"Helper"/"ReplicaSource"/"ReplicaDestination") — the shape
// produced by a plain #[derive(Serialize)] on the generated enum, not
// protobuf JSON's SCREAMING_SNAKE_CASE convention.
type SenderKind int32

const (
	SenderKindOwner              SenderKind = 0
	SenderKindHelper             SenderKind = 1
	SenderKindReplicaSource      SenderKind = 3
	SenderKindReplicaDestination SenderKind = 4
)

func (k SenderKind) String() string {
	switch k {
	case SenderKindOwner:
		return "Owner"
	case SenderKindHelper:
		return "Helper"
	case SenderKindReplicaSource:
		return "ReplicaSource"
	case SenderKindReplicaDestination:
		return "ReplicaDestination"
	default:
		return fmt.Sprintf("SenderKind(%d)", int32(k))
	}
}

// MarshalJSON implements json.Marshaler.
func (k SenderKind) MarshalJSON() ([]byte, error) {
	switch k {
	case SenderKindOwner, SenderKindHelper, SenderKindReplicaSource, SenderKindReplicaDestination:
		return json.Marshal(k.String())
	default:
		return nil, fmt.Errorf("native: unknown SenderKind: %d", int32(k))
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (k *SenderKind) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	switch str {
	case "Owner":
		*k = SenderKindOwner
	case "Helper":
		*k = SenderKindHelper
	case "ReplicaSource":
		*k = SenderKindReplicaSource
	case "ReplicaDestination":
		*k = SenderKindReplicaDestination
	default:
		return fmt.Errorf("native: unknown SenderKind: %q", str)
	}
	return nil
}

// SecretKind selects which kind of secret material a SecretValue carries,
// mirroring the Rust-side SecretKind enum. Numeric values must match.
type SecretKind uint32

const (
	// SecretKindSharedKey is the post-pairing symmetric channel key.
	SecretKindSharedKey SecretKind = 0
	// SecretKindPairingSecret is the ephemeral ECIES/ML-KEM key material
	// used during pairing.
	SecretKindPairingSecret SecretKind = 1
	// SecretKindPairingContact is the initiator's ContactMessage, stored
	// transiently between start and pairing completion.
	SecretKindPairingContact SecretKind = 2
)

// SecretValue is the opaque secret payload stored alongside a channel id
// and SecretKind. Bytes' format depends on Kind — callers treat it as
// opaque:
//   - SharedKey: exactly 32 bytes, the symmetric channel key.
//   - PairingSecret: opaque PairingKeyMaterial blob.
//   - PairingContact: a prost-encoded ContactMessage.
type SecretValue struct {
	Kind  SecretKind
	Bytes []byte
}

// Share is a single stored share entry, keyed by (channelID, secretID,
// version) at the store layer. Mirrors the Rust-side Share struct.
//
// ReplicaID does NOT round-trip through EncodeShare/DecodeShare: the wire
// record used by the FFI bridge (ShareRecord in stores.rs) never carries
// it — Save drops it on encode and Load always sets it to nil on decode,
// matching Rust's ShareRecord::into_share() exactly. Callers must not rely
// on ReplicaID surviving a store round trip through this codec.
type Share struct {
	SecretID  uint64
	Version   uint32
	ReplicaID *uint64
	Bytes     []byte
}

// StateKind tags which category of in-flight orchestrator state a
// StateItem/StateKey belongs to. Numeric values must match the Rust-side
// StateKind enum.
type StateKind uint32

const (
	// StateKindPendingVerification is an outstanding verify-share
	// challenge, one row per channel.
	StateKindPendingVerification StateKind = 0
	// StateKindPendingRecovery is the recovery accumulator, one row per
	// (secretID, version).
	StateKindPendingRecovery StateKind = 1
	// StateKindPendingUnpair is an outstanding unpair acknowledgement,
	// one row per channel.
	StateKindPendingUnpair StateKind = 2
	// StateKindSharingRound is the active sharing round, at most one row
	// per secretID.
	StateKindSharingRound StateKind = 3
)

// StateKey selects one row inside a StateKind under a secretID. Which
// field is populated is determined by Kind:
//   - PendingVerification, PendingUnpair: ChannelID.
//   - PendingRecovery: SecretID, Version.
//   - SharingRound: none (at most one row per secretID).
//
// SecretID names the secret being recovered, which is not necessarily
// the secretID partitioning the store: a recovering device runs an
// ephemeral instance whose own id owns the partition while the target
// belongs to the wire.
type StateKey struct {
	Kind      StateKind
	ChannelID *uint64
	SecretID  *uint64
	Version   *uint32
}

// StateItem is the payload of one row in the state store. Which fields are
// populated is determined by Kind, mirroring the Rust-side StateItem enum
// variants:
//   - PendingVerification: ChannelID, Bytes (prost-encoded
//     VerifyShareRequestMessage).
//   - PendingRecovery: SecretID (the secret being recovered), Version,
//     Shares (each entry a prost-encoded GetShareResponseMessage).
//   - PendingUnpair: ChannelID, StartedAt (unix seconds).
//   - SharingRound: Version, Pending/Confirmed/Failed (channel-id sets),
//     StartedAt (unix seconds).
type StateItem struct {
	Kind      StateKind
	ChannelID *uint64
	SecretID  *uint64
	Version   *uint32
	StartedAt *uint64
	Bytes     []byte
	Shares    [][]byte
	Pending   []uint64
	Confirmed []uint64
	Failed    []uint64
}

// Key returns the StateKey this item is stored under, mirroring the
// Rust-side StateItem::key().
func (i StateItem) Key() StateKey {
	switch i.Kind {
	case StateKindPendingVerification:
		return StateKey{Kind: StateKindPendingVerification, ChannelID: i.ChannelID}
	case StateKindPendingRecovery:
		return StateKey{Kind: StateKindPendingRecovery, SecretID: i.SecretID, Version: i.Version}
	case StateKindPendingUnpair:
		return StateKey{Kind: StateKindPendingUnpair, ChannelID: i.ChannelID}
	default:
		return StateKey{Kind: StateKindSharingRound}
	}
}

// UserSecret is a single user-facing secret entry within a UserSecrets
// bag. Mirrors the Rust-side (prost) UserSecret message.
type UserSecret struct {
	ID   []byte `json:"id"`
	Name string `json:"name"`
	Data []byte `json:"data"`
}

// MarshalJSON implements json.Marshaler, encoding ID and Data as JSON
// number arrays (see JSONByteArray) instead of Go's default base64
// strings — the shape every Rust-side decoder of a UserSecret DTO expects.
func (u UserSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID   JSONByteArray `json:"id"`
		Name string        `json:"name"`
		Data JSONByteArray `json:"data"`
	}{ID: JSONByteArray(u.ID), Name: u.Name, Data: JSONByteArray(u.Data)})
}

// UserSecrets is a snapshot of the user-facing secret contents for one
// secretID, written on every ProtectSecret call. Mirrors the Rust-side
// UserSecrets struct (minus the Owner-side Replicas cache, which is
// rebuilt from live channel state and never crosses this store).
type UserSecrets struct {
	Version     uint32
	Secrets     []UserSecret
	Description *string
}
