// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// HelperChannel is a channel to a single helper, or to the owner from a
// helper's side. Mirrors derec_library::protocol::types::HelperChannel
// field-for-field. Keyed by (secretID, channelID).
//
// PeerRole is the *other end's* role, fixed at pairing time: a helper
// pairing held by an Owner carries SenderKindHelper, and the helper's own
// row for the same channel carries SenderKindOwner.
type HelperChannel struct {
	ChannelID         uint64
	// Transports are every endpoint the peer advertised, in the order it
	// offered them. The library does not rank them; a Transport
	// implementation chooses which to dial and may fall back.
	Transports        []TransportEndpoint
	CommunicationInfo map[string]string
	PeerRole          SenderKind
	Status            ChannelStatus
	CreatedAt         uint64
}

// ReplicaMember is one member of a replica group, including this device
// itself. Mirrors derec_library::protocol::types::ReplicaMember
// field-for-field. Keyed by (secretID, replicaID): every member shares one
// ChannelID, so the channel cannot be the key. Storing this device's own
// row is what makes the roster reconstructible from stores alone.
type ReplicaMember struct {
	ChannelID         uint64
	ReplicaID         uint64
	// Transports are every endpoint the peer advertised, in the order it
	// offered them. The library does not rank them; a Transport
	// implementation chooses which to dial and may fall back.
	Transports        []TransportEndpoint
	CommunicationInfo map[string]string
	Role              ReplicaRole
	Status            ChannelStatus
	CreatedAt         uint64
}

// ChannelRecord is what a ChannelStore holds at one address: either a
// helper channel or one replica-group member. Exactly one field is non-nil.
type ChannelRecord struct {
	Helper  *HelperChannel
	Replica *ReplicaMember
}

// ChannelID reports the channel this record names, whichever variant it is.
func (r ChannelRecord) ChannelID() uint64 {
	switch {
	case r.Helper != nil:
		return r.Helper.ChannelID
	case r.Replica != nil:
		return r.Replica.ChannelID
	default:
		return 0
	}
}

// ReplicaID reports the replica id this record is keyed by, or 0 for a
// helper channel — the value the Rust side reserves as "absent".
func (r ChannelRecord) ReplicaID() uint64 {
	if r.Replica != nil {
		return r.Replica.ReplicaID
	}
	return 0
}

// ReplicaRole is a member's role within a replica group, mirroring the
// Rust-side ReplicaRole enum. Exactly one member of a group is the Source.
// The value is absolute: every member records the same role for a given
// peer, regardless of who is reading. It marshals to/from the exact strings
// Rust's default serde derive produces ("Source"/"Destination").
type ReplicaRole int

const (
	// ReplicaRoleSource marks the member the secret replicates from.
	ReplicaRoleSource ReplicaRole = iota
	// ReplicaRoleDestination marks a member the secret replicates to.
	ReplicaRoleDestination
)

func (r ReplicaRole) String() string {
	switch r {
	case ReplicaRoleSource:
		return "Source"
	case ReplicaRoleDestination:
		return "Destination"
	default:
		return fmt.Sprintf("ReplicaRole(%d)", int(r))
	}
}

// MarshalJSON emits the Rust variant name.
func (r ReplicaRole) MarshalJSON() ([]byte, error) {
	switch r {
	case ReplicaRoleSource, ReplicaRoleDestination:
		return json.Marshal(r.String())
	default:
		return nil, fmt.Errorf("native: invalid ReplicaRole %d", int(r))
	}
}

// UnmarshalJSON accepts the Rust variant name.
func (r *ReplicaRole) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("native: decode ReplicaRole: %w", err)
	}
	switch s {
	case "Source":
		*r = ReplicaRoleSource
	case "Destination":
		*r = ReplicaRoleDestination
	default:
		return fmt.Errorf("native: unknown ReplicaRole %q", s)
	}
	return nil
}

// TransportEndpoint is a peer's advertised transport, mirroring
// derec_proto::TransportProtocol.
type TransportEndpoint struct {
	URI      string
	Protocol int32
}

// ChannelStatus is a channel's lifecycle status, mirroring the Rust-side
// ChannelStatus enum. It marshals to/from the exact strings produced by
// Rust's default serde derive for a unit-variant enum
// ("Pending"/"Paired"/"Unpairing"), not the SCREAMING_SNAKE_CASE convention
// protobuf enums use.
type ChannelStatus int

const (
	// ChannelStatusPending marks a channel awaiting out-of-band fingerprint
	// confirmation: every replica pairing, and every pairing made over
	// ContactModeNoKeys — that mode commits to nothing, so the fingerprint
	// is the only check that catches a key substituted on its plaintext
	// PrePair leg. Such a channel is not a publish target, not a recovery
	// source, and inbound messages on it are ignored.
	ChannelStatusPending ChannelStatus = iota
	// ChannelStatusPaired marks a channel fully paired and ready for
	// protocol messages.
	ChannelStatusPaired
	// ChannelStatusUnpairing marks a replica-group member that has been
	// told to leave and is awaiting the roster version that completes its
	// removal. Never set on a helper channel.
	ChannelStatusUnpairing
)

func (s ChannelStatus) String() string {
	switch s {
	case ChannelStatusPending:
		return "Pending"
	case ChannelStatusPaired:
		return "Paired"
	case ChannelStatusUnpairing:
		return "Unpairing"
	default:
		return fmt.Sprintf("ChannelStatus(%d)", int(s))
	}
}

// MarshalJSON implements json.Marshaler.
func (s ChannelStatus) MarshalJSON() ([]byte, error) {
	str := s.String()
	if s != ChannelStatusPending && s != ChannelStatusPaired && s != ChannelStatusUnpairing {
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
	case "Unpairing":
		*s = ChannelStatusUnpairing
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
	// StateKindPendingReplicaDiscovery is an active replica catch-up, at most one
	// row per secretID. Holds the versions members have reported so far.
	StateKindPendingReplicaDiscovery StateKind = 4
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
//     PendingReplicas/SyncedReplicas/BehindReplicas (replica-id sets),
//     StartedAt (unix seconds).
//
// The two populations of a sharing round are tracked separately and by
// different keys: helpers by channelID, group members by replicaID. Every
// member of a group answers on the one shared channel, so a channel-keyed set
// would collapse them and the first answer would settle the round for all.
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
	// PendingReplicas are members written to that have not yet answered.
	PendingReplicas []uint64
	// SyncedReplicas are members that acknowledged.
	SyncedReplicas []uint64
	// BehindReplicas are members that refused, timed out, or were unreachable.
	BehindReplicas []uint64
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

// ChannelFilter narrows a listing from ChannelStore.
//
// Every field is a restriction, and every field's zero value means "do not
// restrict on this" — a zero ChannelFilter selects everything. Restrictions
// combine with AND, and Exclude is applied last, overriding IDs.
//
// Apply it in your query — a WHERE clause, a key-condition expression —
// instead of transferring rows the caller will discard. That transfer costs
// bandwidth everywhere, and on a metered backing that bills by bytes read it
// costs money. The library re-applies the filter to whatever you return before
// acting on it, so ignoring it is slow rather than wrong. That is one-way:
// returning fewer rows than the filter selects is still wrong, and is not
// something the library can detect.
//
// Role is a pointer so that "any role" (nil) is distinguishable from the
// zero-valued role, which is a real variant.
type ChannelFilter struct {
	// IDs restricts to these ids. Empty selects every record.
	//
	// Decoded from decimal strings on the wire — see the UnmarshalJSON
	// methods below — though callers see ordinary uint64s.
	IDs []uint64 `json:"ids"`
	// Status restricts to these statuses. Empty selects any status.
	Status []ChannelStatus `json:"status"`
	// Exclude omits these ids, applied after IDs. Empty omits nothing.
	Exclude []uint64 `json:"exclude"`
}

// HelperFilter narrows ChannelStore.ListHelpers. IDs are HelperChannel.ChannelID
// and Role is the peer's HelperChannel.PeerRole.
type HelperFilter struct {
	ChannelFilter
	// Role restricts to this peer role. nil selects any role.
	Role *SenderKind `json:"role"`
}

// ReplicaFilter narrows ChannelStore.ListReplicas. IDs are
// ReplicaMember.ReplicaID and Role is ReplicaMember.Role.
type ReplicaFilter struct {
	ChannelFilter
	// Role restricts to this role. nil selects any role.
	Role *ReplicaRole `json:"role"`
}

// matches reports whether the id and status survive the id, status and
// exclude restrictions. Role is checked by the caller, which knows its type.
func (f ChannelFilter) matches(id uint64, status ChannelStatus) bool {
	if len(f.IDs) > 0 && !containsUint64(f.IDs, id) {
		return false
	}
	if len(f.Status) > 0 && !containsStatus(f.Status, status) {
		return false
	}
	return !containsUint64(f.Exclude, id)
}

// Matches reports whether a channel with these attributes survives the filter.
//
// A store whose backing cannot express the restrictions as a query can list
// and call this, which is correct but transfers the rows the filter was meant
// to leave behind.
func (f HelperFilter) Matches(channelID uint64, status ChannelStatus, role SenderKind) bool {
	if f.Role != nil && *f.Role != role {
		return false
	}
	return f.ChannelFilter.matches(channelID, status)
}

// Matches reports whether a member with these attributes survives the filter.
// See HelperFilter.Matches.
func (f ReplicaFilter) Matches(replicaID uint64, status ChannelStatus, role ReplicaRole) bool {
	if f.Role != nil && *f.Role != role {
		return false
	}
	return f.ChannelFilter.matches(replicaID, status)
}

func containsUint64(haystack []uint64, needle uint64) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

func containsStatus(haystack []ChannelStatus, needle ChannelStatus) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// filterWire is the shape the core actually sends.
//
// Ids cross as decimal strings rather than JSON numbers because the same
// payload reaches the React Native bridge, where JavaScript's JSON.parse
// cannot hold a u64: an id above 2^53 is silently rounded, and a by-id filter
// then matches nothing. See `encode_filter` in
// `library/src/interop/ffi/protocol/stores.rs`.
type filterWire struct {
	IDs     []string        `json:"ids"`
	Status  []ChannelStatus `json:"status"`
	Role    json.RawMessage `json:"role"`
	Exclude []string        `json:"exclude"`
}

func parseFilterIDs(raw []string) ([]uint64, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]uint64, 0, len(raw))
	for _, s := range raw {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("channel filter id %q is not a decimal u64: %w", s, err)
		}
		out = append(out, v)
	}
	return out, nil
}

func (w filterWire) into(f *ChannelFilter) error {
	ids, err := parseFilterIDs(w.IDs)
	if err != nil {
		return err
	}
	exclude, err := parseFilterIDs(w.Exclude)
	if err != nil {
		return err
	}
	f.IDs = ids
	f.Status = w.Status
	f.Exclude = exclude
	return nil
}

// UnmarshalJSON implements json.Unmarshaler.
//
// Declared on HelperFilter rather than on the embedded ChannelFilter: an
// embedded implementation is promoted to the outer type, so it would be used
// for the whole struct and Role would never decode.
func (f *HelperFilter) UnmarshalJSON(data []byte) error {
	var w filterWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	if err := w.into(&f.ChannelFilter); err != nil {
		return err
	}
	f.Role = nil
	if len(w.Role) > 0 && string(w.Role) != "null" {
		var role SenderKind
		if err := json.Unmarshal(w.Role, &role); err != nil {
			return err
		}
		f.Role = &role
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler. See HelperFilter.UnmarshalJSON.
func (f *ReplicaFilter) UnmarshalJSON(data []byte) error {
	var w filterWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}
	if err := w.into(&f.ChannelFilter); err != nil {
		return err
	}
	f.Role = nil
	if len(w.Role) > 0 && string(w.Role) != "null" {
		var role ReplicaRole
		if err := json.Unmarshal(w.Role, &role); err != nil {
			return err
		}
		f.Role = &role
	}
	return nil
}
