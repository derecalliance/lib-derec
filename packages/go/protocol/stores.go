// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package protocol is the DeRec Go SDK orchestrator's public surface: the
// six store/transport interfaces an application implements to back a
// protocol instance, plus the domain types those interfaces exchange.
//
// # Layering
//
// The domain types (ChannelRecord, Share, SecretValue, StateItem, StateKey,
// UserSecret, UserSecrets, and the small enums) and the wire codecs that
// convert them to/from the JSON each C callback carries both live in
// internal/native (store_types.go, store_records.go), not in this
// package. This package re-exports them via type aliases (`type
// ChannelRecord = native.ChannelRecord`, etc.) rather than defining new
// types.
//
// That placement is dictated by the hard no-import-cycle constraint:
// internal/native (the purego bridge, wired up in the next task) must be
// able to encode/decode these records without importing this package, and
// this package already needs to import internal/native for the FFI
// plumbing. If the domain types lived here instead, native's callback
// implementation would need to import protocol for the types while
// protocol imports native for the bridge — a cycle. Defining them once in
// native and aliasing them here is cycle-free and keeps exactly one
// definition per type.
//
// A second benefit of aliasing (rather than duplicating and converting):
// because `protocol.ChannelRecord` and `native.ChannelRecord` are the
// identical type,
// a value that satisfies e.g. protocol.ChannelStore automatically
// satisfies any structurally-identical interface internal/native declares
// over native.ChannelRecord — Go's structural interface typing lets the next
// task hand a protocol.ChannelStore implementation to native's callback
// wiring with no adapter shim, despite native never importing this
// package.
package protocol

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// Domain types exchanged by the store/transport interfaces below. See
// internal/native/store_types.go for the authoritative definitions and
// internal/native/store_records.go for the JSON codecs that give each
// type's wire shape its meaning.
type (
	// HelperChannel is a channel to a single helper, or to the owner
	// from a helper's side.
	HelperChannel = native.HelperChannel
	// ReplicaMember is one member of a replica group, including this
	// device itself.
	ReplicaMember = native.ReplicaMember
	// ChannelRecord is what a ChannelStore holds at one address: either
	// a helper channel or one replica-group member.
	ChannelRecord = native.ChannelRecord
	// ReplicaRole is a member's role within a replica group.
	ReplicaRole = native.ReplicaRole
	// TransportEndpoint is a peer's advertised transport.
	TransportEndpoint = native.TransportEndpoint
	// ChannelStatus is a channel's lifecycle status.
	ChannelStatus = native.ChannelStatus
	// SenderKind identifies the role a node holds on a Channel.
	SenderKind = native.SenderKind
	// SecretKind selects which kind of secret material a SecretValue
	// carries.
	SecretKind = native.SecretKind
	// SecretValue is the opaque secret payload stored alongside a
	// channel id and SecretKind.
	SecretValue = native.SecretValue
	// Share is a single stored share entry.
	Share = native.Share
	// StateKind tags which category of in-flight orchestrator state a
	// StateItem/StateKey belongs to.
	StateKind = native.StateKind
	// StateKey selects one row inside a StateKind under a secretID.
	StateKey = native.StateKey
	// StateItem is the payload of one row in the state store.
	StateItem = native.StateItem
	// UserSecret is a single user-facing secret entry.
	UserSecret = native.UserSecret
	// UserSecrets is a snapshot of the user-facing secret contents for
	// one secretID.
	UserSecrets = native.UserSecrets
)

const (
	ChannelStatusPending = native.ChannelStatusPending
	ChannelStatusPaired  = native.ChannelStatusPaired

	SenderKindOwner              = native.SenderKindOwner
	SenderKindHelper             = native.SenderKindHelper
	SenderKindReplicaSource      = native.SenderKindReplicaSource
	SenderKindReplicaDestination = native.SenderKindReplicaDestination

	ReplicaRoleSource      = native.ReplicaRoleSource
	ReplicaRoleDestination = native.ReplicaRoleDestination

	SecretKindSharedKey      = native.SecretKindSharedKey
	SecretKindPairingSecret  = native.SecretKindPairingSecret
	SecretKindPairingContact = native.SecretKindPairingContact

	StateKindPendingVerification = native.StateKindPendingVerification
	StateKindPendingRecovery     = native.StateKindPendingRecovery
	StateKindPendingUnpair       = native.StateKindPendingUnpair
	StateKindSharingRound        = native.StateKindSharingRound
)

// ChannelStore persists channel records plus the channel-link graph used to
// group channels belonging to the same Owner identity (e.g. after a recovery
// re-pairing). Mirrors derec_library::protocol::DeRecChannelStore.
// Implementations must be safe to call repeatedly but are never called
// concurrently for the same protocol instance — the Rust core serializes
// access to a store's methods via &mut self.
//
// A record is addressed by (channelID, replicaID). A replicaID of 0 — the
// value the protocol reserves as "absent" — addresses the helper channel at
// channelID.
//
// Any other value addresses that member of the replica group, and the member
// is keyed by replicaID ALONE. The accompanying channelID is context, not
// part of the key: a member moves between channels during an admission
// handover while remaining the same member, and a lookup that required both
// to match would miss it exactly when the move needs to be observed. Keep two
// maps — helpers by channelID, members by replicaID — not one keyed by the
// pair.
type ChannelStore interface {
	// Load returns the record at (secretID, channelID, replicaID), or
	// ok=false if none is stored.
	Load(secretID, channelID, replicaID uint64) (record ChannelRecord, ok bool, err error)
	// Save inserts or replaces the record at its own address. Deriving
	// the key from the record is what keeps a record from being stored
	// under the wrong one.
	Save(secretID uint64, record ChannelRecord) error
	// Remove deletes the record at (secretID, channelID, replicaID).
	// Returns whether an entry actually existed; removing a missing
	// entry is not an error.
	Remove(secretID, channelID, replicaID uint64) (existed bool, err error)
	// ListHelpers returns every helper channel stored under secretID.
	ListHelpers(secretID uint64) ([]HelperChannel, error)
	// ListReplicas returns every replica-group member stored under
	// secretID, including this device's own row.
	//
	// The order is significant in exactly one situation. A group has one
	// member holding the Source role; when it is removed, the protocol
	// promotes the first element of this slice that is neither the departing
	// member nor itself leaving. Ordering this slice is therefore how an
	// application chooses its succession policy. The choice is read once, on
	// the single device running the removal, and is then published in the
	// roster, so implementations on different devices need not agree on
	// order. Nothing else consults it.
	//
	// Returning an arbitrary order is correct and simply delegates the choice
	// to the storage — note that a SQL SELECT without ORDER BY and Go map
	// iteration are both arbitrary. Order explicitly to make succession
	// predictable.
	ListReplicas(secretID uint64) ([]ReplicaMember, error)
	// LinkChannel records a as belonging to the same Owner identity as
	// b (and vice versa) — a symmetric relation.
	LinkChannel(secretID, a, b uint64) error
	// LinkedChannels returns every channel id reachable from channelID
	// through the link graph, including channelID itself.
	LinkedChannels(secretID, channelID uint64) ([]uint64, error)
}

// SecretStore persists pairing/session secret material, keyed by
// (secretID, channelID, kind). Mirrors
// derec_library::protocol::DeRecSecretStore.
type SecretStore interface {
	// Load returns the value at (secretID, channelID, kind), or
	// ok=false if none is stored.
	Load(secretID, channelID uint64, kind SecretKind) (value SecretValue, ok bool, err error)
	// Save inserts or replaces the value at (secretID, channelID,
	// value.Kind).
	Save(secretID, channelID uint64, value SecretValue) error
	// Remove deletes the value at (secretID, channelID, kind).
	// Idempotent.
	Remove(secretID, channelID uint64, kind SecretKind) error
}

// ShareStore persists shares, keyed by (channelID, secretID, version).
// Mirrors derec_library::protocol::DeRecShareStore. The orchestrator
// funnels every share access through this interface —
// discovery/recovery/verification all hit one of the Load* methods.
type ShareStore interface {
	// Load returns the shares for a single channel within secretID. An
	// empty versions selects every version.
	Load(secretID, channelID uint64, versions []uint32) ([]Share, error)
	// LoadMany returns shares across several channels within secretID.
	// An empty versions selects every version.
	LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error)
	// LoadAll returns every share stored under secretID across the
	// given channels.
	LoadAll(secretID uint64, channelIDs []uint64) ([]Share, error)
	// LatestVersion returns the highest version stored for secretID, or
	// ok=false if no shares exist yet for this secret.
	LatestVersion(secretID uint64) (version uint32, ok bool, err error)
	// Save inserts or replaces the share at (channelID, share.SecretID,
	// share.Version).
	Save(secretID, channelID uint64, share Share) error
	// RemoveChannel deletes every share stored for channelID within
	// secretID.
	RemoveChannel(secretID, channelID uint64) error
}

// UserSecretStore persists the user-facing secret contents, keyed by
// secretID; one secretID maps to at most one stored UserSecrets entry —
// the most recent snapshot written by an application ProtectSecret call.
// Mirrors derec_library::protocol::DeRecUserSecretStore.
type UserSecretStore interface {
	// LoadLatest returns the latest snapshot for secretID, or ok=false
	// if the application has never published for this id on this
	// instance.
	LoadLatest(secretID uint64) (value UserSecrets, ok bool, err error)
	// SaveLatest overwrites the snapshot for secretID.
	SaveLatest(secretID uint64, value UserSecrets) error
	// Remove drops the snapshot for secretID. Idempotent.
	Remove(secretID uint64) error
}

// StateStore persists in-flight orchestrator state, keyed by (secretID,
// key). Mirrors derec_library::protocol::DeRecStateStore. Backends are
// treated as full-replacement upsert stores — accumulator-style state
// (StateKindPendingRecovery and StateKindSharingRound) grows via
// load-modify-save cycles driven by the library, not by the store.
type StateStore interface {
	// Save inserts or full-replaces the row at (secretID, item.Key()).
	// Idempotent.
	Save(secretID uint64, item StateItem) error
	// Load returns the row at (secretID, key), or ok=false if no row
	// exists.
	Load(secretID uint64, key StateKey) (item StateItem, ok bool, err error)
	// Remove deletes the row at (secretID, key). Returns whether a row
	// actually existed; removing a missing entry is not an error.
	Remove(secretID uint64, key StateKey) (existed bool, err error)
	// LoadAll returns every item of the given kind under secretID.
	LoadAll(secretID uint64, kind StateKind) ([]StateItem, error)
}

// Transport delivers outbound protocol messages. The protocol core hands
// the application the encoded envelope bytes plus the destination
// endpoint; the application is responsible for shipping them over the
// wire (HTTP, WebSocket, etc. — the library makes no transport
// assumptions). Mirrors derec_library::protocol::DeRecTransport.
type Transport interface {
	// Send delivers message to uri over the given transport protocol
	// (0 = HTTPS, the only value currently defined —see
	// derecpb.Protocol).
	Send(uri string, protocol int32, message []byte) error
}
