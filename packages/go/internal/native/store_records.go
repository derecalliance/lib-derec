// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Wire record codecs for the store callbacks. Every function here mirrors
// a serde-JSON shape defined by library/src/ffi/protocol/stores.rs (or, for
// Channel, Channel's own serde derive in library/src/protocol/types.rs).
// This file is the Go mirror image of stores.rs's Dotnet* adapters: Rust
// there decodes what Go here encodes, and encodes what Go here decodes —
// Go sits on the callback-implementer side, Rust on the callback-caller
// side. Where stores.rs only defines one direction (e.g. StateKeyRecord
// has an encode-only `From<&StateKey>` on the Rust side, since Rust never
// receives a StateKey from the C boundary), the missing direction here
// (DecodeStateKey) is inferred as the precise inverse.
package native

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// JSONByteArray marshals as a JSON array of small integers, matching
// serde_json's default `Vec<u8>` representation (used by every *Record
// type in stores.rs, none of which opt into serde_bytes). Go's
// encoding/json base64-encodes plain []byte fields by default, which would
// not round-trip with the Rust side, hence this adapter type. Exported so
// package protocol can reuse the same codec for its own []byte-as-wire-array
// fields rather than defining a second, identical type.
type JSONByteArray []byte

// MarshalJSON implements json.Marshaler.
func (b JSONByteArray) MarshalJSON() ([]byte, error) {
	nums := make([]int, len(b))
	for i, v := range b {
		nums[i] = int(v)
	}
	return json.Marshal(nums)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *JSONByteArray) UnmarshalJSON(data []byte) error {
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil {
		return err
	}
	out := make(JSONByteArray, len(nums))
	for i, n := range nums {
		if n < 0 || n > 255 {
			return fmt.Errorf("native: byte value out of range: %d", n)
		}
		out[i] = byte(n)
	}
	*b = out
	return nil
}

// --- Channel -----------------------------------------------------------

// channelWire mirrors Channel's own serde derive exactly (see
// library/src/protocol/types.rs): field names, presence, and nesting are
// load-bearing — Channel crosses the FFI boundary as this shape directly,
// with no separate record wrapper.
type channelWire struct {
	ID                uint64            `json:"id"`
	Transport         transportWire     `json:"transport"`
	CommunicationInfo map[string]string `json:"communication_info"`
	Status            ChannelStatus     `json:"status"`
	CreatedAt         uint64            `json:"created_at"`
	PeerRole          SenderKind        `json:"peer_role"`
	ReplicaID         *uint64           `json:"replica_id"`
}

type transportWire struct {
	URI      string `json:"uri"`
	Protocol int32  `json:"protocol"`
}

// EncodeChannel produces the JSON a ChannelStoreCallbacks.save/load
// response must carry, matching Channel's derived Serialize output
// byte-for-byte (field names, PascalCase enum strings, bare-number id).
func EncodeChannel(c Channel) ([]byte, error) {
	info := c.CommunicationInfo
	if info == nil {
		// Rust's HashMap<String,String> has no Option wrapper here, so an
		// absent map always serializes as `{}`, never `null`.
		info = map[string]string{}
	}
	w := channelWire{
		ID:                c.ID,
		Transport:         transportWire{URI: c.Transport.URI, Protocol: c.Transport.Protocol},
		CommunicationInfo: info,
		Status:            c.Status,
		CreatedAt:         c.CreatedAt,
		PeerRole:          c.PeerRole,
		ReplicaID:         c.ReplicaID,
	}
	return json.Marshal(w)
}

// DecodeChannel parses a Channel from a ChannelStoreCallbacks.load/save
// wire payload.
func DecodeChannel(data []byte) (Channel, error) {
	var w channelWire
	if err := json.Unmarshal(data, &w); err != nil {
		return Channel{}, fmt.Errorf("native: decode Channel: %w", err)
	}
	return Channel{
		ID:                w.ID,
		Transport:         TransportEndpoint{URI: w.Transport.URI, Protocol: w.Transport.Protocol},
		CommunicationInfo: w.CommunicationInfo,
		Status:            w.Status,
		CreatedAt:         w.CreatedAt,
		PeerRole:          w.PeerRole,
		ReplicaID:         w.ReplicaID,
	}, nil
}

// --- Share ---------------------------------------------------------------

// shareWire mirrors ShareRecord in stores.rs: secret_id is stringified (a
// u64 wouldn't safely round-trip through some host languages' JSON number
// type), version is a plain u32, bytes a number array. Notably there is no
// replica_id field — ShareRecord never carries it.
type shareWire struct {
	SecretID string        `json:"secret_id"`
	Version  uint32        `json:"version"`
	Bytes    JSONByteArray `json:"bytes"`
}

// EncodeShare produces the JSON a ShareStoreCallbacks.save call carries.
// ReplicaID is intentionally dropped — matches Rust's
// `impl From<&Share> for ShareRecord`, which never reads it.
func EncodeShare(s Share) ([]byte, error) {
	w := shareWire{
		SecretID: strconv.FormatUint(s.SecretID, 10),
		Version:  s.Version,
		Bytes:    JSONByteArray(s.Bytes),
	}
	return json.Marshal(w)
}

// DecodeShare parses a Share from a single ShareRecord wire payload.
// ReplicaID is always nil on the returned value — matches Rust's
// `ShareRecord::into_share()`, which hardcodes `replica_id: None`.
func DecodeShare(data []byte) (Share, error) {
	var w shareWire
	if err := json.Unmarshal(data, &w); err != nil {
		return Share{}, fmt.Errorf("native: decode Share: %w", err)
	}
	id, err := strconv.ParseUint(w.SecretID, 10, 64)
	if err != nil {
		return Share{}, fmt.Errorf("native: Share secret_id is not a decimal u64: %w", err)
	}
	return Share{SecretID: id, Version: w.Version, Bytes: []byte(w.Bytes)}, nil
}

// EncodeShareList produces the JSON array a ShareStoreCallbacks
// load/load_many/load_all response carries.
func EncodeShareList(shares []Share) ([]byte, error) {
	wires := make([]shareWire, len(shares))
	for i, s := range shares {
		wires[i] = shareWire{
			SecretID: strconv.FormatUint(s.SecretID, 10),
			Version:  s.Version,
			Bytes:    JSONByteArray(s.Bytes),
		}
	}
	return json.Marshal(wires)
}

// DecodeShareList parses a JSON array of ShareRecord.
func DecodeShareList(data []byte) ([]Share, error) {
	var wires []shareWire
	if err := json.Unmarshal(data, &wires); err != nil {
		return nil, fmt.Errorf("native: decode Share list: %w", err)
	}
	out := make([]Share, len(wires))
	for i, w := range wires {
		id, err := strconv.ParseUint(w.SecretID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("native: Share[%d] secret_id is not a decimal u64: %w", i, err)
		}
		out[i] = Share{SecretID: id, Version: w.Version, Bytes: []byte(w.Bytes)}
	}
	return out, nil
}

// --- SecretValue -----------------------------------------------------------

// secretValueWire mirrors SecretValueRecord in stores.rs.
type secretValueWire struct {
	Kind  uint32        `json:"kind"`
	Bytes JSONByteArray `json:"bytes"`
}

// EncodeSecretValue produces the JSON a SecretStoreCallbacks.save call
// carries.
func EncodeSecretValue(v SecretValue) ([]byte, error) {
	return json.Marshal(secretValueWire{Kind: uint32(v.Kind), Bytes: JSONByteArray(v.Bytes)})
}

// DecodeSecretValue parses a SecretValue from a SecretStoreCallbacks.load
// response, applying the same per-kind validation as Rust's
// `SecretValueRecord::into_value()`.
func DecodeSecretValue(data []byte) (SecretValue, error) {
	var w secretValueWire
	if err := json.Unmarshal(data, &w); err != nil {
		return SecretValue{}, fmt.Errorf("native: decode SecretValue: %w", err)
	}
	switch SecretKind(w.Kind) {
	case SecretKindSharedKey:
		if len(w.Bytes) != 32 {
			return SecretValue{}, fmt.Errorf("native: SharedKey payload must be 32 bytes, got %d", len(w.Bytes))
		}
	case SecretKindPairingSecret, SecretKindPairingContact:
		// Opaque blobs — no length constraint.
	default:
		return SecretValue{}, fmt.Errorf("native: unknown SecretKind: %d", w.Kind)
	}
	return SecretValue{Kind: SecretKind(w.Kind), Bytes: []byte(w.Bytes)}, nil
}

// --- StateKey --------------------------------------------------------------

// stateKeyWire mirrors StateKeyRecord in stores.rs. channel_id/version are
// omitted (not null) when absent, matching
// `#[serde(default, skip_serializing_if = "Option::is_none")]`.
type stateKeyWire struct {
	Kind      uint32  `json:"kind"`
	ChannelID *string `json:"channel_id,omitempty"`
	SecretID  *string `json:"secret_id,omitempty"`
	Version   *uint32 `json:"version,omitempty"`
}

// EncodeStateKey produces the JSON a StateStoreCallbacks.load/remove key
// argument carries, mirroring Rust's `impl From<&StateKey> for
// StateKeyRecord`.
func EncodeStateKey(k StateKey) ([]byte, error) {
	w := stateKeyWire{Kind: uint32(k.Kind)}
	switch k.Kind {
	case StateKindPendingVerification, StateKindPendingUnpair:
		if k.ChannelID == nil {
			return nil, fmt.Errorf("native: StateKey kind=%d requires ChannelID", k.Kind)
		}
		cid := strconv.FormatUint(*k.ChannelID, 10)
		w.ChannelID = &cid
	case StateKindPendingRecovery:
		if k.SecretID == nil {
			return nil, fmt.Errorf("native: StateKey PendingRecovery requires SecretID")
		}
		if k.Version == nil {
			return nil, fmt.Errorf("native: StateKey PendingRecovery requires Version")
		}
		sid := strconv.FormatUint(*k.SecretID, 10)
		w.SecretID = &sid
		v := *k.Version
		w.Version = &v
	case StateKindSharingRound:
		// No secondary key.
	default:
		return nil, fmt.Errorf("native: unknown StateKind: %d", k.Kind)
	}
	return json.Marshal(w)
}

// DecodeStateKey parses a StateKey from a StateStoreCallbacks.load/remove
// key argument. Rust never decodes this shape itself (StateKey only ever
// crosses Rust->Go), so this is the inferred precise inverse of
// EncodeStateKey / Rust's `impl From<&StateKey> for StateKeyRecord`.
func DecodeStateKey(data []byte) (StateKey, error) {
	var w stateKeyWire
	if err := json.Unmarshal(data, &w); err != nil {
		return StateKey{}, fmt.Errorf("native: decode StateKey: %w", err)
	}
	switch StateKind(w.Kind) {
	case StateKindPendingVerification, StateKindPendingUnpair:
		if w.ChannelID == nil {
			return StateKey{}, fmt.Errorf("native: StateKey kind=%d requires channel_id", w.Kind)
		}
		cid, err := strconv.ParseUint(*w.ChannelID, 10, 64)
		if err != nil {
			return StateKey{}, fmt.Errorf("native: channel_id not a decimal u64: %w", err)
		}
		return StateKey{Kind: StateKind(w.Kind), ChannelID: &cid}, nil
	case StateKindPendingRecovery:
		if w.SecretID == nil {
			return StateKey{}, fmt.Errorf("native: StateKey PendingRecovery requires secret_id")
		}
		if w.Version == nil {
			return StateKey{}, fmt.Errorf("native: StateKey PendingRecovery requires version")
		}
		sid, err := strconv.ParseUint(*w.SecretID, 10, 64)
		if err != nil {
			return StateKey{}, fmt.Errorf("native: secret_id not a decimal u64: %w", err)
		}
		v := *w.Version
		return StateKey{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &v}, nil
	case StateKindSharingRound:
		return StateKey{Kind: StateKindSharingRound}, nil
	default:
		return StateKey{}, fmt.Errorf("native: unknown StateKind: %d", w.Kind)
	}
}

// --- StateItem ---------------------------------------------------------

// stateItemWire mirrors StateItemRecord in stores.rs. Slice-valued fields
// use a pointer-to-slice so "field entirely absent" (None) is
// distinguishable from "field present but empty" (Some(vec![])) —
// PendingRecovery.shares and SharingRound's three id-sets are always
// Some(...) on the Rust side even when the collection is empty.
type stateItemWire struct {
	Kind      uint32           `json:"kind"`
	ChannelID *string          `json:"channel_id,omitempty"`
	SecretID  *string          `json:"secret_id,omitempty"`
	Version   *uint32          `json:"version,omitempty"`
	StartedAt *string          `json:"started_at,omitempty"`
	Bytes     *JSONByteArray   `json:"bytes,omitempty"`
	Shares    *[]JSONByteArray `json:"shares,omitempty"`
	Pending   *[]string        `json:"pending,omitempty"`
	Confirmed *[]string        `json:"confirmed,omitempty"`
	Failed    *[]string        `json:"failed,omitempty"`
}

func stringifyUint64s(ids []uint64) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = strconv.FormatUint(id, 10)
	}
	return out
}

func parseUint64Strings(raw *[]string, field string) ([]uint64, error) {
	if raw == nil {
		return nil, fmt.Errorf("native: SharingRound requires %s", field)
	}
	out := make([]uint64, len(*raw))
	for i, s := range *raw {
		id, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("native: %s entry not a decimal u64: %w", field, err)
		}
		out[i] = id
	}
	return out, nil
}

// EncodeStateItem produces the JSON a StateStoreCallbacks.save call
// carries, mirroring Rust's `impl From<&StateItem> for StateItemRecord`.
func EncodeStateItem(item StateItem) ([]byte, error) {
	w := stateItemWire{Kind: uint32(item.Kind)}
	switch item.Kind {
	case StateKindPendingVerification:
		if item.ChannelID == nil {
			return nil, fmt.Errorf("native: PendingVerification StateItem requires ChannelID")
		}
		cid := strconv.FormatUint(*item.ChannelID, 10)
		w.ChannelID = &cid
		b := JSONByteArray(item.Bytes)
		w.Bytes = &b
	case StateKindPendingRecovery:
		if item.SecretID == nil {
			return nil, fmt.Errorf("native: PendingRecovery StateItem requires SecretID")
		}
		if item.Version == nil {
			return nil, fmt.Errorf("native: PendingRecovery StateItem requires Version")
		}
		sid := strconv.FormatUint(*item.SecretID, 10)
		w.SecretID = &sid
		v := *item.Version
		w.Version = &v
		shares := make([]JSONByteArray, len(item.Shares))
		for i, s := range item.Shares {
			shares[i] = JSONByteArray(s)
		}
		w.Shares = &shares
	case StateKindPendingUnpair:
		if item.ChannelID == nil {
			return nil, fmt.Errorf("native: PendingUnpair StateItem requires ChannelID")
		}
		if item.StartedAt == nil {
			return nil, fmt.Errorf("native: PendingUnpair StateItem requires StartedAt")
		}
		cid := strconv.FormatUint(*item.ChannelID, 10)
		w.ChannelID = &cid
		sa := strconv.FormatUint(*item.StartedAt, 10)
		w.StartedAt = &sa
	case StateKindSharingRound:
		if item.Version == nil {
			return nil, fmt.Errorf("native: SharingRound StateItem requires Version")
		}
		if item.StartedAt == nil {
			return nil, fmt.Errorf("native: SharingRound StateItem requires StartedAt")
		}
		v := *item.Version
		w.Version = &v
		sa := strconv.FormatUint(*item.StartedAt, 10)
		w.StartedAt = &sa
		pending := stringifyUint64s(item.Pending)
		confirmed := stringifyUint64s(item.Confirmed)
		failed := stringifyUint64s(item.Failed)
		w.Pending = &pending
		w.Confirmed = &confirmed
		w.Failed = &failed
	default:
		return nil, fmt.Errorf("native: unknown StateKind: %d", item.Kind)
	}
	return json.Marshal(w)
}

// DecodeStateItem parses a StateItem from a StateStoreCallbacks.load/
// load_all response, mirroring Rust's `StateItemRecord::into_item()`
// exactly, including its per-kind required-field validation.
func DecodeStateItem(data []byte) (StateItem, error) {
	var w stateItemWire
	if err := json.Unmarshal(data, &w); err != nil {
		return StateItem{}, fmt.Errorf("native: decode StateItem: %w", err)
	}
	switch StateKind(w.Kind) {
	case StateKindPendingVerification:
		if w.ChannelID == nil {
			return StateItem{}, fmt.Errorf("native: PendingVerification requires channel_id")
		}
		cid, err := strconv.ParseUint(*w.ChannelID, 10, 64)
		if err != nil {
			return StateItem{}, fmt.Errorf("native: channel_id not a decimal u64: %w", err)
		}
		if w.Bytes == nil {
			return StateItem{}, fmt.Errorf("native: PendingVerification requires bytes")
		}
		return StateItem{Kind: StateKindPendingVerification, ChannelID: &cid, Bytes: []byte(*w.Bytes)}, nil
	case StateKindPendingRecovery:
		if w.SecretID == nil {
			return StateItem{}, fmt.Errorf("native: PendingRecovery requires secret_id")
		}
		if w.Version == nil {
			return StateItem{}, fmt.Errorf("native: PendingRecovery requires version")
		}
		if w.Shares == nil {
			return StateItem{}, fmt.Errorf("native: PendingRecovery requires shares")
		}
		sid, err := strconv.ParseUint(*w.SecretID, 10, 64)
		if err != nil {
			return StateItem{}, fmt.Errorf("native: secret_id not a decimal u64: %w", err)
		}
		shares := make([][]byte, len(*w.Shares))
		for i, s := range *w.Shares {
			shares[i] = []byte(s)
		}
		v := *w.Version
		return StateItem{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &v, Shares: shares}, nil
	case StateKindPendingUnpair:
		if w.ChannelID == nil {
			return StateItem{}, fmt.Errorf("native: PendingUnpair requires channel_id")
		}
		cid, err := strconv.ParseUint(*w.ChannelID, 10, 64)
		if err != nil {
			return StateItem{}, fmt.Errorf("native: channel_id not a decimal u64: %w", err)
		}
		if w.StartedAt == nil {
			return StateItem{}, fmt.Errorf("native: PendingUnpair requires started_at")
		}
		sa, err := strconv.ParseUint(*w.StartedAt, 10, 64)
		if err != nil {
			return StateItem{}, fmt.Errorf("native: started_at not a decimal u64: %w", err)
		}
		return StateItem{Kind: StateKindPendingUnpair, ChannelID: &cid, StartedAt: &sa}, nil
	case StateKindSharingRound:
		if w.Version == nil {
			return StateItem{}, fmt.Errorf("native: SharingRound requires version")
		}
		if w.StartedAt == nil {
			return StateItem{}, fmt.Errorf("native: SharingRound requires started_at")
		}
		sa, err := strconv.ParseUint(*w.StartedAt, 10, 64)
		if err != nil {
			return StateItem{}, fmt.Errorf("native: started_at not a decimal u64: %w", err)
		}
		pending, err := parseUint64Strings(w.Pending, "pending")
		if err != nil {
			return StateItem{}, err
		}
		confirmed, err := parseUint64Strings(w.Confirmed, "confirmed")
		if err != nil {
			return StateItem{}, err
		}
		failed, err := parseUint64Strings(w.Failed, "failed")
		if err != nil {
			return StateItem{}, err
		}
		v := *w.Version
		return StateItem{
			Kind:      StateKindSharingRound,
			Version:   &v,
			StartedAt: &sa,
			Pending:   pending,
			Confirmed: confirmed,
			Failed:    failed,
		}, nil
	default:
		return StateItem{}, fmt.Errorf("native: unknown StateKind: %d", w.Kind)
	}
}

// --- UserSecrets ---------------------------------------------------------

// userSecretWire mirrors UserSecretRecord in stores.rs.
type userSecretWire struct {
	ID   JSONByteArray `json:"id"`
	Name string        `json:"name"`
	Data JSONByteArray `json:"data"`
}

// userSecretsWire mirrors UserSecretsRecord in stores.rs.
type userSecretsWire struct {
	Version     uint32           `json:"version"`
	Secrets     []userSecretWire `json:"secrets"`
	Description *string          `json:"description,omitempty"`
}

// EncodeUserSecrets produces the JSON a
// UserSecretStoreCallbacks.save_latest call carries.
func EncodeUserSecrets(v UserSecrets) ([]byte, error) {
	secrets := make([]userSecretWire, len(v.Secrets))
	for i, s := range v.Secrets {
		secrets[i] = userSecretWire{ID: JSONByteArray(s.ID), Name: s.Name, Data: JSONByteArray(s.Data)}
	}
	w := userSecretsWire{Version: v.Version, Secrets: secrets, Description: v.Description}
	return json.Marshal(w)
}

// DecodeUserSecrets parses a UserSecrets from a
// UserSecretStoreCallbacks.load_latest response.
func DecodeUserSecrets(data []byte) (UserSecrets, error) {
	var w userSecretsWire
	if err := json.Unmarshal(data, &w); err != nil {
		return UserSecrets{}, fmt.Errorf("native: decode UserSecrets: %w", err)
	}
	secrets := make([]UserSecret, len(w.Secrets))
	for i, s := range w.Secrets {
		secrets[i] = UserSecret{ID: []byte(s.ID), Name: s.Name, Data: []byte(s.Data)}
	}
	return UserSecrets{Version: w.Version, Secrets: secrets, Description: w.Description}, nil
}

// --- Plain number-array helpers -------------------------------------------
//
// Channel-id and version lists cross the FFI as plain JSON number arrays
// (serde_json's default Vec<u64>/Vec<u32> representation) — never
// stringified, unlike the individual u64 fields inside the *Record types
// above.

// EncodeUint64Array encodes a channel-id list for
// list_channels/linked_channels/load_many/load_all arguments and
// responses.
func EncodeUint64Array(ids []uint64) ([]byte, error) {
	if ids == nil {
		ids = []uint64{}
	}
	return json.Marshal(ids)
}

// DecodeUint64Array decodes a channel-id list.
func DecodeUint64Array(data []byte) ([]uint64, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var ids []uint64
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, fmt.Errorf("native: decode uint64 array: %w", err)
	}
	return ids, nil
}

// EncodeUint32Array encodes a version list for
// ShareStoreCallbacks.load/load_many arguments.
func EncodeUint32Array(versions []uint32) ([]byte, error) {
	if versions == nil {
		versions = []uint32{}
	}
	return json.Marshal(versions)
}

// DecodeUint32Array decodes a version list.
func DecodeUint32Array(data []byte) ([]uint32, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var versions []uint32
	if err := json.Unmarshal(data, &versions); err != nil {
		return nil, fmt.Errorf("native: decode uint32 array: %w", err)
	}
	return versions, nil
}
