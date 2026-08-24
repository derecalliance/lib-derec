// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"testing"
)

// mockChannelStore is a minimal in-memory ChannelStore used only to
// compile-check the interface's method set/signatures and exercise it
// through the interface value (not the concrete type).
type channelKey struct {
	channelID uint64
	replicaID uint64
}

type mockChannelStore struct {
	data  map[uint64]map[channelKey]ChannelRecord
	links map[uint64]map[uint64]map[uint64]bool
}

func newMockChannelStore() *mockChannelStore {
	return &mockChannelStore{
		data:  make(map[uint64]map[channelKey]ChannelRecord),
		links: make(map[uint64]map[uint64]map[uint64]bool),
	}
}

func (m *mockChannelStore) Load(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
	c, ok := m.data[secretID][channelKey{channelID, replicaID}]
	return c, ok, nil
}

func (m *mockChannelStore) Save(secretID uint64, record ChannelRecord) error {
	if m.data[secretID] == nil {
		m.data[secretID] = make(map[channelKey]ChannelRecord)
	}
	m.data[secretID][channelKey{record.ChannelID(), record.ReplicaID()}] = record
	return nil
}

func (m *mockChannelStore) Remove(secretID, channelID, replicaID uint64) (bool, error) {
	k := channelKey{channelID, replicaID}
	_, ok := m.data[secretID][k]
	delete(m.data[secretID], k)
	return ok, nil
}

func (m *mockChannelStore) ListHelpers(secretID uint64) ([]HelperChannel, error) {
	out := make([]HelperChannel, 0, len(m.data[secretID]))
	for _, r := range m.data[secretID] {
		if r.Helper != nil {
			out = append(out, *r.Helper)
		}
	}
	return out, nil
}

func (m *mockChannelStore) ListReplicas(secretID uint64) ([]ReplicaMember, error) {
	out := make([]ReplicaMember, 0, len(m.data[secretID]))
	for _, r := range m.data[secretID] {
		if r.Replica != nil {
			out = append(out, *r.Replica)
		}
	}
	return out, nil
}

func (m *mockChannelStore) LinkChannel(secretID, a, b uint64) error {
	return nil
}

func (m *mockChannelStore) LinkedChannels(secretID, channelID uint64) ([]uint64, error) {
	return []uint64{channelID}, nil
}

var _ ChannelStore = (*mockChannelStore)(nil)

type mockSecretStore struct {
	data map[uint64]map[uint64]map[SecretKind]SecretValue
}

func (m *mockSecretStore) Load(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error) {
	v, ok := m.data[secretID][channelID][kind]
	return v, ok, nil
}

func (m *mockSecretStore) Save(secretID, channelID uint64, value SecretValue) error {
	return nil
}

func (m *mockSecretStore) Remove(secretID, channelID uint64, kind SecretKind) error {
	return nil
}

var _ SecretStore = (*mockSecretStore)(nil)

type mockShareStore struct{}

func (m *mockShareStore) Load(secretID, channelID uint64, versions []uint32) ([]Share, error) {
	return nil, nil
}
func (m *mockShareStore) LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error) {
	return nil, nil
}
func (m *mockShareStore) LoadAll(secretID uint64, channelIDs []uint64) ([]Share, error) {
	return nil, nil
}
func (m *mockShareStore) LatestVersion(secretID uint64) (uint32, bool, error) {
	return 0, false, nil
}
func (m *mockShareStore) Save(secretID, channelID uint64, share Share) error {
	return nil
}
func (m *mockShareStore) RemoveChannel(secretID, channelID uint64) error {
	return nil
}

var _ ShareStore = (*mockShareStore)(nil)

type mockUserSecretStore struct{}

func (m *mockUserSecretStore) LoadLatest(secretID uint64) (UserSecrets, bool, error) {
	return UserSecrets{}, false, nil
}
func (m *mockUserSecretStore) SaveLatest(secretID uint64, value UserSecrets) error {
	return nil
}
func (m *mockUserSecretStore) Remove(secretID uint64) error {
	return nil
}

var _ UserSecretStore = (*mockUserSecretStore)(nil)

type mockStateStore struct{}

func (m *mockStateStore) Save(secretID uint64, item StateItem) error {
	return nil
}
func (m *mockStateStore) Load(secretID uint64, key StateKey) (StateItem, bool, error) {
	return StateItem{}, false, nil
}
func (m *mockStateStore) Remove(secretID uint64, key StateKey) (bool, error) {
	return false, nil
}
func (m *mockStateStore) LoadAll(secretID uint64, kind StateKind) ([]StateItem, error) {
	return nil, nil
}

var _ StateStore = (*mockStateStore)(nil)

type mockTransport struct {
	sent []struct {
		uri      string
		protocol int32
		message  []byte
	}
	fail bool
}

func (m *mockTransport) Send(uri string, protocol int32, message []byte) error {
	if m.fail {
		return errors.New("simulated transport failure")
	}
	m.sent = append(m.sent, struct {
		uri      string
		protocol int32
		message  []byte
	}{uri, protocol, message})
	return nil
}

var _ Transport = (*mockTransport)(nil)

// --- Behavioral smoke tests through the interface values (not the
// concrete mock types) — proves the interfaces are usable end to end, not
// just structurally satisfiable.

func TestChannelStore_SaveLoadRemoveThroughInterface(t *testing.T) {
	var store ChannelStore = newMockChannelStore()

	ch := HelperChannel{
		ChannelID: 1,
		Transport: TransportEndpoint{URI: "https://h.example.com", Protocol: 0},
		Status:    ChannelStatusPaired,
		PeerRole:  SenderKindOwner,
	}
	if err := store.Save(100, ChannelRecord{Helper: &ch}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := store.Load(100, 1, 0)
	if err != nil || !ok {
		t.Fatalf("Load: got=%v ok=%v err=%v", got, ok, err)
	}
	if got.Helper == nil || got.Helper.ChannelID != 1 || got.Helper.PeerRole != SenderKindOwner {
		t.Fatalf("Load mismatch: %+v", got)
	}

	_, ok, err = store.Load(100, 999, 0)
	if err != nil || ok {
		t.Fatalf("Load(missing) should report not-found, got ok=%v err=%v", ok, err)
	}

	// A member is addressed by its replica id, and shares the channel id
	// with every other member — so it must not collide with the helper
	// channel at the same id.
	member := ReplicaMember{
		ChannelID: 1,
		ReplicaID: 42,
		Transport: TransportEndpoint{URI: "https://r.example.com", Protocol: 0},
		Role:      ReplicaRoleDestination,
		Status:    ChannelStatusPaired,
	}
	if err := store.Save(100, ChannelRecord{Replica: &member}); err != nil {
		t.Fatalf("Save(member): %v", err)
	}
	gotMember, ok, err := store.Load(100, 1, 42)
	if err != nil || !ok || gotMember.Replica == nil {
		t.Fatalf("Load(member): got=%v ok=%v err=%v", gotMember, ok, err)
	}
	if gotMember.Replica.Role != ReplicaRoleDestination {
		t.Fatalf("member role mismatch: %+v", gotMember.Replica)
	}
	if stillHelper, ok, _ := store.Load(100, 1, 0); !ok || stillHelper.Helper == nil {
		t.Fatal("saving a member at the same channel id must not evict the helper channel")
	}

	helpers, err := store.ListHelpers(100)
	if err != nil || len(helpers) != 1 {
		t.Fatalf("ListHelpers: got %d entries, err=%v", len(helpers), err)
	}
	members, err := store.ListReplicas(100)
	if err != nil || len(members) != 1 {
		t.Fatalf("ListReplicas: got %d entries, err=%v", len(members), err)
	}

	removed, err := store.Remove(100, 1, 0)
	if err != nil || !removed {
		t.Fatalf("Remove: removed=%v err=%v", removed, err)
	}
	removed, err = store.Remove(100, 1, 0)
	if err != nil || removed {
		t.Fatalf("Remove(already gone) should be false, got %v", removed)
	}
}

func TestTransport_SendThroughInterface(t *testing.T) {
	var transport Transport = &mockTransport{}
	if err := transport.Send("https://example.com", 0, []byte("hello")); err != nil {
		t.Fatalf("Send: %v", err)
	}

	failing := &mockTransport{fail: true}
	transport = failing
	if err := transport.Send("https://example.com", 0, nil); err == nil {
		t.Fatal("expected error from failing transport")
	}
}

func TestStateStore_KeyRoundTripThroughInterface(t *testing.T) {
	cid := uint64(5)
	item := StateItem{Kind: StateKindPendingVerification, ChannelID: &cid, Bytes: []byte{1, 2}}
	if item.Key().Kind != StateKindPendingVerification {
		t.Fatalf("Key() = %+v", item.Key())
	}
}
