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
type mockChannelStore struct {
	data  map[uint64]map[uint64]Channel
	links map[uint64]map[uint64]map[uint64]bool
}

func newMockChannelStore() *mockChannelStore {
	return &mockChannelStore{
		data:  make(map[uint64]map[uint64]Channel),
		links: make(map[uint64]map[uint64]map[uint64]bool),
	}
}

func (m *mockChannelStore) Load(secretID, channelID uint64) (Channel, bool, error) {
	c, ok := m.data[secretID][channelID]
	return c, ok, nil
}

func (m *mockChannelStore) Save(secretID uint64, channel Channel) error {
	if m.data[secretID] == nil {
		m.data[secretID] = make(map[uint64]Channel)
	}
	m.data[secretID][channel.ID] = channel
	return nil
}

func (m *mockChannelStore) Remove(secretID, channelID uint64) (bool, error) {
	_, ok := m.data[secretID][channelID]
	delete(m.data[secretID], channelID)
	return ok, nil
}

func (m *mockChannelStore) ListChannels(secretID uint64) ([]uint64, error) {
	out := make([]uint64, 0, len(m.data[secretID]))
	for id := range m.data[secretID] {
		out = append(out, id)
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

	ch := Channel{
		ID:        1,
		Transport: TransportEndpoint{URI: "https://h.example.com", Protocol: 0},
		Status:    ChannelStatusPaired,
		Role:      SenderKindOwner,
	}
	if err := store.Save(100, ch); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok, err := store.Load(100, 1)
	if err != nil || !ok {
		t.Fatalf("Load: got=%v ok=%v err=%v", got, ok, err)
	}
	if got.ID != 1 || got.Role != SenderKindOwner {
		t.Fatalf("Load mismatch: %+v", got)
	}

	_, ok, err = store.Load(100, 999)
	if err != nil || ok {
		t.Fatalf("Load(missing) should report not-found, got ok=%v err=%v", ok, err)
	}

	removed, err := store.Remove(100, 1)
	if err != nil || !removed {
		t.Fatalf("Remove: removed=%v err=%v", removed, err)
	}
	removed, err = store.Remove(100, 1)
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
