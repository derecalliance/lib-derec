// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"errors"
	"testing"
)

// --- Mock store implementations -----------------------------------------
//
// Each mock satisfies the corresponding unexported *Store interface
// structurally (channelStore, secretStore, shareStore, userSecretStore,
// stateStore, transportSender) via configurable function fields, so every
// test can drive a specific dispatch path — including a deliberate panic —
// without a real backend.

type mockChannelStore struct {
	loadFn         func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error)
	saveFn         func(secretID uint64, record ChannelRecord) error
	removeFn       func(secretID, channelID, replicaID uint64) (bool, error)
	listHelpersFn  func(secretID uint64) ([]HelperChannel, error)
	listReplicasFn func(secretID uint64) ([]ReplicaMember, error)
	linkFn         func(secretID, a, b uint64) error
	linkedFn       func(secretID, channelID uint64) ([]uint64, error)
}

func (m *mockChannelStore) Load(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
	return m.loadFn(secretID, channelID, replicaID)
}
func (m *mockChannelStore) Save(secretID uint64, record ChannelRecord) error {
	return m.saveFn(secretID, record)
}
func (m *mockChannelStore) Remove(secretID, channelID, replicaID uint64) (bool, error) {
	return m.removeFn(secretID, channelID, replicaID)
}
func (m *mockChannelStore) ListHelpers(secretID uint64) ([]HelperChannel, error) {
	return m.listHelpersFn(secretID)
}
func (m *mockChannelStore) ListReplicas(secretID uint64) ([]ReplicaMember, error) {
	return m.listReplicasFn(secretID)
}
func (m *mockChannelStore) LinkChannel(secretID, a, b uint64) error {
	return m.linkFn(secretID, a, b)
}
func (m *mockChannelStore) LinkedChannels(secretID, channelID uint64) ([]uint64, error) {
	return m.linkedFn(secretID, channelID)
}

var _ channelStore = (*mockChannelStore)(nil)

type mockSecretStore struct {
	loadFn   func(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error)
	saveFn   func(secretID, channelID uint64, value SecretValue) error
	removeFn func(secretID, channelID uint64, kind SecretKind) error
}

func (m *mockSecretStore) Load(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error) {
	return m.loadFn(secretID, channelID, kind)
}
func (m *mockSecretStore) Save(secretID, channelID uint64, value SecretValue) error {
	return m.saveFn(secretID, channelID, value)
}
func (m *mockSecretStore) Remove(secretID, channelID uint64, kind SecretKind) error {
	return m.removeFn(secretID, channelID, kind)
}

var _ secretStore = (*mockSecretStore)(nil)

type mockShareStore struct {
	loadFn          func(secretID, channelID uint64, versions []uint32) ([]Share, error)
	loadManyFn      func(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error)
	loadAllFn       func(secretID uint64, channelIDs []uint64) ([]Share, error)
	latestVersionFn func(secretID uint64) (uint32, bool, error)
	saveFn          func(secretID, channelID uint64, share Share) error
	removeChannelFn func(secretID, channelID uint64) error
}

func (m *mockShareStore) Load(secretID, channelID uint64, versions []uint32) ([]Share, error) {
	return m.loadFn(secretID, channelID, versions)
}
func (m *mockShareStore) LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error) {
	return m.loadManyFn(secretID, channelIDs, versions)
}
func (m *mockShareStore) LoadAll(secretID uint64, channelIDs []uint64) ([]Share, error) {
	return m.loadAllFn(secretID, channelIDs)
}
func (m *mockShareStore) LatestVersion(secretID uint64) (uint32, bool, error) {
	return m.latestVersionFn(secretID)
}
func (m *mockShareStore) Save(secretID, channelID uint64, share Share) error {
	return m.saveFn(secretID, channelID, share)
}
func (m *mockShareStore) RemoveChannel(secretID, channelID uint64) error {
	return m.removeChannelFn(secretID, channelID)
}

var _ shareStore = (*mockShareStore)(nil)

type mockUserSecretStore struct {
	loadLatestFn func(secretID uint64) (UserSecrets, bool, error)
	saveLatestFn func(secretID uint64, value UserSecrets) error
	removeFn     func(secretID uint64) error
}

func (m *mockUserSecretStore) LoadLatest(secretID uint64) (UserSecrets, bool, error) {
	return m.loadLatestFn(secretID)
}
func (m *mockUserSecretStore) SaveLatest(secretID uint64, value UserSecrets) error {
	return m.saveLatestFn(secretID, value)
}
func (m *mockUserSecretStore) Remove(secretID uint64) error {
	return m.removeFn(secretID)
}

var _ userSecretStore = (*mockUserSecretStore)(nil)

type mockStateStore struct {
	saveFn    func(secretID uint64, item StateItem) error
	loadFn    func(secretID uint64, key StateKey) (StateItem, bool, error)
	removeFn  func(secretID uint64, key StateKey) (bool, error)
	loadAllFn func(secretID uint64, kind StateKind) ([]StateItem, error)
}

func (m *mockStateStore) Save(secretID uint64, item StateItem) error {
	return m.saveFn(secretID, item)
}
func (m *mockStateStore) Load(secretID uint64, key StateKey) (StateItem, bool, error) {
	return m.loadFn(secretID, key)
}
func (m *mockStateStore) Remove(secretID uint64, key StateKey) (bool, error) {
	return m.removeFn(secretID, key)
}
func (m *mockStateStore) LoadAll(secretID uint64, kind StateKind) ([]StateItem, error) {
	return m.loadAllFn(secretID, kind)
}

var _ stateStore = (*mockStateStore)(nil)

type mockTransportSender struct {
	sendFn func(endpoints []Endpoint, message []byte) error
}

func (m *mockTransportSender) Send(endpoints []Endpoint, message []byte) error {
	return m.sendFn(endpoints, message)
}

var _ transportSender = (*mockTransportSender)(nil)

// --- ChannelStore dispatch ------------------------------------------------

func TestDispatchChannelLoad_Found(t *testing.T) {
	helper := HelperChannel{ChannelID: 7, Status: ChannelStatusPaired, PeerRole: SenderKindOwner, CommunicationInfo: map[string]string{}}
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			if secretID != 100 || channelID != 7 || replicaID != 0 {
				t.Fatalf("unexpected args: %d %d %d", secretID, channelID, replicaID)
			}
			return ChannelRecord{Helper: &helper}, true, nil
		},
	}}
	status, out := dispatchChannelLoad(s, 100, 7, 0)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	got, err := DecodeChannelRecord(out)
	if err != nil {
		t.Fatalf("DecodeChannelRecord: %v", err)
	}
	if got.Helper == nil || got.Helper.ChannelID != helper.ChannelID || got.Helper.PeerRole != helper.PeerRole {
		t.Fatalf("decoded = %+v, want %+v", got, helper)
	}
}

// A member row is addressed by its replica id, and the query must reach the
// store verbatim — a member and a helper channel can share a channel id.
func TestDispatchChannelLoad_ReplicaMember(t *testing.T) {
	member := ReplicaMember{ChannelID: 7, ReplicaID: 42, Role: ReplicaRoleDestination, Status: ChannelStatusPaired, CommunicationInfo: map[string]string{}}
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			if channelID != 7 || replicaID != 42 {
				t.Fatalf("query must reach the store verbatim: %d %d", channelID, replicaID)
			}
			return ChannelRecord{Replica: &member}, true, nil
		},
	}}
	status, out := dispatchChannelLoad(s, 100, 7, 42)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	got, err := DecodeChannelRecord(out)
	if err != nil {
		t.Fatalf("DecodeChannelRecord: %v", err)
	}
	if got.Replica == nil || got.Replica.ReplicaID != 42 || got.Replica.Role != ReplicaRoleDestination {
		t.Fatalf("decoded = %+v, want %+v", got, member)
	}
}

func TestDispatchChannelLoad_NotFound(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			return ChannelRecord{}, false, nil
		},
	}}
	status, out := dispatchChannelLoad(s, 1, 2, 0)
	if status != ffiStatusNotFound {
		t.Fatalf("status = %d, want ffiStatusNotFound", status)
	}
	if out != nil {
		t.Fatalf("expected nil out on not-found, got %v", out)
	}
}

func TestDispatchChannelLoad_BackendError(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			return ChannelRecord{}, false, errors.New("boom")
		},
	}}
	status, _ := dispatchChannelLoad(s, 1, 2, 0)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure", status)
	}
}

// TestDispatchChannelLoad_PanicRecovered is the REQUIRED panic-safety proof:
// a store implementation panicking during a callback dispatch must never
// propagate past this function — it must come back as ffiStatusFailure, not
// a crash.
func TestDispatchChannelLoad_PanicRecovered(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			panic("mock store blew up")
		},
	}}
	status, out := dispatchChannelLoad(s, 1, 2, 0)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure after recovered panic", status)
	}
	if out != nil {
		t.Fatalf("expected nil out after recovered panic, got %v", out)
	}
}

func TestDispatchChannelSave_RecordsValue(t *testing.T) {
	var saved ChannelRecord
	var savedSecretID uint64
	s := &storeSet{channel: &mockChannelStore{
		saveFn: func(secretID uint64, record ChannelRecord) error {
			savedSecretID = secretID
			saved = record
			return nil
		},
	}}
	ch := HelperChannel{ChannelID: 9, Status: ChannelStatusPending, PeerRole: SenderKindHelper, CommunicationInfo: map[string]string{}}
	payload, err := EncodeChannelRecord(ChannelRecord{Helper: &ch})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}
	status := dispatchChannelSave(s, 55, 9, 0, payload)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	if savedSecretID != 55 || saved.Helper == nil || saved.Helper.ChannelID != 9 || saved.Helper.PeerRole != SenderKindHelper {
		t.Fatalf("mock did not record expected save: secretID=%d record=%+v", savedSecretID, saved)
	}
}

func TestDispatchChannelSave_InvalidJSON(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		saveFn: func(secretID uint64, record ChannelRecord) error {
			t.Fatal("save should not be called for undecodable input")
			return nil
		},
	}}
	status := dispatchChannelSave(s, 1, 2, 0, []byte("not json"))
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure", status)
	}
}

func TestDispatchChannelRemove_ExistedTransitions(t *testing.T) {
	existed := true
	s := &storeSet{channel: &mockChannelStore{
		removeFn: func(secretID, channelID, replicaID uint64) (bool, error) {
			return existed, nil
		},
	}}
	status, got := dispatchChannelRemove(s, 1, 2, 0)
	if status != ffiStatusOK || !got {
		t.Fatalf("first remove: status=%d existed=%v, want ok/true", status, got)
	}
	existed = false
	status, got = dispatchChannelRemove(s, 1, 2, 0)
	if status != ffiStatusOK || got {
		t.Fatalf("second remove: status=%d existed=%v, want ok/false", status, got)
	}
}

func TestDispatchChannelListHelpers(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		listHelpersFn: func(secretID uint64) ([]HelperChannel, error) {
			return []HelperChannel{
				{ChannelID: 1, CommunicationInfo: map[string]string{}},
				{ChannelID: 2, CommunicationInfo: map[string]string{}},
			}, nil
		},
	}}
	status, out := dispatchChannelListHelpers(s, 1)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	var decoded []helperChannelWire
	if err := json.Unmarshal(out, &decoded); err != nil || len(decoded) != 2 {
		t.Fatalf("decode listHelpers: decoded=%v err=%v", decoded, err)
	}
}

func TestDispatchChannelListReplicas(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		listReplicasFn: func(secretID uint64) ([]ReplicaMember, error) {
			return []ReplicaMember{
				{ChannelID: 5, ReplicaID: 1, Role: ReplicaRoleSource, CommunicationInfo: map[string]string{}},
				{ChannelID: 5, ReplicaID: 2, Role: ReplicaRoleDestination, CommunicationInfo: map[string]string{}},
			}, nil
		},
	}}
	status, out := dispatchChannelListReplicas(s, 1)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	var decoded []replicaMemberWire
	if err := json.Unmarshal(out, &decoded); err != nil || len(decoded) != 2 {
		t.Fatalf("decode listReplicas: decoded=%v err=%v", decoded, err)
	}
	if decoded[0].Role != ReplicaRoleSource || decoded[1].Role != ReplicaRoleDestination {
		t.Fatalf("roles must survive the round trip: %+v", decoded)
	}
}

func TestDispatchChannelLinkChannel(t *testing.T) {
	var gotA, gotB uint64
	s := &storeSet{channel: &mockChannelStore{
		linkFn: func(secretID, a, b uint64) error {
			gotA, gotB = a, b
			return nil
		},
	}}
	status := dispatchChannelLinkChannel(s, 1, 10, 20)
	if status != ffiStatusOK || gotA != 10 || gotB != 20 {
		t.Fatalf("status=%d gotA=%d gotB=%d", status, gotA, gotB)
	}
}

func TestDispatchChannelLinkedChannels(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		linkedFn: func(secretID, channelID uint64) ([]uint64, error) {
			return []uint64{channelID}, nil
		},
	}}
	status, out := dispatchChannelLinkedChannels(s, 1, 42)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	ids, err := DecodeUint64Array(out)
	if err != nil || len(ids) != 1 || ids[0] != 42 {
		t.Fatalf("DecodeUint64Array: ids=%v err=%v", ids, err)
	}
}

// --- SecretStore dispatch --------------------------------------------------

func TestDispatchSecretLoad_FoundAndNotFound(t *testing.T) {
	s := &storeSet{secret: &mockSecretStore{
		loadFn: func(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error) {
			if kind == SecretKindSharedKey {
				return SecretValue{Kind: SecretKindSharedKey, Bytes: make([]byte, 32)}, true, nil
			}
			return SecretValue{}, false, nil
		},
	}}
	status, out := dispatchSecretLoad(s, 1, 2, uint32(SecretKindSharedKey))
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	v, err := DecodeSecretValue(out)
	if err != nil || v.Kind != SecretKindSharedKey {
		t.Fatalf("DecodeSecretValue: v=%+v err=%v", v, err)
	}

	status, out = dispatchSecretLoad(s, 1, 2, uint32(SecretKindPairingSecret))
	if status != ffiStatusNotFound || out != nil {
		t.Fatalf("status=%d out=%v, want not-found/nil", status, out)
	}
}

func TestDispatchSecretSave_PanicRecovered(t *testing.T) {
	s := &storeSet{secret: &mockSecretStore{
		saveFn: func(secretID, channelID uint64, value SecretValue) error {
			panic("secret store exploded")
		},
	}}
	payload, err := EncodeSecretValue(SecretValue{Kind: SecretKindSharedKey, Bytes: make([]byte, 32)})
	if err != nil {
		t.Fatalf("EncodeSecretValue: %v", err)
	}
	status := dispatchSecretSave(s, 1, 2, payload)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure after recovered panic", status)
	}
}

func TestDispatchSecretRemove(t *testing.T) {
	var gotKind SecretKind
	s := &storeSet{secret: &mockSecretStore{
		removeFn: func(secretID, channelID uint64, kind SecretKind) error {
			gotKind = kind
			return nil
		},
	}}
	status := dispatchSecretRemove(s, 1, 2, uint32(SecretKindPairingContact))
	if status != ffiStatusOK || gotKind != SecretKindPairingContact {
		t.Fatalf("status=%d gotKind=%d", status, gotKind)
	}
}

// --- ShareStore dispatch ---------------------------------------------------

func TestDispatchShareLoad(t *testing.T) {
	s := &storeSet{share: &mockShareStore{
		loadFn: func(secretID, channelID uint64, versions []uint32) ([]Share, error) {
			if len(versions) != 2 || versions[0] != 1 || versions[1] != 2 {
				t.Fatalf("unexpected versions: %v", versions)
			}
			return []Share{{SecretID: secretID, Version: 2, Bytes: []byte{9}}}, nil
		},
	}}
	versionsJSON, _ := EncodeUint32Array([]uint32{1, 2})
	status, out := dispatchShareLoad(s, 5, 6, versionsJSON)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	shares, err := DecodeShareList(out)
	if err != nil || len(shares) != 1 || shares[0].Version != 2 {
		t.Fatalf("DecodeShareList: shares=%v err=%v", shares, err)
	}
}

func TestDispatchShareLoad_PanicRecovered(t *testing.T) {
	s := &storeSet{share: &mockShareStore{
		loadFn: func(secretID, channelID uint64, versions []uint32) ([]Share, error) {
			panic("share store blew up")
		},
	}}
	versionsJSON, _ := EncodeUint32Array(nil)
	status, out := dispatchShareLoad(s, 1, 2, versionsJSON)
	if status != ffiStatusFailure || out != nil {
		t.Fatalf("status=%d out=%v, want failure/nil after recovered panic", status, out)
	}
}

func TestDispatchShareLoadMany(t *testing.T) {
	s := &storeSet{share: &mockShareStore{
		loadManyFn: func(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error) {
			return []Share{{SecretID: secretID, Version: 1}}, nil
		},
	}}
	idsJSON, _ := EncodeUint64Array([]uint64{1, 2})
	versionsJSON, _ := EncodeUint32Array([]uint32{1})
	status, out := dispatchShareLoadMany(s, 5, idsJSON, versionsJSON)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	shares, err := DecodeShareList(out)
	if err != nil || len(shares) != 1 {
		t.Fatalf("DecodeShareList: shares=%v err=%v", shares, err)
	}
}

func TestDispatchShareLoadAll(t *testing.T) {
	s := &storeSet{share: &mockShareStore{
		loadAllFn: func(secretID uint64, channelIDs []uint64) ([]Share, error) {
			return nil, nil
		},
	}}
	idsJSON, _ := EncodeUint64Array([]uint64{1})
	status, out := dispatchShareLoadAll(s, 5, idsJSON)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	shares, err := DecodeShareList(out)
	if err != nil || len(shares) != 0 {
		t.Fatalf("DecodeShareList: shares=%v err=%v", shares, err)
	}
}

func TestDispatchShareLatestVersion(t *testing.T) {
	s := &storeSet{share: &mockShareStore{
		latestVersionFn: func(secretID uint64) (uint32, bool, error) {
			return 3, true, nil
		},
	}}
	status, has, version := dispatchShareLatestVersion(s, 5)
	if status != ffiStatusOK || !has || version != 3 {
		t.Fatalf("status=%d has=%v version=%d", status, has, version)
	}

	s2 := &storeSet{share: &mockShareStore{
		latestVersionFn: func(secretID uint64) (uint32, bool, error) {
			return 0, false, nil
		},
	}}
	status, has, _ = dispatchShareLatestVersion(s2, 5)
	if status != ffiStatusOK || has {
		t.Fatalf("status=%d has=%v, want ok/false", status, has)
	}
}

func TestDispatchShareSave(t *testing.T) {
	var savedChannelID uint64
	var savedShare Share
	s := &storeSet{share: &mockShareStore{
		saveFn: func(secretID, channelID uint64, share Share) error {
			savedChannelID = channelID
			savedShare = share
			return nil
		},
	}}
	payload, err := EncodeShare(Share{SecretID: 5, Version: 4, Bytes: []byte{1, 2}})
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}
	status := dispatchShareSave(s, 5, 6, payload)
	if status != ffiStatusOK || savedChannelID != 6 || savedShare.Version != 4 {
		t.Fatalf("status=%d savedChannelID=%d savedShare=%+v", status, savedChannelID, savedShare)
	}
}

func TestDispatchShareRemoveChannel(t *testing.T) {
	called := false
	s := &storeSet{share: &mockShareStore{
		removeChannelFn: func(secretID, channelID uint64) error {
			called = true
			return nil
		},
	}}
	status := dispatchShareRemoveChannel(s, 5, 6)
	if status != ffiStatusOK || !called {
		t.Fatalf("status=%d called=%v", status, called)
	}
}

// --- UserSecretStore dispatch ----------------------------------------------

func TestDispatchUserSecretLoadLatest_FoundAndNotFound(t *testing.T) {
	s := &storeSet{userSecret: &mockUserSecretStore{
		loadLatestFn: func(secretID uint64) (UserSecrets, bool, error) {
			return UserSecrets{Version: 2, Secrets: []UserSecret{{ID: []byte{1}, Name: "n", Data: []byte{2}}}}, true, nil
		},
	}}
	status, out := dispatchUserSecretLoadLatest(s, 1)
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	got, err := DecodeUserSecrets(out)
	if err != nil || got.Version != 2 || len(got.Secrets) != 1 {
		t.Fatalf("DecodeUserSecrets: got=%+v err=%v", got, err)
	}

	s2 := &storeSet{userSecret: &mockUserSecretStore{
		loadLatestFn: func(secretID uint64) (UserSecrets, bool, error) {
			return UserSecrets{}, false, nil
		},
	}}
	status, out = dispatchUserSecretLoadLatest(s2, 1)
	if status != ffiStatusNotFound || out != nil {
		t.Fatalf("status=%d out=%v, want not-found/nil", status, out)
	}
}

func TestDispatchUserSecretSaveLatest_PanicRecovered(t *testing.T) {
	s := &storeSet{userSecret: &mockUserSecretStore{
		saveLatestFn: func(secretID uint64, value UserSecrets) error {
			panic("user secret store exploded")
		},
	}}
	payload, err := EncodeUserSecrets(UserSecrets{Version: 1})
	if err != nil {
		t.Fatalf("EncodeUserSecrets: %v", err)
	}
	status := dispatchUserSecretSaveLatest(s, 1, payload)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure after recovered panic", status)
	}
}

func TestDispatchUserSecretRemove(t *testing.T) {
	called := false
	s := &storeSet{userSecret: &mockUserSecretStore{
		removeFn: func(secretID uint64) error {
			called = true
			return nil
		},
	}}
	status := dispatchUserSecretRemove(s, 1)
	if status != ffiStatusOK || !called {
		t.Fatalf("status=%d called=%v", status, called)
	}
}

// --- StateStore dispatch ----------------------------------------------------

func TestDispatchStateSaveLoadRoundTrip(t *testing.T) {
	var stored StateItem
	cid := uint64(5)
	s := &storeSet{state: &mockStateStore{
		saveFn: func(secretID uint64, item StateItem) error {
			stored = item
			return nil
		},
		loadFn: func(secretID uint64, key StateKey) (StateItem, bool, error) {
			if key.Kind != StateKindPendingVerification {
				t.Fatalf("unexpected key: %+v", key)
			}
			return stored, true, nil
		},
	}}
	item := StateItem{Kind: StateKindPendingVerification, ChannelID: &cid, Bytes: []byte{1, 2, 3}}
	itemJSON, err := EncodeStateItem(item)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	if status := dispatchStateSave(s, 1, itemJSON); status != ffiStatusOK {
		t.Fatalf("save status = %d", status)
	}

	keyJSON, err := EncodeStateKey(item.Key())
	if err != nil {
		t.Fatalf("EncodeStateKey: %v", err)
	}
	status, out := dispatchStateLoad(s, 1, keyJSON)
	if status != ffiStatusOK {
		t.Fatalf("load status = %d, want ffiStatusOK", status)
	}
	got, err := DecodeStateItem(out)
	if err != nil || got.Kind != StateKindPendingVerification || *got.ChannelID != cid {
		t.Fatalf("DecodeStateItem: got=%+v err=%v", got, err)
	}
}

func TestDispatchStateLoad_NotFound(t *testing.T) {
	s := &storeSet{state: &mockStateStore{
		loadFn: func(secretID uint64, key StateKey) (StateItem, bool, error) {
			return StateItem{}, false, nil
		},
	}}
	keyJSON, _ := EncodeStateKey(StateKey{Kind: StateKindSharingRound})
	status, out := dispatchStateLoad(s, 1, keyJSON)
	if status != ffiStatusNotFound || out != nil {
		t.Fatalf("status=%d out=%v, want not-found/nil", status, out)
	}
}

func TestDispatchStateLoad_PanicRecovered(t *testing.T) {
	s := &storeSet{state: &mockStateStore{
		loadFn: func(secretID uint64, key StateKey) (StateItem, bool, error) {
			panic("state store blew up")
		},
	}}
	keyJSON, _ := EncodeStateKey(StateKey{Kind: StateKindSharingRound})
	status, out := dispatchStateLoad(s, 1, keyJSON)
	if status != ffiStatusFailure || out != nil {
		t.Fatalf("status=%d out=%v, want failure/nil after recovered panic", status, out)
	}
}

func TestDispatchStateRemove(t *testing.T) {
	s := &storeSet{state: &mockStateStore{
		removeFn: func(secretID uint64, key StateKey) (bool, error) {
			return true, nil
		},
	}}
	keyJSON, _ := EncodeStateKey(StateKey{Kind: StateKindSharingRound})
	status, removed := dispatchStateRemove(s, 1, keyJSON)
	if status != ffiStatusOK || !removed {
		t.Fatalf("status=%d removed=%v", status, removed)
	}
}

func TestDispatchStateLoadAll(t *testing.T) {
	s := &storeSet{state: &mockStateStore{
		loadAllFn: func(secretID uint64, kind StateKind) ([]StateItem, error) {
			if kind != StateKindPendingUnpair {
				t.Fatalf("unexpected kind: %d", kind)
			}
			cid := uint64(9)
			sa := uint64(1234)
			return []StateItem{{Kind: StateKindPendingUnpair, ChannelID: &cid, StartedAt: &sa}}, nil
		},
	}}
	status, out := dispatchStateLoadAll(s, 1, uint32(StateKindPendingUnpair))
	if status != ffiStatusOK {
		t.Fatalf("status = %d, want ffiStatusOK", status)
	}
	var raw []struct {
		Kind uint32 `json:"kind"`
	}
	if err := json.Unmarshal(out, &raw); err != nil || len(raw) != 1 {
		t.Fatalf("decode list: raw=%v err=%v", raw, err)
	}
}

// --- Transport dispatch -----------------------------------------------------

func TestDispatchTransportSend(t *testing.T) {
	var gotURI string
	var gotProtocol int32
	var gotMessage []byte
	s := &storeSet{transport: &mockTransportSender{
		sendFn: func(endpoints []Endpoint, message []byte) error {
			gotURI = endpoints[0].URI
			gotProtocol = endpoints[0].Protocol
			gotMessage = message
			return nil
		},
	}}
	status := dispatchTransportSend(s, []Endpoint{{URI: "https://example.com", Protocol: 0}}, []byte("hello"))
	if status != ffiStatusOK || gotURI != "https://example.com" || gotProtocol != 0 || string(gotMessage) != "hello" {
		t.Fatalf("status=%d uri=%q protocol=%d message=%q", status, gotURI, gotProtocol, gotMessage)
	}
}

func TestDispatchTransportSend_PanicRecovered(t *testing.T) {
	s := &storeSet{transport: &mockTransportSender{
		sendFn: func(endpoints []Endpoint, message []byte) error {
			panic("transport blew up")
		},
	}}
	status := dispatchTransportSend(s, []Endpoint{{URI: "https://example.com", Protocol: 0}}, nil)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure after recovered panic", status)
	}
}

func TestDispatchTransportSend_Error(t *testing.T) {
	s := &storeSet{transport: &mockTransportSender{
		sendFn: func(endpoints []Endpoint, message []byte) error {
			return errors.New("simulated transport failure")
		},
	}}
	status := dispatchTransportSend(s, []Endpoint{{URI: "https://example.com", Protocol: 0}}, nil)
	if status != ffiStatusFailure {
		t.Fatalf("status = %d, want ffiStatusFailure", status)
	}
}
