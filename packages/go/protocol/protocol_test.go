// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// The in-memory store doubles below are real map-backed storage behind a
// mutex (a protocol instance's callbacks may be invoked from whatever
// goroutine the caller drives process()/accept()/start() from), one type
// per store interface in package protocol.

// Two maps, mirroring the two primary keys the interface defines: a helper
// channel is unique per channelID, while a replica-group member is unique per
// replicaID and moves between channels during an admission handover.
type inMemoryChannelStore struct {
	mu      sync.Mutex
	helpers map[[2]uint64]HelperChannel
	members map[[2]uint64]ReplicaMember
	links   map[[2]uint64]map[uint64]struct{}
}

func newInMemoryChannelStore() *inMemoryChannelStore {
	return &inMemoryChannelStore{
		helpers: make(map[[2]uint64]HelperChannel),
		members: make(map[[2]uint64]ReplicaMember),
		links:   make(map[[2]uint64]map[uint64]struct{}),
	}
}

func (s *inMemoryChannelStore) Load(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if replicaID == 0 {
		h, ok := s.helpers[[2]uint64{secretID, channelID}]
		if !ok {
			return ChannelRecord{}, false, nil
		}
		return ChannelRecord{Helper: &h}, true, nil
	}
	m, ok := s.members[[2]uint64{secretID, replicaID}]
	if !ok {
		return ChannelRecord{}, false, nil
	}
	return ChannelRecord{Replica: &m}, true, nil
}

func (s *inMemoryChannelStore) Save(secretID uint64, record ChannelRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if record.Helper != nil {
		s.helpers[[2]uint64{secretID, record.Helper.ChannelID}] = *record.Helper
	}
	if record.Replica != nil {
		s.members[[2]uint64{secretID, record.Replica.ReplicaID}] = *record.Replica
	}
	return nil
}

func (s *inMemoryChannelStore) Remove(secretID, channelID, replicaID uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if replicaID == 0 {
		key := [2]uint64{secretID, channelID}
		_, existed := s.helpers[key]
		delete(s.helpers, key)
		return existed, nil
	}
	key := [2]uint64{secretID, replicaID}
	_, existed := s.members[key]
	delete(s.members, key)
	return existed, nil
}

func (s *inMemoryChannelStore) ListHelpers(secretID uint64, filter HelperFilter) ([]HelperChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []HelperChannel
	for key, h := range s.helpers {
		if key[0] == secretID && filter.Matches(h.ChannelID, h.Status, h.PeerRole) {
			out = append(out, h)
		}
	}
	return out, nil
}

func (s *inMemoryChannelStore) ListReplicas(secretID uint64, filter ReplicaFilter) ([]ReplicaMember, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ReplicaMember
	for key, m := range s.members {
		if key[0] == secretID && filter.Matches(m.ReplicaID, m.Status, m.Role) {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *inMemoryChannelStore) LinkChannel(secretID, a, b uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a == b {
		return nil
	}
	keyA, keyB := [2]uint64{secretID, a}, [2]uint64{secretID, b}
	if s.links[keyA] == nil {
		s.links[keyA] = make(map[uint64]struct{})
	}
	if s.links[keyB] == nil {
		s.links[keyB] = make(map[uint64]struct{})
	}
	s.links[keyA][b] = struct{}{}
	s.links[keyB][a] = struct{}{}
	return nil
}

func (s *inMemoryChannelStore) LinkedChannels(secretID, channelID uint64) ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	visited := map[uint64]struct{}{channelID: {}}
	queue := []uint64{channelID}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for n := range s.links[[2]uint64{secretID, cur}] {
			if _, ok := visited[n]; !ok {
				visited[n] = struct{}{}
				queue = append(queue, n)
			}
		}
	}
	out := make([]uint64, 0, len(visited))
	for id := range visited {
		out = append(out, id)
	}
	return out, nil
}

var _ ChannelStore = (*inMemoryChannelStore)(nil)

type secretStoreKey struct {
	secretID  uint64
	channelID uint64
	kind      SecretKind
}

type inMemorySecretStore struct {
	mu   sync.Mutex
	data map[secretStoreKey]SecretValue
}

func newInMemorySecretStore() *inMemorySecretStore {
	return &inMemorySecretStore{data: make(map[secretStoreKey]SecretValue)}
}

func (s *inMemorySecretStore) Load(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[secretStoreKey{secretID, channelID, kind}]
	return v, ok, nil
}

func (s *inMemorySecretStore) Save(secretID, channelID uint64, value SecretValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[secretStoreKey{secretID, channelID, value.Kind}] = value
	return nil
}

func (s *inMemorySecretStore) Remove(secretID, channelID uint64, kind SecretKind) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, secretStoreKey{secretID, channelID, kind})
	return nil
}

var _ SecretStore = (*inMemorySecretStore)(nil)

type shareStoreKey struct {
	channelID uint64
	secretID  uint64
	version   uint32
}

type inMemoryShareStore struct {
	mu   sync.Mutex
	data map[shareStoreKey]Share
}

func newInMemoryShareStore() *inMemoryShareStore {
	return &inMemoryShareStore{data: make(map[shareStoreKey]Share)}
}

func (s *inMemoryShareStore) matches(secretID uint64, channelIDs map[uint64]struct{}, versions map[uint32]struct{}) []Share {
	var out []Share
	for k, share := range s.data {
		if k.secretID != secretID {
			continue
		}
		if channelIDs != nil {
			if _, ok := channelIDs[k.channelID]; !ok {
				continue
			}
		}
		if versions != nil {
			if _, ok := versions[k.version]; !ok {
				continue
			}
		}
		out = append(out, share)
	}
	return out
}

func toSet[T comparable](vals []T) map[T]struct{} {
	if len(vals) == 0 {
		return nil
	}
	set := make(map[T]struct{}, len(vals))
	for _, v := range vals {
		set[v] = struct{}{}
	}
	return set
}

func (s *inMemoryShareStore) Load(secretID, channelID uint64, versions []uint32) ([]Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, map[uint64]struct{}{channelID: {}}, toSet(versions)), nil
}

func (s *inMemoryShareStore) LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, toSet(channelIDs), toSet(versions)), nil
}

func (s *inMemoryShareStore) LoadAll(secretID uint64, channelIDs []uint64) ([]Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, toSet(channelIDs), nil), nil
}

func (s *inMemoryShareStore) LatestVersion(secretID uint64) (uint32, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max uint32
	found := false
	for k := range s.data {
		if k.secretID != secretID {
			continue
		}
		if !found || k.version > max {
			max = k.version
			found = true
		}
	}
	return max, found, nil
}

func (s *inMemoryShareStore) Save(secretID uint64, channelID uint64, share Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[shareStoreKey{channelID, share.SecretID, share.Version}] = share
	return nil
}

func (s *inMemoryShareStore) RemoveChannel(secretID, channelID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.data {
		if k.channelID == channelID && k.secretID == secretID {
			delete(s.data, k)
		}
	}
	return nil
}

var _ ShareStore = (*inMemoryShareStore)(nil)

type inMemoryUserSecretStore struct {
	mu   sync.Mutex
	data map[uint64]UserSecrets
}

func newInMemoryUserSecretStore() *inMemoryUserSecretStore {
	return &inMemoryUserSecretStore{data: make(map[uint64]UserSecrets)}
}

func (s *inMemoryUserSecretStore) LoadLatest(secretID uint64) (UserSecrets, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[secretID]
	return v, ok, nil
}

func (s *inMemoryUserSecretStore) SaveLatest(secretID uint64, value UserSecrets) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[secretID] = value
	return nil
}

func (s *inMemoryUserSecretStore) Remove(secretID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, secretID)
	return nil
}

var _ UserSecretStore = (*inMemoryUserSecretStore)(nil)

type inMemoryStateStore struct {
	mu   sync.Mutex
	data map[uint64]map[string]StateItem
}

// stateKeyID renders a StateKey as a comparable value.
//
// StateKey cannot be used as a map key directly: its ChannelID/SecretID/
// Version fields are pointers, and Go compares pointer fields by address.
// A key rebuilt for Load would never match the one Save derived from
// item.Key(), so every lookup would miss.
func stateKeyID(k StateKey) string {
	optU64 := func(v *uint64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatUint(*v, 10)
	}
	optU32 := func(v *uint32) string {
		if v == nil {
			return ""
		}
		return strconv.FormatUint(uint64(*v), 10)
	}
	return strings.Join([]string{
		strconv.FormatUint(uint64(k.Kind), 10),
		optU64(k.ChannelID),
		optU64(k.SecretID),
		optU32(k.Version),
	}, ":")
}

func newInMemoryStateStore() *inMemoryStateStore {
	return &inMemoryStateStore{data: make(map[uint64]map[string]StateItem)}
}

func (s *inMemoryStateStore) Save(secretID uint64, item StateItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[secretID] == nil {
		s.data[secretID] = make(map[string]StateItem)
	}
	s.data[secretID][stateKeyID(item.Key())] = item
	return nil
}

func (s *inMemoryStateStore) Load(secretID uint64, key StateKey) (StateItem, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.data[secretID][stateKeyID(key)]
	return item, ok, nil
}

func (s *inMemoryStateStore) Remove(secretID uint64, key StateKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := stateKeyID(key)
	_, existed := s.data[secretID][id]
	delete(s.data[secretID], id)
	return existed, nil
}

func (s *inMemoryStateStore) LoadAll(secretID uint64, kind StateKind) ([]StateItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StateItem
	for _, item := range s.data[secretID] {
		if item.Kind == kind {
			out = append(out, item)
		}
	}
	return out, nil
}

// A key rebuilt from equal values must find the row Save stored, or the
// store silently loses every row it is given.
func TestInMemoryStateStore_LoadsRowSavedUnderAnEquivalentKey(t *testing.T) {
	s := newInMemoryStateStore()
	sid, ver := uint64(0xA0), uint32(3)
	if err := s.Save(1, StateItem{
		Kind:     StateKindPendingRecovery,
		SecretID: &sid,
		Version:  &ver,
		Shares:   [][]byte{{1}},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Same values, freshly allocated — as the library rebuilds them.
	sid2, ver2 := uint64(0xA0), uint32(3)
	got, ok, err := s.Load(1, StateKey{
		Kind:     StateKindPendingRecovery,
		SecretID: &sid2,
		Version:  &ver2,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !ok {
		t.Fatal("row not found: the map key compared pointers, not values")
	}
	if len(got.Shares) != 1 {
		t.Fatalf("wrong row loaded: %+v", got)
	}
}

// Recoveries of two different secrets at the same version must occupy
// separate rows.
func TestInMemoryStateStore_SeparatesConcurrentRecoveryTargets(t *testing.T) {
	s := newInMemoryStateStore()
	ver := uint32(1)
	sidA, sidB := uint64(0xA0), uint64(0xB0)
	for sid, shares := range map[*uint64][][]byte{
		&sidA: {{1}},
		&sidB: {{2}, {3}},
	} {
		if err := s.Save(1, StateItem{
			Kind: StateKindPendingRecovery, SecretID: sid, Version: &ver, Shares: shares,
		}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	got, ok, err := s.Load(1, StateKey{
		Kind: StateKindPendingRecovery, SecretID: &sidA, Version: &ver,
	})
	if err != nil || !ok {
		t.Fatalf("Load(A): ok=%v err=%v", ok, err)
	}
	if len(got.Shares) != 1 {
		t.Fatalf("vault A row was clobbered by vault B: %+v", got)
	}
}

var _ StateStore = (*inMemoryStateStore)(nil)

// inMemoryTransport buffers outbound (uri, protocol, message) tuples
// instead of performing network I/O — this task exercises construction
// and teardown only, so nothing ever drains the buffer.
type inMemoryTransport struct {
	mu   sync.Mutex
	sent []sentMessage
}

type sentMessage struct {
	uri      string
	protocol int32
	message  []byte
}

func newInMemoryTransport() *inMemoryTransport {
	return &inMemoryTransport{}
}

func (t *inMemoryTransport) Send(endpoints []Endpoint, message []byte) error {
	uri := endpoints[0].URI
	protocol := endpoints[0].Protocol
	_ = protocol
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sent = append(t.sent, sentMessage{uri, protocol, append([]byte(nil), message...)})
	return nil
}

var _ Transport = (*inMemoryTransport)(nil)

// newTestStores builds one full set of in-memory store doubles.
func newTestStores() (ChannelStore, ShareStore, SecretStore, UserSecretStore, StateStore, Transport) {
	return newInMemoryChannelStore(),
		newInMemoryShareStore(),
		newInMemorySecretStore(),
		newInMemoryUserSecretStore(),
		newInMemoryStateStore(),
		newInMemoryTransport()
}

// TestNew_ConstructsRealProtocolHandleAndCloses is the end-to-end
// validation of M3 Tasks 2-4: New assembles the six store/transport
// implementations into their C callback tables and drives a genuine
// derec_protocol_new round trip through the compiled derec-library
// dylib. A non-nil *DeRecProtocol with no error means the FFI accepted the
// JSON config and every callback pointer, and stored them into a
// live Rust-side protocol handle.
func TestNew_ConstructsRealProtocolHandleAndCloses(t *testing.T) {
	channel, share, secret, userSecret, state, transport := newTestStores()

	cfg := Config{
		SecretID:             1,
		OwnTransportURI:      "https://owner.example.com",
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            2,
		KeepVersionsCount:    3,
	}

	p, err := New(channel, share, secret, userSecret, state, transport, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p == nil {
		t.Fatal("expected a non-nil DeRecProtocol")
	}

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close must be idempotent.
	if err := p.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestNew_TwoInstancesBothConstructAndClose builds two independent
// protocol instances back to back, proving the Task 4 shared-callback fix
// (purego.NewCallback registered once, reused across instances) holds
// under a real derec_protocol_new construction, not just the
// unit-level buildCallbacks tests in internal/native.
func TestNew_TwoInstancesBothConstructAndClose(t *testing.T) {
	channel1, share1, secret1, userSecret1, state1, transport1 := newTestStores()
	channel2, share2, secret2, userSecret2, state2, transport2 := newTestStores()

	cfg1 := Config{
		SecretID:             1,
		OwnTransportURI:      "https://owner-a.example.com",
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            2,
		KeepVersionsCount:    3,
	}
	cfg2 := Config{
		SecretID:             2,
		OwnTransportURI:      "https://owner-b.example.com",
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            2,
		KeepVersionsCount:    3,
	}

	p1, err := New(channel1, share1, secret1, userSecret1, state1, transport1, cfg1)
	if err != nil {
		t.Fatalf("New (instance 1): %v", err)
	}
	defer p1.Close()

	p2, err := New(channel2, share2, secret2, userSecret2, state2, transport2, cfg2)
	if err != nil {
		t.Fatalf("New (instance 2): %v", err)
	}
	defer p2.Close()

	if err := p1.Close(); err != nil {
		t.Fatalf("Close (instance 1): %v", err)
	}
	if err := p2.Close(); err != nil {
		t.Fatalf("Close (instance 2): %v", err)
	}
}

func TestNew_RequiresEveryStoreAndTransport(t *testing.T) {
	channel, share, secret, userSecret, state, transport := newTestStores()
	cfg := Config{SecretID: 1, OwnTransportURI: "https://owner.example.com"}

	cases := []struct {
		name string
		call func() (*DeRecProtocol, error)
	}{
		{"nil channelStore", func() (*DeRecProtocol, error) {
			return New(nil, share, secret, userSecret, state, transport, cfg)
		}},
		{"nil shareStore", func() (*DeRecProtocol, error) {
			return New(channel, nil, secret, userSecret, state, transport, cfg)
		}},
		{"nil secretStore", func() (*DeRecProtocol, error) {
			return New(channel, share, nil, userSecret, state, transport, cfg)
		}},
		{"nil userSecretStore", func() (*DeRecProtocol, error) {
			return New(channel, share, secret, nil, state, transport, cfg)
		}},
		{"nil stateStore", func() (*DeRecProtocol, error) {
			return New(channel, share, secret, userSecret, nil, transport, cfg)
		}},
		{"nil transport", func() (*DeRecProtocol, error) {
			return New(channel, share, secret, userSecret, state, nil, cfg)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// newTestProtocol builds a real protocol instance backed by in-memory store
// doubles, for exercising the M3 Task 6 handle-method bindings
// (GetFingerprint, VerifyFingerprint, SetOwnTransport,
// SetCommunicationInfo).
func newTestProtocol(t *testing.T) *DeRecProtocol {
	t.Helper()
	channel, share, secret, userSecret, state, transport := newTestStores()
	cfg := Config{
		SecretID:             1,
		OwnTransportURI:      "https://owner.example.com",
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            2,
		KeepVersionsCount:    3,
	}
	p, err := New(channel, share, secret, userSecret, state, transport, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// TestSetOwnTransport_ValidHTTPSURI covers the happy path: a well-formed
// https URI is accepted and stored without contacting any peer.
func TestSetOwnTransport_ValidHTTPSURI(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.SetOwnTransport("https://owner-new.example.com", int32(derecpb.Protocol_HTTPS)); err != nil {
		t.Fatalf("SetOwnTransport: %v", err)
	}
}

// TestSetOwnTransport_ClosedProtocol asserts the closed-instance guard
// rejects the call instead of touching a freed handle.
func TestSetOwnTransport_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.SetOwnTransport("https://owner-new.example.com", int32(derecpb.Protocol_HTTPS)); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestSetCommunicationInfo_ValidMap covers the happy path: a non-empty
// string map is JSON-encoded and accepted.
func TestSetCommunicationInfo_ValidMap(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.SetCommunicationInfo(map[string]string{"name": "Owner"}); err != nil {
		t.Fatalf("SetCommunicationInfo: %v", err)
	}
}

// TestSetCommunicationInfo_EmptyMap covers the "no entries" convention:
// a nil/empty map must round-trip without the FFI's JSON parser ever
// seeing a `null` body (info_json_len == 0 short-circuits parsing on the
// Rust side).
func TestSetCommunicationInfo_EmptyMap(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.SetCommunicationInfo(nil); err != nil {
		t.Fatalf("SetCommunicationInfo(nil): %v", err)
	}
	if err := p.SetCommunicationInfo(map[string]string{}); err != nil {
		t.Fatalf("SetCommunicationInfo(empty map): %v", err)
	}
}

// TestGetFingerprint_UnpairedChannel asserts the clean error path: a
// channel with no shared key (never paired) fails with a structured
// *derec.Error rather than crashing. The full get→verify round trip
// needs a genuinely paired channel, which this unit test cannot set up
// without driving the pairing flow end to end — that's covered by the
// Task 9 smoke test.
func TestGetFingerprint_UnpairedChannel(t *testing.T) {
	p := newTestProtocol(t)
	_, err := p.GetFingerprint(42)
	if err == nil {
		t.Fatal("expected an error for an unpaired channel")
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestVerifyFingerprint_UnpairedChannel mirrors
// TestGetFingerprint_UnpairedChannel: verifying against a channel with no
// shared key must fail closed (matched == false, non-nil error) instead
// of crashing.
func TestVerifyFingerprint_UnpairedChannel(t *testing.T) {
	p := newTestProtocol(t)
	matched, err := p.VerifyFingerprint(42, "not-a-real-fingerprint")
	if err == nil {
		t.Fatal("expected an error for an unpaired channel")
	}
	if matched {
		t.Fatal("expected matched == false on error (fail-closed)")
	}
}

// TestGetFingerprint_ClosedProtocol and TestVerifyFingerprint_ClosedProtocol
// assert the closed-instance guard rejects calls instead of touching a
// freed handle.
func TestGetFingerprint_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.GetFingerprint(42); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

func TestVerifyFingerprint_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.VerifyFingerprint(42, "fp"); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestSetCommunicationInfo_ClosedProtocol asserts the closed-instance
// guard rejects the call instead of touching a freed handle.
func TestSetCommunicationInfo_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.SetCommunicationInfo(map[string]string{"name": "Owner"}); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}
