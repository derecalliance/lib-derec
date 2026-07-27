// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Protocol-level smoke test: real *protocol.DeRecProtocol instances (Owner
// plus two Helpers), each backed by in-memory implementations of the six
// store/transport interfaces, driven through a genuine pairing ->
// protect-secret -> ShareStored flow over an in-process transport. Mirrors
// bindings/rust/src/protocol.rs and packages/go/protocol/orchestrator_test.go,
// but as an external consumer: only the public
// github.com/derecalliance/lib-derec/packages/go/protocol package is
// imported, never packages/go/internal/....
package main

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/protocol"
)

// protocolSecretID is the shared secret identity both peers configure —
// agreed out of band before pairing, mirroring
// bindings/rust/src/protocol.rs's DEFAULT_TEST_SECRET_ID.
const protocolSecretID = uint64(0xDE2EC)

// -- In-memory store implementations, one per protocol.*Store interface --

type memChannelStore struct {
	mu    sync.Mutex
	data  map[[2]uint64]protocol.Channel
	links map[[2]uint64]map[uint64]struct{}
}

func newMemChannelStore() *memChannelStore {
	return &memChannelStore{
		data:  make(map[[2]uint64]protocol.Channel),
		links: make(map[[2]uint64]map[uint64]struct{}),
	}
}

func (s *memChannelStore) Load(secretID, channelID uint64) (protocol.Channel, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.data[[2]uint64{secretID, channelID}]
	return c, ok, nil
}

func (s *memChannelStore) Save(secretID uint64, channel protocol.Channel) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[[2]uint64{secretID, channel.ID}] = channel
	return nil
}

func (s *memChannelStore) Remove(secretID, channelID uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := [2]uint64{secretID, channelID}
	_, existed := s.data[key]
	delete(s.data, key)
	return existed, nil
}

func (s *memChannelStore) ListChannels(secretID uint64) ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []uint64
	for key := range s.data {
		if key[0] == secretID {
			out = append(out, key[1])
		}
	}
	return out, nil
}

func (s *memChannelStore) LinkChannel(secretID, a, b uint64) error {
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

func (s *memChannelStore) LinkedChannels(secretID, channelID uint64) ([]uint64, error) {
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

var _ protocol.ChannelStore = (*memChannelStore)(nil)

type secretStoreKey struct {
	secretID  uint64
	channelID uint64
	kind      protocol.SecretKind
}

type memSecretStore struct {
	mu   sync.Mutex
	data map[secretStoreKey]protocol.SecretValue
}

func newMemSecretStore() *memSecretStore {
	return &memSecretStore{data: make(map[secretStoreKey]protocol.SecretValue)}
}

func (s *memSecretStore) Load(secretID, channelID uint64, kind protocol.SecretKind) (protocol.SecretValue, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[secretStoreKey{secretID, channelID, kind}]
	return v, ok, nil
}

func (s *memSecretStore) Save(secretID, channelID uint64, value protocol.SecretValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[secretStoreKey{secretID, channelID, value.Kind}] = value
	return nil
}

func (s *memSecretStore) Remove(secretID, channelID uint64, kind protocol.SecretKind) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, secretStoreKey{secretID, channelID, kind})
	return nil
}

var _ protocol.SecretStore = (*memSecretStore)(nil)

type shareStoreKey struct {
	channelID uint64
	secretID  uint64
	version   uint32
}

type memShareStore struct {
	mu   sync.Mutex
	data map[shareStoreKey]protocol.Share
}

func newMemShareStore() *memShareStore {
	return &memShareStore{data: make(map[shareStoreKey]protocol.Share)}
}

func (s *memShareStore) matches(secretID uint64, channelIDs map[uint64]struct{}, versions map[uint32]struct{}) []protocol.Share {
	var out []protocol.Share
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

func (s *memShareStore) Load(secretID, channelID uint64, versions []uint32) ([]protocol.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, map[uint64]struct{}{channelID: {}}, toSet(versions)), nil
}

func (s *memShareStore) LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]protocol.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, toSet(channelIDs), toSet(versions)), nil
}

func (s *memShareStore) LoadAll(secretID uint64, channelIDs []uint64) ([]protocol.Share, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matches(secretID, toSet(channelIDs), nil), nil
}

func (s *memShareStore) LatestVersion(secretID uint64) (uint32, bool, error) {
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

func (s *memShareStore) Save(secretID, channelID uint64, share protocol.Share) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[shareStoreKey{channelID, share.SecretID, share.Version}] = share
	return nil
}

func (s *memShareStore) RemoveChannel(secretID, channelID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.data {
		if k.channelID == channelID && k.secretID == secretID {
			delete(s.data, k)
		}
	}
	return nil
}

var _ protocol.ShareStore = (*memShareStore)(nil)

type memUserSecretStore struct {
	mu   sync.Mutex
	data map[uint64]protocol.UserSecrets
}

func newMemUserSecretStore() *memUserSecretStore {
	return &memUserSecretStore{data: make(map[uint64]protocol.UserSecrets)}
}

func (s *memUserSecretStore) LoadLatest(secretID uint64) (protocol.UserSecrets, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[secretID]
	return v, ok, nil
}

func (s *memUserSecretStore) SaveLatest(secretID uint64, value protocol.UserSecrets) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[secretID] = value
	return nil
}

func (s *memUserSecretStore) Remove(secretID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, secretID)
	return nil
}

var _ protocol.UserSecretStore = (*memUserSecretStore)(nil)

type memStateStore struct {
	mu   sync.Mutex
	data map[uint64]map[protocol.StateKey]protocol.StateItem
}

func newMemStateStore() *memStateStore {
	return &memStateStore{data: make(map[uint64]map[protocol.StateKey]protocol.StateItem)}
}

func (s *memStateStore) Save(secretID uint64, item protocol.StateItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[secretID] == nil {
		s.data[secretID] = make(map[protocol.StateKey]protocol.StateItem)
	}
	s.data[secretID][item.Key()] = item
	return nil
}

func (s *memStateStore) Load(secretID uint64, key protocol.StateKey) (protocol.StateItem, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.data[secretID][key]
	return item, ok, nil
}

func (s *memStateStore) Remove(secretID uint64, key protocol.StateKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, existed := s.data[secretID][key]
	delete(s.data[secretID], key)
	return existed, nil
}

func (s *memStateStore) LoadAll(secretID uint64, kind protocol.StateKind) ([]protocol.StateItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.StateItem
	for key, item := range s.data[secretID] {
		if key.Kind == kind {
			out = append(out, item)
		}
	}
	return out, nil
}

var _ protocol.StateStore = (*memStateStore)(nil)

// outboxEntry is one buffered outbound message: destination URI plus the
// wire-encoded envelope bytes.
type outboxEntry struct {
	uri     string
	message []byte
}

// memTransport buffers outbound (uri, message) pairs instead of performing
// network I/O: Send appends to the outbox, drain retrieves and clears it.
type memTransport struct {
	mu     sync.Mutex
	outbox []outboxEntry
}

func newMemTransport() *memTransport {
	return &memTransport{}
}

func (t *memTransport) Send(uri string, _ int32, message []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outbox = append(t.outbox, outboxEntry{uri: uri, message: append([]byte(nil), message...)})
	return nil
}

func (t *memTransport) drain() []outboxEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.outbox
	t.outbox = nil
	return out
}

var _ protocol.Transport = (*memTransport)(nil)

// peer bundles a protocol instance with the metadata needed to route
// messages to it (its own advertised transport URI) and the concrete store
// doubles backing it, so the smoke test can assert directly on what a store
// actually persisted.
type peer struct {
	label        string
	uri          string
	proto        *protocol.DeRecProtocol
	transport    *memTransport
	shareStore   *memShareStore
	channelStore *memChannelStore
}

func newPeer(label, uri string, threshold uint32) *peer {
	channelStore := newMemChannelStore()
	shareStore := newMemShareStore()
	secretStore := newMemSecretStore()
	userSecretStore := newMemUserSecretStore()
	stateStore := newMemStateStore()
	transport := newMemTransport()

	cfg := protocol.Config{
		SecretID:             protocolSecretID,
		OwnTransportURI:      uri,
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            threshold,
		KeepVersionsCount:    3,
	}
	p, err := protocol.New(channelStore, shareStore, secretStore, userSecretStore, stateStore, transport, cfg)
	must(err, fmt.Sprintf("protocol.New(%s)", label))

	return &peer{
		label:        label,
		uri:          uri,
		proto:        p,
		transport:    transport,
		shareStore:   shareStore,
		channelStore: channelStore,
	}
}

func (p *peer) drain() []outboxEntry {
	return p.transport.drain()
}

// deliver feeds bytes to peer.proto.Process, then satisfies every emitted
// ActionRequired via peer.proto.Accept — mirroring the `deliver` helper in
// bindings/rust/src/protocol.rs. Returns every event produced by Process
// and the follow-up Accept calls.
func deliver(p *peer, bytes []byte) []protocol.Event {
	collected, err := p.proto.Process(bytes)
	must(err, fmt.Sprintf("[%s] Process()", p.label))

	for i := 0; i < len(collected); i++ {
		if collected[i].Type != protocol.EventTypeActionRequired {
			continue
		}
		acceptEvents, err := p.proto.Accept(collected[i].Action)
		must(err, fmt.Sprintf("[%s] Accept()", p.label))
		collected = append(collected, acceptEvents...)
	}
	return collected
}

// pump drains `from`'s outbox and delivers each message to whichever peer's
// own URI matches the destination, recursively transporting any replies
// until the network is quiescent — mirroring `pump` in
// bindings/rust/src/protocol.rs.
func pump(from, to *peer) []protocol.Event {
	var allEvents []protocol.Event
	pending := from.drain()

	for len(pending) > 0 {
		entry := pending[0]
		pending = pending[1:]

		var target *peer
		switch entry.uri {
		case to.uri:
			target = to
		case from.uri:
			target = from
		default:
			fail("no peer for destination uri %s (have %s / %s)", entry.uri, from.uri, to.uri)
		}

		events := deliver(target, entry.message)
		pending = append(pending, target.drain()...)
		allEvents = append(allEvents, events...)
	}

	return allEvents
}

// pumpMany is the multi-peer variant of pump, for flows that fan out to
// more than one participant in a single round (e.g. Owner -> several
// Helpers) — mirroring `pump_many` in bindings/rust/src/protocol.rs.
func pumpMany(peers []*peer) []protocol.Event {
	var allEvents []protocol.Event

	type routed struct {
		target *peer
		entry  outboxEntry
	}

	for {
		var work []routed
		for _, src := range peers {
			for _, entry := range src.drain() {
				var target *peer
				for _, p := range peers {
					if p.uri == entry.uri {
						target = p
						break
					}
				}
				if target == nil {
					fail("no peer for destination uri %s", entry.uri)
				}
				work = append(work, routed{target: target, entry: entry})
			}
		}
		if len(work) == 0 {
			break
		}
		for _, w := range work {
			allEvents = append(allEvents, deliver(w.target, w.entry.message)...)
		}
	}

	return allEvents
}

// pairPeers drives a full pairing handshake — Owner creates a contact,
// Helper starts pairing from it, and bytes are pumped both ways until both
// sides report PairingCompleted — mirroring `pair` in
// bindings/rust/src/protocol.rs. Returns the long-term channel_id both
// peers rotated to.
func pairPeers(owner, helper *peer, pairingChannelID uint64) uint64 {
	contact, err := owner.proto.CreateContact(&pairingChannelID, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact")
	assertTrue(contact.ChannelID == pairingChannelID, "CreateContact.ChannelID = %d, want %d", contact.ChannelID, pairingChannelID)

	startEvents, err := helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:                  int32(protocol.SenderKindHelper),
		Contact:               contact.ContactBytes,
		PeerCommunicationInfo: map[string]string{"name": "helper"},
	})
	must(err, "helper.Start(Pairing)")

	var sawPairingStarted bool
	for _, ev := range startEvents {
		assertTrue(ev.Type != protocol.EventTypePairingCompleted, "PairingCompleted must not appear in Start(Pairing) — it fires from Process() after the peer round-trip")
		if ev.Type == protocol.EventTypePairingStarted {
			sawPairingStarted = true
			assertTrue(ev.ChannelID == strconv.FormatUint(pairingChannelID, 10), "PairingStarted.ChannelID = %s, want %d", ev.ChannelID, pairingChannelID)
			assertTrue(ev.Kind == int32(protocol.SenderKindHelper), "PairingStarted.Kind = %d, want %d (Helper)", ev.Kind, protocol.SenderKindHelper)
		}
	}
	assertTrue(sawPairingStarted, "Start(Pairing) must emit PairingStarted")

	helperToOwner := pump(helper, owner)
	ownerToHelper := pump(owner, helper)

	var completions []protocol.Event
	for _, ev := range helperToOwner {
		if ev.Type == protocol.EventTypePairingCompleted {
			completions = append(completions, ev)
		}
	}
	for _, ev := range ownerToHelper {
		if ev.Type == protocol.EventTypePairingCompleted {
			completions = append(completions, ev)
		}
	}
	assertTrue(len(completions) >= 2, "expected PairingCompleted on both sides, got %d", len(completions))

	newChannelID, err := strconv.ParseUint(completions[0].ChannelID, 10, 64)
	must(err, "parse PairingCompleted.ChannelID")

	for _, ev := range completions {
		assertTrue(ev.PairingChannelID == strconv.FormatUint(pairingChannelID, 10), "PairingCompleted.PairingChannelID = %s, want %d (the transient contact channel_id)", ev.PairingChannelID, pairingChannelID)
		cid, err := strconv.ParseUint(ev.ChannelID, 10, 64)
		must(err, "parse PairingCompleted.ChannelID")
		assertTrue(cid == newChannelID, "both peers must rotate to the same long-term channel_id: got %d and %d", cid, newChannelID)
	}

	return newChannelID
}

// runProtocol is the M3-parity payoff flow: real DeRecProtocol instances
// (Owner + two Helpers), each with its own in-memory stores and an
// in-process transport, driven through a genuine pairing ->
// protect-secret -> share-stored flow. Two Helpers, not one: the builder
// rejects Threshold < 2, and the sharing handler only VSS-splits shares to
// Helpers once helpers.len() >= threshold — a single Helper would never
// observe a real ShareStored event.
func runProtocol() {
	fmt.Println("=== Protocol pairing + protect-secret flow test ===")

	const threshold = 2

	owner := newPeer("owner", "https://owner.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b.example.com", threshold)

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)
	assertTrue(channelA != 1 && channelB != 2, "long-term channel_id must differ from the transient pairing id (got channelA=%d, channelB=%d)", channelA, channelB)

	for _, check := range []struct {
		label string
		store *memChannelStore
		cid   uint64
	}{
		{"owner/channelA", owner.channelStore, channelA},
		{"helper-a/channelA", helperA.channelStore, channelA},
		{"owner/channelB", owner.channelStore, channelB},
		{"helper-b/channelB", helperB.channelStore, channelB},
	} {
		_, ok, err := check.store.Load(protocolSecretID, check.cid)
		must(err, fmt.Sprintf("%s channelStore.Load", check.label))
		assertTrue(ok, "%s channelStore must have the paired channel", check.label)
	}

	ownerFP, err := owner.proto.GetFingerprint(channelA)
	must(err, "owner.GetFingerprint(channelA)")
	helperAFP, err := helperA.proto.GetFingerprint(channelA)
	must(err, "helperA.GetFingerprint(channelA)")
	assertTrue(ownerFP == helperAFP, "owner and helper-a fingerprints must match: %q vs %q", ownerFP, helperAFP)

	fmt.Println("  pairing: two channels paired, fingerprints match ✓")

	secretData := []byte("super-secret-value")
	description := "smoke-test distribution"
	protectEvents, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: []byte{1, 2, 3}, Name: "smoke-test secret", Data: secretData}},
		Description: &description,
	})
	must(err, "owner.Start(ProtectSecret)")

	protectStartedVersions := map[string]uint32{}
	for _, ev := range protectEvents {
		assertTrue(ev.Type != protocol.EventTypeProtectSecretFailed, "Start(ProtectSecret) emitted ProtectSecretFailed: %+v", ev)
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			protectStartedVersions[ev.ChannelID] = *ev.Version
		}
	}
	assertTrue(len(protectStartedVersions) == 2, "Start(ProtectSecret) must emit ProtectSecretStarted for both paired channels, got %+v", protectEvents)

	shareEvents := pumpMany([]*peer{owner, helperA, helperB})

	storedFor := map[string]bool{}
	confirmedCount := 0
	for _, ev := range shareEvents {
		switch ev.Type {
		case protocol.EventTypeShareStored:
			storedFor[ev.ChannelID] = true
		case protocol.EventTypeShareConfirmed:
			confirmedCount++
		}
	}
	assertTrue(storedFor[strconv.FormatUint(channelA, 10)], "expected a ShareStored event for channel-a (%d)", channelA)
	assertTrue(storedFor[strconv.FormatUint(channelB, 10)], "expected a ShareStored event for channel-b (%d)", channelB)
	assertTrue(confirmedCount == 2, "expected 2 ShareConfirmed events (one per helper), got %d", confirmedCount)

	for _, check := range []struct {
		label     string
		store     *memShareStore
		channelID uint64
	}{
		{"helper-a", helperA.shareStore, channelA},
		{"helper-b", helperB.shareStore, channelB},
	} {
		storedShares, err := check.store.Load(protocolSecretID, check.channelID, nil)
		must(err, fmt.Sprintf("%s.shareStore.Load", check.label))
		assertTrue(len(storedShares) != 0, "%s shareStore has no shares for channel %d — the Save callback never fired", check.label, check.channelID)
		assertTrue(len(storedShares[0].Bytes) != 0, "%s stored share has empty Bytes", check.label)
		wantVersion, ok := protectStartedVersions[strconv.FormatUint(check.channelID, 10)]
		assertTrue(ok, "%s: no ProtectSecretStarted version recorded for channel %d", check.label, check.channelID)
		assertTrue(storedShares[0].Version == wantVersion, "%s stored share version = %d, want %d (from ProtectSecretStarted)", check.label, storedShares[0].Version, wantVersion)
	}

	fmt.Println("  protect-secret: ShareStored + ShareConfirmed observed on both helpers, store contents verified ✓")

	owner.proto.Close()
	helperA.proto.Close()
	helperB.proto.Close()

	fmt.Println("Protocol pairing + protect-secret flow test passed.")
}
