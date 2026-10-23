// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Protocol-level smoke test: real *protocol.DeRecProtocol instances (Owner
// plus two Helpers), each backed by in-memory implementations of the six
// store/transport interfaces, driven through a genuine pairing ->
// protect-secret -> ShareStored flow over an in-process transport. Mirrors
// smoke-tests/rust/src/protocol.rs and packages/go/protocol/orchestrator_test.go,
// but as an external consumer: only the public
// github.com/derecalliance/lib-derec/packages/go/protocol package is
// imported, never packages/go/internal/....
package main

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/protocol"

	"google.golang.org/protobuf/proto"
)

// protocolSecretID is the shared secret identity both peers configure —
// agreed out of band before pairing, mirroring
// smoke-tests/rust/src/protocol.rs's DEFAULT_TEST_SECRET_ID.
const protocolSecretID = uint64(0xDE2EC)

// -- In-memory store implementations, one per protocol.*Store interface --

// Two maps, mirroring the two primary keys the interface defines: a helper
// channel is unique per channelID, while a replica-group member is unique per
// replicaID and moves between channels during an admission handover.
type memChannelStore struct {
	mu      sync.Mutex
	helpers map[[2]uint64]protocol.HelperChannel
	members map[[2]uint64]protocol.ReplicaMember
	links   map[[2]uint64]map[uint64]struct{}
}

func newMemChannelStore() *memChannelStore {
	return &memChannelStore{
		helpers: make(map[[2]uint64]protocol.HelperChannel),
		members: make(map[[2]uint64]protocol.ReplicaMember),
		links:   make(map[[2]uint64]map[uint64]struct{}),
	}
}

func (s *memChannelStore) Load(secretID, channelID, replicaID uint64) (protocol.ChannelRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if replicaID == 0 {
		h, ok := s.helpers[[2]uint64{secretID, channelID}]
		if !ok {
			return protocol.ChannelRecord{}, false, nil
		}
		return protocol.ChannelRecord{Helper: &h}, true, nil
	}
	m, ok := s.members[[2]uint64{secretID, replicaID}]
	if !ok {
		return protocol.ChannelRecord{}, false, nil
	}
	return protocol.ChannelRecord{Replica: &m}, true, nil
}

func (s *memChannelStore) Save(secretID uint64, record protocol.ChannelRecord) error {
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

func (s *memChannelStore) Remove(secretID, channelID, replicaID uint64) (bool, error) {
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

func (s *memChannelStore) ListHelpers(secretID uint64, filter protocol.HelperFilter) ([]protocol.HelperChannel, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.HelperChannel
	for key, h := range s.helpers {
		if key[0] == secretID && filter.Matches(h.ChannelID, h.Status, h.PeerRole) {
			out = append(out, h)
		}
	}
	return out, nil
}

func (s *memChannelStore) ListReplicas(secretID uint64, filter protocol.ReplicaFilter) ([]protocol.ReplicaMember, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.ReplicaMember
	for key, m := range s.members {
		if key[0] == secretID && filter.Matches(m.ReplicaID, m.Status, m.Role) {
			out = append(out, m)
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
	// loadManyCalls records the channelIDs of every LoadMany call, in order.
	loadManyCalls [][]uint64
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

func (s *memSecretStore) LoadMany(secretID uint64, channelIDs []uint64, kind protocol.SecretKind) ([]*protocol.SecretValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadManyCalls = append(s.loadManyCalls, append([]uint64(nil), channelIDs...))
	out := make([]*protocol.SecretValue, len(channelIDs))
	for i, c := range channelIDs {
		if v, ok := s.data[secretStoreKey{secretID, c, kind}]; ok {
			out[i] = &v
		}
	}
	return out, nil
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

	// refuseSaves / refuseVerifications refuse with RefusalTooFrequent, the
	// way an application's rate limit would.
	refuseSaves         bool
	refuseVerifications bool

	// failSaves fails every save with a plain error, the way an unavailable
	// storage backend would.
	failSaves bool
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
	if s.refuseSaves {
		return &protocol.ShareStoreRefusedError{Refusal: protocol.RefusalTooFrequent}
	}
	if s.failSaves {
		return errors.New("share backend unavailable")
	}
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

func (s *memShareStore) RemoveVersions(secretID, channelID uint64, versions []uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range versions {
		delete(s.data, shareStoreKey{channelID, secretID, v})
	}
	return nil
}

func (s *memShareStore) KeepList(secretID uint64, version uint32) ([]uint32, bool, error) {
	return nil, false, nil
}

func (s *memShareStore) RecordVerification(secretID, channelID uint64, version uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuseVerifications {
		return &protocol.ShareStoreRefusedError{Refusal: protocol.RefusalTooFrequent}
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
	data map[uint64]map[string]protocol.StateItem
}

// stateKeyID renders a StateKey as a comparable value. StateKey cannot key a
// map directly: its ChannelID/SecretID/Version fields are pointers, which Go
// compares by address, so a key rebuilt for Load would never match the one
// Save derived from item.Key().
func stateKeyID(k protocol.StateKey) string {
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

func newMemStateStore() *memStateStore {
	return &memStateStore{data: make(map[uint64]map[string]protocol.StateItem)}
}

func (s *memStateStore) Save(secretID uint64, item protocol.StateItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data[secretID] == nil {
		s.data[secretID] = make(map[string]protocol.StateItem)
	}
	s.data[secretID][stateKeyID(item.Key())] = item
	return nil
}

func (s *memStateStore) Load(secretID uint64, key protocol.StateKey) (protocol.StateItem, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.data[secretID][stateKeyID(key)]
	return item, ok, nil
}

func (s *memStateStore) Remove(secretID uint64, key protocol.StateKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := stateKeyID(key)
	_, existed := s.data[secretID][id]
	delete(s.data[secretID], id)
	return existed, nil
}

func (s *memStateStore) LoadAll(secretID uint64, kind protocol.StateKind) ([]protocol.StateItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []protocol.StateItem
	for _, item := range s.data[secretID] {
		if item.Kind == kind {
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
//
// The library hands over every endpoint the peer advertised, filtered but
// unranked, and delivery to any one of them is success. A real transport
// would try them in order and fall back; buffering the first is enough here.
type memTransport struct {
	mu     sync.Mutex
	outbox []outboxEntry
}

func newMemTransport() *memTransport {
	return &memTransport{}
}

func (t *memTransport) Send(endpoints []protocol.Endpoint, message []byte) error {
	if len(endpoints) == 0 {
		return errors.New("transport: send called with no endpoints")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outbox = append(t.outbox, outboxEntry{uri: endpoints[0].URI, message: append([]byte(nil), message...)})
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
	secretStore  *memSecretStore
	userSecrets  *memUserSecretStore
}

func newPeer(label, uri string, threshold uint32) *peer {
	return newPeerWithReplicaID(label, uri, threshold, nil)
}

func newPeerWithReplicaID(label, uri string, threshold uint32, replicaID *uint64) *peer {
	p, err := newPeerWithConfig(label, uri, protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(threshold),
			ReplicaID: replicaID,
		},
	})
	must(err, fmt.Sprintf("protocol.New(%s)", label))
	return p
}

// newPeerWithConfig builds a peer from cfg, filling in the shared secret id
// and an HTTPS own transport at uri, and returns protocol.New's error as is.
func newPeerWithConfig(label, uri string, cfg protocol.Config) (*peer, error) {
	cfg.SecretID = protocolSecretID
	cfg.OwnTransports = []protocol.TransportProtocolParam{{URI: uri, Protocol: int32(derecpb.Protocol_HTTPS)}}
	return newPeerFromConfig(label, cfg)
}

// newPeerFromConfig builds a peer from cfg as given, addressed by its first
// own transport, and returns protocol.New's error as is.
func newPeerFromConfig(label string, cfg protocol.Config) (*peer, error) {
	channelStore := newMemChannelStore()
	shareStore := newMemShareStore()
	secretStore := newMemSecretStore()
	userSecretStore := newMemUserSecretStore()
	stateStore := newMemStateStore()
	transport := newMemTransport()

	uri := ""
	if len(cfg.OwnTransports) > 0 {
		uri = cfg.OwnTransports[0].URI
	}
	p, err := protocol.New(protocol.Stores{Channel: channelStore, Share: shareStore, Secret: secretStore, UserSecret: userSecretStore, State: stateStore}, transport, cfg)
	if err != nil {
		return nil, err
	}

	return &peer{
		label:        label,
		uri:          uri,
		proto:        p,
		transport:    transport,
		shareStore:   shareStore,
		channelStore: channelStore,
		secretStore:  secretStore,
		userSecrets:  userSecretStore,
	}, nil
}

func (p *peer) drain() []outboxEntry {
	return p.transport.drain()
}

// deliver feeds bytes to peer.proto.Process, then satisfies every emitted
// ActionRequired via peer.proto.Accept — mirroring the `deliver` helper in
// smoke-tests/rust/src/protocol.rs. Returns every event produced by Process
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
// smoke-tests/rust/src/protocol.rs.
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
// Helpers) — mirroring `pump_many` in smoke-tests/rust/src/protocol.rs.
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
// smoke-tests/rust/src/protocol.rs. Returns the long-term channel_id both
// peers rotated to.
func pairPeers(owner, helper *peer, pairingChannelID uint64) uint64 {
	return pairPeersWithMode(owner, helper, pairingChannelID, protocol.ContactModeInlineKeys)
}

// pairPeersWithMode is pairPeers over any contact mode.
//
// HashedKeys and NoKeys insert a PrePair round-trip before the handshake
// proper: the scanner asks for the real keys, and the contact creator either
// republishes the ones it committed to (HashedKeys) or generates them on the
// spot (NoKeys). pump follows the chain, so the extra legs need no special
// handling here — only the mode the contact is minted with differs.
func pairPeersWithMode(owner, helper *peer, pairingChannelID uint64, mode protocol.ContactMode) uint64 {
	contact, err := owner.proto.CreateContact(&pairingChannelID, mode, nil)
	must(err, "owner.CreateContact")
	assertTrue(contact.ChannelID == pairingChannelID, "CreateContact.ChannelID = %d, want %d", contact.ChannelID, pairingChannelID)

	startEvents, err := helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:                  protocol.SenderKindHelper,
		Contact:               contact.ContactBytes,
		PeerCommunicationInfo: map[string]string{"name": "helper"},
	})
	must(err, "helper.Start(Pairing)")

	var sawPairingStarted bool
	for _, ev := range startEvents {
		assertTrue(ev.Type != protocol.EventTypePairingCompleted, "PairingCompleted must not appear in Start(Pairing) — it fires from Process() after the peer round-trip")
		if ev.Type == protocol.EventTypePairingStarted {
			sawPairingStarted = true
			assertTrue(ev.ChannelID == pairingChannelID, "PairingStarted.ChannelID = %d, want %d", ev.ChannelID, pairingChannelID)
			assertTrue(ev.Kind == protocol.SenderKindHelper, "PairingStarted.Kind = %d, want %d (Helper)", ev.Kind, protocol.SenderKindHelper)
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

	newChannelID := completions[0].ChannelID

	for _, ev := range completions {
		assertTrue(ev.PairingChannelID == pairingChannelID, "PairingCompleted.PairingChannelID = %d, want %d (the transient contact channel_id)", ev.PairingChannelID, pairingChannelID)
		cid := ev.ChannelID
		assertTrue(cid == newChannelID, "both peers must rotate to the same long-term channel_id: got %d and %d", cid, newChannelID)
	}

	return newChannelID
}

// runProtocol is the M3-parity payoff flow: real DeRecProtocol instances
// (Owner + two Helpers), each with its own in-memory stores and an
// in-process transport, driven through a genuine pairing ->
// protect-secret -> share-stored flow. Two Helpers, not one: the builder
// rejects Threshold < 2, and the sharing handler only VSS-splits shares
// once the Helpers' total subshares reach the threshold — with no
// weighted Helper that means helpers.len() >= threshold, so a single
// Helper would never observe a real ShareStored event.
// runEveryContactModePairs proves this SDK can pair over all three contact
// modes. It only ever exercised InlineKeys, so the two modes with a PrePair
// leg — the ones where the wire choreography actually differs — were never
// driven from Go at all.
func runEveryContactModePairs() {
	fmt.Println("=== Protocol contact-mode pairing test ===")

	const threshold = 2
	modes := []struct {
		name string
		mode protocol.ContactMode
	}{
		{"InlineKeys", protocol.ContactModeInlineKeys},
		{"HashedKeys", protocol.ContactModeHashedKeys},
		{"NoKeys", protocol.ContactModeNoKeys},
	}

	for i, m := range modes {
		owner := newPeer("owner", fmt.Sprintf("https://owner-%d.example.com", i), threshold)
		helper := newPeer("helper", fmt.Sprintf("https://helper-%d.example.com", i), threshold)

		channelID := pairPeersWithMode(owner, helper, uint64(900+i), m.mode)
		assertTrue(channelID != uint64(900+i),
			"%s: both peers must rotate off the transient pairing id", m.name)

		// The strongest end-to-end check: the handshake converged on one key.
		ownerKey, ok, err := owner.secretStore.Load(protocolSecretID, channelID, 0)
		must(err, fmt.Sprintf("%s owner secretStore.Load", m.name))
		assertTrue(ok, "%s: owner must hold a shared key", m.name)
		helperKey, ok, err := helper.secretStore.Load(protocolSecretID, channelID, 0)
		must(err, fmt.Sprintf("%s helper secretStore.Load", m.name))
		assertTrue(ok, "%s: helper must hold a shared key", m.name)
		assertTrue(bytes.Equal(ownerKey.Bytes, helperKey.Bytes),
			"%s: owner and helper shared keys must match", m.name)

		// NoKeys stores the contact on the creator so it can authenticate the
		// PrePairRequest by nonce. Once the handshake has rekeyed that row is
		// spent and must not survive — it used to.
		_, stranded, err := owner.secretStore.Load(protocolSecretID, uint64(900+i), 2)
		must(err, fmt.Sprintf("%s owner transient contact lookup", m.name))
		assertTrue(!stranded,
			"%s: the transient PairingContact must not outlive the handshake", m.name)

		// The gate. NoKeys inlines neither the keys nor a commitment to them,
		// so nothing binds what arrived over the plaintext PrePair leg to the
		// contact delivered out of band. Both sides hold the channel Pending
		// until the fingerprints are compared; the other two modes are usable
		// straight away.
		wantStatus := protocol.ChannelStatusPaired
		if m.mode == protocol.ContactModeNoKeys {
			wantStatus = protocol.ChannelStatusPending
		}
		for _, side := range []struct {
			label string
			peer  *peer
		}{{"owner", owner}, {"helper", helper}} {
			rec, ok, err := side.peer.channelStore.Load(protocolSecretID, channelID, 0)
			must(err, fmt.Sprintf("%s %s channelStore.Load", m.name, side.label))
			assertTrue(ok, "%s: %s must hold the channel", m.name, side.label)
			assertTrue(rec.Helper.Status == wantStatus,
				"%s: %s channel status = %v, want %v", m.name, side.label, rec.Helper.Status, wantStatus)
		}

		if m.mode == protocol.ContactModeNoKeys {
			ownerFP, err := owner.proto.GetFingerprint(channelID)
			must(err, "owner GetFingerprint")
			helperFP, err := helper.proto.GetFingerprint(channelID)
			must(err, "helper GetFingerprint")
			assertTrue(ownerFP == helperFP, "both sides must derive one fingerprint")

			matched, err := owner.proto.VerifyFingerprint(channelID, helperFP)
			must(err, "owner VerifyFingerprint")
			assertTrue(matched, "owner VerifyFingerprint must match")
			matched, err = helper.proto.VerifyFingerprint(channelID, ownerFP)
			must(err, "helper VerifyFingerprint")
			assertTrue(matched, "helper VerifyFingerprint must match")

			for _, side := range []struct {
				label string
				peer  *peer
			}{{"owner", owner}, {"helper", helper}} {
				rec, ok, err := side.peer.channelStore.Load(protocolSecretID, channelID, 0)
				must(err, fmt.Sprintf("%s channelStore.Load after verify", side.label))
				assertTrue(ok, "%s must still hold the channel", side.label)
				assertTrue(rec.Helper.Status == protocol.ChannelStatusPaired,
					"%s: a confirmed NoKeys channel must be Paired, got %v", side.label, rec.Helper.Status)
			}
			fmt.Println("  NoKeys held Pending until the fingerprint confirmed it  ✓")
		}

		fmt.Printf("  %s paired → channel_id=%d, shared_key=%dB, no transient state left  ✓\n",
			m.name, channelID, len(ownerKey.Bytes))
	}

	fmt.Println("Protocol contact-mode pairing test passed.")
}

func runProtocol() {
	fmt.Println("=== Protocol pairing + protect-secret flow test ===")

	const threshold = 2

	owner := newPeer("owner", "https://owner.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b.example.com", threshold)

	// Tick before anything is in flight: proves the symbol resolves through
	// purego (a registration failure only surfaces at call time) and that an
	// idle protocol is a safe thing for a scheduler to poke.
	idleEvents, err := owner.proto.Tick()
	must(err, "owner.Tick on an idle protocol")
	assertTrue(len(idleEvents) == 0, "idle Tick must produce no events, got %d", len(idleEvents))
	fmt.Println("  Tick on an idle protocol returns no events  ✓")

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
		_, ok, err := check.store.Load(protocolSecretID, check.cid, 0)
		must(err, fmt.Sprintf("%s channelStore.Load", check.label))
		assertTrue(ok, "%s channelStore must have the paired channel", check.label)
	}

	ownerFP, err := owner.proto.GetFingerprint(channelA)
	must(err, "owner.GetFingerprint(channelA)")
	helperAFP, err := helperA.proto.GetFingerprint(channelA)
	must(err, "helperA.GetFingerprint(channelA)")
	assertTrue(ownerFP == helperAFP, "owner and helper-a fingerprints must match: %q vs %q", ownerFP, helperAFP)

	fmt.Println("  pairing: two channels paired, fingerprints match ✓")

	owner.secretStore.loadManyCalls = nil
	secretData := []byte("super-secret-value")
	description := "smoke-test distribution"
	protectEvents, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: []byte{1, 2, 3}, Name: "smoke-test secret", Data: secretData}},
		Description: &description,
	})
	must(err, "owner.Start(ProtectSecret)")

	// The broadcast reads every helper's SharedKey through one
	// SecretStore.LoadMany call rather than one Load per channel.
	keyCalls := owner.secretStore.loadManyCalls
	assertTrue(len(keyCalls) == 1, "ProtectSecret broadcast must call SecretStore.LoadMany once, got %v", keyCalls)
	assertTrue(len(keyCalls[0]) == 2 && slices.Contains(keyCalls[0], channelA) && slices.Contains(keyCalls[0], channelB),
		"SecretStore.LoadMany must receive both helper channels [%d %d], got %v", channelA, channelB, keyCalls[0])
	fmt.Printf("  ProtectSecret broadcast → one SecretStore.LoadMany(%v)  ✓\n", keyCalls[0])

	protectStartedVersions := map[uint64]uint32{}
	for _, ev := range protectEvents {
		assertTrue(ev.Type != protocol.EventTypeProtectSecretFailed, "Start(ProtectSecret) emitted ProtectSecretFailed: %+v", ev)
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			protectStartedVersions[ev.ChannelID] = *ev.Version
		}
	}
	assertTrue(len(protectStartedVersions) == 2, "Start(ProtectSecret) must emit ProtectSecretStarted for both paired channels, got %+v", protectEvents)

	shareEvents := pumpMany([]*peer{owner, helperA, helperB})

	storedFor := map[uint64]bool{}
	confirmedCount := 0
	storeShareActions := 0
	for _, ev := range shareEvents {
		if ev.Type == protocol.EventTypeActionRequired && ev.ActionKind == protocol.ActionKindStoreShare {
			storeShareActions++
			assertTrue(ev.ShareSize != nil && *ev.ShareSize > 0, "StoreShare ActionRequired must carry a positive ShareSize, got %+v", ev)
			assertTrue(ev.TraceID != 0, "StoreShare ActionRequired must carry a TraceID, got %+v", ev)
		}
		switch ev.Type {
		case protocol.EventTypeShareStored:
			storedFor[ev.ChannelID] = true
		case protocol.EventTypeShareConfirmed:
			confirmedCount++
		}
	}
	assertTrue(storedFor[channelA], "expected a ShareStored event for channel-a (%d)", channelA)
	assertTrue(storedFor[channelB], "expected a ShareStored event for channel-b (%d)", channelB)
	assertTrue(storeShareActions == 2, "expected 2 StoreShare ActionRequired events (one per helper), got %d", storeShareActions)
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
		wantVersion, ok := protectStartedVersions[check.channelID]
		assertTrue(ok, "%s: no ProtectSecretStarted version recorded for channel %d", check.label, check.channelID)
		assertTrue(storedShares[0].Version == wantVersion, "%s stored share version = %d, want %d (from ProtectSecretStarted)", check.label, storedShares[0].Version, wantVersion)
	}

	fmt.Println("  protect-secret: ShareStored + ShareConfirmed observed on both helpers, store contents verified ✓")

	owner.proto.Close()
	helperA.proto.Close()
	helperB.proto.Close()

	fmt.Println("Protocol pairing + protect-secret flow test passed.")

	runExpiredChannelCleanup()
}

// runPairingRefusal mirrors smoke-tests/rust/src/protocol.rs's
// run_pairing_rejects_incompatible_parameter_range: a responder whose
// ParameterRange does not overlap the requester's refuses the PairRequest. It
// reports PairingRefused, sends exactly one rejecting PairResponse, and the
// requester's Process fails with the peer's status and memo on derec.Error.
func runPairingRefusal() {
	fmt.Println("=== Protocol pairing refusal test ===")

	// The memo is read by the requester, so its own range comes first.
	const expectedMemo = "`shareSize` range [10000000, 500000000] does not overlap the accepted range [1000000000, 5000000000]"

	newRangePeer := func(label, uri string, minShareSize, maxShareSize int64) *peer {
		p, err := newPeerWithConfig(label, uri, protocol.Config{
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				Threshold:      proto.Uint32(2),
				ParameterRange: &protocol.ParameterRange{MinShareSize: minShareSize, MaxShareSize: maxShareSize},
			},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p
	}
	owner := newRangePeer("owner", "https://owner-refusal.example.com", 1_000_000_000, 5_000_000_000)
	helper := newRangePeer("helper", "https://helper-refusal.example.com", 10_000_000, 500_000_000)
	defer owner.proto.Close()
	defer helper.proto.Close()

	pairingChannelID := uint64(1)
	contact, err := owner.proto.CreateContact(&pairingChannelID, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact")
	_, err = helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindHelper,
		Contact: contact.ContactBytes,
	})
	must(err, "helper.Start(Pairing)")
	pairRequest := helper.drain()
	assertTrue(len(pairRequest) == 1, "helper must send exactly one PairRequest, got %d", len(pairRequest))

	ownerEvents, err := owner.proto.Process(pairRequest[0].message)
	must(err, "owner.Process(PairRequest): a pairing refusal is reported, not an error")
	assertTrue(len(ownerEvents) == 1 && ownerEvents[0].Type == protocol.EventTypePairingRefused,
		"the responder must report exactly one PairingRefused, got %+v", ownerEvents)
	refused := ownerEvents[0]
	assertTrue(refused.Status == derecpb.StatusEnum_INCOMPATIBLE_PARAMETER_RANGE,
		"PairingRefused.Status: want INCOMPATIBLE_PARAMETER_RANGE, got %v", refused.Status)
	assertTrue(refused.Memo == expectedMemo, "PairingRefused.Memo must read from the requester's side, got %q", refused.Memo)
	assertTrue(refused.ErrorCode == "incompatible_parameter_range",
		"PairingRefused.ErrorCode: want incompatible_parameter_range, got %q", refused.ErrorCode)
	assertTrue(refused.Message != "", "PairingRefused.Message must be non-empty")
	fmt.Println("  owner.Process(PairRequest) → PairingRefused(IncompatibleParameterRange) with memo, error_code and message  ✓")

	pairResponse := owner.drain()
	assertTrue(len(pairResponse) == 1, "the responder must send exactly one rejecting PairResponse, got %d", len(pairResponse))

	_, err = helper.proto.Process(pairResponse[0].message)
	var peerErr *derec.Error
	assertTrue(errors.As(err, &peerErr) && peerErr.Code == derec.CodeNonOKStatus,
		"the requester must fail with CodeNonOKStatus on a rejecting PairResponse, got %v", err)
	assertTrue(peerErr.PeerStatus == int32(derecpb.StatusEnum_INCOMPATIBLE_PARAMETER_RANGE),
		"derec.Error.PeerStatus: want INCOMPATIBLE_PARAMETER_RANGE, got %d", peerErr.PeerStatus)
	assertTrue(peerErr.PeerMemo == expectedMemo, "derec.Error.PeerMemo must carry the responder's memo, got %q", peerErr.PeerMemo)
	fmt.Println("  helper.Process(PairResponse:rejected) → derec.Error(NonOKStatus) with PeerStatus and PeerMemo  ✓")
	fmt.Println("Protocol pairing refusal test passed.")
}

// runProtocolWeightedProtectSecret pairs an owner with two helpers, gives one
// of them a weight of 2 via ProtectSecretParams.Weights, and asserts the
// resulting ProtectSecretStarted events carry that weight — keyed by the
// long-term channel id pairing returns, not the transient pairing id (an
// invalid key there surfaces as InvalidWeight from the core, not a silently
// ignored weight).
func runProtocolWeightedProtectSecret() {
	fmt.Println("=== Protocol weighted protect-secret test ===")

	const threshold = 3

	owner := newPeer("owner", "https://owner-weighted.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-weighted.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-weighted.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)

	secretData := []byte("weighted-helpers-secret")
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{7}, Name: "weighted secret", Data: secretData}},
		Weights: map[uint64]uint32{channelA: 2},
	})
	must(err, "owner.Start(ProtectSecret, weighted)")

	gotWeight := map[uint64]uint32{}
	var v1 uint32
	for _, ev := range events {
		assertTrue(ev.Type != protocol.EventTypeProtectSecretFailed, "weighted Start(ProtectSecret) emitted ProtectSecretFailed: %+v", ev)
		if ev.Type == protocol.EventTypeProtectSecretStarted {
			assertTrue(ev.Weight != nil, "ProtectSecretStarted must carry Weight, got %+v", ev)
			gotWeight[ev.ChannelID] = *ev.Weight
			if ev.Version != nil {
				v1 = *ev.Version
			}
		}
	}
	assertTrue(gotWeight[channelA] == 2, "channel-a weight: want 2, got %d", gotWeight[channelA])
	assertTrue(gotWeight[channelB] == 1, "channel-b (unweighted) weight: want 1, got %d", gotWeight[channelB])

	pumpMany([]*peer{owner, helperA, helperB})

	fmt.Println("  ProtectSecretStarted carries Weight=2 for the weighted channel, Weight=1 for the unweighted one  ✓")

	// The owner records each helper's subshare count on the share it keeps;
	// the helpers record none.
	assertTrue(storedSubshares(owner, channelA, v1) == "2" && storedSubshares(owner, channelB, v1) == "1",
		"owner's v1 shares must record A=2, B=1; got A=%s, B=%s",
		storedSubshares(owner, channelA, v1), storedSubshares(owner, channelB, v1))
	fmt.Println("  owner's stored shares record Subshares A=2, B=1  ✓")
	assertTrue(storedSubshares(helperA, channelA, v1) == "nil" && storedSubshares(helperB, channelB, v1) == "nil",
		"helpers' shares must carry no count; got A=%s, B=%s",
		storedSubshares(helperA, channelA, v1), storedSubshares(helperB, channelB, v1))
	fmt.Println("  helpers' stored shares carry Subshares=nil  ✓")
	got := verifiedSubshares(owner, []*peer{owner, helperA, helperB}, v1)
	assertTrue(got[channelA] == "2" && got[channelB] == "1",
		"ShareVerified must report A=2, B=1 for v1; got %v", got)
	fmt.Println("  ShareVerified.Subshares reports A=2, B=1  ✓")

	// The library wrote the resolved weights into the helper records it saved
	// through this store.
	storedWeight := func(channelID uint64) uint32 {
		record, ok, err := owner.channelStore.Load(protocolSecretID, channelID, 0)
		must(err, "owner.channelStore.Load")
		assertTrue(ok && record.Helper != nil, "helper channel %d missing", channelID)
		return record.Helper.Weight
	}
	assertTrue(storedWeight(channelA) == 2 && storedWeight(channelB) == 1,
		"stored weights must be A=2, B=1; got A=%d, B=%d", storedWeight(channelA), storedWeight(channelB))
	fmt.Println("  HelperChannel.Weight records the resolved weights  ✓")

	// Pairing a third helper makes the library publish on its own, reading
	// the stored weights back from this store: A keeps 2, the new helper
	// starts at 1.
	helperC := newPeer("helper-c", "https://helper-c-weighted.example.com", threshold)
	defer helperC.proto.Close()
	pairingChannelC := uint64(3)
	contact, err := owner.proto.CreateContact(&pairingChannelC, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact(helper-c)")
	_, err = helperC.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindHelper,
		Contact: contact.ContactBytes,
	})
	must(err, "helperC.Start(Pairing)")
	// The publish fans out to every helper, so every peer takes part in the
	// pump.
	var channelC uint64
	republished := map[uint64]uint32{}
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB, helperC}) {
		switch {
		case ev.Type == protocol.EventTypePairingCompleted:
			channelC = ev.ChannelID
		case ev.Type == protocol.EventTypeProtectSecretStarted && ev.Weight != nil:
			republished[ev.ChannelID] = *ev.Weight
		}
	}
	assertTrue(len(republished) == 3 && republished[channelA] == 2 && republished[channelB] == 1 && republished[channelC] == 1,
		"the pairing publish must reuse the stored weights (A=2, B=1, C=1); got %v", republished)
	fmt.Println("  a pairing publish reuses the stored weights; the new helper gets 1  ✓")

	// Re-weight: B now holds 2 and A 1. Verifying v1 still reports the counts
	// of the round that published it.
	_, err = owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{7}, Name: "weighted secret", Data: []byte("re-weighted")}},
		Weights: map[uint64]uint32{channelB: 2},
	})
	must(err, "owner.Start(ProtectSecret, re-weighted)")
	all := []*peer{owner, helperA, helperB, helperC}
	pumpMany(all)
	got = verifiedSubshares(owner, all, v1)
	assertTrue(got[channelA] == "2" && got[channelB] == "1",
		"after re-weighting, verifying v1 must still report A=2, B=1; got %v", got)
	fmt.Println("  re-weighted (A=1, B=2); verifying v1 still reports A=2, B=1  ✓")
	fmt.Println("Protocol weighted protect-secret test passed.")
}

// runProtocolStickyThreshold checks that the threshold is sticky: each
// version's threshold is recorded on the owner's shares and reported by
// ShareVerified after a later round changed it, helpers record none, and the
// publish the library starts after a pairing splits at the stored threshold,
// not the configured one.
func runProtocolStickyThreshold() {
	fmt.Println("=== Protocol sticky threshold test ===")

	// The configured threshold is 2.
	owner := newPeer("owner", "https://owner-sticky.example.com", 2)
	helperA := newPeer("helper-a", "https://helper-a-sticky.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-sticky.example.com", 2)
	helperC := newPeer("helper-c", "https://helper-c-sticky.example.com", 2)
	helperD := newPeer("helper-d", "https://helper-d-sticky.example.com", 2)
	for _, p := range []*peer{owner, helperA, helperB, helperC, helperD} {
		defer p.proto.Close()
	}
	channels := []uint64{pairPeers(owner, helperA, 1), pairPeers(owner, helperB, 2), pairPeers(owner, helperC, 3)}
	helpers := []*peer{helperA, helperB, helperC}
	all := []*peer{owner, helperA, helperB, helperC}

	protect := func(data string, threshold *uint32) uint32 {
		events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
			Secrets:   []protocol.UserSecret{{ID: []byte{9}, Name: "sticky secret", Data: []byte(data)}},
			Threshold: threshold,
		})
		must(err, "owner.Start(ProtectSecret)")
		var version uint32
		for _, ev := range events {
			if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
				version = *ev.Version
			}
		}
		pumpMany(all)
		return version
	}
	three := uint32(3)
	v1 := protect("v1", nil)
	v2 := protect("v2", &three)

	for _, c := range channels {
		assertTrue(storedThreshold(owner, c, v1) == "2" && storedThreshold(owner, c, v2) == "3",
			"owner's shares must record v1 t=2, v2 t=3; got %s, %s", storedThreshold(owner, c, v1), storedThreshold(owner, c, v2))
	}
	fmt.Println("  owner's stored shares record Threshold v1=2, v2=3  ✓")
	for i, h := range helpers {
		assertTrue(storedThreshold(h, channels[i], v1) == "nil", "%s's share must carry no threshold", h.label)
	}
	fmt.Println("  helpers' stored shares carry Threshold=nil  ✓")
	snapshot, ok, err := owner.userSecrets.LoadLatest(protocolSecretID)
	must(err, "owner.userSecrets.LoadLatest")
	assertTrue(ok && subsharesText(snapshot.Threshold) == "3", "the snapshot must store t=3, got %s", subsharesText(snapshot.Threshold))
	fmt.Println("  UserSecrets.Threshold is 3  ✓")

	_, err = owner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: protocolSecretID,
		Version:  v1,
		Target:   protocol.TargetAll(),
	})
	must(err, "owner.Start(VerifyShares)")
	verified := map[uint64]string{}
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeShareVerified && ev.Version != nil && *ev.Version == v1 {
			verified[ev.ChannelID] = subsharesText(ev.Threshold)
		}
	}
	for _, c := range channels {
		assertTrue(verified[c] == "2", "ShareVerified for v1 must report t=2; got %v", verified)
	}
	fmt.Println("  ShareVerified.Threshold reports v1's t=2 after v2 changed it  ✓")

	// Pairing a fourth helper makes the library publish on its own.
	pairingChannelD := uint64(4)
	contact, err := owner.proto.CreateContact(&pairingChannelD, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact(helper-d)")
	_, err = helperD.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindHelper,
		Contact: contact.ContactBytes,
	})
	must(err, "helperD.Start(Pairing)")
	var channelD uint64
	for _, ev := range pumpMany(append(all, helperD)) {
		if ev.Type == protocol.EventTypePairingCompleted {
			channelD = ev.ChannelID
		}
	}
	for _, c := range append(channels, channelD) {
		assertTrue(storedThreshold(owner, c, v2+1) == "3",
			"the library-started publish must split at the stored t=3; got %s", storedThreshold(owner, c, v2+1))
	}
	fmt.Println("  the pairing publish splits at the stored t=3, not the configured 2  ✓")
	fmt.Println("Protocol sticky threshold test passed.")
}

// storedThreshold is the Threshold of the share p stores for channelID at
// version.
func storedThreshold(p *peer, channelID uint64, version uint32) string {
	shares, err := p.shareStore.Load(protocolSecretID, channelID, []uint32{version})
	must(err, p.label+".shareStore.Load")
	assertTrue(len(shares) == 1, "%s must store one share for channel %d at v%d, got %d", p.label, channelID, version, len(shares))
	return subsharesText(shares[0].Threshold)
}

// subsharesText renders an optional subshare count for assertions.
func subsharesText(n *uint32) string {
	if n == nil {
		return "nil"
	}
	return fmt.Sprint(*n)
}

// storedSubshares is the Subshares of the share p stores for channelID at
// version.
func storedSubshares(p *peer, channelID uint64, version uint32) string {
	shares, err := p.shareStore.Load(protocolSecretID, channelID, []uint32{version})
	must(err, p.label+".shareStore.Load")
	assertTrue(len(shares) == 1, "%s must store one share for channel %d at v%d, got %d", p.label, channelID, version, len(shares))
	return subsharesText(shares[0].Subshares)
}

// verifiedSubshares verifies version on every helper and returns the
// Subshares of each ShareVerified, by channel.
func verifiedSubshares(owner *peer, peers []*peer, version uint32) map[uint64]string {
	_, err := owner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: protocolSecretID,
		Version:  version,
		Target:   protocol.TargetAll(),
	})
	must(err, "owner.Start(VerifyShares)")
	out := map[uint64]string{}
	for _, ev := range pumpMany(peers) {
		if ev.Type == protocol.EventTypeShareVerified && ev.Version != nil && *ev.Version == version {
			out[ev.ChannelID] = subsharesText(ev.Subshares)
		}
	}
	return out
}

// runProtocolMaxSubshares exercises Config.MaxSubshares: a cap below the
// threshold is refused by New with CodeInvalidInput, and a round whose
// weights total more than the cap fails Start(ProtectSecret) with
// CodeTooManySubshares before anything is sent.
func runProtocolMaxSubshares() {
	fmt.Println("=== Protocol max-subshares cap test ===")

	const threshold = 3

	var buildErr *derec.Error
	_, err := newPeerWithConfig("owner", "https://owner-capped.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:    proto.Uint32(threshold),
			MaxSubshares: proto.Uint64(threshold - 1),
		},
	})
	assertTrue(errors.As(err, &buildErr) && buildErr.Code == derec.CodeInvalidInput,
		"a cap below the threshold must fail New with CodeInvalidInput, got %v", err)
	fmt.Println("  New refuses a cap below the threshold (CodeInvalidInput)  ✓")

	owner, err := newPeerWithConfig("owner", "https://owner-capped.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:    proto.Uint32(threshold),
			MaxSubshares: proto.Uint64(threshold),
		},
	})
	must(err, "protocol.New(owner, capped)")
	helperA := newPeer("helper-a", "https://helper-a-capped.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-capped.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)
	owner.drain()

	var startErr *derec.Error
	_, err = owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{8}, Name: "capped secret", Data: []byte("capped-secret")}},
		Weights: map[uint64]uint32{channelA: 2, channelB: 2},
	})
	assertTrue(errors.As(err, &startErr) && startErr.Code == derec.CodeTooManySubshares,
		"4 subshares over a cap of 3 must fail with CodeTooManySubshares, got %v", err)
	assertTrue(len(owner.drain()) == 0, "a round over the cap must send nothing")
	fmt.Println("  Start(ProtectSecret) over the cap fails with CodeTooManySubshares and sends nothing  ✓")
	fmt.Println("Protocol max-subshares cap test passed.")
}

// runShareStoreRefusal has a helper's share store refuse with
// RefusalTooFrequent, first from Save and then from RecordVerification. The
// helper still answers, so the owner observes ShareRejected and
// ShareVerifyRejected with status TOO_FREQUENT, and deliver's Process/Accept
// calls succeed on the helper.
func runShareStoreRefusal() {
	fmt.Println("=== Protocol share store refusal test ===")

	owner := newPeer("owner", "https://owner.example.com", 2)
	helperA := newPeer("helper-a", "https://helper-a.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	peers := []*peer{owner, helperA, helperB}

	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)

	protect := func(data string) uint32 {
		events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
			Secrets: []protocol.UserSecret{{ID: []byte{9}, Name: "rate-limited", Data: []byte(data)}},
		})
		must(err, "owner.Start(ProtectSecret)")
		for _, ev := range events {
			if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
				return *ev.Version
			}
		}
		fail("Start(ProtectSecret) must emit ProtectSecretStarted, got %+v", events)
		return 0
	}

	version := protect("first version")
	pumpMany(peers)

	helperA.shareStore.mu.Lock()
	helperA.shareStore.refuseSaves = true
	helperA.shareStore.mu.Unlock()
	nextVersion := protect("second version")
	var shareRejected []protocol.Event
	for _, ev := range pumpMany(peers) {
		if ev.Type == protocol.EventTypeShareRejected {
			shareRejected = append(shareRejected, ev)
		}
	}
	assertTrue(len(shareRejected) == 1 && shareRejected[0].ChannelID == channelA &&
		shareRejected[0].Version != nil && *shareRejected[0].Version == nextVersion &&
		shareRejected[0].Status == derecpb.StatusEnum_TOO_FREQUENT,
		"expected one ShareRejected(TOO_FREQUENT) from helper-a, got %+v", shareRejected)
	fmt.Println("  helper-a Save → RefusalTooFrequent; owner ShareRejected(status=TOO_FREQUENT)  ✓")

	helperA.shareStore.mu.Lock()
	helperA.shareStore.refuseSaves = false
	helperA.shareStore.refuseVerifications = true
	helperA.shareStore.mu.Unlock()
	_, err := owner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: protocolSecretID,
		Version:  version,
		Target:   protocol.TargetAll(),
	})
	must(err, "owner.Start(VerifyShares)")
	var verifyRejected []protocol.Event
	verified := 0
	for _, ev := range pumpMany(peers) {
		switch ev.Type {
		case protocol.EventTypeShareVerifyRejected:
			verifyRejected = append(verifyRejected, ev)
		case protocol.EventTypeShareVerified:
			verified++
		}
	}
	assertTrue(len(verifyRejected) == 1 && verifyRejected[0].ChannelID == channelA &&
		verifyRejected[0].Status == derecpb.StatusEnum_TOO_FREQUENT,
		"expected one ShareVerifyRejected(TOO_FREQUENT) from helper-a, got %+v", verifyRejected)
	assertTrue(verified == 1, "helper-b must still prove possession, got %d ShareVerified", verified)
	fmt.Println("  helper-a RecordVerification → RefusalTooFrequent; owner ShareVerifyRejected(status=TOO_FREQUENT)  ✓")

	fmt.Println("Protocol share store refusal test passed.")
}

// runRequestFailedToken: with AutoRespondOnFailure off (the default), a
// request whose handling fails is not answered by the library. It is reported
// as a RequestFailed event carrying a token, and Reject on that token sends the
// one response the peer is owed. The failure is a share store backend error on
// an accepted StoreShare; the owner observes exactly one ShareRejected carrying
// the status passed to Reject.
func runRequestFailedToken() {
	fmt.Println("=== Protocol failed request answered through its token test ===")

	owner := newPeer("owner", "https://owner.example.com", 2)
	helperA := newPeer("helper-a", "https://helper-a.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)

	helperA.shareStore.mu.Lock()
	helperA.shareStore.failSaves = true
	helperA.shareStore.mu.Unlock()
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{10}, Name: "failing", Data: []byte("payload")}},
	})
	must(err, "owner.Start(ProtectSecret)")
	var version uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			version = *ev.Version
		}
	}
	assertTrue(version != 0, "Start(ProtectSecret) must emit ProtectSecretStarted, got %+v", events)

	var ownerEvents []protocol.Event
	var failed []protocol.Event
	for _, entry := range owner.drain() {
		switch entry.uri {
		case helperB.uri:
			deliver(helperB, entry.message)
			for _, reply := range helperB.drain() {
				ownerEvents = append(ownerEvents, deliver(owner, reply.message)...)
			}
		case helperA.uri:
			for _, ev := range deliver(helperA, entry.message) {
				if ev.Type == protocol.EventTypeRequestFailed {
					failed = append(failed, ev)
				}
			}
		default:
			fail("no peer for destination uri %s", entry.uri)
		}
	}
	assertTrue(len(failed) == 1, "helper-a must report one RequestFailed, got %+v", failed)
	rf := failed[0]
	assertTrue(rf.ChannelID == channelA && rf.ActionKind == protocol.ActionKindStoreShare &&
		!rf.Responded && len(rf.Action) > 0 && rf.ErrorCode != "" &&
		rf.Status == derecpb.StatusEnum_FAIL && rf.Memo == "request could not be processed",
		"unexpected RequestFailed: %+v", rf)
	pending := helperA.drain()
	assertTrue(len(pending) == 0,
		"with AutoRespondOnFailure off, helper-a must not answer by itself; sent %d", len(pending))
	fmt.Printf("  helper-a Save fails → RequestFailed(action_kind=%s, responded=false, status=%s, memo=%q, error_code=%s) with a token, nothing sent  ✓\n",
		rf.ActionKind, rf.Status, rf.Memo, rf.ErrorCode)

	must(helperA.proto.Reject(rf.Action, rf.Status, rf.Memo), "helper-a Reject(token)")
	replies := helperA.drain()
	assertTrue(len(replies) == 1, "Reject(token) must send exactly one response; sent %d", len(replies))
	ownerEvents = append(ownerEvents, deliver(owner, replies[0].message)...)

	var rejected []protocol.Event
	for _, ev := range ownerEvents {
		if ev.Type == protocol.EventTypeShareRejected {
			rejected = append(rejected, ev)
		}
	}
	assertTrue(len(rejected) == 1 && rejected[0].ChannelID == channelA &&
		rejected[0].Version != nil && *rejected[0].Version == version &&
		rejected[0].Status == derecpb.StatusEnum_FAIL && rejected[0].Memo == rf.Memo,
		"expected one ShareRejected(FAIL, event memo) from helper-a, got %+v", rejected)
	fmt.Println("  helper-a Reject(token, event Status, event Memo) → one response; owner ShareRejected(status=FAIL, same memo)  ✓")

	fmt.Println("Protocol failed request answered through its token test passed.")
}

// runExpiredChannelCleanup exercises the expired-channel cleanup surface
// through the Go SDK.
//
// The contradictory pair — Enabled false alongside a non-zero timeout — is
// the point: the wrapper must forward both values verbatim and let the
// library decide that a disabled policy ignores its timeout. A wrapper that
// interpreted the flag locally (dropping the timeout, or substituting its
// own default) would still pass a happy-path test, so the config is chosen
// to fail if any interpretation crept into the Go layer.
func runExpiredChannelCleanup() {
	fmt.Println("=== Protocol expired-channel cleanup test ===")

	channelStore := newMemChannelStore()
	shareStore := newMemShareStore()
	secretStore := newMemSecretStore()
	userSecretStore := newMemUserSecretStore()
	stateStore := newMemStateStore()
	transport := newMemTransport()

	cfg := protocol.Config{
		SecretID: protocolSecretID,
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			OwnTransports: []protocol.TransportProtocolParam{{URI: "https://cleanup.example.com", Protocol: int32(derecpb.Protocol_HTTPS)}},
			Threshold:     proto.Uint32(2),
			Timeouts: &protocol.Timeouts{
				ExpiredChannels: &protocol.RemoveExpiredChannelsPolicy{
					Enabled:       false,
					TimeoutInSecs: 900,
				},
			},
		},
	}
	p, err := protocol.New(protocol.Stores{Channel: channelStore, Share: shareStore, Secret: secretStore, UserSecret: userSecretStore, State: stateStore}, transport, cfg)
	must(err, "protocol.New(cleanup)")
	defer p.Close()

	// The caller-driven sweep works regardless of the disabled policy —
	// that is what Disabled means. No Pending channels exist yet, so the
	// result is an empty (non-nil error) list.
	removed, err := p.RemoveExpiredChannels(0)
	must(err, "RemoveExpiredChannels(0)")
	assertTrue(len(removed) == 0, "expected no removed channels on a fresh protocol, got %d", len(removed))

	fmt.Println("  cleanup: disabled policy forwarded with its timeout; manual sweep callable ✓")
	fmt.Println("Protocol expired-channel cleanup test passed.")
}

// runUnsafeConnection proves the unsafe_connection setting survives the JSON
// config boundary and actually changes behaviour.
//
// Worth its own test because the failure mode is silent: the Rust side reads
// the field with serde's `default`, so a name mismatch between this SDK and
// the FFI config would deserialize as `false` and the setting would appear to
// do nothing — with every other test still passing. Exactly the shape of the
// bug that made three enum variants `undefined` in the JS shims.
func runUnsafeConnection() {
	fmt.Println("=== Protocol unsafe_connection config test ===")

	build := func(uri string, allow bool) error {
		cfg := protocol.Config{
			SecretID: protocolSecretID,
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				OwnTransports:    []protocol.TransportProtocolParam{{URI: uri, Protocol: int32(derecpb.Protocol_HTTPS)}},
				Threshold:        proto.Uint32(2),
				UnsafeConnection: &allow,
			},
		}
		p, err := protocol.New(
			protocol.Stores{
				Channel:    newMemChannelStore(),
				Share:      newMemShareStore(),
				Secret:     newMemSecretStore(),
				UserSecret: newMemUserSecretStore(),
				State:      newMemStateStore(),
			},
			newMemTransport(), cfg,
		)
		if err != nil {
			return err
		}
		p.Close()
		return nil
	}

	// Loopback is free — a local dev server needs no configuration.
	must(build("http://127.0.0.1:8080", false), "loopback plaintext with unsafe_connection=false")
	fmt.Println("  loopback http accepted with unsafe_connection=false  ✓")

	// A LAN address is not, until asked for. If the field name did not match
	// the FFI config, this would build and the assertion would fail here.
	if err := build("http://192.168.1.42:8080", false); err == nil {
		panic("LAN plaintext must be refused when unsafe_connection=false — " +
			"the setting is not reaching the library")
	}
	fmt.Println("  LAN http refused with unsafe_connection=false  ✓")

	must(build("http://192.168.1.42:8080", true), "LAN plaintext with unsafe_connection=true")
	fmt.Println("  LAN http accepted with unsafe_connection=true  ✓")

	fmt.Println("Protocol unsafe_connection config test passed.")
}

// runConfigSurface exercises the config knobs and validation rules an
// application reaches through the Go SDK, each of which crosses the FFI as a
// JSON field. A mismatch between this shim's field names and the Rust
// DeRecProtocolConfig would fail the build rather than apply, so each
// assertion here is checking that the value actually arrived.
func runConfigSurface() {
	fmt.Println("=== Protocol config surface test ===")

	base := func() protocol.Config {
		return protocol.Config{
			SecretID: protocolSecretID,
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				OwnTransports: []protocol.TransportProtocolParam{{URI: "https://owner.example.com", Protocol: int32(derecpb.Protocol_HTTPS)}},
				Threshold:     proto.Uint32(2),
			},
		}
	}
	build := func(cfg protocol.Config) (*protocol.DeRecProtocol, error) {
		return protocol.New(
			protocol.Stores{
				Channel:    newMemChannelStore(),
				Share:      newMemShareStore(),
				Secret:     newMemSecretStore(),
				UserSecret: newMemUserSecretStore(),
				State:      newMemStateStore(),
			},
			newMemTransport(), cfg,
		)
	}

	// ParameterRange reaches the library. Bounds that cannot intersect any
	// peer range would still build — this only proves the field is carried,
	// which is what was missing before it existed in the FFI config.
	cfg := base()
	cfg.ParameterRange = &protocol.ParameterRange{
		MinShareSize:                1,
		MaxShareSize:                1 << 20,
		MinTimeBetweenVerifications: 1,
		MaxTimeBetweenVerifications: 3600,
	}
	p, err := build(cfg)
	must(err, "build with ParameterRange")
	p.Close()
	fmt.Println("  ParameterRange accepted by the FFI config  ✓")

	// A device serves at most one endpoint per protocol: two HTTPS entries
	// contradict rather than extend, so the set is refused even though each
	// entry is individually well-formed.
	cfg = base()
	cfg.OwnTransports = []protocol.TransportProtocolParam{
		{URI: "https://a.example", Protocol: int32(derecpb.Protocol_HTTPS)},
		{URI: "https://b.example", Protocol: int32(derecpb.Protocol_HTTPS)},
	}
	if _, err := build(cfg); err == nil {
		panic("two endpoints of one protocol must be refused — " +
			"the one-per-protocol rule is not reaching the library")
	}
	fmt.Println("  two endpoints of one protocol refused  ✓")

	// Distinct protocols are what the list is for.
	cfg = base()
	cfg.OwnTransports = []protocol.TransportProtocolParam{
		{URI: "https://a.example", Protocol: int32(derecpb.Protocol_HTTPS)},
		{URI: "grpcs://a.example:443", Protocol: int32(derecpb.Protocol_GRPC)},
	}
	p, err = build(cfg)
	must(err, "build with one endpoint per protocol")
	fmt.Println("  distinct protocols accepted  ✓")

	// SetOwnTransports replaces the whole set, and is refused the same way
	// the builder is when it would produce a duplicate.
	must(p.SetOwnTransports([]protocol.TransportProtocolParam{
		{URI: "https://only.example", Protocol: int32(derecpb.Protocol_HTTPS)},
	}), "SetOwnTransports replaces the set")
	fmt.Println("  SetOwnTransports replaces the whole set  ✓")

	if err := p.SetOwnTransports([]protocol.TransportProtocolParam{
		{URI: "https://a.example", Protocol: int32(derecpb.Protocol_HTTPS)},
		{URI: "https://b.example", Protocol: int32(derecpb.Protocol_HTTPS)},
	}); err == nil {
		panic("SetOwnTransports must apply the same one-per-protocol rule as the builder")
	}
	fmt.Println("  SetOwnTransports refuses a duplicate protocol  ✓")

	// An empty list is refused by the core, which the SDK forwards as is.
	var emptyErr *derec.Error
	if err := p.SetOwnTransports([]protocol.TransportProtocolParam{}); !errors.As(err, &emptyErr) ||
		emptyErr.Code != derec.CodeInvalidInput {
		panic(fmt.Sprintf("SetOwnTransports with no endpoints must fail with CodeInvalidInput, got %v", err))
	}
	fmt.Println("  SetOwnTransports refuses an empty list  ✓")
	p.Close()

	// The error constants are a mirror of the Rust DEREC_CODE_* values.
	// Drift here means an application branching on a code would take the
	// wrong branch, which no other test would catch.
	assertTrue(derec.CodeReplicaIDConflict == 16,
		"CodeReplicaIDConflict must be 16, got %d", derec.CodeReplicaIDConflict)
	assertTrue(derec.CodeNoUsableEndpoint == 121,
		"CodeNoUsableEndpoint must be 121, got %d", derec.CodeNoUsableEndpoint)
	assertTrue(derec.CodeTooManySubshares == 66,
		"CodeTooManySubshares must be 66, got %d", derec.CodeTooManySubshares)
	assertTrue(derec.CategoryStateStore == 15,
		"CategoryStateStore must be 15, got %d", derec.CategoryStateStore)
	fmt.Println("  error code/category values match the FFI  ✓")

	fmt.Println("Protocol config surface test passed.")
}

func runUnconfirmedDestination() {
	fmt.Println("=== Protocol unconfirmed replica destination test ===")

	sourceID, destinationID := uint64(0x50505050), uint64(0xDE57DE57)
	source := newPeerWithReplicaID("source", "https://source.example.com", 2, &sourceID)
	destination := newPeerWithReplicaID("destination", "https://destination.example.com", 2, &destinationID)

	pairingChannelID := uint64(31)
	contact, err := source.proto.CreateContact(&pairingChannelID, protocol.ContactModeInlineKeys, nil)
	must(err, "source.CreateContact")
	_, err = destination.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindReplicaDestination,
		Contact: contact.ContactBytes,
	})
	must(err, "destination.Start(Pairing)")
	handshake := append(pump(destination, source), pump(source, destination)...)
	var replicaChannel uint64
	for _, ev := range handshake {
		if ev.Type == protocol.EventTypePairingCompleted {
			replicaChannel = ev.ChannelID
		}
	}
	assertTrue(replicaChannel != 0, "the replica handshake must complete")

	destinationFp, err := destination.proto.GetFingerprint(replicaChannel)
	must(err, "destination.GetFingerprint")
	ok, err := source.proto.VerifyFingerprint(replicaChannel, destinationFp)
	must(err, "source.VerifyFingerprint")
	assertTrue(ok, "the source must accept the matching fingerprint")

	var ignored bool
	for _, ev := range pump(source, destination) {
		switch ev.Type {
		case protocol.EventTypeMessageIgnored:
			ignored = ignored || (ev.Reason == protocol.IgnoreReasonPendingVerification &&
				ev.ChannelID == replicaChannel)
		case protocol.EventTypeReplicaSecretInstalled, protocol.EventTypeReplicaSecretReceived, protocol.EventTypeReplicaSecretAcked:
			fail("nothing may be installed or acknowledged before the destination confirms, got %s", ev.Type)
		}
	}
	assertTrue(ignored, "a copy sent before the destination confirms must surface as MessageIgnored(PendingVerification)")
	fmt.Println("  copy sent before the destination confirmed was ignored  ✓")

	sourceFp, err := source.proto.GetFingerprint(replicaChannel)
	must(err, "source.GetFingerprint")
	ok, err = destination.proto.VerifyFingerprint(replicaChannel, sourceFp)
	must(err, "destination.VerifyFingerprint")
	assertTrue(ok, "the destination must accept the matching fingerprint")
	_, err = destination.proto.Start(protocol.FlowKindReplicaDiscovery, nil)
	must(err, "destination.Start(ReplicaDiscovery)")

	var installed *protocol.Event
	var seen []string
	for _, ev := range pump(destination, source) {
		seen = append(seen, ev.Type)
		if ev.Type == protocol.EventTypeReplicaSecretInstalled {
			installed = &ev
		}
	}
	assertTrue(installed != nil, "after confirming, ReplicaDiscovery must install the copy, got %v", seen)
	fmt.Println("  destination pulled the copy with ReplicaDiscovery after confirming  ✓")

	assertTrue(installed.AuthorReplicaID != nil && *installed.AuthorReplicaID == sourceID,
		"ReplicaSecretInstalled.AuthorReplicaID must name the publisher %d, got %v", sourceID, installed.AuthorReplicaID)
	held, ok, err := destination.userSecrets.LoadLatest(protocolSecretID)
	must(err, "destination.userSecrets.LoadLatest")
	assertTrue(ok, "the destination must persist the installed user secrets")
	assertTrue(held.AuthorReplicaID != nil && *held.AuthorReplicaID == sourceID,
		"the destination's user-secret store must record author %d, got %v", sourceID, held.AuthorReplicaID)
	fmt.Println("  installed copy names the publisher as author, in the event and in the store  ✓")

	fmt.Println("Protocol unconfirmed replica destination test passed.")
	fmt.Println()
}
