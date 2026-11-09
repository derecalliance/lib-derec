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
	"time"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/discovery"
	"github.com/derecalliance/lib-derec/packages/go/primitives/envelope"
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

	// keep, when set, is every KeepVersion answer; unset, the store keeps
	// the previous version (version - 1), the way an application whose
	// every round commits would.
	keep                *uint32
	keepVersionCalls    []uint32
	removeVersionsCalls []removeVersionsCall
}

// removeVersionsCall is one RemoveVersions call as the store received it.
type removeVersionsCall struct {
	secretID  uint64
	channelID uint64
	versions  []uint32
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
	// Keyed by the partition, which is what every read here filters by.
	// share.SecretID names the Owner's secret and differs from the partition
	// whenever this peer is a Helper, so keying on it would put rows where no
	// read looks.
	s.data[shareStoreKey{channelID, secretID, share.Version}] = share
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
	s.removeVersionsCalls = append(s.removeVersionsCalls, removeVersionsCall{secretID, channelID, append([]uint32(nil), versions...)})
	for _, v := range versions {
		delete(s.data, shareStoreKey{channelID, secretID, v})
	}
	return nil
}

func (s *memShareStore) KeepVersion(secretID uint64, version uint32) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keepVersionCalls = append(s.keepVersionCalls, version)
	if s.keep != nil {
		return *s.keep, nil
	}
	return version - 1, nil
}

// setKeep sets the answer KeepVersion gives; nil restores the
// previous-version default.
func (s *memShareStore) setKeep(keep *uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keep = keep
}

// storedVersions returns, sorted, every version stored for secretID.
func (s *memShareStore) storedVersions(secretID uint64) []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var versions []uint32
	for k := range s.data {
		if k.secretID == secretID {
			versions = append(versions, k.version)
		}
	}
	slices.Sort(versions)
	return versions
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
	// failing holds the URIs every send to fails, the way a broken link to
	// one peer would while the others stay healthy.
	failing map[string]bool
}

func newMemTransport() *memTransport {
	return &memTransport{failing: make(map[string]bool)}
}

// failURI makes every later send to uri fail.
func (t *memTransport) failURI(uri string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failing[uri] = true
}

func (t *memTransport) Send(endpoints []protocol.Endpoint, message []byte) error {
	if len(endpoints) == 0 {
		return errors.New("transport: send called with no endpoints")
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failing[endpoints[0].URI] {
		return errors.New("transport: simulated failure")
	}
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
// driven from Go at all. It then refuses a HashedKeys contact whose binding
// hash was tampered with and a NoKeys PrePair naming another nonce. Mirrors
// run_hashed_keys_pairing_flow and run_no_keys_pairing_flow in
// smoke-tests/rust/src/protocol.rs.
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

			must(owner.proto.VerifyFingerprint(channelID, helperFP), "owner VerifyFingerprint")
			must(helper.proto.VerifyFingerprint(channelID, ownerFP), "helper VerifyFingerprint")

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

	// A HashedKeys contact commits to the creator's keys; keys that do not
	// open the commitment are refused by the scanner.
	owner := newPeer("owner", "https://owner-hash-tampered.example.com", threshold)
	helper := newPeer("helper", "https://helper-hash-tampered.example.com", threshold)
	defer owner.proto.Close()
	defer helper.proto.Close()
	hashedChannel := uint64(910)
	hashed, err := owner.proto.CreateContact(&hashedChannel, protocol.ContactModeHashedKeys, nil)
	must(err, "owner CreateContact(HashedKeys)")
	var hashedContact derecpb.ContactMessage
	must(proto.Unmarshal(hashed.ContactBytes, &hashedContact), "decode the HashedKeys contact")
	assertTrue(len(hashedContact.ContactBindingHash) != 0, "a HashedKeys contact must carry a binding hash")
	assertTrue(hashedContact.MlkemEncapsulationKey == nil && hashedContact.EciesPublicKey == nil,
		"a HashedKeys contact must not carry inline public keys")
	hashedContact.ContactBindingHash[0] ^= 0xFF
	tampered, err := proto.Marshal(&hashedContact)
	must(err, "encode the tampered contact")
	_, err = helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{Kind: protocol.SenderKindHelper, Contact: tampered})
	must(err, "helper Start(Pairing, tampered HashedKeys)")
	prePairRequest := helper.drain()
	assertTrue(len(prePairRequest) == 1, "the helper must send exactly one PrePairRequest, got %d", len(prePairRequest))
	deliver(owner, prePairRequest[0].message)
	prePairResponse := owner.drain()
	assertTrue(len(prePairResponse) == 1, "the owner must send exactly one PrePairResponse, got %d", len(prePairResponse))
	_, err = helper.proto.Process(prePairResponse[0].message)
	var hashErr *derec.Error
	assertTrue(errors.As(err, &hashErr) && hashErr.Code == derec.CodePrepairHashMismatch,
		"a tampered binding hash must fail Process with CodePrepairHashMismatch, got %v", err)
	fmt.Println("  HashedKeys with a tampered binding hash → Process fails with CodePrepairHashMismatch  ✓")

	// A NoKeys contact is authenticated by its nonce: a PrePairRequest naming
	// another nonce is refused when the creator accepts it.
	creator := newPeer("owner", "https://owner-nonce.example.com", threshold)
	scanner := newPeer("helper", "https://helper-nonce.example.com", threshold)
	defer creator.proto.Close()
	defer scanner.proto.Close()
	noKeysChannel, realNonce := uint64(9999), uint64(8888)
	noKeys, err := creator.proto.CreateContact(&noKeysChannel, protocol.ContactModeNoKeys, &realNonce)
	must(err, "owner CreateContact(NoKeys)")
	var noKeysContact derecpb.ContactMessage
	must(proto.Unmarshal(noKeys.ContactBytes, &noKeysContact), "decode the NoKeys contact")
	noKeysContact.Nonce = 7777
	wrongNonce, err := proto.Marshal(&noKeysContact)
	must(err, "encode the contact with another nonce")
	_, err = scanner.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{Kind: protocol.SenderKindHelper, Contact: wrongNonce})
	must(err, "helper Start(Pairing, NoKeys with another nonce)")
	prePair := scanner.drain()
	assertTrue(len(prePair) == 1, "the helper must send exactly one PrePairRequest, got %d", len(prePair))
	prompt, err := creator.proto.Process(prePair[0].message)
	must(err, "owner Process(PrePairRequest)")
	var action []byte
	for _, ev := range prompt {
		if ev.Type == protocol.EventTypeActionRequired {
			action = ev.Action
		}
	}
	assertTrue(action != nil, "the owner must raise ActionRequired for the PrePair, got %+v", prompt)
	_, err = creator.proto.Accept(action)
	assertTrue(err != nil && strings.Contains(err.Error(), "NoKeys PrePair nonce mismatch"),
		"accepting a PrePair with another nonce must fail with the NoKeys nonce mismatch, got %v", err)
	fmt.Println("  NoKeys PrePair with another nonce → Accept fails with the nonce mismatch  ✓")

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
	// of the round that published it. The pairing publish was v2, so the
	// round keeps v1 to leave it on the helpers.
	owner.shareStore.setKeep(&v1)
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

// startKeepRound starts one ProtectSecret round on owner, its payload tagged
// with round so every round distributes a new version.
func startKeepRound(owner *peer, secretTag byte, round int) error {
	_, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{secretTag}, Name: "kept", Data: []byte(fmt.Sprintf("round-%d", round))}},
	})
	return err
}

// deliverKeepRound delivers every envelope owner sent to the helper it is
// addressed to, skipping any addressed to skip, and hands each helper's
// answer back to owner.
func deliverKeepRound(owner *peer, helpers []*peer, skip *peer) {
	for _, entry := range owner.drain() {
		var target *peer
		for _, h := range helpers {
			if h.uri == entry.uri {
				target = h
			}
		}
		if target == nil {
			fail("no peer for destination uri %s", entry.uri)
		}
		if target == skip {
			continue
		}
		deliver(target, entry.message)
		for _, answer := range target.drain() {
			deliver(owner, answer.message)
		}
	}
}

// runHelperKeepVersionPrunesShareStore: a helper applies each request's
// keepVersion through ShareStore.RemoveVersions. The owner's KeepVersion
// keeps the previous version for v1 to v3 and answers 2 for v4, so the v4
// publish removes v3 and each helper ends up holding exactly v2 and v4.
func runHelperKeepVersionPrunesShareStore() {
	fmt.Println("=== Helper keepVersion prunes the share store ===")

	const threshold = 2
	owner := newPeer("owner", "https://owner-keep-prune.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-keep-prune.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-keep-prune.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	pairPeers(owner, helperA, 21)
	pairPeers(owner, helperB, 22)
	owner.drain()

	helpers := []*peer{helperA, helperB}
	for round := 1; round <= 4; round++ {
		if round == 4 {
			owner.shareStore.setKeep(proto.Uint32(2))
		}
		must(startKeepRound(owner, 0x03, round), fmt.Sprintf("round %d Start(ProtectSecret)", round))
		deliverKeepRound(owner, helpers, nil)
	}

	for _, h := range helpers {
		versions := h.shareStore.storedVersions(protocolSecretID)
		assertTrue(slices.Equal(versions, []uint32{2, 4}), "[%s] must keep exactly versions [2 4], got %v", h.label, versions)
		h.shareStore.mu.Lock()
		removedV3 := slices.ContainsFunc(h.shareStore.removeVersionsCalls, func(c removeVersionsCall) bool {
			return c.secretID == protocolSecretID && slices.Equal(c.versions, []uint32{3})
		})
		h.shareStore.mu.Unlock()
		assertTrue(removedV3, "[%s] RemoveVersions must reach the app store with [3]", h.label)
	}
	fmt.Println("  v4 with keepVersion 2 removed v3 via RemoveVersions on both helpers  ✓")
	fmt.Println("Helper keepVersion test passed.")
}

// seenEnvelopes is the application's replay record: the identity of every
// envelope a device sent or accepted, keyed on envelope.ReadMessageID.
type seenEnvelopes map[string]struct{}

func messageIDOf(envelopeBytes []byte) string {
	id, err := envelope.ReadMessageID(envelopeBytes)
	must(err, "envelope.ReadMessageID")
	return string(id.ID)
}

func (s seenEnvelopes) record(envelopeBytes []byte) { s[messageIDOf(envelopeBytes)] = struct{}{} }

func (s seenEnvelopes) contains(envelopeBytes []byte) bool {
	_, ok := s[messageIDOf(envelopeBytes)]
	return ok
}

func raisedUpdateChannelInfo(events []protocol.Event) bool {
	return slices.ContainsFunc(events, func(e protocol.Event) bool {
		return e.Type == protocol.EventTypeActionRequired && e.ActionKind == protocol.ActionKindUpdateChannelInfo
	})
}

// runReplayDetection: the library processes every copy of a message
// delivered within the inbound window, including one delivered back to its
// own sender. An application that records the message id of what it sends
// and accepts drops a replay, a copy whose unauthenticated trace id was
// changed, and a reflection.
func runReplayDetection() {
	fmt.Println("=== Replay detection ===")

	owner := newPeer("owner", "https://owner-replay.example.com", 2)
	helper := newPeer("helper", "https://helper-replay.example.com", 2)
	defer owner.proto.Close()
	defer helper.proto.Close()
	channelID := pairPeers(owner, helper, 61)
	owner.drain()
	ownerSeen, helperSeen := seenEnvelopes{}, seenEnvelopes{}

	_, err := owner.proto.Start(protocol.FlowKindUpdateChannelInfo, protocol.UpdateChannelInfoParams{
		Target:            protocol.TargetOne(channelID),
		CommunicationInfo: map[string]string{"name": "owner-renamed"},
	})
	must(err, "owner Start(UpdateChannelInfo)")
	sent := owner.drain()
	assertTrue(len(sent) == 1, "one update for one channel, got %d", len(sent))
	update := sent[0].message
	ownerSeen.record(update)

	assertTrue(!helperSeen.contains(update), "a first delivery is not in the record")
	events, err := helper.proto.Process(update)
	must(err, "helper Process(update)")
	assertTrue(raisedUpdateChannelInfo(events), "the update must raise ActionRequired, got %+v", events)
	helperSeen.record(update)

	restamped, err := envelope.ApplyTraceID(update, 0x7E57)
	must(err, "envelope.ApplyTraceID")
	assertTrue(!bytes.Equal(restamped, update), "the copy travels as different bytes")
	assertTrue(helperSeen.contains(update), "the replay is recognised")
	assertTrue(helperSeen.contains(restamped), "the re-stamped copy is recognised")
	events, err = helper.proto.Process(restamped)
	must(err, "helper Process(copy)")
	assertTrue(raisedUpdateChannelInfo(events), "unchecked, the library processes the copy again, got %+v", events)
	fmt.Println("  [helper] replay and re-stamped copy share the original's message id  ✓")

	assertTrue(ownerSeen.contains(update), "the reflection is recognised")
	events, err = owner.proto.Process(update)
	must(err, "owner Process(reflected update)")
	assertTrue(raisedUpdateChannelInfo(events), "unchecked, the library reads its own update as the peer's, got %+v", events)
	fmt.Println("  [owner]  reflected update matches an outbound message id  ✓")
	fmt.Println("Replay detection test passed.")
}

// runSupersededShareRequest: a helper that dropped v2 under v3's keepVersion
// does not store v2 again when v2's request is delivered once more: it is
// ignored as Superseded, unanswered.
func runSupersededShareRequest() {
	fmt.Println("=== Superseded share request ===")

	const threshold = 2
	owner := newPeer("owner", "https://owner-superseded.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-superseded.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-superseded.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	channelA := pairPeers(owner, helperA, 63)
	pairPeers(owner, helperB, 64)
	owner.drain()
	owner.shareStore.setKeep(proto.Uint32(0))
	helpers := []*peer{helperA, helperB}

	must(startKeepRound(owner, 0x05, 1), "round 1 Start(ProtectSecret)")
	deliverKeepRound(owner, helpers, nil)

	must(startKeepRound(owner, 0x05, 2), "round 2 Start(ProtectSecret)")
	var v2ForA []byte
	for _, entry := range owner.drain() {
		target := helperB
		if entry.uri == helperA.uri {
			target = helperA
			v2ForA = entry.message
		}
		deliver(target, entry.message)
		for _, answer := range target.drain() {
			deliver(owner, answer.message)
		}
	}
	assertTrue(v2ForA != nil, "v2 was sent to helper-a")

	must(startKeepRound(owner, 0x05, 3), "round 3 Start(ProtectSecret)")
	deliverKeepRound(owner, helpers, nil)
	versions := helperA.shareStore.storedVersions(protocolSecretID)
	assertTrue(slices.Equal(versions, []uint32{3}), "helper-a must hold exactly [3], got %v", versions)

	events, err := helperA.proto.Process(v2ForA)
	must(err, "helper-a Process(v2 again)")
	assertTrue(len(events) == 1 && events[0].Type == protocol.EventTypeMessageIgnored &&
		events[0].Reason == protocol.IgnoreReasonSuperseded && events[0].ChannelID == channelA,
		"v2 delivered again must be MessageIgnored(Superseded), got %+v", events)
	versions = helperA.shareStore.storedVersions(protocolSecretID)
	assertTrue(slices.Equal(versions, []uint32{3}), "helper-a must still hold exactly [3], got %v", versions)
	assertTrue(len(helperA.drain()) == 0, "a superseded request is not answered")
	fmt.Println("  [helper-a] v2 delivered after v3 → MessageIgnored(Superseded), still holds [3]  ✓")
	fmt.Println("Superseded share request test passed.")
}

// runUnconfirmedJoiner: a joiner whose fingerprint is not yet confirmed is
// not a member. The source neither lists it in the roster it publishes nor
// asks it in a version check, and a check whose only member stays silent
// concludes once its budget elapses — mirroring `run_unconfirmed_joiner_flow`
// in smoke-tests/rust/src/protocol.rs.
func runUnconfirmedJoiner() {
	fmt.Println("=== Protocol replica unconfirmed joiner test ===")

	sourceID, destID, joinerID := uint64(0x5050), uint64(0xD1D1), uint64(0xD3D3)
	source, err := newPeerWithConfig("source", "https://source-unconfirmed.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(2),
			ReplicaID: &sourceID,
			Timeouts:  &protocol.Timeouts{GetShareResponseSecs: proto.Uint64(1)},
		},
	})
	must(err, "protocol.New(source)")
	defer source.proto.Close()
	dest := newPeerWithReplicaID("dest", "https://dest-unconfirmed.example.com", 2, &destID)
	joiner := newPeerWithReplicaID("joiner", "https://joiner-unconfirmed.example.com", 2, &joinerID)
	defer dest.proto.Close()
	defer joiner.proto.Close()

	pairingCompleted := func(events []protocol.Event, transient uint64) uint64 {
		for _, ev := range events {
			if ev.Type == protocol.EventTypePairingCompleted && ev.PairingChannelID == transient {
				return ev.ChannelID
			}
		}
		fail("the pairing on %d must complete, got %+v", transient, events)
		return 0
	}

	startReplicaScan(dest, source, 191, protocol.SenderKindReplicaDestination)
	group := pairingCompleted(append(pump(dest, source), pump(source, dest)...), 191)
	crossConfirmFingerprint(source, dest, group)
	pumpMany([]*peer{source, dest})
	assertProtects(source, "unconfirmed joiner")
	pumpMany([]*peer{source, dest})

	startReplicaScan(joiner, source, 192, protocol.SenderKindReplicaDestination)
	pairingCompleted(append(pump(joiner, source), pump(source, joiner)...), 192)
	pumpMany([]*peer{source, dest, joiner})

	assertProtects(source, "unconfirmed joiner")
	var listed []uint64
	received := false
	for _, ev := range pumpMany([]*peer{source, dest, joiner}) {
		if (ev.Type == protocol.EventTypeReplicaSecretReceived || ev.Type == protocol.EventTypeReplicaSecretInstalled) &&
			ev.Secret != nil && ev.Secret.Replicas != nil {
			received = true
			for _, m := range ev.Secret.Replicas.Members {
				listed = append(listed, m.ReplicaID)
			}
		}
	}
	assertTrue(received, "the destination must receive the new version")
	assertTrue(len(listed) == 2, "source and destination only, got %v", listed)
	for _, id := range listed {
		assertTrue(id != joinerID, "an unconfirmed joiner must not be published, got %v", listed)
	}
	fmt.Println("  the published roster leaves out the unconfirmed joiner  ✓")

	_, err = source.proto.Start(protocol.FlowKindReplicaDiscovery, nil)
	must(err, "source.Start(ReplicaDiscovery)")
	concludedAtOnce := false
	for _, ev := range pumpMany([]*peer{source, dest, joiner}) {
		assertTrue(ev.Type != protocol.EventTypeMessageIgnored, "the joiner must not be asked, got %+v", ev)
		if ev.Type == protocol.EventTypeReplicaDiscoveryComplete {
			concludedAtOnce = true
		}
	}
	assertTrue(concludedAtOnce, "the check concludes on the destination's answer")
	fmt.Println("  the version check skips the joiner and concludes at once  ✓")

	_, err = source.proto.Start(protocol.FlowKindReplicaDiscovery, nil)
	must(err, "source.Start(ReplicaDiscovery)")
	source.drain()
	early, err := source.proto.Tick()
	must(err, "source.Tick()")
	assertTrue(len(early) == 0, "the check waits out its window, got %+v", early)
	time.Sleep(2100 * time.Millisecond)
	concluded, err := source.proto.Tick()
	must(err, "source.Tick()")
	assertTrue(len(concluded) == 1 && concluded[0].Type == protocol.EventTypeReplicaDiscoveryComplete &&
		concluded[0].FetchedFrom == nil,
		"expected ReplicaDiscoveryComplete, got %+v", concluded)
	after, err := source.proto.Tick()
	must(err, "source.Tick()")
	assertTrue(len(after) == 0, "the check is closed once concluded, got %+v", after)
	fmt.Println("  a silent member's check concludes on the timeout  ✓")

	fmt.Println("Protocol replica unconfirmed joiner test passed.")
	fmt.Println()
}

// runPairingExpiry: a pairing has a lifetime, timeouts.pairing_secs, and
// both sides enforce it without sending anything. The scanner refuses an
// expired contact, and the creator ignores a request on one and refuses a
// late accept. Pairing involves both parties, so the remedy is a fresh
// contact. Mirrors run_pairing_expiry_flow in smoke-tests/rust/src/protocol.rs.
func runPairingExpiry() {
	fmt.Println("=== Pairing expiry ===")

	shortWindow := func(label, uri string) *peer {
		p, err := newPeerWithConfig(label, uri, protocol.Config{
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				Threshold: proto.Uint32(2),
				Timeouts:  &protocol.Timeouts{PairingSecs: proto.Uint64(1)},
			},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p
	}
	scanAsOwner := func(scanner *peer, contact []byte) error {
		_, err := scanner.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
			Kind:    protocol.SenderKindOwner,
			Contact: contact,
		})
		return err
	}
	createContact := func(creator *peer, channelID uint64) []byte {
		contact, err := creator.proto.CreateContact(&channelID, protocol.ContactModeInlineKeys, nil)
		must(err, fmt.Sprintf("[%s] CreateContact", creator.label))
		return contact.ContactBytes
	}
	isExpired := func(err error) bool {
		var derecErr *derec.Error
		return errors.As(err, &derecErr) && derecErr.Code == derec.CodePairingExpired &&
			derecErr.Category == derec.CategoryPairing
	}

	creatorA := newPeer("helper-expiry-a", "https://helper-expiry-a.example.com", 2)
	scannerA := shortWindow("owner-expiry-a", "https://owner-expiry-a.example.com")
	creatorB := shortWindow("helper-expiry-b", "https://helper-expiry-b.example.com")
	scannerB := newPeer("owner-expiry-b", "https://owner-expiry-b.example.com", 2)
	creatorC := shortWindow("helper-expiry-c", "https://helper-expiry-c.example.com")
	scannerC := newPeer("owner-expiry-c", "https://owner-expiry-c.example.com", 2)
	for _, p := range []*peer{creatorA, scannerA, creatorB, scannerB, creatorC, scannerC} {
		defer p.proto.Close()
	}

	staleContact := createContact(creatorA, 181)
	expiringContact := createContact(creatorB, 182)
	must(scanAsOwner(scannerC, createContact(creatorC, 183)), "scanner-c Start(Pairing)")
	sent := scannerC.drain()
	assertTrue(len(sent) == 1, "scanner-c sends one pair request, got %d", len(sent))
	prompt, err := creatorC.proto.Process(sent[0].message)
	must(err, "creator-c Process(PairRequest)")
	var late *protocol.Event
	for i := range prompt {
		if prompt[i].Type == protocol.EventTypeActionRequired {
			late = &prompt[i]
		}
	}
	assertTrue(late != nil, "creator-c is asked to accept the pairing, got %+v", prompt)

	time.Sleep(2100 * time.Millisecond)

	err = scanAsOwner(scannerA, staleContact)
	assertTrue(isExpired(err), "the scanner must refuse an expired contact with CodePairingExpired, got %v", err)
	assertTrue(len(scannerA.drain()) == 0, "nothing is sent for an expired contact")
	fmt.Println("  [owner] scanning a contact older than the window → CodePairingExpired, nothing sent  ✓")

	must(scanAsOwner(scannerB, expiringContact), "scanner-b Start(Pairing)")
	sent = scannerB.drain()
	assertTrue(len(sent) == 1, "scanner-b sends one pair request, got %d", len(sent))
	events, err := creatorB.proto.Process(sent[0].message)
	must(err, "creator-b Process(PairRequest)")
	assertTrue(len(events) == 1 && events[0].Type == protocol.EventTypeMessageIgnored &&
		events[0].Reason == protocol.IgnoreReasonExpired && events[0].ChannelID == 182,
		"a request on an expired contact must be MessageIgnored(Expired), got %+v", events)
	assertTrue(len(creatorB.drain()) == 0, "the creator does not answer it")
	fmt.Println("  [helper] request on its expired contact → MessageIgnored(Expired), nothing sent  ✓")

	_, err = creatorC.proto.Accept(late.Action)
	assertTrue(isExpired(err), "a late accept must be refused with CodePairingExpired, got %v", err)
	assertTrue(len(creatorC.drain()) == 0, "a refused accept sends nothing")
	channels, err := creatorC.channelStore.ListHelpers(protocolSecretID, protocol.HelperFilter{})
	must(err, "creator-c ListHelpers")
	assertTrue(len(channels) == 0, "a refused accept records no channel, got %+v", channels)
	fmt.Println("  [helper] accepting after the window → CodePairingExpired, no channel, nothing sent  ✓")

	must(scanAsOwner(scannerC, createContact(creatorC, 184)), "scanner-c Start(Pairing) on the fresh contact")
	paired := false
	for _, ev := range pump(scannerC, creatorC) {
		paired = paired || ev.Type == protocol.EventTypePairingCompleted
	}
	assertTrue(paired, "a fresh contact pairs")
	fmt.Println("  [helper] a fresh contact pairs  ✓")

	fmt.Println("Pairing expiry test passed.")
}

// runOwnerKeepVersionAcrossMissedRound: the owner asks KeepVersion once per
// round and sends its answer to every helper. v1 reaches both helpers, v2
// reaches only helper-a, and v3 keeps v1: helper-a drops v2 and helper-b,
// which never stored v2, keeps v1, so both hold exactly v1 and v3.
func runOwnerKeepVersionAcrossMissedRound() {
	fmt.Println("=== Owner keepVersion across a missed round ===")

	const threshold = 2
	owner := newPeer("owner", "https://owner-keep-missed.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-keep-missed.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-keep-missed.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	pairPeers(owner, helperA, 31)
	pairPeers(owner, helperB, 32)
	owner.drain()

	helpers := []*peer{helperA, helperB}
	for round := 1; round <= 3; round++ {
		keep := uint32(1)
		if round == 1 {
			keep = 0
		}
		owner.shareStore.setKeep(&keep)
		must(startKeepRound(owner, 0x04, round), fmt.Sprintf("round %d Start(ProtectSecret)", round))
		var skip *peer
		if round == 2 {
			skip = helperB
		}
		deliverKeepRound(owner, helpers, skip)
	}

	owner.shareStore.mu.Lock()
	calls := append([]uint32(nil), owner.shareStore.keepVersionCalls...)
	owner.shareStore.mu.Unlock()
	assertTrue(slices.Equal(calls, []uint32{1, 2, 3}), "KeepVersion must be asked once per round, got versions %v", calls)
	fmt.Println("  KeepVersion asked once per round with the version being sent  ✓")

	for _, h := range helpers {
		versions := h.shareStore.storedVersions(protocolSecretID)
		assertTrue(slices.Equal(versions, []uint32{1, 3}), "[%s] must keep exactly versions [1 3], got %v", h.label, versions)
	}
	fmt.Println("  both helpers hold exactly [1 3] after the v3 round  ✓")
	fmt.Println("Owner keepVersion test passed.")
}

// runInvalidKeepVersionFailsRound: a keepVersion equal to or greater than
// the version being shared fails Start(ProtectSecret) with
// CodeInvalidKeepVersion before anything is sent.
func runInvalidKeepVersionFailsRound() {
	fmt.Println("=== Invalid keepVersion fails the round ===")

	const threshold = 2
	owner := newPeer("owner", "https://owner-keep-invalid.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-keep-invalid.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-keep-invalid.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	pairPeers(owner, helperA, 41)
	pairPeers(owner, helperB, 42)
	owner.drain()

	must(startKeepRound(owner, 0x05, 1), "round 1 Start(ProtectSecret)")
	deliverKeepRound(owner, []*peer{helperA, helperB}, nil)

	owner.shareStore.setKeep(proto.Uint32(2))
	var startErr *derec.Error
	err := startKeepRound(owner, 0x05, 2)
	assertTrue(errors.As(err, &startErr) && startErr.Code == derec.CodeInvalidKeepVersion,
		"keepVersion 2 for v2 must fail with CodeInvalidKeepVersion (67), got %v", err)
	assertTrue(len(owner.drain()) == 0, "a round with an invalid keepVersion must send nothing")
	fmt.Println("  Start(ProtectSecret) with keepVersion 2 for v2 fails with CodeInvalidKeepVersion and sends nothing  ✓")
	fmt.Println("Invalid keepVersion test passed.")
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

// runExpiredChannelCleanup: with the automatic sweep disabled, a Pending
// replica pairing survives a manual sweep, stays usable afterwards, and once
// Paired is never swept. Mirrors run_expired_channel_cleanup_flow in
// smoke-tests/rust/src/protocol.rs.
//
// The contradictory pair — Enabled false alongside a non-zero timeout — is
// the point: the wrapper must forward both values verbatim and let the
// library decide that a disabled policy ignores its timeout. A wrapper that
// interpreted the flag locally (dropping the timeout, or substituting its
// own default) would still pass a happy-path test, so the config is chosen
// to fail if any interpretation crept into the Go layer.
func runExpiredChannelCleanup() {
	fmt.Println("=== Protocol expired-channel cleanup test ===")

	disabled := func(label, uri string, replicaID uint64) *peer {
		p, err := newPeerWithConfig(label, uri, protocol.Config{
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				Threshold: proto.Uint32(2),
				ReplicaID: &replicaID,
				Timeouts: &protocol.Timeouts{
					ExpiredChannels: &protocol.RemoveExpiredChannelsPolicy{
						Enabled:       false,
						TimeoutInSecs: 900,
					},
				},
			},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p
	}
	owner := disabled("owner", "https://owner-cleanup.example.com", 11)
	replica := disabled("replica", "https://replica-cleanup.example.com", 12)
	defer owner.proto.Close()
	defer replica.proto.Close()

	channelID := pairReplicaHandshake(owner, replica, 0xEC0001)

	// Both ends are Pending until the fingerprints are compared, and with
	// the policy disabled nothing sweeps them.
	removed, err := owner.proto.RemoveExpiredChannels(3600)
	must(err, "owner RemoveExpiredChannels(3600)")
	assertTrue(len(removed) == 0, "a Pending channel younger than the threshold survives the sweep, got %v", removed)
	fmt.Println("  Pending replica pairing survives RemoveExpiredChannels(3600) under a disabled policy  ✓")

	// Still usable: the fingerprint round-trip completes, which it could not
	// had the sweep dropped the channel or its key.
	crossConfirmFingerprint(owner, replica, channelID)
	fmt.Println("  the swept-over pairing still completes its fingerprint round-trip  ✓")

	removed, err = owner.proto.RemoveExpiredChannels(0)
	must(err, "owner RemoveExpiredChannels(0) after verification")
	assertTrue(len(removed) == 0, "Paired channels are out of scope for the sweep, got %v", removed)
	fmt.Println("  Paired channel is never swept  ✓")
	fmt.Println("Protocol expired-channel cleanup test passed.")
}

// testSharedKey is the 32-byte channel key the seeded-store flows plant
// alongside a channel record.
func testSharedKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte((i*11 + 5) & 0xff)
	}
	return key
}

// hasSharedKey reports whether p's SecretStore still holds a SharedKey for
// channelID.
func hasSharedKey(p *peer, channelID uint64) bool {
	_, ok, err := p.secretStore.Load(protocolSecretID, channelID, protocol.SecretKindSharedKey)
	must(err, fmt.Sprintf("[%s] secretStore.Load(%d)", p.label, channelID))
	return ok
}

// hasChannelRecord reports whether p's ChannelStore still holds the record
// addressed by (channelID, replicaID).
func hasChannelRecord(p *peer, channelID, replicaID uint64) bool {
	_, ok, err := p.channelStore.Load(protocolSecretID, channelID, replicaID)
	must(err, fmt.Sprintf("[%s] channelStore.Load(%d, %d)", p.label, channelID, replicaID))
	return ok
}

// assertFingerprintMismatch checks that err is the Pairing-category
// FingerprintMismatch a rejected VerifyFingerprint returns, naming the
// channel it was about.
func assertFingerprintMismatch(err error, channelID uint64, label string) {
	var fpErr *derec.Error
	assertTrue(errors.As(err, &fpErr) && fpErr.Code == derec.CodeFingerprintMismatch && fpErr.Category == derec.CategoryPairing,
		"%s must fail with Pairing/CodeFingerprintMismatch (17), got %v", label, err)
	assertChannelID(fpErr, channelID, label)
}

// assertChannelID checks that err names channelID as the channel it is about.
func assertChannelID(err *derec.Error, channelID uint64, label string) {
	assertTrue(err.ChannelID != nil && *err.ChannelID == channelID,
		"%s must name channel %d, got %v", label, channelID, err.ChannelID)
}

// runFingerprintMismatch: VerifyFingerprint(wrong) on a still-Pending channel
// is the man-in-the-middle case. It must fail with FingerprintMismatch and
// revoke the pairing, so neither the member record nor the channel key
// survives.
func runFingerprintMismatch() {
	fmt.Println("=== Protocol fingerprint mismatch test ===")

	const channelID = uint64(5151)
	const replicaID = uint64(0xcafe)

	node := newPeer("owner", "https://owner-fp-mismatch.example.com", 2)
	defer node.proto.Close()

	// The post-replica-pair state: a Pending member and its shared key,
	// awaiting the fingerprint confirmation that would make it Paired.
	must(node.channelStore.Save(protocolSecretID, protocol.ChannelRecord{Replica: &protocol.ReplicaMember{
		ChannelID:         channelID,
		ReplicaID:         replicaID,
		Transports:        []protocol.TransportEndpoint{{URI: "https://peer.example.com", Protocol: int32(derecpb.Protocol_HTTPS)}},
		CommunicationInfo: map[string]string{},
		Role:              protocol.ReplicaRoleDestination,
		Status:            protocol.ChannelStatusPending,
		CreatedAt:         1700000000,
	}}), "seed replica member")
	must(node.secretStore.Save(protocolSecretID, channelID, protocol.SecretValue{Kind: protocol.SecretKindSharedKey, Bytes: testSharedKey()}),
		"seed shared key")

	assertFingerprintMismatch(node.proto.VerifyFingerprint(channelID, "0000-0000-0000-0000"), channelID, "VerifyFingerprint(wrong)")
	fmt.Println("  verifyFingerprint(wrong) fails with FingerprintMismatch  ✓")

	assertTrue(!hasChannelRecord(node, channelID, replicaID), "VerifyFingerprint(wrong) must remove the member record")
	assertTrue(!hasSharedKey(node, channelID), "VerifyFingerprint(wrong) must remove the channel key")
	fmt.Println("  member record and channel key removed  ✓")

	fmt.Println("Protocol fingerprint mismatch test passed.")
}

// runNoKeysFingerprintMismatch drives the same rejection over a real NoKeys
// pairing: the owner refuses the fingerprint before either side confirmed it.
// Only the rejecting side revokes; the helper's Pending channel is its own
// and stays until it confirms or rejects on its side.
func runNoKeysFingerprintMismatch() {
	fmt.Println("=== Protocol NoKeys fingerprint mismatch test ===")

	owner := newPeer("owner", "https://owner-nokeys-mismatch.example.com", 2)
	helper := newPeer("helper", "https://helper-nokeys-mismatch.example.com", 2)
	defer owner.proto.Close()
	defer helper.proto.Close()

	channelID := pairPeersWithMode(owner, helper, 920, protocol.ContactModeNoKeys)

	assertFingerprintMismatch(owner.proto.VerifyFingerprint(channelID, "0000-0000-0000-0000"), channelID, "owner VerifyFingerprint(wrong)")
	fmt.Println("  owner verifyFingerprint(wrong) fails with FingerprintMismatch  ✓")

	assertTrue(!hasChannelRecord(owner, channelID, 0), "owner must drop the rejected helper channel")
	_, err := owner.proto.GetFingerprint(channelID)
	assertTrue(err != nil, "owner GetFingerprint must fail once the channel key is gone")
	fmt.Println("  owner channel record and key removed  ✓")

	rec, ok, err := helper.channelStore.Load(protocolSecretID, channelID, 0)
	must(err, "helper channelStore.Load")
	assertTrue(ok && rec.Helper.Status == protocol.ChannelStatusPending,
		"helper channel must remain Pending, got ok=%v record=%+v", ok, rec.Helper)
	_, err = helper.proto.GetFingerprint(channelID)
	must(err, "helper GetFingerprint after owner rejection")
	fmt.Println("  helper channel untouched: still Pending, fingerprint derivable  ✓")

	fmt.Println("Protocol NoKeys fingerprint mismatch test passed.")
}

// runExpiredPendingPairingLosesItsKey checks that the expired-channel sweep
// takes a Pending channel's SharedKey with its record, for helper channels and
// replica members alike, while a Paired channel is never swept.
func runExpiredPendingPairingLosesItsKey() {
	fmt.Println("=== Protocol expired Pending channel key cleanup test ===")

	node, err := newPeerWithConfig("owner", "https://owner-expired-key.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(2),
			Timeouts: &protocol.Timeouts{
				ExpiredChannels: &protocol.RemoveExpiredChannelsPolicy{
					Enabled:       false,
					TimeoutInSecs: 900,
				},
			},
		},
	})
	must(err, "protocol.New(expired-key)")
	defer node.proto.Close()

	const (
		pendingHelper  = uint64(6161)
		pendingReplica = uint64(6162)
		pairedHelper   = uint64(6163)
		replicaID      = uint64(0xbeef)
	)
	transports := []protocol.TransportEndpoint{{URI: "https://peer.example.com", Protocol: int32(derecpb.Protocol_HTTPS)}}

	for _, rec := range []protocol.ChannelRecord{
		{Helper: &protocol.HelperChannel{
			ChannelID: pendingHelper, Transports: transports, CommunicationInfo: map[string]string{},
			PeerRole: protocol.SenderKindHelper, Status: protocol.ChannelStatusPending, CreatedAt: 1700000000, Weight: 1,
		}},
		{Replica: &protocol.ReplicaMember{
			ChannelID: pendingReplica, ReplicaID: replicaID, Transports: transports, CommunicationInfo: map[string]string{},
			Role: protocol.ReplicaRoleDestination, Status: protocol.ChannelStatusPending, CreatedAt: 1700000000,
		}},
		{Helper: &protocol.HelperChannel{
			ChannelID: pairedHelper, Transports: transports, CommunicationInfo: map[string]string{},
			PeerRole: protocol.SenderKindHelper, Status: protocol.ChannelStatusPaired, CreatedAt: 1700000000, Weight: 1,
		}},
	} {
		must(node.channelStore.Save(protocolSecretID, rec), "seed channel record")
	}
	for _, cid := range []uint64{pendingHelper, pendingReplica, pairedHelper} {
		must(node.secretStore.Save(protocolSecretID, cid, protocol.SecretValue{Kind: protocol.SecretKindSharedKey, Bytes: testSharedKey()}),
			fmt.Sprintf("seed shared key %d", cid))
	}

	removed, err := node.proto.RemoveExpiredChannels(60)
	must(err, "RemoveExpiredChannels(60)")
	assertTrue(slices.Contains(removed, pendingHelper) && slices.Contains(removed, pendingReplica) && !slices.Contains(removed, pairedHelper),
		"RemoveExpiredChannels must report %d and %d but not %d, got %v", pendingHelper, pendingReplica, pairedHelper, removed)
	fmt.Printf("  sweep removed %v, Paired %d kept  ✓\n", removed, pairedHelper)

	assertTrue(!hasChannelRecord(node, pendingHelper, 0) && !hasSharedKey(node, pendingHelper),
		"expired Pending helper channel %d must lose its record and SharedKey", pendingHelper)
	assertTrue(!hasChannelRecord(node, pendingReplica, replicaID) && !hasSharedKey(node, pendingReplica),
		"expired Pending replica channel %d must lose its record and SharedKey", pendingReplica)
	fmt.Println("  expired Pending channels lost their record and SharedKey  ✓")

	assertTrue(hasChannelRecord(node, pairedHelper, 0) && hasSharedKey(node, pairedHelper),
		"Paired channel %d must keep its record and SharedKey", pairedHelper)
	fmt.Println("  Paired channel kept its record and SharedKey  ✓")

	fmt.Println("Protocol expired Pending channel key cleanup test passed.")
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

	// A negative bound, or a min above a non-zero max, is refused by the
	// library, not by this SDK.
	for _, bad := range []struct {
		label string
		r     protocol.ParameterRange
	}{
		{"a negative min", protocol.ParameterRange{MinShareSize: -1, MaxShareSize: 1 << 20}},
		{"min above a non-zero max", protocol.ParameterRange{MinShareSize: 4096, MaxShareSize: 1024}},
	} {
		cfg = base()
		cfg.ParameterRange = &bad.r
		var rangeErr *derec.Error
		_, err := build(cfg)
		assertTrue(errors.As(err, &rangeErr) && rangeErr.Code == derec.CodeInvalidInput,
			"a ParameterRange with %s must fail New with CodeInvalidInput, got %v", bad.label, err)
	}
	fmt.Println("  malformed ParameterRange (negative, min > max) refused with CodeInvalidInput  ✓")

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
	assertTrue(derec.CodeInvalidKeepVersion == 67,
		"CodeInvalidKeepVersion must be 67, got %d", derec.CodeInvalidKeepVersion)
	assertTrue((&derec.Error{Code: derec.CodeInvalidKeepVersion}).CodeName() == "invalid_keep_version",
		"CodeInvalidKeepVersion must be named invalid_keep_version, got %q", (&derec.Error{Code: derec.CodeInvalidKeepVersion}).CodeName())
	assertTrue(derec.CodeFingerprintCommitmentMismatch == 48,
		"CodeFingerprintCommitmentMismatch must be 48, got %d", derec.CodeFingerprintCommitmentMismatch)
	assertTrue(derec.CategoryStateStore == 15,
		"CategoryStateStore must be 15, got %d", derec.CategoryStateStore)
	assertTrue(derec.CodeTransportSendFailed == 123,
		"CodeTransportSendFailed must be 123, got %d", derec.CodeTransportSendFailed)
	assertTrue(derec.CategoryTransport == 16,
		"CategoryTransport must be 16, got %d", derec.CategoryTransport)
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
	must(source.proto.VerifyFingerprint(replicaChannel, destinationFp), "source.VerifyFingerprint")

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
	must(destination.proto.VerifyFingerprint(replicaChannel, sourceFp), "destination.VerifyFingerprint")
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

// startReplicaScan has scanner start a replica pairing of kind on a fresh
// InlineKeys contact from creator — mirroring `start_replica_scan` in
// smoke-tests/rust/src/protocol.rs. Nothing is delivered.
func startReplicaScan(scanner, creator *peer, transient uint64, kind protocol.SenderKind) {
	contact, err := creator.proto.CreateContact(&transient, protocol.ContactModeInlineKeys, nil)
	must(err, fmt.Sprintf("[%s] CreateContact", creator.label))
	_, err = scanner.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    kind,
		Contact: contact.ContactBytes,
	})
	must(err, fmt.Sprintf("[%s] Start(Pairing)", scanner.label))
}

// assertProtects fails unless owner can start a ProtectSecret round —
// mirroring `assert_protects` in smoke-tests/rust/src/protocol.rs.
func assertProtects(owner *peer, name string) {
	_, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{11}, Name: name, Data: []byte(name)}},
	})
	must(err, fmt.Sprintf("ProtectSecret (%s) must succeed", name))
}

// crossConfirmFingerprint has both ends of a replica channel confirm the
// other's fingerprint.
func crossConfirmFingerprint(a, b *peer, channelID uint64) {
	aFp, err := a.proto.GetFingerprint(channelID)
	must(err, fmt.Sprintf("[%s] GetFingerprint", a.label))
	bFp, err := b.proto.GetFingerprint(channelID)
	must(err, fmt.Sprintf("[%s] GetFingerprint", b.label))
	assertTrue(aFp == bFp, "both ends must derive the same fingerprint, got %q and %q", aFp, bFp)
	must(a.proto.VerifyFingerprint(channelID, bFp), fmt.Sprintf("[%s] VerifyFingerprint", a.label))
	must(b.proto.VerifyFingerprint(channelID, aFp), fmt.Sprintf("[%s] VerifyFingerprint", b.label))
}

// runAbandonedReplicaPairing: a replica pairing the peer never answers leaves
// only a Pending placeholder, so publishing to helpers still works while it
// is in flight, a later confirmed pairing fixes the group channel, and the
// expiry sweep of the abandoned one does not disturb it — mirroring
// `run_abandoned_replica_pairing_flow` in smoke-tests/rust/src/protocol.rs.
func runAbandonedReplicaPairing() {
	fmt.Println("=== Protocol abandoned replica pairing test ===")

	aID, bID, cID := uint64(0xA1A1), uint64(0xB2B2), uint64(0xC3C3)
	a, err := newPeerWithConfig("replica-a", "https://replica-a-abandoned.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(2),
			ReplicaID: &aID,
			Timeouts: &protocol.Timeouts{
				ExpiredChannels: &protocol.RemoveExpiredChannelsPolicy{Enabled: true, TimeoutInSecs: 1},
			},
		},
	})
	must(err, "protocol.New(replica-a)")
	defer a.proto.Close()
	b := newPeerWithReplicaID("replica-b", "https://replica-b-abandoned.example.com", 2, &bID)
	c := newPeerWithReplicaID("replica-c", "https://replica-c-abandoned.example.com", 2, &cID)
	defer b.proto.Close()
	defer c.proto.Close()

	// B never hears of the request.
	startReplicaScan(a, b, 100, protocol.SenderKindReplicaSource)
	a.drain()
	assertProtects(a, "while a replica pairing is pending")
	fmt.Println("  ProtectSecret succeeds while a replica pairing is pending  ✓")

	startReplicaScan(a, c, 200, protocol.SenderKindReplicaSource)
	handshake := append(pump(a, c), pump(c, a)...)
	var groupChannel uint64
	for _, ev := range handshake {
		if ev.Type == protocol.EventTypePairingCompleted && ev.PairingChannelID == 200 {
			groupChannel = ev.ChannelID
		}
	}
	assertTrue(groupChannel != 0, "the pairing with C must complete, got %+v", handshake)
	crossConfirmFingerprint(a, c, groupChannel)
	pumpMany([]*peer{a, c})
	assertProtects(a, "after a later pairing is confirmed")
	pumpMany([]*peer{a, c})
	fmt.Println("  ProtectSecret succeeds after the pairing with C is confirmed  ✓")

	time.Sleep(2100 * time.Millisecond)
	_, err = a.proto.Tick()
	must(err, "replica-a.Tick()")
	assertProtects(a, "after the expiry sweep")
	pumpMany([]*peer{a, c})
	fmt.Println("  ProtectSecret succeeds after the expiry sweep  ✓")

	own, err := a.channelStore.ListReplicas(a.proto.SecretID(), protocol.ReplicaFilter{
		ChannelFilter: protocol.ChannelFilter{IDs: []uint64{aID}},
	})
	must(err, "replica-a.channelStore.ListReplicas")
	assertTrue(len(own) == 1, "A must keep its own row, got %+v", own)
	assertTrue(own[0].ChannelID == groupChannel, "A's own row must be on the confirmed group channel %d, got %d", groupChannel, own[0].ChannelID)
	assertTrue(own[0].Status == protocol.ChannelStatusPaired, "A's own row must be Paired, got %v", own[0].Status)
	fmt.Println("  A's own row is on the C channel and Paired  ✓")

	fmt.Println("Protocol abandoned replica pairing test passed.")
}

// runContactOnTheGroupChannel: a contact naming the replica group's channel
// is refused before anything is sent, the group's traffic is still
// processed, and an expired Pending pairing record on that channel does not
// take the group's key — mirroring `run_contact_on_the_group_channel_flow`
// in smoke-tests/rust/src/protocol.rs.
func runContactOnTheGroupChannel() {
	fmt.Println("=== Protocol contact on the group channel test ===")

	aID, cID := uint64(0xA1A1), uint64(0xC3C3)
	a, err := newPeerWithConfig("replica-a", "https://replica-a-group-contact.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(2),
			ReplicaID: &aID,
			Timeouts: &protocol.Timeouts{
				ExpiredChannels: &protocol.RemoveExpiredChannelsPolicy{Enabled: true, TimeoutInSecs: 1},
			},
		},
	})
	must(err, "protocol.New(replica-a)")
	defer a.proto.Close()
	c := newPeerWithReplicaID("replica-c", "https://replica-c-group-contact.example.com", 2, &cID)
	defer c.proto.Close()
	adversary := newPeer("adversary", "https://adversary-group-contact.example.com", 2)
	defer adversary.proto.Close()

	startReplicaScan(a, c, 200, protocol.SenderKindReplicaSource)
	handshake := append(pump(a, c), pump(c, a)...)
	var groupChannel uint64
	for _, ev := range handshake {
		if ev.Type == protocol.EventTypePairingCompleted && ev.PairingChannelID == 200 {
			groupChannel = ev.ChannelID
		}
	}
	assertTrue(groupChannel != 0, "the pairing with C must complete, got %+v", handshake)
	crossConfirmFingerprint(a, c, groupChannel)
	pumpMany([]*peer{a, c})

	contact, err := adversary.proto.CreateContact(&groupChannel, protocol.ContactModeInlineKeys, nil)
	must(err, "[adversary] CreateContact")
	_, err = a.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindOwner,
		Contact: contact.ContactBytes,
	})
	var pairErr *derec.Error
	assertTrue(errors.As(err, &pairErr) && pairErr.Code == derec.CodeChannelAlreadyPaired,
		"a contact on the group channel %d must be refused with CodeChannelAlreadyPaired, got %v", groupChannel, err)
	assertChannelID(pairErr, groupChannel, "the refused group-channel contact")
	sent := a.drain()
	assertTrue(len(sent) == 0, "nothing is sent for a refused contact, got %d messages", len(sent))
	fmt.Println("  contact on the group channel refused  ✓")

	assertProtects(c, "group traffic after the refused contact")
	for _, ev := range pump(c, a) {
		assertTrue(ev.Type != protocol.EventTypeMessageIgnored,
			"A must still process the group's traffic, got %+v", ev)
	}
	pumpMany([]*peer{a, c})
	fmt.Println("  group traffic still processed  ✓")

	must(a.channelStore.Save(a.proto.SecretID(), protocol.ChannelRecord{Helper: &protocol.HelperChannel{
		ChannelID: groupChannel, Transports: []protocol.TransportEndpoint{}, CommunicationInfo: map[string]string{},
		PeerRole: protocol.SenderKindHelper, Status: protocol.ChannelStatusPending, CreatedAt: 0, Weight: 1,
	}}), "record a pending pairing on the group channel")
	_, err = a.proto.Tick()
	must(err, "replica-a.Tick()")
	assertTrue(hasSharedKey(a, groupChannel),
		"an expired pairing on the group channel %d must not take the group key", groupChannel)
	assertProtects(a, "after the expiry sweep")
	fmt.Println("  expired pairing on the group channel leaves the group key  ✓")

	fmt.Println("Protocol contact on the group channel test passed.")
}

// runRecoverRestoreRepublish protects a weighted secret, loses the owner,
// recovers the secret on a new device at the same endpoint, restores it there
// and republishes with the stored weights. The weights and the threshold reach
// Rust only inside the recovered Secret this SDK re-encodes for Restore, so the
// republish splitting at the original threshold with the original weights
// proves that encoding carried them. The restored device holds no proof of the
// recovered version, so verifying it fails with NoProof and sends nothing.
func runRecoverRestoreRepublish() {
	fmt.Println("=== Protocol recover → restore → republish test ===")

	const ownerURI = "https://owner-restore.example.com"
	owner := newPeer("owner", ownerURI, 2)
	helperA := newPeer("helper-a", "https://helper-a-restore.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-restore.example.com", 2)
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)

	three := uint32(3)
	secretData := []byte("restore-me")
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:   []protocol.UserSecret{{ID: []byte{11}, Name: "restored secret", Data: secretData}},
		Weights:   map[uint64]uint32{channelA: 2},
		Threshold: &three,
	})
	must(err, "owner.Start(ProtectSecret)")
	var v1 uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			v1 = *ev.Version
		}
	}
	assertTrue(v1 != 0, "Start(ProtectSecret) must emit ProtectSecretStarted, got %+v", events)
	pumpMany([]*peer{owner, helperA, helperB})
	owner.proto.Close()

	// The new device pairs with each helper afresh; each helper links its
	// original channel to the new one so the recovery request finds the share
	// stored under the original.
	device := newPeer("device", ownerURI, 2)
	defer device.proto.Close()
	recoveryA := pairPeers(device, helperA, 100)
	recoveryB := pairPeers(device, helperB, 101)
	must(helperA.channelStore.LinkChannel(protocolSecretID, channelA, recoveryA), "helper-a LinkChannel")
	must(helperB.channelStore.LinkChannel(protocolSecretID, channelB, recoveryB), "helper-b LinkChannel")
	all := []*peer{device, helperA, helperB}

	_, err = device.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: protocolSecretID,
		Version:  v1,
	})
	must(err, "device.Start(RecoverSecret)")
	var recovered *protocol.Secret
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeSecretRecovered && ev.Secret != nil {
			recovered = ev.Secret
		}
	}
	assertTrue(recovered != nil, "RecoverSecret must surface SecretRecovered")
	assertTrue(len(recovered.Secrets) == 1 && bytes.Equal(recovered.Secrets[0].Data, secretData),
		"the recovered secret must carry the protected data, got %+v", recovered.Secrets)
	assertTrue(recovered.Threshold != nil && *recovered.Threshold == 3,
		"the recovered secret must carry t=3, got %s", subsharesText(recovered.Threshold))
	recoveredWeights := map[uint64]uint32{}
	for _, h := range recovered.Helpers {
		recoveredWeights[h.ChannelID] = h.Weight
	}
	assertTrue(len(recoveredWeights) == 2 && recoveredWeights[channelA] == 2 && recoveredWeights[channelB] == 1,
		"the recovered secret must carry weights A=2, B=1, got %v", recoveredWeights)
	fmt.Println("  SecretRecovered carries t=3 and weights A=2, B=1  ✓")

	restoreEvents, err := device.proto.Restore(*recovered, v1)
	must(err, "device.Restore")
	started := map[uint64]bool{}
	for _, ev := range restoreEvents {
		assertTrue(ev.Type != protocol.EventTypeUnpaired,
			"Restore must wait for the recovery helpers' answers, got %+v", restoreEvents)
		if ev.Type == protocol.EventTypeUnpairStarted {
			started[ev.ChannelID] = true
		}
	}
	assertTrue(len(started) == 2 && started[recoveryA] && started[recoveryB],
		"Restore must start unpairing both recovery channels, got %+v", restoreEvents)
	for _, c := range []uint64{recoveryA, recoveryB} {
		record, ok, err := device.channelStore.Load(protocolSecretID, c, 0)
		must(err, "device.channelStore.Load")
		assertTrue(ok && record.Helper != nil && record.Helper.Status == protocol.ChannelStatusUnpairing,
			"recovery channel %d must be Unpairing until its helper answers", c)
	}
	// The helpers' acknowledgements land on channels that still exist, so
	// Process ends each one rather than failing on an unknown channel.
	unpaired := map[uint64]bool{}
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeUnpaired {
			unpaired[ev.ChannelID] = true
		}
	}
	assertTrue(unpaired[recoveryA] && unpaired[recoveryB],
		"the recovery helpers' answers must unpair both recovery channels, got %v", unpaired)
	fmt.Println("  Restore unpairs the recovery channels once their helpers answer  ✓")
	snapshot, ok, err := device.userSecrets.LoadLatest(protocolSecretID)
	must(err, "device.userSecrets.LoadLatest")
	assertTrue(ok && snapshot.Version == v1 && subsharesText(snapshot.Threshold) == "3",
		"Restore must store v%d at t=3 over the configured 2, got ok=%v v%d t=%s",
		v1, ok, snapshot.Version, subsharesText(snapshot.Threshold))
	storedWeights := map[uint64]uint32{}
	for _, c := range []uint64{channelA, channelB} {
		record, ok, err := device.channelStore.Load(protocolSecretID, c, 0)
		must(err, "device.channelStore.Load")
		assertTrue(ok && record.Helper != nil, "Restore must write helper channel %d", c)
		storedWeights[c] = record.Helper.Weight
	}
	assertTrue(storedWeights[channelA] == 2 && storedWeights[channelB] == 1,
		"Restore must store weights A=2, B=1, got %v", storedWeights)
	fmt.Println("  Restore stores t=3 and HelperChannel.Weight A=2, B=1  ✓")

	events, err = device.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: snapshot.Secrets,
		Weights: storedWeights,
	})
	must(err, "device.Start(ProtectSecret) after Restore")
	var v2 uint32
	republished := map[uint64]uint32{}
	for _, ev := range events {
		assertTrue(ev.Type != protocol.EventTypeProtectSecretFailed, "republish emitted ProtectSecretFailed: %+v", ev)
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Weight != nil && ev.Version != nil {
			republished[ev.ChannelID] = *ev.Weight
			v2 = *ev.Version
		}
	}
	assertTrue(v2 > v1 && republished[channelA] == 2 && republished[channelB] == 1,
		"the republish must be a newer version with weights A=2, B=1; got v%d %v", v2, republished)
	confirmed := 0
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeShareConfirmed {
			confirmed++
		}
	}
	assertTrue(confirmed == 2, "both helpers must confirm the republish, got %d", confirmed)
	for _, c := range []uint64{channelA, channelB} {
		assertTrue(storedThreshold(device, c, v2) == "3",
			"the republish must split at the restored t=3, got %s", storedThreshold(device, c, v2))
	}
	assertTrue(storedSubshares(device, channelA, v2) == "2" && storedSubshares(device, channelB, v2) == "1",
		"the republish must give A=2, B=1 subshares, got A=%s, B=%s",
		storedSubshares(device, channelA, v2), storedSubshares(device, channelB, v2))
	fmt.Printf("  republish v%d with the stored weights splits at t=3 with A=2, B=1, both helpers confirm  ✓\n", v2)

	events, err = device.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: protocolSecretID,
		Version:  v1,
		Target:   protocol.TargetAll(),
	})
	must(err, "device.Start(VerifyShares) of the recovered version")
	noProof := map[uint64]bool{}
	for _, ev := range events {
		if ev.Type == protocol.EventTypeVerifySharesFailed && ev.Reason == protocol.VerifyFailureReasonNoProof {
			noProof[ev.ChannelID] = true
		}
	}
	assertTrue(noProof[channelA] && noProof[channelB],
		"Restore writes no proof, so verifying v%d must fail with NoProof on both helpers; got %+v", v1, events)
	assertTrue(len(device.drain()) == 0, "no challenge may be sent without a proof to check the answer against")
	fmt.Printf("  verifying the recovered v%d → VerifySharesFailed(NoProof) on both helpers, nothing sent  ✓\n", v1)

	fmt.Println("Protocol recover → restore → republish test passed.")
}

// runSilentHelperRecovery recovers with three helpers while one never
// receives its request — mirroring `run_silent_helper_recovery_flow` in
// smoke-tests/rust/src/protocol.rs. Nothing is decided while that helper's
// answer is due; once get_share_response has elapsed, Tick reports it as
// timed out and settles the recovery on the two shares it holds.
func runSilentHelperRecovery() {
	fmt.Println("=== Protocol silent helper recovery test ===")

	owner, err := newPeerWithConfig("owner", "https://owner-silent.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold: proto.Uint32(2),
			Timeouts:  &protocol.Timeouts{GetShareResponseSecs: proto.Uint64(1)},
		},
	})
	must(err, "protocol.New(owner)")
	defer owner.proto.Close()
	helperA := newPeer("helper-a", "https://helper-a-silent.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-silent.example.com", 2)
	helperC := newPeer("helper-c", "https://helper-c-silent.example.com", 2)
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	defer helperC.proto.Close()

	pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)
	channelC := pairPeers(owner, helperC, 3)

	secretData := []byte("three helpers, one silent")
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{9}, Name: "silent-helper secret", Data: secretData}},
	})
	must(err, "owner.Start(ProtectSecret)")
	var version uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			version = *ev.Version
		}
	}
	assertTrue(version != 0, "Start(ProtectSecret) must emit ProtectSecretStarted, got %+v", events)
	pumpMany([]*peer{owner, helperA, helperB, helperC})

	_, err = owner.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: protocolSecretID,
		Version:  version,
	})
	must(err, "owner.Start(RecoverSecret)")

	// helper-c never sees its request.
	var recoveryEvents []protocol.Event
	for _, entry := range owner.drain() {
		switch entry.uri {
		case helperA.uri:
			recoveryEvents = append(recoveryEvents, deliver(helperA, entry.message)...)
		case helperB.uri:
			recoveryEvents = append(recoveryEvents, deliver(helperB, entry.message)...)
		}
	}
	recoveryEvents = append(recoveryEvents, pumpMany([]*peer{owner, helperA, helperB})...)

	received := 0
	for _, ev := range recoveryEvents {
		assertTrue(ev.Type != protocol.EventTypeSecretRecovered,
			"nothing is decided while helper-c's answer is due, got %+v", recoveryEvents)
		if ev.Type == protocol.EventTypeRecoveryShareReceived {
			received++
		}
	}
	assertTrue(received == 2, "helper-a and helper-b must answer, got %d shares", received)
	idle, err := owner.proto.Tick()
	must(err, "owner.Tick() inside the window")
	assertTrue(len(idle) == 0, "the recovery must wait out its window, got %+v", idle)
	fmt.Println("  two of three helpers answer → no SecretRecovered, Tick() empty  ✓")

	time.Sleep(2100 * time.Millisecond)
	settled, err := owner.proto.Tick()
	must(err, "owner.Tick() after the window")
	assertTrue(len(settled) == 2, "expected a timeout then SecretRecovered, got %+v", settled)
	failed, recovered := settled[0], settled[1]
	assertTrue(failed.Type == protocol.EventTypeRecoverSecretFailed && failed.ChannelID == channelC &&
		failed.Version != nil && *failed.Version == version && failed.Error == "timeout",
		"helper-c must be reported as timed out, got %+v", failed)
	assertTrue(recovered.Type == protocol.EventTypeSecretRecovered && recovered.Secret != nil,
		"the recovery must settle as SecretRecovered, got %+v", recovered)
	carried := false
	for _, s := range recovered.Secret.Secrets {
		if bytes.Equal(s.ID, []byte{9}) && bytes.Equal(s.Data, secretData) {
			carried = true
		}
	}
	assertTrue(carried, "the recovered secret must carry the protected bytes, got %+v", recovered.Secret.Secrets)
	fmt.Println("  after the window Tick() → [RecoverSecretFailed(helper-c, \"timeout\"), SecretRecovered]  ✓")

	closed, err := owner.proto.Tick()
	must(err, "owner.Tick() after the decision")
	assertTrue(len(closed) == 0, "the recovery is closed once decided, got %+v", closed)
	fmt.Println("  Tick() afterwards is empty  ✓")

	fmt.Println("Protocol silent helper recovery test passed.")
}

// disputeSecretID is the secret both owners of the dispute scenarios protect,
// so the two splits share a secret id and a version.
const disputeSecretID uint64 = 44

// newPeerWithSecretID builds a peer of secretID at threshold, addressed by an
// HTTPS own transport at uri.
func newPeerWithSecretID(label, uri string, secretID uint64, threshold uint32) *peer {
	p, err := newPeerFromConfig(label, protocol.Config{
		SecretID: secretID,
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:     proto.Uint32(threshold),
			OwnTransports: []protocol.TransportProtocolParam{{URI: uri, Protocol: int32(derecpb.Protocol_HTTPS)}},
		},
	})
	must(err, fmt.Sprintf("protocol.New(%s)", label))
	return p
}

// newDisputeOwner builds an owner of disputeSecretID at threshold.
func newDisputeOwner(label, uri string, threshold uint32) *peer {
	return newPeerWithSecretID(label, uri, disputeSecretID, threshold)
}

// protectAcross publishes one secret named name from owner to helpers and
// returns the version it published — mirroring `protect_across` in
// smoke-tests/rust/src/protocol.rs.
func protectAcross(owner *peer, helpers []*peer, name string) uint32 {
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{10}, Name: name, Data: []byte(name)}},
	})
	must(err, fmt.Sprintf("[%s] Start(ProtectSecret)", owner.label))
	var version uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			version = *ev.Version
		}
	}
	assertTrue(version != 0, "[%s] the round must report the version it published, got %+v", owner.label, events)
	pumpMany(append([]*peer{owner}, helpers...))
	return version
}

// heldShare loads the one share p's share store holds for channel and
// version.
func heldShare(p *peer, channel uint64, version uint32) protocol.Share {
	shares, err := p.shareStore.Load(p.proto.SecretID(), channel, []uint32{version})
	must(err, fmt.Sprintf("[%s] shareStore.Load", p.label))
	assertTrue(len(shares) == 1, "[%s] must hold one share for channel %d v%d, got %d", p.label, channel, version, len(shares))
	return shares[0]
}

// transplantShare overwrites the bytes to holds on toChannel for version with
// the bytes from holds on fromChannel, through the helpers' own share stores
// — mirroring `transplant_share` in smoke-tests/rust/src/protocol.rs.
func transplantShare(from *peer, fromChannel uint64, to *peer, toChannel uint64, version uint32) {
	held := heldShare(to, toChannel, version)
	held.Bytes = heldShare(from, fromChannel, version).Bytes
	must(to.shareStore.Save(to.proto.SecretID(), toChannel, held), fmt.Sprintf("[%s] shareStore.Save", to.label))
}

// recoverWithTwoOfFiveFromAnotherSplit has owner A (threshold 3) protect
// "owner-a secret" across five helpers that advertise themselves as
// helper-1..helper-5, and owner B (bThreshold) protect "owner-b secret" at the
// same secret id and version across three helpers of its own. The shares
// helper-4 and helper-5 hold for A are then replaced with two of B's, and A
// recovers with all five answering — mirroring
// `recover_with_two_of_five_from_another_split` in
// smoke-tests/rust/src/protocol.rs. Returns the recovery's events and A's
// five helper channels.
func recoverWithTwoOfFiveFromAnotherSplit(tag string, bThreshold uint32) ([]protocol.Event, []uint64) {
	owner := newDisputeOwner("owner-a", "https://owner-a-"+tag+".example.com", 3)
	defer owner.proto.Close()
	helpers := make([]*peer, 5)
	channels := make([]uint64, 5)
	for i := range helpers {
		label := fmt.Sprintf("helper-%d", i+1)
		helpers[i] = newPeer(label, "https://"+label+"-"+tag+".example.com", 2)
		defer helpers[i].proto.Close()
		must(helpers[i].proto.SetCommunicationInfo(map[string]string{"name": label}), label+" SetCommunicationInfo")
		channels[i] = pairPeers(owner, helpers[i], uint64(10+i))
	}
	version := protectAcross(owner, helpers, "owner-a secret")

	other := newDisputeOwner("owner-b", "https://owner-b-"+tag+".example.com", bThreshold)
	defer other.proto.Close()
	xs := make([]*peer, 3)
	xChannels := make([]uint64, 3)
	for i := range xs {
		label := fmt.Sprintf("x%d", i+1)
		xs[i] = newPeer(label, "https://"+label+"-"+tag+".example.com", 2)
		defer xs[i].proto.Close()
		xChannels[i] = pairPeers(other, xs[i], uint64(21+i))
	}
	otherVersion := protectAcross(other, xs, "owner-b secret")
	assertTrue(otherVersion == version, "both splits must be of the same version, got v%d and v%d", version, otherVersion)

	transplantShare(xs[0], xChannels[0], helpers[3], channels[3], version)
	transplantShare(xs[1], xChannels[1], helpers[4], channels[4], version)

	_, err := owner.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: disputeSecretID,
		Version:  version,
	})
	must(err, "owner-a.Start(RecoverSecret)")
	events := pumpMany(append([]*peer{owner}, helpers...))
	for _, ev := range events {
		assertTrue(ev.Type != protocol.EventTypeRecoveryShareCorrupted,
			"a share of another split is not evidence against its helper, got %+v", events)
	}
	return events, channels
}

func recoveryHelperChannels(helpers []protocol.RecoveryHelper) []uint64 {
	out := make([]uint64, len(helpers))
	for i, h := range helpers {
		out[i] = h.ChannelID
	}
	return out
}

func recoveryHelperNames(helpers []protocol.RecoveryHelper) []string {
	out := make([]string, len(helpers))
	for i, h := range helpers {
		out[i] = h.CommunicationInfo["name"]
	}
	return out
}

// runDisputedRecovery: three helpers back the owner's split; two hold valid
// shares of another split that cannot reconstruct. The library cannot tell
// which side is the owner's, so it reports RecoveryDisputed naming both
// sides — mirroring `run_disputed_recovery_flow` in
// smoke-tests/rust/src/protocol.rs.
func runDisputedRecovery() {
	fmt.Println("=== Protocol disputed recovery test ===")

	events, channels := recoverWithTwoOfFiveFromAnotherSplit("disputed", 3)
	var disputed *protocol.Event
	for i := range events {
		assertTrue(events[i].Type != protocol.EventTypeSecretRecovered,
			"a disputed secret is never reported as recovered, got %+v", events)
		if events[i].Type == protocol.EventTypeRecoveryDisputed {
			disputed = &events[i]
		}
	}
	assertTrue(disputed != nil, "expected RecoveryDisputed, got %+v", events)
	assertTrue(disputed.Secret != nil && len(disputed.Secret.Secrets) > 0 && disputed.Secret.Secrets[0].Name == "owner-a secret",
		"the disputed secret must be owner A's, got %+v", disputed.Secret)
	assertTrue(slices.Equal(recoveryHelperChannels(disputed.SupportedBy), channels[:3]),
		"supported_by must be helper-1..3's channels, got %v", recoveryHelperChannels(disputed.SupportedBy))
	assertTrue(slices.Equal(recoveryHelperChannels(disputed.DisputedBy), channels[3:]),
		"disputed_by must be helper-4..5's channels, got %v", recoveryHelperChannels(disputed.DisputedBy))
	assertTrue(slices.Equal(recoveryHelperNames(disputed.SupportedBy), []string{"helper-1", "helper-2", "helper-3"}),
		"each side names the helpers as they advertised themselves, got %v", recoveryHelperNames(disputed.SupportedBy))
	assertTrue(slices.Equal(recoveryHelperNames(disputed.DisputedBy), []string{"helper-4", "helper-5"}),
		"disputed_by must name helper-4, helper-5, got %v", recoveryHelperNames(disputed.DisputedBy))
	fmt.Println("  two of five shares from another split → RecoveryDisputed(owner-a secret, [helper-1..3] vs [helper-4, helper-5]), no corruption  ✓")

	fmt.Println("Protocol disputed recovery test passed.")
}

// runConflictingRecovery: the other split was made at threshold 2, so its two
// shares reconstruct too and the library reports RecoveryConflict with both
// candidates — mirroring `run_conflicting_recovery_flow` in
// smoke-tests/rust/src/protocol.rs.
func runConflictingRecovery() {
	fmt.Println("=== Protocol conflicting recovery test ===")

	events, channels := recoverWithTwoOfFiveFromAnotherSplit("conflict", 2)
	var conflict *protocol.Event
	for i := range events {
		if events[i].Type == protocol.EventTypeRecoveryConflict {
			conflict = &events[i]
		}
	}
	assertTrue(conflict != nil, "expected RecoveryConflict, got %+v", events)
	assertTrue(len(conflict.Candidates) == 2, "expected two candidates, got %+v", conflict.Candidates)
	want := []struct {
		name     string
		channels []uint64
	}{{"owner-a secret", channels[:3]}, {"owner-b secret", channels[3:]}}
	for i, w := range want {
		c := conflict.Candidates[i]
		assertTrue(len(c.Secret.Secrets) > 0 && c.Secret.Secrets[0].Name == w.name &&
			slices.Equal(recoveryHelperChannels(c.SupportedBy), w.channels),
			"candidate %d must be (%s, %v), got (%+v, %v)", i, w.name, w.channels, c.Secret.Secrets, recoveryHelperChannels(c.SupportedBy))
	}
	assertTrue(len(conflict.DisputedBy) == 0, "every share is on one side or the other, got %+v", conflict.DisputedBy)
	fmt.Println("  two of five shares from a threshold-2 split → RecoveryConflict[(owner-a secret, helper-1..3), (owner-b secret, helper-4..5)]  ✓")

	fmt.Println("Protocol conflicting recovery test passed.")
}

// runRestoreKeepsHelperDuties: a device that already helps another owner
// recovers and restores its own secret. Restore wipes only the recovery
// channels to its own helpers; the channel to the other owner, and the share
// held for it, survive — mirroring `run_restore_keeps_helper_duties_flow` in
// smoke-tests/rust/src/protocol.rs.
func runRestoreKeepsHelperDuties() {
	fmt.Println("=== Protocol restore keeps helper duties test ===")

	const ownSecretID uint64 = 4545
	lost := newPeerWithSecretID("lost-device", "https://lost-duties.example.com", ownSecretID, 2)
	helperA := newPeer("helper-a", "https://helper-a-duties.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-duties.example.com", 2)
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	channelA := pairPeers(lost, helperA, 1)
	channelB := pairPeers(lost, helperB, 2)
	version := protectAcross(lost, []*peer{helperA, helperB}, "own secret")
	lost.proto.Close()

	device := newPeerWithSecretID("new-device", "https://device-duties.example.com", ownSecretID, 2)
	defer device.proto.Close()

	// The new device helps another owner first.
	otherOwner := newPeerWithSecretID("other-owner", "https://other-duties.example.com", 9090, 2)
	otherHelper := newPeer("other-helper", "https://other-helper-duties.example.com", 2)
	defer otherOwner.proto.Close()
	defer otherHelper.proto.Close()
	dutyChannel := pairPeers(otherOwner, device, 3)
	pairPeers(otherOwner, otherHelper, 4)
	otherVersion := protectAcross(otherOwner, []*peer{device, otherHelper}, "other owner's secret")
	heldForOther := func() int {
		shares, err := device.shareStore.Load(device.proto.SecretID(), dutyChannel, []uint32{otherVersion})
		must(err, "device.shareStore.Load")
		return len(shares)
	}
	assertTrue(heldForOther() == 1, "the device must hold the other owner's share, got %d", heldForOther())

	// Then it recovers its own secret over fresh recovery channels.
	recoveryA := pairPeers(device, helperA, 100)
	recoveryB := pairPeers(device, helperB, 101)
	must(helperA.channelStore.LinkChannel(helperA.proto.SecretID(), channelA, recoveryA), "helper-a LinkChannel")
	must(helperB.channelStore.LinkChannel(helperB.proto.SecretID(), channelB, recoveryB), "helper-b LinkChannel")
	all := []*peer{device, helperA, helperB}

	_, err := device.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: ownSecretID,
		Version:  version,
	})
	must(err, "device.Start(RecoverSecret)")
	var recovered *protocol.Secret
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeSecretRecovered && ev.Secret != nil {
			recovered = ev.Secret
		}
	}
	assertTrue(recovered != nil, "the device must recover its own secret")

	restoreEvents, err := device.proto.Restore(*recovered, version)
	must(err, "device.Restore")
	touched := map[uint64]bool{}
	for _, ev := range restoreEvents {
		switch ev.Type {
		case protocol.EventTypeUnpairStarted, protocol.EventTypeUnpaired, protocol.EventTypeUnpairFailed:
			touched[ev.ChannelID] = true
		}
	}
	assertTrue(!touched[dutyChannel], "restore must not unpair the channel to the other owner, got %+v", restoreEvents)
	assertTrue(touched[recoveryA] && touched[recoveryB], "restore must still wipe both recovery channels, got %+v", restoreEvents)
	fmt.Println("  Restore unpairs both recovery channels, never the channel to the other owner  ✓")
	pumpMany(all)

	record, ok, err := device.channelStore.Load(device.proto.SecretID(), dutyChannel, 0)
	must(err, "device.channelStore.Load")
	assertTrue(ok && record.Helper != nil && record.Helper.Status == protocol.ChannelStatusPaired,
		"the channel to the other owner must survive restore as Paired, got ok=%v %+v", ok, record)
	assertTrue(heldForOther() == 1, "the share held for the other owner must survive restore, got %d", heldForOther())
	fmt.Println("  the channel to the other owner stays Paired and its share stays stored  ✓")

	_, err = otherOwner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: otherOwner.proto.SecretID(),
		Version:  otherVersion,
		Target:   protocol.TargetAll(),
	})
	must(err, "other-owner.Start(VerifyShares)")
	verified := map[uint64]bool{}
	for _, ev := range pumpMany([]*peer{otherOwner, device, otherHelper}) {
		if ev.Type == protocol.EventTypeShareVerified {
			verified[ev.ChannelID] = true
		}
	}
	assertTrue(verified[dutyChannel], "the other owner must still verify the restored device's share, got %v", verified)
	fmt.Println("  the other owner still verifies the restored device's share  ✓")

	fmt.Println("Protocol restore keeps helper duties test passed.")
}

// runHelperShareRefused gives one helper a ParameterRange whose share-size
// bound every share exceeds. The helper refuses the share itself, before any
// ActionRequired, and the owner sees the same status and memo.
func runHelperShareRefused() {
	fmt.Println("=== Protocol helper share-size refusal test ===")

	owner := newPeer("owner", "https://owner-size.example.com", 2)
	helperA, err := newPeerWithConfig("helper-a", "https://helper-a-size.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:      proto.Uint32(2),
			ParameterRange: &protocol.ParameterRange{MinShareSize: 1, MaxShareSize: 16},
		},
	})
	must(err, "protocol.New(helper-a, bounded)")
	helperB := newPeer("helper-b", "https://helper-b-size.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)

	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{12}, Name: "oversized", Data: []byte("larger than sixteen bytes")}},
	})
	must(err, "owner.Start(ProtectSecret)")
	var version uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			version = *ev.Version
		}
	}

	var refused, rejected []protocol.Event
	stored := map[uint64]bool{}
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB}) {
		switch ev.Type {
		case protocol.EventTypeShareRefused:
			refused = append(refused, ev)
		case protocol.EventTypeShareRejected:
			rejected = append(rejected, ev)
		case protocol.EventTypeShareStored:
			stored[ev.ChannelID] = true
		}
	}
	assertTrue(len(refused) == 1 && refused[0].ChannelID == channelA &&
		refused[0].Version != nil && *refused[0].Version == version &&
		refused[0].Status == derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED && refused[0].Memo != "",
		"helper-a must report one ShareRefused(SIZE_LIMIT_EXCEEDED) for v%d, got %+v", version, refused)
	assertTrue(len(rejected) == 1 && rejected[0].ChannelID == channelA &&
		rejected[0].Status == derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED && rejected[0].Memo == refused[0].Memo,
		"the owner must see one ShareRejected(SIZE_LIMIT_EXCEEDED) with the helper's memo, got %+v", rejected)
	assertTrue(!stored[channelA] && stored[channelB], "only helper-b may store its share, got %v", stored)
	held, err := helperA.shareStore.Load(protocolSecretID, channelA, nil)
	must(err, "helper-a shareStore.Load")
	assertTrue(len(held) == 0, "a refused share must not reach the helper's store, got %d", len(held))
	fmt.Printf("  helper-a ShareRefused(SIZE_LIMIT_EXCEEDED, %q); owner ShareRejected with the same status and memo  ✓\n", refused[0].Memo)
	fmt.Println("Protocol helper share-size refusal test passed.")
}

// runProtocolInvalidWeight checks that Start(ProtectSecret) refuses a weight
// that is not below the threshold, and a weight keyed by an id that names no
// paired channel, with CodeInvalidWeight before anything is sent or stored.
func runProtocolInvalidWeight() {
	fmt.Println("=== Protocol invalid weight test ===")

	const threshold = 3
	owner := newPeer("owner", "https://owner-invalid-weight.example.com", threshold)
	helperA := newPeer("helper-a", "https://helper-a-invalid-weight.example.com", threshold)
	helperB := newPeer("helper-b", "https://helper-b-invalid-weight.example.com", threshold)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)
	owner.drain()

	for _, c := range []struct {
		label   string
		weights map[uint64]uint32
	}{
		{"a weight equal to the threshold", map[uint64]uint32{channelA: threshold}},
		{"a weight keyed by the transient pairing id", map[uint64]uint32{1: 2}},
	} {
		var startErr *derec.Error
		_, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
			Secrets: []protocol.UserSecret{{ID: []byte{13}, Name: "invalid weight", Data: []byte("payload")}},
			Weights: c.weights,
		})
		assertTrue(errors.As(err, &startErr) && startErr.Code == derec.CodeInvalidWeight,
			"%s must fail with CodeInvalidWeight (65), got %v", c.label, err)
		assertTrue(len(owner.drain()) == 0, "%s must send nothing", c.label)
		_, ok, err := owner.userSecrets.LoadLatest(protocolSecretID)
		must(err, "owner.userSecrets.LoadLatest")
		assertTrue(!ok, "%s must store no snapshot", c.label)
		fmt.Printf("  %s → CodeInvalidWeight, nothing sent or stored  ✓\n", c.label)
	}
	fmt.Println("Protocol invalid weight test passed.")
}

// runAutoRespondOnFailure is runRequestFailedToken with AutoRespondOnFailure
// on: the library answers the failed request itself, so the RequestFailed event
// carries no token and the owner observes the response the library sent.
func runAutoRespondOnFailure() {
	fmt.Println("=== Protocol failed request answered by the library test ===")

	owner := newPeer("owner", "https://owner-autorespond.example.com", 2)
	helperA, err := newPeerWithConfig("helper-a", "https://helper-a-autorespond.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:            proto.Uint32(2),
			AutoRespondOnFailure: proto.Bool(true),
		},
	})
	must(err, "protocol.New(helper-a, auto-respond)")
	helperB := newPeer("helper-b", "https://helper-b-autorespond.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)

	helperA.shareStore.mu.Lock()
	helperA.shareStore.failSaves = true
	helperA.shareStore.mu.Unlock()
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{14}, Name: "failing", Data: []byte("payload")}},
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
		var target *peer
		switch entry.uri {
		case helperA.uri:
			target = helperA
		case helperB.uri:
			target = helperB
		default:
			fail("no peer for destination uri %s", entry.uri)
		}
		for _, ev := range deliver(target, entry.message) {
			if ev.Type == protocol.EventTypeRequestFailed {
				failed = append(failed, ev)
			}
		}
		for _, reply := range target.drain() {
			ownerEvents = append(ownerEvents, deliver(owner, reply.message)...)
		}
	}
	assertTrue(len(failed) == 1, "helper-a must report one RequestFailed, got %+v", failed)
	rf := failed[0]
	assertTrue(rf.ChannelID == channelA && rf.ActionKind == protocol.ActionKindStoreShare &&
		rf.Responded && len(rf.Action) == 0 && rf.ErrorCode != "" &&
		rf.Status == derecpb.StatusEnum_FAIL && rf.Memo == "request could not be processed",
		"unexpected RequestFailed: %+v", rf)
	fmt.Printf("  helper-a Save fails → RequestFailed(action_kind=%s, responded=true, no token, status=%s, memo=%q)  ✓\n",
		rf.ActionKind, rf.Status, rf.Memo)

	var rejected []protocol.Event
	for _, ev := range ownerEvents {
		if ev.Type == protocol.EventTypeShareRejected {
			rejected = append(rejected, ev)
		}
	}
	assertTrue(len(rejected) == 1 && rejected[0].ChannelID == channelA &&
		rejected[0].Version != nil && *rejected[0].Version == version &&
		rejected[0].Status == derecpb.StatusEnum_FAIL && rejected[0].Memo == "request could not be processed",
		"expected one ShareRejected(FAIL, generic memo) from helper-a, got %+v", rejected)
	fmt.Println("  the library's own response reaches the owner as ShareRejected(status=FAIL, same memo)  ✓")
	fmt.Println("Protocol failed request answered by the library test passed.")
}

// runVerificationResponseVerdicts covers the verdicts on a verification
// answer that does not prove the share: the answer to a challenge a newer one
// replaced is ignored as StaleResponse, a proof over bytes that differ from the
// owner's is ShareVerifyInvalid, and a message whose plaintext envelope
// timestamp differs from the encrypted inner one is ignored as
// TimestampMismatch.
func runVerificationResponseVerdicts() {
	fmt.Println("=== Protocol verification response verdicts test ===")

	owner := newPeer("owner", "https://owner-verdicts.example.com", 2)
	helperA := newPeer("helper-a", "https://helper-a-verdicts.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-verdicts.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)

	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{15}, Name: "verdicts", Data: []byte("verdicts")}},
	})
	must(err, "owner.Start(ProtectSecret)")
	var version uint32
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			version = *ev.Version
		}
	}
	pumpMany([]*peer{owner, helperA, helperB})

	challenge := func() (uint64, []byte) {
		events, err := owner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
			SecretID: protocolSecretID,
			Version:  version,
			Target:   protocol.TargetOne(channelA),
		})
		must(err, "owner.Start(VerifyShares)")
		var traceID uint64
		for _, ev := range events {
			if ev.Type == protocol.EventTypeVerifySharesStarted {
				traceID = ev.TraceID
			}
		}
		sent := owner.drain()
		assertTrue(len(sent) == 1, "VerifyShares on one channel must send one challenge, sent %d", len(sent))
		return traceID, sent[0].message
	}
	answer := func(challenge []byte) []byte {
		deliver(helperA, challenge)
		sent := helperA.drain()
		assertTrue(len(sent) == 1, "helper-a must answer the challenge once, sent %d", len(sent))
		return sent[0].message
	}

	firstTrace, firstChallenge := challenge()
	_, secondChallenge := challenge()
	firstAnswer := answer(firstChallenge)
	secondAnswer := answer(secondChallenge)
	stale, err := owner.proto.Process(firstAnswer)
	must(err, "owner.Process(stale answer)")
	assertTrue(len(stale) == 1 && stale[0].Type == protocol.EventTypeMessageIgnored &&
		stale[0].Reason == protocol.IgnoreReasonStaleResponse && stale[0].ChannelID == channelA &&
		stale[0].TraceID == firstTrace,
		"the replaced challenge's answer must be MessageIgnored(StaleResponse, trace %d), got %+v", firstTrace, stale)
	current, err := owner.proto.Process(secondAnswer)
	must(err, "owner.Process(current answer)")
	assertTrue(slices.ContainsFunc(current, func(ev protocol.Event) bool {
		return ev.Type == protocol.EventTypeShareVerified && ev.ChannelID == channelA
	}), "the current challenge's answer must still verify, got %+v", current)
	fmt.Println("  answer to a replaced challenge → MessageIgnored(StaleResponse); current answer → ShareVerified  ✓")

	// helper-a's stored share no longer matches the bytes the owner holds a
	// proof of, as after storage corruption.
	held, err := helperA.shareStore.Load(protocolSecretID, channelA, []uint32{version})
	must(err, "helper-a shareStore.Load")
	assertTrue(len(held) == 1, "helper-a must hold one share at v%d, got %d", version, len(held))
	var request derecpb.StoreShareRequestMessage
	must(proto.Unmarshal(held[0].Bytes, &request), "decode helper-a's stored StoreShareRequestMessage")
	request.Share[len(request.Share)/2] ^= 0xFF
	corrupted := held[0]
	corrupted.Bytes, err = proto.Marshal(&request)
	must(err, "encode the corrupted StoreShareRequestMessage")
	must(helperA.shareStore.Save(protocolSecretID, channelA, corrupted), "helper-a shareStore.Save(corrupted)")
	_, invalidChallenge := challenge()
	invalid, err := owner.proto.Process(answer(invalidChallenge))
	must(err, "owner.Process(proof over corrupted bytes)")
	assertTrue(len(invalid) == 1 && invalid[0].Type == protocol.EventTypeShareVerifyInvalid &&
		invalid[0].ChannelID == channelA && invalid[0].Version != nil && *invalid[0].Version == version,
		"a proof over corrupted bytes must be ShareVerifyInvalid, got %+v", invalid)
	fmt.Println("  proof over helper-a's corrupted share → ShareVerifyInvalid  ✓")

	_, tsChallenge := challenge()
	var envelope derecpb.DeRecMessage
	must(proto.Unmarshal(tsChallenge, &envelope), "decode the challenge envelope")
	envelope.Timestamp.Nanos = (envelope.Timestamp.Nanos + 1) % 1_000_000_000
	mismatched, err := proto.Marshal(&envelope)
	must(err, "encode the re-stamped envelope")
	ignored, err := helperA.proto.Process(mismatched)
	must(err, "helper-a.Process(mismatched timestamp)")
	assertTrue(len(ignored) == 1 && ignored[0].Type == protocol.EventTypeMessageIgnored &&
		ignored[0].Reason == protocol.IgnoreReasonTimestampMismatch && ignored[0].ChannelID == channelA,
		"a mismatched envelope timestamp must be MessageIgnored(TimestampMismatch), got %+v", ignored)
	assertTrue(len(helperA.drain()) == 0, "a message ignored for its timestamp must not be answered")
	fmt.Println("  envelope timestamp ≠ inner timestamp → MessageIgnored(TimestampMismatch), nothing sent  ✓")

	fmt.Println("Protocol verification response verdicts test passed.")
}

// pairedChannelID returns the long-term channel the pairing on transient
// rotated to, failing when no PairingCompleted names it — mirroring
// `extract_paired_channel_id` in smoke-tests/rust/src/protocol.rs.
func pairedChannelID(events []protocol.Event, transient uint64) uint64 {
	for _, ev := range events {
		if ev.Type == protocol.EventTypePairingCompleted && ev.PairingChannelID == transient {
			return ev.ChannelID
		}
	}
	fail("the pairing on %d must complete, got %+v", transient, events)
	return 0
}

// pairReplicaHandshake drives only the cryptographic handshake of replica
// joining source's group as a Destination; both ends stay Pending until the
// fingerprints are confirmed — mirroring `pair_replica_handshake` in
// smoke-tests/rust/src/protocol.rs.
func pairReplicaHandshake(source, replica *peer, transient uint64) uint64 {
	startReplicaScan(replica, source, transient, protocol.SenderKindReplicaDestination)
	return pairedChannelID(append(pump(replica, source), pump(source, replica)...), transient)
}

// helperStartPair has helper start a Helper pairing on a fresh contact from
// owner; nothing is delivered — mirroring `helper_start_pair` in
// smoke-tests/rust/src/protocol.rs.
func helperStartPair(owner, helper *peer, transient uint64) {
	contact, err := owner.proto.CreateContact(&transient, protocol.ContactModeInlineKeys, nil)
	must(err, fmt.Sprintf("[%s] CreateContact", owner.label))
	_, err = helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindHelper,
		Contact: contact.ContactBytes,
	})
	must(err, fmt.Sprintf("[%s] Start(Pairing)", helper.label))
}

// newReplicaPeer builds a replica-capable peer of secretID at threshold,
// addressed by an HTTPS own transport at uri.
func newReplicaPeer(label, uri string, secretID, replicaID uint64, threshold uint32) *peer {
	p, err := newPeerFromConfig(label, protocol.Config{
		SecretID: secretID,
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:     proto.Uint32(threshold),
			ReplicaID:     &replicaID,
			OwnTransports: []protocol.TransportProtocolParam{{URI: uri, Protocol: int32(derecpb.Protocol_HTTPS)}},
		},
	})
	must(err, fmt.Sprintf("protocol.New(%s)", label))
	return p
}

// channelKey returns the SharedKey p stores for channelID under secretID, or
// nil when it holds none.
func channelKey(p *peer, secretID, channelID uint64) []byte {
	v, ok, err := p.secretStore.Load(secretID, channelID, protocol.SecretKindSharedKey)
	must(err, fmt.Sprintf("[%s] secretStore.Load(%d)", p.label, channelID))
	if !ok {
		return nil
	}
	return v.Bytes
}

// loadChannelKey is channelKey for a key that must be present.
func loadChannelKey(p *peer, secretID, channelID uint64) []byte {
	key := channelKey(p, secretID, channelID)
	assertTrue(key != nil, "[%s] must hold a key for channel %d", p.label, channelID)
	return key
}

// startedVersion is the version the ProtectSecretStarted events of a round
// report, or 0 when there are none.
func startedVersion(events []protocol.Event) uint32 {
	for _, ev := range events {
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			return *ev.Version
		}
	}
	return 0
}

// verifiedChannels collects the channels a ShareVerified names.
func verifiedChannels(events []protocol.Event) map[uint64]bool {
	out := map[uint64]bool{}
	for _, ev := range events {
		if ev.Type == protocol.EventTypeShareVerified {
			out[ev.ChannelID] = true
		}
	}
	return out
}

// replicaArrival returns the first ReplicaSecretInstalled or
// ReplicaSecretReceived on channelID, and whether it was an install, or nil
// when none arrived — mirroring `find_replica_event` in
// smoke-tests/rust/src/protocol.rs.
func replicaArrival(events []protocol.Event, channelID uint64) (*protocol.Event, bool) {
	for i := range events {
		ev := events[i]
		if ev.ChannelID != channelID || ev.Secret == nil || ev.Version == nil {
			continue
		}
		switch ev.Type {
		case protocol.EventTypeReplicaSecretInstalled:
			return &ev, true
		case protocol.EventTypeReplicaSecretReceived:
			return &ev, false
		}
	}
	return nil, false
}

// anyReplicaArrival is replicaArrival on whichever channel the copy came in.
func anyReplicaArrival(events []protocol.Event) *protocol.Event {
	for i := range events {
		ev := events[i]
		if (ev.Type == protocol.EventTypeReplicaSecretInstalled || ev.Type == protocol.EventTypeReplicaSecretReceived) &&
			ev.Secret != nil && ev.Version != nil {
			return &ev
		}
	}
	return nil
}

// rosterSize is the number of members a received secret's roster names.
func rosterSize(secret *protocol.Secret) int {
	if secret.Replicas == nil {
		return 0
	}
	return len(secret.Replicas.Members)
}

// assertHydrated checks that a replica's own stores hold what the source
// published: the snapshot version and secrets, every helper channel, and a
// roster naming exactly one source — mirroring `assert_hydrated` in
// smoke-tests/rust/src/protocol.rs.
func assertHydrated(p *peer, label string, version uint32, helpers, secrets, members int) {
	sid := p.proto.SecretID()
	snapshot, ok, err := p.userSecrets.LoadLatest(sid)
	must(err, fmt.Sprintf("[%s] userSecrets.LoadLatest", label))
	assertTrue(ok, "replica %s must hold a snapshot", label)
	assertTrue(snapshot.Version == version, "replica %s must hold v=%d, got v=%d", label, version, snapshot.Version)
	assertTrue(len(snapshot.Secrets) == secrets, "replica %s secret count: want %d, got %d", label, secrets, len(snapshot.Secrets))
	stored, err := p.channelStore.ListHelpers(sid, protocol.HelperFilter{})
	must(err, fmt.Sprintf("[%s] ListHelpers", label))
	assertTrue(len(stored) == helpers, "replica %s must have materialised %d helper channels, got %d", label, helpers, len(stored))
	roster, err := p.channelStore.ListReplicas(sid, protocol.ReplicaFilter{})
	must(err, fmt.Sprintf("[%s] ListReplicas", label))
	assertTrue(len(roster) == members, "replica %s roster size (includes itself): want %d, got %d", label, members, len(roster))
	sources := 0
	for _, m := range roster {
		if m.Role == protocol.ReplicaRoleSource {
			sources++
		}
	}
	assertTrue(sources == 1, "replica %s roster must name exactly one source, got %d", label, sources)
}

// runProtectSecretPerTargetFailure fans a ProtectSecret out to two helpers
// while the owner's transport fails every send to helper-b: the round reports
// ProtectSecretStarted for helper-a and ProtectSecretFailed for helper-b, and
// Start itself succeeds. Mirrors run_protect_secret_per_target_failure_flow in
// smoke-tests/rust/src/protocol.rs.
func runProtectSecretPerTargetFailure() {
	fmt.Println("=== Protocol ProtectSecret per-target failure test ===")

	owner := newPeerWithSecretID("owner", "https://owner-per-target.example.com", 42, 2)
	helperA := newPeer("helper-a", "https://helper-a-per-target.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-per-target.example.com", 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)

	owner.transport.failURI(helperB.uri)
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{1, 2, 3}, Name: "per-target-failure", Data: []byte("payload")}},
	})
	must(err, "Start(ProtectSecret) must not fail on a per-target failure")

	var started, failed []protocol.Event
	for _, ev := range events {
		switch ev.Type {
		case protocol.EventTypeProtectSecretStarted:
			started = append(started, ev)
		case protocol.EventTypeProtectSecretFailed:
			failed = append(failed, ev)
		}
	}
	assertTrue(len(started) == 1 && started[0].ChannelID == channelA,
		"expected exactly one ProtectSecretStarted, for helper-a; got %+v", started)
	assertTrue(len(failed) == 1 && failed[0].ChannelID == channelB && failed[0].Error == "transport send failed: the message reached none of the peer's endpoints",
		"expected exactly one ProtectSecretFailed with the transport failure, for helper-b; got %+v", failed)
	fmt.Printf("  helper-a: ProtectSecretStarted ✓   helper-b: ProtectSecretFailed(%q)  ✓\n", failed[0].Error)

	fmt.Println("Protocol ProtectSecret per-target failure test passed.")
}

// runReplicaMirrorThenVerify: a Destination that received the Source's copy
// verifies the Source's helpers itself, both for a version pushed to it and
// for one it pulled with ReplicaDiscovery after missing the push. Mirrors
// run_replica_mirror_then_verify_flow in smoke-tests/rust/src/protocol.rs.
func runReplicaMirrorThenVerify() {
	fmt.Println("=== Protocol replica mirror-then-verify test ===")

	source := newReplicaPeer("source", "https://source-mirror.example.com", 0xC0FFEE, 0xAAAAAAAAAAAAAAAA, 2)
	helperA := newPeer("helper-a", "https://helper-a-mirror.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-mirror.example.com", 2)
	destination := newReplicaPeer("destination", "https://destination-mirror.example.com", protocolSecretID, 0xBBBBBBBBBBBBBBBB, 2)
	all := []*peer{source, helperA, helperB, destination}
	for _, p := range all {
		defer p.proto.Close()
	}

	channelA := pairPeers(source, helperA, 1)
	channelB := pairPeers(source, helperB, 2)
	replicaChannel := pairReplicaHandshake(source, destination, 3)
	crossConfirmFingerprint(source, destination, replicaChannel)
	pumpMany(all)

	_, err := source.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{1}, Name: "mirrored secret", Data: []byte("vault-contents")}},
	})
	must(err, "source.Start(ProtectSecret)")
	mirrored := anyReplicaArrival(pumpMany(all))
	assertTrue(mirrored != nil, "the destination must report the mirrored vault")
	assertTrue(len(mirrored.Shares) == 2, "the mirrored payload must carry one share per helper, got %d", len(mirrored.Shares))
	mirroredVersion := *mirrored.Version

	destinationSID := destination.proto.SecretID()
	for _, ch := range []uint64{channelA, channelB} {
		tracked, err := destination.shareStore.Load(destinationSID, ch, []uint32{mirroredVersion})
		must(err, "destination shareStore.Load")
		assertTrue(len(tracked) == 1 && len(tracked[0].Bytes) != 0,
			"the destination must hold a tracking share for helper channel %d at v%d, got %d", ch, mirroredVersion, len(tracked))
	}

	_, err = destination.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: destinationSID,
		Version:  mirroredVersion,
		Target:   protocol.TargetAll(),
	})
	must(err, "destination.Start(VerifyShares)")
	verified := verifiedChannels(pumpMany(all))
	assertTrue(verified[channelA] && verified[channelB],
		"a destination holding a mirrored vault must verify the helpers that hold its shares; verified %v", verified)
	fmt.Printf("  destination verifies both helpers for pushed v%d  ✓\n", mirroredVersion)

	events, err := source.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{1}, Name: "mirrored secret", Data: []byte("vault-contents-v2")}},
	})
	must(err, "source.Start(ProtectSecret) of the missed round")
	missedVersion := startedVersion(events)
	assertTrue(missedVersion > mirroredVersion, "the missed round must be newer, got v%d after v%d", missedVersion, mirroredVersion)
	// The destination's copy of this round is dropped, leaving it behind.
	for _, entry := range source.drain() {
		switch entry.uri {
		case helperA.uri:
			deliver(helperA, entry.message)
		case helperB.uri:
			deliver(helperB, entry.message)
		}
	}
	pumpMany([]*peer{source, helperA, helperB})

	_, err = destination.proto.Start(protocol.FlowKindReplicaDiscovery, nil)
	must(err, "destination.Start(ReplicaDiscovery)")
	caughtUp := false
	for _, ev := range pumpMany(all) {
		if ev.Type == protocol.EventTypeReplicaSecretReceived && ev.Version != nil && *ev.Version == missedVersion {
			caughtUp = true
		}
	}
	assertTrue(caughtUp, "the catch-up must hydrate the missed v%d", missedVersion)

	_, err = destination.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: destinationSID,
		Version:  missedVersion,
		Target:   protocol.TargetAll(),
	})
	must(err, "destination.Start(VerifyShares) after the catch-up")
	verified = verifiedChannels(pumpMany(all))
	assertTrue(verified[channelA] && verified[channelB],
		"a version obtained by catch-up must be as verifiable as one received by push; verified %v", verified)
	fmt.Printf("  destination verifies both helpers for pulled v%d  ✓\n", missedVersion)

	fmt.Println("Protocol replica mirror-then-verify test passed.")
}

// runReplicaRosterDescribesEveryMember: a published roster describes every
// member the same way, the publisher included — every endpoint in preference
// order and its communication_info — and the destination stores each member
// so. Mirrors run_replica_roster_describes_every_member_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplicaRosterDescribesEveryMember() {
	fmt.Println("=== Protocol replica roster describes every member test ===")

	sourceID, destinationID := uint64(0xCCCCCCCCCCCCCCCC), uint64(0xDDDDDDDDDDDDDDDD)
	identity := func(label, name string, replicaID uint64) (*peer, []string) {
		endpoints := []string{"https://" + label + ".example.com", "grpcs://" + label + ".example.com:443"}
		p, err := newPeerFromConfig(label, protocol.Config{
			SecretID: protocolSecretID,
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				Threshold: proto.Uint32(2),
				ReplicaID: &replicaID,
				OwnTransports: []protocol.TransportProtocolParam{
					{URI: endpoints[0], Protocol: int32(derecpb.Protocol_HTTPS)},
					{URI: endpoints[1], Protocol: int32(derecpb.Protocol_GRPC)},
				},
				CommunicationInfo: map[string]string{"name": name},
			},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p, endpoints
	}
	source, sourceEndpoints := identity("roster-source", "Alice-1", sourceID)
	destination, destinationEndpoints := identity("roster-destination", "Alice-2", destinationID)
	defer source.proto.Close()
	defer destination.proto.Close()

	groupChannel := pairReplicaHandshake(source, destination, 0x0570)
	crossConfirmFingerprint(source, destination, groupChannel)
	pumpMany([]*peer{source, destination})

	_, err := source.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{1}, Name: "roster secret", Data: []byte("roster-contents")}},
	})
	must(err, "source.Start(ProtectSecret)")
	events := pumpMany([]*peer{source, destination})
	var secret *protocol.Secret
	for i := len(events) - 1; i >= 0 && secret == nil; i-- {
		ev := events[i]
		if (ev.Type == protocol.EventTypeReplicaSecretReceived || ev.Type == protocol.EventTypeReplicaSecretInstalled) && ev.Secret != nil {
			secret = ev.Secret
		}
	}
	assertTrue(secret != nil && secret.Replicas != nil, "the destination must receive the published secret with its roster")

	want := []struct {
		replicaID uint64
		endpoints []string
		name      string
	}{{sourceID, sourceEndpoints, "Alice-1"}, {destinationID, destinationEndpoints, "Alice-2"}}

	members := secret.Replicas.Members
	assertTrue(len(members) == 2, "both members are published, got %+v", members)
	for _, w := range want {
		idx := slices.IndexFunc(members, func(m protocol.Replica) bool { return m.ReplicaID == w.replicaID })
		assertTrue(idx >= 0, "member %#x missing from %+v", w.replicaID, members)
		var uris []string
		for _, t := range members[idx].Transports {
			uris = append(uris, t.URI)
		}
		assertTrue(slices.Equal(uris, w.endpoints) && members[idx].CommunicationInfo["name"] == w.name,
			"published row for %s: want (%v, %s), got (%v, %v)", w.name, w.endpoints, w.name, uris, members[idx].CommunicationInfo)
	}
	fmt.Println("  published roster names and reaches the writer as well as its peer  ✓")

	stored, err := destination.channelStore.ListReplicas(destination.proto.SecretID(), protocol.ReplicaFilter{})
	must(err, "destination ListReplicas")
	for _, w := range want {
		idx := slices.IndexFunc(stored, func(m protocol.ReplicaMember) bool { return m.ReplicaID == w.replicaID })
		assertTrue(idx >= 0, "destination holds no row for %#x", w.replicaID)
		var uris []string
		for _, t := range stored[idx].Transports {
			uris = append(uris, t.URI)
		}
		assertTrue(slices.Equal(uris, w.endpoints) && stored[idx].CommunicationInfo["name"] == w.name,
			"destination's stored row for %s: want (%v, %s), got (%v, %v)", w.name, w.endpoints, w.name, uris, stored[idx].CommunicationInfo)
	}
	fmt.Println("  destination stores every member, itself included, the same way  ✓")

	fmt.Println("Protocol replica roster describes every member test passed.")
}

// runReplicaVerifiesOnlySyncedVersions: a Destination paired after v1 is
// synced v2 only. Restore on it is refused as already provisioned, both
// devices verify v2, and only the source verifies v1: the Destination fails
// each channel with NoProof and sends nothing. Mirrors
// run_replica_verifies_only_synced_versions_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplicaVerifiesOnlySyncedVersions() {
	fmt.Println("=== Protocol replica verifies only synced versions test ===")

	alice := newReplicaPeer("alice", "https://alice-synced.example.com", 0xC0FFEE, 0xA11CE, 2)
	h1 := newPeer("helper-1", "https://helper-1-synced.example.com", 2)
	h2 := newPeer("helper-2", "https://helper-2-synced.example.com", 2)
	h3 := newPeer("helper-3", "https://helper-3-synced.example.com", 2)
	bob := newReplicaPeer("bob", "https://bob-synced.example.com", protocolSecretID, 0xB0B, 2)
	all := []*peer{alice, h1, h2, h3, bob}
	for _, p := range all {
		defer p.proto.Close()
	}

	helperChannels := []uint64{pairPeers(alice, h1, 1), pairPeers(alice, h2, 2), pairPeers(alice, h3, 3)}
	events, err := alice.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{{ID: []byte{1}, Name: "wallet", Data: []byte("alice-secret-v1")}},
	})
	must(err, "alice.Start(ProtectSecret) v1")
	v1 := startedVersion(events)
	assertTrue(v1 != 0, "v1 must report a version, got %+v", events)
	pumpMany([]*peer{alice, h1, h2, h3})

	replicaChannel := pairReplicaHandshake(alice, bob, 4)
	crossConfirmFingerprint(alice, bob, replicaChannel)
	synced := anyReplicaArrival(pumpMany(all))
	assertTrue(synced != nil, "bob must be synced when he joins the roster")
	v2 := *synced.Version
	assertTrue(v2 > v1, "joining must publish a newer version (v1=%d, v2=%d)", v1, v2)

	_, err = bob.proto.Restore(*synced.Secret, v2)
	var restoreErr *derec.Error
	assertTrue(errors.As(err, &restoreErr) && restoreErr.Code == derec.CodeAlreadyRestored,
		"a synced destination is already provisioned; Restore must refuse it with CodeAlreadyRestored, got %v", err)
	fmt.Println("  Restore on a synced destination → CodeAlreadyRestored  ✓")

	aliceSID, bobSID := alice.proto.SecretID(), bob.proto.SecretID()
	for _, ch := range helperChannels {
		for _, c := range []struct {
			label    string
			p        *peer
			sid      uint64
			version  uint32
			expected int
		}{
			{"alice", alice, aliceSID, v1, 1},
			{"alice", alice, aliceSID, v2, 1},
			{"bob", bob, bobSID, v1, 0},
			{"bob", bob, bobSID, v2, 1},
		} {
			rows, err := c.p.shareStore.Load(c.sid, ch, []uint32{c.version})
			must(err, c.label+" shareStore.Load")
			assertTrue(len(rows) == c.expected, "%s must hold %d tracking share(s) for helper %d at v%d, got %d",
				c.label, c.expected, ch, c.version, len(rows))
		}
	}

	verify := func(p *peer, sid uint64, version uint32) map[uint64]bool {
		_, err := p.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
			SecretID: sid,
			Version:  version,
			Target:   protocol.TargetAll(),
		})
		must(err, fmt.Sprintf("%s.Start(VerifyShares v%d)", p.label, version))
		return verifiedChannels(pumpMany(all))
	}
	for _, c := range []struct {
		p       *peer
		sid     uint64
		version uint32
	}{{alice, aliceSID, v2}, {bob, bobSID, v2}, {alice, aliceSID, v1}} {
		verified := verify(c.p, c.sid, c.version)
		for _, ch := range helperChannels {
			assertTrue(verified[ch], "%s must verify v%d against all three helpers; verified %v", c.p.label, c.version, verified)
		}
	}

	events, err = bob.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: bobSID,
		Version:  v1,
		Target:   protocol.TargetAll(),
	})
	must(err, "a missing proof fails its channel, not the round")
	noProof := map[uint64]bool{}
	for _, ev := range events {
		if ev.Type == protocol.EventTypeVerifySharesFailed && ev.Reason == protocol.VerifyFailureReasonNoProof {
			noProof[ev.ChannelID] = true
		}
	}
	for _, ch := range helperChannels {
		assertTrue(noProof[ch], "bob holds no v1 bytes, so every helper channel fails with NoProof; got %+v", events)
	}
	assertTrue(len(bob.drain()) == 0, "no v1 challenge is sent without a proof to check the answer against")
	fmt.Printf("  alice: v%d ✓ v%d ✓   bob: v%d NoProof (never synced) v%d ✓  ✓\n", v1, v2, v1, v2)

	fmt.Println("Protocol replica verifies only synced versions test passed.")
}

// runDiscoveryAndRecovery: an owner that lost its snapshot and its channels
// re-pairs with each helper, discovers the secret and its versions through
// Discovery, recovers it, and restores it on a fresh device. Mirrors
// run_discovery_and_recovery_flow in smoke-tests/rust/src/protocol.rs.
func runDiscoveryAndRecovery() {
	fmt.Println("=== Protocol discovery & recovery test ===")

	const protectedSecretID uint64 = 7777
	secretIDBytes := []byte{9, 9, 9}
	secretData := []byte("correct horse battery staple")
	owner := newPeerWithSecretID("owner", "https://owner-discovery.example.com", protectedSecretID, 2)
	helperA := newPeerWithSecretID("helper-a", "https://helper-a-discovery.example.com", protectedSecretID, 2)
	helperB := newPeerWithSecretID("helper-b", "https://helper-b-discovery.example.com", protectedSecretID, 2)
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)
	description := "wallet seed phrase"
	_, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: secretIDBytes, Name: "wallet seed", Data: secretData}},
		Description: &description,
	})
	must(err, "owner.Start(ProtectSecret)")
	stored := map[uint64]bool{}
	confirmed := 0
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB}) {
		switch ev.Type {
		case protocol.EventTypeShareStored:
			stored[ev.ChannelID] = true
		case protocol.EventTypeShareConfirmed:
			confirmed++
		}
	}
	assertTrue(stored[channelA] && stored[channelB] && confirmed == 2,
		"both helpers must store and confirm, got stored=%v confirmed=%d", stored, confirmed)

	must(owner.userSecrets.Remove(protectedSecretID), "owner userSecrets.Remove")

	var rekeyed []uint64
	for i, helper := range []*peer{helperA, helperB} {
		fresh := uint64(100 + i)
		contact, err := owner.proto.CreateContact(&fresh, protocol.ContactModeInlineKeys, nil)
		must(err, "owner.CreateContact(recovery)")
		_, err = helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
			Kind:                  protocol.SenderKindHelper,
			Contact:               contact.ContactBytes,
			PeerCommunicationInfo: map[string]string{"name": "recovering-owner"},
		})
		must(err, fmt.Sprintf("%s Start(Pairing recovery)", helper.label))
		rekeyed = append(rekeyed, pairedChannelID(pumpMany([]*peer{owner, helper}), fresh))
	}
	recoveryA, recoveryB := rekeyed[0], rekeyed[1]
	must(helperA.channelStore.LinkChannel(protectedSecretID, channelA, recoveryA), "helper-a LinkChannel")
	must(helperB.channelStore.LinkChannel(protectedSecretID, channelB, recoveryB), "helper-b LinkChannel")
	_, err = owner.channelStore.Remove(protectedSecretID, channelA, 0)
	must(err, "owner remove(channelA)")
	_, err = owner.channelStore.Remove(protectedSecretID, channelB, 0)
	must(err, "owner remove(channelB)")

	_, err = owner.proto.Start(protocol.FlowKindDiscovery, protocol.DiscoveryParams{Target: protocol.TargetMany(recoveryA, recoveryB)})
	must(err, "owner.Start(Discovery)")
	discoveredOn := 0
	var recoverVersion uint32
	foundSecret, describedVersion := false, false
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB}) {
		if ev.Type != protocol.EventTypeSecretsDiscovered {
			continue
		}
		discoveredOn++
		for _, s := range ev.Secrets {
			if s.SecretID != protectedSecretID {
				continue
			}
			foundSecret = true
			for _, v := range s.Versions {
				describedVersion = describedVersion || v.Description == description
				recoverVersion = max(recoverVersion, v.Version)
			}
		}
	}
	assertTrue(discoveredOn > 0, "expected at least one SecretsDiscovered event on the owner")
	assertTrue(foundSecret && recoverVersion != 0, "the discovered list must contain secret %d with a version", protectedSecretID)
	assertTrue(describedVersion, "the version description must be preserved through discovery")
	fmt.Printf("  Discovery → SecretsDiscovered from %d helper(s): secret_id=%d v%d %q  ✓\n",
		discoveredOn, protectedSecretID, recoverVersion, description)

	_, err = owner.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: protectedSecretID,
		Version:  recoverVersion,
	})
	must(err, "owner.Start(RecoverSecret)")
	var recovered *protocol.Secret
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB}) {
		if ev.Type == protocol.EventTypeSecretRecovered && ev.Secret != nil {
			recovered = ev.Secret
		}
	}
	assertTrue(recovered != nil, "expected SecretRecovered on the owner")
	idx := slices.IndexFunc(recovered.Secrets, func(s protocol.UserSecret) bool { return bytes.Equal(s.ID, secretIDBytes) })
	assertTrue(idx >= 0 && bytes.Equal(recovered.Secrets[idx].Data, secretData) && recovered.Secrets[idx].Name == "wallet seed",
		"the recovered secret must carry the protected user secret, got %+v", recovered.Secrets)
	fmt.Printf("  RecoverSecret → UserSecret %q (%dB)  ✓\n", recovered.Secrets[idx].Name, len(recovered.Secrets[idx].Data))

	restored := newPeerWithSecretID("restored-owner", "https://restored-discovery.example.com", protectedSecretID, 2)
	defer restored.proto.Close()
	_, err = restored.proto.Restore(*recovered, recoverVersion)
	must(err, "Restore on a fresh peer")
	snapshot, ok, err := restored.userSecrets.LoadLatest(protectedSecretID)
	must(err, "restored userSecrets.LoadLatest")
	assertTrue(ok && snapshot.Version == recoverVersion, "the restored snapshot must be v%d, got ok=%v v%d", recoverVersion, ok, snapshot.Version)
	assertTrue(slices.ContainsFunc(snapshot.Secrets, func(s protocol.UserSecret) bool {
		return bytes.Equal(s.ID, secretIDBytes) && bytes.Equal(s.Data, secretData)
	}), "the restored snapshot must carry the protected user secret")
	for _, h := range recovered.Helpers {
		record, ok, err := restored.channelStore.Load(protectedSecretID, h.ChannelID, 0)
		must(err, "restored channelStore.Load")
		assertTrue(ok && record.Helper != nil && record.Helper.PeerRole == protocol.SenderKindHelper,
			"restored helper channel %d must exist as a Helper, got ok=%v %+v", h.ChannelID, ok, record)
	}
	fmt.Println("  Restore on a fresh peer writes the snapshot and every helper channel  ✓")

	fmt.Println("Protocol discovery & recovery test passed.")
}

// recoverAfter protects one secret across three helpers, lets damage alter
// helper-a's stored share, and recovers. It then recovers a version no helper
// holds. It returns helper-a's channel, the version, and the events of the
// verification, the recovery and the recovery of the missing version
// (version + 100).
func recoverAfter(tag string, secretID uint64, secret protocol.UserSecret, damage func(helperA *peer, channelA uint64, version uint32)) (uint64, uint32, []protocol.Event, []protocol.Event, []protocol.Event) {
	owner := newPeerWithSecretID("owner", "https://owner-"+tag+".example.com", secretID, 2)
	helperA := newPeer("helper-a", "https://helper-a-"+tag+".example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-"+tag+".example.com", 2)
	helperC := newPeer("helper-c", "https://helper-c-"+tag+".example.com", 2)
	all := []*peer{owner, helperA, helperB, helperC}
	for _, p := range all {
		defer p.proto.Close()
	}
	channelA := pairPeers(owner, helperA, 1)
	pairPeers(owner, helperB, 2)
	pairPeers(owner, helperC, 3)

	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets: []protocol.UserSecret{secret},
	})
	must(err, "owner.Start(ProtectSecret)")
	version := startedVersion(events)
	assertTrue(version != 0, "the round must report the version it published, got %+v", events)
	pumpMany(all)

	damage(helperA, channelA, version)

	_, err = owner.proto.Start(protocol.FlowKindVerifyShares, protocol.VerifySharesParams{
		SecretID: secretID,
		Version:  version,
		Target:   protocol.TargetAll(),
	})
	must(err, "owner.Start(VerifyShares)")
	verifyEvents := pumpMany(all)

	started, err := owner.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: secretID,
		Version:  version,
	})
	must(err, "owner.Start(RecoverSecret)")
	asked := 0
	for _, ev := range started {
		if ev.Type == protocol.EventTypeRecoverSecretStarted {
			asked++
		}
	}
	assertTrue(asked == 3, "every helper is asked for its share, got %d", asked)
	recoveryEvents := pumpMany(all)

	_, err = owner.proto.Start(protocol.FlowKindRecoverSecret, protocol.RecoverSecretParams{
		SecretID: secretID,
		Version:  version + 100,
	})
	must(err, "owner.Start(RecoverSecret) for a missing version")
	return channelA, version, verifyEvents, recoveryEvents, pumpMany(all)
}

// assertRecoveredDespite fails unless the recovery decided SecretRecovered
// carrying secret, never RecoveryIncomplete or RecoveryConflict.
func assertRecoveredDespite(events []protocol.Event, secret protocol.UserSecret, what string) {
	var recovered *protocol.Secret
	for _, ev := range events {
		assertTrue(ev.Type != protocol.EventTypeRecoveryIncomplete && ev.Type != protocol.EventTypeRecoveryConflict,
			"%s must not leave the recovery undecided: %+v", what, events)
		if ev.Type == protocol.EventTypeSecretRecovered && ev.Secret != nil {
			recovered = ev.Secret
		}
	}
	assertTrue(recovered != nil, "the two remaining helpers must complete the recovery, got %+v", events)
	assertTrue(slices.ContainsFunc(recovered.Secrets, func(s protocol.UserSecret) bool {
		return bytes.Equal(s.ID, secret.ID) && bytes.Equal(s.Data, secret.Data)
	}), "the recovered secret must carry the protected bytes, got %+v", recovered.Secrets)
}

// runHelperWithoutTheVersion: one of three helpers no longer holds the
// version. It answers the challenge and the recovery request with
// UNKNOWN_SHARE_VERSION; the owner reports ShareVerifyRejected and
// RecoveryShareRefused and recovers from the other two. Mirrors
// run_helper_without_the_version_flow in smoke-tests/rust/src/protocol.rs.
func runHelperWithoutTheVersion() {
	fmt.Println("=== Protocol helper without the version test ===")

	secret := protocol.UserSecret{ID: []byte{7}, Name: "forgetful-helper secret", Data: []byte("three helpers, one forgetful")}
	channelA, version, verifyEvents, recoveryEvents, missingEvents := recoverAfter("forgetful", 42, secret, func(helperA *peer, channelA uint64, version uint32) {
		must(helperA.shareStore.RemoveVersions(helperA.proto.SecretID(), channelA, []uint32{version}), "helper-a drops its share")
	})

	var rejected []protocol.Event
	verified := 0
	for _, ev := range verifyEvents {
		switch ev.Type {
		case protocol.EventTypeShareVerifyRejected:
			rejected = append(rejected, ev)
		case protocol.EventTypeShareVerified:
			verified++
		}
	}
	assertTrue(len(rejected) == 1 && rejected[0].ChannelID == channelA && rejected[0].Status == derecpb.StatusEnum_UNKNOWN_SHARE_VERSION,
		"helper-a must refuse the challenge with UNKNOWN_SHARE_VERSION, got %+v", rejected)
	assertTrue(verified == 2, "helper-b and helper-c still prove possession, got %d", verified)
	fmt.Println("  VerifyShares → ShareVerifyRejected(helper-a, UNKNOWN_SHARE_VERSION), two ShareVerified  ✓")

	var refused []protocol.Event
	for _, ev := range recoveryEvents {
		if ev.Type == protocol.EventTypeRecoveryShareRefused {
			refused = append(refused, ev)
		}
	}
	assertTrue(len(refused) == 1 && refused[0].ChannelID == channelA && refused[0].Version != nil && *refused[0].Version == version &&
		refused[0].Status == derecpb.StatusEnum_UNKNOWN_SHARE_VERSION,
		"the app sees exactly one refusal, from helper-a, got %+v", refused)
	assertRecoveredDespite(recoveryEvents, secret, "a refusal")
	fmt.Println("  RecoverSecret → RecoveryShareRefused(helper-a, UNKNOWN_SHARE_VERSION), SecretRecovered from the rest  ✓")

	var incomplete []protocol.Event
	for _, ev := range missingEvents {
		if ev.Type == protocol.EventTypeRecoveryIncomplete {
			incomplete = append(incomplete, ev)
		}
	}
	assertTrue(len(incomplete) == 1 && incomplete[0].SecretID == 42 && incomplete[0].Version != nil &&
		*incomplete[0].Version == version+100 && incomplete[0].SharesReceived == 0,
		"a version no helper holds closes as RecoveryIncomplete naming its secret, got %+v", missingEvents)
	fmt.Println("  RecoverSecret for a version no helper holds → RecoveryIncomplete(secret 42, 0 shares)  ✓")

	fmt.Println("Protocol helper without the version test passed.")
}

// runCorruptedShare: one of three helpers holds a share with one byte of a y
// coordinate flipped in storage, so it still answers OK. The owner reports
// RecoveryShareCorrupted(InvalidProof) against it and recovers from the other
// two. Mirrors run_corrupted_share_flow in smoke-tests/rust/src/protocol.rs.
func runCorruptedShare() {
	fmt.Println("=== Protocol corrupted share test ===")

	secret := protocol.UserSecret{ID: []byte{8}, Name: "tampered-helper secret", Data: []byte("three helpers, one tampered")}
	channelA, version, _, recoveryEvents, _ := recoverAfter("corrupted", 43, secret, func(helperA *peer, channelA uint64, version uint32) {
		stored := heldShare(helperA, channelA, version)
		var request derecpb.StoreShareRequestMessage
		must(proto.Unmarshal(stored.Bytes, &request), "decode the stored StoreShareRequestMessage")
		var committed derecpb.CommittedDeRecShare
		must(proto.Unmarshal(request.Share, &committed), "decode the CommittedDeRecShare")
		var share derecpb.DeRecShare
		must(proto.Unmarshal(committed.DeRecShare, &share), "decode the DeRecShare")
		share.Subshares[0].Y[0] ^= 0x01
		var err error
		committed.DeRecShare, err = proto.Marshal(&share)
		must(err, "encode the DeRecShare")
		request.Share, err = proto.Marshal(&committed)
		must(err, "encode the CommittedDeRecShare")
		stored.Bytes, err = proto.Marshal(&request)
		must(err, "encode the StoreShareRequestMessage")
		must(helperA.shareStore.Save(helperA.proto.SecretID(), channelA, stored), "helper-a stores the tampered share")
	})

	var corrupted []protocol.Event
	for _, ev := range recoveryEvents {
		if ev.Type == protocol.EventTypeRecoveryShareCorrupted {
			corrupted = append(corrupted, ev)
		}
	}
	assertTrue(len(corrupted) == 1 && corrupted[0].ChannelID == channelA && corrupted[0].Version != nil &&
		*corrupted[0].Version == version && corrupted[0].Reason == protocol.CorruptionReasonInvalidProof,
		"the app sees exactly one corrupted share, from helper-a (InvalidProof), got %+v", corrupted)
	assertRecoveredDespite(recoveryEvents, secret, "a corrupted share")
	fmt.Println("  RecoverSecret → RecoveryShareCorrupted(helper-a, InvalidProof), SecretRecovered from the rest  ✓")

	fmt.Println("Protocol corrupted share test passed.")
}

// runUnpairing: the owner starts an unpair, the helper accepts it, both sides
// report Unpaired and drop the channel record. A helper starting an unpair is
// refused with CodeRoleMismatch. Mirrors run_unpairing_flow in
// smoke-tests/rust/src/protocol.rs.
func runUnpairing() {
	fmt.Println("=== Protocol unpairing test ===")

	owner := newPeer("owner", "https://owner-unpair.example.com", 2)
	helper := newPeer("helper", "https://helper-unpair.example.com", 2)
	defer owner.proto.Close()
	defer helper.proto.Close()
	channelID := pairPeers(owner, helper, 7)

	memo := "decommissioning"
	_, err := owner.proto.Start(protocol.FlowKindUnpair, protocol.UnpairParams{ChannelID: channelID, Memo: &memo})
	must(err, "owner.Start(Unpair)")
	unpaired := 0
	for _, ev := range pump(owner, helper) {
		assertTrue(ev.Type != protocol.EventTypeUnpairRejected, "an accepted unpair must not be rejected, got %+v", ev)
		if ev.Type == protocol.EventTypeUnpaired && ev.ChannelID == channelID {
			unpaired++
		}
	}
	assertTrue(unpaired >= 2, "expected Unpaired on both sides, got %d", unpaired)
	assertTrue(!hasChannelRecord(owner, channelID, 0), "the owner's channel record must be removed after unpair")
	assertTrue(!hasChannelRecord(helper, channelID, 0), "the helper's channel record must be removed after unpair")
	fmt.Println("  Start(Unpair) → Unpaired on both sides, channel record gone on both  ✓")

	owner2 := newPeer("owner", "https://owner-unpair-2.example.com", 2)
	helper2 := newPeer("helper", "https://helper-unpair-2.example.com", 2)
	defer owner2.proto.Close()
	defer helper2.proto.Close()
	helperChannel := pairPeers(owner2, helper2, 8)
	helperMemo := "helper trying to unpair"
	_, err = helper2.proto.Start(protocol.FlowKindUnpair, protocol.UnpairParams{ChannelID: helperChannel, Memo: &helperMemo})
	var roleErr *derec.Error
	assertTrue(errors.As(err, &roleErr) && roleErr.Code == derec.CodeRoleMismatch,
		"a helper-started unpair must be refused with CodeRoleMismatch, got %v", err)
	assertChannelID(roleErr, helperChannel, "the refused helper unpair")
	fmt.Println("  helper Start(Unpair) → CodeRoleMismatch  ✓")

	fmt.Println("Protocol unpairing test passed.")
}

// runUpdateChannelInfo: the owner changes its communication info and
// endpoint and announces both; both sides report ChannelInfoUpdated and the
// helper's stored record reflects the update. An update naming neither is
// refused with CodeInvalidInput. Mirrors run_update_channel_info_flow in
// smoke-tests/rust/src/protocol.rs.
func runUpdateChannelInfo() {
	fmt.Println("=== Protocol UpdateChannelInfo test ===")

	owner := newPeer("owner", "https://owner-update.example.com", 2)
	helper := newPeer("helper", "https://helper-update.example.com", 2)
	defer owner.proto.Close()
	defer helper.proto.Close()
	channelID := pairPeers(owner, helper, 42)

	newURI := "https://owner-update.NEW.example.com"
	newInfo := map[string]string{"name": "Owner-renamed", "email": "owner.new@example.com"}
	newTransports := []protocol.TransportProtocolParam{{URI: newURI, Protocol: int32(derecpb.Protocol_HTTPS)}}
	must(owner.proto.SetCommunicationInfo(newInfo), "owner SetCommunicationInfo")
	must(owner.proto.SetOwnTransports(newTransports), "owner SetOwnTransports")
	owner.uri = newURI

	_, err := owner.proto.Start(protocol.FlowKindUpdateChannelInfo, protocol.UpdateChannelInfoParams{
		Target:            protocol.TargetOne(channelID),
		CommunicationInfo: newInfo,
		OwnTransports:     newTransports,
	})
	must(err, "owner.Start(UpdateChannelInfo)")
	updated := 0
	for _, ev := range pump(owner, helper) {
		if ev.Type == protocol.EventTypeChannelInfoUpdated && ev.ChannelID == channelID {
			updated++
		}
	}
	assertTrue(updated >= 2, "expected ChannelInfoUpdated on both sides, got %d", updated)
	fmt.Println("  Start(UpdateChannelInfo) → ChannelInfoUpdated on both sides  ✓")

	record, ok, err := helper.channelStore.Load(protocolSecretID, channelID, 0)
	must(err, "helper channelStore.Load")
	assertTrue(ok && record.Helper != nil, "the helper channel must still exist after UpdateChannelInfo")
	assertTrue(len(record.Helper.Transports) > 0 && record.Helper.Transports[0].URI == newURI,
		"the helper's stored transport must be %s, got %+v", newURI, record.Helper.Transports)
	assertTrue(len(record.Helper.CommunicationInfo) == len(newInfo) &&
		record.Helper.CommunicationInfo["name"] == newInfo["name"] && record.Helper.CommunicationInfo["email"] == newInfo["email"],
		"the helper's stored communication_info must mirror the announced map, got %v", record.Helper.CommunicationInfo)
	fmt.Println("  the helper's stored record reflects the new endpoint and communication info  ✓")

	_, err = owner.proto.Start(protocol.FlowKindUpdateChannelInfo, protocol.UpdateChannelInfoParams{
		Target: protocol.TargetOne(channelID),
	})
	var inputErr *derec.Error
	assertTrue(errors.As(err, &inputErr) && inputErr.Code == derec.CodeInvalidInput,
		"an update naming neither field must fail with CodeInvalidInput, got %v", err)
	fmt.Println("  an update naming neither field → CodeInvalidInput  ✓")

	fmt.Println("Protocol UpdateChannelInfo test passed.")
}

// runReplyTo: with AutoReplyTo on, an outbound request still goes to the
// peer's stored endpoint but carries this device's endpoints as replyTo; and
// a responder routes its reply to an inbound request's replyTo instead of the
// stored endpoint. Mirrors run_reply_to_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplyTo() {
	fmt.Println("=== Protocol replyTo test ===")

	owner, err := newPeerWithConfig("owner-reply", "https://owner-reply.example.com", protocol.Config{
		DeRecProtocolConfig: protocol.DeRecProtocolConfig{
			Threshold:   proto.Uint32(2),
			AutoReplyTo: proto.Bool(true),
		},
	})
	must(err, "protocol.New(owner-reply)")
	helper := newPeer("helper-reply", "https://helper-reply.example.com", 2)
	defer owner.proto.Close()
	defer helper.proto.Close()
	channelID := pairPeers(owner, helper, 7)

	_, err = owner.proto.Start(protocol.FlowKindDiscovery, protocol.DiscoveryParams{Target: protocol.TargetOne(channelID)})
	must(err, "owner.Start(Discovery)")
	outbound := owner.drain()
	assertTrue(len(outbound) == 1, "expected exactly one outbound Discovery request, got %d", len(outbound))
	assertTrue(outbound[0].uri == helper.uri, "the request must still route to the helper's stored endpoint, got %s", outbound[0].uri)

	sharedKey := loadChannelKey(owner, protocolSecretID, channelID)
	extracted, err := discovery.Request.Extract(outbound[0].message, sharedKey)
	must(err, "discovery.Request.Extract")
	var request derecpb.GetSecretIdsVersionsRequestMessage
	must(proto.Unmarshal(extracted.RequestProto, &request), "decode GetSecretIdsVersionsRequestMessage")
	replyTo := request.GetReplyToTransports()
	assertTrue(len(replyTo) > 0 && replyTo[0].GetUri() == owner.uri,
		"AutoReplyTo must stamp replyToTransports leading with %s, got %v", owner.uri, replyTo)
	fmt.Println("  AutoReplyTo stamps the outbound request with this device's endpoint  ✓")

	const phantomURI = "https://phantom-replica.example.com"
	crafted, err := discovery.Request.Produce(channelID, sharedKey,
		[]discovery.Endpoint{{URI: phantomURI, Protocol: int32(derecpb.Protocol_HTTPS)}})
	must(err, "discovery.Request.Produce with replyTo")
	helper.drain()
	deliver(helper, crafted)
	answers := helper.drain()
	assertTrue(len(answers) == 1, "expected exactly one Discovery response, got %d", len(answers))
	assertTrue(answers[0].uri == phantomURI,
		"the responder must route to the request's replyTo, not the stored endpoint; got %s", answers[0].uri)
	fmt.Println("  the responder routes its reply to the inbound replyTo  ✓")

	fmt.Println("Protocol replyTo test passed.")
}

// runAutoAccept: helpers whose AutoAccept policy opts into StoreShare store
// each share without ActionRequired, reporting AutoAccepted instead, and the
// owner sees both ShareConfirmed. Mirrors run_auto_accept_flow in
// smoke-tests/rust/src/protocol.rs.
func runAutoAccept() {
	fmt.Println("=== Protocol auto-accept test ===")

	autoAccepting := func(label, uri string) *peer {
		p, err := newPeerWithConfig(label, uri, protocol.Config{
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{
				Threshold:  proto.Uint32(2),
				AutoAccept: &protocol.AutoAcceptPolicy{StoreShare: true},
			},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p
	}
	owner := newPeerWithSecretID("owner", "https://owner-auto-accept.example.com", 99, 2)
	helperA := autoAccepting("helper-a", "https://helper-a-auto-accept.example.com")
	helperB := autoAccepting("helper-b", "https://helper-b-auto-accept.example.com")
	defer owner.proto.Close()
	defer helperA.proto.Close()
	defer helperB.proto.Close()
	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)

	description := "auto-accept smoke"
	_, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: []byte{1, 2, 3}, Name: "auto-accept smoke secret", Data: []byte("auto-accepted-value")}},
		Description: &description,
	})
	must(err, "owner.Start(ProtectSecret)")
	autoAccepted, confirmed := 0, 0
	stored := map[uint64]bool{}
	for _, ev := range pumpMany([]*peer{owner, helperA, helperB}) {
		switch ev.Type {
		case protocol.EventTypeAutoAccepted:
			if ev.ActionKind == protocol.ActionKindStoreShare {
				autoAccepted++
			}
		case protocol.EventTypeActionRequired:
			assertTrue(ev.ActionKind != protocol.ActionKindStoreShare, "auto-accept must suppress ActionRequired(StoreShare), got %+v", ev)
		case protocol.EventTypeShareStored:
			stored[ev.ChannelID] = true
		case protocol.EventTypeShareConfirmed:
			confirmed++
		}
	}
	assertTrue(autoAccepted == 2, "expected AutoAccepted(StoreShare) on both helpers, got %d", autoAccepted)
	assertTrue(stored[channelA] && stored[channelB], "expected ShareStored on both helpers, got %v", stored)
	assertTrue(confirmed == 2, "expected ShareConfirmed from both helpers, got %d", confirmed)
	fmt.Println("  helpers auto-accept StoreShare: AutoAccepted + ShareStored, no ActionRequired; owner ShareConfirmed ×2  ✓")

	fmt.Println("Protocol auto-accept test passed.")
}

// runStartPairingRejectsAlreadyPaired: scanning a fresh contact on a channel
// that already finished pairing is refused with CodeChannelAlreadyPaired; the
// channel stays Paired with its SharedKey, no pairing secret or contact is
// stored, and nothing is sent. Mirrors
// run_start_pairing_rejects_already_paired_channel in
// smoke-tests/rust/src/protocol.rs.
func runStartPairingRejectsAlreadyPaired() {
	fmt.Println("=== Protocol start(Pairing) rejects already-Paired channel test ===")

	everyFlow := &protocol.AutoAcceptPolicy{
		Pairing: true, PrePair: true, StoreShare: true, VerifyShare: true,
		Discovery: true, GetShare: true, Unpair: true, UpdateChannelInfo: true,
	}
	autoAccepting := func(label, uri string) *peer {
		p, err := newPeerWithConfig(label, uri, protocol.Config{
			DeRecProtocolConfig: protocol.DeRecProtocolConfig{Threshold: proto.Uint32(2), AutoAccept: everyFlow},
		})
		must(err, fmt.Sprintf("protocol.New(%s)", label))
		return p
	}
	owner := autoAccepting("owner", "https://owner-already-paired.example.com")
	helper := autoAccepting("helper", "https://helper-already-paired.example.com")
	defer owner.proto.Close()
	defer helper.proto.Close()
	channelID := pairPeers(owner, helper, 1000)

	status := func() protocol.ChannelStatus {
		record, ok, err := helper.channelStore.Load(protocolSecretID, channelID, 0)
		must(err, "helper channelStore.Load")
		assertTrue(ok && record.Helper != nil, "the helper channel must exist")
		return record.Helper.Status
	}
	assertTrue(status() == protocol.ChannelStatusPaired, "the channel must be Paired after pairing")

	fresh, err := owner.proto.CreateContact(&channelID, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact (round 2)")
	_, err = helper.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{Kind: protocol.SenderKindHelper, Contact: fresh.ContactBytes})
	var pairErr *derec.Error
	assertTrue(errors.As(err, &pairErr) && pairErr.Code == derec.CodeChannelAlreadyPaired,
		"Start(Pairing) on an already-Paired channel must fail with CodeChannelAlreadyPaired, got %v", err)
	assertChannelID(pairErr, channelID, "the refused re-scan")

	assertTrue(status() == protocol.ChannelStatusPaired, "the channel must remain Paired after the refused start")
	assertTrue(hasSharedKey(helper, channelID), "the SharedKey must remain after the refused start")
	for _, kind := range []protocol.SecretKind{protocol.SecretKindPairingSecret, protocol.SecretKindPairingContact} {
		_, ok, err := helper.secretStore.Load(protocolSecretID, channelID, kind)
		must(err, "helper secretStore.Load")
		assertTrue(!ok, "secret kind %v must remain absent after the refused start", kind)
	}
	queued := helper.drain()
	assertTrue(len(queued) == 0, "a refused start must send nothing, got %d message(s)", len(queued))
	fmt.Println("  helper Start(Pairing) on an already-Paired channel → CodeChannelAlreadyPaired, no state change  ✓")

	fmt.Println("Protocol start(Pairing) rejects already-Paired channel test passed.")
}

// runReplicaIDWiring: two replica-configured peers pair in replica mode, both
// report ReplicaPaired naming the other, neither records its own row before
// confirming, and afterwards both hold the same absolute roster. A replica
// pairing is refused with CodeReplicaIDNotConfigured by an initiator, and by
// a responder, built without a replica id. Mirrors run_replica_id_wiring_flow
// in smoke-tests/rust/src/protocol.rs.
func runReplicaIDWiring() {
	fmt.Println("=== Protocol replica_id wiring test ===")

	ownerID, helperID := uint64(0x1111222233334444), uint64(0xAAAABBBBCCCCDDDD)
	owner := newPeerWithReplicaID("owner", "https://owner-wiring.example.com", 2, &ownerID)
	helper := newPeerWithReplicaID("helper", "https://helper-wiring.example.com", 2, &helperID)
	defer owner.proto.Close()
	defer helper.proto.Close()

	startReplicaScan(helper, owner, 1, protocol.SenderKindReplicaDestination)
	helperToOwner := pump(helper, owner)
	all := append(helperToOwner, pump(owner, helper)...)
	assertTrue(slices.ContainsFunc(helperToOwner, func(ev protocol.Event) bool { return ev.Type == protocol.EventTypePairingCompleted }),
		"expected PairingCompleted for the replica pairing")
	channelID := pairedChannelID(all, 1)
	replicaPaired := func(peerID uint64) bool {
		return slices.ContainsFunc(all, func(ev protocol.Event) bool {
			return ev.Type == protocol.EventTypeReplicaPaired && ev.ChannelID == channelID && ev.PeerReplicaID == peerID
		})
	}
	assertTrue(replicaPaired(helperID), "the owner-side ReplicaPaired must carry the helper's id")
	assertTrue(replicaPaired(ownerID), "the helper-side ReplicaPaired must carry the owner's id")

	for _, side := range []struct {
		p     *peer
		ownID uint64
	}{{owner, ownerID}, {helper, helperID}} {
		roster, err := side.p.channelStore.ListReplicas(protocolSecretID, protocol.ReplicaFilter{})
		must(err, side.p.label+" ListReplicas")
		for _, m := range roster {
			assertTrue(m.ReplicaID != side.ownID, "%s holds no own row before confirming, got %+v", side.p.label, roster)
		}
	}
	crossConfirmFingerprint(owner, helper, channelID)
	pumpMany([]*peer{owner, helper})

	for _, p := range []*peer{owner, helper} {
		roster, err := p.channelStore.ListReplicas(protocolSecretID, protocol.ReplicaFilter{})
		must(err, p.label+" ListReplicas")
		member := func(id uint64) protocol.ReplicaMember {
			idx := slices.IndexFunc(roster, func(m protocol.ReplicaMember) bool { return m.ReplicaID == id })
			assertTrue(idx >= 0, "%s's roster must contain a row for replica %#x, got %+v", p.label, id, roster)
			return roster[idx]
		}
		assertTrue(member(ownerID).Role == protocol.ReplicaRoleSource && member(helperID).Role == protocol.ReplicaRoleDestination,
			"%s: the owner must be the Source and the helper the Destination", p.label)
		assertTrue(member(ownerID).ChannelID == channelID && member(helperID).ChannelID == channelID,
			"%s must record every member against the group channel %d", p.label, channelID)
		for _, id := range []uint64{ownerID, helperID} {
			_, reserved := member(id).CommunicationInfo["derec.replica_id"]
			assertTrue(!reserved, "%s: communication_info must not contain the reserved key", p.label)
		}
	}
	fmt.Println("  happy path: both sides hold the same absolute roster  ✓")

	owner2 := newPeerWithReplicaID("owner", "https://owner-wiring-2.example.com", 2, &ownerID)
	unconfigured := newPeer("helper", "https://helper-wiring-2.example.com", 2)
	defer owner2.proto.Close()
	defer unconfigured.proto.Close()
	transient := uint64(2)
	contact, err := owner2.proto.CreateContact(&transient, protocol.ContactModeInlineKeys, nil)
	must(err, "owner.CreateContact")
	_, err = unconfigured.proto.Start(protocol.FlowKindPairing, protocol.PairingParams{
		Kind:    protocol.SenderKindReplicaDestination,
		Contact: contact.ContactBytes,
	})
	var initiatorErr *derec.Error
	assertTrue(errors.As(err, &initiatorErr) && initiatorErr.Code == derec.CodeReplicaIDNotConfigured,
		"an initiator without a replica id must refuse a replica pairing with CodeReplicaIDNotConfigured, got %v", err)
	assertTrue(len(unconfigured.drain()) == 0, "no outbound traffic may be generated")
	fmt.Println("  initiator without replica_id → CodeReplicaIDNotConfigured, nothing sent  ✓")

	unconfiguredOwner := newPeer("owner", "https://owner-wiring-3.example.com", 2)
	helper3 := newPeerWithReplicaID("helper", "https://helper-wiring-3.example.com", 2, &helperID)
	defer unconfiguredOwner.proto.Close()
	defer helper3.proto.Close()
	startReplicaScan(helper3, unconfiguredOwner, 3, protocol.SenderKindReplicaDestination)
	request := helper3.drain()
	assertTrue(len(request) == 1, "the helper must send exactly one PairRequest, got %d", len(request))
	_, err = unconfiguredOwner.proto.Process(request[0].message)
	var responderErr *derec.Error
	assertTrue(errors.As(err, &responderErr) && responderErr.Code == derec.CodeReplicaIDNotConfigured,
		"a responder without a replica id must refuse a replica PairRequest with CodeReplicaIDNotConfigured, got %v", err)
	fmt.Println("  responder without replica_id → CodeReplicaIDNotConfigured  ✓")

	fmt.Println("Protocol replica_id wiring test passed.")
}

// runProtectSecretWithReplicaTargets: a ProtectSecret over two helpers and a
// paired Destination reports ProtectSecretStarted per helper channel only and
// sends three requests. The Destination installs the full secret, the helper
// share map and the roster, and acknowledges; the owner reports
// ReplicaSecretAcked. Mirrors run_protect_secret_with_replica_targets_flow in
// smoke-tests/rust/src/protocol.rs, except the decryption of the requests'
// share_algorithm, which needs the Rust message internals.
func runProtectSecretWithReplicaTargets() {
	fmt.Println("=== Protocol ProtectSecret(replica targets) test ===")

	ownerID, replicaID := uint64(0xAAAAAAAAAAAAAAAA), uint64(0xBBBBBBBBBBBBBBBB)
	owner := newReplicaPeer("owner", "https://owner-replica-targets.example.com", 0xC0FFEE, ownerID, 2)
	helperA := newPeer("helper-a", "https://helper-a-replica-targets.example.com", 2)
	helperB := newPeer("helper-b", "https://helper-b-replica-targets.example.com", 2)
	replica := newPeerWithReplicaID("replica", "https://replica-replica-targets.example.com", 2, &replicaID)
	for _, p := range []*peer{owner, helperA, helperB, replica} {
		defer p.proto.Close()
	}

	channelA := pairPeers(owner, helperA, 1)
	channelB := pairPeers(owner, helperB, 2)
	replicaChannel := pairReplicaHandshake(owner, replica, 3)

	record, ok, err := owner.channelStore.Load(0xC0FFEE, replicaChannel, replicaID)
	must(err, "owner channelStore.Load(replica)")
	assertTrue(ok && record.Replica != nil && record.Replica.Role == protocol.ReplicaRoleDestination,
		"the owner must hold a Destination member row for the replica, got ok=%v %+v", ok, record)

	crossConfirmFingerprint(owner, replica, replicaChannel)
	autoPublish := owner.drain()
	assertTrue(len(autoPublish) == 3, "the confirmation's publish must fan out to 2 helpers + 1 replica, got %d", len(autoPublish))

	secretData := []byte("secret-payload-for-replica-and-helper")
	description := "replica + helper distribution"
	events, err := owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: []byte{0x01}, Name: "shared-secret", Data: secretData}},
		Description: &description,
	})
	must(err, "owner.Start(ProtectSecret) with a replica target")
	started := map[uint64]uint32{}
	for _, ev := range events {
		assertTrue(ev.Type != protocol.EventTypeProtectSecretFailed, "ProtectSecret emitted ProtectSecretFailed: %+v", ev)
		if ev.Type == protocol.EventTypeProtectSecretStarted && ev.Version != nil {
			started[ev.ChannelID] = *ev.Version
		}
	}
	assertTrue(len(started) == 2 && started[channelA] != 0 && started[channelA] == started[channelB],
		"ProtectSecretStarted must name each helper channel once, at one version; got %v", started)
	_, onGroup := started[replicaChannel]
	assertTrue(!onGroup, "the group channel must not appear in the helper-keyed started events")

	outbound := owner.drain()
	assertTrue(len(outbound) == 3, "expected three outbound requests (two helpers + one replica), got %d", len(outbound))
	idx := slices.IndexFunc(outbound, func(e outboxEntry) bool { return e.uri == replica.uri })
	assertTrue(idx >= 0 && slices.ContainsFunc(outbound, func(e outboxEntry) bool { return e.uri == helperA.uri }),
		"one request must route to helper-a and one to the replica")
	fmt.Println("  ProtectSecretStarted per helper channel only; three requests sent  ✓")

	replicaEvents, err := replica.proto.Process(outbound[idx].message)
	must(err, "replica.Process(StoreShareRequest)")
	installed, isInstall := replicaArrival(replicaEvents, replicaChannel)
	assertTrue(installed != nil && isInstall, "the first sync must be ReplicaSecretInstalled, got %+v", replicaEvents)
	assertTrue(installed.FromReplicaID == ownerID, "FromReplicaID must be the owner's id, got %#x", installed.FromReplicaID)
	assertTrue(installed.AuthorReplicaID != nil && *installed.AuthorReplicaID == ownerID, "the publisher is recorded as the author")
	assertTrue(installed.SecretID == 0xC0FFEE, "SecretID must be the owner's secret, got %#x", installed.SecretID)
	secret := installed.Secret
	assertTrue(len(secret.Secrets) == 1 && bytes.Equal(secret.Secrets[0].Data, secretData),
		"the secret must carry the one user secret, got %+v", secret.Secrets)
	shareChannels := map[uint64]bool{}
	for _, s := range installed.Shares {
		assertTrue(len(s.CommittedShare) != 0, "ChannelShare.CommittedShare must be non-empty")
		shareChannels[s.ChannelID] = true
	}
	assertTrue(len(installed.Shares) == 2 && shareChannels[channelA] && shareChannels[channelB],
		"the share map must be keyed by the two helper channels, got %+v", installed.Shares)
	helperChannels := map[uint64]bool{}
	for _, h := range secret.Helpers {
		assertTrue(len(h.SharedKey) == 32, "Helper.SharedKey must be a 32-byte key, got %d", len(h.SharedKey))
		helperChannels[h.ChannelID] = true
	}
	assertTrue(len(secret.Helpers) == 2 && helperChannels[channelA] && helperChannels[channelB],
		"secret.Helpers must name both helper channels, got %+v", secret.Helpers)
	assertTrue(secret.Replicas != nil && secret.Replicas.ChannelID == replicaChannel && len(secret.Replicas.Members) == 2,
		"the roster must carry the group channel and both members, got %+v", secret.Replicas)
	for _, m := range secret.Replicas.Members {
		switch m.ReplicaID {
		case ownerID:
			assertTrue(m.Role == protocol.ReplicaRoleSource, "the writer's own entry carries role Source")
		case replicaID:
			assertTrue(m.Role == protocol.ReplicaRoleDestination, "the replica's entry carries role Destination")
			assertTrue(len(m.Transports) > 0 && m.Transports[0].URI == replica.uri,
				"the Destination's entry must lead with its URI, got %+v", m.Transports)
		default:
			fail("unexpected roster member %#x", m.ReplicaID)
		}
	}
	fmt.Printf("  replica installed: from=%x, secret_id=%x, %d secret / %d helpers / %d replicas, %d helper shares  ✓\n",
		installed.FromReplicaID, installed.SecretID, len(secret.Secrets), len(secret.Helpers), len(secret.Replicas.Members), len(installed.Shares))

	ack := replica.drain()
	assertTrue(len(ack) == 1, "the replica must acknowledge with exactly one response, got %d", len(ack))
	ownerEvents, err := owner.proto.Process(ack[0].message)
	must(err, "owner.Process(replica acknowledgement)")
	idx = slices.IndexFunc(ownerEvents, func(ev protocol.Event) bool {
		return ev.Type == protocol.EventTypeReplicaSecretAcked && ev.ChannelID == replicaChannel
	})
	assertTrue(idx >= 0, "the owner must report ReplicaSecretAcked, got %+v", ownerEvents)
	acked := ownerEvents[idx]
	assertTrue(acked.FromReplicaID == replicaID && acked.Status == derecpb.StatusEnum_OK,
		"ReplicaSecretAcked must come from the replica with status OK, got %+v", acked)
	fmt.Printf("  owner received ReplicaSecretAcked: from=%x, status=%s  ✓\n", acked.FromReplicaID, acked.Status)

	fmt.Println("Protocol ProtectSecret(replica targets) test passed.")
}

// runReplicaSyncVersionProgression walks the version progression of a group
// that gains replicas, user secrets and helpers one at a time: every change
// bumps the version, every confirmed Destination is hydrated with it, and the
// helpers receive shares only once the threshold is met. Mirrors
// run_replica_sync_version_progression_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplicaSyncVersionProgression() {
	fmt.Println("=== Protocol replica sync — version progression v0→v8 ===")

	const sid uint64 = 0xABBA
	const threshold = 3
	owner := newReplicaPeer("owner", "https://owner-progression.example.com", sid, 0x0001, threshold)
	replicaA := newReplicaPeer("replica-a", "https://replica-a-progression.example.com", sid, 0x000A, threshold)
	replicaB := newReplicaPeer("replica-b", "https://replica-b-progression.example.com", sid, 0x000B, threshold)
	replicaC := newReplicaPeer("replica-c", "https://replica-c-progression.example.com", sid, 0x000C, threshold)
	helper1 := newPeerWithSecretID("helper-1", "https://helper-1-progression.example.com", sid, threshold)
	helper2 := newPeerWithSecretID("helper-2", "https://helper-2-progression.example.com", sid, threshold)
	helper3 := newPeerWithSecretID("helper-3", "https://helper-3-progression.example.com", sid, threshold)
	replicas := []*peer{owner, replicaA, replicaB, replicaC}
	everyone := append(slices.Clone(replicas), helper1, helper2, helper3)
	for _, p := range everyone {
		defer p.proto.Close()
	}

	_, ok, err := owner.userSecrets.LoadLatest(sid)
	must(err, "owner userSecrets.LoadLatest")
	assertTrue(!ok, "step 0: a brand-new instance has no published snapshot")
	fmt.Println("  step 0: user_secret_store latest = None  ✓")

	arrival := func(events []protocol.Event, channel uint64, step string) (*protocol.Event, bool) {
		ev, installed := replicaArrival(events, channel)
		assertTrue(ev != nil, "%s: no replica arrival on channel %d, got %+v", step, channel, events)
		return ev, installed
	}
	shape := func(ev *protocol.Event, step string, version uint32, helpers, secrets, members, shares int) {
		assertTrue(*ev.Version == version && len(ev.Secret.Helpers) == helpers && len(ev.Secret.Secrets) == secrets &&
			rosterSize(ev.Secret) == members && len(ev.Shares) == shares,
			"%s: want v=%d h=%d s=%d r=%d shares=%d, got v=%d h=%d s=%d r=%d shares=%d", step,
			version, helpers, secrets, members, shares,
			*ev.Version, len(ev.Secret.Helpers), len(ev.Secret.Secrets), rosterSize(ev.Secret), len(ev.Shares))
	}
	storedAt := func(events []protocol.Event, channel uint64, version uint32) bool {
		return slices.ContainsFunc(events, func(ev protocol.Event) bool {
			return ev.Type == protocol.EventTypeShareStored && ev.ChannelID == channel && ev.Version != nil && *ev.Version == version
		})
	}
	anyStored := func(events []protocol.Event) bool {
		return slices.ContainsFunc(events, func(ev protocol.Event) bool { return ev.Type == protocol.EventTypeShareStored })
	}

	cidA := pairReplicaHandshake(owner, replicaA, 1)
	crossConfirmFingerprint(owner, replicaA, cidA)
	events := pumpMany(replicas)
	received, installed := arrival(events, cidA, "step 1")
	assertTrue(installed, "step 1: A had no snapshot, so its first sync installs the secret")
	shape(received, "step 1", 1, 0, 0, 2, 0)
	snapshot, ok, err := owner.userSecrets.LoadLatest(sid)
	must(err, "owner userSecrets.LoadLatest")
	assertTrue(ok && snapshot.Version == 1, "step 1: the owner's snapshot must be v=1")
	fmt.Println("  step 1: pair replica A → v=1, secret(h=0,s=0,r=2,shares=0)  ✓")

	s1 := protocol.UserSecret{ID: []byte{0x01}, Name: "secret-one", Data: []byte("first-user-secret")}
	d2 := "v=2 explicit publish"
	_, err = owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{Secrets: []protocol.UserSecret{s1}, Description: &d2})
	must(err, "ProtectSecret([s1])")
	received, _ = arrival(pumpMany(replicas), cidA, "step 2")
	shape(received, "step 2", 2, 0, 1, 2, 0)
	assertTrue(bytes.Equal(received.Secret.Secrets[0].Data, s1.Data), "step 2: A must receive s1")
	fmt.Println("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=2,shares=0)  ✓")

	cidB := pairReplicaHandshake(owner, replicaB, 3)
	crossConfirmFingerprint(owner, replicaB, cidB)
	events = pumpMany(replicas)
	receivedA, installedA := arrival(events, cidA, "step 3 (A)")
	receivedB, installedB := arrival(events, cidB, "step 3 (B)")
	assertTrue(!installedA, "step 3: A already held the secret, so this is an update")
	assertTrue(installedB, "step 3: B is new to the secret, so this is an install")
	for _, r := range []*protocol.Event{receivedA, receivedB} {
		shape(r, "step 3", 3, 0, 1, 3, 0)
		assertTrue(bytes.Equal(r.Secret.Secrets[0].Data, s1.Data), "step 3: s1 must reach both")
	}
	fmt.Println("  step 3: pair replica B → v=3, secret(h=0,s=1,r=3,shares=0) on A+B  ✓")

	helperStartPair(owner, helper1, 11)
	events = pumpMany(everyone)
	cidH1 := pairedChannelID(events, 11)
	assertTrue(!slices.ContainsFunc(events, func(ev protocol.Event) bool {
		return ev.Type == protocol.EventTypeShareStored && ev.ChannelID == cidH1
	}), "step 4: helper-1 must not store a share (1 < threshold 3)")
	assertHydrated(replicaA, "A", 4, 1, 1, 3)
	assertHydrated(replicaB, "B", 4, 1, 1, 3)
	fmt.Println("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=3,shares=0)  ✓")

	helperStartPair(owner, helper2, 12)
	events = pumpMany(everyone)
	cidH2 := pairedChannelID(events, 12)
	assertTrue(!anyStored(events), "step 5: still below threshold, no helper stores a share")
	assertHydrated(replicaA, "A", 5, 2, 1, 3)
	assertHydrated(replicaB, "B", 5, 2, 1, 3)
	fmt.Println("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=3,shares=0)  ✓")

	s2 := protocol.UserSecret{ID: []byte{0x02}, Name: "secret-two", Data: []byte("second-user-secret")}
	d6 := "v=6 explicit publish"
	_, err = owner.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{Secrets: []protocol.UserSecret{s1, s2}, Description: &d6})
	must(err, "ProtectSecret([s1, s2])")
	assertTrue(!anyStored(pumpMany(everyone)), "step 6: still below threshold, no helper stores a share")
	assertHydrated(replicaA, "A", 6, 2, 2, 3)
	assertHydrated(replicaB, "B", 6, 2, 2, 3)
	snapshotA, ok, err := replicaA.userSecrets.LoadLatest(sid)
	must(err, "replica-a userSecrets.LoadLatest")
	assertTrue(ok, "A holds a snapshot")
	for _, s := range []protocol.UserSecret{s1, s2} {
		assertTrue(slices.ContainsFunc(snapshotA.Secrets, func(us protocol.UserSecret) bool { return bytes.Equal(us.Data, s.Data) }),
			"step 6: A's snapshot must carry %q", s.Name)
	}
	fmt.Println("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=3,shares=0)  ✓")

	helperStartPair(owner, helper3, 13)
	events = pumpMany(everyone)
	cidH3 := pairedChannelID(events, 13)
	helperChannels := []uint64{cidH1, cidH2, cidH3}
	for i, c := range helperChannels {
		assertTrue(storedAt(events, c, 7), "step 7: helper-%d must emit ShareStored at v=7", i+1)
	}
	assertHydrated(replicaA, "A", 7, 3, 2, 3)
	assertHydrated(replicaB, "B", 7, 3, 2, 3)
	fmt.Println("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=3,shares=3); all 3 helpers ShareStored  ✓")

	cidC := pairReplicaHandshake(owner, replicaC, 8)
	crossConfirmFingerprint(owner, replicaC, cidC)
	events = pumpMany(everyone)
	for i, c := range helperChannels {
		assertTrue(storedAt(events, c, 8), "step 8: helper-%d must emit ShareStored at v=8 (fresh VSS round)", i+1)
	}
	receivedC, _ := arrival(events, cidC, "step 8")
	shape(receivedC, "step 8", 8, 3, 2, 4, 3)
	assertHydrated(replicaA, "A", 8, 3, 2, 4)
	assertHydrated(replicaB, "B", 8, 3, 2, 4)
	assertHydrated(replicaC, "C", 8, 3, 2, 4)

	groupChannels := map[uint64]bool{}
	for _, p := range replicas {
		roster, err := p.channelStore.ListReplicas(sid, protocol.ReplicaFilter{})
		must(err, p.label+" ListReplicas")
		ids := map[uint64]bool{}
		for _, m := range roster {
			ids[m.ChannelID] = true
			groupChannels[m.ChannelID] = true
		}
		assertTrue(len(ids) == 1, "%s must place every member on one channel, got %v", p.label, ids)
	}
	assertTrue(len(groupChannels) == 1, "all devices must agree on the group channel, got %v", groupChannels)
	fmt.Println("  step 8: pair replica C → v=8, secret(h=3,s=2,r=4,shares=3) on A+B+C; all helpers refreshed  ✓")

	fmt.Println("Protocol replica sync version progression test passed.")
}

// runReplicaGroupKeyHandover: the first replica pairing fixes the group key;
// a second Destination is moved onto the group channel and key, its
// ephemeral pairing channel dropped on both sides, every member is recorded
// on the group channel, and a follow-up round is decrypted by the newcomer.
// Mirrors run_replica_group_key_handover_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplicaGroupKeyHandover() {
	fmt.Println("=== Protocol replica group-key handover test ===")

	const sid uint64 = 0xBEEF
	source := newReplicaPeer("source", "https://source-handover.example.com", sid, 0xC0DEC0DEC0DEC0DE, 2)
	dest1 := newReplicaPeer("dest1", "https://dest1-handover.example.com", sid, 0xD1D1D1D1D1D1D1D1, 2)
	dest2 := newReplicaPeer("dest2", "https://dest2-handover.example.com", sid, 0xD2D2D2D2D2D2D2D2, 2)
	all := []*peer{source, dest1, dest2}
	for _, p := range all {
		defer p.proto.Close()
	}

	groupChannel := pairReplicaHandshake(source, dest1, 1)
	crossConfirmFingerprint(source, dest1, groupChannel)
	pumpMany(all)
	kGroup := loadChannelKey(source, sid, groupChannel)
	assertTrue(bytes.Equal(kGroup, loadChannelKey(dest1, sid, groupChannel)),
		"after pair 1: Source and Dest1 must hold the same channel key")
	fmt.Println("  step 1: pair Source↔Dest1 — K_group emerged, both sides agree  ✓")

	ephemeral := pairReplicaHandshake(source, dest2, 2)
	kEphemeral := loadChannelKey(source, sid, ephemeral)
	assertTrue(bytes.Equal(kEphemeral, loadChannelKey(dest2, sid, ephemeral)),
		"before the handover: Source and Dest2 must share the ephemeral key")
	assertTrue(!bytes.Equal(kEphemeral, kGroup), "before the handover: Dest2's ephemeral key must not be K_group")

	crossConfirmFingerprint(source, dest2, ephemeral)
	pumpMany(all)
	kSource := loadChannelKey(source, sid, groupChannel)
	assertTrue(bytes.Equal(loadChannelKey(dest1, sid, groupChannel), kSource), "Dest1 must hold K_group")
	assertTrue(bytes.Equal(loadChannelKey(dest2, sid, groupChannel), kSource), "Dest2 must have adopted K_group on the group channel")
	assertTrue(bytes.Equal(kSource, kGroup), "K_group is fixed at the first replica pairing and never re-derived")
	for _, p := range []*peer{source, dest2} {
		assertTrue(channelKey(p, sid, ephemeral) == nil, "%s must drop the ephemeral pairing channel's key after the handover", p.label)
	}
	for _, p := range all {
		roster, err := p.channelStore.ListReplicas(sid, protocol.ReplicaFilter{})
		must(err, p.label+" ListReplicas")
		assertTrue(len(roster) == 3, "%s's roster must hold all three members, got %d", p.label, len(roster))
		for _, m := range roster {
			assertTrue(m.ChannelID == groupChannel, "%s must place every member on the group channel, got %+v", p.label, m)
		}
	}
	fmt.Println("  step 2: pair Source↔Dest2 — group converged on one channel and K_group  ✓")

	description := "post-handover round"
	_, err := source.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
		Secrets:     []protocol.UserSecret{{ID: []byte{0x42}, Name: "post-handover", Data: []byte("k_group payload")}},
		Description: &description,
	})
	must(err, "source.Start(ProtectSecret)")
	post := pumpMany(all)
	assertTrue(slices.ContainsFunc(post, func(ev protocol.Event) bool {
		return ev.Type == protocol.EventTypeReplicaSecretReceived && ev.ChannelID == groupChannel
	}), "the post-handover round must arrive on the group channel")
	snapshot, ok, err := dest2.userSecrets.LoadLatest(sid)
	must(err, "dest2 userSecrets.LoadLatest")
	assertTrue(ok && slices.ContainsFunc(snapshot.Secrets, func(us protocol.UserSecret) bool { return string(us.Data) == "k_group payload" }),
		"Dest2 must decrypt the post-handover payload with K_group")
	assertTrue(bytes.Equal(loadChannelKey(source, sid, groupChannel), kGroup), "K_group must remain stable across follow-up rounds")
	fmt.Println("  step 3: follow-up ProtectSecret round encrypted with K_group; Dest2 decrypted cleanly  ✓")

	fmt.Println("Protocol replica group-key handover test passed.")
}

// runReplicaPublishBeforeHandoverAck: the joiner's handover acknowledgement
// is lost, and the publishes after it still reach the joiner on the group
// channel. Mirrors run_replica_publish_before_handover_ack_flow in
// smoke-tests/rust/src/protocol.rs.
func runReplicaPublishBeforeHandoverAck() {
	fmt.Println("=== Protocol replica publish before handover ack test ===")

	const sid uint64 = 0xBEEF
	source := newReplicaPeer("source", "https://source-lost-ack.example.com", sid, 0xC0DEC0DEC0DEC0DE, 2)
	dest1 := newReplicaPeer("dest1", "https://dest1-lost-ack.example.com", sid, 0xD1D1D1D1D1D1D1D1, 2)
	dest2 := newReplicaPeer("dest2", "https://dest2-lost-ack.example.com", sid, 0xD2D2D2D2D2D2D2D2, 2)
	all := []*peer{source, dest1, dest2}
	for _, p := range all {
		defer p.proto.Close()
	}

	groupChannel := pairReplicaHandshake(source, dest1, 1)
	crossConfirmFingerprint(source, dest1, groupChannel)
	pumpMany(all)

	ephemeral := pairReplicaHandshake(source, dest2, 2)
	crossConfirmFingerprint(source, dest2, ephemeral)
	for _, entry := range source.drain() {
		switch entry.uri {
		case dest1.uri:
			deliver(dest1, entry.message)
		case dest2.uri:
			deliver(dest2, entry.message)
		}
	}
	lost := dest2.drain()
	assertTrue(len(lost) > 0, "Dest2 must have acknowledged the handover before it is dropped")
	pumpMany(all)
	fmt.Println("  step 1: handover delivered, Dest2's acknowledgement lost  ✓")

	for _, payload := range []string{"before the ack", "after the ack"} {
		_, err := source.proto.Start(protocol.FlowKindProtectSecret, protocol.ProtectSecretParams{
			Secrets: []protocol.UserSecret{{ID: []byte{0x42}, Name: "handover", Data: []byte(payload)}},
		})
		must(err, "source.Start(ProtectSecret)")
		pumpMany(all)
		snapshot, ok, err := dest2.userSecrets.LoadLatest(sid)
		must(err, "dest2 userSecrets.LoadLatest")
		assertTrue(ok && slices.ContainsFunc(snapshot.Secrets, func(us protocol.UserSecret) bool { return string(us.Data) == payload }),
			"Dest2 must receive the publish carrying %q", payload)
	}
	fmt.Println("  step 2: both publishes reached Dest2 on the group channel  ✓")

	fmt.Println("Protocol replica publish before handover ack test passed.")
}
