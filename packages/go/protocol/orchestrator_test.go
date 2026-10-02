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

	"google.golang.org/protobuf/proto"
)

// This file is the M3 payoff: two real DeRecProtocol instances (Owner +
// Helper), each backed by the in-memory store doubles from
// protocol_test.go plus an in-process transport, driven through a genuine
// pairing -> protect-secret flow, so the Go orchestrator is exercised under
// a realistic shape of end-to-end load rather than one call at a time.

// orchestratorSecretID is the shared secret identity both peers configure
// — the protocol-level SecretID that names which secret this pairing
// manages, agreed out of band before pairing. Every peer in a scenario
// shares the same value; it is not per-node.
const orchestratorSecretID = 0xDE2EC

// outboxEntry is one buffered outbound message: destination URI plus the
// wire-encoded envelope bytes.
type outboxEntry struct {
	uri     string
	message []byte
}

// inProcessTransport buffers outbound (uri, message) pairs instead of
// performing network I/O: Send appends to outbox, drain retrieves and
// clears it. Guarded by a mutex since a protocol instance's transport
// callback may fire from whatever goroutine drives Process/Start/Accept.
type inProcessTransport struct {
	mu     sync.Mutex
	outbox []outboxEntry
}

func newInProcessTransport() *inProcessTransport {
	return &inProcessTransport{}
}

func (t *inProcessTransport) Send(endpoints []Endpoint, message []byte) error {
	uri := endpoints[0].URI
	protocol := endpoints[0].Protocol
	_ = protocol
	t.mu.Lock()
	defer t.mu.Unlock()
	t.outbox = append(t.outbox, outboxEntry{uri: uri, message: append([]byte(nil), message...)})
	return nil
}

func (t *inProcessTransport) drain() []outboxEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := t.outbox
	t.outbox = nil
	return out
}

var _ Transport = (*inProcessTransport)(nil)

// orchestratorPeer bundles a protocol instance with the metadata needed to
// route messages to it (its own advertised transport URI) and the
// concrete store doubles backing it — kept concrete (not just the
// interface types New accepts) so tests can assert directly on what a
// store actually persisted, e.g. the Helper's shareStore after a
// ProtectSecret round.
type orchestratorPeer struct {
	label        string
	uri          string
	protocol     *DeRecProtocol
	transport    *inProcessTransport
	shareStore   *inMemoryShareStore
	channelStore *inMemoryChannelStore
	secretStore  *inMemorySecretStore

	// rejectStoreShare, when set, makes this peer Reject every StoreShare
	// action with that status instead of accepting it.
	rejectStoreShare *derecpb.StatusEnum
}

// newOrchestratorPeer builds a peer with its own full set of in-memory
// store doubles, an in-process transport, and a live DeRecProtocol
// instance bound to them.
func newOrchestratorPeer(t *testing.T, label, uri string, threshold uint32) *orchestratorPeer {
	t.Helper()
	return newOrchestratorPeerWith(t, label, uri, threshold, nil)
}

// newOrchestratorPeerWith is newOrchestratorPeer with configure applied to
// the Config before the protocol is built.
func newOrchestratorPeerWith(t *testing.T, label, uri string, threshold uint32, configure func(*Config)) *orchestratorPeer {
	t.Helper()
	channelStore := newInMemoryChannelStore()
	shareStore := newInMemoryShareStore()
	secretStore := newInMemorySecretStore()
	userSecretStore := newInMemoryUserSecretStore()
	stateStore := newInMemoryStateStore()
	transport := newInProcessTransport()

	cfg := Config{
		SecretID:          orchestratorSecretID,
		OwnTransports:     []TransportProtocolParam{{URI: uri, Protocol: int32(derecpb.Protocol_HTTPS)}},
		Threshold:         proto.Uint32(threshold),
		KeepVersionsCount: proto.Uint32(3),
	}
	if configure != nil {
		configure(&cfg)
	}
	p, err := New(channelStore, shareStore, secretStore, userSecretStore, stateStore, transport, cfg)
	if err != nil {
		t.Fatalf("New(%s): %v", label, err)
	}
	t.Cleanup(func() { p.Close() })

	return &orchestratorPeer{
		label:        label,
		uri:          uri,
		protocol:     p,
		transport:    transport,
		shareStore:   shareStore,
		channelStore: channelStore,
		secretStore:  secretStore,
	}
}

// deliverToOrchestratorPeer feeds bytes to peer.protocol.Process, then
// satisfies every emitted ActionRequired via peer.protocol.Accept. Returns
// every event produced by process() and the follow-up accept() calls, so
// the caller can assert on them. Walks the collected slice by index (not
// range) since an accept() call can itself append further events —
// matching the Rust reference's loop shape exactly, in case a flow ever
// needs a nested accept.
func deliverToOrchestratorPeer(t *testing.T, peer *orchestratorPeer, bytes []byte) []Event {
	t.Helper()
	collected, err := peer.protocol.Process(bytes)
	if err != nil {
		t.Fatalf("[%s] Process() failed: %v", peer.label, err)
	}
	for i := 0; i < len(collected); i++ {
		if collected[i].Type != EventTypeActionRequired {
			continue
		}
		if peer.rejectStoreShare != nil && collected[i].ActionKind == ActionKindStoreShare {
			if err := peer.protocol.Reject(collected[i].Action, *peer.rejectStoreShare, "over quota"); err != nil {
				t.Fatalf("[%s] Reject() failed: %v", peer.label, err)
			}
			continue
		}
		acceptEvents, err := peer.protocol.Accept(collected[i].Action)
		if err != nil {
			t.Fatalf("[%s] Accept() failed: %v", peer.label, err)
		}
		collected = append(collected, acceptEvents...)
	}
	return collected
}

// pumpOrchestratorPeers drains `from`'s outbox and delivers each message
// to whichever peer's own URI matches the destination, recursively
// transporting any replies until the network is quiescent. Returns every
// event observed across the whole exchange, on both sides.
func pumpOrchestratorPeers(t *testing.T, from, to *orchestratorPeer) []Event {
	t.Helper()
	var allEvents []Event
	pending := make([]outboxEntry, 0)
	pending = append(pending, from.transport.drain()...)

	for len(pending) > 0 {
		entry := pending[0]
		pending = pending[1:]

		var target *orchestratorPeer
		switch entry.uri {
		case to.uri:
			target = to
		case from.uri:
			target = from
		default:
			t.Fatalf("no peer for destination uri %s (have %s / %s)", entry.uri, from.uri, to.uri)
		}

		events := deliverToOrchestratorPeer(t, target, entry.message)
		pending = append(pending, target.transport.drain()...)
		allEvents = append(allEvents, events...)
	}

	return allEvents
}

// pumpOrchestratorPeersMany is the multi-peer variant of
// pumpOrchestratorPeers, for flows that fan out to more than one
// participant in a single round (e.g. an Owner sending StoreShareRequest
// to several helpers at once). Drains every peer's outbox, dispatches each
// message to the peer whose URI matches the destination, and repeats until
// the whole network is quiescent.
func pumpOrchestratorPeersMany(t *testing.T, peers []*orchestratorPeer) []Event {
	t.Helper()
	var allEvents []Event

	type routedEntry struct {
		target *orchestratorPeer
		entry  outboxEntry
	}

	for {
		var work []routedEntry
		for _, src := range peers {
			for _, entry := range src.transport.drain() {
				var target *orchestratorPeer
				for _, p := range peers {
					if p.uri == entry.uri {
						target = p
						break
					}
				}
				if target == nil {
					t.Fatalf("no peer for destination uri %s", entry.uri)
				}
				work = append(work, routedEntry{target: target, entry: entry})
			}
		}
		if len(work) == 0 {
			break
		}
		for _, w := range work {
			events := deliverToOrchestratorPeer(t, w.target, w.entry.message)
			allEvents = append(allEvents, events...)
		}
	}

	return allEvents
}

// pairOrchestratorPeers drives a full pairing handshake — Owner creates a
// contact, Helper starts pairing from it, and bytes are pumped both ways
// until both sides report PairingCompleted. Returns the long-term
// channel_id both peers rotated to.
func pairOrchestratorPeers(t *testing.T, owner, helper *orchestratorPeer, pairingChannelID uint64) uint64 {
	t.Helper()

	contact, err := owner.protocol.CreateContact(&pairingChannelID, ContactModeInlineKeys, nil)
	if err != nil {
		t.Fatalf("owner.CreateContact failed: %v", err)
	}
	if contact.ChannelID != pairingChannelID {
		t.Fatalf("CreateContact.ChannelID = %d, want %d", contact.ChannelID, pairingChannelID)
	}

	startEvents, err := helper.protocol.Start(FlowKindPairing, PairingParams{
		Kind:                  SenderKindHelper,
		Contact:               contact.ContactBytes,
		PeerCommunicationInfo: map[string]string{"name": "helper"},
	})
	if err != nil {
		t.Fatalf("helper.Start(Pairing) failed: %v", err)
	}

	var sawPairingStarted bool
	for _, ev := range startEvents {
		if ev.Type == EventTypePairingCompleted {
			t.Fatalf("PairingCompleted must not appear in start(Pairing) — it fires from Process() after the peer round-trip")
		}
		if ev.Type == EventTypePairingStarted {
			sawPairingStarted = true
			if ev.ChannelID != pairingChannelID {
				t.Fatalf("PairingStarted.ChannelID = %d, want %d", ev.ChannelID, pairingChannelID)
			}
			if ev.Kind != SenderKindHelper {
				t.Fatalf("PairingStarted.Kind = %d, want %d (Helper)", ev.Kind, SenderKindHelper)
			}
		}
	}
	if !sawPairingStarted {
		t.Fatalf("start(Pairing) must emit PairingStarted, got %+v", startEvents)
	}

	helperToOwner := pumpOrchestratorPeers(t, helper, owner)
	ownerToHelper := pumpOrchestratorPeers(t, owner, helper)

	var completions []Event
	for _, ev := range helperToOwner {
		if ev.Type == EventTypePairingCompleted {
			completions = append(completions, ev)
		}
	}
	for _, ev := range ownerToHelper {
		if ev.Type == EventTypePairingCompleted {
			completions = append(completions, ev)
		}
	}
	if len(completions) < 2 {
		t.Fatalf("expected PairingCompleted on both sides, got %d (helper->owner=%+v, owner->helper=%+v)",
			len(completions), helperToOwner, ownerToHelper)
	}

	newChannelID := completions[0].ChannelID
	for _, ev := range completions {
		if ev.PairingChannelID != pairingChannelID {
			t.Fatalf("PairingCompleted.PairingChannelID = %d, want %d (the transient contact channel_id)",
				ev.PairingChannelID, pairingChannelID)
		}
		if cid := ev.ChannelID; cid != newChannelID {
			t.Fatalf("both peers must rotate to the same long-term channel_id: got %d and %d", cid, newChannelID)
		}
	}

	return newChannelID
}

// TestOrchestrator_PairingAndProtectSecret_EndToEnd is the M3 payoff test:
// real DeRecProtocol instances (Owner + two Helpers), each with its own
// in-memory stores and an in-process transport, driven through a genuine
// pairing -> protect-secret -> share-stored flow. This exercises the
// entire M3 orchestrator stack together — Rust calling back into the Go
// store implementations, the Go transport callback routing messages
// between independent instances, event decoding, and the JSON-config FFI
// protocol construction — all under real (not stubbed) load.
//
// Two Helpers, not one: DeRecProtocolBuilder rejects Threshold < 2
// (derec_library::protocol::mod.rs — "0 or 1 lets a single helper
// reconstruct the secret and defeats threshold sharing"), and the sharing
// handler only VSS-splits shares to Helpers when helpers.len() >=
// threshold (library/src/protocol/handlers/sharing.rs) — below that it
// treats the round as a no-op distribution. A single Helper can therefore
// never observe a real ShareStored, so this test mirrors the Rust
// reference's own `run_sharing_flow` shape: threshold=2, two Helpers.
func TestOrchestrator_PairingAndProtectSecret_EndToEnd(t *testing.T) {
	const threshold = 2

	owner := newOrchestratorPeer(t, "owner", "https://owner.example.com", threshold)
	helperA := newOrchestratorPeer(t, "helper-a", "https://helper-a.example.com", threshold)
	helperB := newOrchestratorPeer(t, "helper-b", "https://helper-b.example.com", threshold)

	channelA := pairOrchestratorPeers(t, owner, helperA, 1)
	channelB := pairOrchestratorPeers(t, owner, helperB, 2)
	if channelA == 1 || channelB == 2 {
		t.Fatalf("long-term channel_id must differ from the transient pairing id (got channelA=%d, channelB=%d)", channelA, channelB)
	}

	// Both sides of both channels must actually have persisted the paired
	// channel through their own ChannelStore — proof the channel-store
	// save callback fired on every instance, not just that events were
	// emitted.
	for _, check := range []struct {
		label string
		store *inMemoryChannelStore
		cid   uint64
	}{
		{"owner/channelA", owner.channelStore, channelA},
		{"helper-a/channelA", helperA.channelStore, channelA},
		{"owner/channelB", owner.channelStore, channelB},
		{"helper-b/channelB", helperB.channelStore, channelB},
	} {
		if _, ok, err := check.store.Load(orchestratorSecretID, check.cid, 0); err != nil || !ok {
			t.Fatalf("%s channelStore must have the paired channel: ok=%v err=%v", check.label, ok, err)
		}
	}

	ownerFP, err := owner.protocol.GetFingerprint(channelA)
	if err != nil {
		t.Fatalf("owner.GetFingerprint(channelA): %v", err)
	}
	helperAFP, err := helperA.protocol.GetFingerprint(channelA)
	if err != nil {
		t.Fatalf("helperA.GetFingerprint: %v", err)
	}
	if ownerFP != helperAFP {
		t.Fatalf("owner and helper-a fingerprints must match: %q vs %q", ownerFP, helperAFP)
	}

	// Now distribute a secret to both paired Helpers.
	secretData := []byte("super-secret-value")
	description := "smoke-test distribution"
	protectEvents, err := owner.protocol.Start(FlowKindProtectSecret, ProtectSecretParams{
		Secrets: []UserSecret{
			{ID: []byte{1, 2, 3}, Name: "smoke-test secret", Data: secretData},
		},
		Description: &description,
	})
	if err != nil {
		t.Fatalf("owner.Start(ProtectSecret) failed: %v", err)
	}

	protectStartedVersions := map[uint64]uint32{}
	for _, ev := range protectEvents {
		if ev.Type == EventTypeProtectSecretFailed {
			t.Fatalf("start(ProtectSecret) emitted ProtectSecretFailed: %+v", ev)
		}
		if ev.Type == EventTypeProtectSecretStarted && ev.Version != nil {
			protectStartedVersions[ev.ChannelID] = *ev.Version
		}
	}
	if len(protectStartedVersions) != 2 {
		t.Fatalf("start(ProtectSecret) must emit ProtectSecretStarted for both paired channels, got %+v", protectEvents)
	}

	shareEvents := pumpOrchestratorPeersMany(t, []*orchestratorPeer{owner, helperA, helperB})

	storedFor := map[uint64]bool{}
	confirmedCount := 0
	storeShareActions := 0
	for _, ev := range shareEvents {
		if ev.Type == EventTypeActionRequired && ev.ActionKind == ActionKindStoreShare {
			storeShareActions++
			if ev.ShareSize == nil || *ev.ShareSize == 0 {
				t.Fatalf("StoreShare ActionRequired must carry a positive ShareSize, got %+v", ev)
			}
			if ev.TraceID == 0 {
				t.Fatalf("StoreShare ActionRequired must carry a TraceID, got %+v", ev)
			}
		}
		switch ev.Type {
		case EventTypeShareStored:
			storedFor[ev.ChannelID] = true
		case EventTypeShareConfirmed:
			confirmedCount++
		}
	}
	if !storedFor[channelA] {
		t.Fatalf("expected a ShareStored event for channel-a (%d), got %+v", channelA, shareEvents)
	}
	if !storedFor[channelB] {
		t.Fatalf("expected a ShareStored event for channel-b (%d), got %+v", channelB, shareEvents)
	}
	if storeShareActions != 2 {
		t.Fatalf("expected 2 StoreShare ActionRequired events (one per helper), got %d", storeShareActions)
	}
	if confirmedCount != 2 {
		t.Fatalf("expected 2 ShareConfirmed events (one per helper), got %d: %+v", confirmedCount, shareEvents)
	}

	// The real validation: each Helper's in-memory ShareStore must have
	// actually received its share through the Save callback, not just
	// that an event claiming so was emitted.
	for _, check := range []struct {
		label     string
		store     *inMemoryShareStore
		channelID uint64
	}{
		{"helper-a", helperA.shareStore, channelA},
		{"helper-b", helperB.shareStore, channelB},
	} {
		storedShares, err := check.store.Load(orchestratorSecretID, check.channelID, nil)
		if err != nil {
			t.Fatalf("%s.shareStore.Load: %v", check.label, err)
		}
		if len(storedShares) == 0 {
			t.Fatalf("%s shareStore has no shares for channel %d — the Save callback never fired", check.label, check.channelID)
		}
		if len(storedShares[0].Bytes) == 0 {
			t.Fatalf("%s stored share has empty Bytes", check.label)
		}
		wantVersion, ok := protectStartedVersions[check.channelID]
		if !ok {
			t.Fatalf("%s: no ProtectSecretStarted version recorded for channel %d", check.label, check.channelID)
		}
		if storedShares[0].Version != wantVersion {
			t.Fatalf("%s stored share version = %d, want %d (from ProtectSecretStarted)", check.label, storedShares[0].Version, wantVersion)
		}
	}
}

// TestOrchestrator_RejectForwardsStatusEnum has one helper Reject its
// StoreShare with a typed StatusEnum; the owner must observe exactly that
// status on the ShareRejected event for that helper's channel.
func TestOrchestrator_RejectForwardsStatusEnum(t *testing.T) {
	const threshold = 2

	owner := newOrchestratorPeer(t, "owner", "https://owner.example.com", threshold)
	helperA := newOrchestratorPeer(t, "helper-a", "https://helper-a.example.com", threshold)
	helperB := newOrchestratorPeer(t, "helper-b", "https://helper-b.example.com", threshold)

	channelA := pairOrchestratorPeers(t, owner, helperA, 1)
	pairOrchestratorPeers(t, owner, helperB, 2)

	status := derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED
	helperA.rejectStoreShare = &status

	if _, err := owner.protocol.Start(FlowKindProtectSecret, ProtectSecretParams{
		Secrets: []UserSecret{{ID: []byte{1}, Name: "n", Data: []byte("v")}},
	}); err != nil {
		t.Fatalf("owner.Start(ProtectSecret): %v", err)
	}
	events := pumpOrchestratorPeersMany(t, []*orchestratorPeer{owner, helperA, helperB})

	var rejected []Event
	for _, ev := range events {
		if ev.Type == EventTypeShareRejected {
			rejected = append(rejected, ev)
		}
	}
	if len(rejected) != 1 {
		t.Fatalf("expected one ShareRejected, got %+v", events)
	}
	if rejected[0].ChannelID != channelA || rejected[0].Status != derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED ||
		rejected[0].Memo != "over quota" {
		t.Fatalf("ShareRejected: got %+v", rejected[0])
	}
}

// TestOrchestrator_ConfigCommunicationInfoReachesPairingPeer builds both
// peers with Config.CommunicationInfo and pairs them: each side's
// PairingCompleted carries the other side's map as PeerCommunicationInfo.
func TestOrchestrator_ConfigCommunicationInfoReachesPairingPeer(t *testing.T) {
	const threshold = 2

	ownerInfo := map[string]string{"name": "owner", "email": "owner@example.com"}
	helperInfo := map[string]string{"name": "helper-cfg"}
	owner := newOrchestratorPeerWith(t, "owner", "https://owner.example.com", threshold, func(c *Config) {
		c.CommunicationInfo = ownerInfo
	})
	helper := newOrchestratorPeerWith(t, "helper", "https://helper.example.com", threshold, func(c *Config) {
		c.CommunicationInfo = helperInfo
	})

	const pairingChannelID = 1
	contact, err := owner.protocol.CreateContact(proto.Uint64(pairingChannelID), ContactModeInlineKeys, nil)
	if err != nil {
		t.Fatalf("owner.CreateContact: %v", err)
	}
	if _, err := helper.protocol.Start(FlowKindPairing, PairingParams{
		Kind:    SenderKindHelper,
		Contact: contact.ContactBytes,
	}); err != nil {
		t.Fatalf("helper.Start(Pairing): %v", err)
	}
	events := append(pumpOrchestratorPeers(t, helper, owner), pumpOrchestratorPeers(t, owner, helper)...)

	sameMap := func(a, b map[string]string) bool {
		if len(a) != len(b) {
			return false
		}
		for k, v := range b {
			if a[k] != v {
				return false
			}
		}
		return true
	}
	var sawOwnerInfo, sawHelperInfo bool
	for _, ev := range events {
		if ev.Type != EventTypePairingCompleted {
			continue
		}
		switch {
		case sameMap(ev.PeerCommunicationInfo, ownerInfo):
			sawOwnerInfo = true
		case sameMap(ev.PeerCommunicationInfo, helperInfo):
			sawHelperInfo = true
		default:
			t.Fatalf("unexpected PeerCommunicationInfo %+v", ev.PeerCommunicationInfo)
		}
	}
	if !sawOwnerInfo || !sawHelperInfo {
		t.Fatalf("expected each PairingCompleted to carry the other side's Config.CommunicationInfo; got %+v", events)
	}
}

// TestOrchestrator_UpdateChannelInfoAnnouncesEndpointsByName drives a real
// UpdateChannelInfo round: the endpoints the owner announces reach the
// helper's ActionRequired with their protocol intact, decoded from the
// protocol names the library emits.
func TestOrchestrator_UpdateChannelInfoAnnouncesEndpointsByName(t *testing.T) {
	owner := newOrchestratorPeer(t, "owner", "https://owner.example.com", 2)
	helper := newOrchestratorPeer(t, "helper", "https://helper.example.com", 2)
	channel := pairOrchestratorPeers(t, owner, helper, 1)

	announced := []TransportProtocolParam{
		{URI: "https://owner.new.example.com", Protocol: int32(derecpb.Protocol_HTTPS)},
		{URI: "grpcs://owner.new.example.com", Protocol: int32(derecpb.Protocol_GRPC)},
	}
	if _, err := owner.protocol.Start(FlowKindUpdateChannelInfo, UpdateChannelInfoParams{
		Target:        TargetOne(channel),
		OwnTransports: announced,
	}); err != nil {
		t.Fatalf("owner.Start(UpdateChannelInfo): %v", err)
	}
	outbox := owner.transport.drain()
	if len(outbox) != 1 {
		t.Fatalf("expected one UpdateChannelInfo request, got %d", len(outbox))
	}
	events, err := helper.protocol.Process(outbox[0].message)
	if err != nil {
		t.Fatalf("helper.Process: %v", err)
	}
	var prompt *Event
	for i := range events {
		if events[i].Type == EventTypeActionRequired {
			prompt = &events[i]
		}
	}
	if prompt == nil || prompt.ActionKind != ActionKindUpdateChannelInfo {
		t.Fatalf("expected ActionRequired(UpdateChannelInfo), got %+v", events)
	}
	want := []EndpointJSON{
		{URI: announced[0].URI, Protocol: announced[0].Protocol},
		{URI: announced[1].URI, Protocol: announced[1].Protocol},
	}
	if len(prompt.UpdatedTransports) != 2 || prompt.UpdatedTransports[0] != want[0] || prompt.UpdatedTransports[1] != want[1] {
		t.Fatalf("UpdatedTransports: got %+v, want %+v", prompt.UpdatedTransports, want)
	}
	if _, err := helper.protocol.Accept(prompt.Action); err != nil {
		t.Fatalf("helper.Accept: %v", err)
	}
}

// TestOrchestrator_SecretStoreLoadManyServesTheWholeBroadcast checks that a
// broadcast to several helpers reads every SharedKey through one
// SecretStore.LoadMany call, and that a nil entry is judged by the
// library's missing-entry policy: discovery needs a key for every target,
// so it fails with CodeMissingSharedKey naming the channel without one.
func TestOrchestrator_SecretStoreLoadManyServesTheWholeBroadcast(t *testing.T) {
	const threshold = 2

	owner := newOrchestratorPeer(t, "owner", "https://owner.example.com", threshold)
	helperA := newOrchestratorPeer(t, "helper-a", "https://helper-a.example.com", threshold)
	helperB := newOrchestratorPeer(t, "helper-b", "https://helper-b.example.com", threshold)

	channelA := pairOrchestratorPeers(t, owner, helperA, 1)
	channelB := pairOrchestratorPeers(t, owner, helperB, 2)

	owner.secretStore.loadManyCalls = nil
	if _, err := owner.protocol.Start(FlowKindDiscovery, DiscoveryParams{Target: TargetMany(channelA, channelB)}); err != nil {
		t.Fatalf("Start(Discovery): %v", err)
	}
	calls := owner.secretStore.loadManyCalls
	if len(calls) != 1 {
		t.Fatalf("discovery broadcast must call LoadMany once, got %d calls: %v", len(calls), calls)
	}
	got := map[uint64]bool{}
	for _, c := range calls[0] {
		got[c] = true
	}
	if len(calls[0]) != 2 || !got[channelA] || !got[channelB] {
		t.Fatalf("LoadMany must receive both helper channels [%d %d], got %v", channelA, channelB, calls[0])
	}
	owner.transport.drain()

	if err := owner.secretStore.Remove(orchestratorSecretID, channelB, SecretKindSharedKey); err != nil {
		t.Fatal(err)
	}
	owner.secretStore.loadManyCalls = nil
	_, err := owner.protocol.Start(FlowKindDiscovery, DiscoveryParams{Target: TargetMany(channelA, channelB)})
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) || derecErr.Code != derec.CodeMissingSharedKey {
		t.Fatalf("a nil LoadMany entry must surface CodeMissingSharedKey, got %v", err)
	}
	if !strings.Contains(derecErr.Message, strconv.FormatUint(channelB, 10)) {
		t.Fatalf("MissingSharedKey must name channel %d: %s", channelB, derecErr.Message)
	}
	if len(owner.secretStore.loadManyCalls) != 1 {
		t.Fatalf("the failing broadcast must still be one LoadMany call, got %v", owner.secretStore.loadManyCalls)
	}
}
