// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"strconv"
	"sync"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// This file is the M3 payoff: two real DeRecProtocol instances (Owner +
// Helper), each backed by the in-memory store doubles from
// protocol_test.go plus an in-process transport, driven through a genuine
// pairing -> protect-secret flow. It mirrors the `InProcessTransport` /
// `Peer` / `deliver` / `pump` / `pair` pattern in
// bindings/rust/src/protocol.rs so the Go orchestrator is exercised under
// the same shape of end-to-end load the Rust reference already validates.

// orchestratorSecretID is the shared secret identity both peers configure
// — the protocol-level SecretID that names which secret this pairing
// manages, agreed out of band before pairing (mirrors
// bindings/rust/src/protocol.rs's DEFAULT_TEST_SECRET_ID: every peer in a
// scenario shares the same value, it is not per-node).
const orchestratorSecretID = 0xDE2EC

// outboxEntry is one buffered outbound message: destination URI plus the
// wire-encoded envelope bytes.
type outboxEntry struct {
	uri     string
	message []byte
}

// inProcessTransport buffers outbound (uri, message) pairs instead of
// performing network I/O, mirroring InProcessTransport in
// bindings/rust/src/protocol.rs: Send appends to outbox, drain retrieves
// and clears it. Guarded by a mutex since a protocol instance's transport
// callback may fire from whatever goroutine drives Process/Start/Accept.
type inProcessTransport struct {
	mu     sync.Mutex
	outbox []outboxEntry
}

func newInProcessTransport() *inProcessTransport {
	return &inProcessTransport{}
}

func (t *inProcessTransport) Send(uri string, _ int32, message []byte) error {
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
}

// newOrchestratorPeer builds a peer with its own full set of in-memory
// store doubles, an in-process transport, and a live DeRecProtocol
// instance bound to them.
func newOrchestratorPeer(t *testing.T, label, uri string, threshold uint32) *orchestratorPeer {
	t.Helper()
	channelStore := newInMemoryChannelStore()
	shareStore := newInMemoryShareStore()
	secretStore := newInMemorySecretStore()
	userSecretStore := newInMemoryUserSecretStore()
	stateStore := newInMemoryStateStore()
	transport := newInProcessTransport()

	cfg := Config{
		SecretID:             orchestratorSecretID,
		OwnTransportURI:      uri,
		OwnTransportProtocol: int32(derecpb.Protocol_HTTPS),
		Threshold:            threshold,
		KeepVersionsCount:    3,
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
	}
}

// deliverToOrchestratorPeer feeds bytes to peer.protocol.Process, then
// satisfies every emitted ActionRequired via peer.protocol.Accept —
// mirroring the `deliver` helper in bindings/rust/src/protocol.rs. Returns
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
// transporting any replies until the network is quiescent — mirroring
// `pump` in bindings/rust/src/protocol.rs. Returns every event observed
// across the whole exchange, on both sides.
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
// to several helpers at once) — mirroring `pump_many` in
// bindings/rust/src/protocol.rs. Drains every peer's outbox, dispatches
// each message to the peer whose URI matches the destination, and repeats
// until the whole network is quiescent.
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
// until both sides report PairingCompleted — mirroring `pair` in
// bindings/rust/src/protocol.rs. Returns the long-term channel_id both
// peers rotated to.
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
		Kind:                  int32(SenderKindHelper),
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
			if ev.ChannelID != strconv.FormatUint(pairingChannelID, 10) {
				t.Fatalf("PairingStarted.ChannelID = %s, want %d", ev.ChannelID, pairingChannelID)
			}
			if ev.Kind != int32(SenderKindHelper) {
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

	newChannelID, err := strconv.ParseUint(completions[0].ChannelID, 10, 64)
	if err != nil {
		t.Fatalf("PairingCompleted.ChannelID = %q: %v", completions[0].ChannelID, err)
	}
	for _, ev := range completions {
		if ev.PairingChannelID != strconv.FormatUint(pairingChannelID, 10) {
			t.Fatalf("PairingCompleted.PairingChannelID = %s, want %d (the transient contact channel_id)",
				ev.PairingChannelID, pairingChannelID)
		}
		cid, err := strconv.ParseUint(ev.ChannelID, 10, 64)
		if err != nil {
			t.Fatalf("PairingCompleted.ChannelID = %q: %v", ev.ChannelID, err)
		}
		if cid != newChannelID {
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
		if _, ok, err := check.store.Load(orchestratorSecretID, check.cid); err != nil || !ok {
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

	protectStartedVersions := map[string]uint32{}
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

	storedFor := map[string]bool{}
	confirmedCount := 0
	for _, ev := range shareEvents {
		switch ev.Type {
		case EventTypeShareStored:
			storedFor[ev.ChannelID] = true
		case EventTypeShareConfirmed:
			confirmedCount++
		}
	}
	if !storedFor[strconv.FormatUint(channelA, 10)] {
		t.Fatalf("expected a ShareStored event for channel-a (%d), got %+v", channelA, shareEvents)
	}
	if !storedFor[strconv.FormatUint(channelB, 10)] {
		t.Fatalf("expected a ShareStored event for channel-b (%d), got %+v", channelB, shareEvents)
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
		wantVersion, ok := protectStartedVersions[strconv.FormatUint(check.channelID, 10)]
		if !ok {
			t.Fatalf("%s: no ProtectSecretStarted version recorded for channel %d", check.label, check.channelID)
		}
		if storedShares[0].Version != wantVersion {
			t.Fatalf("%s stored share version = %d, want %d (from ProtectSecretStarted)", check.label, storedShares[0].Version, wantVersion)
		}
	}
}
