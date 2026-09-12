// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// TestTarget_MarshalJSON covers the three wire shapes parse_target in
// library/src/interop/ffi/protocol/flow.rs expects, including the edge case where
// TargetMany is called with zero ids — that must stay distinct from
// TargetAll (null) since Rust resolves an empty array to zero channels,
// not "every channel".
func TestTarget_MarshalJSON(t *testing.T) {
	cases := []struct {
		name string
		in   Target
		want string
	}{
		{"zero value", Target{}, "null"},
		{"All", TargetAll(), "null"},
		{"One", TargetOne(42), `"42"`},
		{"Many", TargetMany(1, 2, 3), `["1","2","3"]`},
		{"Many empty", TargetMany(), "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.in.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("MarshalJSON = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCreateContact_InlineKeys_ReturnsContactBytesAndChannelID drives the
// genuine FFI round trip end to end: derec_protocol_create_contact needs no
// peer (the material it persists lands in the local stores only), so this
// asserts the real happy path — non-empty encoded ContactMessage bytes that
// decode cleanly and echo the caller-supplied channel id.
func TestCreateContact_InlineKeys_ReturnsContactBytesAndChannelID(t *testing.T) {
	p := newTestProtocol(t)
	channelID := uint64(99)

	contact, err := p.CreateContact(&channelID, ContactModeInlineKeys, nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	if len(contact.ContactBytes) == 0 {
		t.Fatal("expected non-empty ContactBytes")
	}
	if contact.ChannelID != channelID {
		t.Fatalf("ChannelID = %d, want %d", contact.ChannelID, channelID)
	}

	var msg derecpb.ContactMessage
	if err := proto.Unmarshal(contact.ContactBytes, &msg); err != nil {
		t.Fatalf("decode ContactMessage: %v", err)
	}
	if msg.GetContactMode() != derecpb.ContactMode_INLINE_KEYS {
		t.Fatalf("ContactMode = %v, want INLINE_KEYS", msg.GetContactMode())
	}
	if msg.GetMlkemEncapsulationKey() == nil || msg.GetEciesPublicKey() == nil {
		t.Fatal("expected InlineKeys contact to carry both public keys")
	}
}

// TestCreateContact_NilChannelID_MintsARandomID covers the "let the library
// choose" path: passing a nil channelID must still yield a usable contact.
func TestCreateContact_NilChannelID_MintsARandomID(t *testing.T) {
	p := newTestProtocol(t)

	contact, err := p.CreateContact(nil, ContactModeInlineKeys, nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	if len(contact.ContactBytes) == 0 {
		t.Fatal("expected non-empty ContactBytes")
	}
}

// TestCreateContact_NoKeys_EchoesNonceAndCarriesNoKeyMaterial exercises the
// NoKeys mode: the contact must carry the caller-supplied nonce verbatim
// and no public-key material.
func TestCreateContact_NoKeys_EchoesNonceAndCarriesNoKeyMaterial(t *testing.T) {
	p := newTestProtocol(t)
	channelID := uint64(4242)
	nonce := uint64(1234)

	contact, err := p.CreateContact(&channelID, ContactModeNoKeys, &nonce)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}

	var msg derecpb.ContactMessage
	if err := proto.Unmarshal(contact.ContactBytes, &msg); err != nil {
		t.Fatalf("decode ContactMessage: %v", err)
	}
	if msg.GetContactMode() != derecpb.ContactMode_NO_KEYS {
		t.Fatalf("ContactMode = %v, want NO_KEYS", msg.GetContactMode())
	}
	if msg.GetNonce() != nonce {
		t.Fatalf("Nonce = %d, want %d", msg.GetNonce(), nonce)
	}
	if msg.MlkemEncapsulationKey != nil || msg.EciesPublicKey != nil || msg.ContactBindingHash != nil {
		t.Fatal("expected NoKeys contact to carry no key material or binding hash")
	}
}

// TestCreateContact_ClosedProtocol asserts the closed-instance guard
// rejects the call instead of touching a freed handle.
func TestCreateContact_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.CreateContact(nil, ContactModeInlineKeys, nil); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestStart_Pairing_InvalidContactBytes_ReturnsCleanError drives the
// genuine FFI round trip: a Start(FlowKindPairing, ...) call whose Contact
// bytes are not a valid ContactMessage proto must fail cleanly with a
// structured error, not a crash — the only path this unit test can
// exercise without a peer (the full handshake needs two live instances
// pumping messages at each other end to end).
func TestStart_Pairing_InvalidContactBytes_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	_, err := p.Start(FlowKindPairing, PairingParams{
		Kind:    int32(SenderKindHelper),
		Contact: []byte("not-a-valid-contact-message"),
	})
	if err == nil {
		t.Fatal("expected an error for invalid contact bytes")
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestStart_ParamsTypeMismatch_ReturnsAnError asserts the marshal-level
// guard: passing a params struct that doesn't match flowKind is a returned
// error, not a panic or a silently-wrong wire payload.
func TestStart_ParamsTypeMismatch_ReturnsAnError(t *testing.T) {
	p := newTestProtocol(t)
	_, err := p.Start(FlowKindPairing, DiscoveryParams{})
	if err == nil {
		t.Fatal("expected an error for a params/FlowKind mismatch")
	}
	if !strings.Contains(err.Error(), "PairingParams") {
		t.Fatalf("expected the error to name the required type, got: %v", err)
	}
}

// TestStart_UnknownFlowKind_ReturnsAnError covers the default arm of the
// flowKind switch.
func TestStart_UnknownFlowKind_ReturnsAnError(t *testing.T) {
	p := newTestProtocol(t)
	if _, err := p.Start(FlowKind(999), nil); err == nil {
		t.Fatal("expected an error for an unknown FlowKind")
	}
}

// TestStart_ClosedProtocol asserts the closed-instance guard rejects the
// call instead of touching a freed handle.
func TestStart_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.Start(FlowKindDiscovery, DiscoveryParams{}); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestAccept_MalformedAction_ReturnsCleanError feeds bytes that are not a
// valid PendingAction encoding through the FFI, proving the accept() decode
// error path surfaces as a Go error rather than a panic across the C ABI
// boundary — the only path this unit test can exercise without a peer.
func TestAccept_MalformedAction_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	events, err := p.Accept([]byte{0xff, 0xff, 0xff, 0xff})
	if err == nil {
		t.Fatalf("expected a decode error, got events: %+v", events)
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestAccept_EmptyAction_ReturnsCleanError covers the FFI's null/empty
// action-bytes rejection.
func TestAccept_EmptyAction_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	if _, err := p.Accept(nil); err == nil {
		t.Fatal("expected an error for an empty action")
	}
}

// TestAccept_ClosedProtocol asserts the closed-instance guard rejects the
// call instead of touching a freed handle.
func TestAccept_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.Accept([]byte{0x01}); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestReject_MalformedAction_ReturnsCleanError mirrors
// TestAccept_MalformedAction_ReturnsCleanError for derec_protocol_reject.
func TestReject_MalformedAction_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	err := p.Reject([]byte{0xff, 0xff, 0xff, 0xff}, 0, "no thanks")
	if err == nil {
		t.Fatal("expected a decode error")
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestReject_EmptyAction_ReturnsCleanError covers the FFI's null/empty
// action-bytes rejection.
func TestReject_EmptyAction_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Reject(nil, 0, ""); err == nil {
		t.Fatal("expected an error for an empty action")
	}
}

// TestReject_ClosedProtocol asserts the closed-instance guard rejects the
// call instead of touching a freed handle.
func TestReject_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := p.Reject([]byte{0x01}, 0, ""); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// fixtureRestoreSecret is a minimal recoverable Secret: one helper channel
// with a well-formed 32-byte SharedKey, no replicas. Sufficient to drive
// restore()'s canonical-state rebuild without a peer — restore only
// touches the local stores (see library/src/protocol/handlers/restore.rs).
func fixtureRestoreSecret(helperChannelID uint64) Secret {
	sharedKey := make([]byte, 32)
	for i := range sharedKey {
		sharedKey[i] = byte(i)
	}
	return Secret{
		Helpers: []Helper{
			{
				ChannelID:    "11",
				Transports:        []EndpointJSON{{URI: "https://helper.example.com", Protocol: 0}},
				SharedKey:    sharedKey,
			},
		},
		Secrets: []UserSecret{
			{ID: []byte{0x01}, Name: "wallet", Data: []byte("correct horse battery staple")},
		},
	}
}

// TestRestore_HappyPath_PersistsHelperChannel drives the genuine FFI round
// trip for restore(): no peer is required (it only rebuilds local store
// state — see library/src/protocol/handlers/restore.rs), so this is a real
// happy-path test, not a bind/error-path stand-in. It proves the params
// JSON this package builds decodes correctly on the Rust side by checking
// an externally observable effect: the restored helper channel now has a
// derivable fingerprint.
func TestRestore_HappyPath_PersistsHelperChannel(t *testing.T) {
	p := newTestProtocol(t)
	secret := fixtureRestoreSecret(11)

	events, err := p.Restore(secret, 7)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	_ = events

	if _, err := p.GetFingerprint(11); err != nil {
		t.Fatalf("GetFingerprint on the restored helper channel: %v", err)
	}
}

// TestRestore_AlreadyRestored_ReturnsCleanError calls Restore twice for the
// same secret_id: the second call must fail with a structured error
// (RestoreError::AlreadyRestored on the Rust side) rather than silently
// re-applying or crashing.
func TestRestore_AlreadyRestored_ReturnsCleanError(t *testing.T) {
	p := newTestProtocol(t)
	secret := fixtureRestoreSecret(11)

	if _, err := p.Restore(secret, 7); err != nil {
		t.Fatalf("first Restore: %v", err)
	}
	_, err := p.Restore(secret, 7)
	if err == nil {
		t.Fatal("expected an error on the second Restore")
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestRestore_ClosedProtocol asserts the closed-instance guard rejects the
// call instead of touching a freed handle.
func TestRestore_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.Restore(fixtureRestoreSecret(11), 7); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}
