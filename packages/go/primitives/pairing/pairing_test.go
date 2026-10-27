// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package pairing_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/pairing"
	"google.golang.org/protobuf/proto"
)

// encodeTransportProtocol hand-encodes a org.derecalliance.derec.protobuf
// TransportProtocol message (protobufs/protobufs/transportprotocol.proto):
// field 1 "uri" (string), field 2 "protocol" (enum, HTTPS = 0). The wrapper
// API accepts/returns raw proto bytes like every other primitive; this test
// builds the one message application code is responsible for supplying from
// scratch.
func encodeTransportProtocol(uri string) []byte {
	buf := []byte{0x0A} // field 1, wire type 2 (length-delimited)
	buf = appendVarint(buf, uint64(len(uri)))
	buf = append(buf, uri...)
	return buf
}

// encodeTransportList frames endpoints the way the FFI seam expects: each
// entry preceded by its varint byte length.
func encodeTransportList(uris ...string) []byte {
	var out []byte
	for _, uri := range uris {
		entry := encodeTransportProtocol(uri)
		out = appendVarint(out, uint64(len(entry)))
		out = append(out, entry...)
	}
	return out
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// TestPairingInlineKeysHandshakeRoundTrip drives a full INLINE_KEYS
// handshake for channel id 1, asserting both sides derive the same shared
// key and the same rekeyed channel id, which must differ from the original.
func TestPairingInlineKeysHandshakeRoundTrip(t *testing.T) {
	const channelID = uint64(1)

	aliceTransport := encodeTransportList("https://example.com/alice")
	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, aliceTransport, nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	if len(created.ContactWireBytes) == 0 {
		t.Fatal("CreateContact returned empty contact wire bytes")
	}
	if len(created.SecretKeyMaterial) == 0 {
		t.Fatal("CreateContact returned empty secret key material")
	}

	if _, err := pairing.Request.DecodeContact(created.ContactWireBytes); err != nil {
		t.Fatalf("DecodeContact: %v", err)
	}

	bobTransport := encodeTransportList("https://example.com/helper")
	producedReq, err := pairing.Request.Produce(pairing.SenderKindHelper, bobTransport, created.ContactWireBytes, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	if len(producedReq.Envelope) == 0 {
		t.Fatal("Request.Produce returned empty envelope")
	}
	if len(producedReq.SecretKeyMaterial) == 0 {
		t.Fatal("Request.Produce returned empty secret key material")
	}

	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}
	if len(extractedReq.RequestProto) == 0 {
		t.Fatal("Request.Extract returned empty request proto")
	}

	producedResp, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, false)
	if err != nil {
		t.Fatalf("Response.Produce: %v", err)
	}
	if len(producedResp.Envelope) == 0 {
		t.Fatal("Response.Produce returned empty envelope")
	}
	// The endpoints the requester advertised come back decoded, in its order.
	// Reading them as a single encoded TransportProtocol is the bug this
	// guards: the buffer carries a length-delimited list, not one message.
	if len(producedResp.PeerTransports) != 1 {
		t.Fatalf("Response.Produce: want 1 peer transport, got %d", len(producedResp.PeerTransports))
	}
	if producedResp.PeerTransports[0].URI != "https://example.com/helper" {
		t.Fatalf("Response.Produce: unexpected peer transport %q", producedResp.PeerTransports[0].URI)
	}
	if len(producedResp.SharedKey) == 0 {
		t.Fatal("Response.Produce returned empty shared key (initiator side)")
	}

	extractedResp, err := pairing.Response.Extract(producedResp.Envelope, producedReq.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.Extract: %v", err)
	}
	if len(extractedResp.ResponseProto) == 0 {
		t.Fatal("Response.Extract returned empty response proto")
	}

	processed, err := pairing.Response.Process(producedReq.InitiatorContactMessage, extractedResp.ResponseProto, producedReq.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Response.Process: %v", err)
	}
	if len(processed.SharedKey) == 0 {
		t.Fatal("Response.Process returned empty shared key (responder side)")
	}

	if !bytes.Equal(producedResp.SharedKey, processed.SharedKey) {
		t.Fatalf("shared keys derived by both sides must match: initiator=%x responder=%x", producedResp.SharedKey, processed.SharedKey)
	}
	if producedResp.ChannelID != processed.ChannelID {
		t.Fatalf("both sides must derive the same rekeyed channel id: initiator=%d responder=%d", producedResp.ChannelID, processed.ChannelID)
	}
	if producedResp.ChannelID == channelID {
		t.Fatalf("rekeyed channel id must differ from the pre-rekey id %d", channelID)
	}
}

func TestDecodeContactRejectsGarbageBytes(t *testing.T) {
	_, err := pairing.Request.DecodeContact([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected an error for malformed contact message bytes")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeProtobufDecode {
		t.Fatalf("want *derec.Error CodeProtobufDecode, got %#v", err)
	}
}

// TestContactCodecRoundTripsEveryMode decodes the bytes the core produced
// into the typed contact and re-encodes it: the bytes must come back
// identical, so no field is lost on the way through this SDK.
func TestContactCodecRoundTripsEveryMode(t *testing.T) {
	nonce := uint64(777)
	for _, mode := range []pairing.ContactMode{
		pairing.ContactModeInlineKeys,
		pairing.ContactModeHashedKeys,
		pairing.ContactModeNoKeys,
	} {
		created, err := pairing.Request.CreateContact(^uint64(0), mode,
			encodeTransportList("https://example.com/alice", "https://example.com/alice/backup"), &nonce)
		if err != nil {
			t.Fatalf("CreateContact(%d): %v", mode, err)
		}
		contact, err := pairing.Request.DecodeContact(created.ContactWireBytes)
		if err != nil {
			t.Fatalf("DecodeContact(%d): %v", mode, err)
		}
		if contact.ChannelID != ^uint64(0) || contact.Nonce != nonce || contact.ContactMode != mode {
			t.Fatalf("DecodeContact(%d): unexpected header %+v", mode, contact)
		}
		if len(contact.SupportedTransports) != 2 || contact.SupportedTransports[1].URI != "https://example.com/alice/backup" {
			t.Fatalf("DecodeContact(%d): endpoints %+v", mode, contact.SupportedTransports)
		}
		if contact.Timestamp == nil {
			t.Fatalf("DecodeContact(%d): timestamp missing", mode)
		}
		wantCommitment := 0
		if mode == pairing.ContactModeInlineKeys {
			wantCommitment = 32
		}
		if len(contact.FingerprintCommitment) != wantCommitment {
			t.Fatalf("DecodeContact(%d): fingerprint commitment is %d bytes, want %d", mode, len(contact.FingerprintCommitment), wantCommitment)
		}
		encoded, err := pairing.Request.EncodeContact(contact)
		if err != nil {
			t.Fatalf("EncodeContact(%d): %v", mode, err)
		}
		if !bytes.Equal(encoded, created.ContactWireBytes) {
			t.Fatalf("EncodeContact(%d): bytes differ from the core's", mode)
		}
	}
}

// TestContactCodecRefusesAnInvalidContact builds an INLINE_KEYS contact that
// also carries a binding hash: it is refused on encode, and the same value
// as wire bytes is refused on decode.
func TestContactCodecRefusesAnInvalidContact(t *testing.T) {
	invalid := pairing.ContactMessage{
		ChannelID:             7,
		Nonce:                 9,
		ContactMode:           pairing.ContactModeInlineKeys,
		MlkemEncapsulationKey: []byte{1, 2, 3},
		EciesPublicKey:        []byte{4, 5, 6},
		ContactBindingHash:    make([]byte, 48),
		FingerprintCommitment: make([]byte, 32),
		SupportedTransports:   []pairing.Endpoint{{URI: "https://example.com/alice"}},
	}
	_, err := pairing.Request.EncodeContact(invalid)
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeInvalidContactMessage {
		t.Fatalf("EncodeContact: want CodeInvalidContactMessage, got %#v", err)
	}

	wire, err := proto.Marshal(&derecpb.ContactMessage{
		ChannelId:             7,
		Nonce:                 9,
		ContactMode:           derecpb.ContactMode_INLINE_KEYS,
		MlkemEncapsulationKey: []byte{1, 2, 3},
		EciesPublicKey:        []byte{4, 5, 6},
		ContactBindingHash:    make([]byte, 48),
		FingerprintCommitment: make([]byte, 32),
		SupportedTransports:   []*derecpb.TransportProtocol{{Uri: "https://example.com/alice"}},
	})
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	_, err = pairing.Request.DecodeContact(wire)
	if !errors.As(err, &derr) || derr.Code != derec.CodeInvalidContactMessage {
		t.Fatalf("DecodeContact: want CodeInvalidContactMessage, got %#v", err)
	}
}

func shareSizeRange(t *testing.T, minSize, maxSize int64) []byte {
	t.Helper()
	b, err := proto.Marshal(&derecpb.ParameterRange{
		MinShareSize:                       minSize,
		MaxShareSize:                       maxSize,
		MaxTimeBetweenVerifications:        math.MaxInt64,
		MaxTimeBetweenShareUpdates:         math.MaxInt64,
		MaxUnresponsiveDeletionTimeout:     math.MaxInt64,
		MaxUnresponsiveDeactivationTimeout: math.MaxInt64,
	})
	if err != nil {
		t.Fatalf("proto.Marshal(ParameterRange): %v", err)
	}
	return b
}

func requireIncompatibleRange(t *testing.T, what string, err error) {
	t.Helper()
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeIncompatibleParameterRange {
		t.Fatalf("%s: want CodeIncompatibleParameterRange, got %#v", what, err)
	}
}

// TestPairingRefusesAnIncompatibleParameterRange: disjoint ranges are
// refused by the primitives themselves on both sides, with no separate check
// for the application to call.
func TestPairingRefusesAnIncompatibleParameterRange(t *testing.T) {
	const channelID = uint64(9)
	creatorRange := shareSizeRange(t, 1_000_000_000, 5_000_000_000)
	scannerRange := shareSizeRange(t, 10_000_000, 500_000_000)

	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, encodeTransportList("https://example.com/alice"), nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}

	ranged, err := pairing.Request.Produce(pairing.SenderKindHelper, encodeTransportList("https://example.com/helper"), created.ContactWireBytes, nil, scannerRange)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	_, err = pairing.Request.Extract(ranged.Envelope, created.SecretKeyMaterial, creatorRange)
	requireIncompatibleRange(t, "Request.Extract", err)
	unchecked, err := pairing.Request.Extract(ranged.Envelope, created.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Request.Extract without a local range: %v", err)
	}
	_, err = pairing.Response.Produce(channelID, unchecked.RequestProto, created.SecretKeyMaterial, nil, creatorRange, false)
	requireIncompatibleRange(t, "Response.Produce", err)

	plain, err := pairing.Request.Produce(pairing.SenderKindHelper, encodeTransportList("https://example.com/helper"), created.ContactWireBytes, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	extracted, err := pairing.Request.Extract(plain.Envelope, created.SecretKeyMaterial, creatorRange)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}
	produced, err := pairing.Response.Produce(channelID, extracted.RequestProto, created.SecretKeyMaterial, nil, creatorRange, false)
	if err != nil {
		t.Fatalf("Response.Produce: %v", err)
	}
	extractedResp, err := pairing.Response.Extract(produced.Envelope, plain.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.Extract: %v", err)
	}
	_, err = pairing.Response.Process(plain.InitiatorContactMessage, extractedResp.ResponseProto, plain.SecretKeyMaterial, scannerRange)
	requireIncompatibleRange(t, "Response.Process", err)

	processed, err := pairing.Response.Process(plain.InitiatorContactMessage, extractedResp.ResponseProto, plain.SecretKeyMaterial,
		shareSizeRange(t, 1_000_000_000, 2_000_000_000))
	if err != nil {
		t.Fatalf("Response.Process with an overlapping range: %v", err)
	}
	if !bytes.Equal(processed.SharedKey, produced.SharedKey) {
		t.Fatal("overlapping ranges must pair to the same shared key")
	}
}

func TestCreateContactRejectsInvalidContactMode(t *testing.T) {
	_, err := pairing.Request.CreateContact(1, pairing.ContactMode(99), encodeTransportList("https://example.com"), nil)
	if err == nil {
		t.Fatal("expected an error for an invalid ContactMode value")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeFFIInvalidEnum {
		t.Fatalf("want *derec.Error CodeFFIInvalidEnum, got %#v", err)
	}
}

// tamperContactBindingHash flips one byte inside the contactBindingHash field
// (field 4, wire type 2 length-delimited, protobufs/protobufs/contact.proto)
// of a HASHED_KEYS ContactMessage, simulating an attacker who swapped in a
// different SHA-384 commitment on the out-of-band channel. The Go SDK has no
// generated ContactMessage bindings, so this locates the field by its wire
// tag plus the fixed 48-byte SHA-384 length rather than a full proto decode.
// XORing with 0xFF is guaranteed to change the byte (b^0xFF == b would imply
// 0xFF == 0), so the resulting hash is deterministically wrong.
func tamperContactBindingHash(t *testing.T, contactWireBytes []byte) []byte {
	t.Helper()
	tag := []byte{0x22, 0x30} // field 4, wire type 2, length 48
	idx := bytes.Index(contactWireBytes, tag)
	if idx < 0 {
		t.Fatal("contactBindingHash field not found in contact wire bytes")
	}
	hashStart := idx + len(tag)
	tampered := append([]byte(nil), contactWireBytes...)
	tampered[hashStart] ^= 0xFF
	return tampered
}

// TestPairingHashedKeysPrePairRoundTrip drives the PrePair leg: a
// HASHED_KEYS contact carries only a binding hash, the scanner
// requests the real keys over an ephemeral PrePair exchange, and
// Response.ProcessPrePair validates the republished keys against that hash
// before returning them.
func TestPairingHashedKeysPrePairRoundTrip(t *testing.T) {
	const channelID = uint64(2)
	const expectedNonce = uint64(0x1234_5678)

	aliceTransport := encodeTransportList("https://example.com/alice/ephemeral")
	nonce := expectedNonce
	aliceContact, err := pairing.Request.CreateContact(channelID, pairing.ContactModeHashedKeys, aliceTransport, &nonce)
	if err != nil {
		t.Fatalf("CreateContact (HASHED_KEYS): %v", err)
	}
	if len(aliceContact.ContactWireBytes) == 0 {
		t.Fatal("CreateContact (HASHED_KEYS) returned empty contact wire bytes")
	}
	if len(aliceContact.SecretKeyMaterial) == 0 {
		t.Fatal("CreateContact (HASHED_KEYS) returned empty secret key material")
	}

	if _, err := pairing.Request.DecodeContact(aliceContact.ContactWireBytes); err != nil {
		t.Fatalf("DecodeContact (HASHED_KEYS contact): %v", err)
	}

	// PrePair now advertises the scanner's whole list, framed like every
	// other endpoint list crossing the seam.
	bobTransport := encodeTransportList("https://example.com/helper/ephemeral")
	prepairReq, err := pairing.Request.ProducePrePair(bobTransport, aliceContact.ContactWireBytes)
	if err != nil {
		t.Fatalf("Request.ProducePrePair: %v", err)
	}
	if len(prepairReq.Envelope) == 0 {
		t.Fatal("Request.ProducePrePair returned empty envelope")
	}

	extractedReq, err := pairing.Request.ExtractPrePair(prepairReq.Envelope)
	if err != nil {
		t.Fatalf("Request.ExtractPrePair: %v", err)
	}
	if len(extractedReq.RequestProto) == 0 {
		t.Fatal("Request.ExtractPrePair returned empty request proto")
	}

	prepairResp, err := pairing.Response.ProducePrePair(channelID, extractedReq.RequestProto, aliceContact.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.ProducePrePair: %v", err)
	}
	if len(prepairResp.Envelope) == 0 {
		t.Fatal("Response.ProducePrePair returned empty envelope")
	}

	extractedResp, err := pairing.Response.ExtractPrePair(prepairResp.Envelope)
	if err != nil {
		t.Fatalf("Response.ExtractPrePair: %v", err)
	}
	if len(extractedResp.ResponseProto) == 0 {
		t.Fatal("Response.ExtractPrePair returned empty response proto")
	}

	processed, err := pairing.Response.ProcessPrePair(aliceContact.ContactWireBytes, extractedResp.ResponseProto)
	if err != nil {
		t.Fatalf("Response.ProcessPrePair: %v", err)
	}
	if len(processed.MlkemEncapsulationKey) == 0 {
		t.Fatal("Response.ProcessPrePair returned empty mlkem encapsulation key")
	}
	if len(processed.EciesPublicKey) == 0 {
		t.Fatal("Response.ProcessPrePair returned empty ecies public key")
	}
	if processed.Nonce != expectedNonce {
		t.Fatalf("Response.ProcessPrePair nonce = %d, want echoed contact nonce %d", processed.Nonce, expectedNonce)
	}
	var respMsg derecpb.PrePairResponseMessage
	if err := proto.Unmarshal(extractedResp.ResponseProto, &respMsg); err != nil {
		t.Fatalf("decode PrePairResponseMessage: %v", err)
	}
	if len(processed.FingerprintCommitment) != 32 || !bytes.Equal(processed.FingerprintCommitment, respMsg.GetFingerprintCommitment()) {
		t.Fatalf("Response.ProcessPrePair fingerprint commitment = %x, want the response's %x", processed.FingerprintCommitment, respMsg.GetFingerprintCommitment())
	}
}

// TestProcessPrePairRejectsBindingHashMismatch is the security-critical
// negative case: an attacker who tampers with the published keys (or, as
// here, the contact's binding hash itself) between the out-of-band exchange
// and PrePair completion must be caught by Response.ProcessPrePair's SHA-384
// recomputation, surfacing derec.CodePrepairHashMismatch rather than silently
// accepting mismatched keys.
func TestProcessPrePairRejectsBindingHashMismatch(t *testing.T) {
	const channelID = uint64(3)
	nonce := uint64(0xABCD)

	aliceTransport := encodeTransportList("https://example.com/alice/ephemeral")
	aliceContact, err := pairing.Request.CreateContact(channelID, pairing.ContactModeHashedKeys, aliceTransport, &nonce)
	if err != nil {
		t.Fatalf("CreateContact (HASHED_KEYS): %v", err)
	}

	// PrePair now advertises the scanner's whole list, framed like every
	// other endpoint list crossing the seam.
	bobTransport := encodeTransportList("https://example.com/helper/ephemeral")
	prepairReq, err := pairing.Request.ProducePrePair(bobTransport, aliceContact.ContactWireBytes)
	if err != nil {
		t.Fatalf("Request.ProducePrePair: %v", err)
	}

	extractedReq, err := pairing.Request.ExtractPrePair(prepairReq.Envelope)
	if err != nil {
		t.Fatalf("Request.ExtractPrePair: %v", err)
	}

	prepairResp, err := pairing.Response.ProducePrePair(channelID, extractedReq.RequestProto, aliceContact.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.ProducePrePair: %v", err)
	}

	extractedResp, err := pairing.Response.ExtractPrePair(prepairResp.Envelope)
	if err != nil {
		t.Fatalf("Response.ExtractPrePair: %v", err)
	}

	tamperedContact := tamperContactBindingHash(t, aliceContact.ContactWireBytes)

	_, err = pairing.Response.ProcessPrePair(tamperedContact, extractedResp.ResponseProto)
	if err == nil {
		t.Fatal("expected an error when the published keys don't match the (tampered) contact binding hash")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodePrepairHashMismatch {
		t.Fatalf("want *derec.Error CodePrepairHashMismatch, got %#v", err)
	}
}

// TestPairingResponseRejectsPlaintextPeerEndpoint asserts the plaintext
// guardrail actually reaches the library across the FFI seam: a requester
// advertising only http:// must be refused unless unsafeConnection is set.
//
// This guards the argument list as much as the policy. unsafeConnection is
// the last scalar the C function reads, so an SDK passing an extra argument
// ahead of it hands the library a stray value in that slot and silently
// enables plaintext — which is not observable from a handshake that only
// ever uses https://.
func TestPairingResponseRejectsPlaintextPeerEndpoint(t *testing.T) {
	const channelID = uint64(7)

	aliceTransport := encodeTransportList("https://example.com/alice")
	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, aliceTransport, nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}

	bobTransport := encodeTransportList("http://example.com/helper")
	producedReq, err := pairing.Request.Produce(pairing.SenderKindHelper, bobTransport, created.ContactWireBytes, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}

	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}

	if _, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, false); err == nil {
		t.Fatal("Response.Produce accepted a plaintext-only peer with unsafeConnection=false")
	}

	// The same request succeeds once plaintext is opted into, proving the
	// rejection above came from the policy and not from a malformed request.
	produced, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, true)
	if err != nil {
		t.Fatalf("Response.Produce with unsafeConnection=true: %v", err)
	}
	if len(produced.PeerTransports) != 1 || produced.PeerTransports[0].URI != "http://example.com/helper" {
		t.Fatalf("Response.Produce: unexpected peer transports %+v", produced.PeerTransports)
	}
}

// TestPairingNoKeysPrePairRoundTrip drives a complete NO_KEYS pairing
// through primitives only: the contact carries no keys, the creator
// authenticates the PrePair request by nonce and generates keys on the spot,
// the scanner accepts them unbound and finishes the handshake against an
// INLINE_KEYS-shaped contact, and both ends confirm by fingerprint.
func TestPairingNoKeysPrePairRoundTrip(t *testing.T) {
	const channelID = uint64(4)
	nonce := uint64(424242)

	aliceTransport := encodeTransportList("https://example.com/alice/ephemeral")
	aliceContact, err := pairing.Request.CreateContact(channelID, pairing.ContactModeNoKeys, aliceTransport, &nonce)
	if err != nil {
		t.Fatalf("CreateContact (NO_KEYS): %v", err)
	}
	if _, err := pairing.Request.DecodeContact(aliceContact.ContactWireBytes); err != nil {
		t.Fatalf("DecodeContact (NO_KEYS contact): %v", err)
	}

	bobTransport := encodeTransportList("https://example.com/helper/ephemeral")
	prepairReq, err := pairing.Request.ProducePrePair(bobTransport, aliceContact.ContactWireBytes)
	if err != nil {
		t.Fatalf("Request.ProducePrePair: %v", err)
	}

	extractedReq, err := pairing.Request.ExtractPrePair(prepairReq.Envelope)
	if err != nil {
		t.Fatalf("Request.ExtractPrePair: %v", err)
	}
	var reqMsg derecpb.PrePairRequestMessage
	if err := proto.Unmarshal(extractedReq.RequestProto, &reqMsg); err != nil {
		t.Fatalf("decode PrePairRequestMessage: %v", err)
	}
	if reqMsg.GetNonce() != nonce {
		t.Fatalf("PrePair request nonce = %d, want the issued contact nonce %d", reqMsg.GetNonce(), nonce)
	}

	prepairResp, err := pairing.Response.ProducePrePairNoKeys(channelID, extractedReq.RequestProto)
	if err != nil {
		t.Fatalf("Response.ProducePrePairNoKeys: %v", err)
	}
	if len(prepairResp.Envelope) == 0 || len(prepairResp.SecretKeyMaterial) == 0 {
		t.Fatal("Response.ProducePrePairNoKeys returned an empty envelope or secret key material")
	}

	extractedResp, err := pairing.Response.ExtractPrePair(prepairResp.Envelope)
	if err != nil {
		t.Fatalf("Response.ExtractPrePair: %v", err)
	}

	processed, err := pairing.Response.ProcessPrePairNoKeys(aliceContact.ContactWireBytes, extractedResp.ResponseProto)
	if err != nil {
		t.Fatalf("Response.ProcessPrePairNoKeys: %v", err)
	}
	if len(processed.MlkemEncapsulationKey) == 0 || len(processed.EciesPublicKey) == 0 {
		t.Fatal("Response.ProcessPrePairNoKeys returned empty keys")
	}
	if processed.Nonce != nonce {
		t.Fatalf("Response.ProcessPrePairNoKeys nonce = %d, want %d", processed.Nonce, nonce)
	}

	filledIn := inlineContactWithKeys(t, aliceContact.ContactWireBytes, processed)

	pairReq, err := pairing.Request.Produce(pairing.SenderKindHelper, encodeTransportList("https://example.com/helper"), filledIn, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	extractedPairReq, err := pairing.Request.Extract(pairReq.Envelope, prepairResp.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}
	produced, err := pairing.Response.Produce(channelID, extractedPairReq.RequestProto, prepairResp.SecretKeyMaterial, nil, nil, false)
	if err != nil {
		t.Fatalf("Response.Produce: %v", err)
	}
	extractedPairResp, err := pairing.Response.Extract(produced.Envelope, pairReq.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.Extract: %v", err)
	}
	processedPair, err := pairing.Response.Process(pairReq.InitiatorContactMessage, extractedPairResp.ResponseProto, pairReq.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Response.Process: %v", err)
	}

	if !bytes.Equal(produced.SharedKey, processedPair.SharedKey) {
		t.Fatal("shared keys derived by both sides must match (NO_KEYS path)")
	}
	if produced.ChannelID != processedPair.ChannelID {
		t.Fatalf("rekeyed channel id mismatch: creator=%d scanner=%d", produced.ChannelID, processedPair.ChannelID)
	}

	aliceFP, err := pairing.Fingerprint(produced.SharedKey)
	if err != nil {
		t.Fatalf("Fingerprint (creator): %v", err)
	}
	bobFP, err := pairing.Fingerprint(processedPair.SharedKey)
	if err != nil {
		t.Fatalf("Fingerprint (scanner): %v", err)
	}
	if aliceFP == "" || aliceFP != bobFP {
		t.Fatalf("fingerprints must be equal and non-empty: creator=%q scanner=%q", aliceFP, bobFP)
	}

	if _, err := pairing.Fingerprint(make([]byte, 31)); err == nil {
		t.Fatal("Fingerprint must refuse a 31-byte shared key")
	}
}

// inlineContactWithKeys rewrites a NO_KEYS or HASHED_KEYS contact into the
// INLINE_KEYS shape Request.Produce requires, carrying the keys and the
// fingerprint commitment PrePair returned.
func inlineContactWithKeys(t *testing.T, contactWireBytes []byte, keys pairing.ProcessedPrePair) []byte {
	t.Helper()
	var contact derecpb.ContactMessage
	if err := proto.Unmarshal(contactWireBytes, &contact); err != nil {
		t.Fatalf("decode ContactMessage: %v", err)
	}
	contact.ContactMode = derecpb.ContactMode_INLINE_KEYS
	contact.MlkemEncapsulationKey = keys.MlkemEncapsulationKey
	contact.EciesPublicKey = keys.EciesPublicKey
	contact.FingerprintCommitment = keys.FingerprintCommitment
	contact.ContactBindingHash = nil
	out, err := proto.Marshal(&contact)
	if err != nil {
		t.Fatalf("encode ContactMessage: %v", err)
	}
	return out
}

func requireCode(t *testing.T, what string, err error, want int32) {
	t.Helper()
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != want {
		t.Fatalf("%s: want code %d, got %#v", what, want, err)
	}
}

// inlineKeysHandshake runs one INLINE_KEYS handshake up to the scanner
// holding the decrypted pair response. It returns the creator's contact, the
// contact the scanner processes the response against, the response proto,
// the scanner's secret key material, and the key the creator derived.
func inlineKeysHandshake(t *testing.T) (contact, initiatorContact, responseProto, scannerSecret, creatorKey []byte) {
	t.Helper()
	const channelID = uint64(42)
	created, err := pairing.Request.CreateContact(channelID, pairing.ContactModeInlineKeys, encodeTransportList("https://relay.example/alice"), nil)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	req, err := pairing.Request.Produce(pairing.SenderKindHelper, encodeTransportList("https://relay.example/bob"), created.ContactWireBytes, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	extractedReq, err := pairing.Request.Extract(req.Envelope, created.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}
	produced, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil, false)
	if err != nil {
		t.Fatalf("Response.Produce: %v", err)
	}
	extractedResp, err := pairing.Response.Extract(produced.Envelope, req.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.Extract: %v", err)
	}
	return created.ContactWireBytes, req.InitiatorContactMessage, extractedResp.ResponseProto, req.SecretKeyMaterial, produced.SharedKey
}

func decodePairResponse(t *testing.T, responseProto []byte) *derecpb.PairResponseMessage {
	t.Helper()
	var msg derecpb.PairResponseMessage
	if err := proto.Unmarshal(responseProto, &msg); err != nil {
		t.Fatalf("decode PairResponseMessage: %v", err)
	}
	return &msg
}

func encodeProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	out, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return out
}

// TestPairResponseRevealsTheNonceTheContactCommittedTo: the nonce an
// accepted response reveals opens the commitment the contact published,
// SHA-256("DeRec fingerprint commitment v1" || mlkemEK || eciesPK || nonce).
func TestPairResponseRevealsTheNonceTheContactCommittedTo(t *testing.T) {
	contactWire, _, responseProto, _, _ := inlineKeysHandshake(t)
	contact, err := pairing.Request.DecodeContact(contactWire)
	if err != nil {
		t.Fatalf("DecodeContact: %v", err)
	}
	nonce := decodePairResponse(t, responseProto).GetFingerprintNonce()
	if len(nonce) != 32 {
		t.Fatalf("pair response fingerprint nonce is %d bytes, want 32", len(nonce))
	}
	h := sha256.New()
	h.Write([]byte("DeRec fingerprint commitment v1"))
	h.Write(contact.MlkemEncapsulationKey)
	h.Write(contact.EciesPublicKey)
	h.Write(nonce)
	if !bytes.Equal(h.Sum(nil), contact.FingerprintCommitment) {
		t.Fatal("the revealed nonce must open the contact's fingerprint commitment")
	}
}

// TestBothSidesDeriveTheChannelKeyFromTheRevealedNonce: the honest response
// completes pairing with the creator's key and fingerprint.
func TestBothSidesDeriveTheChannelKeyFromTheRevealedNonce(t *testing.T) {
	_, initiatorContact, responseProto, scannerSecret, creatorKey := inlineKeysHandshake(t)
	processed, err := pairing.Response.Process(initiatorContact, responseProto, scannerSecret, nil)
	if err != nil {
		t.Fatalf("Response.Process: %v", err)
	}
	if !bytes.Equal(processed.SharedKey, creatorKey) {
		t.Fatal("both sides must derive the same channel key")
	}
	creatorFP, err := pairing.Fingerprint(creatorKey)
	if err != nil {
		t.Fatalf("Fingerprint (creator): %v", err)
	}
	scannerFP, err := pairing.Fingerprint(processed.SharedKey)
	if err != nil {
		t.Fatalf("Fingerprint (scanner): %v", err)
	}
	if creatorFP != scannerFP {
		t.Fatalf("fingerprints differ: creator=%q scanner=%q", creatorFP, scannerFP)
	}
}

func TestPairResponseWhoseNonceDoesNotOpenTheCommitmentIsRefused(t *testing.T) {
	_, initiatorContact, responseProto, scannerSecret, _ := inlineKeysHandshake(t)
	msg := decodePairResponse(t, responseProto)
	msg.FingerprintNonce[0] ^= 1
	_, err := pairing.Response.Process(initiatorContact, encodeProto(t, msg), scannerSecret, nil)
	requireCode(t, "Response.Process", err, derec.CodeFingerprintCommitmentMismatch)
}

func TestPairResponseWithoutAFingerprintNonceIsRefused(t *testing.T) {
	_, initiatorContact, responseProto, scannerSecret, _ := inlineKeysHandshake(t)
	msg := decodePairResponse(t, responseProto)
	msg.FingerprintNonce = nil
	_, err := pairing.Response.Process(initiatorContact, encodeProto(t, msg), scannerSecret, nil)
	requireCode(t, "Response.Process", err, derec.CodeInvalidPairResponseMessage)
}

// prePairLeg runs the PrePair exchange for a fresh contact of mode and
// returns the contact, the PrePair request proto, and the creator's
// response proto.
func prePairLeg(t *testing.T, mode pairing.ContactMode) (contact, requestProto, responseProto []byte) {
	t.Helper()
	const channelID = uint64(7)
	nonce := uint64(4321)
	created, err := pairing.Request.CreateContact(channelID, mode, encodeTransportList("https://relay.example/alice"), &nonce)
	if err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
	req, err := pairing.Request.ProducePrePair(encodeTransportList("https://relay.example/bob"), created.ContactWireBytes)
	if err != nil {
		t.Fatalf("Request.ProducePrePair: %v", err)
	}
	extractedReq, err := pairing.Request.ExtractPrePair(req.Envelope)
	if err != nil {
		t.Fatalf("Request.ExtractPrePair: %v", err)
	}
	var envelope []byte
	if mode == pairing.ContactModeNoKeys {
		answer, err := pairing.Response.ProducePrePairNoKeys(channelID, extractedReq.RequestProto)
		if err != nil {
			t.Fatalf("Response.ProducePrePairNoKeys: %v", err)
		}
		envelope = answer.Envelope
	} else {
		answer, err := pairing.Response.ProducePrePair(channelID, extractedReq.RequestProto, created.SecretKeyMaterial)
		if err != nil {
			t.Fatalf("Response.ProducePrePair: %v", err)
		}
		envelope = answer.Envelope
	}
	extractedResp, err := pairing.Response.ExtractPrePair(envelope)
	if err != nil {
		t.Fatalf("Response.ExtractPrePair: %v", err)
	}
	return created.ContactWireBytes, extractedReq.RequestProto, extractedResp.ResponseProto
}

func withoutPrePairCommitment(t *testing.T, responseProto []byte) []byte {
	t.Helper()
	var msg derecpb.PrePairResponseMessage
	if err := proto.Unmarshal(responseProto, &msg); err != nil {
		t.Fatalf("decode PrePairResponseMessage: %v", err)
	}
	msg.FingerprintCommitment = nil
	return encodeProto(t, &msg)
}

func TestHashedKeysPrePairResponseWithoutACommitmentIsRefused(t *testing.T) {
	contact, _, responseProto := prePairLeg(t, pairing.ContactModeHashedKeys)
	_, err := pairing.Response.ProcessPrePair(contact, withoutPrePairCommitment(t, responseProto))
	requireCode(t, "Response.ProcessPrePair", err, derec.CodeInvalidPairResponseMessage)
}

func TestNoKeysPrePairResponseWithoutACommitmentIsRefused(t *testing.T) {
	contact, _, responseProto := prePairLeg(t, pairing.ContactModeNoKeys)
	_, err := pairing.Response.ProcessPrePairNoKeys(contact, withoutPrePairCommitment(t, responseProto))
	requireCode(t, "Response.ProcessPrePairNoKeys", err, derec.CodeInvalidPairResponseMessage)
}

// TestRelayCannotPassOffTheCreatorsCommitmentAsItsOwn: a relay on the
// PrePair leg answers the scanner with its own keys and copies the creator's
// commitment. That commitment covers the creator's keys and opens only with
// the creator's nonce, so the relay's pairing response is refused.
func TestRelayCannotPassOffTheCreatorsCommitmentAsItsOwn(t *testing.T) {
	const channelID = uint64(7)
	contact, requestProto, creatorAnswer := prePairLeg(t, pairing.ContactModeNoKeys)
	var creatorMsg derecpb.PrePairResponseMessage
	if err := proto.Unmarshal(creatorAnswer, &creatorMsg); err != nil {
		t.Fatalf("decode PrePairResponseMessage: %v", err)
	}

	relay, err := pairing.Response.ProducePrePairNoKeys(channelID, requestProto)
	if err != nil {
		t.Fatalf("relay Response.ProducePrePairNoKeys: %v", err)
	}
	relayedResp, err := pairing.Response.ExtractPrePair(relay.Envelope)
	if err != nil {
		t.Fatalf("Response.ExtractPrePair (relayed): %v", err)
	}
	var relayed derecpb.PrePairResponseMessage
	if err := proto.Unmarshal(relayedResp.ResponseProto, &relayed); err != nil {
		t.Fatalf("decode PrePairResponseMessage: %v", err)
	}
	relayed.FingerprintCommitment = creatorMsg.GetFingerprintCommitment()

	validated, err := pairing.Response.ProcessPrePairNoKeys(contact, encodeProto(t, &relayed))
	if err != nil {
		t.Fatalf("Response.ProcessPrePairNoKeys must accept unbound NO_KEYS keys: %v", err)
	}
	filledIn := inlineContactWithKeys(t, contact, validated)

	req, err := pairing.Request.Produce(pairing.SenderKindHelper, encodeTransportList("https://relay.example/bob"), filledIn, nil, nil)
	if err != nil {
		t.Fatalf("Request.Produce: %v", err)
	}
	extractedReq, err := pairing.Request.Extract(req.Envelope, relay.SecretKeyMaterial, nil)
	if err != nil {
		t.Fatalf("relay Request.Extract: %v", err)
	}
	produced, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, relay.SecretKeyMaterial, nil, nil, false)
	if err != nil {
		t.Fatalf("relay Response.Produce: %v", err)
	}
	extractedResp, err := pairing.Response.Extract(produced.Envelope, req.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Response.Extract: %v", err)
	}
	_, err = pairing.Response.Process(req.InitiatorContactMessage, extractedResp.ResponseProto, req.SecretKeyMaterial, nil)
	requireCode(t, "Response.Process", err, derec.CodeFingerprintCommitmentMismatch)
}
