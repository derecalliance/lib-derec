// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package pairing_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/primitives/pairing"
)

// encodeTransportProtocol hand-encodes a org.derecalliance.derec.protobuf
// TransportProtocol message (protobufs/protobufs/transportprotocol.proto):
// field 1 "uri" (string), field 2 "protocol" (enum, HTTPS = 0). The Go SDK
// has no generated proto bindings, and the wrapper API accepts/returns raw
// proto bytes like every other primitive; this test builds the one message
// application code is responsible for supplying from scratch.
func encodeTransportProtocol(uri string) []byte {
	buf := []byte{0x0A} // field 1, wire type 2 (length-delimited)
	buf = appendVarint(buf, uint64(len(uri)))
	buf = append(buf, uri...)
	return buf
}

func appendVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

// TestPairingInlineKeysHandshakeRoundTrip mirrors
// bindings/rust/src/primitives.rs::run_pairing_flow_test: a full INLINE_KEYS
// handshake for channel id 1, asserting both sides derive the same shared
// key and the same rekeyed channel id, which must differ from the original.
func TestPairingInlineKeysHandshakeRoundTrip(t *testing.T) {
	const channelID = uint64(1)

	aliceTransport := encodeTransportProtocol("https://example.com/alice")
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

	if err := pairing.Request.Validate(created.ContactWireBytes); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	bobTransport := encodeTransportProtocol("https://example.com/helper")
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

	extractedReq, err := pairing.Request.Extract(producedReq.Envelope, created.SecretKeyMaterial)
	if err != nil {
		t.Fatalf("Request.Extract: %v", err)
	}
	if len(extractedReq.RequestProto) == 0 {
		t.Fatal("Request.Extract returned empty request proto")
	}

	producedResp, err := pairing.Response.Produce(channelID, extractedReq.RequestProto, created.SecretKeyMaterial, nil, nil)
	if err != nil {
		t.Fatalf("Response.Produce: %v", err)
	}
	if len(producedResp.Envelope) == 0 {
		t.Fatal("Response.Produce returned empty envelope")
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

	processed, err := pairing.Response.Process(producedReq.InitiatorContactMessage, extractedResp.ResponseProto, producedReq.SecretKeyMaterial)
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

func TestValidateContactMessageRejectsGarbageBytes(t *testing.T) {
	err := pairing.Request.Validate([]byte{0xFF, 0xFF, 0xFF})
	if err == nil {
		t.Fatal("expected an error for malformed contact message bytes")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeFFIBadProto {
		t.Fatalf("want *derec.Error CodeFFIBadProto, got %#v", err)
	}
}

func TestCreateContactRejectsInvalidContactMode(t *testing.T) {
	_, err := pairing.Request.CreateContact(1, pairing.ContactMode(99), encodeTransportProtocol("https://example.com"), nil)
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

// TestPairingHashedKeysPrePairRoundTrip mirrors
// bindings/rust/src/primitives.rs::run_pairing_flow_hashed_keys_test's PrePair
// leg: a HASHED_KEYS contact carries only a binding hash, the scanner
// requests the real keys over an ephemeral PrePair exchange, and
// Response.ProcessPrePair validates the republished keys against that hash
// before returning them.
func TestPairingHashedKeysPrePairRoundTrip(t *testing.T) {
	const channelID = uint64(2)
	const expectedNonce = uint64(0x1234_5678)

	aliceTransport := encodeTransportProtocol("https://example.com/alice/ephemeral")
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

	if err := pairing.Request.Validate(aliceContact.ContactWireBytes); err != nil {
		t.Fatalf("Validate (HASHED_KEYS contact): %v", err)
	}

	bobTransport := encodeTransportProtocol("https://example.com/helper/ephemeral")
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

	aliceTransport := encodeTransportProtocol("https://example.com/alice/ephemeral")
	aliceContact, err := pairing.Request.CreateContact(channelID, pairing.ContactModeHashedKeys, aliceTransport, &nonce)
	if err != nil {
		t.Fatalf("CreateContact (HASHED_KEYS): %v", err)
	}

	bobTransport := encodeTransportProtocol("https://example.com/helper/ephemeral")
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
