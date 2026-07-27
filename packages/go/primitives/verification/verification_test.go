// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package verification_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/primitives/sharing"
	"github.com/derecalliance/lib-derec/packages/go/primitives/verification"
)

func sharedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestVerificationRequestRoundTrip(t *testing.T) {
	const channelID, secretID, version = uint64(7), uint64(42), uint32(1)
	key := sharedKey()

	envelope, err := verification.Request.Produce(channelID, secretID, version, key)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	if len(envelope) == 0 {
		t.Fatal("produce returned empty envelope")
	}

	got, err := verification.Request.Extract(envelope, key)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got.ChannelID != channelID {
		t.Fatalf("channel id: want %d got %d", channelID, got.ChannelID)
	}
	if len(got.RequestProto) == 0 {
		t.Fatal("extract returned empty request proto")
	}
	if bytes.Equal(got.RequestProto, envelope) {
		t.Fatal("request proto should be the inner message, not the wire envelope")
	}
}

func TestVerificationRequestRejectsShortKey(t *testing.T) {
	_, err := verification.Request.Produce(1, 1, 1, make([]byte, 16))
	if err == nil {
		t.Fatal("expected an error for a 16-byte shared key")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeFFIBadSharedKey {
		t.Fatalf("want *derec.Error CodeFFIBadSharedKey, got %#v", err)
	}
}

// TestVerificationResponseRoundTrip mirrors run_verification_flow_test in
// bindings/rust/src/primitives.rs: split a real secret into committed shares,
// challenge channel 1, answer with its share content, and confirm the owner
// accepts a response proving possession of the exact share while rejecting
// one proving possession of a different channel's share.
func TestVerificationResponseRoundTrip(t *testing.T) {
	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)
	const channel1, channel2 = uint64(1), uint64(2)
	key := sharedKey()

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	shareContent1 := shares[channel1]
	shareContent2 := shares[channel2]

	challengeEnvelope, err := verification.Request.Produce(channel1, secretID, version, key)
	if err != nil {
		t.Fatalf("request produce: %v", err)
	}

	extractedReq, err := verification.Request.Extract(challengeEnvelope, key)
	if err != nil {
		t.Fatalf("request extract: %v", err)
	}

	respEnvelope, err := verification.Response.Produce(channel1, extractedReq.RequestProto, key, shareContent1)
	if err != nil {
		t.Fatalf("response produce: %v", err)
	}
	if len(respEnvelope) == 0 {
		t.Fatal("response produce returned empty envelope")
	}

	extractedResp, err := verification.Response.Extract(respEnvelope, key)
	if err != nil {
		t.Fatalf("response extract: %v", err)
	}
	if extractedResp.ChannelID != channel1 {
		t.Fatalf("channel id: want %d got %d", channel1, extractedResp.ChannelID)
	}
	if len(extractedResp.ResponseProto) == 0 {
		t.Fatal("response extract returned empty response proto")
	}

	valid, err := verification.Response.Process(extractedReq.RequestProto, extractedResp.ResponseProto, shareContent1)
	if err != nil {
		t.Fatalf("response process (valid case): %v", err)
	}
	if !valid {
		t.Fatal("expected a valid verification response")
	}

	// Negative case: an honestly-produced response is processed against a
	// different channel's share content, which must not validate.
	respEnvelope2, err := verification.Response.Produce(channel1, extractedReq.RequestProto, key, shareContent1)
	if err != nil {
		t.Fatalf("second response produce: %v", err)
	}
	extractedResp2, err := verification.Response.Extract(respEnvelope2, key)
	if err != nil {
		t.Fatalf("second response extract: %v", err)
	}
	valid2, err := verification.Response.Process(extractedReq.RequestProto, extractedResp2.ResponseProto, shareContent2)
	if err != nil {
		t.Fatalf("response process (invalid case): %v", err)
	}
	if valid2 {
		t.Fatal("expected an invalid verification response for the wrong share")
	}
}
