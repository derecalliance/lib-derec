// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package recovery_test

import (
	"bytes"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/primitives/recovery"
	"github.com/derecalliance/lib-derec/packages/go/primitives/sharing"
)

func sharedKey(fill byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

// TestRecoverReconstructsOriginalSecret mirrors run_recovery_flow_test in
// bindings/rust/src/primitives.rs: split a secret across three channels at
// threshold 2, store committed shares with two of the helpers, walk the
// get-share request/response exchange with each, and assert the recovered
// secret is byte-identical to the original.
func TestRecoverReconstructsOriginalSecret(t *testing.T) {
	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	keys := map[uint64][]byte{
		1: sharedKey(1),
		2: sharedKey(2),
		3: sharedKey(3),
	}

	// Persist committed shares with two helpers (channels 1 and 2), mirroring
	// the sharing store-share flow, keeping each helper's stored request
	// proto for later recovery response production.
	storedRequests := make(map[uint64][]byte)
	for _, channelID := range []uint64{1, 2} {
		key := keys[channelID]

		requestWire, err := sharing.Request.Produce(channelID, version, secretID, shares[channelID], nil, "", key)
		if err != nil {
			t.Fatalf("channel %d: store request produce: %v", channelID, err)
		}

		extracted, err := sharing.Request.Extract(requestWire, key)
		if err != nil {
			t.Fatalf("channel %d: store request extract: %v", channelID, err)
		}
		storedRequests[channelID] = extracted.RequestProto
	}

	var responses []recovery.ShareResponse
	for _, channelID := range []uint64{1, 2} {
		key := keys[channelID]

		getRequestWire, err := recovery.Request.Produce(channelID, secretID, version, key)
		if err != nil {
			t.Fatalf("channel %d: get-share request produce: %v", channelID, err)
		}

		extractedReq, err := recovery.Request.Extract(getRequestWire, key)
		if err != nil {
			t.Fatalf("channel %d: get-share request extract: %v", channelID, err)
		}
		if extractedReq.ChannelID != channelID {
			t.Fatalf("channel %d: extracted request channel id mismatch, got %d", channelID, extractedReq.ChannelID)
		}

		getResponseWire, err := recovery.Response.Produce(channelID, extractedReq.RequestProto, storedRequests[channelID], key)
		if err != nil {
			t.Fatalf("channel %d: get-share response produce: %v", channelID, err)
		}

		extractedResp, err := recovery.Response.Extract(getResponseWire, key)
		if err != nil {
			t.Fatalf("channel %d: get-share response extract: %v", channelID, err)
		}
		if extractedResp.ChannelID != channelID {
			t.Fatalf("channel %d: extracted response channel id mismatch, got %d", channelID, extractedResp.ChannelID)
		}

		responses = append(responses, recovery.ShareResponse{Response: getResponseWire, SharedKey: key})
	}

	recovered, err := recovery.Response.Recover(responses, secretID, version)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !bytes.Equal(recovered, secretData) {
		t.Fatalf("recovered secret mismatch: got %x, want %x", recovered, secretData)
	}
}

// TestRecoverBelowThresholdFails asserts recovery reports an error rather
// than silently reconstructing an incorrect secret when fewer than threshold
// responses are supplied.
func TestRecoverBelowThresholdFails(t *testing.T) {
	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	channelID := uint64(1)
	key := sharedKey(1)

	requestWire, err := sharing.Request.Produce(channelID, version, secretID, shares[channelID], nil, "", key)
	if err != nil {
		t.Fatalf("store request produce: %v", err)
	}
	extracted, err := sharing.Request.Extract(requestWire, key)
	if err != nil {
		t.Fatalf("store request extract: %v", err)
	}

	getRequestWire, err := recovery.Request.Produce(channelID, secretID, version, key)
	if err != nil {
		t.Fatalf("get-share request produce: %v", err)
	}
	extractedReq, err := recovery.Request.Extract(getRequestWire, key)
	if err != nil {
		t.Fatalf("get-share request extract: %v", err)
	}
	getResponseWire, err := recovery.Response.Produce(channelID, extractedReq.RequestProto, extracted.RequestProto, key)
	if err != nil {
		t.Fatalf("get-share response produce: %v", err)
	}

	_, err = recovery.Response.Recover([]recovery.ShareResponse{{Response: getResponseWire, SharedKey: key}}, secretID, version)
	if err == nil {
		t.Fatalf("expected recovery to fail with only one of two required shares")
	}
}
