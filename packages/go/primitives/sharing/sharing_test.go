// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package sharing_test

import (
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/primitives/sharing"
)

func sharedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 42
	}
	return k
}

func TestSplitProducesOneCommittedShareperChannel(t *testing.T) {
	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if len(shares) != len(channelIDs) {
		t.Fatalf("expected %d shares, got %d", len(channelIDs), len(shares))
	}
	for _, id := range channelIDs {
		bytes, ok := shares[id]
		if !ok {
			t.Fatalf("missing committed share for channel %d", id)
		}
		if len(bytes) == 0 {
			t.Fatalf("empty committed share for channel %d", id)
		}
	}
}

func TestStoreShareRequestResponseRoundTrip(t *testing.T) {
	const secretID = uint64(0x0102_0304_05ff)
	secretData := []byte{5, 6, 7, 8, 255}
	channelIDs := []uint64{1, 2, 3}
	const threshold = 2
	const version = uint32(1)
	key := sharedKey()

	shares, err := sharing.Request.Split(secretID, secretData, channelIDs, threshold, version)
	if err != nil {
		t.Fatalf("split: %v", err)
	}

	for _, channelID := range channelIDs {
		committedShare := shares[channelID]

		requestWire, err := sharing.Request.Produce(channelID, version, secretID, committedShare, nil, "", key)
		if err != nil {
			t.Fatalf("channel %d: request produce: %v", channelID, err)
		}
		if len(requestWire) == 0 {
			t.Fatalf("channel %d: produce returned empty envelope", channelID)
		}

		extractedReq, err := sharing.Request.Extract(requestWire, key)
		if err != nil {
			t.Fatalf("channel %d: request extract: %v", channelID, err)
		}
		if extractedReq.ChannelID != channelID {
			t.Fatalf("channel %d: extracted channel id mismatch, got %d", channelID, extractedReq.ChannelID)
		}
		if len(extractedReq.RequestProto) == 0 {
			t.Fatalf("channel %d: extracted request proto is empty", channelID)
		}

		respResult, err := sharing.Response.Produce(channelID, extractedReq.RequestProto, key)
		if err != nil {
			t.Fatalf("channel %d: response produce: %v", channelID, err)
		}
		if len(respResult.Envelope) == 0 {
			t.Fatalf("channel %d: response envelope is empty", channelID)
		}
		if len(respResult.CommittedShare) == 0 {
			t.Fatalf("channel %d: response committed share is empty", channelID)
		}
		if respResult.SecretID != secretID {
			t.Fatalf("channel %d: response secret id mismatch, got %d", channelID, respResult.SecretID)
		}
		if respResult.Version != version {
			t.Fatalf("channel %d: response version mismatch, got %d", channelID, respResult.Version)
		}

		extractedResp, err := sharing.Response.Extract(respResult.Envelope, key)
		if err != nil {
			t.Fatalf("channel %d: response extract: %v", channelID, err)
		}
		if extractedResp.ChannelID != channelID {
			t.Fatalf("channel %d: extracted response channel id mismatch, got %d", channelID, extractedResp.ChannelID)
		}
		if len(extractedResp.ResponseProto) == 0 {
			t.Fatalf("channel %d: extracted response proto is empty", channelID)
		}

		if err := sharing.Response.Process(version, extractedResp.ResponseProto); err != nil {
			t.Fatalf("channel %d: response process: %v", channelID, err)
		}
	}
}
