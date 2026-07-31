// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package discovery_test

import (
	"reflect"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/primitives/discovery"
)

func sharedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = 11
	}
	return k
}

func TestDiscoveryRequestRoundTrip(t *testing.T) {
	const channelID = uint64(7)
	key := sharedKey()

	requestWire, err := discovery.Request.Produce(channelID, key)
	if err != nil {
		t.Fatalf("request produce: %v", err)
	}
	if len(requestWire) == 0 {
		t.Fatalf("produce returned empty envelope")
	}

	extractedReq, err := discovery.Request.Extract(requestWire, key)
	if err != nil {
		t.Fatalf("request extract: %v", err)
	}
	if extractedReq.ChannelID != channelID {
		t.Fatalf("extracted channel id mismatch: got %d, want %d", extractedReq.ChannelID, channelID)
	}
}

func TestDiscoveryResponseRoundTrip(t *testing.T) {
	const channelID = uint64(7)
	key := sharedKey()

	secretList := []discovery.SecretVersionEntry{
		{
			SecretID: 0xABCD,
			Versions: []discovery.VersionEntry{
				{Version: 1, Description: "wallet seed"},
				{Version: 2, Description: "wallet seed v2"},
			},
		},
	}

	responseWire, err := discovery.Response.Produce(channelID, secretList, key)
	if err != nil {
		t.Fatalf("response produce: %v", err)
	}
	if len(responseWire) == 0 {
		t.Fatalf("produce returned empty envelope")
	}

	extractedResp, err := discovery.Response.Extract(responseWire, key)
	if err != nil {
		t.Fatalf("response extract: %v", err)
	}
	if extractedResp.ChannelID != channelID {
		t.Fatalf("extracted channel id mismatch: got %d, want %d", extractedResp.ChannelID, channelID)
	}

	processed, err := discovery.Response.Process(extractedResp.ResponseProto)
	if err != nil {
		t.Fatalf("response process: %v", err)
	}

	if !reflect.DeepEqual(processed, secretList) {
		t.Fatalf("discovery secret list must round-trip unchanged: got %+v, want %+v", processed, secretList)
	}
}
