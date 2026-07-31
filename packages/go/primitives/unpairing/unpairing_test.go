// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package unpairing_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/primitives/unpairing"
)

func sharedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestUnpairRequestRoundTrip(t *testing.T) {
	const channelID = uint64(7)
	const memo = "no longer needed"
	key := sharedKey()

	envelope, err := unpairing.Request.Produce(channelID, memo, key)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	if len(envelope) == 0 {
		t.Fatal("produce returned empty envelope")
	}

	got, err := unpairing.Request.Extract(envelope, key)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got.ChannelID != channelID {
		t.Fatalf("channel id: want %d got %d", channelID, got.ChannelID)
	}
	if got.Memo != memo {
		t.Fatalf("memo: want %q got %q", memo, got.Memo)
	}
	if len(got.RequestProto) == 0 {
		t.Fatal("extract returned empty request proto")
	}
	if bytes.Equal(got.RequestProto, envelope) {
		t.Fatal("request proto should be the inner message, not the wire envelope")
	}
}

func TestUnpairRequestRejectsShortKey(t *testing.T) {
	_, err := unpairing.Request.Produce(1, "reason", make([]byte, 16))
	if err == nil {
		t.Fatal("expected an error for a 16-byte shared key")
	}
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeFFIBadSharedKey {
		t.Fatalf("want *derec.Error CodeFFIBadSharedKey, got %#v", err)
	}
}

func TestUnpairResponseRoundTrip(t *testing.T) {
	const channelID = uint64(7)
	key := sharedKey()

	reqEnvelope, err := unpairing.Request.Produce(channelID, "no longer needed", key)
	if err != nil {
		t.Fatalf("request produce: %v", err)
	}
	if _, err := unpairing.Request.Extract(reqEnvelope, key); err != nil {
		t.Fatalf("request extract: %v", err)
	}

	respEnvelope, err := unpairing.Response.Produce(channelID, key)
	if err != nil {
		t.Fatalf("response produce: %v", err)
	}
	if len(respEnvelope) == 0 {
		t.Fatal("response produce returned empty envelope")
	}

	extractedResp, err := unpairing.Response.Extract(respEnvelope, key)
	if err != nil {
		t.Fatalf("response extract: %v", err)
	}
	if extractedResp.ChannelID != channelID {
		t.Fatalf("channel id: want %d got %d", channelID, extractedResp.ChannelID)
	}
	if len(extractedResp.ResponseProto) == 0 {
		t.Fatal("response extract returned empty response proto")
	}

	if err := unpairing.Response.Process(extractedResp.ResponseProto); err != nil {
		t.Fatalf("response process: %v", err)
	}
}
