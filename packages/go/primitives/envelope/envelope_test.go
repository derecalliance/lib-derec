// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package envelope_test

import (
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/primitives/channelkey"
	"github.com/derecalliance/lib-derec/packages/go/primitives/envelope"
	"github.com/derecalliance/lib-derec/packages/go/primitives/verification"
)

func sharedKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func TestTraceIDRoundTrip(t *testing.T) {
	const channelID, secretID, version = uint64(7), uint64(42), uint32(1)
	const traceID = uint64(0xDEADBEEF12345678)
	key := sharedKey()

	original, err := verification.Request.Produce(channelID, secretID, version, key, 0, nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}

	tagged, err := envelope.ApplyTraceID(original, traceID)
	if err != nil {
		t.Fatalf("apply trace id: %v", err)
	}
	if len(tagged) == 0 {
		t.Fatal("apply trace id returned empty envelope")
	}

	got, err := envelope.ReadTraceID(tagged)
	if err != nil {
		t.Fatalf("read trace id: %v", err)
	}
	if got != traceID {
		t.Fatalf("trace id: want %d got %d", traceID, got)
	}

	originalTraceID, err := envelope.ReadTraceID(original)
	if err != nil {
		t.Fatalf("read trace id from original: %v", err)
	}
	if originalTraceID == traceID {
		t.Fatal("original envelope should not already carry the applied trace id")
	}
}

func TestReadSequenceAndDerive(t *testing.T) {
	k0 := sharedKey()
	k3, err := channelkey.Derive(k0, 0, 3)
	if err != nil || len(k3) != 32 {
		t.Fatalf("derive: %v len=%d", err, len(k3))
	}
	wire, err := verification.Request.Produce(7, 42, 1, k3, 3, nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	seq, err := envelope.ReadSequence(wire)
	if err != nil || seq != 3 {
		t.Fatalf("read sequence: want 3 got %d (%v)", seq, err)
	}
	if _, err := verification.Request.Extract(wire, k3); err != nil {
		t.Fatalf("extract with derived key: %v", err)
	}
	if _, err := verification.Request.Extract(wire, k0); err == nil {
		t.Fatal("extract with epoch-0 key must fail")
	}
	if _, err := channelkey.Derive(k3, 3, 2); err == nil {
		t.Fatal("backward derive must fail")
	}
	if _, err := channelkey.Derive(k0, 0, 513); err == nil {
		t.Fatal("derive beyond 512 steps must fail")
	}
}
