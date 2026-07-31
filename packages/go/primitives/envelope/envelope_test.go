// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package envelope_test

import (
	"testing"

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

	original, err := verification.Request.Produce(channelID, secretID, version, key)
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
