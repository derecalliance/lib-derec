// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package envelope_test

import (
	"bytes"
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

	original, err := verification.Request.Produce(channelID, secretID, version, key, nil)
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

func TestMessageIDIgnoresTheTraceID(t *testing.T) {
	key := sharedKey()
	original, err := verification.Request.Produce(7, 42, 1, key, nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	restamped, err := envelope.ApplyTraceID(original, 0x7E57)
	if err != nil {
		t.Fatalf("apply trace id: %v", err)
	}
	another, err := verification.Request.Produce(7, 42, 1, key, nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}

	first, err := envelope.ReadMessageID(original)
	if err != nil {
		t.Fatalf("message id: %v", err)
	}
	copied, err := envelope.ReadMessageID(restamped)
	if err != nil {
		t.Fatalf("message id of the copy: %v", err)
	}
	other, err := envelope.ReadMessageID(another)
	if err != nil {
		t.Fatalf("message id of another message: %v", err)
	}

	if len(first.ID) != 32 || first.Timestamp == 0 {
		t.Fatalf("unexpected identity %+v", first)
	}
	if !bytes.Equal(first.ID, copied.ID) {
		t.Fatal("a copy with another trace id must keep the message id")
	}
	if bytes.Equal(first.ID, other.ID) {
		t.Fatal("two messages must not share a message id")
	}
	if _, err := envelope.ReadMessageID([]byte("not an envelope")); err == nil {
		t.Fatal("garbage must not yield a message id")
	}
}
