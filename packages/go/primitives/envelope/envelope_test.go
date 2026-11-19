// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package envelope_test

import (
	"bytes"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/discovery"
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

func TestEncryptedPayloadIsTheMessageField(t *testing.T) {
	wire, err := verification.Request.Produce(7, 42, 1, sharedKey(), nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}

	payload, err := envelope.EncryptedPayload(wire)
	if err != nil {
		t.Fatalf("encrypted payload: %v", err)
	}

	var decoded derecpb.DeRecMessage
	if err := proto.Unmarshal(wire, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if len(payload) == 0 || !bytes.Equal(payload, decoded.Message) {
		t.Fatal("encrypted payload must equal the envelope's message field")
	}
}

func TestEncryptedPayloadSurvivesRestamping(t *testing.T) {
	wire, err := verification.Request.Produce(7, 42, 1, sharedKey(), nil)
	if err != nil {
		t.Fatalf("produce: %v", err)
	}
	original, err := envelope.EncryptedPayload(wire)
	if err != nil {
		t.Fatalf("encrypted payload: %v", err)
	}

	traced, err := envelope.ApplyTraceID(wire, 0xABCD)
	if err != nil {
		t.Fatalf("apply trace id: %v", err)
	}
	var decoded derecpb.DeRecMessage
	if err := proto.Unmarshal(traced, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	decoded.Sequence++
	restamped, err := proto.Marshal(&decoded)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}
	if bytes.Equal(restamped, wire) {
		t.Fatal("restamped envelope must differ from the original on the wire")
	}

	got, err := envelope.EncryptedPayload(restamped)
	if err != nil {
		t.Fatalf("encrypted payload of restamped copy: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("a restamped copy must carry the same encrypted payload")
	}
}

func TestEncryptedPayloadDiffersForSameBody(t *testing.T) {
	first, err := discovery.Request.Produce(7, sharedKey(), nil)
	if err != nil {
		t.Fatalf("produce first: %v", err)
	}
	second, err := discovery.Request.Produce(7, sharedKey(), nil)
	if err != nil {
		t.Fatalf("produce second: %v", err)
	}

	a, err := envelope.EncryptedPayload(first)
	if err != nil {
		t.Fatalf("encrypted payload first: %v", err)
	}
	b, err := envelope.EncryptedPayload(second)
	if err != nil {
		t.Fatalf("encrypted payload second: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two messages with the same body must carry different encrypted payloads")
	}
}

func TestEncryptedPayloadRejectsNonEnvelopeBytes(t *testing.T) {
	_, err := envelope.EncryptedPayload([]byte{0xFF, 0xFF, 0xFF})
	var derr *derec.Error
	if !errors.As(err, &derr) || derr.Code != derec.CodeFFIBadProto {
		t.Fatalf("want *derec.Error CodeFFIBadProto, got %#v", err)
	}
}
