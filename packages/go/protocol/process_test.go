// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// TestProcess_EmptyMessage_ReturnsAnErrorNotAPanic drives the genuine FFI
// round trip: derec_protocol_process accepts message_len == 0 as a valid
// (zero-length) call rather than a null-pointer error — see
// library/src/interop/ffi/protocol/handle/flow.rs — but the protocol core still
// decodes it into a default DeRecMessage{channel_id: 0} and rejects it
// because no shared key or pairing secret exists for channel 0 on a fresh
// instance (library/src/protocol/mod.rs process_inner's final Err arm).
// Process must surface that as a *derec.Error, not a crash or a silent
// empty event slice — proving the binding itself (bytePtr/errorFrom/
// bytesFromBuffer/decodeEvents) round-trips correctly end to end.
func TestProcess_EmptyMessage_ReturnsAnErrorNotAPanic(t *testing.T) {
	p := newTestProtocol(t)
	events, err := p.Process(nil)
	if err == nil {
		t.Fatalf("expected an error for an empty message, got events: %+v", events)
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
	if events != nil {
		t.Fatalf("expected nil events on error, got %+v", events)
	}
}

// TestProcess_UnrecognizedChannel_ReturnsAnError mirrors the empty-message
// case with a well-formed (proto-encoded) envelope instead of a
// zero-length body: a DeRecMessage naming a channel_id this instance has
// never paired or started a pairing handshake on must still fail cleanly
// with a structured error rather than panicking or returning a bogus
// event.
func TestProcess_UnrecognizedChannel_ReturnsAnError(t *testing.T) {
	p := newTestProtocol(t)

	msg := &derecpb.DeRecMessage{
		ChannelId: 999999,
		Timestamp: timestamppb.Now(),
	}
	wireBytes, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	events, err := p.Process(wireBytes)
	if err == nil {
		t.Fatalf("expected an error for an unrecognized channel_id, got events: %+v", events)
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}

// TestProcess_ClosedProtocol asserts the closed-instance guard rejects the
// call instead of touching a freed handle, matching every other method on
// DeRecProtocol.
func TestProcess_ClosedProtocol(t *testing.T) {
	p := newTestProtocol(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.Process(nil); err == nil {
		t.Fatal("expected an error on a closed protocol")
	}
}

// TestProcess_MalformedBytes_ReturnsAnError feeds genuinely undecodable
// protobuf bytes (an invalid varint tag) through the FFI, proving
// process()'s ProtobufDecode error path surfaces as a Go error rather than
// a panic across the C ABI boundary.
func TestProcess_MalformedBytes_ReturnsAnError(t *testing.T) {
	p := newTestProtocol(t)
	// 0xFF repeated is not a valid protobuf tag/varint sequence.
	garbage := []byte{0xff, 0xff, 0xff, 0xff, 0xff}
	events, err := p.Process(garbage)
	if err == nil {
		t.Fatalf("expected a decode error, got events: %+v", events)
	}
	var derecErr *derec.Error
	if !errors.As(err, &derecErr) {
		t.Fatalf("expected a *derec.Error, got %T: %v", err, err)
	}
}
