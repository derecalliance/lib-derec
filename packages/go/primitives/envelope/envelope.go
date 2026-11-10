// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package envelope exposes helpers that read or rewrite an envelope's
// cleartext fields without touching the encrypted inner message: trace ids
// for correlating requests and responses, the sequence that selects the
// channel key, and the message identity replay detection keys on.
package envelope

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// ApplyTraceID overwrites the trace id on an already-produced envelope and
// returns the re-encoded bytes.
func ApplyTraceID(envelopeBytes []byte, traceID uint64) ([]byte, error) {
	return native.ApplyTraceIDToEnvelope(envelopeBytes, traceID)
}

// ReadTraceID reads the trace id off an envelope without touching the
// encrypted inner payload.
func ReadTraceID(envelopeBytes []byte) (uint64, error) {
	return native.ReadTraceIDFromEnvelope(envelopeBytes)
}

// ReadSequence reads the sequence off an envelope without touching the
// encrypted inner payload: the epoch of the channel key that encrypted it.
func ReadSequence(envelopeBytes []byte) (uint32, error) {
	return native.ReadSequenceFromEnvelope(envelopeBytes)
}

// MessageID identifies an envelope for replay and reflection detection.
//
// ID (32 bytes) is the same for every copy of one message, whatever its
// unauthenticated cleartext fields (sequence, trace id, protocol version)
// say, and different for every other message. Timestamp is the envelope's
// send time in seconds since the Unix epoch.
type MessageID struct {
	ID        []byte
	Timestamp uint64
}

// ReadMessageID reads the identity of an envelope. Detecting a message
// delivered twice, or delivered back to its sender, is the application's
// job: keep the ID of every envelope sent and every envelope Process
// accepted until max(received or sent at, Timestamp) +
// Timeouts.InboundMessageSecs, keep the record across restarts, and drop an
// inbound envelope whose ID is kept. The README has the full contract.
func ReadMessageID(envelopeBytes []byte) (MessageID, error) {
	id, timestamp, err := native.MessageIDFromEnvelope(envelopeBytes)
	if err != nil {
		return MessageID{}, err
	}
	return MessageID{ID: id, Timestamp: timestamp}, nil
}
