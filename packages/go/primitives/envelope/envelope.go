// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package envelope exposes trace-id and sequence helpers for correlating
// request and response envelopes and selecting the channel key, without
// touching the encrypted inner message.
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
