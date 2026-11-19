// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package envelope exposes helpers that read or rewrite an envelope's
// cleartext fields without touching the encrypted inner message: trace ids
// for correlating requests and responses.
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

// EncryptedPayload reads the encrypted message field off an envelope,
// without the channel key.
//
// This is the part of an envelope an application can key duplicate
// detection on. It cannot be changed without failing decryption, and every
// message is sealed under a fresh random nonce, so it is the same for every
// copy of one message and different for every other message, even one with
// the same body. The cleartext fields around it (sequence, trace id) are not
// authenticated, and protobuf accepts more than one encoding of the same
// envelope, so a copy can arrive as different bytes: a hash of the raw
// envelope does not identify a message. How to key on these bytes (as they
// are, or hashed) and for how long is the application's choice; the README
// covers duplicate detection and the inbound window.
//
// The plaintext PrePair leg of HashedKeys pairing is the exception: its
// message field is not encrypted, so a copy re-encoded inside it reads
// differently. That leg is not authenticated at all; the contact's nonce is
// what binds it.
//
// Returns a *derec.Error with code derec.CodeFFIBadProto when the bytes are
// not an envelope.
func EncryptedPayload(envelope []byte) ([]byte, error) {
	return native.EncryptedPayloadFromEnvelope(envelope)
}
