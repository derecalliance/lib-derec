// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type applyTraceIdResult struct {
	Error     DeRecError
	WireBytes DeRecBuffer
}

type readTraceIdResult struct {
	Error   DeRecError
	TraceID uint64
}

type readSequenceResult struct {
	Error    DeRecError
	Sequence uint32
}

type encryptedPayloadResult struct {
	Error   DeRecError
	Payload DeRecBuffer
}

var (
	applyTraceIDOnce sync.Once
	applyTraceIDFn   func(envelope *byte, envelopeLen uintptr, traceID uint64) applyTraceIdResult

	readTraceIDOnce sync.Once
	readTraceIDFn   func(envelope *byte, envelopeLen uintptr) readTraceIdResult

	readSequenceOnce sync.Once
	readSequenceFn   func(envelope *byte, envelopeLen uintptr) readSequenceResult

	encryptedPayloadOnce sync.Once
	encryptedPayloadFn   func(envelope *byte, envelopeLen uintptr) encryptedPayloadResult
)

func ApplyTraceIDToEnvelope(envelope []byte, traceID uint64) ([]byte, error) {
	applyTraceIDOnce.Do(func() {
		purego.RegisterFunc(&applyTraceIDFn, symbol("apply_trace_id_to_envelope"))
	})
	res := applyTraceIDFn(bytePtr(envelope), uintptr(len(envelope)), traceID)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.WireBytes), nil
}

func ReadTraceIDFromEnvelope(envelope []byte) (uint64, error) {
	readTraceIDOnce.Do(func() {
		purego.RegisterFunc(&readTraceIDFn, symbol("read_trace_id_from_envelope"))
	})
	res := readTraceIDFn(bytePtr(envelope), uintptr(len(envelope)))
	if err := errorFrom(res.Error); err != nil {
		return 0, err
	}
	return res.TraceID, nil
}

func ReadSequenceFromEnvelope(envelope []byte) (uint32, error) {
	readSequenceOnce.Do(func() {
		purego.RegisterFunc(&readSequenceFn, symbol("read_sequence_from_envelope"))
	})
	res := readSequenceFn(bytePtr(envelope), uintptr(len(envelope)))
	if err := errorFrom(res.Error); err != nil {
		return 0, err
	}
	return res.Sequence, nil
}

func EncryptedPayloadFromEnvelope(envelope []byte) ([]byte, error) {
	encryptedPayloadOnce.Do(func() {
		purego.RegisterFunc(&encryptedPayloadFn, symbol("encrypted_payload_from_envelope"))
	})
	res := encryptedPayloadFn(bytePtr(envelope), uintptr(len(envelope)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.Payload), nil
}
