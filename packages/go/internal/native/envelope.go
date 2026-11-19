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

var (
	applyTraceIDOnce sync.Once
	applyTraceIDFn   func(envelope *byte, envelopeLen uintptr, traceID uint64) applyTraceIdResult

	readTraceIDOnce sync.Once
	readTraceIDFn   func(envelope *byte, envelopeLen uintptr) readTraceIdResult
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
