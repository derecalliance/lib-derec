// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/ebitengine/purego"
)

const categoryOK int32 = 0

// DeRecError mirrors #[repr(C)] struct DeRecError. Go's natural alignment
// matches the C layout on amd64/arm64: the 4 bytes of padding after PeerStatus
// (to 8-align PeerMemo) are inserted identically by both compilers.
type DeRecError struct {
	Category   int32
	Code       int32
	Message    *byte
	PeerStatus int32
	PeerMemo   *byte
	Expected   uint32
	Got        uint32
}

var (
	freeErrorOnce sync.Once
	freeErrorFn   func(ptr *DeRecError)
)

// cString copies a null-terminated C string into a Go string. Returns "" on nil.
func cString(p *byte) string {
	if p == nil {
		return ""
	}
	var n int
	for ptr := unsafe.Pointer(p); *(*byte)(ptr) != 0; ptr = unsafe.Add(ptr, 1) {
		n++
	}
	return string(unsafe.Slice(p, n))
}

// errorFrom converts an FFI error envelope to an error, copying the owned
// strings before releasing them via derec_free_error. Returns an untyped nil
// on success so callers can `return errorFrom(...)` directly without boxing a
// typed-nil *derec.Error into a non-nil error interface. On failure the
// concrete value is a *derec.Error, recoverable via errors.As.
func errorFrom(e DeRecError) error {
	if e.Category == categoryOK {
		return nil
	}
	out := &derec.Error{
		Category:   e.Category,
		Code:       e.Code,
		Message:    cString(e.Message),
		PeerStatus: e.PeerStatus,
		PeerMemo:   cString(e.PeerMemo),
		Expected:   e.Expected,
		Got:        e.Got,
	}
	freeErrorOnce.Do(func() {
		purego.RegisterFunc(&freeErrorFn, symbol("derec_free_error"))
	})
	freeErrorFn(&e)
	return out
}
