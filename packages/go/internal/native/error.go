// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"fmt"
	"sync"
	"unsafe"

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

// Error is the typed error every fallible FFI call returns, exposed publicly
// as derec.Error (see that alias for the field contract). It is declared here
// rather than in package derec so that derec can import this package.
type Error struct {
	Category   int32
	Code       int32
	Message    string
	PeerStatus int32
	PeerMemo   string
	Expected   uint32
	Got        uint32
	// ConflictingChannelIDs lists the channel ids a restore was refused
	// over; set only by Restore when Code is CodeRestoreConflict, empty
	// otherwise.
	ConflictingChannelIDs []uint64
}

// Error implements the error interface, naming the category and code
// alongside their numeric values.
func (e *Error) Error() string {
	return fmt.Sprintf("derec: %s (category=%s(%d) code=%s(%d))",
		e.Message, e.CategoryName(), e.Category, e.CodeName(), e.Code)
}

// CategoryName returns the library's stable name for e.Category, e.g.
// "sharing", or "unknown" for a value the library does not define.
func (e *Error) CategoryName() string {
	return ErrorCategoryName(e.Category)
}

// CodeName returns the library's stable name for e.Code, e.g.
// "no_usable_endpoint", or "unknown" for a value the library does not define.
func (e *Error) CodeName() string {
	return ErrorCodeName(e.Code)
}

// Unwrap always returns nil: Error is a terminal, self-contained error value
// with no wrapped cause to unwrap.
func (e *Error) Unwrap() error {
	return nil
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
// typed-nil *Error into a non-nil error interface. On failure the
// concrete value is an *Error (derec.Error), recoverable via errors.As.
func errorFrom(e DeRecError) error {
	if e.Category == categoryOK {
		return nil
	}
	out := &Error{
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
