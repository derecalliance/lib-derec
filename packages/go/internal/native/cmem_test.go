// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"testing"
	"unsafe"
)

// TestCCopyBytesRoundTrip proves malloc/copy/free actually work end-to-end
// through purego: bytes written into C heap memory by cCopyBytes are read
// back correctly via unsafe.Slice, then released via cFree.
func TestCCopyBytesRoundTrip(t *testing.T) {
	in := []byte{1, 2, 3, 4}
	ptr, length := cCopyBytes(in)
	if ptr == nil {
		t.Fatal("expected non-nil pointer for non-empty input")
	}
	if length != uintptr(len(in)) {
		t.Fatalf("expected length %d, got %d", len(in), length)
	}

	out := unsafe.Slice(ptr, length)
	for i, b := range in {
		if out[i] != b {
			t.Fatalf("byte %d: expected %d, got %d", i, b, out[i])
		}
	}

	cFree(unsafe.Pointer(ptr))
}

func TestCCopyBytesEmptySliceYieldsNilZero(t *testing.T) {
	ptr, length := cCopyBytes(nil)
	if ptr != nil {
		t.Fatalf("expected nil pointer for empty input, got %v", ptr)
	}
	if length != 0 {
		t.Fatalf("expected zero length for empty input, got %d", length)
	}

	ptr, length = cCopyBytes([]byte{})
	if ptr != nil {
		t.Fatalf("expected nil pointer for empty slice, got %v", ptr)
	}
	if length != 0 {
		t.Fatalf("expected zero length for empty slice, got %d", length)
	}
}

func TestCMallocCFreeRoundTrip(t *testing.T) {
	p := cMalloc(16)
	if p == nil {
		t.Fatal("expected non-nil pointer from cMalloc(16)")
	}
	cFree(p)
}
