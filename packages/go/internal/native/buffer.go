// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// DeRecBuffer mirrors #[repr(C)] struct DeRecBuffer { ptr, len }.
type DeRecBuffer struct {
	Ptr *byte
	Len uintptr
}

var (
	freeBufferOnce sync.Once
	freeBufferFn   func(ptr *byte, length uintptr)
)

func freeBuffer(b DeRecBuffer) {
	freeBufferOnce.Do(func() {
		purego.RegisterFunc(&freeBufferFn, symbol("derec_free_buffer"))
	})
	freeBufferFn(b.Ptr, b.Len)
}

// bytesFromBuffer copies an SDK-owned buffer into a Go slice and releases the
// original. A null/empty buffer yields a nil slice. After this call the
// DeRecBuffer must not be reused.
func bytesFromBuffer(b DeRecBuffer) []byte {
	if b.Ptr == nil || b.Len == 0 {
		return nil
	}
	out := make([]byte, b.Len)
	copy(out, unsafe.Slice(b.Ptr, b.Len))
	freeBuffer(b)
	return out
}
