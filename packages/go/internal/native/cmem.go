// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// A load-style store callback (e.g. a helper's "load share" store method)
// must hand Rust a buffer it did not allocate with Go's runtime allocator,
// since Rust frees it later through the store's free_buffer callback. cmem
// provides that C-heap allocation via libc malloc/free, resolved through
// purego rather than cgo. libcPath is platform-specific (see libc_darwin.go
// / libc_linux.go); only darwin is exercised by this SDK's tests today.
var (
	libcOnce   sync.Once
	libcHandle uintptr
	libcErr    error
)

func loadLibc() (uintptr, error) {
	libcOnce.Do(func() {
		h, err := purego.Dlopen(libcPath, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			libcErr = fmt.Errorf("derec: dlopen libc (%s): %w", libcPath, err)
			return
		}
		libcHandle = h
	})
	return libcHandle, libcErr
}

// libcSymbol resolves a libc export address, mirroring symbol() in
// library.go but against the libc handle instead of the derec dylib.
func libcSymbol(name string) (uintptr, error) {
	h, err := loadLibc()
	if err != nil {
		return 0, err
	}
	addr, err := purego.Dlsym(h, name)
	if err != nil {
		return 0, fmt.Errorf("derec: resolve libc symbol %q: %w", name, err)
	}
	return addr, nil
}

var (
	mallocOnce sync.Once
	mallocFn   func(size uintptr) unsafe.Pointer
	mallocErr  error

	freeOnce sync.Once
	freeFn   func(ptr unsafe.Pointer)
	freeErr  error
)

func registerMalloc() error {
	mallocOnce.Do(func() {
		addr, err := libcSymbol("malloc")
		if err != nil {
			mallocErr = err
			return
		}
		purego.RegisterFunc(&mallocFn, addr)
	})
	return mallocErr
}

func registerFree() error {
	freeOnce.Do(func() {
		addr, err := libcSymbol("free")
		if err != nil {
			freeErr = err
			return
		}
		purego.RegisterFunc(&freeFn, addr)
	})
	return freeErr
}

// cMalloc allocates n bytes of C heap memory via libc malloc. It returns nil
// for n == 0 without allocating. Failure to resolve the malloc symbol is an
// unrecoverable packaging/platform bug and panics, matching symbol()'s
// treatment of missing derec dylib exports; a null return from malloc itself
// (out of memory) is passed through as nil for the caller to check.
func cMalloc(n uintptr) unsafe.Pointer {
	if n == 0 {
		return nil
	}
	if err := registerMalloc(); err != nil {
		panic(err)
	}
	return mallocFn(n)
}

// cFree releases memory obtained from cMalloc/cCopyBytes. It is a no-op for
// nil.
func cFree(p unsafe.Pointer) {
	if p == nil {
		return
	}
	if err := registerFree(); err != nil {
		panic(err)
	}
	freeFn(p)
}

// cCopyBytes mallocs len(b) bytes and copies b into them, returning the C
// pointer and length suitable for writing into a store callback's
// *out_ptr/*out_len pair. The returned memory is owned by the caller on the
// Rust side, which releases it via the store's free_buffer callback (which
// must in turn call cFree). An empty or nil slice yields (nil, 0) without
// allocating, matching how the Rust side represents an empty/absent buffer.
func cCopyBytes(b []byte) (ptr *byte, length uintptr) {
	if len(b) == 0 {
		return nil, 0
	}
	p := cMalloc(uintptr(len(b)))
	if p == nil {
		panic("derec: malloc failed")
	}
	copy(unsafe.Slice((*byte)(p), len(b)), b)
	return (*byte)(p), uintptr(len(b))
}
