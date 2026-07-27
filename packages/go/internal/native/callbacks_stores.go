// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Wires the six store/transport interfaces held by a storeSet to the C
// callback ABI library/src/ffi/protocol/stores.rs expects, via
// purego.NewCallback. Each store has its own file (callbacks_channel.go,
// callbacks_secret.go, callbacks_share.go, callbacks_usersecret.go,
// callbacks_state.go, callbacks_transport.go) containing three layers:
//
//  1. The #[repr(C)]-mirroring *Callbacks struct: a leading UserData field
//     (the storeHandle, never a Go pointer — see callbacks.go) followed by
//     one uintptr field per fn pointer, in the exact order stores.rs
//     declares them.
//  2. A "dispatch" function per method: resolved *storeSet + decoded
//     arguments in, a status code (+ any decoded result) out. Pure Go, no
//     C-ABI types — independently unit-testable against a mock store.
//  3. A "callback" function per method carrying the exact FFI signature
//     (uintptr user_data, primitive/pointer args matching stores.rs's
//     extern "C" fn byte-for-byte): resolves the handle via lookupStores,
//     decodes the raw pointer/length arguments, calls the matching
//     dispatch function, and encodes the result back across the boundary.
//     This is the function registered directly with purego.NewCallback.
//     Every callback function is stateless (it resolves its *storeSet from
//     UserData at call time), so each is registered with purego.NewCallback
//     exactly once per process — guarded by a sync.Once per store file,
//     mirroring sharedFreeBufferCallback below — and the resulting address
//     is reused across every buildXStoreCallbacks call. purego caps its
//     callback table at 2000 entries with no unregister API, so registering
//     fresh per protocol instance would exhaust it after a few dozen
//     instances.
//
// This file holds what's shared across all six: the status-code
// constants, the mandatory panic-recovery wrapper, the out-buffer/
// free-buffer plumbing, and the buildCallbacks entry point.
package native

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Status codes follow the convention documented on every load callback in
// stores.rs: 0 = success, 1 = not found (load-style callbacks only),
// anything else = backend failure. ffiStatusFailure is the fixed value
// this package uses for "anything else" — Rust does not distinguish
// failure codes beyond "not 0 (and not 1 for loads)".
const (
	ffiStatusOK       int32 = 0
	ffiStatusNotFound int32 = 1
	ffiStatusFailure  int32 = 2
)

// recoverInto is deferred as `defer recoverInto(&status)` at the top of
// every dispatch and callback function in this package (status is always
// each function's first named return value). A panic — from a
// consumer-supplied store implementation, a codec bug, or a cCopyBytes
// allocation failure — must never unwind across an extern "C" callback
// boundary: Rust has no Go stack to unwind through there, so an
// unrecovered panic crashes the host process outright rather than
// returning an error. Any out-parameters are left untouched on a
// recovered panic; every callback's documented convention only reads them
// when status is 0 (or, for a load, 0 or 1), both of which a panic never
// produces.
func recoverInto(status *int32) {
	if recover() != nil {
		*status = ffiStatusFailure
	}
}

// writeOutBuffer copies out into C heap memory via cCopyBytes and writes
// the resulting pointer/length into a load-style callback's out
// parameters, matching the *out_ptr/*out_len convention documented on
// fetch_callback_bytes in stores.rs. Rust copies the bytes out and then
// releases the buffer via the store's free_buffer callback.
func writeOutBuffer(out []byte, outPtr, outLen *uintptr) {
	ptr, length := cCopyBytes(out)
	*outPtr = uintptr(unsafe.Pointer(ptr))
	*outLen = length
}

// boolToU32 renders a Go bool as the C `u32` (0/1) used by every
// out_existed/out_removed/out_has_version parameter.
func boolToU32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// cloneBytes copies a byte slice that may alias caller-owned memory valid
// only for the duration of the current callback invocation, before handing
// it to application code that might retain it beyond the call returning.
// Every *Record JSON payload decoded in this package is already immune to
// this concern (encoding/json always copies out of its input), so this
// helper exists solely for TransportCallbacks.send's message, which
// reaches the application's Transport.Send unparsed.
func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// freeBufferCallback releases a buffer previously produced by
// writeOutBuffer/cCopyBytes. It is shared across all five store
// *Callbacks.FreeBuffer fields — TransportCallbacks has none, since send
// has no out buffer — because freeing never depends on which store
// produced the buffer. Panic safety still applies: cFree panics if the
// libc free symbol failed to resolve (an unrecoverable packaging bug per
// cmem.go), and free_buffer has no return value to signal failure
// through, so the recovered panic is silently swallowed here rather than
// crashing the process.
func freeBufferCallback(userData uintptr, ptr *byte, length uintptr) {
	defer func() { recover() }()
	cFree(unsafe.Pointer(ptr))
}

var (
	freeBufferCallbackOnce sync.Once
	freeBufferCallbackPtr  uintptr
)

// sharedFreeBufferCallback lazily registers freeBufferCallback once and
// returns its address for every store's FreeBuffer field.
func sharedFreeBufferCallback() uintptr {
	freeBufferCallbackOnce.Do(func() {
		freeBufferCallbackPtr = purego.NewCallback(freeBufferCallback)
	})
	return freeBufferCallbackPtr
}

// builtCallbacks holds the six populated *Callbacks structs for one
// protocol instance plus the storeHandle they dispatch through. Every
// purego.NewCallback address here (and the storeSet backing them, kept
// reachable via the handle registry) must stay alive for as long as Rust
// may still invoke a callback through it — the caller is responsible for
// keeping the returned value referenced and calling release only after
// the protocol instance is fully torn down on the Rust side.
type builtCallbacks struct {
	handle     storeHandle
	Channel    ChannelStoreCallbacks
	Secret     SecretStoreCallbacks
	Share      ShareStoreCallbacks
	UserSecret UserSecretStoreCallbacks
	State      StateStoreCallbacks
	Transport  TransportCallbacks
}

// buildCallbacks registers s under a new handle and assembles the six
// #[repr(C)]-mirroring callback structs library/src/ffi/protocol/stores.rs
// expects, ready to hand to derec_protocol_new.
func buildCallbacks(s *storeSet) (*builtCallbacks, error) {
	if s == nil {
		return nil, fmt.Errorf("native: buildCallbacks: nil storeSet")
	}
	h := registerStores(s)
	return &builtCallbacks{
		handle:     h,
		Channel:    buildChannelStoreCallbacks(h),
		Secret:     buildSecretStoreCallbacks(h),
		Share:      buildShareStoreCallbacks(h),
		UserSecret: buildUserSecretStoreCallbacks(h),
		State:      buildStateStoreCallbacks(h),
		Transport:  buildTransportCallbacks(h),
	}, nil
}

// release drops the handle's storeSet mapping. Must only be called once
// the protocol instance backed by these callbacks has been fully torn
// down on the Rust side — Rust must never invoke a callback through a
// released handle.
func (b *builtCallbacks) release() {
	releaseStores(b.handle)
}
