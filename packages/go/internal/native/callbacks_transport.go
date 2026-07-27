// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// transportSender mirrors protocol.Transport's method set — see the
// storeSet doc comment in callbacks.go. Named transportSender (not
// transport) to avoid shadowing the storeSet field of the same
// underlying purpose while still reading naturally at call sites.
type transportSender interface {
	Send(uri string, protocol int32, message []byte) error
}

// TransportCallbacks mirrors #[repr(C)] struct TransportCallbacks in
// library/src/ffi/protocol/stores.rs field-for-field. Unlike the five
// store callbacks, there is no FreeBuffer field — send has no out buffer.
type TransportCallbacks struct {
	UserData uintptr
	Send     uintptr
}

// --- Dispatch ---------------------------------------------------------------

func dispatchTransportSend(s *storeSet, uri string, protocol int32, message []byte) (status int32) {
	defer recoverInto(&status)
	if err := s.transport.Send(uri, protocol, message); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// --- C-facing callback -------------------------------------------------------

func transportSendCallback(userData uintptr, uriPtr *byte, uriLen uintptr, protocol int32, bytesPtr *byte, length uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	// uri is copied by the string() conversion itself; message is raw
	// caller-owned memory valid only for this call, so it is defensively
	// cloned before reaching application code that might retain it.
	uri := string(unsafe.Slice(uriPtr, uriLen))
	message := cloneBytes(unsafe.Slice(bytesPtr, length))
	return dispatchTransportSend(s, uri, protocol, message)
}

// transportSendCallbackPtr holds the purego.NewCallback address for
// transportSendCallback, a stateless package-level func that needs exactly
// one registration total — see registerChannelCallbacks in
// callbacks_channel.go for why per-call registration would exhaust
// purego's 2000-slot callback table.
var (
	transportCallbacksOnce   sync.Once
	transportSendCallbackPtr uintptr
)

func registerTransportCallbacks() {
	transportCallbacksOnce.Do(func() {
		transportSendCallbackPtr = purego.NewCallback(transportSendCallback)
	})
}

// buildTransportCallbacks assembles TransportCallbacks for h. The Send
// fn-pointer field is registered once per process (see
// registerTransportCallbacks); only UserData varies per call.
func buildTransportCallbacks(h storeHandle) TransportCallbacks {
	registerTransportCallbacks()
	return TransportCallbacks{
		UserData: uintptr(h),
		Send:     transportSendCallbackPtr,
	}
}
