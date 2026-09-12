// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/binary"
	"errors"
	"sync"
	"unsafe"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/ebitengine/purego"
	"google.golang.org/protobuf/proto"
)

// transportSender mirrors protocol.Transports[0]'s method set — see the
// storeSet doc comment in callbacks.go. Named transportSender (not
// transport) to avoid shadowing the storeSet field of the same
// underlying purpose while still reading naturally at call sites.
type transportSender interface {
	Send(endpoints []Endpoint, message []byte) error
}

// Endpoint is one address a peer advertised. Aliased to the existing
// TransportEndpoint rather than redeclared so the transport seam and the
// channel records name the same type.
type Endpoint = TransportEndpoint

// TransportCallbacks mirrors #[repr(C)] struct TransportCallbacks in
// library/src/interop/ffi/protocol/stores.rs field-for-field. Unlike the five
// store callbacks, there is no FreeBuffer field — send has no out buffer.
type TransportCallbacks struct {
	UserData uintptr
	Send     uintptr
}

// --- Dispatch ---------------------------------------------------------------

func dispatchTransportSend(s *storeSet, endpoints []Endpoint, message []byte) (status int32) {
	defer recoverInto(&status)
	if err := s.transport.Send(endpoints, message); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// --- C-facing callback -------------------------------------------------------

func transportSendCallback(userData uintptr, endpointsPtr *byte, endpointsLen uintptr, bytesPtr *byte, length uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	// Both buffers are caller-owned memory valid only for this call, so each
	// is copied before reaching application code that might retain it.
	endpoints, err := decodeEndpointList(unsafe.Slice(endpointsPtr, endpointsLen))
	if err != nil {
		return ffiStatusFailure
	}
	message := cloneBytes(unsafe.Slice(bytesPtr, length))
	return dispatchTransportSend(s, endpoints, message)
}

// decodeEndpointList reads the length-delimited TransportProtocol sequence the
// library passes across the seam: each entry preceded by its protobuf varint
// byte length, the same framing protobuf uses for a repeated embedded message.
func decodeEndpointList(buf []byte) ([]Endpoint, error) {
	var out []Endpoint
	for len(buf) > 0 {
		size, read := binary.Uvarint(buf)
		if read <= 0 {
			return nil, errors.New("derec: malformed endpoint length prefix")
		}
		buf = buf[read:]
		if uint64(len(buf)) < size {
			return nil, errors.New("derec: endpoint length prefix overruns the buffer")
		}
		var tp derecpb.TransportProtocol
		if err := proto.Unmarshal(buf[:size], &tp); err != nil {
			return nil, err
		}
		out = append(out, Endpoint{URI: tp.GetUri(), Protocol: int32(tp.GetProtocol())})
		buf = buf[size:]
	}
	return out, nil
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
