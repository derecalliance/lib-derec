// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"runtime"
	"sync"

	"github.com/ebitengine/purego"
)

var (
	transportProtocolNameOnce sync.Once
	transportProtocolNameFn   func(protocol int32) *byte

	transportProtocolDiscriminantOnce sync.Once
	transportProtocolDiscriminantFn   func(namePtr *byte, nameLen uintptr) int32
)

// TransportProtocolName returns the library's name ("https", "grpc") for a
// Protocol discriminant, and false when the discriminant names no defined
// protocol. The C string is static and is copied, never freed.
func TransportProtocolName(protocol int32) (string, bool) {
	transportProtocolNameOnce.Do(func() {
		purego.RegisterFunc(&transportProtocolNameFn, symbol("derec_transport_protocol_name"))
	})
	p := transportProtocolNameFn(protocol)
	return cString(p), p != nil
}

// TransportProtocolDiscriminant returns the Protocol discriminant for a
// protocol name, and false when the name names no defined protocol.
func TransportProtocolDiscriminant(name string) (int32, bool) {
	transportProtocolDiscriminantOnce.Do(func() {
		purego.RegisterFunc(&transportProtocolDiscriminantFn, symbol("derec_transport_protocol_discriminant"))
	})
	b := []byte(name)
	d := transportProtocolDiscriminantFn(bytePtr(b), uintptr(len(b)))
	runtime.KeepAlive(b)
	return d, d >= 0
}
