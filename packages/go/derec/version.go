// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// ProtocolVersion is the DeRec protocol version a build speaks, as reported
// by the core library. Record it in audit trails and logs.
type ProtocolVersion struct {
	Major uint32
	Minor uint32
}

// CurrentProtocolVersion returns the protocol version compiled into the
// embedded core library.
func CurrentProtocolVersion() ProtocolVersion {
	major, minor := native.ProtocolVersion()
	return ProtocolVersion{Major: major, Minor: minor}
}
