// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

// DeRecProtocolVersion mirrors the #[repr(C)] struct returned by
// derec_protocol_version.
type DeRecProtocolVersion struct {
	Major uint32
	Minor uint32
}

var (
	protocolVersionOnce sync.Once
	protocolVersionFn   func() DeRecProtocolVersion
)

// ProtocolVersion returns the compiled-in protocol version. Registering a Go
// func that returns the struct by value exercises purego's amd64/arm64
// struct-return path — the mechanism every result-returning FFI call relies on.
func ProtocolVersion() (uint32, uint32) {
	protocolVersionOnce.Do(func() {
		purego.RegisterFunc(&protocolVersionFn, symbol("derec_protocol_version"))
	})
	v := protocolVersionFn()
	return v.Major, v.Minor
}
