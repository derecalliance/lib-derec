// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec

import "github.com/derecalliance/lib-derec/packages/go/internal/native"

// GenerateReplicaID returns a fresh replica identity from the core library;
// never 0. Generate it once per device, persist it, and pass the same value
// as protocol.Config.ReplicaID on every init.
func GenerateReplicaID() uint64 {
	return native.GenerateReplicaID()
}
