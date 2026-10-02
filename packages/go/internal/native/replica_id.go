// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

var (
	generateReplicaIDOnce sync.Once
	generateReplicaIDFn   func() uint64
)

// GenerateReplicaID wraps derec_generate_replica_id: a fresh random replica
// id, never 0.
func GenerateReplicaID() uint64 {
	generateReplicaIDOnce.Do(func() {
		purego.RegisterFunc(&generateReplicaIDFn, symbol("derec_generate_replica_id"))
	})
	return generateReplicaIDFn()
}
