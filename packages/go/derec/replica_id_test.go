// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec_test

import (
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
)

func TestGenerateReplicaIDNeverZero(t *testing.T) {
	for i := 0; i < 64; i++ {
		if id := derec.GenerateReplicaID(); id == 0 {
			t.Fatalf("call %d returned 0", i)
		}
	}
}
