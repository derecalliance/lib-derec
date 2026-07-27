// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec_test

import (
	"strings"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
)

func TestErrorCarriesCodeAndFormats(t *testing.T) {
	e := &derec.Error{Category: derec.CategoryFFI, Code: derec.CodeFFIBadSharedKey, Message: "bad key"}
	if e.Code != derec.CodeFFIBadSharedKey {
		t.Fatalf("code: want %d got %d", derec.CodeFFIBadSharedKey, e.Code)
	}
	if !strings.Contains(e.Error(), "bad key") {
		t.Fatalf("Error() should contain the message, got %q", e.Error())
	}
}
