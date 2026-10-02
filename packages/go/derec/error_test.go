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

func TestCodeName(t *testing.T) {
	cases := map[int32]string{
		derec.CodeOK:               "ok",
		derec.CodeNonOKStatus:      "non_ok_status",
		derec.CodeFFIBadSharedKey:  "ffi_bad_shared_key",
		derec.CodeTransportInvalid: "transport_invalid",
		derec.CodeNoUsableEndpoint: "no_usable_endpoint",
		122:                        "unknown",
		9999:                       "unknown",
	}
	for code, want := range cases {
		if got := (&derec.Error{Code: code}).CodeName(); got != want {
			t.Errorf("CodeName(%d): want %q got %q", code, want, got)
		}
	}
}

func TestCategoryName(t *testing.T) {
	cases := map[int32]string{
		derec.CategoryOK:           "ok",
		derec.CategoryFFI:          "ffi",
		derec.CategorySharing:      "sharing",
		derec.CategoryInvalidInput: "input",
		derec.CategoryStateStore:   "state_store",
		-1:                         "unknown",
	}
	for category, want := range cases {
		if got := (&derec.Error{Category: category}).CategoryName(); got != want {
			t.Errorf("CategoryName(%d): want %q got %q", category, want, got)
		}
	}
}

func TestErrorStringCarriesNames(t *testing.T) {
	e := &derec.Error{Category: derec.CategoryFFI, Code: derec.CodeNoUsableEndpoint, Message: "no route"}
	s := e.Error()
	for _, want := range []string{"no route", "ffi", "no_usable_endpoint", "121"} {
		if !strings.Contains(s, want) {
			t.Errorf("Error() %q should contain %q", s, want)
		}
	}
}
