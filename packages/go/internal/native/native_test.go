// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import "testing"

func TestSymbolResolvesKnownExport(t *testing.T) {
	addr := symbol("derec_protocol_version")
	if addr == 0 {
		t.Fatal("expected non-zero address for derec_protocol_version")
	}
}

func TestProtocolVersionMatchesSourceOfTruth(t *testing.T) {
	major, minor := ProtocolVersion()
	// library/src/protocol_version.rs defines CURRENT = { major: 0, minor: 1 }
	// as the source of truth for the DeRec protocol version.
	if major != 0 || minor != 1 {
		t.Fatalf("expected protocol version 0.1 (per library/src/protocol_version.rs CURRENT), got %d.%d", major, minor)
	}
}

func TestErrorFromSuccessIsNil(t *testing.T) {
	if err := errorFrom(DeRecError{Category: categoryOK}); err != nil {
		t.Fatalf("expected nil error for OK category, got %v", err)
	}
}
