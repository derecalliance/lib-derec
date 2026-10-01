// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodeEvents_MessageIgnored(t *testing.T) {
	ev := decodeOne(t, `{"type": "MessageIgnored", "channel_id": "18446744073709551615", "reason": "PendingVerification", "trace_id": "42"}`)
	if ev.Type != EventTypeMessageIgnored ||
		ev.ChannelID != "18446744073709551615" ||
		ev.Reason != IgnoreReasonPendingVerification ||
		ev.TraceID != "42" {
		t.Fatalf("got %+v", ev)
	}
}

func TestIgnoreReasonConstantsMatchTheFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "library", "tests", "fixtures", "enums.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Enums map[string]json.RawMessage `json:"enums"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	var reasons struct {
		Variants []struct {
			Wire string `json:"wire"`
		} `json:"variants"`
	}
	if err := json.Unmarshal(doc.Enums["IgnoreReason"], &reasons); err != nil {
		t.Fatalf("parsing IgnoreReason: %v", err)
	}

	constants := map[string]bool{
		IgnoreReasonPendingVerification: true,
		IgnoreReasonExpired:             true,
	}
	variants := reasons.Variants
	for _, v := range variants {
		if !constants[v.Wire] {
			t.Errorf("fixture reason %q has no IgnoreReason constant", v.Wire)
		}
	}
	if len(variants) != len(constants) {
		t.Errorf("fixture lists %d reasons, Go declares %d", len(variants), len(constants))
	}
}
