// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/primitives/pairing"
)

// enumFixtureCoverage names, for every enum in enums.json, the Go test that
// checks it, or that the Go SDK does not declare it.
var enumFixtureCoverage = map[string]string{
	"ChannelStatus":       "internal/native/enum_fixture_test.go",
	"ReplicaRole":         "internal/native/enum_fixture_test.go",
	"StateKind":           "internal/native/enum_fixture_test.go",
	"SecretKind":          "internal/native/enum_fixture_test.go",
	"IgnoreReason":        "protocol/message_ignored_test.go",
	"NotRestoredReason":   "protocol/message_ignored_test.go",
	"CorruptionReason":    "protocol/message_ignored_test.go",
	"VerifyFailureReason": "protocol/message_ignored_test.go",
	"PendingActionKind":   "protocol/message_ignored_test.go",
	"DeRecErrorCategory":  "derec/enum_fixture_test.go",
	"DeRecErrorCode":      "derec/enum_fixture_test.go",
	"DeRecEvent":          "protocol/enum_fixture_test.go",
	"FlowKind":            "protocol/enum_fixture_test.go",
	"SenderKind":          "protocol/enum_fixture_test.go",
	"ContactMode":         "protocol/enum_fixture_test.go",
	"StatusEnum":          "protocol/enum_fixture_test.go",
	"MessageKind":         "not declared: Go does not bind derec_decode_message_json / derec_encode_message_json",
}

type enumFixtureVariant struct {
	Name string          `json:"name"`
	Wire json.RawMessage `json:"wire"`
}

func loadEnumsFixture(t *testing.T) map[string][]enumFixtureVariant {
	t.Helper()
	raw, err := os.ReadFile("../../../library/tests/fixtures/enums.json")
	if err != nil {
		t.Fatalf("read enums.json: %v", err)
	}
	var doc struct {
		Enums map[string]struct {
			Variants []enumFixtureVariant `json:"variants"`
		} `json:"enums"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse enums.json: %v", err)
	}
	out := map[string][]enumFixtureVariant{}
	for name, e := range doc.Enums {
		out[name] = e.Variants
	}
	return out
}

func numericVariants(t *testing.T, enums map[string][]enumFixtureVariant, enumName string) map[string]int64 {
	t.Helper()
	variants, ok := enums[enumName]
	if !ok {
		t.Fatalf("enums.json has no %q", enumName)
	}
	out := map[string]int64{}
	for _, v := range variants {
		var n int64
		if err := json.Unmarshal(v.Wire, &n); err != nil {
			t.Fatalf("%s %s: wire %s is not a number", enumName, v.Name, v.Wire)
		}
		out[v.Name] = n
	}
	return out
}

func assertNumericEnum(t *testing.T, enumName string, fixture map[string]int64, goValues map[string]int64) {
	t.Helper()
	for name, wire := range fixture {
		got, ok := goValues[name]
		if !ok {
			t.Errorf("%s %s (%d) has no Go constant", enumName, name, wire)
			continue
		}
		if got != wire {
			t.Errorf("%s %s: Go has %d, fixture has %d", enumName, name, got, wire)
		}
	}
	for name := range goValues {
		if _, ok := fixture[name]; !ok {
			t.Errorf("%s %s is declared in Go but not in the fixture", enumName, name)
		}
	}
}

func TestEveryFixtureEnumIsCovered(t *testing.T) {
	enums := loadEnumsFixture(t)
	for name := range enums {
		if _, ok := enumFixtureCoverage[name]; !ok {
			t.Errorf("enums.json has %s, which no Go test checks", name)
		}
	}
	for name := range enumFixtureCoverage {
		if _, ok := enums[name]; !ok {
			t.Errorf("enumFixtureCoverage names %s, which enums.json does not list", name)
		}
	}
}

func TestEventTypeConstantsMatchTheFixture(t *testing.T) {
	enums := loadEnumsFixture(t)
	known := eventTypeConstants(t)
	fixture := map[string]bool{}
	for _, v := range enums["DeRecEvent"] {
		var wire string
		if err := json.Unmarshal(v.Wire, &wire); err != nil {
			t.Fatalf("DeRecEvent %s: %v", v.Name, err)
		}
		fixture[wire] = true
		if _, ok := known[wire]; !ok {
			t.Errorf("DeRecEvent %q has no EventType constant", wire)
		}
	}
	var extra []string
	for value, name := range known {
		if !fixture[value] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("EventType constants not in the fixture: %v", extra)
	}
}

func TestFlowKindMatchesTheFixture(t *testing.T) {
	assertNumericEnum(t, "FlowKind", numericVariants(t, loadEnumsFixture(t), "FlowKind"), map[string]int64{
		"Pairing":           int64(FlowKindPairing),
		"Discovery":         int64(FlowKindDiscovery),
		"ProtectSecret":     int64(FlowKindProtectSecret),
		"VerifyShares":      int64(FlowKindVerifyShares),
		"RecoverSecret":     int64(FlowKindRecoverSecret),
		"Unpair":            int64(FlowKindUnpair),
		"UpdateChannelInfo": int64(FlowKindUpdateChannelInfo),
		"ReplicaDiscovery":  int64(FlowKindReplicaDiscovery),
		"UnpairReplica":     int64(FlowKindUnpairReplica),
	})
}

func TestSenderKindMatchesTheFixture(t *testing.T) {
	fixture := numericVariants(t, loadEnumsFixture(t), "SenderKind")
	goValues := map[string]SenderKind{
		"Owner":              SenderKindOwner,
		"Helper":             SenderKindHelper,
		"ReplicaSource":      SenderKindReplicaSource,
		"ReplicaDestination": SenderKindReplicaDestination,
	}
	asInt := map[string]int64{}
	for name, kind := range goValues {
		asInt[name] = int64(kind)
		if kind.String() != name {
			t.Errorf("SenderKind %d: Go names it %q, fixture %q", kind, kind.String(), name)
		}
	}
	assertNumericEnum(t, "SenderKind", fixture, asInt)
}

func TestContactModeMatchesTheFixture(t *testing.T) {
	fixture := numericVariants(t, loadEnumsFixture(t), "ContactMode")
	assertNumericEnum(t, "ContactMode", fixture, map[string]int64{
		"InlineKeys": int64(ContactModeInlineKeys),
		"HashedKeys": int64(ContactModeHashedKeys),
		"NoKeys":     int64(ContactModeNoKeys),
	})
	assertNumericEnum(t, "pairing.ContactMode", fixture, map[string]int64{
		"InlineKeys": int64(pairing.ContactModeInlineKeys),
		"HashedKeys": int64(pairing.ContactModeHashedKeys),
		"NoKeys":     int64(pairing.ContactModeNoKeys),
	})
}

// screamingSnake turns a fixture variant name ("UnknownSecretId") into the
// protoc-gen-go value name ("UNKNOWN_SECRET_ID").
func screamingSnake(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

func TestStatusEnumMatchesTheFixture(t *testing.T) {
	fixture := numericVariants(t, loadEnumsFixture(t), "StatusEnum")
	goValues := map[string]int64{}
	byProtoName := map[string]string{}
	for name := range fixture {
		byProtoName[screamingSnake(name)] = name
	}
	for protoName, value := range derecpb.StatusEnum_value {
		name, ok := byProtoName[protoName]
		if !ok {
			name = protoName
		}
		goValues[name] = int64(value)
	}
	assertNumericEnum(t, "StatusEnum", fixture, goValues)
}
