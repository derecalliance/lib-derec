// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fixtureVariant is one entry of bindings/test_fixture/enums.json. `Wire` is a
// serde variant-name string for some enums and a number for others, so it stays
// untyped until the per-enum check knows which.
type fixtureVariant struct {
	Name string          `json:"name"`
	Wire json.RawMessage `json:"wire"`
}

func loadEnumFixture(t *testing.T, enumName string) []fixtureVariant {
	t.Helper()
	// packages/go/internal/native -> repo root
	path := filepath.Join("..", "..", "..", "..", "bindings", "test_fixture", "enums.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Enums map[string]struct {
			Variants []fixtureVariant `json:"variants"`
		} `json:"enums"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	e, ok := doc.Enums[enumName]
	if !ok {
		t.Fatalf("fixture has no enum %q", enumName)
	}
	return e.Variants
}

// The Rust core emits every variant the fixture lists. This SDK must decode all
// of them: ChannelStatus once gained a variant that never reached Go, and
// UnmarshalJSON rejected a value the core legitimately produced. Round-tripping
// only the variants Go already knew about did not catch that — the fixture is
// the external source of truth that does.
func TestChannelStatusDecodesEveryFixtureVariant(t *testing.T) {
	for _, v := range loadEnumFixture(t, "ChannelStatus") {
		var got ChannelStatus
		if err := json.Unmarshal(v.Wire, &got); err != nil {
			t.Fatalf("ChannelStatus %q: %v", v.Name, err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("re-encoding ChannelStatus %q: %v", v.Name, err)
		}
		if string(encoded) != string(v.Wire) {
			t.Fatalf("ChannelStatus %q: round-tripped to %s, want %s", v.Name, encoded, v.Wire)
		}
	}
}

func TestReplicaRoleDecodesEveryFixtureVariant(t *testing.T) {
	for _, v := range loadEnumFixture(t, "ReplicaRole") {
		var got ReplicaRole
		if err := json.Unmarshal(v.Wire, &got); err != nil {
			t.Fatalf("ReplicaRole %q: %v", v.Name, err)
		}
		encoded, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("re-encoding ReplicaRole %q: %v", v.Name, err)
		}
		if string(encoded) != string(v.Wire) {
			t.Fatalf("ReplicaRole %q: round-tripped to %s, want %s", v.Name, encoded, v.Wire)
		}
	}
}

// Numeric enums are checked by value: agreeing on the names but not the
// numbers is just as broken as not knowing a variant at all.
func TestNumericEnumsMatchTheFixture(t *testing.T) {
	byName := func(enumName string) map[string]int64 {
		out := map[string]int64{}
		for _, v := range loadEnumFixture(t, enumName) {
			var n int64
			if err := json.Unmarshal(v.Wire, &n); err != nil {
				t.Fatalf("%s %q wire value: %v", enumName, v.Name, err)
			}
			out[v.Name] = n
		}
		return out
	}

	state := byName("StateKind")
	for name, want := range map[string]StateKind{
		"PendingVerification": StateKindPendingVerification,
		"PendingRecovery":     StateKindPendingRecovery,
		"PendingUnpair":       StateKindPendingUnpair,
		"SharingRound":        StateKindSharingRound,
		"PendingSyncCheck":    StateKindPendingSyncCheck,
	} {
		got, ok := state[name]
		if !ok {
			t.Fatalf("StateKind %q missing from fixture", name)
		}
		if int64(want) != got {
			t.Fatalf("StateKind %q: Go has %d, fixture says %d", name, want, got)
		}
	}
	if len(state) != 5 {
		t.Fatalf("fixture lists %d StateKind variants; Go knows 5", len(state))
	}

	secret := byName("SecretKind")
	for name, want := range map[string]SecretKind{
		"SharedKey":      SecretKindSharedKey,
		"PairingSecret":  SecretKindPairingSecret,
		"PairingContact": SecretKindPairingContact,
	} {
		got, ok := secret[name]
		if !ok {
			t.Fatalf("SecretKind %q missing from fixture", name)
		}
		if int64(want) != got {
			t.Fatalf("SecretKind %q: Go has %d, fixture says %d", name, want, got)
		}
	}
	if len(secret) != 3 {
		t.Fatalf("fixture lists %d SecretKind variants; Go knows 3", len(secret))
	}
}
