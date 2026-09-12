// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// Drives library/tests/fixtures/channel_filter.json against HelperFilter.Matches
// and ReplicaFilter.Matches.
//
// A channel store may push the filter into its query rather than returning
// every row. That is an optimization and it is the store's to verify: the core
// re-applies the filter to whatever a listing returns, which drops rows the
// filter excludes but cannot recover a row that was never returned. An
// over-selecting pushdown costs bandwidth; an under-selecting one is
// undetectable at runtime.
//
// The same table drives the Rust, .NET and TypeScript suites. When two
// bindings disagree, the fixture says which is wrong.

type filterCase struct {
	Name   string `json:"name"`
	Why    string `json:"why"`
	Filter struct {
		IDs     []string `json:"ids"`
		Status  []string `json:"status"`
		Role    *string  `json:"role"`
		Exclude []string `json:"exclude"`
	} `json:"filter"`
	Expected []string `json:"expected"`
}

type filterRecord struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Role   string `json:"role"`
}

type filterSection struct {
	Records []filterRecord `json:"records"`
	Cases   []filterCase   `json:"cases"`
}

func loadFilterFixture(t *testing.T) map[string]filterSection {
	t.Helper()
	// The fixture is read at run time, so `-count=1` matters: Go's build graph
	// does not see it and a cached pass would survive the file changing.
	path := filepath.Join("..", "..", "..", "..", "library", "tests", "fixtures", "channel_filter.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	out := make(map[string]filterSection, 2)
	for _, section := range []string{"helpers", "replicas"} {
		var s filterSection
		if err := json.Unmarshal(doc[section], &s); err != nil {
			t.Fatalf("parsing section %s: %v", section, err)
		}
		out[section] = s
	}
	return out
}

func statusByName(t *testing.T, name string) ChannelStatus {
	t.Helper()
	switch name {
	case "Pending":
		return ChannelStatusPending
	case "Paired":
		return ChannelStatusPaired
	case "Unpairing":
		return ChannelStatusUnpairing
	}
	t.Fatalf("fixture names an unknown ChannelStatus: %s", name)
	return 0
}

func senderKindByName(t *testing.T, name string) SenderKind {
	t.Helper()
	switch name {
	case "Owner":
		return SenderKindOwner
	case "Helper":
		return SenderKindHelper
	case "ReplicaSource":
		return SenderKindReplicaSource
	case "ReplicaDestination":
		return SenderKindReplicaDestination
	}
	t.Fatalf("fixture names an unknown SenderKind: %s", name)
	return 0
}

func replicaRoleByName(t *testing.T, name string) ReplicaRole {
	t.Helper()
	switch name {
	case "Source":
		return ReplicaRoleSource
	case "Destination":
		return ReplicaRoleDestination
	}
	t.Fatalf("fixture names an unknown ReplicaRole: %s", name)
	return 0
}

func mustU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("fixture id %q is not a u64: %v", s, err)
	}
	return v
}

func ids(t *testing.T, ss []string) []uint64 {
	out := make([]uint64, 0, len(ss))
	for _, s := range ss {
		out = append(out, mustU64(t, s))
	}
	return out
}

func statuses(t *testing.T, ss []string) []ChannelStatus {
	out := make([]ChannelStatus, 0, len(ss))
	for _, s := range ss {
		out = append(out, statusByName(t, s))
	}
	return out
}

func TestHelperFilterMatchesTheFixture(t *testing.T) {
	section := loadFilterFixture(t)["helpers"]
	for _, c := range section.Cases {
		t.Run(c.Name, func(t *testing.T) {
			f := HelperFilter{
				ChannelFilter: ChannelFilter{
					IDs:     ids(t, c.Filter.IDs),
					Status:  statuses(t, c.Filter.Status),
					Exclude: ids(t, c.Filter.Exclude),
				},
			}
			if c.Filter.Role != nil {
				role := senderKindByName(t, *c.Filter.Role)
				f.Role = &role
			}

			var survivors []string
			for _, r := range section.Records {
				if f.Matches(mustU64(t, r.ID), statusByName(t, r.Status), senderKindByName(t, r.Role)) {
					survivors = append(survivors, r.ID)
				}
			}
			if len(survivors) == 0 {
				survivors = []string{}
			}
			if !reflect.DeepEqual(survivors, c.Expected) {
				t.Fatalf("got %v, want %v\n  why this case exists: %s", survivors, c.Expected, c.Why)
			}
		})
	}
}

func TestReplicaFilterMatchesTheFixture(t *testing.T) {
	section := loadFilterFixture(t)["replicas"]
	for _, c := range section.Cases {
		t.Run(c.Name, func(t *testing.T) {
			f := ReplicaFilter{
				ChannelFilter: ChannelFilter{
					IDs:     ids(t, c.Filter.IDs),
					Status:  statuses(t, c.Filter.Status),
					Exclude: ids(t, c.Filter.Exclude),
				},
			}
			if c.Filter.Role != nil {
				role := replicaRoleByName(t, *c.Filter.Role)
				f.Role = &role
			}

			var survivors []string
			for _, r := range section.Records {
				if f.Matches(mustU64(t, r.ID), statusByName(t, r.Status), replicaRoleByName(t, r.Role)) {
					survivors = append(survivors, r.ID)
				}
			}
			if len(survivors) == 0 {
				survivors = []string{}
			}
			if !reflect.DeepEqual(survivors, c.Expected) {
				t.Fatalf("got %v, want %v\n  why this case exists: %s", survivors, c.Expected, c.Why)
			}
		})
	}
}
