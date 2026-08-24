// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"testing"
)

// Every ChannelStatus the Rust core can emit must round-trip. `Unpairing` was
// missing here once: a replica member flagged for removal serialized fine on
// the Rust side and then failed to decode in Go, so a Go application could not
// load a channel record mid-removal.
func TestChannelStatusRoundTripsEveryVariant(t *testing.T) {
	for _, want := range []ChannelStatus{
		ChannelStatusPending,
		ChannelStatusPaired,
		ChannelStatusUnpairing,
	} {
		encoded, err := json.Marshal(want)
		if err != nil {
			t.Fatalf("marshal %v: %v", want, err)
		}
		var got ChannelStatus
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("unmarshal %s: %v", encoded, err)
		}
		if got != want {
			t.Fatalf("round-trip: got %v, want %v", got, want)
		}
	}
}
