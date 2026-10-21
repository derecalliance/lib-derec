// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"testing"
)

// The buffer derec_protocol_new reads is the canonical config object as
// given, with secret_id added as a decimal string so a u64 above 2^53
// survives.
func TestMarshalProtocolConfig_AddsSecretIDBesideTheConfig(t *testing.T) {
	for _, tc := range []struct{ config, want string }{
		{`{}`, `{"secret_id":"18446744073709551615"}`},
		{`null`, `{"secret_id":"18446744073709551615"}`},
		{
			`{"threshold":0,"timeouts":{"sharing_round_secs":0}}`,
			`{"secret_id":"18446744073709551615","threshold":0,"timeouts":{"sharing_round_secs":0}}`,
		},
	} {
		raw, err := marshalProtocolConfig(^uint64(0), []byte(tc.config))
		if err != nil {
			t.Fatalf("%s: %v", tc.config, err)
		}
		var got, want any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: config JSON is not valid: %v", tc.config, err)
		}
		if err := json.Unmarshal([]byte(tc.want), &want); err != nil {
			t.Fatal(err)
		}
		if string(mustMarshal(t, got)) != string(mustMarshal(t, want)) {
			t.Fatalf("%s: got %s, want %s", tc.config, raw, tc.want)
		}
	}

	if _, err := marshalProtocolConfig(1, []byte(`[1]`)); err == nil {
		t.Fatal("a config that is not a JSON object must be refused")
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
