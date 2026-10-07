// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"testing"
)

func decodeConfigJSON(t *testing.T, cfg ProtocolConfig) map[string]json.RawMessage {
	t.Helper()
	raw, err := marshalProtocolConfig(cfg)
	if err != nil {
		t.Fatalf("marshalProtocolConfig: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("config JSON is not an object: %v", err)
	}
	return fields
}

// An explicit zero threshold must reach the library, which decides whether
// it is valid; only an unset value is omitted so the library default
// applies.
func TestMarshalProtocolConfig_ExplicitZeroCountsAreSent(t *testing.T) {
	zero := uint32(0)
	fields := decodeConfigJSON(t, ProtocolConfig{SecretID: 1, Threshold: &zero})
	got, ok := fields["threshold"]
	if !ok {
		t.Fatalf("threshold: explicit 0 was dropped from the config JSON")
	}
	if string(got) != "0" {
		t.Fatalf("threshold: got %s, want 0", got)
	}

	fields = decodeConfigJSON(t, ProtocolConfig{SecretID: 1})
	if _, ok := fields["threshold"]; ok {
		t.Fatalf("threshold: unset value must be omitted so the library default applies")
	}
}

// Timeouts cross in whole seconds, verbatim: an explicit 0 is sent, and an
// unset field is omitted.
func TestMarshalProtocolConfig_TimeoutsForwardedVerbatim(t *testing.T) {
	zero, inbound := uint64(0), uint64(1)
	fields := decodeConfigJSON(t, ProtocolConfig{
		SecretID: 1,
		Timeouts: &TimeoutsConfig{
			InboundMessageSecs: &inbound,
			SharingRoundSecs:   &zero,
			ExpiredChannels:    &RemoveExpiredChannelsPolicy{Enabled: false, TimeoutInSecs: 900},
		},
	})
	var timeouts map[string]json.RawMessage
	if err := json.Unmarshal(fields["timeouts"], &timeouts); err != nil {
		t.Fatalf("timeouts is not an object: %v", err)
	}
	want := map[string]string{
		"inbound_message_secs": "1",
		"sharing_round_secs":   "0",
		"expired_channels":     `{"enabled":false,"timeout_in_secs":900}`,
	}
	for key, w := range want {
		if got := string(timeouts[key]); got != w {
			t.Fatalf("timeouts.%s: got %q, want %q", key, got, w)
		}
	}
	if _, ok := timeouts["unpair_ack_secs"]; ok {
		t.Fatal("timeouts.unpair_ack_secs: unset value must be omitted")
	}
}

// CommunicationInfo crosses as the config JSON's "communication_info" object,
// so derec_protocol_new's proto buffer argument stays empty; a nil or empty
// map omits the key.
func TestMarshalProtocolConfig_CommunicationInfoIsAJSONObject(t *testing.T) {
	fields := decodeConfigJSON(t, ProtocolConfig{
		SecretID:          1,
		CommunicationInfo: map[string]string{"name": "alice", "email": "a@example.com"},
	})
	raw, ok := fields["communication_info"]
	if !ok {
		t.Fatalf("communication_info missing from config JSON: %v", fields)
	}
	var info map[string]string
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("communication_info is not a string->string object: %s", raw)
	}
	if len(info) != 2 || info["name"] != "alice" || info["email"] != "a@example.com" {
		t.Fatalf("communication_info: got %v", info)
	}

	for _, empty := range []map[string]string{nil, {}} {
		fields = decodeConfigJSON(t, ProtocolConfig{SecretID: 1, CommunicationInfo: empty})
		if _, ok := fields["communication_info"]; ok {
			t.Fatalf("communication_info: an empty map must omit the key, got %s", fields["communication_info"])
		}
	}
}
