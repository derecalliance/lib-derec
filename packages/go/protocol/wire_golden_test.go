// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// goldenJSON loads one entry from the shared golden fixture
// (library/tests/fixtures/wire_golden.json), which every SDK asserts its own
// params builder against. Any difference from what that fixture pins means
// the wire format changed — do not update the fixture to make a failing
// assertion pass; fix the marshal code instead.
func goldenJSON(t *testing.T, key string) string {
	t.Helper()
	raw, err := os.ReadFile("../../../library/tests/fixtures/wire_golden.json")
	if err != nil {
		t.Fatalf("read wire_golden.json: %v", err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse wire_golden.json: %v", err)
	}
	value, ok := fixture[key]
	if !ok {
		t.Fatalf("wire_golden.json has no %q entry", key)
	}
	return string(value)
}

// assertJSONEqual compares two JSON documents by parsed value rather than
// raw bytes: the fixture is pretty-printed while the marshaled output under
// test is compact, so a byte comparison would always fail even when the
// values are identical.
func assertJSONEqual(t *testing.T, got, want string) {
	t.Helper()
	var gotValue, wantValue map[string]any
	if err := json.Unmarshal([]byte(got), &gotValue); err != nil {
		t.Fatalf("parse got JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("parse want JSON: %v", err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("wire format changed:\n got  = %s\n want = %s", got, want)
	}
}

// goldenRestoreSecret builds the same fully-populated Secret the golden
// bytes above were captured from: two helpers (one with
// CommunicationInfo, one without — exercising the omitempty branch both
// ways), two UserSecrets, and a populated Replicas with two entries (same
// CommunicationInfo-present/absent split).
func goldenRestoreSecret() Secret {
	sharedKey1 := make([]byte, 32)
	for i := range sharedKey1 {
		sharedKey1[i] = byte(i)
	}
	sharedKey2 := make([]byte, 32)
	for i := range sharedKey2 {
		sharedKey2[i] = byte(31 - i)
	}
	replicaGroupKey := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}

	return Secret{
		Helpers: []Helper{
			{
				ChannelID:         "11",
				Transports:        []EndpointJSON{{URI: "https://helper-a.example.com", Protocol: 0}},
				SharedKey:         sharedKey1,
				CommunicationInfo: map[string]string{"foo": "bar"},
			},
			{
				ChannelID:    "22",
				Transports:        []EndpointJSON{{URI: "https://helper-b.example.com", Protocol: 0}},
				SharedKey:    sharedKey2,
			},
		},
		Secrets: []UserSecret{
			{ID: []byte{0x01}, Name: "wallet", Data: []byte("correct horse battery staple")},
			{ID: []byte{0x02, 0x03}, Name: "seed", Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		},
		Replicas: &Replicas{
			ChannelID: "33",
			Members: []Replica{
				{
					ReplicaID:         "44",
					Transports:        []EndpointJSON{{URI: "https://replica-a.example.com", Protocol: 0}},
					Role:              "Source",
					CommunicationInfo: map[string]string{"baz": "qux"},
				},
				{
					ReplicaID:    "66",
					Transports:        []EndpointJSON{{URI: "https://replica-b.example.com", Protocol: 0}},
					Role:         "Destination",
				},
			},
			SharedKey: replicaGroupKey,
		},
	}
}

// TestWireGolden_Restore asserts Restore's params marshal (via
// restoreParamsWire, whose RecoveredSecret field is now a plain Secret —
// see flow.go) matches the shared golden fixture that every SDK's params
// builder is checked against.
func TestWireGolden_Restore(t *testing.T) {
	got, err := json.Marshal(restoreParamsWire{
		Version:         7,
		RecoveredSecret: goldenRestoreSecret(),
	})
	if err != nil {
		t.Fatalf("marshal restore params: %v", err)
	}
	assertJSONEqual(t, string(got), goldenJSON(t, "restore"))
}

// TestWireGolden_ProtectSecret asserts ProtectSecretParams' marshal (via
// marshalFlowParams, whose protectSecretParamsWire.Secrets field is now
// []UserSecret directly — see flow.go) matches the shared golden fixture
// that every SDK's params builder is checked against.
func TestWireGolden_ProtectSecret(t *testing.T) {
	secret := goldenRestoreSecret()
	desc := "capture description"
	got, err := marshalFlowParams(FlowKindProtectSecret, ProtectSecretParams{
		Secrets:     secret.Secrets,
		Description: &desc,
	})
	if err != nil {
		t.Fatalf("marshal protect secret params: %v", err)
	}
	assertJSONEqual(t, string(got), goldenJSON(t, "protect_secret"))
}

// TestWireGolden_Restore_NilReplicasOmitsField pins the other end of the
// omitempty behavior: a Secret with no Replicas setup must omit the
// "replicas" key entirely, matching wire.rs's
// `#[serde(skip_serializing_if = "Option::is_none")]` on SecretWire.replicas
// — not marshal it as a JSON null (which secret.MarshalJSON's plain
// `*Replicas` field, without the custom method, would have produced).
func TestWireGolden_Restore_NilReplicasOmitsField(t *testing.T) {
	secret := Secret{
		Helpers: []Helper{
			{ChannelID: "1", Transports:        []EndpointJSON{{URI: "https://h.example.com", Protocol: 0}}, SharedKey: make([]byte, 32)},
		},
		Secrets: []UserSecret{{ID: []byte{0x01}, Name: "n", Data: []byte{0x02}}},
	}
	got, err := json.Marshal(restoreParamsWire{Version: 1, RecoveredSecret: secret})
	if err != nil {
		t.Fatalf("marshal restore params: %v", err)
	}
	if strings.Contains(string(got), `"replicas"`) {
		t.Fatalf("expected no replicas key for a nil Replicas pointer, got: %s", got)
	}
}
