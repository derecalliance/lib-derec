// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

// These golden byte strings were captured from the pre-refactor code (the
// duplicate secretWire/helperWire/replicaWire/replicasWire/userSecretWire
// hierarchy and secretToWire converter that used to live in this file)
// before it was replaced by Secret/Helper/Replica/Replicas/UserSecret's own
// MarshalJSON methods (see events.go and internal/native/store_types.go).
// Any byte difference below means the wire format changed — do not update
// these constants to make a failing assertion pass; fix the marshal code
// instead.
const (
	restoreGoldenJSON = `{"version":7,"recovered_secret":{"helpers":[{"channel_id":"11","transport_uri":"https://helper-a.example.com","shared_key":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],"communication_info":{"foo":"bar"}},{"channel_id":"22","transport_uri":"https://helper-b.example.com","shared_key":[31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0]}],"secrets":[{"id":[1],"name":"wallet","data":[99,111,114,114,101,99,116,32,104,111,114,115,101,32,98,97,116,116,101,114,121,32,115,116,97,112,108,101]},{"id":[2,3],"name":"seed","data":[222,173,190,239]}],"replicas":{"channel_id":"33","members":[{"replica_id":"44","transport_uri":"https://replica-a.example.com","role":"Source","communication_info":{"baz":"qux"}},{"replica_id":"66","transport_uri":"https://replica-b.example.com","role":"Destination"}],"shared_key":[9,8,7,6,5,4,3,2,1,0]}}}`

	protectSecretGoldenJSON = `{"secrets":[{"id":[1],"name":"wallet","data":[99,111,114,114,101,99,116,32,104,111,114,115,101,32,98,97,116,116,101,114,121,32,115,116,97,112,108,101]},{"id":[2,3],"name":"seed","data":[222,173,190,239]}],"description":"capture description"}`
)

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
				TransportURI:      "https://helper-a.example.com",
				SharedKey:         sharedKey1,
				CommunicationInfo: map[string]string{"foo": "bar"},
			},
			{
				ChannelID:    "22",
				TransportURI: "https://helper-b.example.com",
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
					TransportURI:      "https://replica-a.example.com",
					Role:              "Source",
					CommunicationInfo: map[string]string{"baz": "qux"},
				},
				{
					ReplicaID:    "66",
					TransportURI: "https://replica-b.example.com",
					Role:         "Destination",
				},
			},
			SharedKey: replicaGroupKey,
		},
	}
}

// TestWireGolden_Restore asserts Restore's params marshal (via
// restoreParamsWire, whose RecoveredSecret field is now a plain Secret —
// see flow.go) is byte-identical to the pre-refactor output, which built
// the same JSON through the now-deleted secretToWire/secretWire/
// helperWire/replicaWire/replicasWire hierarchy.
func TestWireGolden_Restore(t *testing.T) {
	got, err := json.Marshal(restoreParamsWire{
		Version:         7,
		RecoveredSecret: goldenRestoreSecret(),
	})
	if err != nil {
		t.Fatalf("marshal restore params: %v", err)
	}
	if string(got) != restoreGoldenJSON {
		t.Fatalf("wire format changed:\n got  = %s\n want = %s", got, restoreGoldenJSON)
	}
}

// TestWireGolden_ProtectSecret asserts ProtectSecretParams' marshal (via
// marshalFlowParams, whose protectSecretParamsWire.Secrets field is now
// []UserSecret directly — see flow.go) is byte-identical to the
// pre-refactor output, which built the same JSON through the now-deleted
// encodeUserSecrets/userSecretWire helpers.
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
	if string(got) != protectSecretGoldenJSON {
		t.Fatalf("wire format changed:\n got  = %s\n want = %s", got, protectSecretGoldenJSON)
	}
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
			{ChannelID: "1", TransportURI: "https://h.example.com", SharedKey: make([]byte, 32)},
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
