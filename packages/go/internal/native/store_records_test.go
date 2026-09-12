// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"strings"
	"testing"
)

// --- Channel records: JSON rides serde directly on the Rust side (see
// library/src/interop/ffi/protocol/stores.rs doc comment), so EncodeChannelRecord's
// output must match ChannelRecord's derived Serialize shape byte-for-byte:
// externally tagged enum ("Helper" / "Replica" wrapper key), bare-number ids
// (ChannelId and ReplicaId are #[serde(transparent)]), nested transport
// object with a plain-int protocol field, and PascalCase enum strings for
// status/peer_role/role (Rust's default unit-variant serde form, not
// SCREAMING_CASE). Field order matches the Rust struct declaration order.

func TestEncodeChannelRecord_Helper_MatchesRustJSONShape(t *testing.T) {
	h := HelperChannel{
		ChannelID: 123456789,
		Transports:        []TransportEndpoint{{
			URI:      "https://example.com/derec",
			Protocol: 0,
		}},
		CommunicationInfo: map[string]string{"name": "helper"},
		PeerRole:          SenderKindHelper,
		Status:            ChannelStatusPaired,
		CreatedAt:         1700000000,
	}

	got, err := EncodeChannelRecord(ChannelRecord{Helper: &h})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}

	want := `{"Helper":{"schema_version":3,"channel_id":123456789,"transports":[{"uri":"https://example.com/derec","protocol":0}],` +
		`"communication_info":{"name":"helper"},"peer_role":"Helper","status":"Paired","created_at":1700000000}}`
	if string(got) != want {
		t.Fatalf("EncodeChannelRecord mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeChannelRecord_Replica_MatchesRustJSONShape(t *testing.T) {
	m := ReplicaMember{
		ChannelID:         123456789,
		ReplicaID:         42,
		Transports:        []TransportEndpoint{{URI: "https://replica.example.com", Protocol: 0}},
		CommunicationInfo: map[string]string{"name": "alice-2"},
		Role:              ReplicaRoleDestination,
		Status:            ChannelStatusPending,
		CreatedAt:         1700000000,
	}

	got, err := EncodeChannelRecord(ChannelRecord{Replica: &m})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}

	want := `{"Replica":{"schema_version":3,"channel_id":123456789,"replica_id":42,"transports":[{"uri":"https://replica.example.com","protocol":0}],` +
		`"communication_info":{"name":"alice-2"},"role":"Destination","status":"Pending","created_at":1700000000}}`
	if string(got) != want {
		t.Fatalf("EncodeChannelRecord mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeChannelRecord_EmptyCommunicationInfoIsEmptyObjectNotNull(t *testing.T) {
	h := HelperChannel{
		ChannelID: 1,
		Transports:        []TransportEndpoint{{URI: "https://h.example.com", Protocol: 0}},
		Status:    ChannelStatusPending,
		PeerRole:  SenderKindOwner,
	}
	got, err := EncodeChannelRecord(ChannelRecord{Helper: &h})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}
	if !strings.Contains(string(got), `"communication_info":{}`) {
		t.Fatalf("expected empty object for nil CommunicationInfo (Rust HashMap never serializes as null), got: %s", got)
	}
}

// A record must carry exactly one variant — neither is as wrong as both,
// since the Rust side cannot decode either into ChannelRecord.
func TestEncodeChannelRecord_RejectsAmbiguousRecords(t *testing.T) {
	if _, err := EncodeChannelRecord(ChannelRecord{}); err == nil {
		t.Fatal("expected an error for a record carrying neither variant")
	}
	h := HelperChannel{ChannelID: 1}
	m := ReplicaMember{ChannelID: 1, ReplicaID: 2}
	if _, err := EncodeChannelRecord(ChannelRecord{Helper: &h, Replica: &m}); err == nil {
		t.Fatal("expected an error for a record carrying both variants")
	}
}

// DecodeChannelRecord against hand-written samples matching the exact shape
// produced by Rust's serde derive (see library/src/protocol/types/mod.rs).
func TestDecodeChannelRecord_KnownGoodRustSamples(t *testing.T) {
	helperSample := `{"Helper":{"channel_id":987654321,"transports":[{"uri":"https://owner.example.com","protocol":0}],` +
		`"communication_info":{"name":"owner"},"peer_role":"Owner","status":"Pending","created_at":42}}`

	record, err := DecodeChannelRecord([]byte(helperSample))
	if err != nil {
		t.Fatalf("DecodeChannelRecord(helper): %v", err)
	}
	if record.Helper == nil {
		t.Fatal("expected the Helper variant")
	}
	ch := record.Helper
	if ch.ChannelID != 987654321 {
		t.Errorf("ChannelID = %d, want 987654321", ch.ChannelID)
	}
	if ch.Transports[0].URI != "https://owner.example.com" || ch.Transports[0].Protocol != 0 {
		t.Errorf("Transport = %+v", ch.Transports[0])
	}
	if ch.CommunicationInfo["name"] != "owner" {
		t.Errorf("CommunicationInfo = %v", ch.CommunicationInfo)
	}
	if ch.Status != ChannelStatusPending {
		t.Errorf("Status = %v, want Pending", ch.Status)
	}
	if ch.CreatedAt != 42 {
		t.Errorf("CreatedAt = %d, want 42", ch.CreatedAt)
	}
	if ch.PeerRole != SenderKindOwner {
		t.Errorf("PeerRole = %v, want Owner", ch.PeerRole)
	}

	replicaSample := `{"Replica":{"channel_id":987654321,"replica_id":7,"transports":[{"uri":"https://alice-2.example.com","protocol":0}],` +
		`"communication_info":{},"role":"Source","status":"Paired","created_at":42}}`

	record, err = DecodeChannelRecord([]byte(replicaSample))
	if err != nil {
		t.Fatalf("DecodeChannelRecord(replica): %v", err)
	}
	if record.Replica == nil {
		t.Fatal("expected the Replica variant")
	}
	if record.Replica.ReplicaID != 7 {
		t.Errorf("ReplicaID = %d, want 7", record.Replica.ReplicaID)
	}
	if record.Replica.Role != ReplicaRoleSource {
		t.Errorf("Role = %v, want Source", record.Replica.Role)
	}
}

// The core stamps schema_version on every record it writes, and a record
// written before the marker existed carries none. Decoding has to accept
// both: the samples above are the unversioned shape, this is the current one.
func TestDecodeChannelRecord_AcceptsTheSchemaVersionMarker(t *testing.T) {
	versioned := `{"Helper":{"schema_version":3,"channel_id":987654321,` +
		`"transports":[{"uri":"https://owner.example.com","protocol":0}],` +
		`"communication_info":{},"peer_role":"Owner","status":"Pending","created_at":42}}`

	record, err := DecodeChannelRecord([]byte(versioned))
	if err != nil {
		t.Fatalf("DecodeChannelRecord(versioned): %v", err)
	}
	if record.Helper == nil {
		t.Fatal("expected the Helper variant")
	}
	if record.Helper.ChannelID != 987654321 {
		t.Errorf("ChannelID = %d, want 987654321", record.Helper.ChannelID)
	}
}

// Re-encoding must stamp the marker even when the record came in without one,
// so a record that round-trips through this package does not keep looking
// older than the shape it is actually written in.
func TestChannelRecordRoundTrip_StampsTheMarkerOnUnversionedInput(t *testing.T) {
	unversioned := `{"Helper":{"channel_id":1,"transports":[{"uri":"https://a.example","protocol":0}],` +
		`"communication_info":{},"peer_role":"Owner","status":"Paired","created_at":0}}`

	record, err := DecodeChannelRecord([]byte(unversioned))
	if err != nil {
		t.Fatalf("DecodeChannelRecord: %v", err)
	}
	got, err := EncodeChannelRecord(record)
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}
	if !strings.Contains(string(got), `"schema_version":3`) {
		t.Fatalf("re-encoded record is missing the marker: %s", got)
	}
}

func TestDecodeChannelRecord_RejectsAmbiguousJSON(t *testing.T) {
	if _, err := DecodeChannelRecord([]byte(`{}`)); err == nil {
		t.Fatal("expected an error for JSON carrying neither variant")
	}
	both := `{"Helper":{"channel_id":1,"transports":[{"uri":"","protocol":0}],"communication_info":{},"peer_role":"Owner","status":"Paired","created_at":0},` +
		`"Replica":{"channel_id":1,"replica_id":2,"transports":[{"uri":"","protocol":0}],"communication_info":{},"role":"Source","status":"Paired","created_at":0}}`
	if _, err := DecodeChannelRecord([]byte(both)); err == nil {
		t.Fatal("expected an error for JSON carrying both variants")
	}
}

func TestChannelRecordRoundTrip(t *testing.T) {
	orig := ReplicaMember{
		ChannelID:         5,
		ReplicaID:         7,
		Transports:        []TransportEndpoint{{URI: "https://x.example.com", Protocol: 0}},
		CommunicationInfo: map[string]string{"a": "1", "b": "2"},
		Role:              ReplicaRoleDestination,
		Status:            ChannelStatusPaired,
		CreatedAt:         999,
	}
	wire, err := EncodeChannelRecord(ChannelRecord{Replica: &orig})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}
	record, err := DecodeChannelRecord(wire)
	if err != nil {
		t.Fatalf("DecodeChannelRecord: %v", err)
	}
	got := record.Replica
	if got == nil {
		t.Fatal("expected the Replica variant")
	}
	if got.ChannelID != orig.ChannelID || got.ReplicaID != orig.ReplicaID ||
		got.Transports[0] != orig.Transports[0] || got.Status != orig.Status ||
		got.CreatedAt != orig.CreatedAt || got.Role != orig.Role {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, orig)
	}
	if len(got.CommunicationInfo) != 2 || got.CommunicationInfo["a"] != "1" || got.CommunicationInfo["b"] != "2" {
		t.Fatalf("CommunicationInfo mismatch: %v", got.CommunicationInfo)
	}
}

// --- Share: wire shape is ShareRecord { secret_id: String, version: u32,
// bytes: Vec<u8> } — secret_id stringified, bytes a number array (serde_json's
// default Vec<u8> representation, not base64).

func TestEncodeShare_MatchesRustJSONShape(t *testing.T) {
	s := Share{SecretID: 18446744073709551615, Version: 3, Bytes: []byte{1, 2, 255}}
	got, err := EncodeShare(s)
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}
	want := `{"secret_id":"18446744073709551615","version":3,"bytes":[1,2,255]}`
	if string(got) != want {
		t.Fatalf("EncodeShare mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodeShare_DropsReplicaID(t *testing.T) {
	rid := uint64(9)
	s := Share{SecretID: 1, Version: 1, ReplicaID: &rid, Bytes: []byte{9}}
	got, err := EncodeShare(s)
	if err != nil {
		t.Fatalf("EncodeShare: %v", err)
	}
	if strings.Contains(string(got), "replica") {
		t.Fatalf("ShareRecord must never carry replica_id (matches Rust ShareRecord), got: %s", got)
	}
}

func TestDecodeShare_KnownGoodRustSample(t *testing.T) {
	sample := `{"secret_id":"42","version":7,"bytes":[10,20,30]}`
	s, err := DecodeShare([]byte(sample))
	if err != nil {
		t.Fatalf("DecodeShare: %v", err)
	}
	if s.SecretID != 42 || s.Version != 7 {
		t.Errorf("got SecretID=%d Version=%d", s.SecretID, s.Version)
	}
	if string(s.Bytes) != string([]byte{10, 20, 30}) {
		t.Errorf("Bytes = %v", s.Bytes)
	}
	if s.ReplicaID != nil {
		t.Errorf("ReplicaID must decode to nil (matches Rust ShareRecord::into_share), got %v", s.ReplicaID)
	}
}

func TestShareListRoundTrip(t *testing.T) {
	shares := []Share{
		{SecretID: 1, Version: 1, Bytes: []byte{1}},
		{SecretID: 2, Version: 2, Bytes: []byte{}},
	}
	wire, err := EncodeShareList(shares)
	if err != nil {
		t.Fatalf("EncodeShareList: %v", err)
	}
	got, err := DecodeShareList(wire)
	if err != nil {
		t.Fatalf("DecodeShareList: %v", err)
	}
	if len(got) != 2 || got[0].SecretID != 1 || got[1].SecretID != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestDecodeShareList_EmptyArray(t *testing.T) {
	got, err := DecodeShareList([]byte(`[]`))
	if err != nil {
		t.Fatalf("DecodeShareList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %v", got)
	}
}

// --- SecretValue: wire shape is SecretValueRecord { kind: u32, bytes: Vec<u8> }.

func TestSecretValueRoundTrip_AllKinds(t *testing.T) {
	cases := []SecretValue{
		{Kind: SecretKindSharedKey, Bytes: make([]byte, 32)},
		{Kind: SecretKindPairingSecret, Bytes: []byte{1, 2, 3}},
		{Kind: SecretKindPairingContact, Bytes: []byte{4, 5, 6, 7}},
	}
	for _, want := range cases {
		wire, err := EncodeSecretValue(want)
		if err != nil {
			t.Fatalf("EncodeSecretValue(kind=%d): %v", want.Kind, err)
		}
		got, err := DecodeSecretValue(wire)
		if err != nil {
			t.Fatalf("DecodeSecretValue(kind=%d): %v", want.Kind, err)
		}
		if got.Kind != want.Kind || string(got.Bytes) != string(want.Bytes) {
			t.Fatalf("round trip mismatch: got %+v, want %+v", got, want)
		}
	}
}

func TestEncodeSecretValue_MatchesRustJSONShape(t *testing.T) {
	got, err := EncodeSecretValue(SecretValue{Kind: SecretKindPairingContact, Bytes: []byte{1, 2}})
	if err != nil {
		t.Fatalf("EncodeSecretValue: %v", err)
	}
	want := `{"kind":2,"bytes":[1,2]}`
	if string(got) != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestDecodeSecretValue_RejectsBadSharedKeyLength(t *testing.T) {
	// Rust: "SharedKey payload must be 32 bytes" — SecretValueRecord::into_value.
	sample := `{"kind":0,"bytes":[1,2,3]}`
	if _, err := DecodeSecretValue([]byte(sample)); err == nil {
		t.Fatal("expected error for SharedKey payload != 32 bytes")
	}
}

func TestDecodeSecretValue_RejectsUnknownKind(t *testing.T) {
	sample := `{"kind":9,"bytes":[]}`
	if _, err := DecodeSecretValue([]byte(sample)); err == nil {
		t.Fatal("expected error for unknown SecretKind")
	}
}

// --- StateKey: wire shape is StateKeyRecord { kind: u32, channel_id:
// Option<String>, version: Option<u32> }, absent fields omitted.

func TestStateKeyRoundTrip_AllKinds(t *testing.T) {
	cid := uint64(10)
	sid := uint64(0xA0)
	ver := uint32(3)
	cases := []StateKey{
		{Kind: StateKindPendingVerification, ChannelID: &cid},
		{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &ver},
		{Kind: StateKindPendingUnpair, ChannelID: &cid},
		{Kind: StateKindSharingRound},
	}
	for _, want := range cases {
		wire, err := EncodeStateKey(want)
		if err != nil {
			t.Fatalf("EncodeStateKey(kind=%d): %v", want.Kind, err)
		}
		got, err := DecodeStateKey(wire)
		if err != nil {
			t.Fatalf("DecodeStateKey(kind=%d): %v", want.Kind, err)
		}
		if got.Kind != want.Kind {
			t.Fatalf("Kind mismatch: got %d want %d", got.Kind, want.Kind)
		}
		if (got.ChannelID == nil) != (want.ChannelID == nil) {
			t.Fatalf("ChannelID presence mismatch for kind=%d", want.Kind)
		}
		if want.ChannelID != nil && *got.ChannelID != *want.ChannelID {
			t.Fatalf("ChannelID mismatch: got %v want %v", got.ChannelID, want.ChannelID)
		}
		if (got.Version == nil) != (want.Version == nil) {
			t.Fatalf("Version presence mismatch for kind=%d", want.Kind)
		}
	}
}

func TestEncodeStateKey_OmitsAbsentFields(t *testing.T) {
	got, err := EncodeStateKey(StateKey{Kind: StateKindSharingRound})
	if err != nil {
		t.Fatalf("EncodeStateKey: %v", err)
	}
	want := `{"kind":3}`
	if string(got) != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestDecodeStateKey_KnownGoodRustSample(t *testing.T) {
	sample := `{"kind":0,"channel_id":"55"}`
	k, err := DecodeStateKey([]byte(sample))
	if err != nil {
		t.Fatalf("DecodeStateKey: %v", err)
	}
	if k.Kind != StateKindPendingVerification || k.ChannelID == nil || *k.ChannelID != 55 {
		t.Fatalf("got %+v", k)
	}
}

// --- StateItem: wire shape is StateItemRecord (see stores.rs). Field
// presence is driven by Kind, per StateItem's From/into_item impls.

func TestStateItemRoundTrip_PendingVerification(t *testing.T) {
	cid := uint64(11)
	want := StateItem{Kind: StateKindPendingVerification, ChannelID: &cid, Bytes: []byte{1, 2, 3}}
	wire, err := EncodeStateItem(want)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	got, err := DecodeStateItem(wire)
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if got.Kind != want.Kind || *got.ChannelID != *want.ChannelID || string(got.Bytes) != string(want.Bytes) {
		t.Fatalf("mismatch: got %+v want %+v", got, want)
	}
}

func TestStateItemRoundTrip_PendingRecovery(t *testing.T) {
	sid := uint64(0xA0)
	ver := uint32(4)
	want := StateItem{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &ver, Shares: [][]byte{{1, 2}, {3, 4, 5}}}
	wire, err := EncodeStateItem(want)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	got, err := DecodeStateItem(wire)
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if got.Kind != want.Kind || *got.Version != *want.Version || len(got.Shares) != 2 {
		t.Fatalf("mismatch: got %+v want %+v", got, want)
	}
}

// PendingRecovery with zero shares must still emit "shares":[] on the wire
// (Rust always wraps Some(...) for this variant, even over an empty vec —
// it is not the same as the field being entirely absent).
func TestEncodeStateItem_PendingRecoveryEmptySharesStillPresent(t *testing.T) {
	sid := uint64(0xA0)
	ver := uint32(1)
	got, err := EncodeStateItem(StateItem{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &ver, Shares: [][]byte{}})
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(got, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sharesRaw, ok := raw["shares"]
	if !ok {
		t.Fatalf("expected \"shares\" key to be present even when empty, got: %s", got)
	}
	if string(sharesRaw) != "[]" {
		t.Fatalf("expected shares:[], got %s", sharesRaw)
	}
}

func TestStateItemRoundTrip_PendingUnpair(t *testing.T) {
	cid := uint64(20)
	sa := uint64(1700000000)
	want := StateItem{Kind: StateKindPendingUnpair, ChannelID: &cid, StartedAt: &sa}
	wire, err := EncodeStateItem(want)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	got, err := DecodeStateItem(wire)
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if got.Kind != want.Kind || *got.ChannelID != *want.ChannelID || *got.StartedAt != *want.StartedAt {
		t.Fatalf("mismatch: got %+v want %+v", got, want)
	}
}

func TestStateItemRoundTrip_SharingRound(t *testing.T) {
	ver := uint32(2)
	sa := uint64(1234)
	want := StateItem{
		Kind:      StateKindSharingRound,
		Version:   &ver,
		StartedAt: &sa,
		Pending:   []uint64{1, 2},
		Confirmed: []uint64{3},
		Failed:    []uint64{},
	}
	wire, err := EncodeStateItem(want)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	got, err := DecodeStateItem(wire)
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if got.Kind != want.Kind || *got.Version != *want.Version || *got.StartedAt != *want.StartedAt {
		t.Fatalf("mismatch: got %+v want %+v", got, want)
	}
	if len(got.Pending) != 2 || len(got.Confirmed) != 1 || len(got.Failed) != 0 {
		t.Fatalf("set mismatch: got %+v", got)
	}
}

func TestDecodeStateItem_KnownGoodRustSample_SharingRound(t *testing.T) {
	sample := `{"kind":3,"version":5,"started_at":"1700000000","pending":["1","2"],"confirmed":[],"failed":["3"]}`
	item, err := DecodeStateItem([]byte(sample))
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if item.Kind != StateKindSharingRound || *item.Version != 5 || *item.StartedAt != 1700000000 {
		t.Fatalf("got %+v", item)
	}
	if len(item.Pending) != 2 || item.Pending[0] != 1 || item.Pending[1] != 2 {
		t.Fatalf("Pending = %v", item.Pending)
	}
	if len(item.Confirmed) != 0 {
		t.Fatalf("Confirmed = %v", item.Confirmed)
	}
	if len(item.Failed) != 1 || item.Failed[0] != 3 {
		t.Fatalf("Failed = %v", item.Failed)
	}
}

func TestDecodeStateItem_SharingRoundRequiresAllThreeSets(t *testing.T) {
	// Rust: parse_channel_id_set errors "SharingRound requires {field}" when
	// the field is absent entirely (None), not merely empty.
	sample := `{"kind":3,"version":1,"started_at":"1"}`
	if _, err := DecodeStateItem([]byte(sample)); err == nil {
		t.Fatal("expected error when pending/confirmed/failed are absent")
	}
}

func TestStateItemKey(t *testing.T) {
	cid := uint64(5)
	item := StateItem{Kind: StateKindPendingVerification, ChannelID: &cid}
	key := item.Key()
	if key.Kind != StateKindPendingVerification || key.ChannelID == nil || *key.ChannelID != 5 {
		t.Fatalf("Key() = %+v", key)
	}
}

// --- UserSecrets: wire shape is UserSecretsRecord { version, secrets:
// [UserSecretRecord], description: Option<String> }.

func TestUserSecretsRoundTrip(t *testing.T) {
	desc := "v1"
	want := UserSecrets{
		Version: 1,
		Secrets: []UserSecret{
			{ID: []byte{1}, Name: "a", Data: []byte{9, 9}},
			{ID: []byte{2}, Name: "b", Data: []byte{}},
		},
		Description: &desc,
	}
	wire, err := EncodeUserSecrets(want)
	if err != nil {
		t.Fatalf("EncodeUserSecrets: %v", err)
	}
	got, err := DecodeUserSecrets(wire)
	if err != nil {
		t.Fatalf("DecodeUserSecrets: %v", err)
	}
	if got.Version != want.Version || len(got.Secrets) != 2 || *got.Description != desc {
		t.Fatalf("mismatch: got %+v", got)
	}
	if got.Secrets[0].Name != "a" || string(got.Secrets[0].Data) != string([]byte{9, 9}) {
		t.Fatalf("Secrets[0] = %+v", got.Secrets[0])
	}
}

func TestEncodeUserSecrets_NoDescriptionOmitsField(t *testing.T) {
	got, err := EncodeUserSecrets(UserSecrets{Version: 1, Secrets: nil})
	if err != nil {
		t.Fatalf("EncodeUserSecrets: %v", err)
	}
	want := `{"version":1,"secrets":[]}`
	if string(got) != want {
		t.Fatalf("mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// --- uint array helpers used for channel-id / version lists that cross
// the FFI as plain JSON number arrays (Vec<u64>/Vec<u32>, never
// stringified).

func TestUint64ArrayRoundTrip(t *testing.T) {
	want := []uint64{1, 2, 18446744073709551615}
	wire, err := EncodeUint64Array(want)
	if err != nil {
		t.Fatalf("EncodeUint64Array: %v", err)
	}
	if string(wire) != `[1,2,18446744073709551615]` {
		t.Fatalf("unexpected wire shape (must be a plain number array, not strings): %s", wire)
	}
	got, err := DecodeUint64Array(wire)
	if err != nil {
		t.Fatalf("DecodeUint64Array: %v", err)
	}
	if len(got) != 3 || got[2] != 18446744073709551615 {
		t.Fatalf("got %v", got)
	}
}

func TestUint32ArrayRoundTrip(t *testing.T) {
	want := []uint32{7, 8}
	wire, err := EncodeUint32Array(want)
	if err != nil {
		t.Fatalf("EncodeUint32Array: %v", err)
	}
	got, err := DecodeUint32Array(wire)
	if err != nil {
		t.Fatalf("DecodeUint32Array: %v", err)
	}
	if len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Fatalf("got %v", got)
	}
}

// --- JSONByteArray: the core reason a naive struct-tag []byte field would
// be wrong here — Go's encoding/json base64-encodes []byte by default,
// but serde_json's default Vec<u8> representation is a number array.

func TestJsonByteArray_MarshalsAsNumberArrayNotBase64(t *testing.T) {
	b := JSONByteArray{0, 1, 255}
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != "[0,1,255]" {
		t.Fatalf("expected number array, got %s (base64 would be wrong here)", out)
	}
}

func TestJsonByteArray_UnmarshalRejectsOutOfRange(t *testing.T) {
	var b JSONByteArray
	if err := json.Unmarshal([]byte("[1,2,300]"), &b); err == nil {
		t.Fatal("expected error for byte value out of range")
	}
}

// --- PendingRecovery carries the secret being recovered --------------
//
// The recovering device runs an ephemeral instance, so the secret named
// in a PendingRecovery row is not the secret_id partitioning the store.
// Both the key and the item must carry it, or the Rust side rejects the
// row and every recovered share is dropped.

func TestStateKeyRoundTrip_PendingRecoveryCarriesSecretID(t *testing.T) {
	sid := uint64(0xA0)
	ver := uint32(3)
	wire, err := EncodeStateKey(StateKey{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &ver})
	if err != nil {
		t.Fatalf("EncodeStateKey: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(wire, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(raw["secret_id"]) != `"160"` {
		t.Fatalf("secret_id must be a stringified u64, got: %s", wire)
	}

	got, err := DecodeStateKey(wire)
	if err != nil {
		t.Fatalf("DecodeStateKey: %v", err)
	}
	if got.SecretID == nil || *got.SecretID != sid {
		t.Fatalf("SecretID mismatch: got %+v want %d", got.SecretID, sid)
	}
}

func TestEncodeStateKey_PendingRecoveryRequiresSecretID(t *testing.T) {
	ver := uint32(3)
	if _, err := EncodeStateKey(StateKey{Kind: StateKindPendingRecovery, Version: &ver}); err == nil {
		t.Fatal("expected an error when SecretID is absent")
	}
}

func TestStateItemRoundTrip_PendingRecoveryCarriesSecretID(t *testing.T) {
	sid := uint64(0xA0)
	ver := uint32(4)
	want := StateItem{
		Kind:     StateKindPendingRecovery,
		SecretID: &sid,
		Version:  &ver,
		Shares:   [][]byte{{1, 2}},
	}
	wire, err := EncodeStateItem(want)
	if err != nil {
		t.Fatalf("EncodeStateItem: %v", err)
	}
	got, err := DecodeStateItem(wire)
	if err != nil {
		t.Fatalf("DecodeStateItem: %v", err)
	}
	if got.SecretID == nil || *got.SecretID != sid {
		t.Fatalf("SecretID mismatch: got %+v want %d", got.SecretID, sid)
	}
}

func TestStateItemKey_PendingRecoveryPropagatesSecretID(t *testing.T) {
	sid := uint64(0xA0)
	ver := uint32(4)
	key := StateItem{Kind: StateKindPendingRecovery, SecretID: &sid, Version: &ver}.Key()
	if key.SecretID == nil || *key.SecretID != sid {
		t.Fatalf("Key() dropped SecretID: %+v", key)
	}
	if key.Version == nil || *key.Version != ver {
		t.Fatalf("Key() dropped Version: %+v", key)
	}
}

func TestDecodeStateItem_PendingRecoveryRequiresSecretID(t *testing.T) {
	wire := []byte(`{"kind":1,"version":4,"shares":[]}`)
	if _, err := DecodeStateItem(wire); err == nil {
		t.Fatal("expected an error when secret_id is absent")
	}
}
