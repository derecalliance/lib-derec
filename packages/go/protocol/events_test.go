// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import "testing"

// The JSON literals below are hand-built to match wire::Event in
// library/src/protocol/events/wire.rs exactly: `#[serde(tag = "type")]`
// (internally tagged — the discriminator and every payload field are
// siblings in one flat object) with the Rust field names verbatim.
// skip_serializing_if fields are exercised both present and (where the
// real encoder would omit them) absent, to prove the corresponding Go
// field decodes to nil/zero rather than erroring.

func decodeOne(t *testing.T, raw string) Event {
	t.Helper()
	events, err := decodeEvents([]byte("[" + raw + "]"))
	if err != nil {
		t.Fatalf("decodeEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one event, got %d", len(events))
	}
	return events[0]
}

func TestDecodeEvents_PairingCompleted(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "PairingCompleted",
		"channel_id": "11",
		"pairing_channel_id": "5",
		"kind": 0,
		"peer_communication_info": {"name": "Owner"}
	}`)
	if ev.Type != EventTypePairingCompleted {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != "11" || ev.PairingChannelID != "5" {
		t.Fatalf("channel ids: got %+v", ev)
	}
	if ev.Kind != 0 {
		t.Fatalf("Kind: got %d", ev.Kind)
	}
	if ev.PeerCommunicationInfo["name"] != "Owner" {
		t.Fatalf("PeerCommunicationInfo: got %+v", ev.PeerCommunicationInfo)
	}
}

// TestDecodeEvents_PairingCompleted_EmptyCommunicationInfoOmitted proves the
// skip_serializing_if = "HashMap::is_empty" convention round-trips: when the
// Rust encoder omits an empty map entirely, the Go field decodes to nil,
// not an empty-but-non-nil map.
func TestDecodeEvents_PairingCompleted_EmptyCommunicationInfoOmitted(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "PairingCompleted",
		"channel_id": "11",
		"pairing_channel_id": "5",
		"kind": 1
	}`)
	if ev.PeerCommunicationInfo != nil {
		t.Fatalf("expected nil PeerCommunicationInfo, got %+v", ev.PeerCommunicationInfo)
	}
}

func TestDecodeEvents_ReplicaPaired(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaPaired",
		"channel_id": "11",
		"peer_replica_id": "48879"
	}`)
	if ev.Type != EventTypeReplicaPaired {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != "11" || ev.PeerReplicaID != "48879" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ReplicaSecretReceived(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSecretReceived",
		"channel_id": "11",
		"from_replica_id": "48879",
		"secret_id": "42",
		"version": 3,
		"secret": {
			"helpers": [
				{"channel_id": "1", "transport_uri": "https://h1", "shared_key": [1,2,3], "communication_info": {"k": "v"}}
			],
			"secrets": [
				{"id": [9,9], "name": "n1", "data": [10,11]}
			],
			"replicas": {
				"replicas": [
					{"channel_id": "21", "transport_uri": "https://r1", "communication_info": {}, "replica_id": "0xCAFE", "sender_kind": 4}
				],
				"shared_key": [1,2,3,4]
			},
			"owner_replica_id": "48879"
		},
		"shares": [
			{"channel_id": "1", "committed_share": [5,6,7]}
		]
	}`)
	if ev.Type != EventTypeReplicaSecretReceived {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != "11" || ev.FromReplicaID != "48879" || ev.SecretID != "42" {
		t.Fatalf("ids: got %+v", ev)
	}
	if ev.Version == nil || *ev.Version != 3 {
		t.Fatalf("Version: got %v", ev.Version)
	}
	if ev.Secret == nil {
		t.Fatal("expected non-nil Secret")
	}
	if len(ev.Secret.Helpers) != 1 || ev.Secret.Helpers[0].ChannelID != "1" ||
		ev.Secret.Helpers[0].TransportURI != "https://h1" ||
		string(ev.Secret.Helpers[0].SharedKey) != string([]byte{1, 2, 3}) ||
		ev.Secret.Helpers[0].CommunicationInfo["k"] != "v" {
		t.Fatalf("Helpers: got %+v", ev.Secret.Helpers)
	}
	if len(ev.Secret.Secrets) != 1 || ev.Secret.Secrets[0].Name != "n1" ||
		string(ev.Secret.Secrets[0].ID) != string([]byte{9, 9}) ||
		string(ev.Secret.Secrets[0].Data) != string([]byte{10, 11}) {
		t.Fatalf("Secrets: got %+v", ev.Secret.Secrets)
	}
	if ev.Secret.Replicas == nil {
		t.Fatal("expected non-nil Replicas")
	}
	if len(ev.Secret.Replicas.Replicas) != 1 ||
		ev.Secret.Replicas.Replicas[0].ReplicaID != "0xCAFE" ||
		ev.Secret.Replicas.Replicas[0].SenderKind != 4 {
		t.Fatalf("Replicas: got %+v", ev.Secret.Replicas.Replicas)
	}
	if string(ev.Secret.Replicas.SharedKey) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("group shared_key: got %v", ev.Secret.Replicas.SharedKey)
	}
	if ev.Secret.OwnerReplicaID != "48879" {
		t.Fatalf("OwnerReplicaID: got %q", ev.Secret.OwnerReplicaID)
	}
	if len(ev.Shares) != 1 || ev.Shares[0].ChannelID != "1" ||
		string(ev.Shares[0].CommittedShare) != string([]byte{5, 6, 7}) {
		t.Fatalf("Shares: got %+v", ev.Shares)
	}
}

// TestDecodeEvents_ReplicaSecretReceived_NoReplicas covers the
// skip_serializing_if = "Option::is_none" convention on SecretWire.replicas
// — absent when the secret_id has no replica setup.
func TestDecodeEvents_ReplicaSecretReceived_NoReplicas(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSecretReceived",
		"channel_id": "11",
		"from_replica_id": "48879",
		"secret_id": "42",
		"version": 1,
		"secret": {
			"helpers": [],
			"secrets": [],
			"owner_replica_id": "48879"
		},
		"shares": []
	}`)
	if ev.Secret == nil {
		t.Fatal("expected non-nil Secret")
	}
	if ev.Secret.Replicas != nil {
		t.Fatalf("expected nil Replicas, got %+v", ev.Secret.Replicas)
	}
}

func TestDecodeEvents_ReplicaSecretAcked(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSecretAcked",
		"channel_id": "11",
		"from_replica_id": "48879",
		"secret_id": "42",
		"version": 2,
		"status": 0,
		"memo": ""
	}`)
	if ev.Type != EventTypeReplicaSecretAcked {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.Status != 0 || ev.Memo != "" {
		t.Fatalf("status/memo: got %+v", ev)
	}
	if ev.Version == nil || *ev.Version != 2 {
		t.Fatalf("Version: got %v", ev.Version)
	}
}

func TestDecodeEvents_ShareStored_WithReplicaID(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ShareStored",
		"channel_id": "11",
		"version": 1,
		"replica_id": "48879"
	}`)
	if ev.Type != EventTypeShareStored {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ReplicaID == nil || *ev.ReplicaID != "48879" {
		t.Fatalf("ReplicaID: got %v", ev.ReplicaID)
	}
}

// TestDecodeEvents_ShareStored_NullReplicaID covers the non-replica Owner
// writer case: the Rust field is Option<u64> encoded as JSON null (not
// omitted — ShareStored has no skip_serializing_if on replica_id).
func TestDecodeEvents_ShareStored_NullReplicaID(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ShareStored",
		"channel_id": "11",
		"version": 1,
		"replica_id": null
	}`)
	if ev.ReplicaID != nil {
		t.Fatalf("expected nil ReplicaID, got %v", *ev.ReplicaID)
	}
}

func TestDecodeEvents_ShareConfirmed(t *testing.T) {
	ev := decodeOne(t, `{"type": "ShareConfirmed", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeShareConfirmed || ev.ChannelID != "11" || ev.Version == nil || *ev.Version != 1 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ShareRejected(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ShareRejected",
		"channel_id": "11",
		"version": 1,
		"status": 3,
		"memo": "timeout"
	}`)
	if ev.Type != EventTypeShareRejected || ev.Status != 3 || ev.Memo != "timeout" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_SharingComplete(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "SharingComplete",
		"version": 1,
		"confirmed_count": 3,
		"failed_count": 1,
		"threshold_met": true
	}`)
	if ev.Type != EventTypeSharingComplete {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ConfirmedCount != 3 || ev.FailedCount != 1 || !ev.ThresholdMet {
		t.Fatalf("got %+v", ev)
	}
	// SharingComplete carries no channel_id in wire.rs.
	if ev.ChannelID != "" {
		t.Fatalf("expected empty ChannelID, got %q", ev.ChannelID)
	}
}

func TestDecodeEvents_ShareVerified(t *testing.T) {
	ev := decodeOne(t, `{"type": "ShareVerified", "channel_id": "11", "version": 2}`)
	if ev.Type != EventTypeShareVerified || ev.ChannelID != "11" || ev.Version == nil || *ev.Version != 2 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_SecretsDiscovered(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "SecretsDiscovered",
		"channel_id": "11",
		"secrets": [
			{"secret_id": "42", "versions": [{"version": 1, "description": "first"}, {"version": 2, "description": ""}]}
		]
	}`)
	if ev.Type != EventTypeSecretsDiscovered {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if len(ev.Secrets) != 1 || ev.Secrets[0].SecretID != "42" {
		t.Fatalf("Secrets: got %+v", ev.Secrets)
	}
	if len(ev.Secrets[0].Versions) != 2 ||
		ev.Secrets[0].Versions[0].Version != 1 || ev.Secrets[0].Versions[0].Description != "first" ||
		ev.Secrets[0].Versions[1].Version != 2 || ev.Secrets[0].Versions[1].Description != "" {
		t.Fatalf("Versions: got %+v", ev.Secrets[0].Versions)
	}
}

func TestDecodeEvents_RecoveryShareReceived(t *testing.T) {
	ev := decodeOne(t, `{"type": "RecoveryShareReceived", "channel_id": "11", "shares_received": 2}`)
	if ev.Type != EventTypeRecoveryShareReceived || ev.SharesReceived != 2 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_RecoveryShareError(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "RecoveryShareError",
		"channel_id": "11",
		"shares_received": 2,
		"error": "corrupted share"
	}`)
	if ev.Type != EventTypeRecoveryShareError || ev.SharesReceived != 2 || ev.Error != "corrupted share" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_SecretRecovered(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "SecretRecovered",
		"secret": {
			"helpers": [],
			"secrets": [{"id": [1], "name": "n", "data": [2]}],
			"owner_replica_id": "7"
		}
	}`)
	if ev.Type != EventTypeSecretRecovered {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.Secret == nil || ev.Secret.OwnerReplicaID != "7" || len(ev.Secret.Secrets) != 1 {
		t.Fatalf("Secret: got %+v", ev.Secret)
	}
	// SecretRecovered carries no channel_id in wire.rs.
	if ev.ChannelID != "" {
		t.Fatalf("expected empty ChannelID, got %q", ev.ChannelID)
	}
}

func TestDecodeEvents_Unpaired(t *testing.T) {
	ev := decodeOne(t, `{"type": "Unpaired", "channel_id": "11"}`)
	if ev.Type != EventTypeUnpaired || ev.ChannelID != "11" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UnpairRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "UnpairRejected", "channel_id": "11", "status": 3, "memo": "refused"}`)
	if ev.Type != EventTypeUnpairRejected || ev.Status != 3 || ev.Memo != "refused" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_PrePairRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "PrePairRejected", "channel_id": "11", "status": 3, "memo": "no"}`)
	if ev.Type != EventTypePrePairRejected || ev.Status != 3 || ev.Memo != "no" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ChannelInfoUpdated(t *testing.T) {
	ev := decodeOne(t, `{"type": "ChannelInfoUpdated", "channel_id": "11"}`)
	if ev.Type != EventTypeChannelInfoUpdated || ev.ChannelID != "11" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ChannelInfoUpdateRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "ChannelInfoUpdateRejected", "channel_id": "11", "status": 3, "memo": "no"}`)
	if ev.Type != EventTypeChannelInfoUpdateRejected || ev.Status != 3 || ev.Memo != "no" {
		t.Fatalf("got %+v", ev)
	}
}

// TestDecodeEvents_ActionRequired_Pairing covers the Pairing-flavored
// ActionRequired: peer_communication_info + sender_kind populated,
// share_description/share_secret_id absent (skip_serializing_if).
func TestDecodeEvents_ActionRequired_Pairing(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [1,2,3,4],
		"action_kind": "Pairing",
		"peer_communication_info": {"name": "Scanner"},
		"sender_kind": 1
	}`)
	if ev.Type != EventTypeActionRequired {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if string(ev.Action) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("Action: got %v", ev.Action)
	}
	if ev.ActionKind != "Pairing" {
		t.Fatalf("ActionKind: got %q", ev.ActionKind)
	}
	if ev.PeerCommunicationInfo["name"] != "Scanner" {
		t.Fatalf("PeerCommunicationInfo: got %+v", ev.PeerCommunicationInfo)
	}
	if ev.SenderKind == nil || *ev.SenderKind != 1 {
		t.Fatalf("SenderKind: got %v", ev.SenderKind)
	}
	if ev.Version != nil || ev.ShareDescription != nil || ev.ShareSecretID != nil {
		t.Fatalf("expected StoreShare-only fields absent, got version=%v desc=%v secretID=%v",
			ev.Version, ev.ShareDescription, ev.ShareSecretID)
	}
}

// TestDecodeEvents_ActionRequired_StoreShare covers the StoreShare-flavored
// ActionRequired: version/share_description/share_secret_id populated,
// sender_kind and peer_communication_info absent.
func TestDecodeEvents_ActionRequired_StoreShare(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [9],
		"action_kind": "StoreShare",
		"version": 4,
		"share_description": "quarterly rotation",
		"share_secret_id": "42"
	}`)
	if ev.ActionKind != "StoreShare" {
		t.Fatalf("ActionKind: got %q", ev.ActionKind)
	}
	if ev.Version == nil || *ev.Version != 4 {
		t.Fatalf("Version: got %v", ev.Version)
	}
	if ev.ShareDescription == nil || *ev.ShareDescription != "quarterly rotation" {
		t.Fatalf("ShareDescription: got %v", ev.ShareDescription)
	}
	if ev.ShareSecretID == nil || *ev.ShareSecretID != "42" {
		t.Fatalf("ShareSecretID: got %v", ev.ShareSecretID)
	}
	if ev.SenderKind != nil {
		t.Fatalf("expected nil SenderKind, got %v", *ev.SenderKind)
	}
	if ev.PeerCommunicationInfo != nil {
		t.Fatalf("expected nil PeerCommunicationInfo, got %+v", ev.PeerCommunicationInfo)
	}
}

// TestDecodeEvents_ActionRequired_Discovery covers a flavor with none of
// the optional fields present (Discovery/GetShare/Unpair/UpdateChannelInfo
// carry no per-flow metadata beyond action_kind).
func TestDecodeEvents_ActionRequired_Discovery(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [],
		"action_kind": "Discovery"
	}`)
	if ev.ActionKind != "Discovery" {
		t.Fatalf("ActionKind: got %q", ev.ActionKind)
	}
	if len(ev.Action) != 0 {
		t.Fatalf("expected an empty Action, got %v", ev.Action)
	}
	if ev.SenderKind != nil || ev.Version != nil || ev.ShareDescription != nil || ev.ShareSecretID != nil {
		t.Fatalf("expected every optional field nil, got %+v", ev)
	}
}

func TestDecodeEvents_AutoAccepted(t *testing.T) {
	ev := decodeOne(t, `{"type": "AutoAccepted", "channel_id": "11", "action_kind": "StoreShare"}`)
	if ev.Type != EventTypeAutoAccepted || ev.ChannelID != "11" || ev.ActionKind != "StoreShare" {
		t.Fatalf("got %+v", ev)
	}
}

// TestDecodeEvents_NoOp proves the unit variant — and, by extension, any
// future/unrecognized variant that degrades to NoOp on the Rust side —
// decodes cleanly with no error and no populated payload fields.
func TestDecodeEvents_NoOp(t *testing.T) {
	ev := decodeOne(t, `{"type": "NoOp"}`)
	if ev.Type != EventTypeNoOp {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != "" || ev.Version != nil || ev.Secret != nil {
		t.Fatalf("expected an all-zero payload, got %+v", ev)
	}
}

func TestDecodeEvents_PairingStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "PairingStarted", "channel_id": "11", "kind": 0}`)
	if ev.Type != EventTypePairingStarted || ev.ChannelID != "11" || ev.Kind != 0 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_DiscoveryStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "DiscoveryStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeDiscoveryStarted || ev.ChannelID != "11" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_DiscoveryFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "DiscoveryFailed", "channel_id": "11", "error": "send failed"}`)
	if ev.Type != EventTypeDiscoveryFailed || ev.Error != "send failed" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ProtectSecretStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "ProtectSecretStarted", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeProtectSecretStarted || ev.Version == nil || *ev.Version != 1 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ProtectSecretFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "ProtectSecretFailed", "channel_id": "11", "version": 1, "error": "send failed"}`)
	if ev.Type != EventTypeProtectSecretFailed || ev.Error != "send failed" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_VerifySharesStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "VerifySharesStarted", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeVerifySharesStarted || ev.Version == nil || *ev.Version != 1 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_VerifySharesFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "VerifySharesFailed", "channel_id": "11", "version": 1, "error": "timeout"}`)
	if ev.Type != EventTypeVerifySharesFailed || ev.Error != "timeout" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_RecoverSecretStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "RecoverSecretStarted", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeRecoverSecretStarted || ev.Version == nil || *ev.Version != 1 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_RecoverSecretFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "RecoverSecretFailed", "channel_id": "11", "version": 1, "error": "no quorum"}`)
	if ev.Type != EventTypeRecoverSecretFailed || ev.Error != "no quorum" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UnpairStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "UnpairStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeUnpairStarted || ev.ChannelID != "11" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UpdateChannelInfoStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "UpdateChannelInfoStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeUpdateChannelInfoStarted || ev.ChannelID != "11" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UpdateChannelInfoFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "UpdateChannelInfoFailed", "channel_id": "11", "error": "peer unreachable"}`)
	if ev.Type != EventTypeUpdateChannelInfoFailed || ev.Error != "peer unreachable" {
		t.Fatalf("got %+v", ev)
	}
}

// TestDecodeEvents_Array proves the top-level shape: a JSON array of mixed
// event objects (as encode_events actually emits — see
// library/src/ffi/protocol/events.rs) decodes into a slice preserving
// order, without any per-event cross-talk.
func TestDecodeEvents_Array(t *testing.T) {
	raw := `[
		{"type": "PairingStarted", "channel_id": "1", "kind": 0},
		{"type": "NoOp"},
		{"type": "PairingCompleted", "channel_id": "11", "pairing_channel_id": "1", "kind": 0}
	]`
	events, err := decodeEvents([]byte(raw))
	if err != nil {
		t.Fatalf("decodeEvents: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].Type != EventTypePairingStarted || events[1].Type != EventTypeNoOp || events[2].Type != EventTypePairingCompleted {
		t.Fatalf("order/type mismatch: %+v", events)
	}
}

// TestDecodeEvents_EmptyArray covers the "no events" case
// derec_protocol_process can legitimately emit (e.g. a message whose only
// effect was already-applied auto-accept bookkeeping — see the Process
// binding tests in protocol_test.go for the FFI-level round trip).
func TestDecodeEvents_EmptyArray(t *testing.T) {
	events, err := decodeEvents([]byte(`[]`))
	if err != nil {
		t.Fatalf("decodeEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected no events, got %+v", events)
	}
}

// TestDecodeEvents_NilInput covers the FFI's empty-buffer convention:
// bytesFromBuffer returns nil for a null/zero-length DeRecBuffer, which
// decodeEvents must accept without attempting to parse it as JSON.
func TestDecodeEvents_NilInput(t *testing.T) {
	events, err := decodeEvents(nil)
	if err != nil {
		t.Fatalf("decodeEvents(nil): %v", err)
	}
	if events != nil {
		t.Fatalf("expected nil events, got %+v", events)
	}
}

// TestDecodeEvents_MalformedJSON asserts the decoder surfaces a genuine
// JSON parse error instead of silently dropping/zeroing malformed input —
// decodeEvents must not weaken error reporting from encoding/json.
func TestDecodeEvents_MalformedJSON(t *testing.T) {
	_, err := decodeEvents([]byte(`not json`))
	if err == nil {
		t.Fatal("expected a JSON decode error")
	}
}
