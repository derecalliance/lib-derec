// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

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
	if ev.ChannelID != 11 || ev.PairingChannelID != 5 {
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
	if ev.ChannelID != 11 || ev.PeerReplicaID != 48879 {
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
				{"channel_id": "1", "transports": [{"uri": "https://h1", "protocol": "https"}], "shared_key": [1,2,3], "communication_info": {"k": "v"}}
			],
			"secrets": [
				{"id": [9,9], "name": "n1", "data": [10,11]}
			],
			"replicas": {
				"channel_id": "21",
				"members": [
					{"replica_id": "48879", "transports": [{"uri": "https://src", "protocol": "https"}], "role": "Source", "communication_info": {}},
					{"replica_id": "51966", "transports": [{"uri": "https://r1", "protocol": "https"}], "role": "Destination", "communication_info": {}}
				],
				"shared_key": [1,2,3,4]
			}
		},
		"shares": [
			{"channel_id": "1", "committed_share": [5,6,7]}
		]
	}`)
	if ev.Type != EventTypeReplicaSecretReceived {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != 11 || ev.FromReplicaID != 48879 || ev.SecretID != 42 {
		t.Fatalf("ids: got %+v", ev)
	}
	if ev.Version == nil || *ev.Version != 3 {
		t.Fatalf("Version: got %v", ev.Version)
	}
	if ev.Secret == nil {
		t.Fatal("expected non-nil Secret")
	}
	if len(ev.Secret.Helpers) != 1 || ev.Secret.Helpers[0].ChannelID != 1 ||
		ev.Secret.Helpers[0].Transports[0].URI != "https://h1" ||
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
	if ev.Secret.Replicas.ChannelID != 21 {
		t.Fatalf("group channel_id: got %d", ev.Secret.Replicas.ChannelID)
	}
	if len(ev.Secret.Replicas.Members) != 2 {
		t.Fatalf("Members: got %+v", ev.Secret.Replicas.Members)
	}
	// The roster names its source by role rather than a separate field.
	var sources []uint64
	for _, m := range ev.Secret.Replicas.Members {
		if m.Role == ReplicaRoleSource {
			sources = append(sources, m.ReplicaID)
		}
	}
	if len(sources) != 1 || sources[0] != 48879 {
		t.Fatalf("roster must name exactly one source, got %v", sources)
	}
	if ev.Secret.Replicas.Members[1].ReplicaID != 51966 ||
		ev.Secret.Replicas.Members[1].Role != ReplicaRoleDestination {
		t.Fatalf("destination member: got %+v", ev.Secret.Replicas.Members[1])
	}
	if string(ev.Secret.Replicas.SharedKey) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("group shared_key: got %v", ev.Secret.Replicas.SharedKey)
	}
	if len(ev.Shares) != 1 || ev.Shares[0].ChannelID != 1 ||
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
	if ev.Status != derecpb.StatusEnum_OK || ev.Memo != "" {
		t.Fatalf("status/memo: got %+v", ev)
	}
	if ev.Version == nil || *ev.Version != 2 {
		t.Fatalf("Version: got %v", ev.Version)
	}
}

// TestDecodeEvents_ShareStored covers the wire shape: channel_id and version
// only. Helpers never learn replica identity, so no replica_id is carried.
func TestDecodeEvents_ShareStored(t *testing.T) {
	ev := decodeOne(t, `{"type": "ShareStored", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeShareStored || ev.ChannelID != 11 || ev.Version == nil || *ev.Version != 1 {
		t.Fatalf("got %+v", ev)
	}
	if ev.ReplicaID != nil {
		t.Fatalf("expected nil ReplicaID, got %v", *ev.ReplicaID)
	}
}

func TestDecodeEvents_ReplicaSecretReceived_AuthorReplicaID(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSecretReceived",
		"channel_id": "11",
		"from_replica_id": "7",
		"author_replica_id": "18446744073709551615",
		"secret_id": "42",
		"version": 4,
		"secret": {"helpers": [], "secrets": []},
		"shares": []
	}`)
	if ev.FromReplicaID != 7 {
		t.Fatalf("FromReplicaID: got %d", ev.FromReplicaID)
	}
	if ev.AuthorReplicaID == nil || *ev.AuthorReplicaID != 18446744073709551615 {
		t.Fatalf("AuthorReplicaID: got %v", ev.AuthorReplicaID)
	}
}

func TestDecodeEvents_ReplicaSecretInstalled_NullAuthorReplicaID(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSecretInstalled",
		"channel_id": "11",
		"from_replica_id": "7",
		"author_replica_id": null,
		"secret_id": "42",
		"version": 1,
		"secret": {"helpers": [], "secrets": []},
		"shares": []
	}`)
	if ev.Type != EventTypeReplicaSecretInstalled || ev.AuthorReplicaID != nil {
		t.Fatalf("got Type=%q AuthorReplicaID=%v", ev.Type, ev.AuthorReplicaID)
	}
}

func TestDecodeEvents_ReplicaVersionConflict(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaVersionConflict",
		"channel_id": "11",
		"from_replica_id": "7",
		"secret_id": "42",
		"version": 5,
		"held_author_replica_id": null,
		"incoming_author_replica_id": "9",
		"secret": {
			"helpers": [],
			"secrets": [{"id": [1], "name": "n", "data": [2]}]
		}
	}`)
	if ev.Type != EventTypeReplicaVersionConflict {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.ChannelID != 11 || ev.FromReplicaID != 7 || ev.SecretID != 42 ||
		ev.Version == nil || *ev.Version != 5 {
		t.Fatalf("ids/version: got %+v", ev)
	}
	if ev.HeldAuthorReplicaID != nil {
		t.Fatalf("HeldAuthorReplicaID: got %v, want nil", *ev.HeldAuthorReplicaID)
	}
	if ev.IncomingAuthorReplicaID == nil || *ev.IncomingAuthorReplicaID != 9 {
		t.Fatalf("IncomingAuthorReplicaID: got %v", ev.IncomingAuthorReplicaID)
	}
	if ev.Secret == nil || len(ev.Secret.Secrets) != 1 || ev.Secret.Secrets[0].Name != "n" {
		t.Fatalf("Secret: got %+v", ev.Secret)
	}
}

func TestDecodeEvents_ShareConfirmed(t *testing.T) {
	ev := decodeOne(t, `{"type": "ShareConfirmed", "channel_id": "11", "version": 1}`)
	if ev.Type != EventTypeShareConfirmed || ev.ChannelID != 11 || ev.Version == nil || *ev.Version != 1 {
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
	if ev.Type != EventTypeShareRejected || ev.Status != derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED || ev.Memo != "timeout" {
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
	if ev.ChannelID != 0 {
		t.Fatalf("expected empty ChannelID, got %d", ev.ChannelID)
	}
}

func TestDecodeEvents_ShareVerified(t *testing.T) {
	ev := decodeOne(t, `{"type": "ShareVerified", "channel_id": "11", "version": 2}`)
	if ev.Type != EventTypeShareVerified || ev.ChannelID != 11 || ev.Version == nil || *ev.Version != 2 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ShareVerifyRejected(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ShareVerifyRejected",
		"channel_id": "11",
		"version": 2,
		"status": 6,
		"memo": "no stored share"
	}`)
	if ev.Type != EventTypeShareVerifyRejected || ev.ChannelID != 11 || ev.Version == nil || *ev.Version != 2 ||
		ev.Status != derecpb.StatusEnum_UNKNOWN_SHARE_VERSION || ev.Memo != "no stored share" {
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
	if len(ev.Secrets) != 1 || ev.Secrets[0].SecretID != 42 {
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

func TestDecodeEvents_RecoveryShareRefused(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "RecoveryShareRefused",
		"channel_id": "11",
		"version": 2,
		"status": 6,
		"memo": "no share stored for this secret and version"
	}`)
	if ev.Type != EventTypeRecoveryShareRefused || ev.ChannelID != 11 || ev.Version == nil || *ev.Version != 2 ||
		ev.Status != derecpb.StatusEnum_UNKNOWN_SHARE_VERSION || ev.Memo != "no share stored for this secret and version" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_RecoveryShareCorrupted(t *testing.T) {
	for _, reason := range []string{CorruptionReasonMalformed, CorruptionReasonInvalidProof, CorruptionReasonInconsistent} {
		ev := decodeOne(t, `{
			"type": "RecoveryShareCorrupted",
			"channel_id": "18446744073709551615",
			"version": 2,
			"reason": "`+reason+`"
		}`)
		if ev.Type != EventTypeRecoveryShareCorrupted || ev.ChannelID != 18446744073709551615 ||
			ev.Version == nil || *ev.Version != 2 || ev.Reason != reason {
			t.Fatalf("got %+v", ev)
		}
	}
}

func TestDecodeEvents_SecretRecovered(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "SecretRecovered",
		"secret": {
			"helpers": [],
			"secrets": [{"id": [1], "name": "n", "data": [2]}]
		}
	}`)
	if ev.Type != EventTypeSecretRecovered {
		t.Fatalf("Type: got %q", ev.Type)
	}
	if ev.Secret == nil || len(ev.Secret.Secrets) != 1 {
		t.Fatalf("Secret: got %+v", ev.Secret)
	}
	// SecretRecovered carries no channel_id in wire.rs.
	if ev.ChannelID != 0 {
		t.Fatalf("expected empty ChannelID, got %d", ev.ChannelID)
	}
}

func TestDecodeEvents_ReplicaSyncRejected(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSyncRejected",
		"replica_id": "7",
		"secret_id": "42",
		"version": 2,
		"status": 13,
		"memo": "conflict"
	}`)
	if ev.Type != EventTypeReplicaSyncRejected || ev.Status != derecpb.StatusEnum_VERSION_CONFLICT || ev.Memo != "conflict" {
		t.Fatalf("got %+v", ev)
	}
	if ev.ReplicaID == nil || *ev.ReplicaID != 7 || ev.SecretID != 42 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_Unpaired(t *testing.T) {
	ev := decodeOne(t, `{"type": "Unpaired", "channel_id": "11"}`)
	if ev.Type != EventTypeUnpaired || ev.ChannelID != 11 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UnpairRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "UnpairRejected", "channel_id": "11", "status": 3, "memo": "refused"}`)
	if ev.Type != EventTypeUnpairRejected || ev.Status != derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED || ev.Memo != "refused" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_PrePairRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "PrePairRejected", "channel_id": "11", "status": 3, "memo": "no"}`)
	if ev.Type != EventTypePrePairRejected || ev.Status != derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED || ev.Memo != "no" {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ChannelInfoUpdated(t *testing.T) {
	ev := decodeOne(t, `{"type": "ChannelInfoUpdated", "channel_id": "11"}`)
	if ev.Type != EventTypeChannelInfoUpdated || ev.ChannelID != 11 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_ChannelInfoUpdateRejected(t *testing.T) {
	ev := decodeOne(t, `{"type": "ChannelInfoUpdateRejected", "channel_id": "11", "status": 3, "memo": "no"}`)
	if ev.Type != EventTypeChannelInfoUpdateRejected || ev.Status != derecpb.StatusEnum_SIZE_LIMIT_EXCEEDED || ev.Memo != "no" {
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
	if ev.ShareSecretID == nil || *ev.ShareSecretID != 42 {
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

// TestDecodeEvents_ActionRequired_StoreShareSizeAndTrace covers share_size
// and trace_id on a StoreShare ActionRequired.
func TestDecodeEvents_ActionRequired_StoreShareSizeAndTrace(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [9],
		"action_kind": "StoreShare",
		"version": 4,
		"share_secret_id": "42",
		"trace_id": "18446744073709551615",
		"share_size": 1234
	}`)
	if ev.TraceID != 18446744073709551615 {
		t.Fatalf("TraceID: got %d", ev.TraceID)
	}
	if ev.ShareSize == nil || *ev.ShareSize != 1234 {
		t.Fatalf("ShareSize: got %v", ev.ShareSize)
	}
	if ev.UnpairMemo != nil || ev.UpdatedCommunicationInfo != nil || ev.UpdatedTransports != nil {
		t.Fatalf("expected Unpair/UpdateChannelInfo fields absent, got %+v", ev)
	}
}

// TestDecodeEvents_ActionRequired_GetShare covers version + share_secret_id
// naming the share a GetShare asks for.
func TestDecodeEvents_ActionRequired_GetShare(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [1],
		"action_kind": "GetShare",
		"version": 7,
		"share_secret_id": "99",
		"trace_id": "5"
	}`)
	if ev.ActionKind != ActionKindGetShare {
		t.Fatalf("ActionKind: got %q", ev.ActionKind)
	}
	if ev.Version == nil || *ev.Version != 7 {
		t.Fatalf("Version: got %v", ev.Version)
	}
	if ev.ShareSecretID == nil || *ev.ShareSecretID != 99 {
		t.Fatalf("ShareSecretID: got %v", ev.ShareSecretID)
	}
	if ev.TraceID != 5 {
		t.Fatalf("TraceID: got %d", ev.TraceID)
	}
	if ev.ShareSize != nil {
		t.Fatalf("expected nil ShareSize, got %v", *ev.ShareSize)
	}
}

func TestDecodeEvents_ActionRequired_Unpair(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired",
		"channel_id": "11",
		"action": [1],
		"action_kind": "Unpair",
		"trace_id": "6",
		"unpair_memo": "moving on"
	}`)
	if ev.ActionKind != ActionKindUnpair {
		t.Fatalf("ActionKind: got %q", ev.ActionKind)
	}
	if ev.UnpairMemo == nil || *ev.UnpairMemo != "moving on" {
		t.Fatalf("UnpairMemo: got %v", ev.UnpairMemo)
	}
}

func TestDecodeEvents_ActionRequired_UpdateChannelInfo(t *testing.T) {
	t.Run("both fields", func(t *testing.T) {
		ev := decodeOne(t, `{
			"type": "ActionRequired",
			"channel_id": "11",
			"action": [1],
			"action_kind": "UpdateChannelInfo",
			"trace_id": "7",
			"updated_communication_info": {"name": "Bob"},
			"updated_transports": [{"uri": "https://new.example", "protocol": "grpc"}]
		}`)
		if ev.UpdatedCommunicationInfo == nil || ev.UpdatedCommunicationInfo["name"] != "Bob" {
			t.Fatalf("UpdatedCommunicationInfo: got %+v", ev.UpdatedCommunicationInfo)
		}
		want := []EndpointJSON{{URI: "https://new.example", Protocol: 1}}
		if len(ev.UpdatedTransports) != 1 || ev.UpdatedTransports[0] != want[0] {
			t.Fatalf("UpdatedTransports: got %+v", ev.UpdatedTransports)
		}
	})
	t.Run("transports only leaves communication info nil", func(t *testing.T) {
		ev := decodeOne(t, `{
			"type": "ActionRequired",
			"channel_id": "11",
			"action": [1],
			"action_kind": "UpdateChannelInfo",
			"trace_id": "8",
			"updated_transports": [{"uri": "https://new.example", "protocol": "grpc"}]
		}`)
		if ev.UpdatedCommunicationInfo != nil {
			t.Fatalf("expected nil UpdatedCommunicationInfo (unchanged), got %+v", ev.UpdatedCommunicationInfo)
		}
		if len(ev.UpdatedTransports) != 1 || ev.UpdatedTransports[0].URI != "https://new.example" {
			t.Fatalf("UpdatedTransports: got %+v", ev.UpdatedTransports)
		}
	})
	t.Run("empty map means clear", func(t *testing.T) {
		ev := decodeOne(t, `{
			"type": "ActionRequired",
			"channel_id": "11",
			"action": [1],
			"action_kind": "UpdateChannelInfo",
			"trace_id": "9",
			"updated_communication_info": {}
		}`)
		if ev.UpdatedCommunicationInfo == nil || len(ev.UpdatedCommunicationInfo) != 0 {
			t.Fatalf("expected non-nil empty UpdatedCommunicationInfo (clear), got %#v", ev.UpdatedCommunicationInfo)
		}
		if ev.UpdatedTransports != nil {
			t.Fatalf("expected nil UpdatedTransports (unchanged), got %+v", ev.UpdatedTransports)
		}
	})
}

func TestDecodeEvents_AutoAccepted(t *testing.T) {
	ev := decodeOne(t, `{"type": "AutoAccepted", "channel_id": "11", "action_kind": "StoreShare"}`)
	if ev.Type != EventTypeAutoAccepted || ev.ChannelID != 11 || ev.ActionKind != "StoreShare" {
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
	if ev.ChannelID != 0 || ev.Version != nil || ev.Secret != nil {
		t.Fatalf("expected an all-zero payload, got %+v", ev)
	}
}

func TestDecodeEvents_PairingStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "PairingStarted", "channel_id": "11", "kind": 0}`)
	if ev.Type != EventTypePairingStarted || ev.ChannelID != 11 || ev.Kind != 0 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_DiscoveryStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "DiscoveryStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeDiscoveryStarted || ev.ChannelID != 11 {
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

func TestDecodeEvents_UnpairFailed(t *testing.T) {
	ev := decodeOne(t, `{"type": "UnpairFailed", "channel_id": "99", "error": "transport unreachable"}`)
	if ev.Type != EventTypeUnpairFailed || ev.ChannelID != 99 || ev.Error != "transport unreachable" {
		t.Fatalf("UnpairFailed decoded wrong: %+v", ev)
	}
}

func TestDecodeEvents_UnpairStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "UnpairStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeUnpairStarted || ev.ChannelID != 11 {
		t.Fatalf("got %+v", ev)
	}
}

func TestDecodeEvents_UpdateChannelInfoStarted(t *testing.T) {
	ev := decodeOne(t, `{"type": "UpdateChannelInfoStarted", "channel_id": "11"}`)
	if ev.Type != EventTypeUpdateChannelInfoStarted || ev.ChannelID != 11 {
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
// library/src/interop/ffi/protocol/events.rs) decodes into a slice preserving
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

// TestDecodeEvents_IDsAboveFloat64Precision_RoundTripToRestore decodes ids
// past 2^53 (and u64::MAX) from the decimal strings the wire carries, then
// re-marshals the recovered Secret as Restore's params: every id must come
// back as the identical decimal string.
func TestDecodeEvents_IDsAboveFloat64Precision_RoundTripToRestore(t *testing.T) {
	const max = "18446744073709551615"
	const above53 = "9007199254740993"
	ev := decodeOne(t, `{
		"type": "SecretRecovered",
		"secret": {
			"helpers": [{"channel_id": "`+max+`", "transports": [], "shared_key": [1]}],
			"secrets": [],
			"replicas": {
				"channel_id": "`+above53+`",
				"members": [{"replica_id": "`+max+`", "transports": [], "role": "Source"}],
				"shared_key": [2]
			}
		}
	}`)
	if ev.Secret.Helpers[0].ChannelID != 18446744073709551615 ||
		ev.Secret.Replicas.ChannelID != 9007199254740993 ||
		ev.Secret.Replicas.Members[0].ReplicaID != 18446744073709551615 {
		t.Fatalf("ids lost precision: %+v", ev.Secret)
	}

	got, err := json.Marshal(restoreParamsWire{Version: 1, RecoveredSecret: *ev.Secret})
	if err != nil {
		t.Fatalf("marshal restore params: %v", err)
	}
	var wire struct {
		RecoveredSecret struct {
			Helpers []struct {
				ChannelID string `json:"channel_id"`
			} `json:"helpers"`
			Replicas struct {
				ChannelID string `json:"channel_id"`
				Members   []struct {
					ReplicaID string `json:"replica_id"`
					Role      string `json:"role"`
				} `json:"members"`
			} `json:"replicas"`
		} `json:"recovered_secret"`
	}
	if err := json.Unmarshal(got, &wire); err != nil {
		t.Fatalf("parse restore params: %v", err)
	}
	rs := wire.RecoveredSecret
	if rs.Helpers[0].ChannelID != max || rs.Replicas.ChannelID != above53 ||
		rs.Replicas.Members[0].ReplicaID != max || rs.Replicas.Members[0].Role != "Source" {
		t.Fatalf("restore params do not carry the decimal ids verbatim: %s", got)
	}
}

func TestDecodeEvents_IDsAboveFloat64Precision_EventFields(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ReplicaSyncComplete",
		"version": 1,
		"synced": ["18446744073709551615", "9007199254740993"],
		"behind": ["0"]
	}`)
	if len(ev.Synced) != 2 || ev.Synced[0] != 18446744073709551615 || ev.Synced[1] != 9007199254740993 ||
		len(ev.Behind) != 1 || ev.Behind[0] != 0 {
		t.Fatalf("Synced/Behind: got %v / %v", ev.Synced, ev.Behind)
	}

	ev = decodeOne(t, `{"type": "ReplicaRemoved", "replica_id": "18446744073709551615"}`)
	if ev.ReplicaID == nil || *ev.ReplicaID != 18446744073709551615 {
		t.Fatalf("ReplicaID: got %v", ev.ReplicaID)
	}
}

func TestDecodeEvents_MalformedIDIsAnError(t *testing.T) {
	for _, raw := range []string{
		`{"type": "Unpaired", "channel_id": "18446744073709551616"}`,
		`{"type": "Unpaired", "channel_id": "-1"}`,
		`{"type": "ReplicaSyncComplete", "version": 1, "synced": ["x"], "behind": []}`,
	} {
		if _, err := decodeEvents([]byte("[" + raw + "]")); err == nil {
			t.Fatalf("expected a decode error for %s", raw)
		}
	}
}

func TestDecodeEvents_UnknownReplicaRoleIsAnError(t *testing.T) {
	raw := `[{"type": "SecretRecovered", "secret": {"helpers": [], "secrets": [],
		"replicas": {"channel_id": "1", "shared_key": [1],
			"members": [{"replica_id": "2", "transports": [], "role": "source"}]}}}]`
	if _, err := decodeEvents([]byte(raw)); err == nil {
		t.Fatal("expected a decode error for an unknown role")
	}
}

func TestEndpointJSON_ProtocolTravelsByName(t *testing.T) {
	ev := decodeOne(t, `{
		"type": "ActionRequired", "channel_id": "1", "action": [1],
		"action_kind": "UpdateChannelInfo", "trace_id": "2",
		"updated_transports": [
			{"uri": "https://a.example", "protocol": "https"},
			{"uri": "grpcs://b.example", "protocol": "grpc"}
		]
	}`)
	want := []EndpointJSON{
		{URI: "https://a.example", Protocol: int32(derecpb.Protocol_HTTPS)},
		{URI: "grpcs://b.example", Protocol: int32(derecpb.Protocol_GRPC)},
	}
	if len(ev.UpdatedTransports) != 2 || ev.UpdatedTransports[0] != want[0] || ev.UpdatedTransports[1] != want[1] {
		t.Fatalf("UpdatedTransports: got %+v", ev.UpdatedTransports)
	}

	got, err := json.Marshal(want[1])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != `{"uri":"grpcs://b.example","protocol":"grpc"}` {
		t.Fatalf("marshal: got %s", got)
	}
}

func TestEndpointJSON_UnknownOrNumericProtocolIsAnError(t *testing.T) {
	for _, protocol := range []string{`"websocket"`, `""`, `0`} {
		raw := `[{"type": "ActionRequired", "channel_id": "1", "action": [1],
			"action_kind": "UpdateChannelInfo", "trace_id": "2",
			"updated_transports": [{"uri": "https://a.example", "protocol": ` + protocol + `}]}]`
		if _, err := decodeEvents([]byte(raw)); err == nil {
			t.Fatalf("expected a decode error for protocol %s", protocol)
		}
	}
	if _, err := json.Marshal(EndpointJSON{URI: "https://a.example", Protocol: 99}); err == nil {
		t.Fatal("expected a marshal error for an undefined discriminant")
	}
}

// Kind and SenderKind carry the derec_proto::SenderKind numeric value on the
// wire and decode to the typed SenderKind, including the values past the gap
// at 2.
func TestDecodeEvents_SenderKindIsTyped(t *testing.T) {
	started := decodeOne(t, `{"type": "PairingStarted", "channel_id": "11", "kind": 4, "trace_id": "1"}`)
	var kind SenderKind = started.Kind
	if kind != SenderKindReplicaDestination || kind.String() != "ReplicaDestination" {
		t.Fatalf("Kind: got %v", kind)
	}

	action := decodeOne(t, `{
		"type": "ActionRequired",
		"trace_id": "1",
		"channel_id": "11",
		"action": [1],
		"action_kind": "Pairing",
		"sender_kind": 3
	}`)
	if action.SenderKind == nil || *action.SenderKind != SenderKindReplicaSource {
		t.Fatalf("SenderKind: got %v", action.SenderKind)
	}
}

func TestDecodeEvents_PeerNotRestored(t *testing.T) {
	helper := decodeOne(t, `{"type": "PeerNotRestored", "channel_id": "18446744073709551615", "reason": "NoTransports"}`)
	if helper.Type != EventTypePeerNotRestored ||
		helper.ChannelID != 18446744073709551615 ||
		helper.ReplicaID != nil ||
		helper.Reason != NotRestoredReasonNoTransports {
		t.Fatalf("helper entry: got %+v", helper)
	}

	member := decodeOne(t, `{"type": "PeerNotRestored", "channel_id": "21", "replica_id": "18446744073709551615", "reason": "NoTransports"}`)
	if member.Type != EventTypePeerNotRestored ||
		member.ChannelID != 21 ||
		member.ReplicaID == nil || *member.ReplicaID != 18446744073709551615 ||
		member.Reason != NotRestoredReasonNoTransports {
		t.Fatalf("member entry: got %+v", member)
	}
}
