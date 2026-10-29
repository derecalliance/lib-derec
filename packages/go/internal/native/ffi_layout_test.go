// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// layoutMirror pairs a #[repr(C)] struct in library/tests/fixtures/ffi_layout.json
// with the Go struct purego passes in its place, field by field.
type layoutMirror struct {
	fixture string
	goType  reflect.Type
	fields  [][2]string
}

var layoutMirrors = []layoutMirror{
	{"ApplyTraceIdResult", reflect.TypeOf(applyTraceIdResult{}), [][2]string{{"Error", "error"}, {"WireBytes", "wire_bytes"}}},
	{"ChannelStoreCallbacks", reflect.TypeOf(ChannelStoreCallbacks{}), [][2]string{{"UserData", "user_data"}, {"Load", "load"}, {"Save", "save"}, {"Remove", "remove"}, {"RemoveMany", "remove_many"}, {"ListHelpers", "list_helpers"}, {"ListReplicas", "list_replicas"}, {"LinkChannel", "link_channel"}, {"LinkedChannels", "linked_channels"}, {"FreeBuffer", "free_buffer"}}},
	{"CreateContactMessageResult", reflect.TypeOf(createContactMessageResult{}), [][2]string{{"Error", "error"}, {"ContactWireBytes", "contact_wire_bytes"}, {"SecretKeyMaterial", "secret_key_material"}}},
	{"DeRecBuffer", reflect.TypeOf(DeRecBuffer{}), [][2]string{{"Ptr", "ptr"}, {"Len", "len"}}},
	{"DeRecError", reflect.TypeOf(DeRecError{}), [][2]string{{"Category", "category"}, {"Code", "code"}, {"Message", "message"}, {"PeerStatus", "peer_status"}, {"PeerMemo", "peer_memo"}, {"Expected", "expected"}, {"Got", "got"}}},
	{"DeRecProtocolCreateContactResult", reflect.TypeOf(DeRecProtocolCreateContactResult{}), [][2]string{{"Error", "error"}, {"ContactWireBytes", "contact_wire_bytes"}}},
	{"DeRecProtocolEventsResult", reflect.TypeOf(DeRecProtocolEventsResult{}), [][2]string{{"Error", "error"}, {"EventsJSON", "events_json"}}},
	{"DeRecProtocolFingerprintResult", reflect.TypeOf(DeRecProtocolFingerprintResult{}), [][2]string{{"Error", "error"}, {"Fingerprint", "fingerprint"}}},
	{"DeRecProtocolNewResult", reflect.TypeOf(DeRecProtocolNewResult{}), [][2]string{{"Error", "error"}, {"Handle", "handle"}}},
	{"DeRecProtocolProcessResult", reflect.TypeOf(DeRecProtocolProcessResult{}), [][2]string{{"Error", "error"}, {"EventsJSON", "events_json"}, {"HasChannelID", "has_channel_id"}, {"ChannelID", "channel_id"}}},
	{"DeRecProtocolRestoreResult", reflect.TypeOf(DeRecProtocolRestoreResult{}), [][2]string{{"Error", "error"}, {"EventsJSON", "events_json"}, {"ConflictingChannelIDsJSON", "conflicting_channel_ids_json"}}},
	{"DeRecProtocolVersion", reflect.TypeOf(DeRecProtocolVersion{}), [][2]string{{"Major", "major"}, {"Minor", "minor"}}},
	{"DeRecRemovedChannelsResult", reflect.TypeOf(DeRecRemovedChannelsResult{}), [][2]string{{"Error", "error"}, {"Channels", "channels"}}},
	{"DecodeContactMessageResult", reflect.TypeOf(decodeContactMessageResult{}), [][2]string{{"Error", "error"}, {"ContactJSON", "contact_json"}}},
	{"EncodeContactMessageResult", reflect.TypeOf(encodeContactMessageResult{}), [][2]string{{"Error", "error"}, {"WireBytes", "wire_bytes"}}},
	{"ExtractGetSecretIdsVersionsRequestResult", reflect.TypeOf(extractGetSecretIdsVersionsRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractGetSecretIdsVersionsResponseResult", reflect.TypeOf(extractGetSecretIdsVersionsResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractGetShareRequestResult", reflect.TypeOf(extractGetShareRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractGetShareResponseResult", reflect.TypeOf(extractGetShareResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractPairRequestResult", reflect.TypeOf(extractPairRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractPairResponseResult", reflect.TypeOf(extractPairResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractPrePairRequestResult", reflect.TypeOf(extractPrePairRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractPrePairResponseResult", reflect.TypeOf(extractPrePairResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractStoreShareRequestResult", reflect.TypeOf(extractStoreShareRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractStoreShareResponseResult", reflect.TypeOf(extractStoreShareResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractUnpairRequestResult", reflect.TypeOf(extractUnpairRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"Memo", "memo"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractUnpairResponseResult", reflect.TypeOf(extractUnpairResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"ExtractVerifyShareRequestResult", reflect.TypeOf(extractVerifyRequestResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"RequestProtoBytes", "request_proto_bytes"}}},
	{"ExtractVerifyShareResponseResult", reflect.TypeOf(extractVerifyShareResponseResult{}), [][2]string{{"Error", "error"}, {"ChannelID", "channel_id"}, {"ResponseProtoBytes", "response_proto_bytes"}}},
	{"PairingFingerprintResult", reflect.TypeOf(pairingFingerprintResult{}), [][2]string{{"Error", "error"}, {"Fingerprint", "fingerprint"}}},
	{"ProcessGetSecretIdsVersionsResponseMessageResult", reflect.TypeOf(processGetSecretIdsVersionsResponseMessageResult{}), [][2]string{{"Error", "error"}, {"SecretListBytes", "secret_list_bytes"}}},
	{"ProcessPairResponseMessageResult", reflect.TypeOf(processPairResponseMessageResult{}), [][2]string{{"Error", "error"}, {"SharedKey", "shared_key"}, {"ChannelID", "channel_id"}}},
	{"ProcessPrePairResponseMessageResult", reflect.TypeOf(processPrePairResponseMessageResult{}), [][2]string{{"Error", "error"}, {"MlkemEncapsulationKey", "mlkem_encapsulation_key"}, {"EciesPublicKey", "ecies_public_key"}, {"Nonce", "nonce"}, {"FingerprintCommitment", "fingerprint_commitment"}}},
	{"ProcessStoreShareResponseMessageResult", reflect.TypeOf(processStoreShareResponseMessageResult{}), [][2]string{{"Error", "error"}}},
	{"ProcessUnpairResponseResult", reflect.TypeOf(processUnpairResponseResult{}), [][2]string{{"Error", "error"}}},
	{"ProduceGetSecretIdsVersionsRequestMessageResult", reflect.TypeOf(produceGetSecretIdsVersionsRequestMessageResult{}), [][2]string{{"Error", "error"}, {"EnvelopeWireBytes", "envelope_wire_bytes"}}},
	{"ProduceGetSecretIdsVersionsResponseMessageResult", reflect.TypeOf(produceGetSecretIdsVersionsResponseMessageResult{}), [][2]string{{"Error", "error"}, {"EnvelopeWireBytes", "envelope_wire_bytes"}}},
	{"ProduceGetShareRequestMessageResult", reflect.TypeOf(produceGetShareRequestMessageResult{}), [][2]string{{"Error", "error"}, {"RequestWireBytes", "request_wire_bytes"}}},
	{"ProduceGetShareResponseMessageResult", reflect.TypeOf(produceGetShareResponseMessageResult{}), [][2]string{{"Error", "error"}, {"ResponseWireBytes", "response_wire_bytes"}}},
	{"ProducePairRequestMessageResult", reflect.TypeOf(producePairRequestMessageResult{}), [][2]string{{"Error", "error"}, {"RequestWireBytes", "request_wire_bytes"}, {"InitiatorContactMessageWireBytes", "initiator_contact_message_wire_bytes"}, {"SecretKeyMaterial", "secret_key_material"}}},
	{"ProducePairResponseMessageResult", reflect.TypeOf(producePairResponseMessageResult{}), [][2]string{{"Error", "error"}, {"ResponseWireBytes", "response_wire_bytes"}, {"PeerTransports", "peer_transports"}, {"SharedKey", "shared_key"}, {"ChannelID", "channel_id"}}},
	{"ProducePrePairNoKeysResponseMessageResult", reflect.TypeOf(producePrePairNoKeysResponseMessageResult{}), [][2]string{{"Error", "error"}, {"EnvelopeWireBytes", "envelope_wire_bytes"}, {"SecretKeyMaterial", "secret_key_material"}}},
	{"ProducePrePairRequestMessageResult", reflect.TypeOf(producePrePairRequestMessageResult{}), [][2]string{{"Error", "error"}, {"EnvelopeWireBytes", "envelope_wire_bytes"}}},
	{"ProducePrePairResponseMessageResult", reflect.TypeOf(producePrePairResponseMessageResult{}), [][2]string{{"Error", "error"}, {"EnvelopeWireBytes", "envelope_wire_bytes"}}},
	{"ProduceStoreShareRequestMessageResult", reflect.TypeOf(produceStoreShareRequestMessageResult{}), [][2]string{{"Error", "error"}, {"WireBytes", "wire_bytes"}}},
	{"ProduceStoreShareResponseMessageResult", reflect.TypeOf(produceStoreShareResponseMessageResult{}), [][2]string{{"Error", "error"}, {"WireBytes", "wire_bytes"}, {"CommittedShareBytes", "committed_share_bytes"}, {"SecretID", "secret_id"}, {"Version", "version"}}},
	{"ProduceUnpairRequestMessageResult", reflect.TypeOf(produceUnpairRequestMessageResult{}), [][2]string{{"Error", "error"}, {"RequestWireBytes", "request_wire_bytes"}}},
	{"ProduceUnpairResponseMessageResult", reflect.TypeOf(produceUnpairResponseMessageResult{}), [][2]string{{"Error", "error"}, {"ResponseWireBytes", "response_wire_bytes"}}},
	{"ProduceVerifyShareRequestMessageResult", reflect.TypeOf(produceVerifyRequestResult{}), [][2]string{{"Error", "error"}, {"RequestWireBytes", "request_wire_bytes"}}},
	{"ProduceVerifyShareResponseMessageResult", reflect.TypeOf(produceVerifyShareResponseMessageResult{}), [][2]string{{"Error", "error"}, {"ResponseWireBytes", "response_wire_bytes"}}},
	{"ProtectSecretResult", reflect.TypeOf(protectSecretResult{}), [][2]string{{"Error", "error"}, {"SharesWireBytes", "shares_wire_bytes"}}},
	{"ReadTraceIdResult", reflect.TypeOf(readTraceIdResult{}), [][2]string{{"Error", "error"}, {"TraceID", "trace_id"}}},
	{"RecoverFromShareResponsesResult", reflect.TypeOf(recoverFromShareResponsesResult{}), [][2]string{{"Error", "error"}, {"SecretData", "secret_data"}}},
	{"SecretStoreCallbacks", reflect.TypeOf(SecretStoreCallbacks{}), [][2]string{{"UserData", "user_data"}, {"Load", "load"}, {"LoadMany", "load_many"}, {"Save", "save"}, {"Remove", "remove"}, {"RemoveMany", "remove_many"}, {"FreeBuffer", "free_buffer"}}},
	{"ShareStoreCallbacks", reflect.TypeOf(ShareStoreCallbacks{}), [][2]string{{"UserData", "user_data"}, {"Load", "load"}, {"LoadMany", "load_many"}, {"LoadAll", "load_all"}, {"LatestVersion", "latest_version"}, {"Save", "save"}, {"RemoveChannel", "remove_channel"}, {"RemoveVersions", "remove_versions"}, {"RemoveVersionsMany", "remove_versions_many"}, {"KeepVersion", "keep_version"}, {"RecordVerification", "record_verification"}, {"FreeBuffer", "free_buffer"}}},
	{"StateStoreCallbacks", reflect.TypeOf(StateStoreCallbacks{}), [][2]string{{"UserData", "user_data"}, {"Save", "save"}, {"Load", "load"}, {"Remove", "remove"}, {"RemoveMany", "remove_many"}, {"LoadAll", "load_all"}, {"FreeBuffer", "free_buffer"}}},
	{"TransportCallbacks", reflect.TypeOf(TransportCallbacks{}), [][2]string{{"UserData", "user_data"}, {"Send", "send"}}},
	{"UserSecretStoreCallbacks", reflect.TypeOf(UserSecretStoreCallbacks{}), [][2]string{{"UserData", "user_data"}, {"LoadLatest", "load_latest"}, {"SaveLatest", "save_latest"}, {"Remove", "remove"}, {"FreeBuffer", "free_buffer"}}},
	{"VerifyShareResponseResult", reflect.TypeOf(verifyShareResponseResult{}), [][2]string{{"Error", "error"}, {"IsValid", "is_valid"}}},
}

// layoutNotMirrored lists the fixture structs no Go code passes across the
// boundary.
var layoutNotMirrored = map[string]bool{
	"DeRecMessageJsonResult": true,
}

type layoutFixture struct {
	PointerWidth int `json:"pointer_width"`
	Structs      []struct {
		Name   string  `json:"name"`
		Size   uintptr `json:"size"`
		Align  uintptr `json:"align"`
		Fields []struct {
			Name   string  `json:"name"`
			Offset uintptr `json:"offset"`
		} `json:"fields"`
	} `json:"structs"`
}

func TestFFILayoutMatchesTheFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "library", "tests", "fixtures", "ffi_layout.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc layoutFixture
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if got := int(unsafe.Sizeof(uintptr(0)) * 8); got != doc.PointerWidth {
		t.Fatalf("fixture is for %d-bit pointers, this build has %d-bit", doc.PointerWidth, got)
	}

	byName := map[string]int{}
	for i, s := range doc.Structs {
		byName[s.Name] = i
	}

	mirrored := map[string]bool{}
	for _, m := range layoutMirrors {
		mirrored[m.fixture] = true
		idx, ok := byName[m.fixture]
		if !ok {
			t.Errorf("%s mirrors %s, which the fixture does not list", m.goType, m.fixture)
			continue
		}
		want := doc.Structs[idx]
		if m.goType.Size() != want.Size {
			t.Errorf("%s: Go size %d, fixture %d", m.fixture, m.goType.Size(), want.Size)
		}
		if uintptr(m.goType.Align()) != want.Align {
			t.Errorf("%s: Go align %d, fixture %d", m.fixture, m.goType.Align(), want.Align)
		}
		if m.goType.NumField() != len(m.fields) {
			t.Errorf("%s: Go struct %s has %d fields, mapping names %d", m.fixture, m.goType, m.goType.NumField(), len(m.fields))
		}
		if len(want.Fields) != len(m.fields) {
			t.Errorf("%s: fixture has %d fields, mapping names %d", m.fixture, len(want.Fields), len(m.fields))
		}
		offsets := map[string]uintptr{}
		for _, f := range want.Fields {
			offsets[f.Name] = f.Offset
		}
		for _, pair := range m.fields {
			goField, ok := m.goType.FieldByName(pair[0])
			if !ok {
				t.Errorf("%s: Go struct %s has no field %s", m.fixture, m.goType, pair[0])
				continue
			}
			wantOffset, ok := offsets[pair[1]]
			if !ok {
				t.Errorf("%s: fixture has no field %s", m.fixture, pair[1])
				continue
			}
			if goField.Offset != wantOffset {
				t.Errorf("%s.%s: Go offset %d (%s.%s), fixture %d", m.fixture, pair[1], goField.Offset, m.goType, pair[0], wantOffset)
			}
		}
	}

	for _, s := range doc.Structs {
		if mirrored[s.Name] == layoutNotMirrored[s.Name] {
			t.Errorf("fixture struct %s must be either mirrored or listed as not mirrored, not both or neither", s.Name)
		}
	}
	for name := range layoutNotMirrored {
		if _, ok := byName[name]; !ok {
			t.Errorf("layoutNotMirrored names %s, which the fixture does not list", name)
		}
	}
}

// TestEveryFFIStructIsLayoutChecked finds, in this package's sources, every
// struct shaped like one passed by value across the FFI (it holds a
// DeRecError or DeRecBuffer, or is a table of uintptr callbacks) and requires
// a layoutMirrors entry for it.
func TestEveryFFIStructIsLayoutChecked(t *testing.T) {
	checked := map[string]bool{}
	for _, m := range layoutMirrors {
		checked[m.goType.Name()] = true
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := spec.Type.(*ast.StructType)
			if !ok || len(st.Fields.List) == 0 {
				return false
			}
			ffi, allUintptr := false, true
			for _, f := range st.Fields.List {
				ident, isIdent := f.Type.(*ast.Ident)
				if !isIdent {
					allUintptr = false
					continue
				}
				if ident.Name == "DeRecError" || ident.Name == "DeRecBuffer" {
					ffi = true
				}
				if ident.Name != "uintptr" {
					allUintptr = false
				}
			}
			if (ffi || allUintptr) && !checked[spec.Name.Name] {
				t.Errorf("%s: struct %s looks FFI-passed but has no layoutMirrors entry", file, spec.Name.Name)
			}
			return false
		})
	}
}
