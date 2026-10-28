// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"google.golang.org/protobuf/proto"
)

// protocolConfigFixture reads library/tests/fixtures/protocol_config.json,
// the canonical config JSON every SDK reads.
func protocolConfigFixture(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	path := filepath.Join("..", "..", "..", "library", "tests", "fixtures", "protocol_config.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return fixture
}

func unmarshalConfig(t *testing.T, layers ...string) DeRecProtocolConfig {
	t.Helper()
	var cfg DeRecProtocolConfig
	for _, layer := range layers {
		if err := json.Unmarshal([]byte(layer), &cfg); err != nil {
			t.Fatalf("unmarshal %s: %v", layer, err)
		}
	}
	return cfg
}

func TestDeRecProtocolConfig_FullFixtureSetsEveryField(t *testing.T) {
	full := protocolConfigFixture(t)["full"]
	cfg := unmarshalConfig(t, string(full))

	want := DeRecProtocolConfig{
		Threshold:    proto.Uint32(3),
		MaxSubshares: proto.Uint64(12),
		Timeouts: &Timeouts{
			InboundMessageSecs: proto.Uint64(120),
			SharingRoundSecs:   proto.Uint64(30),
			UnpairAckSecs:      proto.Uint64(45),
			ExpiredChannels:    &RemoveExpiredChannelsPolicy{Enabled: true, TimeoutInSecs: 600},
		},
		ParameterRange: &ParameterRange{
			MinShareSize:                       1,
			MaxShareSize:                       4096,
			MinTimeBetweenVerifications:        60,
			MaxTimeBetweenVerifications:        86400,
			MinTimeBetweenShareUpdates:         60,
			MaxTimeBetweenShareUpdates:         86400,
			MinUnresponsiveDeletionTimeout:     3600,
			MaxUnresponsiveDeletionTimeout:     9007199254740993,
			MinUnresponsiveDeactivationTimeout: 3600,
			MaxUnresponsiveDeactivationTimeout: 2592000,
		},
		AutoAccept: &AutoAcceptPolicy{
			Pairing:     true,
			StoreShare:  true,
			VerifyShare: true,
			Unpair:      true,
		},
		AutoRespondOnFailure: proto.Bool(true),
		AutoReplyTo:          proto.Bool(true),
		UnpairAck:            ptr(UnpairAckNotRequired),
		UnsafeConnection:     proto.Bool(false),
		CommunicationInfo:    map[string]string{"name": "alice", "device": "laptop"},
		OwnTransports: []TransportProtocolParam{
			{URI: "https://me.example.com/derec", Protocol: int32(derecpb.Protocol_HTTPS)},
			{URI: "grpcs://me.example.com:443", Protocol: int32(derecpb.Protocol_GRPC)},
		},
		ReplicaID: proto.Uint64(9007199254740993),
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("fixture `full`:\n got  %+v\n want %+v", cfg, want)
	}

	minimal := unmarshalConfig(t, string(protocolConfigFixture(t)["minimal"]))
	if !reflect.DeepEqual(minimal, DeRecProtocolConfig{
		OwnTransports: []TransportProtocolParam{{URI: "https://me.example.com/derec", Protocol: int32(derecpb.Protocol_HTTPS)}},
	}) {
		t.Fatalf("fixture `minimal`: got %+v", minimal)
	}
}

// Marshalling writes the canonical JSON back. The one parameter_range bound
// the fixture writes as a decimal string comes back as a number, the form
// the library writes.
func TestDeRecProtocolConfig_FixturesRoundTrip(t *testing.T) {
	for name, raw := range protocolConfigFixture(t) {
		cfg := unmarshalConfig(t, string(raw))
		written, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var got, want map[string]any
		if err := json.Unmarshal(written, &got); err != nil {
			t.Fatal(err)
		}
		normalized := strings.Replace(string(raw), `"9007199254740993",`, `9007199254740993,`, 1)
		if err := json.Unmarshal([]byte(normalized), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s did not round-trip:\n got  %s\n want %s", name, written, normalized)
		}
	}
}

// Layering is one json.Unmarshal per layer: a layer sets only the keys it
// carries, the last write wins, timeouts merge per field, and every other
// nested value is replaced as a whole.
func TestDeRecProtocolConfig_LayersLastWriteWins(t *testing.T) {
	cfg := unmarshalConfig(t,
		`{"threshold": 3, "replica_id": "7", "auto_reply_to": true,
		  "timeouts": {"sharing_round_secs": 30},
		  "auto_accept": {"pairing": true, "store_share": true},
		  "communication_info": {"name": "alice"},
		  "parameter_range": {"min_share_size": 1, "max_share_size": 4096}}`,
		`{"threshold": 4, "auto_reply_to": null,
		  "timeouts": {"inbound_message_secs": 120},
		  "auto_accept": {"unpair": true},
		  "communication_info": {"device": "laptop"},
		  "parameter_range": {"max_share_size": 2048}}`,
	)

	if cfg.Threshold == nil || *cfg.Threshold != 4 {
		t.Fatalf("threshold: got %v, want the later layer's 4", cfg.Threshold)
	}
	if cfg.ReplicaID == nil || *cfg.ReplicaID != 7 {
		t.Fatalf("replica_id: an earlier layer's value must survive a layer that omits it, got %v", cfg.ReplicaID)
	}
	if cfg.AutoReplyTo == nil || !*cfg.AutoReplyTo {
		t.Fatalf("auto_reply_to: null is unset and must leave the earlier value, got %v", cfg.AutoReplyTo)
	}
	if cfg.Timeouts == nil ||
		cfg.Timeouts.SharingRoundSecs == nil || *cfg.Timeouts.SharingRoundSecs != 30 ||
		cfg.Timeouts.InboundMessageSecs == nil || *cfg.Timeouts.InboundMessageSecs != 120 ||
		cfg.Timeouts.UnpairAckSecs != nil || cfg.Timeouts.ExpiredChannels != nil {
		t.Fatalf("timeouts must merge per field, got %+v", cfg.Timeouts)
	}
	if !reflect.DeepEqual(cfg.AutoAccept, &AutoAcceptPolicy{Unpair: true}) {
		t.Fatalf("auto_accept must be replaced as a whole, got %+v", cfg.AutoAccept)
	}
	if !reflect.DeepEqual(cfg.CommunicationInfo, map[string]string{"device": "laptop"}) {
		t.Fatalf("communication_info must be replaced as a whole, got %v", cfg.CommunicationInfo)
	}
	if !reflect.DeepEqual(cfg.ParameterRange, &ParameterRange{MaxShareSize: 2048}) {
		t.Fatalf("parameter_range must be replaced as a whole, got %+v", cfg.ParameterRange)
	}
}

// Unmarshalling into Config fills its embedded DeRecProtocolConfig, and an
// assignment after the layers is one more write.
func TestDeRecProtocolConfig_ConfigEmbedsIt(t *testing.T) {
	cfg := Config{SecretID: 9}
	if err := json.Unmarshal([]byte(`{"threshold": 3}`), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SecretID != 9 || cfg.Threshold == nil || *cfg.Threshold != 3 {
		t.Fatalf("got SecretID=%d Threshold=%v", cfg.SecretID, cfg.Threshold)
	}
	cfg.Threshold = proto.Uint32(2)
	if *cfg.DeRecProtocolConfig.Threshold != 2 {
		t.Fatal("a promoted field must write the embedded config")
	}
}

// A misspelled key fails the unmarshal and names the key, at every level,
// rather than being dropped.
func TestDeRecProtocolConfig_UnknownKeysAreRefused(t *testing.T) {
	for _, tc := range []struct{ json, key string }{
		{`{"treshold": 3}`, "treshold"},
		{`{"timeouts": {"sharing_round": 30}}`, "sharing_round"},
		{`{"timeouts": {"expired_channels": {"enabled": true, "timeout": 5}}}`, "timeout"},
		{`{"auto_accept": {"pair": true}}`, "pair"},
		{`{"parameter_range": {"min_size": 1}}`, "min_size"},
		{`{"own_transports": [{"uri": "https://a.example", "protocl": "https"}]}`, "protocl"},
	} {
		var cfg DeRecProtocolConfig
		err := json.Unmarshal([]byte(tc.json), &cfg)
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Fatalf("%s: want an error naming %q, got %v", tc.json, tc.key, err)
		}
	}
}

// expired_channels needs both of its keys, as the library requires them: a
// missing one is an error naming it, never a zero value that would disable
// the sweep or set a zero timeout.
func TestDeRecProtocolConfig_ExpiredChannelsNeedsBothKeys(t *testing.T) {
	for _, tc := range []struct{ json, key string }{
		{`{"timeouts": {"expired_channels": {"timeout_in_secs": 600}}}`, "enabled"},
		{`{"timeouts": {"expired_channels": {"enabled": true}}}`, "timeout_in_secs"},
		{`{"timeouts": {"expired_channels": {}}}`, "enabled"},
		{`{"timeouts": {"expired_channels": {"enabled": null, "timeout_in_secs": 600}}}`, "enabled"},
	} {
		var cfg DeRecProtocolConfig
		err := json.Unmarshal([]byte(tc.json), &cfg)
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Fatalf("%s: want an error naming %q, got %v (config %+v)", tc.json, tc.key, err, cfg.Timeouts)
		}
	}
	cfg := unmarshalConfig(t, `{"timeouts": {"expired_channels": {"enabled": false, "timeout_in_secs": 0}}}`)
	if *cfg.Timeouts.ExpiredChannels != (RemoveExpiredChannelsPolicy{Enabled: false, TimeoutInSecs: 0}) {
		t.Fatalf("got %+v", cfg.Timeouts.ExpiredChannels)
	}
}

// A parameter_range bound is a number or a decimal string; null is refused,
// as the library refuses it, rather than read as 0.
func TestDeRecProtocolConfig_ParameterRangeBoundRefusesNull(t *testing.T) {
	var cfg DeRecProtocolConfig
	err := json.Unmarshal([]byte(`{"parameter_range": {"min_share_size": null}}`), &cfg)
	if err == nil || !strings.Contains(err.Error(), "min_share_size") {
		t.Fatalf("a null bound must be refused naming it, got %v (range %+v)", err, cfg.ParameterRange)
	}
	cfg = unmarshalConfig(t, `{"parameter_range": {"min_share_size": "5", "max_share_size": 9}}`)
	if *cfg.ParameterRange != (ParameterRange{MinShareSize: 5, MaxShareSize: 9}) {
		t.Fatalf("got %+v", cfg.ParameterRange)
	}
}

// u64 settings are decimal strings, as the library reads them.
func TestDeRecProtocolConfig_U64SettingsAreDecimalStrings(t *testing.T) {
	cfg := unmarshalConfig(t, `{"replica_id": "18446744073709551615", "max_subshares": "12"}`)
	if *cfg.ReplicaID != ^uint64(0) || *cfg.MaxSubshares != 12 {
		t.Fatalf("got replica_id=%d max_subshares=%d", *cfg.ReplicaID, *cfg.MaxSubshares)
	}
	for _, bad := range []string{`{"replica_id": 5}`, `{"max_subshares": 12}`} {
		var c DeRecProtocolConfig
		if err := json.Unmarshal([]byte(bad), &c); err == nil {
			t.Fatalf("%s: a bare number must be refused", bad)
		}
	}
}

// What New sends: an explicit zero reaches the library, an unset value is
// omitted so the library default applies, and an empty communication_info
// is omitted.
func TestDeRecProtocolConfig_MarshalSendsOnlySetFields(t *testing.T) {
	fields := func(cfg DeRecProtocolConfig) map[string]json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if got := fields(DeRecProtocolConfig{}); len(got) != 0 {
		t.Fatalf("an empty config must marshal to {}, got %v", got)
	}
	got := fields(DeRecProtocolConfig{
		Threshold: proto.Uint32(0),
		Timeouts: &Timeouts{
			SharingRoundSecs: proto.Uint64(0),
			ExpiredChannels:  &RemoveExpiredChannelsPolicy{Enabled: false, TimeoutInSecs: 900},
		},
		MaxSubshares:      proto.Uint64(^uint64(0)),
		CommunicationInfo: map[string]string{},
	})
	if string(got["threshold"]) != "0" {
		t.Fatalf("threshold: an explicit 0 must be sent, got %s", got["threshold"])
	}
	if string(got["timeouts"]) != `{"sharing_round_secs":0,"expired_channels":{"enabled":false,"timeout_in_secs":900}}` {
		t.Fatalf("timeouts: got %s", got["timeouts"])
	}
	if string(got["max_subshares"]) != `"18446744073709551615"` {
		t.Fatalf("max_subshares: got %s", got["max_subshares"])
	}
	if _, ok := got["communication_info"]; ok {
		t.Fatal("communication_info: an empty map must be omitted")
	}
}

func TestNew_BuildsFromTheFixtureConfig(t *testing.T) {
	channel, share, secret, userSecret, state, transport := newTestStores()
	cfg := Config{SecretID: 1}
	if err := json.Unmarshal(protocolConfigFixture(t)["full"], &cfg.DeRecProtocolConfig); err != nil {
		t.Fatal(err)
	}
	p, err := New(Stores{Channel: channel, Share: share, Secret: secret, UserSecret: userSecret, State: state}, transport, cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()
	if _, err := p.CreateContact(proto.Uint64(5), ContactModeInlineKeys, nil); err != nil {
		t.Fatalf("CreateContact: %v", err)
	}
}

// The library validates the layered result at New, as it validates the same
// values set field by field.
func TestNew_ValidatesTheLayeredConfig(t *testing.T) {
	build := func(layers ...string) error {
		channel, share, secret, userSecret, state, transport := newTestStores()
		cfg := Config{SecretID: 1}
		cfg.DeRecProtocolConfig = unmarshalConfig(t, append([]string{string(protocolConfigFixture(t)["minimal"])}, layers...)...)
		p, err := New(Stores{Channel: channel, Share: share, Secret: secret, UserSecret: userSecret, State: state}, transport, cfg)
		if err == nil {
			p.Close()
		}
		return err
	}
	isInvalidInput := func(err error) bool {
		var de *derec.Error
		return errors.As(err, &de) && de.Code == derec.CodeInvalidInput
	}

	if err := build(`{"threshold": 1}`, `{"threshold": 3}`); err != nil {
		t.Fatalf("the later threshold must win: %v", err)
	}
	if err := build(`{"threshold": 3}`, `{"threshold": 1}`); !isInvalidInput(err) {
		t.Fatalf("threshold 1 must be refused by the library, got %v", err)
	}
	if err := build(`{"threshold": 3}`, `{"max_subshares": "2"}`); !isInvalidInput(err) {
		t.Fatalf("an earlier threshold must survive a later layer, got %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
