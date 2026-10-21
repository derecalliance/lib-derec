// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
)

// DeRecProtocolConfig holds every data setting of a DeRecProtocol, mirroring
// the Rust DeRecProtocolConfig field for field. Config embeds it, beside the
// per-instance SecretID.
//
// Every field is optional: nil means unset, and an unset field takes the
// library default documented on it. Settings whose zero value the library
// must be able to see are pointers; build one inline with proto.Uint32 /
// proto.Uint64 / proto.Bool from google.golang.org/protobuf/proto.
//
// # Canonical JSON
//
// The json tags give the canonical config JSON shared by every DeRec SDK:
// snake_case keys, max_subshares and replica_id as decimal strings, timeouts
// as whole seconds. json.Marshal writes it and json.Unmarshal reads it; New
// sends exactly what json.Marshal writes. An unknown key, at any level, fails
// json.Unmarshal with an error naming it, so a misspelled setting is never
// silently dropped.
// Marshal and unmarshal this struct, cfg.DeRecProtocolConfig, not the
// enclosing Config: json.Marshal(cfg) also writes SecretID, which is not a key
// of the canonical JSON, so the result cannot be read back.
//
// # Layering
//
// A general config file, then a per-user record, then individual assignments
// is one json.Unmarshal per layer into the same value, then plain field
// writes:
//
//	cfg := protocol.Config{SecretID: secretID}
//	if err := json.Unmarshal(generalJSON, &cfg.DeRecProtocolConfig); err != nil { ... }
//	if err := json.Unmarshal(userRecordJSON, &cfg.DeRecProtocolConfig); err != nil { ... }
//	cfg.Threshold = proto.Uint32(4)
//
// Each json.Unmarshal assigns only the keys its JSON carries (an absent key
// or null leaves the value already held), so the last write wins, as the Rust
// with_config does. Timeouts layer per field: a later layer that sets only
// inbound_message_secs keeps the sharing_round_secs an earlier one set. Every
// other nested value is replaced as a whole.
//
// Nothing is validated here: New hands the result to the library, which
// checks it exactly as it checks the same value set field by field.
type DeRecProtocolConfig struct {
	// Threshold is the minimum number of shares required to reconstruct
	// the secret. nil uses the library default (3). Every non-nil value,
	// including 0, is forwarded as given: the library rejects a threshold
	// below 2 with a *derec.Error, because a threshold of 0 or 1 lets a
	// single helper reconstruct the secret.
	Threshold *uint32 `json:"threshold,omitempty"`

	// MaxSubshares caps the total number of subshares one sharing round may
	// split the secret into — the sum of every helper's weight. Default:
	// unset, no cap.
	//
	// Checked only by Start(ProtectSecret), including the publishes the
	// library starts itself: a round over the cap fails with
	// derec.CodeTooManySubshares before anything is sent. Recovery applies
	// no cap. Recovering costs time that grows quadratically with the total
	// number of subshares, so the cap bounds what a later recovery must do.
	// A cap below Threshold makes New return a *derec.Error
	// (CodeInvalidInput).
	MaxSubshares *uint64 `json:"max_subshares,omitempty,string"`

	// Timeouts configures how long the protocol waits on each thing that
	// can keep it waiting. nil, or a nil field inside it, leaves the
	// library's own default in force. See Timeouts.
	Timeouts *Timeouts `json:"timeouts,omitempty"`

	// ParameterRange declares the bounds this node advertises during pair
	// negotiation. Embedded in outbound PairRequest/PairResponse envelopes
	// and checked against the peer's range on inbound ones: a range that
	// fails to intersect rejects the pairing with
	// derec.CodeIncompatibleParameterRange. Default: unset — no constraints
	// advertised, every peer range accepted.
	//
	// Share size is enforced by the helper; frequency limits are enforced by
	// the app's share store (refuse from Save / RecordVerification); the
	// deletion and deactivation timeouts are checked at pairing only.
	ParameterRange *ParameterRange `json:"parameter_range,omitempty"`

	// AutoAccept is the per-flow auto-accept policy. Default: every flow
	// off.
	AutoAccept *AutoAcceptPolicy `json:"auto_accept,omitempty"`

	// AutoRespondOnFailure controls whether the protocol auto-replies on
	// failed inbound processing. Default: false.
	AutoRespondOnFailure *bool `json:"auto_respond_on_failure,omitempty"`

	// AutoReplyTo controls whether outbound requests carry an ephemeral
	// replyTo pointing at OwnTransports. Default: false.
	AutoReplyTo *bool `json:"auto_reply_to,omitempty"`

	// UnpairAck controls whether the unpair initiator waits for the
	// peer's acknowledgement. Default: UnpairAckRequired.
	UnpairAck *UnpairAck `json:"unpair_ack,omitempty"`

	// UnsafeConnection accepts plaintext http:// and grpc:// transport
	// endpoints. Development only. nil (unset) is the production posture.
	//
	// With it unset or false, plaintext is accepted only for an endpoint
	// this device configured for itself that names loopback (localhost,
	// 127.0.0.1, ::1), so a local dev server needs no configuration. With it
	// true, plaintext is accepted for any host on any path, including
	// endpoints a peer supplies — which is what makes the LAN case work (a
	// phone against a laptop), and why the name is blunt.
	//
	// This is a guardrail, not transport security: the SDK opens no sockets,
	// so nothing here stops an application sending plaintext. It governs
	// which endpoints the protocol will record, propagate and reply to.
	UnsafeConnection *bool `json:"unsafe_connection,omitempty"`

	// CommunicationInfo carries key/value pairs included in
	// pairing-request and pairing-response CommunicationInfo. Default:
	// empty.
	CommunicationInfo map[string]string `json:"communication_info,omitempty"`

	// OwnTransports is every transport endpoint this application serves,
	// in preference order. Each entry's Protocol is 0 = HTTPS
	// (derecpb.Protocol_HTTPS) or 1 = gRPC (derecpb.Protocol_GRPC).
	// Required: New returns a *derec.Error (CodeInvalidInput) when it is
	// unset or empty, since a node with no endpoint cannot be reached by any
	// peer.
	//
	// The order given is the order forwarded to the library — it is not
	// sorted, deduplicated, or reordered here. It is this application's
	// own preference and decides which of a peer's offered endpoints is
	// used. Every listed transport must actually be served, because
	// delivery is push-only: listing an endpoint this application does not
	// serve makes pairing succeed and replies vanish.
	OwnTransports []TransportProtocolParam `json:"own_transports,omitempty"`

	// ReplicaID configures this node's local replica_id, required for
	// any replica-mode pairing. Obtain it once per device from
	// derec.GenerateReplicaID, persist it, and pass the same value on
	// every init. Default: unset.
	ReplicaID *uint64 `json:"replica_id,omitempty,string"`
}

// UnmarshalJSON reads one layer of the canonical config JSON over c: each
// key the layer carries is assigned, and an absent key or null leaves c's
// value. Timeouts are assigned per field; every other nested value is
// replaced as a whole. An unknown key, at any level, is an error naming it.
func (c *DeRecProtocolConfig) UnmarshalJSON(data []byte) error {
	type fields DeRecProtocolConfig
	var layer fields
	if err := decodeStrict(data, &layer); err != nil {
		return err
	}
	if layer.Threshold != nil {
		c.Threshold = layer.Threshold
	}
	if layer.MaxSubshares != nil {
		c.MaxSubshares = layer.MaxSubshares
	}
	if t := layer.Timeouts; t != nil {
		merged := Timeouts{}
		if c.Timeouts != nil {
			merged = *c.Timeouts
		}
		if t.InboundMessageSecs != nil {
			merged.InboundMessageSecs = t.InboundMessageSecs
		}
		if t.SharingRoundSecs != nil {
			merged.SharingRoundSecs = t.SharingRoundSecs
		}
		if t.UnpairAckSecs != nil {
			merged.UnpairAckSecs = t.UnpairAckSecs
		}
		if t.ExpiredChannels != nil {
			merged.ExpiredChannels = t.ExpiredChannels
		}
		c.Timeouts = &merged
	}
	if layer.ParameterRange != nil {
		c.ParameterRange = layer.ParameterRange
	}
	if layer.AutoAccept != nil {
		c.AutoAccept = layer.AutoAccept
	}
	if layer.AutoRespondOnFailure != nil {
		c.AutoRespondOnFailure = layer.AutoRespondOnFailure
	}
	if layer.AutoReplyTo != nil {
		c.AutoReplyTo = layer.AutoReplyTo
	}
	if layer.UnpairAck != nil {
		c.UnpairAck = layer.UnpairAck
	}
	if layer.UnsafeConnection != nil {
		c.UnsafeConnection = layer.UnsafeConnection
	}
	if layer.CommunicationInfo != nil {
		c.CommunicationInfo = layer.CommunicationInfo
	}
	if layer.OwnTransports != nil {
		c.OwnTransports = layer.OwnTransports
	}
	if layer.ReplicaID != nil {
		c.ReplicaID = layer.ReplicaID
	}
	return nil
}

// decodeStrict decodes data into v, refusing a key v has no field for.
func decodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// UnmarshalJSON reads a parameter_range object. A bound may be a number or a
// decimal string, as the library reads it; an absent bound is 0 and a null
// bound is an error.
func (r *ParameterRange) UnmarshalJSON(data []byte) error {
	var w struct {
		MinShareSize                       json.RawMessage `json:"min_share_size"`
		MaxShareSize                       json.RawMessage `json:"max_share_size"`
		MinTimeBetweenVerifications        json.RawMessage `json:"min_time_between_verifications"`
		MaxTimeBetweenVerifications        json.RawMessage `json:"max_time_between_verifications"`
		MinTimeBetweenShareUpdates         json.RawMessage `json:"min_time_between_share_updates"`
		MaxTimeBetweenShareUpdates         json.RawMessage `json:"max_time_between_share_updates"`
		MinUnresponsiveDeletionTimeout     json.RawMessage `json:"min_unresponsive_deletion_timeout"`
		MaxUnresponsiveDeletionTimeout     json.RawMessage `json:"max_unresponsive_deletion_timeout"`
		MinUnresponsiveDeactivationTimeout json.RawMessage `json:"min_unresponsive_deactivation_timeout"`
		MaxUnresponsiveDeactivationTimeout json.RawMessage `json:"max_unresponsive_deactivation_timeout"`
	}
	if err := decodeStrict(data, &w); err != nil {
		return err
	}
	var out ParameterRange
	for _, b := range []struct {
		key string
		dst *int64
		src json.RawMessage
	}{
		{"min_share_size", &out.MinShareSize, w.MinShareSize},
		{"max_share_size", &out.MaxShareSize, w.MaxShareSize},
		{"min_time_between_verifications", &out.MinTimeBetweenVerifications, w.MinTimeBetweenVerifications},
		{"max_time_between_verifications", &out.MaxTimeBetweenVerifications, w.MaxTimeBetweenVerifications},
		{"min_time_between_share_updates", &out.MinTimeBetweenShareUpdates, w.MinTimeBetweenShareUpdates},
		{"max_time_between_share_updates", &out.MaxTimeBetweenShareUpdates, w.MaxTimeBetweenShareUpdates},
		{"min_unresponsive_deletion_timeout", &out.MinUnresponsiveDeletionTimeout, w.MinUnresponsiveDeletionTimeout},
		{"max_unresponsive_deletion_timeout", &out.MaxUnresponsiveDeletionTimeout, w.MaxUnresponsiveDeletionTimeout},
		{"min_unresponsive_deactivation_timeout", &out.MinUnresponsiveDeactivationTimeout, w.MinUnresponsiveDeactivationTimeout},
		{"max_unresponsive_deactivation_timeout", &out.MaxUnresponsiveDeactivationTimeout, w.MaxUnresponsiveDeactivationTimeout},
	} {
		if len(b.src) == 0 {
			continue
		}
		var n json.Number
		if string(b.src) == "null" || json.Unmarshal(b.src, &n) != nil {
			return fmt.Errorf("parameter_range.%s must be a number or a decimal string, got %s", b.key, b.src)
		}
		v, err := n.Int64()
		if err != nil {
			return fmt.Errorf("parameter_range.%s: %w", b.key, err)
		}
		*b.dst = v
	}
	*r = out
	return nil
}

// UnmarshalJSON reads an expired_channels object. Both keys are required, as
// the library requires them: a missing or null one is an error naming it.
func (p *RemoveExpiredChannelsPolicy) UnmarshalJSON(data []byte) error {
	var w struct {
		Enabled       *bool   `json:"enabled"`
		TimeoutInSecs *uint64 `json:"timeout_in_secs"`
	}
	if err := decodeStrict(data, &w); err != nil {
		return err
	}
	if w.Enabled == nil {
		return fmt.Errorf("expired_channels: missing field `enabled`")
	}
	if w.TimeoutInSecs == nil {
		return fmt.Errorf("expired_channels: missing field `timeout_in_secs`")
	}
	*p = RemoveExpiredChannelsPolicy{Enabled: *w.Enabled, TimeoutInSecs: *w.TimeoutInSecs}
	return nil
}

// unpairAckNames are the names the canonical config JSON gives UnpairAck.
var unpairAckNames = map[UnpairAck]string{
	UnpairAckRequired:    "required",
	UnpairAckNotRequired: "not_required",
}

// MarshalJSON writes an UnpairAck as its name, or as its number when it has
// none, for the library to refuse.
func (a UnpairAck) MarshalJSON() ([]byte, error) {
	if name, ok := unpairAckNames[a]; ok {
		return json.Marshal(name)
	}
	return json.Marshal(int32(a))
}

// UnmarshalJSON reads an UnpairAck from its name or its number.
func (a *UnpairAck) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		var code int32
		if err := json.Unmarshal(data, &code); err != nil {
			return fmt.Errorf("unpair_ack must be a name or a number: %s", data)
		}
		*a = UnpairAck(code)
		return nil
	}
	for value, n := range unpairAckNames {
		if n == name {
			*a = value
			return nil
		}
	}
	return fmt.Errorf("invalid unpair_ack: %q", name)
}

// MarshalJSON writes an own_transports entry, its protocol as the lowercase
// protobuf name, or as the number when it names no protocol, for the library
// to refuse.
func (t TransportProtocolParam) MarshalJSON() ([]byte, error) {
	protocol := []byte(strconv.FormatInt(int64(t.Protocol), 10))
	if name, ok := derecpb.Protocol_name[t.Protocol]; ok {
		protocol, _ = json.Marshal(strings.ToLower(name))
	}
	return json.Marshal(struct {
		URI      string          `json:"uri"`
		Protocol json.RawMessage `json:"protocol"`
	}{t.URI, protocol})
}

// UnmarshalJSON reads an own_transports entry. Its protocol is a protobuf
// name in any case ("https", "grpc") or a numeric discriminant; both uri and
// protocol are required.
func (t *TransportProtocolParam) UnmarshalJSON(data []byte) error {
	var w struct {
		URI      *string         `json:"uri"`
		Protocol json.RawMessage `json:"protocol"`
	}
	if err := decodeStrict(data, &w); err != nil {
		return err
	}
	if w.URI == nil || len(w.Protocol) == 0 {
		return fmt.Errorf("own_transports entry needs both uri and protocol: %s", data)
	}
	var name string
	if err := json.Unmarshal(w.Protocol, &name); err == nil {
		value, ok := derecpb.Protocol_value[strings.ToUpper(name)]
		if !ok {
			return fmt.Errorf("unknown transport protocol %q", name)
		}
		*t = TransportProtocolParam{URI: *w.URI, Protocol: value}
		return nil
	}
	var code int32
	if err := json.Unmarshal(w.Protocol, &code); err != nil {
		return fmt.Errorf("own_transports protocol must be a name or a number: %s", w.Protocol)
	}
	*t = TransportProtocolParam{URI: *w.URI, Protocol: code}
	return nil
}
