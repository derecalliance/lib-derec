// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// FlowKind selects which flow Start dispatches. Values match the numeric
// constants in library/src/interop/ffi/protocol/flow.rs.
type FlowKind uint32

const (
	FlowKindPairing           FlowKind = 0
	FlowKindDiscovery         FlowKind = 1
	FlowKindProtectSecret     FlowKind = 2
	FlowKindVerifyShares      FlowKind = 3
	FlowKindRecoverSecret     FlowKind = 4
	FlowKindUnpair            FlowKind = 5
	FlowKindUpdateChannelInfo FlowKind = 6
	// FlowKindReplicaDiscovery asks the replica group whether this device is behind
	// and catches up if it is. Replica-only, and takes no params.
	FlowKindReplicaDiscovery FlowKind = 7
	// FlowKindUnpairReplica removes a member from the replica group.
	// Replica-only: naming this device is a voluntary departure, naming
	// another is an eviction.
	FlowKindUnpairReplica FlowKind = 8
)

// targetKind discriminates Target's three wire shapes. The zero value
// (targetAll) is what the Target zero value carries, so an unconstructed
// Target{} is equivalent to TargetAll() — matching parse_target's
// #[serde(default)] None-means-All behavior.
type targetKind int

const (
	targetAll targetKind = iota
	targetOne
	targetMany
)

// Target selects which channels a fan-out flow (Discovery, VerifyShares,
// UpdateChannelInfo) addresses. The zero value is equivalent to TargetAll.
// Construct via TargetAll, TargetOne, or TargetMany.
type Target struct {
	kind targetKind
	ids  []uint64
}

// TargetAll addresses every paired channel.
func TargetAll() Target { return Target{kind: targetAll} }

// TargetOne addresses a single channel.
func TargetOne(channelID uint64) Target {
	return Target{kind: targetOne, ids: []uint64{channelID}}
}

// TargetMany addresses an explicit set of channels. Note this is distinct
// from TargetAll even when called with zero ids — Rust's parse_target
// resolves an empty array to zero channels, not "every channel".
func TargetMany(channelIDs ...uint64) Target {
	return Target{kind: targetMany, ids: channelIDs}
}

// MarshalJSON implements json.Marshaler, producing the wire shape
// parse_target in library/src/interop/ffi/protocol/flow.rs expects: null for
// TargetAll, a decimal-string for TargetOne, an array of decimal-strings
// for TargetMany.
func (t Target) MarshalJSON() ([]byte, error) {
	switch t.kind {
	case targetOne:
		return json.Marshal(strconv.FormatUint(t.ids[0], 10))
	case targetMany:
		strs := make([]string, len(t.ids))
		for i, id := range t.ids {
			strs[i] = strconv.FormatUint(id, 10)
		}
		return json.Marshal(strs)
	default:
		return []byte("null"), nil
	}
}

// PairingParams are the parameters for FlowKindPairing.
type PairingParams struct {
	// Kind is the local party's role in the handshake. Matches
	// derec_proto::SenderKind's numeric values — the same ones the
	// SenderKind* constants in this package hold (0=Owner, 1=Helper,
	// 3=ReplicaSource, 4=ReplicaDestination), e.g.
	// int32(SenderKindHelper).
	Kind int32
	// Contact is the prost-encoded ContactMessage received out-of-band
	// (the peer's CreatedContact.ContactBytes from CreateContact).
	Contact []byte
	// PeerCommunicationInfo is this node's communication_info to publish
	// to the peer during the handshake. Optional.
	PeerCommunicationInfo map[string]string
}

type pairingParamsWire struct {
	Kind                  int32                `json:"kind"`
	Contact               native.JSONByteArray `json:"contact"`
	PeerCommunicationInfo map[string]string    `json:"peer_communication_info,omitempty"`
}

// DiscoveryParams are the parameters for FlowKindDiscovery.
type DiscoveryParams struct {
	Target Target
}

type discoveryParamsWire struct {
	Target Target `json:"target"`
}

// ProtectSecretParams are the parameters for FlowKindProtectSecret. The
// target set is the protocol's full roster of paired Owner->Helper and
// Source->ReplicaDestination channels; it is not carried on the params.
type ProtectSecretParams struct {
	Secrets []UserSecret
	// Description is optional; nil omits it (matches the Rust side's
	// Option<String> None), a non-nil pointer — including one to an
	// empty string — sets it explicitly.
	Description *string
}

type protectSecretParamsWire struct {
	Secrets     []UserSecret `json:"secrets"`
	Description *string      `json:"description,omitempty"`
}

// VerifySharesParams are the parameters for FlowKindVerifyShares.
type VerifySharesParams struct {
	SecretID uint64
	Version  uint32
	Target   Target
}

type verifySharesParamsWire struct {
	SecretID string `json:"secret_id"`
	Version  uint32 `json:"version"`
	Target   Target `json:"target"`
}

// RecoverSecretParams are the parameters for FlowKindRecoverSecret.
type RecoverSecretParams struct {
	SecretID uint64
	Version  uint32
}

type recoverSecretParamsWire struct {
	SecretID string `json:"secret_id"`
	Version  uint32 `json:"version"`
}

// UnpairParams are the parameters for FlowKindUnpair.
type UnpairParams struct {
	ChannelID uint64
	// Memo is optional; nil omits it.
	Memo *string
}

type unpairParamsWire struct {
	ChannelID string  `json:"channel_id"`
	Memo      *string `json:"memo,omitempty"`
}

// TransportProtocolParam is the transport endpoint carried by
// UpdateChannelInfoParams.
type TransportProtocolParam struct {
	URI      string
	Protocol int32
}

// ReplicaDiscoveryParams carries nothing: the group and this device's own
// version are both read from the stores.
//
// Declared so every FlowKind has a params type, matching dotnet's
// ReplicaDiscoveryParams and the TypeScript `Record<string, never>`. Start
// also accepts nil for this flow.
type ReplicaDiscoveryParams struct{}

// UnpairReplicaParams are the parameters for FlowKindUnpairReplica.
// ReplicaID names the member being removed — this device for a voluntary
// departure, another for an eviction.
type UnpairReplicaParams struct {
	ReplicaID uint64
	Memo      *string
}

type unpairReplicaParamsWire struct {
	ReplicaID string  `json:"replica_id"`
	Memo      *string `json:"memo,omitempty"`
}

// UpdateChannelInfoParams are the parameters for FlowKindUpdateChannelInfo.
type UpdateChannelInfoParams struct {
	Target Target
	// CommunicationInfo replaces the target(s)' view of this node's
	// communication_info. nil leaves it untouched; a non-nil map
	// (including an empty one) sets it, matching the destructive-replace
	// semantics of SetCommunicationInfo.
	CommunicationInfo map[string]string
	// TransportProtocol replaces the target(s)' view of this node's
	// transport endpoint. nil leaves it untouched.
	//
	// Deprecated: superseded by OwnTransports, which carries every endpoint
	// rather than one. Scheduled for removal in v0.0.5. OwnTransports takes
	// precedence when both are set.
	TransportProtocol *TransportProtocolParam
	// OwnTransports replaces the target(s)' view of every endpoint this node
	// serves, in its own preference order. Empty leaves them untouched. The
	// first entry also fills the deprecated singular field so a peer
	// predating the list still learns the new address.
	OwnTransports []TransportProtocolParam
}

type updateChannelInfoParamsWire struct {
	Target            Target                       `json:"target"`
	CommunicationInfo *map[string]string           `json:"communication_info,omitempty"`
	TransportProtocol *transportProtocolParamWire  `json:"transport_protocol,omitempty"`
	OwnTransports     []transportProtocolParamWire `json:"own_transports,omitempty"`
}

type transportProtocolParamWire struct {
	URI      string `json:"uri"`
	Protocol int32  `json:"protocol"`
}

// marshalFlowParams validates params against flowKind and renders it into
// the JSON shape the matching decoder in library/src/interop/ffi/protocol/flow.rs
// expects.
func marshalFlowParams(flowKind FlowKind, params any) ([]byte, error) {
	switch flowKind {
	case FlowKindPairing:
		pp, ok := params.(PairingParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindPairing requires PairingParams, got %T", params)
		}
		return json.Marshal(pairingParamsWire{
			Kind:                  pp.Kind,
			Contact:               native.JSONByteArray(pp.Contact),
			PeerCommunicationInfo: pp.PeerCommunicationInfo,
		})
	case FlowKindDiscovery:
		dp, ok := params.(DiscoveryParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindDiscovery requires DiscoveryParams, got %T", params)
		}
		return json.Marshal(discoveryParamsWire{Target: dp.Target})
	case FlowKindProtectSecret:
		psp, ok := params.(ProtectSecretParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindProtectSecret requires ProtectSecretParams, got %T", params)
		}
		secrets := psp.Secrets
		if secrets == nil {
			// A nil slice with no `omitempty` marshals as JSON null, not
			// `[]` — the Rust decoder's `secrets: Vec<UserSecret>` field
			// isn't Option-wrapped, so it would reject a null. Normalize
			// to a non-nil empty slice to keep marshaling `[]`.
			secrets = []UserSecret{}
		}
		return json.Marshal(protectSecretParamsWire{
			Secrets:     secrets,
			Description: psp.Description,
		})
	case FlowKindVerifyShares:
		vsp, ok := params.(VerifySharesParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindVerifyShares requires VerifySharesParams, got %T", params)
		}
		return json.Marshal(verifySharesParamsWire{
			SecretID: strconv.FormatUint(vsp.SecretID, 10),
			Version:  vsp.Version,
			Target:   vsp.Target,
		})
	case FlowKindRecoverSecret:
		rsp, ok := params.(RecoverSecretParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindRecoverSecret requires RecoverSecretParams, got %T", params)
		}
		return json.Marshal(recoverSecretParamsWire{
			SecretID: strconv.FormatUint(rsp.SecretID, 10),
			Version:  rsp.Version,
		})
	case FlowKindUnpair:
		up, ok := params.(UnpairParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindUnpair requires UnpairParams, got %T", params)
		}
		return json.Marshal(unpairParamsWire{
			ChannelID: strconv.FormatUint(up.ChannelID, 10),
			Memo:      up.Memo,
		})
	case FlowKindUpdateChannelInfo:
		ucip, ok := params.(UpdateChannelInfoParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindUpdateChannelInfo requires UpdateChannelInfoParams, got %T", params)
		}
		w := updateChannelInfoParamsWire{Target: ucip.Target}
		if ucip.CommunicationInfo != nil {
			w.CommunicationInfo = &ucip.CommunicationInfo
		}
		if len(ucip.OwnTransports) > 0 {
			w.OwnTransports = make([]transportProtocolParamWire, len(ucip.OwnTransports))
			for i, t := range ucip.OwnTransports {
				w.OwnTransports[i] = transportProtocolParamWire{URI: t.URI, Protocol: t.Protocol}
			}
			// The first entry also fills the deprecated singular field.
			w.TransportProtocol = &w.OwnTransports[0]
		} else if ucip.TransportProtocol != nil {
			w.TransportProtocol = &transportProtocolParamWire{
				URI:      ucip.TransportProtocol.URI,
				Protocol: ucip.TransportProtocol.Protocol,
			}
		}
		return json.Marshal(w)
	case FlowKindUnpairReplica:
		rrp, ok := params.(UnpairReplicaParams)
		if !ok {
			return nil, fmt.Errorf("protocol: Start: FlowKindUnpairReplica requires UnpairReplicaParams, got %T", params)
		}
		return json.Marshal(unpairReplicaParamsWire{
			ReplicaID: strconv.FormatUint(rrp.ReplicaID, 10),
			Memo:      rrp.Memo,
		})
	case FlowKindReplicaDiscovery:
		// No parameters: the group and this device's own version both come
		// from the stores. nil is accepted for the same reason the other
		// SDKs make theirs optional.
		if params != nil {
			if _, ok := params.(ReplicaDiscoveryParams); !ok {
				return nil, fmt.Errorf("protocol: Start: FlowKindReplicaDiscovery requires ReplicaDiscoveryParams or nil, got %T", params)
			}
		}
		return json.Marshal(struct{}{})
	default:
		return nil, fmt.Errorf("protocol: Start: unknown FlowKind %d", flowKind)
	}
}

// Start kicks off flowKind with the matching params struct — PairingParams,
// DiscoveryParams, ProtectSecretParams, VerifySharesParams,
// RecoverSecretParams, UnpairParams, UpdateChannelInfoParams,
// ReplicaDiscoveryParams or UnpairReplicaParams. Passing a
// params value that doesn't match flowKind is a returned error, not a
// panic. Returns the per-target *Started / *Failed events describing what
// was dispatched.
func (p *DeRecProtocol) Start(flowKind FlowKind, params any) ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Start: protocol is closed")
	}
	paramsJSON, err := marshalFlowParams(flowKind, params)
	if err != nil {
		return nil, err
	}
	eventsJSON, err := p.instance.Start(uint32(flowKind), paramsJSON)
	if err != nil {
		return nil, err
	}
	return decodeEvents(eventsJSON)
}

// Accept accepts a pending action carried by an ActionRequired event's
// Action field, passed verbatim. Returns the events produced by resuming
// the suspended flow (e.g. PairingCompleted).
func (p *DeRecProtocol) Accept(action []byte) ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Accept: protocol is closed")
	}
	eventsJSON, err := p.instance.Accept(action)
	if err != nil {
		return nil, err
	}
	return decodeEvents(eventsJSON)
}

// Reject rejects a pending action carried by an ActionRequired event's
// Action field, with a status + memo. status matches
// derec_proto::StatusEnum.
func (p *DeRecProtocol) Reject(action []byte, status int32, memo string) error {
	if p.closed {
		return errors.New("protocol: Reject: protocol is closed")
	}
	return p.instance.Reject(action, status, memo)
}

// Restore rebuilds this protocol's secret_id namespace from a recovered
// Secret — the same typed snapshot carried by SecretRecoveredEvent.Secret
// (and ReplicaSecretReceivedEvent.Secret); pass it verbatim along with the
// version it was recovered at.
func (p *DeRecProtocol) Restore(secret Secret, version uint32) ([]Event, error) {
	if p.closed {
		return nil, errors.New("protocol: Restore: protocol is closed")
	}
	paramsJSON, err := json.Marshal(restoreParamsWire{
		Version:         version,
		RecoveredSecret: secret,
	})
	if err != nil {
		return nil, fmt.Errorf("protocol: Restore: marshal params: %w", err)
	}
	eventsJSON, err := p.instance.Restore(paramsJSON)
	if err != nil {
		return nil, err
	}
	return decodeEvents(eventsJSON)
}

// restoreParamsWire carries the version alongside Secret's own MarshalJSON
// output (see events.go) — no separate wire mirror is needed since Secret
// already encodes to the byte-array-as-number-array shape Restore's FFI
// params require.
type restoreParamsWire struct {
	Version         uint32 `json:"version"`
	RecoveredSecret Secret `json:"recovered_secret"`
}
