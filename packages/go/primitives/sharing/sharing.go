// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package sharing wraps the DeRec sharing flow: splitting a secret into
// per-channel committed shares and exchanging store-share request/response
// messages that persist them with helpers.
package sharing

import (
	"encoding/binary"
	"fmt"

	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// ExtractedRequest is the decrypted store-share request: the channel it
// arrived on and the inner StoreShareRequestMessage proto bytes, which chain
// into response production.
type ExtractedRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

// ProducedResponse is a produced store-share response: the wire-encoded
// envelope to send back, the committed share the helper persisted, and the
// secret id/version it was persisted under.
type ProducedResponse struct {
	Envelope       []byte
	CommittedShare []byte
	SecretID       uint64
	Version        uint32
}

// ExtractedResponse is the decrypted store-share response: the channel it
// arrived on and the inner StoreShareResponseMessage proto bytes, which chain
// into Response.Process.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

type requestAPI struct{}

// Request groups the owner-side sharing operations, mirroring the Rust
// primitives::sharing::request module.
var Request requestAPI

// Split shares secretData across channelIDs using a Shamir secret-sharing
// scheme at the given threshold, returning one committed share per channel
// keyed by channel id.
func (requestAPI) Split(secretID uint64, secretData []byte, channelIDs []uint64, threshold int, version uint32) (map[uint64][]byte, error) {
	wire, err := native.ProtectSecret(secretID, secretData, channelIDs, uintptr(threshold), version)
	if err != nil {
		return nil, err
	}
	return decodeShares(wire)
}

// Produce builds the wire-encoded DeRecMessage carrying committedShare for
// storage at channelID under secretID/version, encrypted under sharedKey.
func (requestAPI) Produce(channelID uint64, version uint32, secretID uint64, committedShare []byte, keepList []uint32, description string, sharedKey []byte) ([]byte, error) {
	return native.ProduceStoreShareRequest(channelID, version, secretID, committedShare, keepList, description, sharedKey)
}

// Extract decrypts a store-share request envelope and returns its channel id
// and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, proto, err := native.ExtractStoreShareRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, RequestProto: proto}, nil
}

type responseAPI struct{}

// Response groups the helper-side sharing operations, mirroring the Rust
// primitives::sharing::response module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage acknowledging requestProto
// (the RequestProto returned by Request.Extract), encrypted under sharedKey,
// and returns the committed share the helper should persist for later
// recovery responses.
func (responseAPI) Produce(channelID uint64, requestProto, sharedKey []byte) (ProducedResponse, error) {
	wireBytes, committedShareBytes, secretID, version, err := native.ProduceStoreShareResponse(channelID, requestProto, sharedKey)
	if err != nil {
		return ProducedResponse{}, err
	}
	return ProducedResponse{
		Envelope:       wireBytes,
		CommittedShare: committedShareBytes,
		SecretID:       secretID,
		Version:        version,
	}, nil
}

// Extract decrypts a store-share response envelope and returns its channel id
// and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, proto, err := native.ExtractStoreShareResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: proto}, nil
}

// Process validates a store-share response (the ResponseProto returned by
// Response.Extract) against the expected version.
func (responseAPI) Process(version uint32, responseProto []byte) error {
	return native.ProcessStoreShareResponse(version, responseProto)
}

// decodeShares unpacks the committed-shares wire format documented at
// library/src/interop/ffi/sharing.rs into a channel id -> serialized
// CommittedDeRecShare map:
//
//	[count: u32 LE]
//	for each entry (sorted by channel ID):
//	  [channel_id: u64 LE]
//	  [share_len: u32 LE]
//	  [serialized CommittedDeRecShare protobuf]
func decodeShares(wire []byte) (map[uint64][]byte, error) {
	if len(wire) < 4 {
		return nil, fmt.Errorf("sharing: shares wire bytes too short for count: got %d bytes", len(wire))
	}
	count := binary.LittleEndian.Uint32(wire)
	offset := 4

	out := make(map[uint64][]byte, count)
	for i := uint32(0); i < count; i++ {
		if offset+8+4 > len(wire) {
			return nil, fmt.Errorf("sharing: unexpected end of shares wire bytes reading entry %d header", i)
		}
		channelID := binary.LittleEndian.Uint64(wire[offset:])
		offset += 8
		shareLen := int(binary.LittleEndian.Uint32(wire[offset:]))
		offset += 4
		if shareLen < 0 || offset+shareLen > len(wire) {
			return nil, fmt.Errorf("sharing: unexpected end of shares wire bytes reading entry %d payload", i)
		}
		shareBytes := make([]byte, shareLen)
		copy(shareBytes, wire[offset:offset+shareLen])
		offset += shareLen

		if _, exists := out[channelID]; exists {
			return nil, fmt.Errorf("sharing: duplicate channel id %d in shares wire bytes", channelID)
		}
		out[channelID] = shareBytes
	}

	if offset != len(wire) {
		return nil, fmt.Errorf("sharing: trailing bytes in shares wire bytes: offset=%d total=%d", offset, len(wire))
	}

	return out, nil
}
