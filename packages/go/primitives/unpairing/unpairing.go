// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package unpairing wraps the DeRec unpairing flow, which terminates a
// paired relationship between two channel endpoints.
package unpairing

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/derecalliance/lib-derec/packages/go/derecpb"
	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// ExtractedRequest is the decrypted unpair request: the channel it arrived
// on, the channel it asks to unpair, the human-readable reason for
// termination, and the inner UnpairRequestMessage proto bytes, which chain
// into response production.
//
// UnpairChannelID equals ChannelID for an ordinary unpair and names a channel
// linked to it for a linked unpair.
type ExtractedRequest struct {
	ChannelID       uint64
	UnpairChannelID uint64
	Memo            string
	RequestProto    []byte
}

// Endpoint is a transport endpoint: a URI and the protocol discriminant that
// says how to reach it (see derecpb.Protocol: 0 = HTTPS, 1 = GRPC). It is the
// same type as pairing.Endpoint.
type Endpoint = native.Endpoint

type requestAPI struct{}

// Request groups the unpair request operations, mirroring the Rust
// primitives::unpairing::request module.
var Request requestAPI

// Produce builds the wire-encoded DeRecMessage asking the peer on channelID
// to drop all state for the paired relationship, carrying memo, encrypted
// under sharedKey.
//
// replyTo lists the endpoints, in preference order, the peer should answer
// on; nil or empty means answer on the endpoints recorded for the channel.
//
// epoch is the epoch of sharedKey in the channel's key chain, stamped into
// the envelope's sequence; 0 for a freshly paired channel.
//
// unpairChannelID is the channel to unpair: channelID for an ordinary
// unpair, or a channel linked to it for a linked unpair, where the request
// travels on channelID and asks the peer to unpair the linked channel.
func (requestAPI) Produce(channelID uint64, memo string, sharedKey []byte, epoch uint32, replyTo []Endpoint, unpairChannelID uint64) ([]byte, error) {
	return native.ProduceUnpairRequest(channelID, memo, sharedKey, epoch, replyTo, unpairChannelID)
}

// Extract decrypts an unpair request envelope and returns its channel id,
// the channel it asks to unpair, memo, and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, memo, requestProto, err := native.ExtractUnpairRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	var inner derecpb.UnpairRequestMessage
	if err := proto.Unmarshal(requestProto, &inner); err != nil {
		return ExtractedRequest{}, fmt.Errorf("unpairing: Request.Extract: decode request: %w", err)
	}
	return ExtractedRequest{
		ChannelID:       channelID,
		UnpairChannelID: inner.GetChannelId(),
		Memo:            memo,
		RequestProto:    requestProto,
	}, nil
}

// ExtractedResponse is the decrypted unpair response: the channel it arrived
// on, the channel the request named (echoed back), and the inner
// UnpairResponseMessage proto bytes, which chain into Response.Process.
type ExtractedResponse struct {
	ChannelID       uint64
	UnpairChannelID uint64
	ResponseProto   []byte
}

type responseAPI struct{}

// Response groups the unpair response operations, mirroring the Rust
// primitives::unpairing::response module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage, sent on channelID,
// acknowledging termination of the paired relationship, encrypted under
// sharedKey.
//
// epoch is the epoch of sharedKey in the channel's key chain, stamped into
// the envelope's sequence; 0 for a freshly paired channel.
//
// unpairChannelID is the channel the request named (its UnpairChannelID),
// which the answer names back: channelID for an ordinary unpair, the linked
// channel for a linked unpair.
func (responseAPI) Produce(channelID uint64, sharedKey []byte, epoch uint32, unpairChannelID uint64) ([]byte, error) {
	return native.ProduceUnpairResponse(channelID, sharedKey, epoch, unpairChannelID)
}

// Extract decrypts an unpair response envelope and returns its channel id,
// the channel it names, and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, responseProto, err := native.ExtractUnpairResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	var inner derecpb.UnpairResponseMessage
	if err := proto.Unmarshal(responseProto, &inner); err != nil {
		return ExtractedResponse{}, fmt.Errorf("unpairing: Response.Extract: decode response: %w", err)
	}
	return ExtractedResponse{
		ChannelID:       channelID,
		UnpairChannelID: inner.GetChannelId(),
		ResponseProto:   responseProto,
	}, nil
}

// Process validates an unpair response (the ResponseProto returned by
// Response.Extract), confirming the peer acknowledged termination of the
// paired relationship.
func (responseAPI) Process(responseProto []byte) error {
	return native.ProcessUnpairResponse(responseProto)
}
