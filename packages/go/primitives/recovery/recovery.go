// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package recovery wraps the DeRec recovery flow: requesting a helper's
// stored share and reconstructing the original secret from a threshold of
// get-share responses.
package recovery

import (
	"encoding/binary"

	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// ExtractedRequest is the decrypted get-share request: the channel it arrived
// on and the inner GetShareRequestMessage proto bytes, which chain into
// response production.
type ExtractedRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

// ExtractedResponse is the decrypted get-share response: the channel it
// arrived on and the inner GetShareResponseMessage proto bytes.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

// ShareResponse is a helper's get-share response envelope together with the
// shared key under which it was encrypted, as collected by the owner from
// each helper contacted during recovery.
type ShareResponse struct {
	Response  []byte
	SharedKey []byte
}

type requestAPI struct{}

// Request groups the owner-side get-share operations, mirroring the Rust
// primitives::recovery::request module.
var Request requestAPI

// Produce builds the wire-encoded DeRecMessage requesting the helper's stored
// share for (secretID, version) on channelID, encrypted under sharedKey.
func (requestAPI) Produce(channelID, secretID uint64, version uint32, sharedKey []byte) ([]byte, error) {
	return native.ProduceGetShareRequest(channelID, secretID, version, sharedKey)
}

// Extract decrypts a get-share request envelope and returns its channel id
// and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, proto, err := native.ExtractGetShareRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, RequestProto: proto}, nil
}

type responseAPI struct{}

// Response groups the helper-side get-share operations and the owner-side
// secret reconstruction, mirroring the Rust primitives::recovery::response
// module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage answering requestProto (the
// RequestProto returned by Request.Extract) with the helper's
// storedShareProto (the RequestProto returned by sharing's
// Request.Extract at storage time), encrypted under sharedKey.
func (responseAPI) Produce(channelID uint64, requestProto, storedShareProto, sharedKey []byte) ([]byte, error) {
	return native.ProduceGetShareResponse(channelID, requestProto, storedShareProto, sharedKey)
}

// Extract decrypts a get-share response envelope and returns its channel id
// and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, proto, err := native.ExtractGetShareResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: proto}, nil
}

// Recover decrypts each response in responses under its paired shared key and
// reconstructs the secret stored under secretID/version from the resulting
// set of GetShareResponseMessage protos. All responses must agree on the same
// Merkle root and ciphertext; fewer than the sharing threshold, or an
// inconsistent set, is reported as an error.
func (responseAPI) Recover(responses []ShareResponse, secretID uint64, version uint32) ([]byte, error) {
	protoList := make([][]byte, 0, len(responses))
	for _, r := range responses {
		_, proto, err := native.ExtractGetShareResponse(r.Response, r.SharedKey)
		if err != nil {
			return nil, err
		}
		protoList = append(protoList, proto)
	}
	return native.RecoverFromShareResponses(encodeResponsesSet(protoList), secretID, version)
}

// encodeResponsesSet packs decrypted GetShareResponseMessage proto bytes into
// the responses binary format documented at library/src/ffi/recovery.rs:
//
//	[count: u32 LE]
//	for each entry:
//	  [response_len: u32 LE]
//	  [serialized GetShareResponseMessage]
func encodeResponsesSet(protoList [][]byte) []byte {
	total := 4
	for _, p := range protoList {
		total += 4 + len(p)
	}
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf, uint32(len(protoList)))
	offset := 4
	for _, p := range protoList {
		binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p)))
		offset += 4
		copy(buf[offset:], p)
		offset += len(p)
	}
	return buf
}
