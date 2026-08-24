// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package discovery wraps the DeRec discovery flow: an owner asking a helper
// which secret ids/versions it holds.
package discovery

import (
	"encoding/binary"
	"fmt"

	"github.com/derecalliance/lib-derec/packages/go/internal/native"
)

// VersionEntry is one advertised version of a secret.
type VersionEntry struct {
	Version     uint32
	Description string
}

// SecretVersionEntry is the set of versions a helper advertises for one
// secret id.
type SecretVersionEntry struct {
	SecretID uint64
	Versions []VersionEntry
}

// ExtractedRequest is the decrypted discovery request: the channel it arrived
// on and the inner GetSecretIdsVersionsRequestMessage proto bytes.
type ExtractedRequest struct {
	ChannelID    uint64
	RequestProto []byte
}

type requestAPI struct{}

// Request groups the owner-side discovery operations, mirroring the Rust
// primitives::discovery::request module.
var Request requestAPI

// Produce builds the wire-encoded DeRecMessage carrying a discovery request
// on channelID, encrypted under sharedKey.
func (requestAPI) Produce(channelID uint64, sharedKey []byte) ([]byte, error) {
	return native.ProduceGetSecretIdsVersionsRequest(channelID, sharedKey)
}

// Extract decrypts a discovery request envelope and returns its channel id
// and inner proto bytes.
func (requestAPI) Extract(request, sharedKey []byte) (ExtractedRequest, error) {
	channelID, proto, err := native.ExtractGetSecretIdsVersionsRequest(request, sharedKey)
	if err != nil {
		return ExtractedRequest{}, err
	}
	return ExtractedRequest{ChannelID: channelID, RequestProto: proto}, nil
}

// ExtractedResponse is the decrypted discovery response: the channel it
// arrived on and the inner GetSecretIdsVersionsResponseMessage proto bytes,
// which chain into Response.Process.
type ExtractedResponse struct {
	ChannelID     uint64
	ResponseProto []byte
}

type responseAPI struct{}

// Response groups the helper-side discovery operations, mirroring the Rust
// primitives::discovery::response module.
var Response responseAPI

// Produce builds the wire-encoded DeRecMessage advertising secretList on
// channelID, encrypted under sharedKey.
func (responseAPI) Produce(channelID uint64, secretList []SecretVersionEntry, sharedKey []byte) ([]byte, error) {
	return native.ProduceGetSecretIdsVersionsResponse(channelID, encodeSecretList(secretList), sharedKey)
}

// Extract decrypts a discovery response envelope and returns its channel id
// and inner proto bytes.
func (responseAPI) Extract(response, sharedKey []byte) (ExtractedResponse, error) {
	channelID, proto, err := native.ExtractGetSecretIdsVersionsResponse(response, sharedKey)
	if err != nil {
		return ExtractedResponse{}, err
	}
	return ExtractedResponse{ChannelID: channelID, ResponseProto: proto}, nil
}

// Process validates a discovery response (the ResponseProto returned by
// Response.Extract) and returns the advertised secret-id/version set.
func (responseAPI) Process(responseProto []byte) ([]SecretVersionEntry, error) {
	wire, err := native.ProcessGetSecretIdsVersionsResponse(responseProto)
	if err != nil {
		return nil, err
	}
	return decodeSecretList(wire)
}

// encodeSecretList packs entries into the secret-list binary format
// documented at library/src/ffi/discovery.rs:
//
//	[count: u32 LE]
//	for each entry:
//	  [secret_id: u64 LE]
//	  [versions_count: u32 LE]
//	  for each version:
//	    [version: u32 LE]
//	    [description_len: u32 LE]
//	    [description: UTF-8 bytes]
//	    [has_replica_id: u8]
//	    [replica_id: u64 LE]  (present only when has_replica_id != 0)
func encodeSecretList(entries []SecretVersionEntry) []byte {
	out := make([]byte, 0)
	out = appendUint32(out, uint32(len(entries)))
	for _, entry := range entries {
		out = appendUint64(out, entry.SecretID)
		out = appendUint32(out, uint32(len(entry.Versions)))
		for _, v := range entry.Versions {
			out = appendUint32(out, v.Version)
			descBytes := []byte(v.Description)
			out = appendUint32(out, uint32(len(descBytes)))
			out = append(out, descBytes...)
		}
	}
	return out
}

// decodeSecretList unpacks the secret-list binary format documented at
// library/src/ffi/discovery.rs; see encodeSecretList for the layout.
func decodeSecretList(wire []byte) ([]SecretVersionEntry, error) {
	if len(wire) < 4 {
		return nil, fmt.Errorf("discovery: secret list wire bytes too short for count: got %d bytes", len(wire))
	}
	count := binary.LittleEndian.Uint32(wire)
	offset := 4

	entries := make([]SecretVersionEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		if offset+8+4 > len(wire) {
			return nil, fmt.Errorf("discovery: unexpected end of secret list wire bytes reading entry %d header", i)
		}
		secretID := binary.LittleEndian.Uint64(wire[offset:])
		offset += 8
		versionsCount := binary.LittleEndian.Uint32(wire[offset:])
		offset += 4

		versions := make([]VersionEntry, 0, versionsCount)
		for j := uint32(0); j < versionsCount; j++ {
			if offset+4+4 > len(wire) {
				return nil, fmt.Errorf("discovery: unexpected end of secret list wire bytes reading entry %d version %d header", i, j)
			}
			version := binary.LittleEndian.Uint32(wire[offset:])
			offset += 4
			descLen := int(binary.LittleEndian.Uint32(wire[offset:]))
			offset += 4
			if descLen < 0 || offset+descLen > len(wire) {
				return nil, fmt.Errorf("discovery: unexpected end of secret list wire bytes reading entry %d version %d description", i, j)
			}
			description := string(wire[offset : offset+descLen])
			offset += descLen

			versions = append(versions, VersionEntry{
				Version:     version,
				Description: description,
			})
		}

		entries = append(entries, SecretVersionEntry{
			SecretID: secretID,
			Versions: versions,
		})
	}

	if offset != len(wire) {
		return nil, fmt.Errorf("discovery: trailing bytes in secret list wire bytes: offset=%d total=%d", offset, len(wire))
	}

	return entries, nil
}

func appendUint32(out []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(out, buf[:]...)
}

func appendUint64(out []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(out, buf[:]...)
}
