// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type protectSecretResult struct {
	Error           DeRecError
	SharesWireBytes DeRecBuffer
}

type produceStoreShareRequestMessageResult struct {
	Error     DeRecError
	WireBytes DeRecBuffer
}

type extractStoreShareRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	RequestProtoBytes DeRecBuffer
}

type produceStoreShareResponseMessageResult struct {
	Error               DeRecError
	WireBytes           DeRecBuffer
	CommittedShareBytes DeRecBuffer
	SecretID            uint64
	Version             uint32
}

type extractStoreShareResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type processStoreShareResponseMessageResult struct {
	Error DeRecError
}

var (
	protectSecretOnce sync.Once
	protectSecretFn   func(secretID uint64,
		secretData *byte, secretDataLen uintptr,
		channels *uint64, channelsLen uintptr,
		threshold uintptr, version uint32) protectSecretResult

	produceStoreShareReqOnce sync.Once
	produceStoreShareReqFn   func(channelID uint64, version uint32, secretID uint64,
		committedShare *byte, committedShareLen uintptr,
		keepList *uint32, keepListLen uintptr,
		description *byte, descriptionLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr,
		replyTo *byte, replyToLen uintptr,
		hasReplicaID uint32, replicaID uint64) produceStoreShareRequestMessageResult

	extractStoreShareReqOnce sync.Once
	extractStoreShareReqFn   func(request *byte, requestLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractStoreShareRequestResult

	produceStoreShareRespOnce sync.Once
	produceStoreShareRespFn   func(channelID uint64,
		requestProto *byte, requestProtoLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) produceStoreShareResponseMessageResult

	extractStoreShareRespOnce sync.Once
	extractStoreShareRespFn   func(response *byte, responseLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractStoreShareResponseResult

	processStoreShareRespOnce sync.Once
	processStoreShareRespFn   func(version uint32,
		responseProto *byte, responseProtoLen uintptr) processStoreShareResponseMessageResult
)

// u64Ptr returns the address of the first element of s, or nil for an empty
// slice, mirroring bytePtr for []uint64 FFI array arguments.
func u64Ptr(s []uint64) *uint64 {
	if len(s) == 0 {
		return nil
	}
	return &s[0]
}

// u32Ptr returns the address of the first element of s, or nil for an empty
// slice, mirroring bytePtr for []uint32 FFI array arguments.
func u32Ptr(s []uint32) *uint32 {
	if len(s) == 0 {
		return nil
	}
	return &s[0]
}

// ProtectSecret splits secretData across channelIDs at the given threshold,
// returning the committed shares in the wire format documented at
// library/src/interop/ffi/sharing.rs: a length-prefixed sequence of (channel_id,
// serialized CommittedDeRecShare) entries sorted by channel id.
func ProtectSecret(secretID uint64, secretData []byte, channelIDs []uint64, threshold uintptr, version uint32) ([]byte, error) {
	protectSecretOnce.Do(func() {
		purego.RegisterFunc(&protectSecretFn, symbol("protect_secret"))
	})
	res := protectSecretFn(secretID,
		bytePtr(secretData), uintptr(len(secretData)),
		u64Ptr(channelIDs), uintptr(len(channelIDs)),
		threshold, version)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.SharesWireBytes), nil
}

// ProduceStoreShareRequest builds the wire-encoded DeRecMessage carrying
// committedShare for storage at channelID, encrypted under sharedKey.
func ProduceStoreShareRequest(channelID uint64, version uint32, secretID uint64, committedShare []byte, keepList []uint32, description string, sharedKey []byte) ([]byte, error) {
	produceStoreShareReqOnce.Do(func() {
		purego.RegisterFunc(&produceStoreShareReqFn, symbol("produce_store_share_request_message"))
	})
	descriptionBytes := []byte(description)
	res := produceStoreShareReqFn(channelID, version, secretID,
		bytePtr(committedShare), uintptr(len(committedShare)),
		u32Ptr(keepList), uintptr(len(keepList)),
		bytePtr(descriptionBytes), uintptr(len(descriptionBytes)),
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		nil, 0,
		0, 0)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.WireBytes), nil
}

// ExtractStoreShareRequest decrypts a store-share request envelope and
// returns its channel id and inner proto bytes.
func ExtractStoreShareRequest(request, sharedKey []byte) (uint64, []byte, error) {
	extractStoreShareReqOnce.Do(func() {
		purego.RegisterFunc(&extractStoreShareReqFn, symbol("extract_store_share_request"))
	})
	res := extractStoreShareReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProduceStoreShareResponse builds the wire-encoded DeRecMessage acknowledging
// requestProto (the inner StoreShareRequestMessage proto bytes returned by
// ExtractStoreShareRequest), encrypted under sharedKey. It also returns the
// committed share the helper should persist for later recovery responses.
func ProduceStoreShareResponse(channelID uint64, requestProto, sharedKey []byte) (wireBytes, committedShareBytes []byte, secretID uint64, version uint32, err error) {
	produceStoreShareRespOnce.Do(func() {
		purego.RegisterFunc(&produceStoreShareRespFn, symbol("produce_store_share_response_message"))
	})
	res := produceStoreShareRespFn(channelID,
		bytePtr(requestProto), uintptr(len(requestProto)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if e := errorFrom(res.Error); e != nil {
		return nil, nil, 0, 0, e
	}
	return bytesFromBuffer(res.WireBytes), bytesFromBuffer(res.CommittedShareBytes), res.SecretID, res.Version, nil
}

// ExtractStoreShareResponse decrypts a store-share response envelope and
// returns its channel id and inner proto bytes.
func ExtractStoreShareResponse(response, sharedKey []byte) (uint64, []byte, error) {
	extractStoreShareRespOnce.Do(func() {
		purego.RegisterFunc(&extractStoreShareRespFn, symbol("extract_store_share_response"))
	})
	res := extractStoreShareRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessStoreShareResponse validates a store-share response (the inner
// StoreShareResponseMessage proto bytes returned by
// ExtractStoreShareResponse) against the expected version.
func ProcessStoreShareResponse(version uint32, responseProto []byte) error {
	processStoreShareRespOnce.Do(func() {
		purego.RegisterFunc(&processStoreShareRespFn, symbol("process_store_share_response_message"))
	})
	res := processStoreShareRespFn(version, bytePtr(responseProto), uintptr(len(responseProto)))
	if err := errorFrom(res.Error); err != nil {
		return err
	}
	return nil
}
