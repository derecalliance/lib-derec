// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"

	"github.com/ebitengine/purego"
)

type produceUnpairRequestMessageResult struct {
	Error            DeRecError
	RequestWireBytes DeRecBuffer
}

type extractUnpairRequestResult struct {
	Error             DeRecError
	ChannelID         uint64
	Memo              *byte
	RequestProtoBytes DeRecBuffer
}

type produceUnpairResponseMessageResult struct {
	Error             DeRecError
	ResponseWireBytes DeRecBuffer
}

type extractUnpairResponseResult struct {
	Error              DeRecError
	ChannelID          uint64
	ResponseProtoBytes DeRecBuffer
}

type processUnpairResponseResult struct {
	Error DeRecError
}

var (
	produceUnpairReqOnce sync.Once
	produceUnpairReqFn   func(channelID uint64,
		memo *byte, memoLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr,
		replyTo *byte, replyToLen uintptr) produceUnpairRequestMessageResult

	extractUnpairReqOnce sync.Once
	extractUnpairReqFn   func(request *byte, requestLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractUnpairRequestResult

	produceUnpairRespOnce sync.Once
	produceUnpairRespFn   func(channelID uint64,
		sharedKey *byte, sharedKeyLen uintptr) produceUnpairResponseMessageResult

	extractUnpairRespOnce sync.Once
	extractUnpairRespFn   func(response *byte, responseLen uintptr,
		sharedKey *byte, sharedKeyLen uintptr) extractUnpairResponseResult

	processUnpairRespOnce sync.Once
	processUnpairRespFn   func(responseProto *byte, responseProtoLen uintptr) processUnpairResponseResult

	freeStringOnce sync.Once
	freeStringFn   func(ptr *byte)
)

// ProduceUnpairRequest builds the wire-encoded DeRecMessage asking the peer
// on channelID to drop all state for the paired relationship, carrying memo,
// encrypted under sharedKey.
func ProduceUnpairRequest(channelID uint64, memo string, sharedKey []byte) ([]byte, error) {
	produceUnpairReqOnce.Do(func() {
		purego.RegisterFunc(&produceUnpairReqFn, symbol("produce_unpair_request_message"))
	})
	memoBytes := []byte(memo)
	res := produceUnpairReqFn(channelID,
		bytePtr(memoBytes), uintptr(len(memoBytes)),
		bytePtr(sharedKey), uintptr(len(sharedKey)),
		nil, 0)
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.RequestWireBytes), nil
}

// ExtractUnpairRequest decrypts an unpair request envelope and returns its
// channel id, memo, and inner proto bytes.
func ExtractUnpairRequest(request, sharedKey []byte) (uint64, string, []byte, error) {
	extractUnpairReqOnce.Do(func() {
		purego.RegisterFunc(&extractUnpairReqFn, symbol("extract_unpair_request"))
	})
	res := extractUnpairReqFn(bytePtr(request), uintptr(len(request)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, "", nil, err
	}
	return res.ChannelID, stringFromCString(res.Memo), bytesFromBuffer(res.RequestProtoBytes), nil
}

// ProduceUnpairResponse builds the wire-encoded DeRecMessage acknowledging
// termination of the paired relationship on channelID, encrypted under
// sharedKey.
func ProduceUnpairResponse(channelID uint64, sharedKey []byte) ([]byte, error) {
	produceUnpairRespOnce.Do(func() {
		purego.RegisterFunc(&produceUnpairRespFn, symbol("produce_unpair_response_message"))
	})
	res := produceUnpairRespFn(channelID, bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return nil, err
	}
	return bytesFromBuffer(res.ResponseWireBytes), nil
}

// ExtractUnpairResponse decrypts an unpair response envelope and returns its
// channel id and inner proto bytes.
func ExtractUnpairResponse(response, sharedKey []byte) (uint64, []byte, error) {
	extractUnpairRespOnce.Do(func() {
		purego.RegisterFunc(&extractUnpairRespFn, symbol("extract_unpair_response"))
	})
	res := extractUnpairRespFn(bytePtr(response), uintptr(len(response)),
		bytePtr(sharedKey), uintptr(len(sharedKey)))
	if err := errorFrom(res.Error); err != nil {
		return 0, nil, err
	}
	return res.ChannelID, bytesFromBuffer(res.ResponseProtoBytes), nil
}

// ProcessUnpairResponse validates an unpair response (the inner
// UnpairResponseMessage proto bytes returned by ExtractUnpairResponse),
// confirming the peer acknowledged termination of the paired relationship.
func ProcessUnpairResponse(responseProto []byte) error {
	processUnpairRespOnce.Do(func() {
		purego.RegisterFunc(&processUnpairRespFn, symbol("process_unpair_response_message"))
	})
	res := processUnpairRespFn(bytePtr(responseProto), uintptr(len(responseProto)))
	return errorFrom(res.Error)
}

// stringFromCString copies an SDK-owned NUL-terminated C string into a Go
// string and releases the original via derec_free_string. A nil pointer
// yields "".
func stringFromCString(p *byte) string {
	if p == nil {
		return ""
	}
	s := cString(p)
	freeStringOnce.Do(func() {
		purego.RegisterFunc(&freeStringFn, symbol("derec_free_string"))
	})
	freeStringFn(p)
	return s
}
