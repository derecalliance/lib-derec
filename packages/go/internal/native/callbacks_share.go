// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// shareStore mirrors protocol.ShareStore's method set over native's own
// domain types — see the storeSet doc comment in callbacks.go.
type shareStore interface {
	Load(secretID, channelID uint64, versions []uint32) ([]Share, error)
	LoadMany(secretID uint64, channelIDs []uint64, versions []uint32) ([]Share, error)
	LoadAll(secretID uint64, channelIDs []uint64) ([]Share, error)
	LatestVersion(secretID uint64) (uint32, bool, error)
	Save(secretID, channelID uint64, share Share) error
	RemoveChannel(secretID, channelID uint64) error
}

// ShareStoreCallbacks mirrors #[repr(C)] struct ShareStoreCallbacks in
// library/src/ffi/protocol/stores.rs field-for-field. channel_ids[]/
// versions[] cross the FFI as JSON-array byte buffers, matching stores.rs's
// doc comment on the struct.
type ShareStoreCallbacks struct {
	UserData      uintptr
	Load          uintptr
	LoadMany      uintptr
	LoadAll       uintptr
	LatestVersion uintptr
	Save          uintptr
	RemoveChannel uintptr
	FreeBuffer    uintptr
}

// --- Dispatch ---------------------------------------------------------------

func dispatchShareLoad(s *storeSet, secretID, channelID uint64, versionsJSON []byte) (status int32, out []byte) {
	defer recoverInto(&status)
	versions, err := DecodeUint32Array(versionsJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	shares, err := s.share.Load(secretID, channelID, versions)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeShareList(shares)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchShareLoadMany(s *storeSet, secretID uint64, channelIDsJSON, versionsJSON []byte) (status int32, out []byte) {
	defer recoverInto(&status)
	channelIDs, err := DecodeUint64Array(channelIDsJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	versions, err := DecodeUint32Array(versionsJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	shares, err := s.share.LoadMany(secretID, channelIDs, versions)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeShareList(shares)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchShareLoadAll(s *storeSet, secretID uint64, channelIDsJSON []byte) (status int32, out []byte) {
	defer recoverInto(&status)
	channelIDs, err := DecodeUint64Array(channelIDsJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	shares, err := s.share.LoadAll(secretID, channelIDs)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeShareList(shares)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchShareLatestVersion(s *storeSet, secretID uint64) (status int32, hasVersion bool, version uint32) {
	defer recoverInto(&status)
	v, ok, err := s.share.LatestVersion(secretID)
	if err != nil {
		return ffiStatusFailure, false, 0
	}
	return ffiStatusOK, ok, v
}

func dispatchShareSave(s *storeSet, secretID, channelID uint64, shareJSON []byte) (status int32) {
	defer recoverInto(&status)
	share, err := DecodeShare(shareJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.share.Save(secretID, channelID, share); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchShareRemoveChannel(s *storeSet, secretID, channelID uint64) (status int32) {
	defer recoverInto(&status)
	if err := s.share.RemoveChannel(secretID, channelID); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// --- C-facing callbacks ------------------------------------------------------

func shareLoadCallback(userData uintptr, secretID, channelID uint64, versionsPtr *byte, versionsLen uintptr, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchShareLoad(s, secretID, channelID, unsafe.Slice(versionsPtr, versionsLen))
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func shareLoadManyCallback(userData uintptr, secretID uint64, channelIDsPtr *byte, channelIDsLen uintptr, versionsPtr *byte, versionsLen uintptr, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchShareLoadMany(s, secretID, unsafe.Slice(channelIDsPtr, channelIDsLen), unsafe.Slice(versionsPtr, versionsLen))
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func shareLoadAllCallback(userData uintptr, secretID uint64, channelIDsPtr *byte, channelIDsLen uintptr, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchShareLoadAll(s, secretID, unsafe.Slice(channelIDsPtr, channelIDsLen))
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func shareLatestVersionCallback(userData uintptr, secretID uint64, outHasVersion, outVersion *uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, has, version := dispatchShareLatestVersion(s, secretID)
	if st == ffiStatusOK {
		*outHasVersion = boolToU32(has)
		*outVersion = version
	}
	return st
}

func shareSaveCallback(userData uintptr, secretID, channelID uint64, sharePtr *byte, shareLen uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchShareSave(s, secretID, channelID, unsafe.Slice(sharePtr, shareLen))
}

func shareRemoveChannelCallback(userData uintptr, secretID, channelID uint64) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchShareRemoveChannel(s, secretID, channelID)
}

// shareCallbackPtrs holds the purego.NewCallback address for every
// ShareStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). These six functions are stateless
// package-level funcs, so each needs exactly one registration total — see
// registerChannelCallbacks in callbacks_channel.go for why per-call
// registration would exhaust purego's 2000-slot callback table.
var (
	shareCallbacksOnce sync.Once
	shareCallbackPtrs  struct {
		load, loadMany, loadAll, latestVersion, save, removeChannel uintptr
	}
)

func registerShareCallbacks() {
	shareCallbacksOnce.Do(func() {
		shareCallbackPtrs.load = purego.NewCallback(shareLoadCallback)
		shareCallbackPtrs.loadMany = purego.NewCallback(shareLoadManyCallback)
		shareCallbackPtrs.loadAll = purego.NewCallback(shareLoadAllCallback)
		shareCallbackPtrs.latestVersion = purego.NewCallback(shareLatestVersionCallback)
		shareCallbackPtrs.save = purego.NewCallback(shareSaveCallback)
		shareCallbackPtrs.removeChannel = purego.NewCallback(shareRemoveChannelCallback)
	})
}

// buildShareStoreCallbacks assembles ShareStoreCallbacks for h. The
// fn-pointer fields are registered once per process (see
// registerShareCallbacks); only UserData varies per call.
func buildShareStoreCallbacks(h storeHandle) ShareStoreCallbacks {
	registerShareCallbacks()
	return ShareStoreCallbacks{
		UserData:      uintptr(h),
		Load:          shareCallbackPtrs.load,
		LoadMany:      shareCallbackPtrs.loadMany,
		LoadAll:       shareCallbackPtrs.loadAll,
		LatestVersion: shareCallbackPtrs.latestVersion,
		Save:          shareCallbackPtrs.save,
		RemoveChannel: shareCallbackPtrs.removeChannel,
		FreeBuffer:    sharedFreeBufferCallback(),
	}
}
