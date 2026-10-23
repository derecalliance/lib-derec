// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"errors"
	"fmt"
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
	RemoveVersions(secretID, channelID uint64, versions []uint32) error
	KeepList(secretID uint64, version uint32) ([]uint32, bool, error)
	RecordVerification(secretID, channelID uint64, version uint32) error
}

// ShareStoreCallbacks mirrors #[repr(C)] struct ShareStoreCallbacks in
// library/src/interop/ffi/protocol/stores.rs field-for-field. channel_ids[]/
// versions[] cross the FFI as JSON-array byte buffers, matching stores.rs's
// doc comment on the struct. RecordVerification sits after KeepList and
// before FreeBuffer, matching the Rust struct's field order exactly — a
// different position here is a runtime crash, not a compile error.
type ShareStoreCallbacks struct {
	UserData           uintptr
	Load               uintptr
	LoadMany           uintptr
	LoadAll            uintptr
	LatestVersion      uintptr
	Save               uintptr
	RemoveChannel      uintptr
	RemoveVersions     uintptr
	KeepList           uintptr
	RecordVerification uintptr
	FreeBuffer         uintptr
}

// ShareStoreRefusal is the reason a ShareStoreRefusedError refuses a
// ShareStore.Save or ShareStore.RecordVerification call. Declared here —
// not in package derec, which already imports this package, nor in package
// protocol, which imports both — so every Go SDK layer can reference one
// definition without a dependency cycle; mirrors why Error is declared in
// error.go instead of package derec. derec and protocol each alias this
// type rather than redeclaring it.
type ShareStoreRefusal int32

const (
	// RefusalTooFrequent refuses a share update or verification that
	// arrived before the application's own frequency policy allows.
	RefusalTooFrequent ShareStoreRefusal = iota
	// RefusalSizeLimitExceeded refuses a share update whose size the
	// application's own store rejects, independent of the library's
	// own ParameterRange check on StoreShareRequest.
	RefusalSizeLimitExceeded
	// RefusalRejected refuses the call for any other application-chosen
	// reason.
	RefusalRejected
)

// String names the way r appears in log/error output. Branch on the
// Refusal field itself, never this string.
func (r ShareStoreRefusal) String() string {
	switch r {
	case RefusalTooFrequent:
		return "too_frequent"
	case RefusalSizeLimitExceeded:
		return "size_limit_exceeded"
	case RefusalRejected:
		return "rejected"
	default:
		return fmt.Sprintf("unknown(%d)", int32(r))
	}
}

// ffiCode maps r to the FFI return code documented on
// ShareStoreCallbacks.Save/RecordVerification in stores.rs — the
// StatusEnum numbers DEREC_SHARE_STORE_REFUSED_SIZE_LIMIT_EXCEEDED/
// _TOO_FREQUENT/_REJECTED name in library/src/interop/ffi/error.rs. The
// library chooses the wire status from this code; the application only
// chose the reason via Refusal.
func (r ShareStoreRefusal) ffiCode() int32 {
	switch r {
	case RefusalSizeLimitExceeded:
		return 3
	case RefusalTooFrequent:
		return 4
	case RefusalRejected:
		return 10
	default:
		return ffiStatusFailure
	}
}

// ShareStoreRefusedError is returned from ShareStore.Save or
// ShareStore.RecordVerification to refuse the write or verification with
// Refusal. dispatchShareSave/dispatchShareRecordVerification turn this into
// the matching protocol status answered to the owner, rather than treating
// it as a backend failure; any other error is an ordinary backend failure.
type ShareStoreRefusedError struct {
	Refusal ShareStoreRefusal
}

// Error implements the error interface.
func (e *ShareStoreRefusedError) Error() string {
	return fmt.Sprintf("derec: share store refused: %s", e.Refusal)
}

// shareRefusalCode extracts the FFI return code from err via errors.As,
// when err (or something it wraps) is a *ShareStoreRefusedError. ok is
// false for a plain backend error, which the caller answers with the
// existing failure code instead.
func shareRefusalCode(err error) (code int32, ok bool) {
	var refused *ShareStoreRefusedError
	if errors.As(err, &refused) {
		return refused.Refusal.ffiCode(), true
	}
	return 0, false
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
		if code, ok := shareRefusalCode(err); ok {
			return code
		}
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// dispatchShareRecordVerification is called once per accepted verification
// challenge, after the challenged share is found and before the helper
// answers — see DeRecShareStore::record_verification on the Rust side. A
// *ShareStoreRefusedError from the application's store refuses the
// verification with the matching protocol status; any other error is an
// ordinary backend failure.
func dispatchShareRecordVerification(s *storeSet, secretID, channelID uint64, version uint32) (status int32) {
	defer recoverInto(&status)
	if err := s.share.RecordVerification(secretID, channelID, version); err != nil {
		if code, ok := shareRefusalCode(err); ok {
			return code
		}
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

func dispatchShareRemoveVersions(s *storeSet, secretID, channelID uint64, versionsJSON []byte) (status int32) {
	defer recoverInto(&status)
	versions, err := DecodeUint32Array(versionsJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.share.RemoveVersions(secretID, channelID, versions); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchShareKeepList(s *storeSet, secretID uint64, version uint32) (status int32, out []byte) {
	defer recoverInto(&status)
	versions, ok, err := s.share.KeepList(secretID, version)
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusOK, []byte("null")
	}
	encoded, err := EncodeUint32Array(versions)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
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

func shareRemoveVersionsCallback(userData uintptr, secretID, channelID uint64, versionsPtr *byte, versionsLen uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchShareRemoveVersions(s, secretID, channelID, unsafe.Slice(versionsPtr, versionsLen))
}

func shareKeepListCallback(userData uintptr, secretID uint64, version uint32, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchShareKeepList(s, secretID, version)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func shareRecordVerificationCallback(userData uintptr, secretID, channelID uint64, version uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchShareRecordVerification(s, secretID, channelID, version)
}

// shareCallbackPtrs holds the purego.NewCallback address for every
// ShareStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). These nine functions are stateless
// package-level funcs, so each needs exactly one registration total — see
// registerChannelCallbacks in callbacks_channel.go for why per-call
// registration would exhaust purego's 2000-slot callback table.
var (
	shareCallbacksOnce sync.Once
	shareCallbackPtrs  struct {
		load, loadMany, loadAll, latestVersion, save, removeChannel, removeVersions, keepList, recordVerification uintptr
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
		shareCallbackPtrs.removeVersions = purego.NewCallback(shareRemoveVersionsCallback)
		shareCallbackPtrs.keepList = purego.NewCallback(shareKeepListCallback)
		shareCallbackPtrs.recordVerification = purego.NewCallback(shareRecordVerificationCallback)
	})
}

// buildShareStoreCallbacks assembles ShareStoreCallbacks for h. The
// fn-pointer fields are registered once per process (see
// registerShareCallbacks); only UserData varies per call.
func buildShareStoreCallbacks(h storeHandle) ShareStoreCallbacks {
	registerShareCallbacks()
	return ShareStoreCallbacks{
		UserData:           uintptr(h),
		Load:               shareCallbackPtrs.load,
		LoadMany:           shareCallbackPtrs.loadMany,
		LoadAll:            shareCallbackPtrs.loadAll,
		LatestVersion:      shareCallbackPtrs.latestVersion,
		Save:               shareCallbackPtrs.save,
		RemoveChannel:      shareCallbackPtrs.removeChannel,
		RemoveVersions:     shareCallbackPtrs.removeVersions,
		KeepList:           shareCallbackPtrs.keepList,
		RecordVerification: shareCallbackPtrs.recordVerification,
		FreeBuffer:         sharedFreeBufferCallback(),
	}
}
