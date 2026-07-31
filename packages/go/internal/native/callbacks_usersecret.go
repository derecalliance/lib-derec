// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// userSecretStore mirrors protocol.UserSecretStore's method set over
// native's own domain types — see the storeSet doc comment in
// callbacks.go.
type userSecretStore interface {
	LoadLatest(secretID uint64) (UserSecrets, bool, error)
	SaveLatest(secretID uint64, value UserSecrets) error
	Remove(secretID uint64) error
}

// UserSecretStoreCallbacks mirrors #[repr(C)] struct
// UserSecretStoreCallbacks in library/src/ffi/protocol/stores.rs
// field-for-field.
type UserSecretStoreCallbacks struct {
	UserData   uintptr
	LoadLatest uintptr
	SaveLatest uintptr
	Remove     uintptr
	FreeBuffer uintptr
}

// --- Dispatch ---------------------------------------------------------------

func dispatchUserSecretLoadLatest(s *storeSet, secretID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	v, ok, err := s.userSecret.LoadLatest(secretID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusNotFound, nil
	}
	encoded, err := EncodeUserSecrets(v)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchUserSecretSaveLatest(s *storeSet, secretID uint64, valueJSON []byte) (status int32) {
	defer recoverInto(&status)
	v, err := DecodeUserSecrets(valueJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.userSecret.SaveLatest(secretID, v); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchUserSecretRemove(s *storeSet, secretID uint64) (status int32) {
	defer recoverInto(&status)
	if err := s.userSecret.Remove(secretID); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// --- C-facing callbacks ------------------------------------------------------

func userSecretLoadLatestCallback(userData uintptr, secretID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchUserSecretLoadLatest(s, secretID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func userSecretSaveLatestCallback(userData uintptr, secretID uint64, valuePtr *byte, valueLen uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchUserSecretSaveLatest(s, secretID, unsafe.Slice(valuePtr, valueLen))
}

func userSecretRemoveCallback(userData uintptr, secretID uint64) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchUserSecretRemove(s, secretID)
}

// userSecretCallbackPtrs holds the purego.NewCallback address for every
// UserSecretStoreCallbacks fn-pointer field except FreeBuffer (shared
// package-wide via sharedFreeBufferCallback). These three functions are
// stateless package-level funcs, so each needs exactly one registration
// total — see registerChannelCallbacks in callbacks_channel.go for why
// per-call registration would exhaust purego's 2000-slot callback table.
var (
	userSecretCallbacksOnce sync.Once
	userSecretCallbackPtrs  struct {
		loadLatest, saveLatest, remove uintptr
	}
)

func registerUserSecretCallbacks() {
	userSecretCallbacksOnce.Do(func() {
		userSecretCallbackPtrs.loadLatest = purego.NewCallback(userSecretLoadLatestCallback)
		userSecretCallbackPtrs.saveLatest = purego.NewCallback(userSecretSaveLatestCallback)
		userSecretCallbackPtrs.remove = purego.NewCallback(userSecretRemoveCallback)
	})
}

// buildUserSecretStoreCallbacks assembles UserSecretStoreCallbacks for h.
// The fn-pointer fields are registered once per process (see
// registerUserSecretCallbacks); only UserData varies per call.
func buildUserSecretStoreCallbacks(h storeHandle) UserSecretStoreCallbacks {
	registerUserSecretCallbacks()
	return UserSecretStoreCallbacks{
		UserData:   uintptr(h),
		LoadLatest: userSecretCallbackPtrs.loadLatest,
		SaveLatest: userSecretCallbackPtrs.saveLatest,
		Remove:     userSecretCallbackPtrs.remove,
		FreeBuffer: sharedFreeBufferCallback(),
	}
}
