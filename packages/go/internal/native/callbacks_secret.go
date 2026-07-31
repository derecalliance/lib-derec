// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// secretStore mirrors protocol.SecretStore's method set over native's own
// domain types — see the storeSet doc comment in callbacks.go.
type secretStore interface {
	Load(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error)
	Save(secretID, channelID uint64, value SecretValue) error
	Remove(secretID, channelID uint64, kind SecretKind) error
}

// SecretStoreCallbacks mirrors #[repr(C)] struct SecretStoreCallbacks in
// library/src/ffi/protocol/stores.rs field-for-field.
type SecretStoreCallbacks struct {
	UserData   uintptr
	Load       uintptr
	Save       uintptr
	Remove     uintptr
	FreeBuffer uintptr
}

// --- Dispatch ---------------------------------------------------------------

func dispatchSecretLoad(s *storeSet, secretID, channelID uint64, kind uint32) (status int32, out []byte) {
	defer recoverInto(&status)
	v, ok, err := s.secret.Load(secretID, channelID, SecretKind(kind))
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusNotFound, nil
	}
	encoded, err := EncodeSecretValue(v)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchSecretSave(s *storeSet, secretID, channelID uint64, valueJSON []byte) (status int32) {
	defer recoverInto(&status)
	v, err := DecodeSecretValue(valueJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.secret.Save(secretID, channelID, v); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchSecretRemove(s *storeSet, secretID, channelID uint64, kind uint32) (status int32) {
	defer recoverInto(&status)
	if err := s.secret.Remove(secretID, channelID, SecretKind(kind)); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// --- C-facing callbacks ------------------------------------------------------

func secretLoadCallback(userData uintptr, secretID, channelID uint64, kind uint32, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchSecretLoad(s, secretID, channelID, kind)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func secretSaveCallback(userData uintptr, secretID, channelID uint64, kind uint32, bytesPtr *byte, length uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchSecretSave(s, secretID, channelID, unsafe.Slice(bytesPtr, length))
}

func secretRemoveCallback(userData uintptr, secretID, channelID uint64, kind uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchSecretRemove(s, secretID, channelID, kind)
}

// secretCallbackPtrs holds the purego.NewCallback address for every
// SecretStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). These three functions are stateless
// package-level funcs, so each needs exactly one registration total — see
// registerChannelCallbacks in callbacks_channel.go for why per-call
// registration would exhaust purego's 2000-slot callback table.
var (
	secretCallbacksOnce sync.Once
	secretCallbackPtrs  struct {
		load, save, remove uintptr
	}
)

func registerSecretCallbacks() {
	secretCallbacksOnce.Do(func() {
		secretCallbackPtrs.load = purego.NewCallback(secretLoadCallback)
		secretCallbackPtrs.save = purego.NewCallback(secretSaveCallback)
		secretCallbackPtrs.remove = purego.NewCallback(secretRemoveCallback)
	})
}

// buildSecretStoreCallbacks assembles SecretStoreCallbacks for h. The
// fn-pointer fields are registered once per process (see
// registerSecretCallbacks); only UserData varies per call.
func buildSecretStoreCallbacks(h storeHandle) SecretStoreCallbacks {
	registerSecretCallbacks()
	return SecretStoreCallbacks{
		UserData:   uintptr(h),
		Load:       secretCallbackPtrs.load,
		Save:       secretCallbackPtrs.save,
		Remove:     secretCallbackPtrs.remove,
		FreeBuffer: sharedFreeBufferCallback(),
	}
}
