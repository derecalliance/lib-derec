// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"strconv"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// secretStore mirrors protocol.SecretStore's method set over native's own
// domain types — see the storeSet doc comment in callbacks.go.
type secretStore interface {
	Load(secretID, channelID uint64, kind SecretKind) (SecretValue, bool, error)
	LoadMany(secretID uint64, channelIDs []uint64, kind SecretKind) ([]*SecretValue, error)
	Save(secretID, channelID uint64, value SecretValue) error
	Remove(secretID, channelID uint64, kind SecretKind) error
	RemoveMany(secretID uint64, entries []SecretEntry) error
}

// SecretStoreCallbacks mirrors #[repr(C)] struct SecretStoreCallbacks in
// library/src/interop/ffi/protocol/stores.rs field-for-field.
type SecretStoreCallbacks struct {
	UserData   uintptr
	Load       uintptr
	LoadMany   uintptr
	Save       uintptr
	Remove     uintptr
	RemoveMany uintptr
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

func dispatchSecretLoadMany(s *storeSet, secretID uint64, channelIDsJSON []byte, kind uint32) (status int32, out []byte) {
	defer recoverInto(&status)
	channelIDs, err := DecodeUint64Array(channelIDsJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	values, err := s.secret.LoadMany(secretID, channelIDs, SecretKind(kind))
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeSecretValueList(values)
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

func dispatchSecretRemoveMany(s *storeSet, secretID uint64, entriesJSON []byte) (status int32) {
	defer recoverInto(&status)
	entries, err := decodeSecretEntries(entriesJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.secret.RemoveMany(secretID, entries); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

// decodeSecretEntries parses the core's JSON array of [channel_id, kind]
// pairs, the channel id a decimal string and the kind a number.
func decodeSecretEntries(data []byte) ([]SecretEntry, error) {
	var pairs [][2]json.RawMessage
	if len(data) > 0 {
		if err := json.Unmarshal(data, &pairs); err != nil {
			return nil, err
		}
	}
	entries := make([]SecretEntry, 0, len(pairs))
	for _, p := range pairs {
		var channelStr string
		if err := json.Unmarshal(p[0], &channelStr); err != nil {
			return nil, err
		}
		var kind uint32
		if err := json.Unmarshal(p[1], &kind); err != nil {
			return nil, err
		}
		channelID, err := strconv.ParseUint(channelStr, 10, 64)
		if err != nil {
			return nil, err
		}
		entries = append(entries, SecretEntry{ChannelID: channelID, Kind: SecretKind(kind)})
	}
	return entries, nil
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

func secretLoadManyCallback(userData uintptr, secretID uint64, channelIDsPtr *byte, channelIDsLen uintptr, kind uint32, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchSecretLoadMany(s, secretID, unsafe.Slice(channelIDsPtr, channelIDsLen), kind)
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

func secretRemoveManyCallback(userData uintptr, secretID uint64, entriesPtr *byte, entriesLen uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchSecretRemoveMany(s, secretID, readFilterBytes(entriesPtr, entriesLen))
}

// secretCallbackPtrs holds the purego.NewCallback address for every
// SecretStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). These five functions are stateless
// package-level funcs, so each needs exactly one registration total — see
// registerChannelCallbacks in callbacks_channel.go for why per-call
// registration would exhaust purego's 2000-slot callback table.
var (
	secretCallbacksOnce sync.Once
	secretCallbackPtrs  struct {
		load, loadMany, save, remove, removeMany uintptr
	}
)

func registerSecretCallbacks() {
	secretCallbacksOnce.Do(func() {
		secretCallbackPtrs.load = purego.NewCallback(secretLoadCallback)
		secretCallbackPtrs.loadMany = purego.NewCallback(secretLoadManyCallback)
		secretCallbackPtrs.save = purego.NewCallback(secretSaveCallback)
		secretCallbackPtrs.remove = purego.NewCallback(secretRemoveCallback)
		secretCallbackPtrs.removeMany = purego.NewCallback(secretRemoveManyCallback)
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
		LoadMany:   secretCallbackPtrs.loadMany,
		Save:       secretCallbackPtrs.save,
		Remove:     secretCallbackPtrs.remove,
		RemoveMany: secretCallbackPtrs.removeMany,
		FreeBuffer: sharedFreeBufferCallback(),
	}
}
