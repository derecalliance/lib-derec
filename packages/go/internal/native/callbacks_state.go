// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"encoding/json"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// stateStore mirrors protocol.StateStore's method set over native's own
// domain types — see the storeSet doc comment in callbacks.go.
type stateStore interface {
	Save(secretID uint64, item StateItem) error
	Load(secretID uint64, key StateKey) (StateItem, bool, error)
	Remove(secretID uint64, key StateKey) (bool, error)
	LoadAll(secretID uint64, kind StateKind) ([]StateItem, error)
}

// StateStoreCallbacks mirrors #[repr(C)] struct StateStoreCallbacks in
// library/src/ffi/protocol/stores.rs field-for-field.
type StateStoreCallbacks struct {
	UserData   uintptr
	Save       uintptr
	Load       uintptr
	Remove     uintptr
	LoadAll    uintptr
	FreeBuffer uintptr
}

// encodeStateItemList JSON-array-encodes items the way
// StateStoreCallbacks.load_all's response is decoded on the Rust side (a
// `Vec<StateItemRecord>`). store_records.go only provides a per-item
// codec (EncodeStateItem), so the list wrapping lives here instead of
// duplicating it there.
func encodeStateItemList(items []StateItem) ([]byte, error) {
	parts := make([]json.RawMessage, len(items))
	for i, item := range items {
		b, err := EncodeStateItem(item)
		if err != nil {
			return nil, err
		}
		parts[i] = b
	}
	return json.Marshal(parts)
}

// --- Dispatch ---------------------------------------------------------------

func dispatchStateSave(s *storeSet, secretID uint64, itemJSON []byte) (status int32) {
	defer recoverInto(&status)
	item, err := DecodeStateItem(itemJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.state.Save(secretID, item); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchStateLoad(s *storeSet, secretID uint64, keyJSON []byte) (status int32, out []byte) {
	defer recoverInto(&status)
	key, err := DecodeStateKey(keyJSON)
	if err != nil {
		return ffiStatusFailure, nil
	}
	item, ok, err := s.state.Load(secretID, key)
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusNotFound, nil
	}
	encoded, err := EncodeStateItem(item)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchStateRemove(s *storeSet, secretID uint64, keyJSON []byte) (status int32, removed bool) {
	defer recoverInto(&status)
	key, err := DecodeStateKey(keyJSON)
	if err != nil {
		return ffiStatusFailure, false
	}
	removed, err = s.state.Remove(secretID, key)
	if err != nil {
		return ffiStatusFailure, false
	}
	return ffiStatusOK, removed
}

func dispatchStateLoadAll(s *storeSet, secretID uint64, kind uint32) (status int32, out []byte) {
	defer recoverInto(&status)
	items, err := s.state.LoadAll(secretID, StateKind(kind))
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := encodeStateItemList(items)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

// --- C-facing callbacks ------------------------------------------------------

func stateSaveCallback(userData uintptr, secretID uint64, itemPtr *byte, itemLen uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchStateSave(s, secretID, unsafe.Slice(itemPtr, itemLen))
}

func stateLoadCallback(userData uintptr, secretID uint64, keyPtr *byte, keyLen uintptr, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchStateLoad(s, secretID, unsafe.Slice(keyPtr, keyLen))
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func stateRemoveCallback(userData uintptr, secretID uint64, keyPtr *byte, keyLen uintptr, outRemoved *uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, removed := dispatchStateRemove(s, secretID, unsafe.Slice(keyPtr, keyLen))
	if st == ffiStatusOK {
		*outRemoved = boolToU32(removed)
	}
	return st
}

func stateLoadAllCallback(userData uintptr, secretID uint64, kind uint32, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchStateLoadAll(s, secretID, kind)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

// stateCallbackPtrs holds the purego.NewCallback address for every
// StateStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). These four functions are stateless
// package-level funcs, so each needs exactly one registration total — see
// registerChannelCallbacks in callbacks_channel.go for why per-call
// registration would exhaust purego's 2000-slot callback table.
var (
	stateCallbacksOnce sync.Once
	stateCallbackPtrs  struct {
		save, load, remove, loadAll uintptr
	}
)

func registerStateCallbacks() {
	stateCallbacksOnce.Do(func() {
		stateCallbackPtrs.save = purego.NewCallback(stateSaveCallback)
		stateCallbackPtrs.load = purego.NewCallback(stateLoadCallback)
		stateCallbackPtrs.remove = purego.NewCallback(stateRemoveCallback)
		stateCallbackPtrs.loadAll = purego.NewCallback(stateLoadAllCallback)
	})
}

// buildStateStoreCallbacks assembles StateStoreCallbacks for h. The
// fn-pointer fields are registered once per process (see
// registerStateCallbacks); only UserData varies per call.
func buildStateStoreCallbacks(h storeHandle) StateStoreCallbacks {
	registerStateCallbacks()
	return StateStoreCallbacks{
		UserData:   uintptr(h),
		Save:       stateCallbackPtrs.save,
		Load:       stateCallbackPtrs.load,
		Remove:     stateCallbackPtrs.remove,
		LoadAll:    stateCallbackPtrs.loadAll,
		FreeBuffer: sharedFreeBufferCallback(),
	}
}
