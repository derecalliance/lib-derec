// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// channelStore mirrors protocol.ChannelStore's method set over native's own
// domain types — see the storeSet doc comment in callbacks.go for why
// native re-declares this instead of importing protocol.
type channelStore interface {
	Load(secretID, channelID uint64) (Channel, bool, error)
	Save(secretID uint64, channel Channel) error
	Remove(secretID, channelID uint64) (bool, error)
	ListChannels(secretID uint64) ([]uint64, error)
	LinkChannel(secretID, a, b uint64) error
	LinkedChannels(secretID, channelID uint64) ([]uint64, error)
}

// ChannelStoreCallbacks mirrors #[repr(C)] struct ChannelStoreCallbacks in
// library/src/ffi/protocol/stores.rs field-for-field. UserData carries the
// storeHandle (never a Go pointer); every other field holds the uintptr
// purego.NewCallback returned for that fn-pointer slot.
type ChannelStoreCallbacks struct {
	UserData       uintptr
	Load           uintptr
	Save           uintptr
	Remove         uintptr
	ListChannels   uintptr
	LinkChannel    uintptr
	LinkedChannels uintptr
	FreeBuffer     uintptr
}

// --- Dispatch (pure, unit-testable against a mock channelStore) -----------

func dispatchChannelLoad(s *storeSet, secretID, channelID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	ch, ok, err := s.channel.Load(secretID, channelID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusNotFound, nil
	}
	encoded, err := EncodeChannel(ch)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

// dispatchChannelSave takes channelID purely for FFI signature parity with
// ChannelStoreCallbacks.save (which carries it redundantly alongside the
// encoded Channel, mirroring remove/linked_channels) — the store call
// itself is keyed by the decoded channel's own ID, matching
// protocol.ChannelStore.Save's signature and Rust's DotnetChannelStore::save
// (which derives channel_id from the Channel object, not a caller-supplied
// value).
func dispatchChannelSave(s *storeSet, secretID, channelID uint64, channelJSON []byte) (status int32) {
	defer recoverInto(&status)
	ch, err := DecodeChannel(channelJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.channel.Save(secretID, ch); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchChannelRemove(s *storeSet, secretID, channelID uint64) (status int32, existed bool) {
	defer recoverInto(&status)
	existed, err := s.channel.Remove(secretID, channelID)
	if err != nil {
		return ffiStatusFailure, false
	}
	return ffiStatusOK, existed
}

func dispatchChannelListChannels(s *storeSet, secretID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	ids, err := s.channel.ListChannels(secretID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeUint64Array(ids)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchChannelLinkChannel(s *storeSet, secretID, a, b uint64) (status int32) {
	defer recoverInto(&status)
	if err := s.channel.LinkChannel(secretID, a, b); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchChannelLinkedChannels(s *storeSet, secretID, channelID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	ids, err := s.channel.LinkedChannels(secretID, channelID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeUint64Array(ids)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

// --- C-facing callbacks (exact FFI signature; registered with
// purego.NewCallback in buildChannelStoreCallbacks) -------------------------

func channelLoadCallback(userData uintptr, secretID, channelID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelLoad(s, secretID, channelID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func channelSaveCallback(userData uintptr, secretID, channelID uint64, bytesPtr *byte, length uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchChannelSave(s, secretID, channelID, unsafe.Slice(bytesPtr, length))
}

func channelRemoveCallback(userData uintptr, secretID, channelID uint64, outExisted *uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, existed := dispatchChannelRemove(s, secretID, channelID)
	if st == ffiStatusOK {
		*outExisted = boolToU32(existed)
	}
	return st
}

func channelListChannelsCallback(userData uintptr, secretID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelListChannels(s, secretID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func channelLinkChannelCallback(userData uintptr, secretID, a, b uint64) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchChannelLinkChannel(s, secretID, a, b)
}

func channelLinkedChannelsCallback(userData uintptr, secretID, channelID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelLinkedChannels(s, secretID, channelID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

// channelCallbackPtrs holds the purego.NewCallback address for every
// ChannelStoreCallbacks fn-pointer field except FreeBuffer (shared package-
// wide via sharedFreeBufferCallback). All six functions are stateless
// package-level funcs that resolve their *storeSet from UserData at call
// time, so each needs exactly one registration total, reused across every
// buildChannelStoreCallbacks call — purego.NewCallback has a fixed 2000-slot
// table and no unregister API, so calling it per protocol instance would
// exhaust that table after a few dozen instances.
var (
	channelCallbacksOnce sync.Once
	channelCallbackPtrs  struct {
		load, save, remove, listChannels, linkChannel, linkedChannels uintptr
	}
)

func registerChannelCallbacks() {
	channelCallbacksOnce.Do(func() {
		channelCallbackPtrs.load = purego.NewCallback(channelLoadCallback)
		channelCallbackPtrs.save = purego.NewCallback(channelSaveCallback)
		channelCallbackPtrs.remove = purego.NewCallback(channelRemoveCallback)
		channelCallbackPtrs.listChannels = purego.NewCallback(channelListChannelsCallback)
		channelCallbackPtrs.linkChannel = purego.NewCallback(channelLinkChannelCallback)
		channelCallbackPtrs.linkedChannels = purego.NewCallback(channelLinkedChannelsCallback)
	})
}

// buildChannelStoreCallbacks assembles ChannelStoreCallbacks for h. The
// fn-pointer fields are registered once per process (see
// registerChannelCallbacks); only UserData varies per call.
func buildChannelStoreCallbacks(h storeHandle) ChannelStoreCallbacks {
	registerChannelCallbacks()
	return ChannelStoreCallbacks{
		UserData:       uintptr(h),
		Load:           channelCallbackPtrs.load,
		Save:           channelCallbackPtrs.save,
		Remove:         channelCallbackPtrs.remove,
		ListChannels:   channelCallbackPtrs.listChannels,
		LinkChannel:    channelCallbackPtrs.linkChannel,
		LinkedChannels: channelCallbackPtrs.linkedChannels,
		FreeBuffer:     sharedFreeBufferCallback(),
	}
}
