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
//
// A record is addressed by (channelID, replicaID). A replicaID of 0 — the
// value the protocol reserves as "absent" — addresses the helper channel at
// channelID; any other value addresses that member of the replica group,
// which is keyed by replicaID alone (see protocol.ChannelStore).
type channelStore interface {
	Load(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error)
	Save(secretID uint64, record ChannelRecord) error
	Remove(secretID, channelID, replicaID uint64) (bool, error)
	ListHelpers(secretID uint64) ([]HelperChannel, error)
	ListReplicas(secretID uint64) ([]ReplicaMember, error)
	LinkChannel(secretID, a, b uint64) error
	LinkedChannels(secretID, channelID uint64) ([]uint64, error)
}

// ChannelStoreCallbacks mirrors #[repr(C)] struct ChannelStoreCallbacks in
// library/src/interop/ffi/protocol/stores.rs field-for-field. UserData carries the
// storeHandle (never a Go pointer); every other field holds the uintptr
// purego.NewCallback returned for that fn-pointer slot.
type ChannelStoreCallbacks struct {
	UserData       uintptr
	Load           uintptr
	Save           uintptr
	Remove         uintptr
	ListHelpers    uintptr
	ListReplicas   uintptr
	LinkChannel    uintptr
	LinkedChannels uintptr
	FreeBuffer     uintptr
}

// --- Dispatch (pure, unit-testable against a mock channelStore) -----------

func dispatchChannelLoad(s *storeSet, secretID, channelID, replicaID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	record, ok, err := s.channel.Load(secretID, channelID, replicaID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	if !ok {
		return ffiStatusNotFound, nil
	}
	encoded, err := EncodeChannelRecord(record)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

// dispatchChannelSave takes channelID and replicaID purely for FFI signature
// parity with ChannelStoreCallbacks.save (which carries them redundantly
// alongside the encoded record, mirroring remove) — the store call itself is
// keyed by the decoded record's own address, matching Rust's
// DotnetChannelStore::save, which derives the key from the record rather than
// a caller-supplied value so a record cannot be saved under the wrong key.
func dispatchChannelSave(s *storeSet, secretID, channelID, replicaID uint64, recordJSON []byte) (status int32) {
	defer recoverInto(&status)
	record, err := DecodeChannelRecord(recordJSON)
	if err != nil {
		return ffiStatusFailure
	}
	if err := s.channel.Save(secretID, record); err != nil {
		return ffiStatusFailure
	}
	return ffiStatusOK
}

func dispatchChannelRemove(s *storeSet, secretID, channelID, replicaID uint64) (status int32, existed bool) {
	defer recoverInto(&status)
	existed, err := s.channel.Remove(secretID, channelID, replicaID)
	if err != nil {
		return ffiStatusFailure, false
	}
	return ffiStatusOK, existed
}

func dispatchChannelListHelpers(s *storeSet, secretID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	helpers, err := s.channel.ListHelpers(secretID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeHelperChannelList(helpers)
	if err != nil {
		return ffiStatusFailure, nil
	}
	return ffiStatusOK, encoded
}

func dispatchChannelListReplicas(s *storeSet, secretID uint64) (status int32, out []byte) {
	defer recoverInto(&status)
	members, err := s.channel.ListReplicas(secretID)
	if err != nil {
		return ffiStatusFailure, nil
	}
	encoded, err := EncodeReplicaMemberList(members)
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

func channelLoadCallback(userData uintptr, secretID, channelID, replicaID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelLoad(s, secretID, channelID, replicaID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func channelSaveCallback(userData uintptr, secretID, channelID, replicaID uint64, bytesPtr *byte, length uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	return dispatchChannelSave(s, secretID, channelID, replicaID, unsafe.Slice(bytesPtr, length))
}

func channelRemoveCallback(userData uintptr, secretID, channelID, replicaID uint64, outExisted *uint32) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, existed := dispatchChannelRemove(s, secretID, channelID, replicaID)
	if st == ffiStatusOK {
		*outExisted = boolToU32(existed)
	}
	return st
}

func channelListHelpersCallback(userData uintptr, secretID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelListHelpers(s, secretID)
	if st != ffiStatusOK {
		return st
	}
	writeOutBuffer(out, outPtr, outLen)
	return ffiStatusOK
}

func channelListReplicasCallback(userData uintptr, secretID uint64, outPtr, outLen *uintptr) (status int32) {
	defer recoverInto(&status)
	s, ok := lookupStores(storeHandle(userData))
	if !ok {
		return ffiStatusFailure
	}
	st, out := dispatchChannelListReplicas(s, secretID)
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
		load, save, remove, listHelpers, listReplicas, linkChannel, linkedChannels uintptr
	}
)

func registerChannelCallbacks() {
	channelCallbacksOnce.Do(func() {
		channelCallbackPtrs.load = purego.NewCallback(channelLoadCallback)
		channelCallbackPtrs.save = purego.NewCallback(channelSaveCallback)
		channelCallbackPtrs.remove = purego.NewCallback(channelRemoveCallback)
		channelCallbackPtrs.listHelpers = purego.NewCallback(channelListHelpersCallback)
		channelCallbackPtrs.listReplicas = purego.NewCallback(channelListReplicasCallback)
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
		ListHelpers:    channelCallbackPtrs.listHelpers,
		ListReplicas:   channelCallbackPtrs.listReplicas,
		LinkChannel:    channelCallbackPtrs.linkChannel,
		LinkedChannels: channelCallbackPtrs.linkedChannels,
		FreeBuffer:     sharedFreeBufferCallback(),
	}
}
