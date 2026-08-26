// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package native

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/ebitengine/purego"
)

// TestBuildCallbacks_PopulatesAllSixStructs is a smoke test that
// buildCallbacks wires every field of every *Callbacks struct to a
// non-zero UserData (the storeHandle) and a non-zero fn-pointer address
// (the purego.NewCallback result), matching every field
// library/src/interop/ffi/protocol/stores.rs declares.
func TestBuildCallbacks_PopulatesAllSixStructs(t *testing.T) {
	s := &storeSet{
		channel:    &mockChannelStore{},
		secret:     &mockSecretStore{},
		share:      &mockShareStore{},
		userSecret: &mockUserSecretStore{},
		state:      &mockStateStore{},
		transport:  &mockTransportSender{},
	}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	if built.handle == 0 {
		t.Fatal("expected non-zero handle")
	}
	if _, ok := lookupStores(built.handle); !ok {
		t.Fatal("expected handle to resolve to the registered storeSet")
	}

	checkNonZero := func(name string, v uintptr) {
		t.Helper()
		if v == 0 {
			t.Errorf("%s is zero", name)
		}
	}

	checkNonZero("Channel.UserData", built.Channel.UserData)
	checkNonZero("Channel.Load", built.Channel.Load)
	checkNonZero("Channel.Save", built.Channel.Save)
	checkNonZero("Channel.Remove", built.Channel.Remove)
	checkNonZero("Channel.ListHelpers", built.Channel.ListHelpers)
	checkNonZero("Channel.ListReplicas", built.Channel.ListReplicas)
	checkNonZero("Channel.LinkChannel", built.Channel.LinkChannel)
	checkNonZero("Channel.LinkedChannels", built.Channel.LinkedChannels)
	checkNonZero("Channel.FreeBuffer", built.Channel.FreeBuffer)

	checkNonZero("Secret.UserData", built.Secret.UserData)
	checkNonZero("Secret.Load", built.Secret.Load)
	checkNonZero("Secret.Save", built.Secret.Save)
	checkNonZero("Secret.Remove", built.Secret.Remove)
	checkNonZero("Secret.FreeBuffer", built.Secret.FreeBuffer)

	checkNonZero("Share.UserData", built.Share.UserData)
	checkNonZero("Share.Load", built.Share.Load)
	checkNonZero("Share.LoadMany", built.Share.LoadMany)
	checkNonZero("Share.LoadAll", built.Share.LoadAll)
	checkNonZero("Share.LatestVersion", built.Share.LatestVersion)
	checkNonZero("Share.Save", built.Share.Save)
	checkNonZero("Share.RemoveChannel", built.Share.RemoveChannel)
	checkNonZero("Share.FreeBuffer", built.Share.FreeBuffer)

	checkNonZero("UserSecret.UserData", built.UserSecret.UserData)
	checkNonZero("UserSecret.LoadLatest", built.UserSecret.LoadLatest)
	checkNonZero("UserSecret.SaveLatest", built.UserSecret.SaveLatest)
	checkNonZero("UserSecret.Remove", built.UserSecret.Remove)
	checkNonZero("UserSecret.FreeBuffer", built.UserSecret.FreeBuffer)

	checkNonZero("State.UserData", built.State.UserData)
	checkNonZero("State.Save", built.State.Save)
	checkNonZero("State.Load", built.State.Load)
	checkNonZero("State.Remove", built.State.Remove)
	checkNonZero("State.LoadAll", built.State.LoadAll)
	checkNonZero("State.FreeBuffer", built.State.FreeBuffer)

	checkNonZero("Transport.UserData", built.Transport.UserData)
	checkNonZero("Transport.Send", built.Transport.Send)

	// The five store FreeBuffer fields share one registered callback.
	if built.Channel.FreeBuffer != built.Secret.FreeBuffer ||
		built.Secret.FreeBuffer != built.Share.FreeBuffer ||
		built.Share.FreeBuffer != built.UserSecret.FreeBuffer ||
		built.UserSecret.FreeBuffer != built.State.FreeBuffer {
		t.Fatal("expected all five FreeBuffer fields to share one registered callback")
	}

	built.release()
	if _, ok := lookupStores(built.handle); ok {
		t.Fatal("expected handle to be released")
	}
}

func TestBuildCallbacks_NilStoreSet(t *testing.T) {
	if _, err := buildCallbacks(nil); err == nil {
		t.Fatal("expected an error for a nil storeSet")
	}
}

// --- Real C-ABI round trips ------------------------------------------------
//
// purego.NewCallback compiles a Go function into a genuine C-callable
// function pointer; purego.RegisterFunc binds a Go func variable to call an
// arbitrary address using the platform C calling convention. Invoking a
// purego.NewCallback address through a purego.RegisterFunc-bound variable
// therefore drives the exact same architecture-specific trampoline
// (callbackasm) a real Rust `extern "C" fn(...)` call would use, without
// needing the compiled derec-library dylib present. This exercises the
// actual registered callback — not just the pure dispatch function — for
// the "real C round-trip" test the brief calls out as valuable beyond the
// unit-test floor.

func TestChannelStoreCallbacks_LoadCallback_RealRoundTrip(t *testing.T) {
	want := HelperChannel{ChannelID: 77, Status: ChannelStatusPaired, PeerRole: SenderKindOwner, CommunicationInfo: map[string]string{}}
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			return ChannelRecord{Helper: &want}, true, nil
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	// outPtr is declared as **byte (not uintptr) so the callback's write
	// can be read back as a genuine Go pointer with no
	// unsafe.Pointer(uintptr) round trip on the test's side — purego
	// marshals by raw register bits, so this differs from the callback's
	// own *uintptr-typed parameter in name only, not in ABI.
	var load func(userData uintptr, secretID, channelID, replicaID uint64, outPtr **byte, outLen *uintptr) int32
	purego.RegisterFunc(&load, built.Channel.Load)

	var outPtr *byte
	var outLen uintptr
	rc := load(built.Channel.UserData, 1, 77, 0, &outPtr, &outLen)
	if rc != ffiStatusOK {
		t.Fatalf("rc = %d, want ffiStatusOK", rc)
	}
	if outPtr == nil || outLen == 0 {
		t.Fatalf("expected non-zero out buffer, got ptr=%p len=%d", outPtr, outLen)
	}

	got := unsafe.Slice(outPtr, outLen)
	record, err := DecodeChannelRecord(got)
	if err != nil {
		t.Fatalf("DecodeChannelRecord: %v", err)
	}
	if record.Helper == nil || record.Helper.ChannelID != want.ChannelID {
		t.Fatalf("record = %+v, want helper %+v", record, want)
	}

	var freeBuffer func(userData uintptr, ptr *byte, length uintptr)
	purego.RegisterFunc(&freeBuffer, built.Channel.FreeBuffer)
	freeBuffer(built.Channel.UserData, outPtr, outLen)
}

func TestChannelStoreCallbacks_LoadCallback_NotFound_RealRoundTrip(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			return ChannelRecord{}, false, nil
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	var load func(userData uintptr, secretID, channelID, replicaID uint64, outPtr **byte, outLen *uintptr) int32
	purego.RegisterFunc(&load, built.Channel.Load)

	var outPtr *byte
	var outLen uintptr
	rc := load(built.Channel.UserData, 1, 2, 0, &outPtr, &outLen)
	if rc != ffiStatusNotFound {
		t.Fatalf("rc = %d, want ffiStatusNotFound", rc)
	}
	if outPtr != nil || outLen != 0 {
		t.Fatalf("expected untouched out params on not-found, got ptr=%p len=%d", outPtr, outLen)
	}
}

// TestChannelStoreCallbacks_SaveCallback_RealRoundTrip proves the save
// direction — Go writing a JSON payload into C-owned memory and the real
// registered callback reading it back out via unsafe.Slice — round trips
// correctly.
func TestChannelStoreCallbacks_SaveCallback_RealRoundTrip(t *testing.T) {
	var saved ChannelRecord
	s := &storeSet{channel: &mockChannelStore{
		saveFn: func(secretID uint64, record ChannelRecord) error {
			saved = record
			return nil
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	var save func(userData uintptr, secretID, channelID, replicaID uint64, bytesPtr *byte, length uintptr) int32
	purego.RegisterFunc(&save, built.Channel.Save)

	helper := HelperChannel{ChannelID: 5, Status: ChannelStatusPending, PeerRole: SenderKindHelper, CommunicationInfo: map[string]string{}}
	payload, err := EncodeChannelRecord(ChannelRecord{Helper: &helper})
	if err != nil {
		t.Fatalf("EncodeChannelRecord: %v", err)
	}
	rc := save(built.Channel.UserData, 9, 5, 0, &payload[0], uintptr(len(payload)))
	if rc != ffiStatusOK {
		t.Fatalf("rc = %d, want ffiStatusOK", rc)
	}
	if saved.Helper == nil || saved.Helper.ChannelID != 5 || saved.Helper.PeerRole != SenderKindHelper {
		t.Fatalf("saved = %+v", saved)
	}
}

// TestChannelStoreCallbacks_LoadCallback_PanicNotCrash_RealRoundTrip drives
// the mandatory panic-safety proof through the actual registered C-ABI
// callback (not just the pure dispatch function): a store implementation
// that panics must come back as a failure status code across a genuine
// purego.NewCallback trampoline, not crash the process.
func TestChannelStoreCallbacks_LoadCallback_PanicNotCrash_RealRoundTrip(t *testing.T) {
	s := &storeSet{channel: &mockChannelStore{
		loadFn: func(secretID, channelID, replicaID uint64) (ChannelRecord, bool, error) {
			panic("mock store blew up across the C boundary")
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	var load func(userData uintptr, secretID, channelID, replicaID uint64, outPtr **byte, outLen *uintptr) int32
	purego.RegisterFunc(&load, built.Channel.Load)

	var outPtr *byte
	var outLen uintptr
	rc := load(built.Channel.UserData, 1, 2, 0, &outPtr, &outLen)
	if rc != ffiStatusFailure {
		t.Fatalf("rc = %d, want ffiStatusFailure after recovered panic", rc)
	}
	if outPtr != nil || outLen != 0 {
		t.Fatalf("expected untouched out params after recovered panic, got ptr=%p len=%d", outPtr, outLen)
	}
}

func TestTransportCallbacks_SendCallback_RealRoundTrip(t *testing.T) {
	var gotURI string
	var gotMessage []byte
	s := &storeSet{transport: &mockTransportSender{
		sendFn: func(uri string, protocol int32, message []byte) error {
			gotURI = uri
			gotMessage = append([]byte(nil), message...)
			return nil
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	var send func(userData uintptr, uriPtr *byte, uriLen uintptr, protocol int32, bytesPtr *byte, length uintptr) int32
	purego.RegisterFunc(&send, built.Transport.Send)

	uri := []byte("https://example.com/derec")
	msg := []byte("hello derec")
	rc := send(built.Transport.UserData, &uri[0], uintptr(len(uri)), 0, &msg[0], uintptr(len(msg)))
	if rc != ffiStatusOK {
		t.Fatalf("rc = %d, want ffiStatusOK", rc)
	}
	if gotURI != "https://example.com/derec" || string(gotMessage) != "hello derec" {
		t.Fatalf("gotURI=%q gotMessage=%q", gotURI, gotMessage)
	}
}

func TestTransportCallbacks_SendCallback_ErrorPropagates_RealRoundTrip(t *testing.T) {
	s := &storeSet{transport: &mockTransportSender{
		sendFn: func(uri string, protocol int32, message []byte) error {
			return errors.New("simulated failure")
		},
	}}
	built, err := buildCallbacks(s)
	if err != nil {
		t.Fatalf("buildCallbacks: %v", err)
	}
	defer built.release()

	var send func(userData uintptr, uriPtr *byte, uriLen uintptr, protocol int32, bytesPtr *byte, length uintptr) int32
	purego.RegisterFunc(&send, built.Transport.Send)

	uri := []byte("https://example.com")
	rc := send(built.Transport.UserData, &uri[0], uintptr(len(uri)), 0, nil, 0)
	if rc != ffiStatusFailure {
		t.Fatalf("rc = %d, want ffiStatusFailure", rc)
	}
}

// TestFreeBufferCallback_RealRoundTrip proves the shared free_buffer
// callback actually releases a buffer cCopyBytes allocated, through the
// real registered C-ABI function pointer.
func TestFreeBufferCallback_RealRoundTrip(t *testing.T) {
	ptr, length := cCopyBytes([]byte{1, 2, 3})
	if ptr == nil {
		t.Fatal("expected non-nil buffer")
	}

	cb := sharedFreeBufferCallback()
	var freeBuffer func(userData uintptr, ptr *byte, length uintptr)
	purego.RegisterFunc(&freeBuffer, cb)

	// Must not panic/crash — that's the only property directly observable
	// from Go for a libc free() call.
	freeBuffer(0, ptr, length)
}

func TestFreeBufferCallback_NilPointerDoesNotCrash(t *testing.T) {
	cb := sharedFreeBufferCallback()
	var freeBuffer func(userData uintptr, ptr *byte, length uintptr)
	purego.RegisterFunc(&freeBuffer, cb)
	freeBuffer(0, nil, 0)
}

// TestBuildCallbacks_ManyInstancesDoNotExhaustCallbackTable proves the fix
// for the purego.NewCallback exhaustion bug: purego v0.10.2 caps its
// callback table at 2000 entries (const maxCB = 2000) with no unregister
// API, and buildCallbacks assembles ~23 callback fn-pointer fields per
// call. Registering all 23 fresh on every call — as buildCallbacks used to
// — would panic with "the maximum number of callbacks has been reached"
// after roughly 2000/23 ≈ 86 instances. Since every callback function is
// stateless (storeSet is resolved from UserData at call time, never
// captured), each is registered exactly once per process and the address
// reused; this loop runs 500 iterations, comfortably past the 86-instance
// threshold that would previously panic, to prove no new registration
// happens per call.
func TestBuildCallbacks_ManyInstancesDoNotExhaustCallbackTable(t *testing.T) {
	const iterations = 500

	var first *builtCallbacks
	for i := 0; i < iterations; i++ {
		s := &storeSet{
			channel:    &mockChannelStore{},
			secret:     &mockSecretStore{},
			share:      &mockShareStore{},
			userSecret: &mockUserSecretStore{},
			state:      &mockStateStore{},
			transport:  &mockTransportSender{},
		}
		built, err := buildCallbacks(s)
		if err != nil {
			t.Fatalf("iteration %d: buildCallbacks: %v", i, err)
		}

		if built.handle == 0 {
			t.Fatalf("iteration %d: expected non-zero handle", i)
		}

		checkNonZero := func(name string, v uintptr) {
			t.Helper()
			if v == 0 {
				t.Errorf("iteration %d: %s is zero", i, name)
			}
		}

		checkNonZero("Channel.Load", built.Channel.Load)
		checkNonZero("Channel.Save", built.Channel.Save)
		checkNonZero("Channel.Remove", built.Channel.Remove)
		checkNonZero("Channel.ListHelpers", built.Channel.ListHelpers)
		checkNonZero("Channel.ListReplicas", built.Channel.ListReplicas)
		checkNonZero("Channel.LinkChannel", built.Channel.LinkChannel)
		checkNonZero("Channel.LinkedChannels", built.Channel.LinkedChannels)
		checkNonZero("Channel.FreeBuffer", built.Channel.FreeBuffer)

		checkNonZero("Secret.Load", built.Secret.Load)
		checkNonZero("Secret.Save", built.Secret.Save)
		checkNonZero("Secret.Remove", built.Secret.Remove)
		checkNonZero("Secret.FreeBuffer", built.Secret.FreeBuffer)

		checkNonZero("Share.Load", built.Share.Load)
		checkNonZero("Share.LoadMany", built.Share.LoadMany)
		checkNonZero("Share.LoadAll", built.Share.LoadAll)
		checkNonZero("Share.LatestVersion", built.Share.LatestVersion)
		checkNonZero("Share.Save", built.Share.Save)
		checkNonZero("Share.RemoveChannel", built.Share.RemoveChannel)
		checkNonZero("Share.FreeBuffer", built.Share.FreeBuffer)

		checkNonZero("UserSecret.LoadLatest", built.UserSecret.LoadLatest)
		checkNonZero("UserSecret.SaveLatest", built.UserSecret.SaveLatest)
		checkNonZero("UserSecret.Remove", built.UserSecret.Remove)
		checkNonZero("UserSecret.FreeBuffer", built.UserSecret.FreeBuffer)

		checkNonZero("State.Save", built.State.Save)
		checkNonZero("State.Load", built.State.Load)
		checkNonZero("State.Remove", built.State.Remove)
		checkNonZero("State.LoadAll", built.State.LoadAll)
		checkNonZero("State.FreeBuffer", built.State.FreeBuffer)

		checkNonZero("Transport.Send", built.Transport.Send)

		// Every callback pointer must be identical across iterations —
		// that's the whole point of the fix: one registration, reused.
		if first == nil {
			first = built
		} else if built.Channel.Load != first.Channel.Load ||
			built.Secret.Load != first.Secret.Load ||
			built.Share.Load != first.Share.Load ||
			built.UserSecret.LoadLatest != first.UserSecret.LoadLatest ||
			built.State.Load != first.State.Load ||
			built.Transport.Send != first.Transport.Send {
			t.Fatalf("iteration %d: callback pointers changed across calls; expected stable shared registration", i)
		}

		built.release()
	}
}
