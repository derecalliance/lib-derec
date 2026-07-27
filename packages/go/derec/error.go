// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

// Package derec holds the public DeRec SDK error vocabulary: the typed
// [Error] returned by every fallible primitive, and the Category*/Code*
// constants it carries. This package is a leaf — it imports nothing else
// from this module — so that internal/native and every primitives/* package
// can depend on it without creating an import cycle.
//
// The Category*/Code* constants mirror, one-for-one and with the same
// integer values, the DEREC_CATEGORY_*/DEREC_CODE_* constants declared in
// library/src/ffi/error.rs, which remains the source of truth.
package derec

import "fmt"

// Error is the typed error returned by every fallible DeRec primitive. It
// carries the FFI category/code plus the structured fields that are only
// meaningful for specific codes:
//
//   - PeerStatus / PeerMemo are valid when Code == CodeNonOKStatus.
//   - Expected / Got are valid when Code == CodeVersionMismatch.
//
// Message is human-readable only — branch on Code, never parse Message.
type Error struct {
	Category   int32
	Code       int32
	Message    string
	PeerStatus int32
	PeerMemo   string
	Expected   uint32
	Got        uint32
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("derec: %s (category=%d code=%d)", e.Message, e.Category, e.Code)
}

// Unwrap always returns nil: Error is a terminal, self-contained error value
// with no wrapped cause to unwrap.
func (e *Error) Unwrap() error {
	return nil
}

// Categories identify the protocol phase or layer that produced an [Error].
// They mirror the DEREC_CATEGORY_* constants in library/src/ffi/error.rs.
const (
	CategoryOK           int32 = 0
	CategoryFFI          int32 = 1
	CategoryPairing      int32 = 2
	CategorySharing      int32 = 3
	CategoryRecovery     int32 = 4
	CategoryVerification int32 = 5
	CategoryDiscovery    int32 = 6
	CategoryUnpairing    int32 = 7
	CategoryDeRecMessage int32 = 8
	CategorySecretStore  int32 = 9
	CategoryChannelStore int32 = 10
	CategoryShareStore   int32 = 11
	CategoryInvalidInput int32 = 12
	CategoryProtobuf     int32 = 13
	CategoryInvariant    int32 = 14
	CategoryStateStore   int32 = 15
)

// Codes give the specific reason an [Error] occurred. Codes are global — the
// same value means the same thing regardless of Category. They mirror the
// DEREC_CODE_* constants in library/src/ffi/error.rs.
const (
	CodeOK                     int32 = 0
	CodeNonOKStatus            int32 = 1
	CodeVersionMismatch        int32 = 2
	CodeInvariant              int32 = 3
	CodeInvalidInput           int32 = 4
	CodeProtobufDecode         int32 = 5
	CodeProtobufEncode         int32 = 6
	CodeProtocolViolation      int32 = 7
	CodeStoreError             int32 = 8
	CodeBuilderError           int32 = 9
	CodeMissingSharedKey       int32 = 10
	CodeRoleMismatch           int32 = 11
	CodeReplicaIDNotConfigured int32 = 12
	CodeChannelAlreadyPaired   int32 = 13
	CodeAlreadyRestored        int32 = 14
	CodeRestoreConflict        int32 = 15

	CodeEncryption             int32 = 20
	CodeKeygen                 int32 = 21
	CodeFinishPairingInitiator int32 = 22
	CodeFinishPairingResponder int32 = 23

	CodeEmptyTransportURI          int32 = 40
	CodeInvalidContactMessage      int32 = 41
	CodeInvalidPairRequestMessage  int32 = 42
	CodeInvalidPairResponseMessage int32 = 43
	CodePrepairHashMismatch        int32 = 44
	CodeMissingReplicaID           int32 = 45
	CodeUnexpectedReplicaID        int32 = 46
	CodeIncompatibleParameterRange int32 = 47

	CodeEmptyChannels      int32 = 60
	CodeDuplicateChannelID int32 = 61
	CodeInvalidThreshold   int32 = 62
	CodeEmptySecretData    int32 = 63
	CodeVSSShareFailed     int32 = 64

	CodeEmptyResponses            int32 = 80
	CodeEmptyCommittedDeRecShare  int32 = 81
	CodeDecodeCommittedDeRecShare int32 = 82
	CodeDecodeDeRecShare          int32 = 83
	CodeSecretIDMismatch          int32 = 84
	CodeReconstructionFailed      int32 = 85
	CodeMalformedRecoveredSecret  int32 = 86

	CodeFFINullPtr      int32 = 100
	CodeFFIBadLength    int32 = 101
	CodeFFIBadUTF8      int32 = 102
	CodeFFIBadProto     int32 = 103
	CodeFFIInvalidEnum  int32 = 104
	CodeFFIBadSharedKey int32 = 105
	CodeFFINulInString  int32 = 106

	CodeTransportInvalid int32 = 120
)
