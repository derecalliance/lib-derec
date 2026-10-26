// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

package derec_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/derecalliance/lib-derec/packages/go/derec"
)

type numberToNameVariant struct {
	Name string `json:"name"`
	Wire int32  `json:"wire"`
	Text string `json:"text"`
}

func loadNumberToNameEnum(t *testing.T, enumName string) []numberToNameVariant {
	t.Helper()
	raw, err := os.ReadFile("../../../library/tests/fixtures/enums.json")
	if err != nil {
		t.Fatalf("read enums.json: %v", err)
	}
	var doc struct {
		Enums map[string]json.RawMessage `json:"enums"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse enums.json: %v", err)
	}
	entry, ok := doc.Enums[enumName]
	if !ok {
		t.Fatalf("enums.json has no %q", enumName)
	}
	var e struct {
		Variants []numberToNameVariant `json:"variants"`
	}
	if err := json.Unmarshal(entry, &e); err != nil {
		t.Fatalf("parse %s: %v", enumName, err)
	}
	return e.Variants
}

// declaredConstants returns the value of every constant in error.go whose
// name starts with prefix, read from the source so a constant Go declares
// but the fixture lacks is seen.
func declaredConstants(t *testing.T, prefix string) map[string]int32 {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "error.go", nil, 0)
	if err != nil {
		t.Fatalf("parse error.go: %v", err)
	}
	out := map[string]int32{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, prefix) || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					continue
				}
				n, err := strconv.ParseInt(lit.Value, 0, 32)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				out[name.Name] = int32(n)
			}
		}
	}
	return out
}

var fixtureErrorCategories = map[string]int32{
	"Ok":           derec.CategoryOK,
	"Ffi":          derec.CategoryFFI,
	"Pairing":      derec.CategoryPairing,
	"Sharing":      derec.CategorySharing,
	"Recovery":     derec.CategoryRecovery,
	"Verification": derec.CategoryVerification,
	"Discovery":    derec.CategoryDiscovery,
	"Unpairing":    derec.CategoryUnpairing,
	"DeRecMessage": derec.CategoryDeRecMessage,
	"SecretStore":  derec.CategorySecretStore,
	"ChannelStore": derec.CategoryChannelStore,
	"ShareStore":   derec.CategoryShareStore,
	"InvalidInput": derec.CategoryInvalidInput,
	"Protobuf":     derec.CategoryProtobuf,
	"Invariant":    derec.CategoryInvariant,
	"StateStore":   derec.CategoryStateStore,
}

var fixtureErrorCodes = map[string]int32{
	"Ok":                         derec.CodeOK,
	"NonOkStatus":                derec.CodeNonOKStatus,
	"VersionMismatch":            derec.CodeVersionMismatch,
	"Invariant":                  derec.CodeInvariant,
	"InvalidInput":               derec.CodeInvalidInput,
	"ProtobufDecode":             derec.CodeProtobufDecode,
	"ProtobufEncode":             derec.CodeProtobufEncode,
	"ProtocolViolation":          derec.CodeProtocolViolation,
	"StoreError":                 derec.CodeStoreError,
	"BuilderError":               derec.CodeBuilderError,
	"MissingSharedKey":           derec.CodeMissingSharedKey,
	"RoleMismatch":               derec.CodeRoleMismatch,
	"ReplicaIdNotConfigured":     derec.CodeReplicaIDNotConfigured,
	"ChannelAlreadyPaired":       derec.CodeChannelAlreadyPaired,
	"AlreadyRestored":            derec.CodeAlreadyRestored,
	"RestoreConflict":            derec.CodeRestoreConflict,
	"ReplicaIdConflict":          derec.CodeReplicaIDConflict,
	"FingerprintMismatch":        derec.CodeFingerprintMismatch,
	"Encryption":                 derec.CodeEncryption,
	"Keygen":                     derec.CodeKeygen,
	"FinishPairingInitiator":     derec.CodeFinishPairingInitiator,
	"FinishPairingResponder":     derec.CodeFinishPairingResponder,
	"EmptyTransportUri":          derec.CodeEmptyTransportURI,
	"InvalidContactMessage":      derec.CodeInvalidContactMessage,
	"InvalidPairRequestMessage":  derec.CodeInvalidPairRequestMessage,
	"InvalidPairResponseMessage": derec.CodeInvalidPairResponseMessage,
	"PrepairHashMismatch":        derec.CodePrepairHashMismatch,
	"MissingReplicaId":           derec.CodeMissingReplicaID,
	"UnexpectedReplicaId":        derec.CodeUnexpectedReplicaID,
	"IncompatibleParameterRange": derec.CodeIncompatibleParameterRange,
	"EmptyChannels":              derec.CodeEmptyChannels,
	"DuplicateChannelId":         derec.CodeDuplicateChannelID,
	"InvalidThreshold":           derec.CodeInvalidThreshold,
	"EmptySecretData":            derec.CodeEmptySecretData,
	"VssShareFailed":             derec.CodeVSSShareFailed,
	"InvalidWeight":              derec.CodeInvalidWeight,
	"TooManySubshares":           derec.CodeTooManySubshares,
	"EmptyResponses":             derec.CodeEmptyResponses,
	"EmptyCommittedDeRecShare":   derec.CodeEmptyCommittedDeRecShare,
	"DecodeCommittedDeRecShare":  derec.CodeDecodeCommittedDeRecShare,
	"DecodeDeRecShare":           derec.CodeDecodeDeRecShare,
	"SecretIdMismatch":           derec.CodeSecretIDMismatch,
	"ReconstructionFailed":       derec.CodeReconstructionFailed,
	"MalformedRecoveredSecret":   derec.CodeMalformedRecoveredSecret,
	"FfiNullPtr":                 derec.CodeFFINullPtr,
	"FfiBadLength":               derec.CodeFFIBadLength,
	"FfiBadUtf8":                 derec.CodeFFIBadUTF8,
	"FfiBadProto":                derec.CodeFFIBadProto,
	"FfiInvalidEnum":             derec.CodeFFIInvalidEnum,
	"FfiBadSharedKey":            derec.CodeFFIBadSharedKey,
	"FfiNulInString":             derec.CodeFFINulInString,
	"TransportInvalid":           derec.CodeTransportInvalid,
	"NoUsableEndpoint":           derec.CodeNoUsableEndpoint,
}

func checkNumberToNameEnum(t *testing.T, enumName, prefix string, goValues map[string]int32, name func(int32) string) {
	t.Helper()
	variants := loadNumberToNameEnum(t, enumName)
	wires := map[int32]bool{}
	for _, v := range variants {
		wires[v.Wire] = true
		got, ok := goValues[v.Name]
		if !ok {
			t.Errorf("%s %s (%d) has no Go constant", enumName, v.Name, v.Wire)
			continue
		}
		if got != v.Wire {
			t.Errorf("%s %s: Go has %d, fixture has %d", enumName, v.Name, got, v.Wire)
		}
		if text := name(v.Wire); text != v.Text {
			t.Errorf("%s %d: Go names it %q, fixture %q", enumName, v.Wire, text, v.Text)
		}
	}
	if len(goValues) != len(variants) {
		t.Errorf("%s: fixture lists %d variants, Go maps %d", enumName, len(variants), len(goValues))
	}
	for constName, value := range declaredConstants(t, prefix) {
		if !wires[value] {
			t.Errorf("%s = %d is not a %s in the fixture", constName, value, enumName)
		}
	}
}

func TestErrorCategoriesMatchTheFixture(t *testing.T) {
	checkNumberToNameEnum(t, "DeRecErrorCategory", "Category", fixtureErrorCategories, func(c int32) string {
		return (&derec.Error{Category: c}).CategoryName()
	})
}

func TestErrorCodesMatchTheFixture(t *testing.T) {
	checkNumberToNameEnum(t, "DeRecErrorCode", "Code", fixtureErrorCodes, func(c int32) string {
		return (&derec.Error{Code: c}).CodeName()
	})
}
