// SPDX-License-Identifier: Apache-2.0
#![allow(dead_code)]

//! Typed error envelope for the DeRec C FFI.
//!
//! Every fallible FFI function returns a [`DeRecError`] embedded in its result
//! struct. A successful call has `category == DEREC_CATEGORY_OK`; any other
//! value indicates failure.
//!
//! Reading the error:
//!
//! 1. Check `category` to identify the protocol phase or layer that failed
//!    (`DEREC_CATEGORY_*`).
//! 2. Inspect `code` for the specific reason (`DEREC_CODE_*`). Codes are
//!    global — the same value means the same thing across categories.
//! 3. Read structured fields conditionally: `peer_status` / `peer_memo` are
//!    valid when `code == DEREC_CODE_NON_OK_STATUS`; `expected` / `got` are
//!    valid when `code == DEREC_CODE_VERSION_MISMATCH`.
//! 4. Treat `message` as human-readable only — never parse it.
//!
//! Call [`derec_free_error`] exactly once per error returned by the SDK to
//! release the owned strings (no-op on success errors).

use std::ffi::CString;
use std::os::raw::c_char;

use crate::primitives::{
    discovery::DiscoveryError, pairing::PairingError, recovery::RecoveryError,
    sharing::SharingError, unpairing::UnpairingError, verification::VerificationError,
};

#[repr(C)]
pub struct DeRecError {
    pub category: i32,
    pub code: i32,
    /// Owned C string. Null on success. Released by [`derec_free_error`].
    pub message: *mut c_char,
    /// Valid when `code == DEREC_CODE_NON_OK_STATUS`.
    pub peer_status: i32,
    /// Owned C string. Null when not applicable. Released by [`derec_free_error`].
    pub peer_memo: *mut c_char,
    /// Valid when `code == DEREC_CODE_VERSION_MISMATCH`.
    pub expected: u32,
    /// Valid when `code == DEREC_CODE_VERSION_MISMATCH`.
    pub got: u32,
}

pub const DEREC_CATEGORY_OK: i32 = 0;
pub const DEREC_CATEGORY_FFI: i32 = 1;
pub const DEREC_CATEGORY_PAIRING: i32 = 2;
pub const DEREC_CATEGORY_SHARING: i32 = 3;
pub const DEREC_CATEGORY_RECOVERY: i32 = 4;
pub const DEREC_CATEGORY_VERIFICATION: i32 = 5;
pub const DEREC_CATEGORY_DISCOVERY: i32 = 6;
pub const DEREC_CATEGORY_UNPAIRING: i32 = 7;
pub const DEREC_CATEGORY_DEREC_MESSAGE: i32 = 8;
pub const DEREC_CATEGORY_SECRET_STORE: i32 = 9;
pub const DEREC_CATEGORY_CHANNEL_STORE: i32 = 10;
pub const DEREC_CATEGORY_SHARE_STORE: i32 = 11;
pub const DEREC_CATEGORY_INVALID_INPUT: i32 = 12;
pub const DEREC_CATEGORY_PROTOBUF: i32 = 13;
pub const DEREC_CATEGORY_INVARIANT: i32 = 14;

pub const DEREC_CODE_OK: i32 = 0;
pub const DEREC_CODE_NON_OK_STATUS: i32 = 1;
pub const DEREC_CODE_VERSION_MISMATCH: i32 = 2;
pub const DEREC_CODE_INVARIANT: i32 = 3;
pub const DEREC_CODE_INVALID_INPUT: i32 = 4;
pub const DEREC_CODE_PROTOBUF_DECODE: i32 = 5;
pub const DEREC_CODE_PROTOBUF_ENCODE: i32 = 6;
pub const DEREC_CODE_PROTOCOL_VIOLATION: i32 = 7;
pub const DEREC_CODE_STORE_ERROR: i32 = 8;
pub const DEREC_CODE_BUILDER_ERROR: i32 = 9;
/// `SecretStore::load_many(.., MissingPolicy::Fail)` returned because one or
/// more channels had no `SharedKey` entry. The formatted `message` carries
/// the missing channel ids (e.g. `"secret store: missing SharedKey entries
/// for channel(s): [42, 7]"`). `category` is
/// [`DEREC_CATEGORY_SECRET_STORE`].
pub const DEREC_CODE_MISSING_SHARED_KEY: i32 = 10;

pub const DEREC_CODE_ENCRYPTION: i32 = 20;
pub const DEREC_CODE_KEYGEN: i32 = 21;
pub const DEREC_CODE_FINISH_PAIRING_INITIATOR: i32 = 22;
pub const DEREC_CODE_FINISH_PAIRING_RESPONDER: i32 = 23;

pub const DEREC_CODE_EMPTY_TRANSPORT_URI: i32 = 40;
pub const DEREC_CODE_INVALID_CONTACT_MESSAGE: i32 = 41;
pub const DEREC_CODE_INVALID_PAIR_REQUEST_MESSAGE: i32 = 42;
pub const DEREC_CODE_INVALID_PAIR_RESPONSE_MESSAGE: i32 = 43;

pub const DEREC_CODE_EMPTY_CHANNELS: i32 = 60;
pub const DEREC_CODE_DUPLICATE_CHANNEL_ID: i32 = 61;
pub const DEREC_CODE_INVALID_THRESHOLD: i32 = 62;
pub const DEREC_CODE_EMPTY_SECRET_DATA: i32 = 63;
pub const DEREC_CODE_VSS_SHARE_FAILED: i32 = 64;

pub const DEREC_CODE_EMPTY_RESPONSES: i32 = 80;
pub const DEREC_CODE_EMPTY_COMMITTED_DEREC_SHARE: i32 = 81;
pub const DEREC_CODE_DECODE_COMMITTED_DEREC_SHARE: i32 = 82;
pub const DEREC_CODE_DECODE_DEREC_SHARE: i32 = 83;
pub const DEREC_CODE_SECRET_ID_MISMATCH: i32 = 84;
pub const DEREC_CODE_RECONSTRUCTION_FAILED: i32 = 85;

pub const DEREC_CODE_FFI_NULL_PTR: i32 = 100;
pub const DEREC_CODE_FFI_BAD_LENGTH: i32 = 101;
pub const DEREC_CODE_FFI_BAD_UTF8: i32 = 102;
pub const DEREC_CODE_FFI_BAD_PROTO: i32 = 103;
pub const DEREC_CODE_FFI_INVALID_ENUM: i32 = 104;
pub const DEREC_CODE_FFI_BAD_SHARED_KEY: i32 = 105;
pub const DEREC_CODE_FFI_NUL_IN_STRING: i32 = 106;

pub(crate) fn success() -> DeRecError {
    DeRecError {
        category: DEREC_CATEGORY_OK,
        code: DEREC_CODE_OK,
        message: std::ptr::null_mut(),
        peer_status: 0,
        peer_memo: std::ptr::null_mut(),
        expected: 0,
        got: 0,
    }
}

pub(crate) fn ffi_error(code: i32, msg: impl AsRef<str>) -> DeRecError {
    DeRecError {
        category: DEREC_CATEGORY_FFI,
        code,
        message: to_owned_cstring(msg.as_ref()),
        peer_status: 0,
        peer_memo: std::ptr::null_mut(),
        expected: 0,
        got: 0,
    }
}

/// Maps a [`crate::Error`] into a typed FFI error. Single source of truth for
/// category/code mapping — extend the arms here when adding new variants.
pub(crate) fn from_lib_error(err: crate::Error) -> DeRecError {
    let (category, code) = categorize(&err);
    let message = to_owned_cstring(&err.to_string());

    let (peer_status, peer_memo) = err
        .as_non_ok_status()
        .map(|(s, m)| (s, to_owned_cstring(m)))
        .unwrap_or((0, std::ptr::null_mut()));

    let (expected, got) = match &err {
        crate::Error::Sharing(SharingError::VersionMismatch { expected, got })
        | crate::Error::Recovery(RecoveryError::VersionMismatch { expected, got }) => {
            (*expected, *got)
        }
        _ => (0, 0),
    };

    DeRecError {
        category,
        code,
        message,
        peer_status,
        peer_memo,
        expected,
        got,
    }
}

/// Releases the owned strings carried by a [`DeRecError`]. No-op when both
/// pointers are null.
///
/// # Safety
///
/// `error` must have been returned by the DeRec SDK and not previously freed.
#[unsafe(no_mangle)]
pub extern "C" fn derec_free_error(error: DeRecError) {
    if !error.message.is_null() {
        unsafe { drop(CString::from_raw(error.message)) };
    }
    if !error.peer_memo.is_null() {
        unsafe { drop(CString::from_raw(error.peer_memo)) };
    }
}

fn categorize(err: &crate::Error) -> (i32, i32) {
    match err {
        crate::Error::Pairing(e) => (DEREC_CATEGORY_PAIRING, pairing_code(e)),
        crate::Error::Recovery(e) => (DEREC_CATEGORY_RECOVERY, recovery_code(e)),
        crate::Error::Discovery(e) => (DEREC_CATEGORY_DISCOVERY, discovery_code(e)),
        crate::Error::Sharing(e) => (DEREC_CATEGORY_SHARING, sharing_code(e)),
        crate::Error::Verification(e) => (DEREC_CATEGORY_VERIFICATION, verification_code(e)),
        crate::Error::Unpairing(e) => (DEREC_CATEGORY_UNPAIRING, unpairing_code(e)),
        crate::Error::DeRecMessage(_) => (DEREC_CATEGORY_DEREC_MESSAGE, DEREC_CODE_BUILDER_ERROR),
        crate::Error::SecretStore(e) => {
            let code = match e {
                crate::protocol::SecretStoreError::MissingEntries {
                    kind: crate::protocol::SecretKind::SharedKey,
                    ..
                } => DEREC_CODE_MISSING_SHARED_KEY,
                _ => DEREC_CODE_STORE_ERROR,
            };
            (DEREC_CATEGORY_SECRET_STORE, code)
        }
        crate::Error::ChannelStore(_) => (DEREC_CATEGORY_CHANNEL_STORE, DEREC_CODE_STORE_ERROR),
        crate::Error::ShareStore(_) => (DEREC_CATEGORY_SHARE_STORE, DEREC_CODE_STORE_ERROR),
        crate::Error::InvalidInput(_) => (DEREC_CATEGORY_INVALID_INPUT, DEREC_CODE_INVALID_INPUT),
        crate::Error::ProtobufDecode(_) => (DEREC_CATEGORY_PROTOBUF, DEREC_CODE_PROTOBUF_DECODE),
        crate::Error::ProtobufEncode(_) => (DEREC_CATEGORY_PROTOBUF, DEREC_CODE_PROTOBUF_ENCODE),
        crate::Error::Invariant(_) => (DEREC_CATEGORY_INVARIANT, DEREC_CODE_INVARIANT),
    }
}

fn pairing_code(e: &PairingError) -> i32 {
    match e {
        PairingError::EmptyTransportUri => DEREC_CODE_EMPTY_TRANSPORT_URI,
        PairingError::InvalidContactMessage(_) => DEREC_CODE_INVALID_CONTACT_MESSAGE,
        PairingError::InvalidPairRequestMessage(_) => DEREC_CODE_INVALID_PAIR_REQUEST_MESSAGE,
        PairingError::InvalidPairResponseMessage(_) => DEREC_CODE_INVALID_PAIR_RESPONSE_MESSAGE,
        PairingError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
        PairingError::ProtocolViolation(_) => DEREC_CODE_PROTOCOL_VIOLATION,
        PairingError::Invariant(_) => DEREC_CODE_INVARIANT,
        PairingError::ContactMessageKeygen { .. } => DEREC_CODE_KEYGEN,
        PairingError::PairRequestKeygen { .. } => DEREC_CODE_KEYGEN,
        PairingError::FinishPairingInitiator { .. } => DEREC_CODE_FINISH_PAIRING_INITIATOR,
        PairingError::FinishPairingResponder { .. } => DEREC_CODE_FINISH_PAIRING_RESPONDER,
        PairingError::PairingEncryption(_) => DEREC_CODE_ENCRYPTION,
    }
}

fn recovery_code(e: &RecoveryError) -> i32 {
    match e {
        RecoveryError::EmptyResponses => DEREC_CODE_EMPTY_RESPONSES,
        RecoveryError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
        RecoveryError::EmptyCommittedDeRecShare => DEREC_CODE_EMPTY_COMMITTED_DEREC_SHARE,
        RecoveryError::DecodeCommittedDeRecShare { .. } => DEREC_CODE_DECODE_COMMITTED_DEREC_SHARE,
        RecoveryError::DecodeDeRecShare { .. } => DEREC_CODE_DECODE_DEREC_SHARE,
        RecoveryError::SecretIdMismatch => DEREC_CODE_SECRET_ID_MISMATCH,
        RecoveryError::VersionMismatch { .. } => DEREC_CODE_VERSION_MISMATCH,
        RecoveryError::ReconstructionFailed { .. } => DEREC_CODE_RECONSTRUCTION_FAILED,
    }
}

fn discovery_code(e: &DiscoveryError) -> i32 {
    match e {
        DiscoveryError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
    }
}

fn sharing_code(e: &SharingError) -> i32 {
    match e {
        SharingError::EmptyChannels => DEREC_CODE_EMPTY_CHANNELS,
        SharingError::DuplicateChannelId(_) => DEREC_CODE_DUPLICATE_CHANNEL_ID,
        SharingError::InvalidThreshold { .. } => DEREC_CODE_INVALID_THRESHOLD,
        SharingError::EmptySecretData => DEREC_CODE_EMPTY_SECRET_DATA,
        SharingError::VssShareFailed { .. } => DEREC_CODE_VSS_SHARE_FAILED,
        SharingError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
        SharingError::VersionMismatch { .. } => DEREC_CODE_VERSION_MISMATCH,
    }
}

fn verification_code(e: &VerificationError) -> i32 {
    match e {
        VerificationError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
    }
}

fn unpairing_code(e: &UnpairingError) -> i32 {
    match e {
        UnpairingError::NonOkStatus { .. } => DEREC_CODE_NON_OK_STATUS,
    }
}

fn to_owned_cstring(s: &str) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("internal error: string contains NUL").unwrap())
        .into_raw()
}
