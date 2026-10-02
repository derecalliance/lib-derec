// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The error vocabulary every binding reports.
//!
//! A library [`crate::Error`] is classified once, here, into a [`Category`]
//! (the layer or flow that failed) and a [`Code`] (the specific reason). The
//! C ABI carries the numeric discriminants; WASM carries the names. Both come
//! from this table, so the same failure reads the same in every SDK.
//!
//! Errors a binding raises itself, before a value reaches the library, are
//! outside this table's library categories: the C ABI reports them under
//! [`Category::Ffi`] with the `ffi_*` codes, and WASM under its own `wasm`
//! category.

use crate::primitives::{
    discovery::DiscoveryError, pairing::PairingError, recovery::RecoveryError,
    sharing::SharingError, unpairing::UnpairingError, verification::VerificationError,
};

macro_rules! vocabulary {
    ($(#[$meta:meta])* $enum:ident { $($variant:ident = $value:literal => $name:literal,)* }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(i32)]
        pub(crate) enum $enum {
            $($variant = $value,)*
        }

        impl $enum {
            /// Every member, in discriminant order.
            #[cfg_attr(not(test), allow(dead_code))]
            pub(crate) const ALL: &'static [$enum] = &[$($enum::$variant,)*];

            /// The lowercase snake_case name every binding reports.
            #[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
            pub(crate) fn name(self) -> &'static str {
                match self {
                    $($enum::$variant => $name,)*
                }
            }

            /// [`Self::name`], NUL-terminated for the C ABI.
            #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
            pub(crate) fn c_name(self) -> &'static str {
                match self {
                    $($enum::$variant => concat!($name, "\0"),)*
                }
            }

            /// The member with this discriminant, if any.
            #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
            pub(crate) fn from_i32(value: i32) -> Option<Self> {
                match value {
                    $($value => Some($enum::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

vocabulary! {
    /// The layer or flow an error came from.
    Category {
        Ok = 0 => "ok",
        Ffi = 1 => "ffi",
        Pairing = 2 => "pairing",
        Sharing = 3 => "sharing",
        Recovery = 4 => "recovery",
        Verification = 5 => "verification",
        Discovery = 6 => "discovery",
        Unpairing = 7 => "unpairing",
        DeRecMessage = 8 => "derec_message",
        SecretStore = 9 => "secret_store",
        ChannelStore = 10 => "channel_store",
        ShareStore = 11 => "share_store",
        InvalidInput = 12 => "input",
        Protobuf = 13 => "protobuf",
        Invariant = 14 => "invariant",
        StateStore = 15 => "state_store",
    }
}

vocabulary! {
    /// The specific reason for an error. Codes are global: one value means
    /// the same thing in every category.
    Code {
        Ok = 0 => "ok",
        NonOkStatus = 1 => "non_ok_status",
        VersionMismatch = 2 => "version_mismatch",
        Invariant = 3 => "invariant",
        InvalidInput = 4 => "invalid_input",
        ProtobufDecode = 5 => "protobuf_decode",
        ProtobufEncode = 6 => "protobuf_encode",
        ProtocolViolation = 7 => "protocol_violation",
        StoreError = 8 => "store_error",
        BuilderError = 9 => "builder_error",
        MissingSharedKey = 10 => "missing_shared_key",
        RoleMismatch = 11 => "role_mismatch",
        ReplicaIdNotConfigured = 12 => "replica_id_not_configured",
        ChannelAlreadyPaired = 13 => "channel_already_paired",
        AlreadyRestored = 14 => "already_restored",
        RestoreConflict = 15 => "restore_conflict",
        ReplicaIdConflict = 16 => "replica_id_conflict",
        Encryption = 20 => "encryption",
        Keygen = 21 => "keygen",
        FinishPairingInitiator = 22 => "finish_pairing_initiator",
        FinishPairingResponder = 23 => "finish_pairing_responder",
        EmptyTransportUri = 40 => "empty_transport_uri",
        InvalidContactMessage = 41 => "invalid_contact_message",
        InvalidPairRequestMessage = 42 => "invalid_pair_request_message",
        InvalidPairResponseMessage = 43 => "invalid_pair_response_message",
        PrePairHashMismatch = 44 => "prepair_hash_mismatch",
        MissingReplicaId = 45 => "missing_replica_id",
        UnexpectedReplicaId = 46 => "unexpected_replica_id",
        IncompatibleParameterRange = 47 => "incompatible_parameter_range",
        EmptyChannels = 60 => "empty_channels",
        DuplicateChannelId = 61 => "duplicate_channel_id",
        InvalidThreshold = 62 => "invalid_threshold",
        EmptySecretData = 63 => "empty_secret_data",
        VssShareFailed = 64 => "vss_share_failed",
        EmptyResponses = 80 => "empty_responses",
        EmptyCommittedDeRecShare = 81 => "empty_committed_derec_share",
        DecodeCommittedDeRecShare = 82 => "decode_committed_derec_share",
        DecodeDeRecShare = 83 => "decode_derec_share",
        SecretIdMismatch = 84 => "secret_id_mismatch",
        ReconstructionFailed = 85 => "reconstruction_failed",
        MalformedRecoveredSecret = 86 => "malformed_recovered_secret",
        FfiNullPtr = 100 => "ffi_null_ptr",
        FfiBadLength = 101 => "ffi_bad_length",
        FfiBadUtf8 = 102 => "ffi_bad_utf8",
        FfiBadProto = 103 => "ffi_bad_proto",
        FfiInvalidEnum = 104 => "ffi_invalid_enum",
        FfiBadSharedKey = 105 => "ffi_bad_shared_key",
        FfiNulInString = 106 => "ffi_nul_in_string",
        TransportInvalid = 120 => "transport_invalid",
        NoUsableEndpoint = 121 => "no_usable_endpoint",
    }
}

/// Classifies a library error into the category and code every binding
/// reports for it.
pub(crate) fn classify(err: &crate::Error) -> (Category, Code) {
    use crate::Error as E;
    match err {
        E::Pairing(e) => (Category::Pairing, pairing_code(e)),
        E::Recovery(e) => (Category::Recovery, recovery_code(e)),
        E::Discovery(e) => (Category::Discovery, discovery_code(e)),
        E::Sharing(e) => (Category::Sharing, sharing_code(e)),
        E::Verification(e) => (Category::Verification, verification_code(e)),
        E::Unpairing(e) => (Category::Unpairing, unpairing_code(e)),
        E::DeRecMessage(_) => (Category::DeRecMessage, Code::BuilderError),
        E::SecretStore(e) => {
            let code = match e {
                crate::protocol::SecretStoreError::MissingEntries {
                    kind: crate::protocol::SecretKind::SharedKey,
                    ..
                } => Code::MissingSharedKey,
                _ => Code::StoreError,
            };
            (Category::SecretStore, code)
        }
        E::ChannelStore(_) => (Category::ChannelStore, Code::StoreError),
        E::ShareStore(_) => (Category::ShareStore, Code::StoreError),
        E::StateStore(_) => (Category::StateStore, Code::StoreError),
        E::Transport(_) => (Category::InvalidInput, Code::TransportInvalid),
        E::NoUsableEndpoint { .. } => (Category::InvalidInput, Code::NoUsableEndpoint),
        E::InvalidInput(_) => (Category::InvalidInput, Code::InvalidInput),
        E::ProtobufDecode(_) => (Category::Protobuf, Code::ProtobufDecode),
        E::ProtobufEncode(_) => (Category::Protobuf, Code::ProtobufEncode),
        E::Invariant(_) => (Category::Invariant, Code::Invariant),
        E::RoleMismatch { .. } => (Category::InvalidInput, Code::RoleMismatch),
        E::ReplicaIdNotConfigured => (Category::InvalidInput, Code::ReplicaIdNotConfigured),
        E::ReplicaIdConflict { .. } => (Category::InvalidInput, Code::ReplicaIdConflict),
        E::ChannelAlreadyPaired { .. } => (Category::InvalidInput, Code::ChannelAlreadyPaired),
        E::Restore(e) => {
            use crate::protocol::RestoreError;
            match e {
                RestoreError::AlreadyRestored => (Category::InvalidInput, Code::AlreadyRestored),
                RestoreError::Conflict(_) => (Category::InvalidInput, Code::RestoreConflict),
                RestoreError::Invariant(_) => (Category::Invariant, Code::Invariant),
            }
        }
    }
}

fn pairing_code(e: &PairingError) -> Code {
    match e {
        PairingError::EmptyTransportUri => Code::EmptyTransportUri,
        PairingError::InvalidContactMessage(_) => Code::InvalidContactMessage,
        PairingError::InvalidPairRequestMessage(_) => Code::InvalidPairRequestMessage,
        PairingError::InvalidPairResponseMessage(_) => Code::InvalidPairResponseMessage,
        PairingError::NonOkStatus { .. } => Code::NonOkStatus,
        PairingError::ProtocolViolation(_) => Code::ProtocolViolation,
        PairingError::PrePairHashMismatch => Code::PrePairHashMismatch,
        PairingError::MissingReplicaId { .. } => Code::MissingReplicaId,
        PairingError::UnexpectedReplicaId { .. } => Code::UnexpectedReplicaId,
        PairingError::IncompatibleParameterRange { .. } => Code::IncompatibleParameterRange,
        PairingError::Invariant(_) => Code::Invariant,
        PairingError::ContactMessageKeygen { .. } => Code::Keygen,
        PairingError::PairRequestKeygen { .. } => Code::Keygen,
        PairingError::FinishPairingInitiator { .. } => Code::FinishPairingInitiator,
        PairingError::FinishPairingResponder { .. } => Code::FinishPairingResponder,
        PairingError::PairingEncryption(_) => Code::Encryption,
    }
}

fn recovery_code(e: &RecoveryError) -> Code {
    match e {
        RecoveryError::EmptyResponses => Code::EmptyResponses,
        RecoveryError::NonOkStatus { .. } => Code::NonOkStatus,
        RecoveryError::EmptyCommittedDeRecShare => Code::EmptyCommittedDeRecShare,
        RecoveryError::DecodeCommittedDeRecShare { .. } => Code::DecodeCommittedDeRecShare,
        RecoveryError::DecodeDeRecShare { .. } => Code::DecodeDeRecShare,
        RecoveryError::SecretIdMismatch => Code::SecretIdMismatch,
        RecoveryError::VersionMismatch { .. } => Code::VersionMismatch,
        RecoveryError::ReconstructionFailed { .. } => Code::ReconstructionFailed,
        RecoveryError::MalformedRecoveredSecret { .. } => Code::MalformedRecoveredSecret,
    }
}

fn discovery_code(e: &DiscoveryError) -> Code {
    match e {
        DiscoveryError::NonOkStatus { .. } => Code::NonOkStatus,
    }
}

fn sharing_code(e: &SharingError) -> Code {
    match e {
        SharingError::EmptyChannels => Code::EmptyChannels,
        SharingError::DuplicateChannelId(_) => Code::DuplicateChannelId,
        SharingError::InvalidThreshold { .. } => Code::InvalidThreshold,
        SharingError::EmptySecretData => Code::EmptySecretData,
        SharingError::VssShareFailed { .. } => Code::VssShareFailed,
        SharingError::NonOkStatus { .. } => Code::NonOkStatus,
        SharingError::VersionMismatch { .. } => Code::VersionMismatch,
    }
}

fn verification_code(e: &VerificationError) -> Code {
    match e {
        VerificationError::NonOkStatus { .. } => Code::NonOkStatus,
        // The response did not echo the outstanding request: validated wire
        // material that contradicts the session it claims to answer.
        VerificationError::ResponseBindingMismatch { .. } => Code::ProtocolViolation,
    }
}

fn unpairing_code(e: &UnpairingError) -> Code {
    match e {
        UnpairingError::NonOkStatus { .. } => Code::NonOkStatus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_member_round_trips_through_its_discriminant() {
        for &category in Category::ALL {
            assert_eq!(Category::from_i32(category as i32), Some(category));
        }
        for &code in Code::ALL {
            assert_eq!(Code::from_i32(code as i32), Some(code));
        }
        assert_eq!(Code::from_i32(9999), None);
    }

    #[test]
    fn names_are_lowercase_snake_case_and_unique() {
        let is_snake = |name: &str| {
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        };
        let mut seen = std::collections::HashSet::new();
        for &code in Code::ALL {
            assert!(is_snake(code.name()), "{:?}", code);
            assert!(seen.insert(code.name()), "duplicate {}", code.name());
            assert_eq!(code.c_name(), format!("{}\0", code.name()));
        }
        for &category in Category::ALL {
            assert!(is_snake(category.name()), "{:?}", category);
        }
    }

    #[test]
    fn restore_errors_are_classified_like_every_other_error() {
        use crate::protocol::RestoreError;
        assert_eq!(
            classify(&crate::Error::Restore(RestoreError::AlreadyRestored)),
            (Category::InvalidInput, Code::AlreadyRestored)
        );
        assert_eq!(
            classify(&crate::Error::Restore(RestoreError::Conflict(Vec::new()))),
            (Category::InvalidInput, Code::RestoreConflict)
        );
    }
}
