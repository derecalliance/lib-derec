// SPDX-License-Identifier: Apache-2.0

use crate::sharing::{ProtectSecretResult, SharingError};
use crate::types::*;
use crate::utils::generate_seed;
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecShare, StoreShareRequestMessage, committed_de_rec_share::SiblingHash,
};
use prost::Message;
use std::collections::{HashMap, HashSet};

/// Protects a secret by generating verifiable secret shares and preparing
/// protocol messages for distribution to previously paired helpers.
///
/// In DeRec, the *sharing* flow is responsible for splitting a secret into
/// multiple independently verifiable shares using a Verifiable Secret Sharing (VSS) scheme.
/// Each share is:
///
/// - Bound to a specific `secret_id` and `version`
/// - Committed (Merkle commitment + proof)
/// - Wrapped into a [`StoreShareRequestMessage`] suitable for transmission
///   over the DeRec transport layer (relay, BLE, etc.)
///
/// The returned messages are **not encrypted by this function**. They are
/// protocol-level payloads that must later be signed and encrypted according
/// to the DeRec wire rules before being transmitted to helpers.
///
/// # Arguments
///
/// * `secret_id` - Identifier of the secret being protected. This value is
///   embedded into each generated share and is used later during verification
///   and recovery flows. Must not be empty.
/// * `secret_data` - The raw secret bytes to split using VSS. Must not be empty.
/// * `channels` - Identifiers of the previously paired helpers (e.g. channel IDs
///   derived from pairing). Each channel will receive exactly one share.
///   Must not be empty.
/// * `threshold` - Minimum number of shares required to reconstruct the secret.
///   Must satisfy `2 <= threshold <= channels.len()`.
/// * `version` - Logical version of this secret distribution. Allows rotation,
///   refresh, or re-sharing while preserving history.
/// * `keep_list` - Optional list of version numbers that helpers should retain.
///   If `None`, an empty list is used.
/// * `description` - Optional human-readable description of this secret version.
///   If `None`, an empty string is used.
///
/// # Returns
///
/// On success returns [`ProtectSecretResult`] containing:
///
/// - `shares`: `HashMap<ChannelId, StoreShareRequestMessage>` —
///   a mapping from each channel to its corresponding share message.
///   Each entry is ready to be signed, encrypted, and sent to that helper.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Sharing(...)`) in the following cases:
///
/// - `SharingError::EmptyChannels` if `channels` is empty.
/// - `SharingError::DuplicateChannels` if `channels` contains duplicated values.
/// - `SharingError::EmptySecretId` if `secret_id` is empty.
/// - `SharingError::EmptySecretData` if `secret_data` is empty.
/// - `SharingError::InvalidThreshold { .. }` if `threshold` does not satisfy
///   `2 <= threshold <= channels.len()`.
/// - `SharingError::VssShareFailed { .. }` if the underlying VSS algorithm fails.
///
/// # Security Notes
///
/// - This function uses the OS CSPRNG (`OsRng`) to generate entropy required
///   by the VSS scheme.
/// - The generated shares include commitments and Merkle proofs, enabling
///   helpers to verify integrity.
/// - The returned messages are protocol payloads only; callers must ensure
///   they are signed and encrypted before transmission.
/// - The caller is responsible for securely storing the original `secret_data`
///   if local retention is required.
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
///
/// let secret_id = b"my_secret";
/// let secret_data = b"super_secret_value";
/// let channels: Vec<ChannelId> = [1, 2, 3].into_iter().map(ChannelId::from).collect();
/// let threshold = 2;
/// let version = 1;
///
/// let ProtectSecretResult { shares } = protect_secret(
///     secret_id,
///     secret_data,
///     &channels,
///     threshold,
///     version,
///     None,
///     None,
/// ).expect("sharing failed");
///
/// assert_eq!(shares.len(), 3);
/// ```
pub fn protect_secret(
    secret_id: impl AsRef<[u8]>,
    secret_data: impl AsRef<[u8]>,
    channels: impl AsRef<[ChannelId]>,
    threshold: usize,
    version: i32,
    keep_list: Option<&[i32]>,
    description: Option<&str>,
) -> Result<ProtectSecretResult, crate::Error> {
    let secret_id = secret_id.as_ref();
    let secret_data = secret_data.as_ref();
    let channels = channels.as_ref();

    if channels.is_empty() {
        return Err(SharingError::EmptyChannels.into());
    }

    let unique: HashSet<_> = channels.iter().copied().collect();
    if unique.len() != channels.len() {
        return Err(SharingError::DuplicateChannels.into());
    }

    if secret_id.is_empty() {
        return Err(SharingError::EmptySecretId.into());
    }

    if secret_data.is_empty() {
        return Err(SharingError::EmptySecretData.into());
    }

    if threshold < 2 || threshold > channels.len() {
        return Err(SharingError::InvalidThreshold {
            threshold,
            channels: channels.len(),
        }
        .into());
    }

    let vss_shares = generate_vss_shares(secret_data, threshold, channels.len())?;
    let keep_list = keep_list.map(|lst| lst.to_vec()).unwrap_or_default();
    let version_description = description.unwrap_or_default().to_owned();

    let mut shares = HashMap::with_capacity(channels.len());

    for (channel, share) in channels.iter().zip(vss_shares.iter()) {
        let derec_share = DeRecShare {
            encrypted_secret: share.encrypted_secret.to_owned(),
            x: share.x.to_owned(),
            y: share.y.to_owned(),
            secret_id: secret_id.to_vec(),
            version,
        };

        let committed_derec_share = CommittedDeRecShare {
            de_rec_share: derec_share.encode_to_vec(),
            commitment: share.commitment.to_owned(),
            merkle_path: share
                .merkle_path
                .iter()
                .map(|(is_left, hash)| SiblingHash {
                    is_left: *is_left,
                    hash: hash.to_owned(),
                })
                .collect(),
        };

        let outbound_msg = StoreShareRequestMessage {
            share: committed_derec_share.encode_to_vec(),
            share_algorithm: 0,
            version,
            keep_list: keep_list.clone(),
            version_description: version_description.clone(),
        };

        shares.insert(*channel, outbound_msg);
    }

    Ok(ProtectSecretResult { shares })
}

fn generate_vss_shares(
    secret_data: &[u8],
    threshold: usize,
    channels_len: usize,
) -> Result<Vec<derec_cryptography::vss::VSSShare>, SharingError> {
    let entropy = generate_seed::<32>();

    let (t, n) = (threshold as u64, channels_len as u64);

    vss::share((t, n), secret_data, &entropy)
        .map_err(|source| SharingError::VssShareFailed { source })
}
