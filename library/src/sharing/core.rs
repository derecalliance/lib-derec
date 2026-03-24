// SPDX-License-Identifier: Apache-2.0

use crate::derec_message::{DeRecMessageBuilder, current_timestamp};
use crate::sharing::{ProtectSecretResult, SharingError};
use crate::types::*;
use crate::utils::generate_seed;
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecShare, StoreShareRequestMessage, committed_de_rec_share::SiblingHash,
};
use prost::Message;
use std::collections::HashMap;

/// Current share algorithm identifier embedded into [`StoreShareRequestMessage`].
///
/// At present the sharing flow uses the library's VSS-based share generation and
/// encodes that choice using the protocol value `0`.
const SHARE_ALGORITHM_VSS: i32 = 0;

/// Protects a secret by generating verifiable secret shares and preparing one
/// serialized [`derec_proto::DeRecMessage`] envelope per helper channel.
///
/// In DeRec, the *sharing* flow splits a secret into independently verifiable
/// shares using a Verifiable Secret Sharing (VSS) scheme. Each generated share is:
///
/// - Bound to a specific `secret_id` and `version`
/// - Committed using a Merkle commitment and proof
/// - Wrapped into a [`StoreShareRequestMessage`]
/// - Serialized and symmetrically encrypted with the helper’s previously established
///   shared channel key
/// - Embedded into the `message` field of a plain outer [`derec_proto::DeRecMessage`] envelope
///
/// The result is one serialized envelope per [`ChannelId`], ready to be sent to the
/// corresponding previously paired helper.
///
/// # Deterministic channel/share assignment
///
/// The input `channels` map is first converted into a deterministically ordered list
/// sorted by [`ChannelId`]. Generated VSS shares are then assigned in that sorted order.
///
/// This avoids relying on `HashMap` iteration order when pairing shares with helpers.
///
/// # Arguments
///
/// * `secret_id` - Identifier of the secret being protected. This value is embedded
///   into each generated share and is later used during verification and recovery.
///   Must not be empty.
/// * `secret_data` - Raw secret bytes to split using VSS. Must not be empty.
/// * `channels` - Mapping from helper [`ChannelId`] to the 32-byte shared symmetric key
///   previously established during pairing. Each entry receives exactly one encrypted
///   share envelope. Must not be empty.
/// * `threshold` - Minimum number of shares required to reconstruct the secret.
///   Must satisfy `2 <= threshold <= channels.len()`.
/// * `version` - Logical version of this secret distribution. This value is embedded
///   into each generated share and echoed in the outer share-request message.
/// * `keep_list` - Optional list of version numbers helpers should retain.
///   If `None`, an empty list is used.
/// * `description` - Optional human-readable description of this version.
///   If `None`, an empty string is used.
///
/// # Returns
///
/// On success returns [`ProtectSecretResult`] containing:
///
/// - `shares`: `HashMap<ChannelId, Vec<u8>>` — a mapping from each helper channel
///   to a serialized outer [`derec_proto::DeRecMessage`] envelope. The envelope’s
///   `message` field contains the encrypted serialized [`StoreShareRequestMessage`].
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Sharing(...)`) in the following cases:
///
/// - [`SharingError::EmptyChannels`] if `channels` is empty
/// - [`SharingError::EmptySecretId`] if `secret_id` is empty
/// - [`SharingError::EmptySecretData`] if `secret_data` is empty
/// - [`SharingError::InvalidThreshold`] if `threshold` does not satisfy
///   `2 <= threshold <= channels.len()`
/// - [`SharingError::VssShareFailed`] if the underlying VSS algorithm fails
/// - outer envelope construction or symmetric encryption fails
///
/// # Security Notes
///
/// - This function uses cryptographically secure randomness for VSS generation
/// - Each inner [`StoreShareRequestMessage`] is encrypted with that helper’s shared key
/// - The outer [`derec_proto::DeRecMessage`] envelope is plain protobuf metadata and
///   is not itself encrypted
/// - The outer envelope timestamp is set to the same value as the inner
///   [`StoreShareRequestMessage::timestamp`] to preserve the invariant that both
///   timestamps match
/// - The caller is responsible for securely managing the original `secret_data` if local
///   retention is required
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
/// use std::collections::HashMap;
///
/// let secret_id = b"my_secret";
/// let secret_data = b"super_secret_value";
///
/// let mut channels: HashMap<ChannelId, [u8; 32]> = HashMap::new();
/// channels.insert(ChannelId(1), [1u8; 32]);
/// channels.insert(ChannelId(2), [2u8; 32]);
/// channels.insert(ChannelId(3), [3u8; 32]);
///
/// let ProtectSecretResult { shares } = protect_secret(
///     secret_id,
///     secret_data,
///     channels,
///     2,
///     1,
///     None,
///     None,
/// ).expect("sharing failed");
///
/// assert_eq!(shares.len(), 3);
/// ```
pub fn protect_secret(
    secret_id: impl AsRef<[u8]>,
    secret_data: impl AsRef<[u8]>,
    channels: HashMap<ChannelId, [u8; 32]>,
    threshold: usize,
    version: i32,
    keep_list: Option<&[i32]>,
    description: Option<&str>,
) -> Result<ProtectSecretResult, crate::Error> {
    let secret_id = secret_id.as_ref();
    let secret_data = secret_data.as_ref();

    if channels.is_empty() {
        return Err(SharingError::EmptyChannels.into());
    }

    if secret_id.is_empty() {
        return Err(SharingError::EmptySecretId.into());
    }

    if secret_data.is_empty() {
        return Err(SharingError::EmptySecretData.into());
    }

    let channel_count = channels.len();

    if threshold < 2 || threshold > channel_count {
        return Err(SharingError::InvalidThreshold {
            threshold,
            channels: channel_count,
        }
        .into());
    }

    let vss_shares = generate_vss_shares(secret_data, threshold, channel_count)?;
    let keep_list = keep_list.map(|lst| lst.to_vec()).unwrap_or_default();
    let version_description = description.unwrap_or_default().to_owned();

    // Make channel/share assignment deterministic instead of relying on HashMap
    // iteration order.
    let mut ordered_channels: Vec<_> = channels.into_iter().collect();
    ordered_channels.sort_by_key(|(channel_id, _)| <u64 as From<ChannelId>>::from(*channel_id));

    let mut shares = HashMap::with_capacity(channel_count);

    for ((channel_id, shared_key), share) in
        ordered_channels.into_iter().zip(vss_shares.into_iter())
    {
        let derec_share = DeRecShare {
            encrypted_secret: share.encrypted_secret,
            x: share.x,
            y: share.y,
            secret_id: secret_id.to_vec(),
            version,
        };

        let committed_derec_share = CommittedDeRecShare {
            de_rec_share: derec_share.encode_to_vec(),
            commitment: share.commitment,
            merkle_path: share
                .merkle_path
                .into_iter()
                .map(|(is_left, hash)| SiblingHash { is_left, hash })
                .collect(),
        };

        let timestamp = current_timestamp();

        let message = StoreShareRequestMessage {
            share: committed_derec_share.encode_to_vec(),
            share_algorithm: SHARE_ALGORITHM_VSS,
            version,
            keep_list: keep_list.clone(),
            version_description: version_description.clone(),
            timestamp: Some(timestamp),
        };

        let wire_bytes = DeRecMessageBuilder::channel()
            .channel_id(channel_id)
            .timestamp(timestamp)
            .message(&message)
            .encrypt(&shared_key)?
            .build()?
            .encode_to_vec();

        shares.insert(channel_id, wire_bytes);
    }

    Ok(ProtectSecretResult { shares })
}

fn generate_vss_shares(
    secret_data: &[u8],
    threshold: usize,
    channels_len: usize,
) -> Result<Vec<derec_cryptography::vss::VSSShare>, SharingError> {
    let entropy = generate_seed::<32>();
    let t = threshold as u64;
    let n = channels_len as u64;

    vss::share((t, n), secret_data, &entropy)
        .map_err(|source| SharingError::VssShareFailed { source })
}
