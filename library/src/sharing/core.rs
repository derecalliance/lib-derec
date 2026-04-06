// SPDX-License-Identifier: Apache-2.0

use crate::derec_message::{self, DeRecMessageBuilder, current_timestamp};
use crate::sharing::{
    ProduceStoreShareRequestMessageResult, ProduceStoreShareResponseMessageResult,
    ProtectSecretResult, SharingError,
};
use crate::types::*;
use crate::utils::generate_seed;
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecResult, DeRecShare, StatusEnum, StoreShareRequestMessage,
    StoreShareResponseMessage, committed_de_rec_share::SiblingHash,
};
use prost::Message;
use std::collections::HashMap;

/// Current share algorithm identifier embedded into [`derec_proto::StoreShareRequestMessage`].
///
/// At present the sharing flow uses the library's VSS-based share generation and
/// encodes that choice using the protocol value `0`.
const SHARE_ALGORITHM_VSS: i32 = 0;

/// Protects a secret by generating verifiable secret shares.
///
/// In DeRec, the *sharing* flow splits a secret into independently verifiable
/// shares using a Verifiable Secret Sharing (VSS) scheme. Each generated share is:
///
/// - Bound to a specific `secret_id` and `version`
/// - Committed using a Merkle commitment and proof
/// - Returned as a [`CommittedDeRecShare`] ready to be delivered to its helper
///
/// To send a share to a helper, pass the returned [`CommittedDeRecShare`] to
/// `produce_store_share_request_message` together with the helper's shared key
/// to produce the encrypted delivery envelope.
///
/// # Deterministic channel/share assignment
///
/// The input `channels` slice is sorted by [`ChannelId`] before shares are assigned.
/// Generated VSS shares are assigned in that sorted order. Duplicate channel IDs are
/// rejected with [`SharingError::DuplicateChannelId`].
///
/// # Arguments
///
/// * `secret_id` - Identifier of the secret being protected. Embedded into each
///   generated share. Must not be empty.
/// * `secret_data` - Raw secret bytes to split using VSS. Must not be empty.
/// * `channels` - Slice of helper [`ChannelId`] values. Each entry receives exactly
///   one committed share. Must not be empty. Duplicate entries are deduplicated.
/// * `threshold` - Minimum number of shares required to reconstruct the secret.
///   Must satisfy `2 <= threshold <= channels.len()` (after deduplication).
/// * `version` - Logical version of this secret distribution. Embedded into each
///   generated share.
///
/// # Returns
///
/// On success returns [`ProtectSecretResult`] containing:
///
/// - `shares`: `HashMap<ChannelId, CommittedDeRecShare>` — one committed share per channel.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Sharing(...)`) in the following cases:
///
/// - [`SharingError::EmptyChannels`] if `channels` is empty
/// - [`SharingError::EmptySecretId`] if `secret_id` is empty
/// - [`SharingError::EmptySecretData`] if `secret_data` is empty
/// - [`SharingError::DuplicateChannelId`] if `channels` contains any repeated ID
/// - [`SharingError::InvalidThreshold`] if `threshold` does not satisfy
///   `2 <= threshold <= channels.len()`
/// - [`SharingError::VssShareFailed`] if the underlying VSS algorithm fails
///
/// # Security Notes
///
/// - This function uses cryptographically secure randomness for VSS generation
/// - The caller is responsible for securely managing the original `secret_data`
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
///
/// let secret_id = b"my_secret";
/// let secret_data = b"super_secret_value";
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
///
/// let ProtectSecretResult { shares } = protect_secret(
///     secret_id,
///     secret_data,
///     &channels,
///     2,
///     1,
/// ).expect("sharing failed");
///
/// assert_eq!(shares.len(), 3);
/// ```
pub fn protect_secret(
    secret_id: impl AsRef<[u8]>,
    secret_data: impl AsRef<[u8]>,
    channels: &[ChannelId],
    threshold: usize,
    version: i32,
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

    // Sort channels for deterministic share assignment, then reject any duplicates.
    let mut ordered_channels: Vec<ChannelId> = channels.to_vec();
    ordered_channels.sort();
    for pair in ordered_channels.windows(2) {
        if pair[0] == pair[1] {
            return Err(SharingError::DuplicateChannelId(pair[0].into()).into());
        }
    }

    let channel_count = ordered_channels.len();

    if threshold < 2 || threshold > channel_count {
        return Err(SharingError::InvalidThreshold {
            threshold,
            channels: channel_count,
        }
        .into());
    }

    let vss_shares = generate_vss_shares(secret_data, threshold, channel_count)?;

    let mut shares = HashMap::with_capacity(channel_count);

    for (channel_id, share) in ordered_channels.into_iter().zip(vss_shares.into_iter()) {
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

        shares.insert(channel_id, committed_derec_share);
    }

    Ok(ProtectSecretResult { shares })
}

/// Wraps a [`CommittedDeRecShare`] into an encrypted [`derec_proto::DeRecMessage`] envelope
/// carrying a [`derec_proto::StoreShareRequestMessage`] inner payload.
///
/// Call this once for each share returned by [`protect_secret`], providing the corresponding
/// helper's shared key (established during pairing). The resulting wire bytes should be sent
/// to the helper over the channel transport and stored by the helper for future verification
/// and recovery requests.
///
/// # Arguments
///
/// * `channel_id` - The helper channel this share belongs to.
/// * `version` - Share-distribution version, matching the value passed to [`protect_secret`].
/// * `committed_share` - The share for this channel, as returned by [`protect_secret`].
/// * `keep_list` - Ordered list of version numbers the helper should retain. Pass an empty
///   slice to let the helper apply its default retention policy.
/// * `description` - Human-readable description of this share distribution. May be empty.
/// * `shared_key` - 256-bit symmetric key shared with this helper, derived during pairing.
///
/// # Returns
///
/// On success returns [`ProduceStoreShareRequestMessageResult`] containing:
///
/// - `wire_bytes`: serialized [`derec_proto::DeRecMessage`] envelope carrying an encrypted
///   [`derec_proto::StoreShareRequestMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if envelope construction or symmetric encryption fails.
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let ProtectSecretResult { shares } = protect_secret(
///     b"my_secret_id",
///     b"super_secret_value",
///     &channels,
///     2,
///     1,
/// ).expect("sharing failed");
///
/// let shared_key = [42u8; 32];
/// let channel_id = ChannelId(1);
/// let committed_share = shares.get(&channel_id).expect("missing share");
///
/// let ProduceStoreShareRequestMessageResult { wire_bytes } =
///     produce_store_share_request_message(
///         channel_id,
///         1,
///         committed_share,
///         &[],
///         "",
///         &shared_key,
///     ).expect("produce_store_share_request_message failed");
///
/// assert!(!wire_bytes.is_empty());
/// ```
pub fn produce_store_share_request_message(
    channel_id: ChannelId,
    version: i32,
    committed_share: &CommittedDeRecShare,
    keep_list: &[i32],
    description: impl Into<String>,
    shared_key: &[u8; 32],
) -> Result<ProduceStoreShareRequestMessageResult, crate::Error> {
    let timestamp = current_timestamp();

    let msg = StoreShareRequestMessage {
        share: committed_share.encode_to_vec(),
        share_algorithm: SHARE_ALGORITHM_VSS,
        version,
        keep_list: keep_list.to_vec(),
        version_description: description.into(),
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&msg)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(ProduceStoreShareRequestMessageResult { wire_bytes })
}

/// Processes an incoming [`derec_proto::StoreShareRequestMessage`] on behalf of a Helper,
/// returning an encrypted response and the committed share to persist locally.
///
/// This function is executed by a **Helper** upon receiving a sharing request from an Owner.
/// It:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `request_bytes`
/// 2. Decrypts and decodes the inner [`StoreShareRequestMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
/// 4. Decodes the embedded [`CommittedDeRecShare`] from the request's `share` field
/// 5. Validates that `commitment` and `merkle_path` are non-empty
/// 6. Verifies the Merkle proof: recomputes the root from `(x, y)` and the path,
///    and rejects the share if it does not match `commitment`
/// 7. Constructs a [`StoreShareResponseMessage`] with `status = Ok`
/// 8. Encrypts and wraps the response into a new [`derec_proto::DeRecMessage`] envelope
///
/// The Helper must persist `committed_share` from the returned result for future verification
/// and recovery requests. The encrypted request bytes received on the wire (`request_bytes`)
/// must also be retained — they are used as the `share_content` parameter of
/// `generate_verification_response` and `generate_share_response`.
///
/// # Arguments
///
/// * `channel_id` - The channel this request arrived on. Used to build the response envelope.
/// * `shared_key` - 256-bit symmetric key shared with the Owner, established during pairing.
///   Used to decrypt the request and encrypt the response.
/// * `request_bytes` - Serialized [`derec_proto::DeRecMessage`] envelope bytes received from
///   the Owner, as produced by [`produce_store_share_request_message`].
///
/// # Returns
///
/// On success returns [`ProcessStoreShareRequestMessageResult`] containing:
///
/// - `wire_bytes`: serialized response [`derec_proto::DeRecMessage`] to send back to the Owner
/// - `committed_share`: the [`CommittedDeRecShare`] extracted from the request, ready to store
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `request_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != request.timestamp`
/// - the `share` field of the inner request is empty
/// - the `share` field cannot be decoded as a valid [`CommittedDeRecShare`]
/// - `CommittedDeRecShare.commitment` is empty
/// - `CommittedDeRecShare.merkle_path` is empty
/// - the Merkle proof does not verify against `commitment`
/// - response envelope construction or encryption fails
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let ProtectSecretResult { shares } = protect_secret(
///     b"my_secret_id",
///     b"super_secret_value",
///     &channels,
///     2,
///     1,
/// ).expect("sharing failed");
///
/// let channel_id = ChannelId(1);
/// let shared_key = [42u8; 32];
/// let committed_share = shares.get(&channel_id).expect("missing share");
///
/// let ProduceStoreShareRequestMessageResult { wire_bytes: request_bytes } =
///     produce_store_share_request_message(channel_id, 1, committed_share, &[], "", &shared_key)
///         .expect("produce failed");
///
/// let ProduceStoreShareResponseMessageResult { wire_bytes, committed_share } =
///     produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
///         .expect("process failed");
///
/// assert!(!wire_bytes.is_empty());
/// assert!(!committed_share.commitment.is_empty());
/// ```
pub fn produce_store_share_response_message(
    channel_id: ChannelId,
    shared_key: &[u8; 32],
    request_bytes: impl AsRef<[u8]>,
) -> Result<ProduceStoreShareResponseMessageResult, crate::Error> {
    let (envelope, request) = derec_message::extract_inner_message::<StoreShareRequestMessage>(
        request_bytes,
        shared_key,
    )?;

    if envelope.timestamp != request.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request timestamp",
        ));
    }

    if request.share.is_empty() {
        return Err(crate::Error::Invariant(
            "share field is empty in StoreShareRequestMessage",
        ));
    }

    let committed_share = CommittedDeRecShare::decode(request.share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;

    if committed_share.de_rec_share.is_empty() {
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.de_rec_share is empty",
        ));
    }

    if committed_share.commitment.is_empty() {
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.commitment is empty",
        ));
    }

    if committed_share.merkle_path.is_empty() {
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare.merkle_path is empty",
        ));
    }

    let inner_share = DeRecShare::decode(committed_share.de_rec_share.as_slice())
        .map_err(crate::Error::ProtobufDecode)?;

    let vss_share = vss::VSSShare {
        x: inner_share.x,
        y: inner_share.y,
        encrypted_secret: inner_share.encrypted_secret,
        commitment: committed_share.commitment.clone(),
        merkle_path: committed_share
            .merkle_path
            .iter()
            .map(|s| (s.is_left, s.hash.clone()))
            .collect(),
    };

    if !vss::verify(&vss_share) {
        return Err(crate::Error::Invariant(
            "CommittedDeRecShare Merkle proof verification failed",
        ));
    }

    let timestamp = current_timestamp();

    let response = StoreShareResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        version: request.version,
        timestamp: Some(timestamp),
    };

    let wire_bytes = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message(&response)
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    Ok(ProduceStoreShareResponseMessageResult {
        wire_bytes,
        committed_share,
    })
}

/// Validates a [`derec_proto::StoreShareResponseMessage`] received from a Helper.
///
/// Call this on the **Owner** side after receiving the Helper's response to a
/// [`produce_store_share_request_message`] envelope. The function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `response_bytes`
/// 2. Decrypts and decodes the inner [`StoreShareResponseMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
/// 4. Validates that `response.version == version`
/// 5. Returns the Helper's acknowledgement as a `bool`
///
/// Returns `Ok(())` if the Helper's response is valid and its status is `Ok`.
/// Any failure — whether a protocol error or the Helper's explicit rejection — is
/// returned as [`crate::Error`].
///
/// # Arguments
///
/// * `version` - The version number that was sent in the original request. Used to
///   cross-check the version echoed back by the Helper.
/// * `shared_key` - 256-bit symmetric key shared with this Helper, derived during pairing.
///   Used to decrypt the response envelope.
/// * `response_bytes` - Serialized [`derec_proto::DeRecMessage`] envelope bytes received
///   from the Helper, as produced by [`produce_store_share_response_message`].
///
/// # Returns
///
/// `Ok(())` on success.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `response_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - `response.version != version`
/// - the `result` field is absent in the response
/// - [`SharingError::HelperRejected`] if `result.status != Ok`, carrying the
///   Helper's status code and memo string
///
/// # Example
///
/// ```rust
/// use derec_library::sharing::*;
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let ProtectSecretResult { shares } = protect_secret(
///     b"my_secret_id",
///     b"super_secret_value",
///     &channels,
///     2,
///     1,
/// ).expect("sharing failed");
///
/// let channel_id = ChannelId(1);
/// let shared_key = [42u8; 32];
/// let version = 1;
/// let committed_share = shares.get(&channel_id).expect("missing share");
///
/// let ProduceStoreShareRequestMessageResult { wire_bytes: request_bytes } =
///     produce_store_share_request_message(channel_id, version, committed_share, &[], "", &shared_key)
///         .expect("produce failed");
///
/// let ProduceStoreShareResponseMessageResult { wire_bytes: response_bytes, .. } =
///     produce_store_share_response_message(channel_id, &shared_key, &request_bytes)
///         .expect("process failed");
///
/// process_store_share_response_message(version, &shared_key, &response_bytes)
///     .expect("validate failed");
/// ```
pub fn process_store_share_response_message(
    version: i32,
    shared_key: &[u8; 32],
    response_bytes: impl AsRef<[u8]>,
) -> Result<(), crate::Error> {
    let (envelope, response) = derec_message::extract_inner_message::<StoreShareResponseMessage>(
        response_bytes,
        shared_key,
    )?;

    if envelope.timestamp != response.timestamp {
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    if response.version != version {
        return Err(crate::Error::Invariant(
            "Response version does not match request version",
        ));
    }

    let result = response.result.ok_or(crate::Error::Invariant(
        "StoreShareResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        return Err(SharingError::HelperRejected {
            status: result.status,
            memo: result.memo,
        }
        .into());
    }

    Ok(())
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
