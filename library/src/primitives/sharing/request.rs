// SPDX-License-Identifier: Apache-2.0

use crate::primitives::sharing::SharingError;
use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    types::{ChannelId, SharedKey},
    utils::{generate_seed, verify_timestamps},
};
use derec_cryptography::vss;
use derec_proto::{
    CommittedDeRecShare, DeRecMessage, DeRecShare, MessageBody, StoreShareRequestMessage,
    committed_de_rec_share::SiblingHash,
};
use prost::Message;
use std::collections::HashMap;

/// Current share algorithm identifier embedded into [`derec_proto::StoreShareRequestMessage`].
///
/// At present the sharing flow uses the library's VSS-based share generation and
/// encodes that choice using the protocol value `0`.
const SHARE_ALGORITHM_VSS: i32 = 0;
/// `share` bytes carry a **full vault payload** (`DeRecSecret` proto)
/// instead of a single VSS share fragment. Used on replica channels —
/// every replica holds an identical copy of the vault rather than a
/// reconstructable fragment of it.
///
/// Disambiguates the payload semantics on the wire; the receiver's
/// `Channel.role` is the authoritative source of truth, but a distinct
/// `share_algorithm` value lets wire dumps and middle-boxes tell the two
/// payload shapes apart without channel-state context.
pub const SHARE_ALGORITHM_REPLICA_VAULT: i32 = 1;

pub struct SplitResult {
    pub shares: HashMap<ChannelId, CommittedDeRecShare>,
}

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::StoreShareRequestMessage`] inner payload.
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub request: StoreShareRequestMessage,
}

/// Splits a secret into verifiable committed shares, one per Helper channel.
///
/// In DeRec, the *sharing* flow splits a secret into independently verifiable
/// shares using a Verifiable Secret Sharing (VSS) scheme. Each generated share is:
///
/// - Bound to a specific `secret_id` and `version`
/// - Committed using a Merkle commitment and proof
/// - Returned as a [`CommittedDeRecShare`] ready to be delivered to its Helper
///
/// To send a share to a Helper, pass the returned [`CommittedDeRecShare`] to
/// [`produce`] together with the Helper's shared key to produce the encrypted
/// delivery envelope.
///
/// # Deterministic channel/share assignment
///
/// The input `channels` slice is sorted by [`ChannelId`] before shares are assigned.
/// Generated VSS shares are assigned in that sorted order. Duplicate channel IDs are
/// rejected with [`SharingError::DuplicateChannelId`].
///
/// # Arguments
///
/// * `channels` - Slice of Helper [`ChannelId`] values. Each entry receives exactly
///   one committed share. Must not be empty. Duplicate entries are rejected.
/// * `secret_id` - Identifier of the secret being protected. Embedded into each
///   generated share. Must not be empty.
/// * `version` - Logical version of this secret distribution. Embedded into each
///   generated share.
/// * `secret_data` - Raw secret bytes to split using VSS. Must not be empty.
/// * `threshold` - Minimum number of shares required to reconstruct the secret.
///   Must satisfy `2 <= threshold <= channels.len()`.
///
/// # Returns
///
/// On success returns [`SplitResult`] containing:
///
/// - `shares`: `HashMap<ChannelId, CommittedDeRecShare>` — one committed share per channel.
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Sharing(...)`) in the following cases:
///
/// - [`SharingError::EmptyChannels`] if `channels` is empty
/// - [`SharingError::EmptySecretData`] if `secret_data` is empty
/// - [`SharingError::DuplicateChannelId`] if `channels` contains any repeated ID
/// - [`SharingError::InvalidThreshold`] if `threshold` does not satisfy
///   `2 <= threshold <= channels.len()`
/// - [`SharingError::VssShareFailed`] if the underlying VSS algorithm fails
///
/// # Security Notes
///
/// - The caller is responsible for securely managing the original `secret_data`.
///
/// # Example
///
/// ```
/// use derec_library::primitives::sharing::request::{split, SplitResult};
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
///
/// let SplitResult { shares } = split(
///     &channels,
///     1,
///     1,
///     b"super_secret_value",
///     2,
/// ).expect("split failed");
///
/// assert_eq!(shares.len(), 3);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channels_count = channels.len(),
            version = version,
            threshold = threshold,
            secret_data_len = secret_data.as_ref().len(),
        )
    )
)]
pub fn split(
    channels: &[ChannelId],
    secret_id: u64,
    version: u32,
    secret_data: impl AsRef<[u8]>,
    threshold: usize,
) -> Result<SplitResult, crate::Error> {
    let secret_data = secret_data.as_ref();

    let ordered_channels = validate_split_inputs(channels, secret_data, threshold)?;
    let channel_count = ordered_channels.len();

    let vss_shares = generate_vss_shares(secret_data, threshold, channel_count)?;

    let shares = build_shares(ordered_channels, vss_shares, secret_id, version);

    #[cfg(feature = "logging")]
    tracing::info!("secret split into shares");

    Ok(SplitResult { shares })
}

/// Produces an encrypted [`derec_proto::DeRecMessage`] envelope wrapping a
/// [`CommittedDeRecShare`] as a [`derec_proto::StoreShareRequestMessage`] inner payload.
///
/// Call this once for each share returned by [`split`], providing the corresponding
/// Helper's shared key (established during pairing). The resulting wire bytes should be
/// sent to the Helper over the channel transport. On the Helper side, the inner
/// [`derec_proto::StoreShareRequestMessage`] extracted by [`extract`] must be retained
/// for future verification and recovery flows.
///
/// # Arguments
///
/// * `channel_id` - The Helper channel this share belongs to.
/// * `version` - Share-distribution version, matching the value passed to [`split`].
/// * `secret_id` - Identifier of the secret being distributed. Must match the value
///   passed to [`split`].
/// * `committed_share` - The share for this channel, as returned by [`split`].
/// * `keep_list` - Ordered list of version numbers the Helper should retain. Pass an empty
///   slice to let the Helper apply its default retention policy.
/// * `description` - Human-readable description of this share distribution. May be empty.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to
///   encrypt the inner request.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized [`derec_proto::DeRecMessage`] wire bytes carrying an encrypted
///   [`derec_proto::StoreShareRequestMessage`].
///
/// # Errors
///
/// Returns [`crate::Error`] if envelope construction or symmetric encryption fails.
///
/// # Example
///
/// ```
/// use derec_library::primitives::sharing::request::{split, produce, SplitResult, ProduceResult};
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let SplitResult { shares } = split(&channels, 1, 1, b"super_secret_value", 2)
///     .expect("split failed");
///
/// let shared_key = [42u8; 32];
/// let channel_id = ChannelId(1);
/// let committed_share = shares.get(&channel_id).expect("missing share");
///
/// let ProduceResult { envelope } =
///     produce(channel_id, 1, 1, committed_share, &[], "", &shared_key, None)
///         .expect("produce failed");
///
/// assert!(!envelope.is_empty());
/// ```
#[allow(clippy::too_many_arguments)]
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, version = version))
)]
pub fn produce(
    channel_id: ChannelId,
    version: u32,
    secret_id: u64,
    committed_share: &CommittedDeRecShare,
    keep_list: &[u32],
    description: impl Into<String>,
    shared_key: &SharedKey,
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let msg = StoreShareRequestMessage {
        share: committed_share.encode_to_vec(),
        share_algorithm: SHARE_ALGORITHM_VSS,
        version,
        keep_list: keep_list.to_vec(),
        version_description: description.into(),
        timestamp: Some(timestamp),
        secret_id,
        reply_to,
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::StoreShareRequest(msg))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("share request envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`StoreShareRequestMessage`] from an outer envelope.
///
/// Call this on the **Helper** side after receiving a sharing request from an Owner.
/// The function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`StoreShareRequestMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == request.timestamp`
///
/// The extracted [`StoreShareRequestMessage`] should be passed to
/// [`crate::primitives::sharing::response::produce`] to build the acknowledgement
/// response. The Helper must also persist the [`StoreShareRequestMessage`] itself (e.g.
/// as serialized bytes via `.encode_to_vec()`) for future verification and recovery flows.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized [`derec_proto::DeRecMessage`] wire bytes received from
///   the Owner, as produced by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to
///   decrypt the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `request`: the decrypted inner [`derec_proto::StoreShareRequestMessage`].
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - the inner message is not a [`derec_proto::StoreShareRequestMessage`]
/// - `envelope.timestamp != request.timestamp`
///
/// # Security Notes
///
/// - The decrypted [`derec_proto::StoreShareRequestMessage`] carries the committed share the
///   Helper must persist for future verification and recovery; treat it as sensitive material
///   and store it securely.
/// - **No freshness or replay protection.** The timestamp check
///   enforced here only binds the envelope to the inner body
///   (`envelope.timestamp == body.timestamp`). It does NOT enforce
///   a freshness window against the receiver's clock and does NOT
///   detect replays of a previously-captured ciphertext. Because
///   the channel key is long-lived, a recorded envelope stays
///   decryptable indefinitely. Callers MUST add a freshness window
///   and per-channel anti-replay (monotonic counter or nonce log)
///   on top before driving any side-effecting state off the parsed
///   body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::sharing::request::{split, produce, extract, SplitResult, ProduceResult, ExtractResult};
/// use derec_library::types::ChannelId;
///
/// let channels = [ChannelId(1), ChannelId(2), ChannelId(3)];
/// let SplitResult { shares } = split(&channels, 1, 1, b"super_secret_value", 2)
///     .expect("split failed");
///
/// let channel_id = ChannelId(1);
/// let shared_key = [42u8; 32];
/// let committed_share = shares.get(&channel_id).expect("missing share");
///
/// let ProduceResult { envelope } =
///     produce(channel_id, 1, 1, committed_share, &[], "", &shared_key)
///         .expect("produce failed");
///
/// let ExtractResult { request } = extract(&envelope, &shared_key).expect("extract failed");
///
/// assert_eq!(request.secret_id, 1);
/// assert_eq!(request.version, 1);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(envelope_len = envelope_bytes.len()))
)]
pub fn extract(
    envelope_bytes: &[u8],
    shared_key: &SharedKey,
) -> Result<ExtractResult, crate::Error> {
    let envelope = DeRecMessage::decode(envelope_bytes).map_err(crate::Error::ProtobufDecode)?;

    let request = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::StoreShareRequest(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected StoreShareRequestMessage");
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: StoreShareRequestMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, request.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("share request extracted and validated");

    Ok(ExtractResult { request })
}

fn generate_vss_shares(
    secret_data: &[u8],
    threshold: usize,
    channels_len: usize,
) -> Result<Vec<derec_cryptography::vss::VSSShare>, SharingError> {
    let entropy = generate_seed::<32>();
    let t = threshold as u64;
    let n = channels_len as u64;

    vss::share(t, n, secret_data, &entropy)
        .map_err(|source| SharingError::VssShareFailed { source })
}

fn build_shares(
    ordered_channels: Vec<ChannelId>,
    vss_shares: Vec<derec_cryptography::vss::VSSShare>,
    secret_id: u64,
    version: u32,
) -> HashMap<ChannelId, CommittedDeRecShare> {
    let mut shares = HashMap::with_capacity(ordered_channels.len());

    for (channel_id, share) in ordered_channels.into_iter().zip(vss_shares) {
        let derec_share = DeRecShare {
            encrypted_secret: share.encrypted_secret.clone(),
            x: share.x.clone(),
            y: share.y.clone(),
            secret_id,
            version,
        };

        let committed_derec_share = CommittedDeRecShare {
            de_rec_share: derec_share.encode_to_vec(),
            commitment: share.commitment.clone(),
            merkle_path: share
                .merkle_path
                .iter()
                .map(|(is_left, hash)| SiblingHash {
                    is_left: *is_left,
                    hash: hash.clone(),
                })
                .collect(),
        };

        shares.insert(channel_id, committed_derec_share);
    }

    shares
}

fn validate_split_inputs(
    channels: &[ChannelId],
    secret_data: &[u8],
    threshold: usize,
) -> Result<Vec<ChannelId>, crate::Error> {
    if channels.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("channels list is empty");
        return Err(SharingError::EmptyChannels.into());
    }

    if secret_data.is_empty() {
        #[cfg(feature = "logging")]
        tracing::warn!("secret_data is empty");
        return Err(SharingError::EmptySecretData.into());
    }

    let mut ordered_channels: Vec<ChannelId> = channels.to_vec();
    ordered_channels.sort();
    for pair in ordered_channels.windows(2) {
        if pair[0] == pair[1] {
            #[cfg(feature = "logging")]
            tracing::warn!("duplicate channel ID detected");
            return Err(SharingError::DuplicateChannelId(pair[0].into()).into());
        }
    }

    let channel_count = ordered_channels.len();

    if threshold < 2 || threshold > channel_count {
        #[cfg(feature = "logging")]
        tracing::warn!(
            threshold = threshold,
            channels = channel_count,
            "threshold out of valid range"
        );
        return Err(SharingError::InvalidThreshold {
            threshold,
            channels: channel_count,
        }
        .into());
    }

    Ok(ordered_channels)
}
