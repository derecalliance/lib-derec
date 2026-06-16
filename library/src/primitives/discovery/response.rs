// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::discovery::DiscoveryError,
    types::{ChannelId, SharedKey},
    utils::verify_timestamps,
};
use derec_proto::{
    DeRecMessage, DeRecResult, GetSecretIdsVersionsResponseMessage, MessageBody, StatusEnum,
    get_secret_ids_versions_response_message::{
        VersionList, version_list::VersionEntry as ProtoVersionEntry,
    },
};
use prost::Message;

#[derive(Debug, Clone, PartialEq)]
pub struct VersionEntry {
    pub version: u32,
    pub description: String,
}

impl From<&VersionEntry> for ProtoVersionEntry {
    fn from(version: &VersionEntry) -> Self {
        ProtoVersionEntry {
            version: version.version,
            version_description: version.description.to_owned(),
        }
    }
}

impl From<VersionEntry> for ProtoVersionEntry {
    fn from(version: VersionEntry) -> Self {
        Self::from(&version)
    }
}

impl From<ProtoVersionEntry> for VersionEntry {
    fn from(entry: ProtoVersionEntry) -> Self {
        Self::from(&entry)
    }
}

impl From<&ProtoVersionEntry> for VersionEntry {
    fn from(entry: &ProtoVersionEntry) -> Self {
        Self {
            version: entry.version,
            description: entry.version_description.to_owned(),
        }
    }
}

/// One entry in a discovery response — a single secret and all versions the
/// Helper holds for it, each paired with its human-readable description.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretVersionEntry {
    pub secret_id: u64,
    pub versions: Vec<VersionEntry>,
}

impl From<&SecretVersionEntry> for VersionList {
    fn from(entry: &SecretVersionEntry) -> Self {
        VersionList {
            secret_id: entry.secret_id,
            versions: entry.versions.iter().map(ProtoVersionEntry::from).collect(),
        }
    }
}

impl From<SecretVersionEntry> for VersionList {
    fn from(entry: SecretVersionEntry) -> Self {
        Self::from(&entry)
    }
}

impl From<&VersionList> for SecretVersionEntry {
    fn from(list: &VersionList) -> Self {
        Self {
            secret_id: list.secret_id,
            versions: list.versions.iter().map(Into::into).collect(),
        }
    }
}

impl From<VersionList> for SecretVersionEntry {
    fn from(list: VersionList) -> Self {
        Self::from(&list)
    }
}

pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::GetSecretIdsVersionsResponseMessage`].
    pub envelope: Vec<u8>,
}

pub struct ExtractResult {
    pub response: GetSecretIdsVersionsResponseMessage,
}

pub struct ProcessResult {
    pub secret_list: Vec<SecretVersionEntry>,
}

/// Produces a discovery response envelope containing the list of secret IDs and
/// their share versions stored by the Helper for this Owner.
///
/// This function is typically executed by a Helper after receiving and extracting
/// a [`derec_proto::GetSecretIdsVersionsRequestMessage`]. The Helper enumerates
/// all `(secret_id, versions)` pairs it holds for the requesting channel and
/// passes them to this function.
///
/// The resulting [`derec_proto::GetSecretIdsVersionsResponseMessage`] is encrypted
/// with the channel shared key and wrapped in a plain outer
/// [`derec_proto::DeRecMessage`] envelope.
///
/// # Arguments
///
/// * `channel_id` - Identifier of the previously paired Owner channel.
/// * `secret_list` - All secrets and their stored versions to include in the
///   response. May be empty if no secrets are stored for this channel. Each
///   [`SecretVersionEntry`] carries a `secret_id` and a list of [`VersionEntry`]
///   values where each entry pairs a version number with its human-readable
///   description.
/// * `shared_key` - Previously established 32-byte symmetric channel key used to
///   encrypt the response.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetSecretIdsVersionsResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if outer envelope construction or symmetric encryption fails.
///
/// # Pre-requisites
///
/// The `channel_id` used for this request is a brand new one Owner and Helper just established.
/// The Owner is usually in recovery-mode when this flow triggers. This means that the Helper
/// must have already linked this new `channel_id` with previous Owner's channel_ids. Otherwise the
/// Helper will not be able to return old secrets and versions for the Owner
///
/// # Security Notes
///
/// This response reveals metadata about secrets stored by the Helper. It must only
/// be sent over an authenticated, encrypted channel to a verified Owner.
///
/// # Example
///
/// ```
/// use derec_library::primitives::discovery::response::{self, SecretVersionEntry, VersionEntry};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let secret_list = vec![
///     SecretVersionEntry {
///         secret_id: 1,
///         versions: vec![VersionEntry { version: 1, description: "wallet seed".to_owned() }],
///     },
/// ];
///
/// let result = response::produce(channel_id, &secret_list, &shared_key)
///     .expect("failed to build discovery response");
///
/// assert!(!result.envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0, secrets_count = secret_list.len()))
)]
pub fn produce(
    channel_id: ChannelId,
    secret_list: &[SecretVersionEntry],
    shared_key: &SharedKey,
) -> Result<ProduceResult, crate::Error> {
    let timestamp = current_timestamp();

    let secret_list: Vec<VersionList> = secret_list.iter().map(VersionList::from).collect();

    let message = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: StatusEnum::Ok as i32,
            memo: String::new(),
        }),
        secret_list,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsResponse(message))
        .encrypt(shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("discovery response envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes an incoming [`derec_proto::GetSecretIdsVersionsResponseMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner [`derec_proto::GetSecretIdsVersionsResponseMessage`]
///    using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **Owner** side after receiving a discovery response from a Helper.
/// Pass the extracted response to [`process`] to validate the result status and obtain
/// the clean secret list.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::GetSecretIdsVersionsResponseMessage`], as produced
///   by [`produce`].
/// * `shared_key` - Previously established 32-byte symmetric channel key used to decrypt
///   the inner message.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner [`derec_proto::GetSecretIdsVersionsResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a [`derec_proto::GetSecretIdsVersionsResponseMessage`]
///
/// # Security: no freshness or replay protection
///
/// The timestamp check enforced here only binds the envelope to the
/// inner body (`envelope.timestamp == body.timestamp`). It does NOT
/// enforce a freshness window against the receiver's clock and does
/// NOT detect replays of a previously-captured ciphertext. Because
/// the channel key is long-lived, a recorded envelope stays
/// decryptable indefinitely. Callers MUST add a freshness window
/// and per-channel anti-replay (monotonic counter or nonce log) on
/// top before driving any side-effecting state off the parsed body.
///
/// # Example
///
/// ```
/// use derec_library::primitives::discovery::response::{self, SecretVersionEntry, VersionEntry};
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let secret_list = vec![SecretVersionEntry {
///     secret_id: 1,
///     versions: vec![VersionEntry { version: 1, description: "v1".to_owned() }],
/// }];
///
/// let response::ProduceResult { envelope } =
///     response::produce(channel_id, &secret_list, &shared_key)
///         .expect("failed to build discovery response");
///
/// let response::ExtractResult { response } =
///     response::extract(&envelope, &shared_key).expect("failed to extract");
///
/// assert_eq!(response.secret_list.len(), 1);
/// assert_eq!(response.secret_list[0].secret_id, 1);
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

    let response = match extract_inner_message(&envelope.message, shared_key)? {
        MessageBody::GetSecretIdsVersionsResponse(message) => message,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("unexpected message type; expected GetSecretIdsVersionsResponseMessage");

            return Err(crate::Error::Invariant(
                "Invalid message. Expected: GetSecretIdsVersionsResponseMessage",
            ));
        }
    };

    verify_timestamps(envelope.timestamp, response.timestamp)?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery response extracted and validated");

    Ok(ExtractResult { response })
}

/// Validates a discovery response and extracts the secret list.
///
/// This function:
///
/// 1. Checks that the response contains a `result` field
/// 2. Validates that `result.status == Ok`
/// 3. Converts each [`derec_proto::get_secret_ids_versions_response_message::VersionList`]
///    entry into a [`SecretVersionEntry`], preserving version descriptions
///
/// Call this on the **Owner** side after [`extract`] succeeds, to obtain the
/// clean list of secrets and versions held by the Helper.
///
/// # Arguments
///
/// * `response` - The decrypted inner [`derec_proto::GetSecretIdsVersionsResponseMessage`]
///   returned by [`extract`].
///
/// # Returns
///
/// On success returns [`ProcessResult`] containing:
///
/// - `secret_list`: all secrets reported by the Helper, each with its stored
///   versions and their human-readable descriptions
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::Discovery(...)`) in the following cases:
///
/// - the response does not contain a `result` field (returned as `crate::Error::Invariant`)
/// - [`DiscoveryError::NonOkStatus`] if `result.status != Ok`, carrying the Helper's
///   status code and memo string
///
/// # Example
///
/// ```
/// use derec_library::primitives::discovery::response::{
///     self, ProcessResult, SecretVersionEntry, VersionEntry,
/// };
/// use derec_library::types::ChannelId;
///
/// let channel_id = ChannelId(42);
/// let shared_key = [7u8; 32];
///
/// let secret_list = vec![SecretVersionEntry {
///     secret_id: 1,
///     versions: vec![VersionEntry { version: 1, description: "v1".to_owned() }],
/// }];
///
/// // Helper → Owner roundtrip.
/// let response::ProduceResult { envelope } =
///     response::produce(channel_id, &secret_list, &shared_key).expect("produce failed");
/// let response::ExtractResult { response: resp } =
///     response::extract(&envelope, &shared_key).expect("extract failed");
///
/// let ProcessResult { secret_list: parsed } =
///     response::process(&resp).expect("process failed");
///
/// assert_eq!(parsed.len(), 1);
/// assert_eq!(parsed[0].secret_id, 1);
/// assert_eq!(parsed[0].versions[0].version, 1);
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(secrets_count = response.secret_list.len()))
)]
pub fn process(
    response: &GetSecretIdsVersionsResponseMessage,
) -> Result<ProcessResult, crate::Error> {
    let result = response.result.as_ref().ok_or(crate::Error::Invariant(
        "GetSecretIdsVersionsResponseMessage is missing result field",
    ))?;

    if result.status != StatusEnum::Ok as i32 {
        #[cfg(feature = "logging")]
        tracing::warn!(status = result.status, memo = %result.memo, "discovery response status is not Ok");

        return Err(DiscoveryError::NonOkStatus {
            status: result.status,
            memo: result.memo.to_owned(),
        }
        .into());
    }

    let secret_list: Vec<SecretVersionEntry> = response
        .secret_list
        .iter()
        .map(SecretVersionEntry::from)
        .collect();

    #[cfg(feature = "logging")]
    tracing::info!("discovery response processed successfully");

    Ok(ProcessResult { secret_list })
}
