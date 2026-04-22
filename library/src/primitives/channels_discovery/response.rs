// SPDX-License-Identifier: Apache-2.0

use crate::{
    derec_message::{DeRecMessageBuilder, current_timestamp, extract_inner_message},
    primitives::channels_discovery::ChannelsDiscoveryError,
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecMessage, MessageBody, ReplicaChannelsDiscoveryResponseMessage, ReplicaChannelsEntry,
};
use prost::Message;

/// A single channel entry for the Replica to learn about.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelEntry {
    /// Channel identifier for the Owner↔Helper relationship.
    pub channel_id: ChannelId,
    /// 32-byte shared symmetric key for the channel.
    pub shared_key: SharedKey,
}

/// Result of [`produce`].
pub struct ProduceResult {
    /// Serialized outer [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`].
    pub envelope: Vec<u8>,
}

/// Result of [`extract`].
pub struct ExtractResult {
    /// The decrypted inner [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`].
    pub response: ReplicaChannelsDiscoveryResponseMessage,
}

/// Result of [`process`].
pub struct ProcessResult {
    /// Total number of batches the Owner will send.
    pub total_batches: i32,
    /// 1-based index of this batch.
    pub current_batch: i32,
    /// Channel entries in this batch.
    pub entries: Vec<ChannelEntry>,
}

/// Produces a channels discovery response [`derec_proto::DeRecMessage`] envelope.
///
/// This function is executed by the **Owner** after receiving and extracting a
/// [`derec_proto::ReplicaChannelsDiscoveryRequestMessage`] from a confirmed
/// Replica. The Owner enumerates all active Helper channels and provides them
/// in batched responses so the Replica can synchronise its local state.
///
/// Each [`ChannelEntry`] contains the Helper channel's `channel_id` and
/// `shared_key`. The entry data is encrypted inside the Owner↔Replica channel
/// envelope, so the Helper shared keys are protected in transit.
///
/// # Arguments
///
/// * `channel_id` - Owner↔Replica channel established during Replica pairing.
/// * `replica_shared_key` - 32-byte symmetric key for the Owner↔Replica channel.
/// * `entries` - Channel entries to include in this batch. May be empty if no
///   Helper channels exist.
/// * `total_batches` - Total number of batches the Owner will send. Must be ≥ 1.
/// * `current_batch` - 1-based index of this batch. Must satisfy
///   `1 ≤ current_batch ≤ total_batches`.
///
/// # Returns
///
/// On success returns [`ProduceResult`] containing:
///
/// - `envelope`: serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::ChannelsDiscovery(...)`) in
/// the following cases:
///
/// - [`ChannelsDiscoveryError::InvalidBatchMetadata`] if `total_batches < 1`,
///   `current_batch < 1`, or `current_batch > total_batches`
/// - [`ChannelsDiscoveryError::EmptySharedKey`] if any entry has an empty
///   `shared_key`
///
/// # Security Notes
///
/// The response carries shared keys for Helper channels. It must only be sent
/// to a confirmed Replica over the encrypted Owner↔Replica channel.
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::channels_discovery::response::{self, ChannelEntry};
/// use derec_library::types::ChannelId;
///
/// let replica_channel_id = ChannelId(42);
/// let replica_shared_key = [7u8; 32];
///
/// let entries = vec![
///     ChannelEntry {
///         channel_id: ChannelId(100),
///         shared_key: [0xAAu8; 32],
///     },
///     ChannelEntry {
///         channel_id: ChannelId(200),
///         shared_key: [0xBBu8; 32],
///     },
/// ];
///
/// let response::ProduceResult { envelope } =
///     response::produce(replica_channel_id, &replica_shared_key, &entries, 1, 1)
///         .expect("failed to produce channels discovery response");
///
/// assert!(!envelope.is_empty());
/// ```
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(
        channel_id = channel_id.0,
        total_batches,
        current_batch,
        entries_count = entries.len()
    ))
)]
pub fn produce(
    channel_id: ChannelId,
    replica_shared_key: &SharedKey,
    entries: &[ChannelEntry],
    total_batches: i32,
    current_batch: i32,
) -> Result<ProduceResult, crate::Error> {
    if total_batches < 1 || current_batch < 1 || current_batch > total_batches {
        return Err(ChannelsDiscoveryError::InvalidBatchMetadata {
            total: total_batches,
            current: current_batch,
        }
        .into());
    }

    for (index, entry) in entries.iter().enumerate() {
        if entry.shared_key.is_empty() {
            return Err(ChannelsDiscoveryError::EmptySharedKey { index }.into());
        }
    }

    let timestamp = current_timestamp();

    let proto_entries: Vec<ReplicaChannelsEntry> = entries
        .iter()
        .map(|e| ReplicaChannelsEntry {
            channel_id: e.channel_id.into(),
            shared_key: e.shared_key.to_vec(),
        })
        .collect();

    let message = ReplicaChannelsDiscoveryResponseMessage {
        total_batches,
        current_batch,
        entries: proto_entries,
        timestamp: Some(timestamp),
    };

    let envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::ReplicaChannelsDiscoveryResponse(message))
        .encrypt(replica_shared_key)?
        .build()?
        .encode_to_vec();

    #[cfg(feature = "logging")]
    tracing::info!("channels discovery response envelope produced");

    Ok(ProduceResult { envelope })
}

/// Decrypts and decodes a [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`]
/// from an outer [`derec_proto::DeRecMessage`] envelope.
///
/// This function:
///
/// 1. Decodes the outer [`derec_proto::DeRecMessage`] envelope from `envelope_bytes`
/// 2. Decrypts and decodes the inner
///    [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`] using `shared_key`
/// 3. Validates the invariant `envelope.timestamp == response.timestamp`
///
/// Call this on the **Replica** side after receiving a channels discovery response
/// from the Owner. Pass the extracted response to [`process`] to validate batch
/// metadata and obtain the channel entries with their shared keys.
///
/// # Arguments
///
/// * `envelope_bytes` - Serialized outer [`derec_proto::DeRecMessage`] bytes carrying an
///   encrypted inner [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`], as
///   produced by [`produce`].
/// * `shared_key` - 32-byte symmetric key for the Owner↔Replica channel.
///
/// # Returns
///
/// On success returns [`ExtractResult`] containing:
///
/// - `response`: the decrypted inner
///   [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`]
///
/// # Errors
///
/// Returns [`crate::Error`] if:
///
/// - `envelope_bytes` cannot be decoded as a valid [`derec_proto::DeRecMessage`]
/// - decryption or inner-message decoding fails
/// - `envelope.timestamp != response.timestamp`
/// - the inner message is not a
///   [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`]
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::channels_discovery::response;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let response::ExtractResult { response: resp } =
///     response::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract channels discovery response");
///
/// println!("batch {}/{}", resp.current_batch, resp.total_batches);
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
        MessageBody::ReplicaChannelsDiscoveryResponse(m) => m,
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                "unexpected message type; expected ReplicaChannelsDiscoveryResponseMessage"
            );
            return Err(crate::Error::Invariant(
                "Invalid message. Expected: ReplicaChannelsDiscoveryResponseMessage",
            ));
        }
    };

    if envelope.timestamp != response.timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");
        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match response timestamp",
        ));
    }

    #[cfg(feature = "logging")]
    tracing::info!("channels discovery response extracted and validated");

    Ok(ExtractResult { response })
}

/// Validates a channels discovery response and extracts the channel entries.
///
/// This function:
///
/// 1. Validates that the batch metadata is consistent (`total_batches ≥ 1`,
///    `1 ≤ current_batch ≤ total_batches`)
/// 2. Validates that each entry's `shared_key` is non-empty and exactly 32 bytes
/// 3. Converts the protobuf entries into [`ChannelEntry`] values
///
/// Call this on the **Replica** side after [`extract`] succeeds. The Replica
/// should request subsequent batches until `current_batch == total_batches`.
///
/// # Arguments
///
/// * `response` - The decrypted inner
///   [`derec_proto::ReplicaChannelsDiscoveryResponseMessage`] returned by
///   [`extract`].
///
/// # Returns
///
/// On success returns [`ProcessResult`] containing:
///
/// - `total_batches`: total number of batches the Owner will send
/// - `current_batch`: 1-based index of this batch
/// - `entries`: channel entries in this batch, each with a validated 32-byte key
///
/// # Errors
///
/// Returns [`crate::Error`] (specifically `Error::ChannelsDiscovery(...)`) in
/// the following cases:
///
/// - [`ChannelsDiscoveryError::InvalidBatchMetadata`] if batch numbers are invalid
/// - [`ChannelsDiscoveryError::EmptySharedKey`] if any entry has an empty key
/// - [`ChannelsDiscoveryError::InvalidSharedKeyLength`] if any key is not 32 bytes
///
/// # Example
///
/// ```no_run
/// use derec_library::primitives::channels_discovery::response;
///
/// let shared_key = [7u8; 32];
/// # let envelope_bytes: Vec<u8> = vec![];
///
/// let response::ExtractResult { response: resp } =
///     response::extract(&envelope_bytes, &shared_key)
///         .expect("failed to extract");
///
/// let response::ProcessResult {
///     total_batches,
///     current_batch,
///     entries,
/// } = response::process(&resp)
///     .expect("failed to process channels discovery response");
///
/// for entry in &entries {
///     println!("channel {} synced", entry.channel_id.0);
/// }
/// ```
pub fn process(
    response: &ReplicaChannelsDiscoveryResponseMessage,
) -> Result<ProcessResult, crate::Error> {
    if response.total_batches < 1
        || response.current_batch < 1
        || response.current_batch > response.total_batches
    {
        return Err(ChannelsDiscoveryError::InvalidBatchMetadata {
            total: response.total_batches,
            current: response.current_batch,
        }
        .into());
    }

    let mut entries = Vec::with_capacity(response.entries.len());

    for (index, proto_entry) in response.entries.iter().enumerate() {
        if proto_entry.shared_key.is_empty() {
            return Err(ChannelsDiscoveryError::EmptySharedKey { index }.into());
        }

        let key: SharedKey = proto_entry.shared_key.as_slice().try_into().map_err(|_| {
            ChannelsDiscoveryError::InvalidSharedKeyLength {
                index,
                len: proto_entry.shared_key.len(),
            }
        })?;

        entries.push(ChannelEntry {
            channel_id: ChannelId(proto_entry.channel_id),
            shared_key: key,
        });
    }

    #[cfg(feature = "logging")]
    tracing::info!("channels discovery response processed successfully");

    Ok(ProcessResult {
        total_batches: response.total_batches,
        current_batch: response.current_batch,
        entries,
    })
}
