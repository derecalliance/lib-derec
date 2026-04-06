use crate::types::ChannelId;
use derec_proto::CommittedDeRecShare;
use std::collections::HashMap;

/// Result of [`protect_secret`].
///
/// Contains one [`CommittedDeRecShare`] per helper channel, ready to be wrapped
/// into a [`derec_proto::StoreShareRequestMessage`] and delivered to each helper
/// using [`produce_store_share_request_message`].
pub struct ProtectSecretResult {
    /// Mapping from helper [`ChannelId`] to its committed share.
    ///
    /// Each value is a cryptographically committed VSS share for that helper.
    /// Pass each entry to [`produce_store_share_request_message`] together with
    /// the helper's shared key to produce the encrypted delivery envelope.
    pub shares: HashMap<ChannelId, CommittedDeRecShare>,
}

/// Result of [`produce_store_share_request_message`].
pub struct ProduceStoreShareRequestMessageResult {
    /// Serialized [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::StoreShareRequestMessage`] inner payload.
    ///
    /// Send these bytes to the helper over the channel transport.
    /// The helper stores them and uses them to respond to verification
    /// and recovery requests.
    pub wire_bytes: Vec<u8>,
}

/// Result of [`process_store_share_request_message`].
pub struct ProduceStoreShareResponseMessageResult {
    /// Serialized [`derec_proto::DeRecMessage`] envelope carrying an encrypted
    /// [`derec_proto::StoreShareResponseMessage`] inner payload.
    ///
    /// Send these bytes back to the owner over the channel transport.
    pub wire_bytes: Vec<u8>,

    /// The [`CommittedDeRecShare`] extracted from the request.
    ///
    /// The helper must persist this value. It is required to respond to
    /// future verification and recovery requests on this channel.
    pub committed_share: CommittedDeRecShare,
}
