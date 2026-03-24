use crate::types::ChannelId;
use std::collections::HashMap;

/// Result of [`protect_secret`].
///
/// This type contains one serialized share-delivery message per helper channel.
///
/// Each value in [`ProtectSecretResult::shares`] is a serialized outer
/// [`derec_proto::DeRecMessage`] envelope ready to be sent to the corresponding
/// helper. The envelope contains an encrypted inner
/// [`derec_proto::StoreShareRequestMessage`].
pub struct ProtectSecretResult {
    /// Mapping from helper [`ChannelId`] to serialized outer
    /// [`derec_proto::DeRecMessage`] wire bytes.
    ///
    /// Each envelope carries exactly one encrypted
    /// [`derec_proto::StoreShareRequestMessage`] for that helper.
    pub shares: HashMap<ChannelId, Vec<u8>>,
}
