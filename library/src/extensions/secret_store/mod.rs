// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading a channel's shared key.
//!
//! Like [`ChannelStoreExt`](crate::extensions::channel_store::ChannelStoreExt),
//! these are methods on the store rather than part of [`DeRecSecretStore`]
//! itself: applications implement that trait, so a method added there would
//! have to be written by every implementor and every SDK's store shim.

use crate::protocol::{DeRecSecretStore, SecretKind, SecretValue};
use crate::types::{ChannelId, SharedKey};
use crate::{Error, Result};

/// Shared-key reads every flow needs, as methods on the store that holds
/// them.
///
/// Blanket-implemented for every [`DeRecSecretStore`], so bringing the trait
/// into scope (`use crate::extensions::secret_store::SecretStoreExt as _;`)
/// is all a caller does.
pub(crate) trait SecretStoreExt: DeRecSecretStore {
    /// The shared key stored for `channel_id`, or `None` when it has none.
    async fn shared_key(&self, secret_id: u64, channel_id: ChannelId) -> Result<Option<SharedKey>> {
        Ok(
            match self
                .load(secret_id, channel_id, SecretKind::SharedKey)
                .await?
            {
                Some(SecretValue::SharedKey(key)) => Some(key),
                _ => None,
            },
        )
    }

    /// The shared key stored for `channel_id`: a helper channel's key, or a
    /// replica group's key on the group channel. A channel with none is not
    /// paired, which is [`Error::InvalidInput`].
    async fn paired_key(&self, secret_id: u64, channel_id: ChannelId) -> Result<SharedKey> {
        self.shared_key(secret_id, channel_id)
            .await?
            .ok_or(Error::InvalidInput(
                "channel has no shared key — not yet paired",
            ))
    }
}

impl<T: DeRecSecretStore> SecretStoreExt for T {}

#[cfg(test)]
mod tests;
