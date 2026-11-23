// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading and writing a channel's shared key and key ring.
//!
//! Like [`ChannelStoreExt`](crate::extensions::channel_store::ChannelStoreExt),
//! these are methods on the store rather than part of [`DeRecSecretStore`]
//! itself: applications implement that trait, so a method added there would
//! have to be written by every implementor and every SDK's store shim.

use crate::protocol::{
    ChannelKey, DeRecSecretStore, KeyRing, MissingPolicy, SecretKind, SecretValue,
};
use crate::types::{ChannelId, SharedKey};
use crate::{Error, Result};

/// Shared-key and key-ring access every flow needs, as methods on the store that holds
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

    /// The newest key of `channel_id` with its epoch: the key a message sent
    /// now is encrypted under. A channel with none is not paired, which is
    /// [`Error::InvalidInput`].
    async fn current_key(&self, secret_id: u64, channel_id: ChannelId) -> Result<ChannelKey> {
        Ok(self
            .key_ring(secret_id, channel_id)
            .await?
            .ok_or(Error::InvalidInput(
                "channel has no shared key — not yet paired",
            ))?
            .current())
    }

    /// The key ring of `channel_id`, or `None` when it has no shared key.
    ///
    /// The stored ring is returned whenever there is one, whatever the
    /// `SharedKey` row holds: that row only mirrors the ring's newest key. A
    /// channel with a shared key and no ring row is at epoch 0 under that key.
    ///
    /// # Errors
    ///
    /// [`Error::Invariant`] when the store answers the ring query with a
    /// value of another kind: the channel's epoch is then unknown, and is not
    /// taken to be 0.
    async fn key_ring(&self, secret_id: u64, channel_id: ChannelId) -> Result<Option<KeyRing>> {
        let Some(shared) = self.shared_key(secret_id, channel_id).await? else {
            return Ok(None);
        };
        match self
            .load(secret_id, channel_id, SecretKind::KeyRing)
            .await?
        {
            Some(SecretValue::KeyRing(ring)) => Ok(Some(ring)),
            None => Ok(Some(KeyRing::fresh(shared))),
            Some(_) => Err(WRONG_KIND_RING),
        }
    }

    /// The key rings of `ids`, in one call per kind, in the order the store
    /// returns the `SharedKey` rows.
    ///
    /// The `SharedKey` rows decide which channels are returned, and `missing`
    /// applies to them. A channel with no ring row is at epoch 0 under its
    /// shared key. A channel whose `SharedKey` or ring row the store answered
    /// with a value of another kind is returned with `None`: its key is not
    /// known, and each flow reports that channel as failed.
    async fn key_rings_many(
        &self,
        secret_id: u64,
        ids: &[ChannelId],
        missing: MissingPolicy,
    ) -> Result<Vec<(ChannelId, Option<KeyRing>)>> {
        let keys = self
            .load_many(secret_id, ids, SecretKind::SharedKey, missing)
            .await?;
        let stored: Vec<ChannelId> = keys.iter().map(|(id, _)| *id).collect();
        let mut rings: std::collections::HashMap<ChannelId, SecretValue> = self
            .load_many(secret_id, &stored, SecretKind::KeyRing, MissingPolicy::Skip)
            .await?
            .into_iter()
            .collect();
        Ok(keys
            .into_iter()
            .map(|(id, value)| {
                let ring = match (value, rings.remove(&id)) {
                    (SecretValue::SharedKey(_), Some(SecretValue::KeyRing(ring))) => Some(ring),
                    (SecretValue::SharedKey(key), None) => Some(KeyRing::fresh(key)),
                    _ => None,
                };
                (id, ring)
            })
            .collect())
    }

    /// Store `ring` for `channel_id`: the ring first, then the `SharedKey`
    /// row mirroring its newest key.
    ///
    /// The order leaves a failure between the two writes with a ring ahead
    /// of its mirror, which [`key_ring`](Self::key_ring) reads correctly,
    /// rather than a mirror ahead of the ring.
    ///
    /// # Errors
    ///
    /// [`Error::Invariant`], before anything is written, when the ring holds
    /// more entries than [`KeyRing::as_bytes`] can encode.
    async fn save_key_ring(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        ring: &KeyRing,
    ) -> Result<()> {
        ring.counts()?;
        self.save(secret_id, channel_id, SecretValue::KeyRing(ring.clone()))
            .await?;
        self.save(
            secret_id,
            channel_id,
            SecretValue::SharedKey(ring.current().key),
        )
        .await?;
        Ok(())
    }

    /// Rewrite the pins of `channel_id` with `edit`, saving the ring only
    /// when it changes. A channel with no key holds no pins, and is left as
    /// it is.
    async fn repin(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        edit: impl FnOnce(&KeyRing) -> KeyRing,
    ) -> Result<()> {
        let Some(ring) = self.key_ring(secret_id, channel_id).await? else {
            return Ok(());
        };
        let edited = edit(&ring);
        if edited != ring {
            self.save_key_ring(secret_id, channel_id, &edited).await?;
        }
        Ok(())
    }
}

impl<T: DeRecSecretStore> SecretStoreExt for T {}

/// A ring query answered with a value of another kind.
const WRONG_KIND_RING: Error =
    Error::Invariant("secret store answered a key ring query with another kind");

#[cfg(test)]
mod tests;
