//! The per-channel key chain and the keys a party holds.
//!
//! A channel starts under the key pairing established, K₀. When rotation is
//! on, the key moves forward one step per epoch: K₍ₑ₊₁₎ is
//! `HMAC-SHA256(Kₑ, label ‖ be32(e+1))`. The chain only runs forward, so a
//! key does not reveal the ones before it.
//!
//! `DeRecMessage.sequence` carries the epoch of the key a payload is
//! encrypted with. A party holds its newest key and one older key per pinned
//! secret version: a pin `(version, epoch)` records that the version
//! travelled under that epoch. A message from an epoch below the newest that
//! is not held is opened by deriving forward from the nearest held key below
//! it; a message from a newer epoch is opened by deriving forward from the
//! newest key, and the party then moves to that epoch. Either derivation is
//! bounded by [`FORWARD_JUMP_LIMIT`] steps, which bounds the work a forged
//! epoch can cause.
//!
//! # Retention
//!
//! Nothing is stored beyond the newest key and the keys the pins name: a key
//! is dropped when the last version that travelled under it is. Any secret
//! version a party still stores can therefore be answered, and a kept
//! version restores. Pairing negotiates nothing about retention.
//!
//! # Acceptance
//!
//! An epoch from 1 to [`FORWARD_JUMP_LIMIT`] steps above the newest key moves
//! the party forward once a payload decrypts under the derived key. An epoch
//! more than the limit above the newest key, below the oldest held key, or
//! more than the limit past the nearest held key below it has no usable key,
//! and the message is ignored. The envelope's `sequence` is not
//! authenticated: a forged value selects the wrong key, and decryption fails.
//!
//! # Forward secrecy
//!
//! Every key derives from the one before it, so a party holding Kₑ can
//! recompute every later key. Forward secrecy only covers epochs older than
//! the oldest key a party still holds. It is claimed against the compromise of
//! a helper device, or of a key alone, plus recorded transport traffic; it is
//! not claimed against the compromise of the owner device or of replica
//! devices, which hold the secret and the keys of the versions they store. A
//! compromised helper plus recorded traffic exposes the shares sent to that
//! helper from the oldest key it holds on. A key does not heal the chain:
//! the later keys stay derivable from it.

use crate::types::{ChannelKey, SharedKey};
use crate::{Error, Result};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

#[cfg(test)]
mod tests;

type HmacSha256 = Hmac<Sha256>;

/// Domain label mixed into every chain step.
const CHAIN_LABEL: &[u8] = b"derec channel key v1";

/// How many chain steps a party will derive from a held key to open a
/// message.
pub(crate) const FORWARD_JUMP_LIMIT: u32 = 512;

/// K₍ₑ₊₁₎ from Kₑ: `HMAC-SHA256(Kₑ, label ‖ be32(next_epoch))`.
pub(crate) fn next_key(key: &SharedKey, next_epoch: u32) -> SharedKey {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(CHAIN_LABEL);
    mac.update(&next_epoch.to_be_bytes());
    SharedKey::new(mac.finalize().into_bytes().into())
}

/// Version byte of the [`KeyRing`] encoding.
const RING_VERSION: u8 = 1;

/// Length of a key in the [`KeyRing`] encoding.
const KEY_LEN: usize = 32;

/// What a channel's key ring has to say about a message's epoch.
pub(crate) enum Lookup {
    /// The key is the newest one or an old one the ring holds.
    Held(ChannelKey),
    /// The epoch is below the newest and not held: the key was derived from
    /// the nearest held key below it, and is not stored.
    Behind(ChannelKey),
    /// The epoch is ahead of the newest: the key was derived, and `advanced`
    /// is the ring once the party has moved to that epoch.
    Ahead { key: ChannelKey, advanced: KeyRing },
    /// The epoch is neither held nor within the forward limit of a held key.
    Unavailable,
}

/// The keys a party holds for one channel: the newest key and its epoch, the
/// pins, and the older keys the pins name.
///
/// `pins` are `(version, epoch)`, sorted by version with unique versions.
/// `old` are `(epoch, key)`, strictly ascending by epoch, every epoch below
/// the newest and named by some pin. Keys between two held keys are not
/// stored; they are derived when needed. Each list holds at most
/// `u16::MAX` entries, the most its encoding can count.
///
/// With the `serde` feature, a deserialized ring is checked against the same
/// rules as [`KeyRing::from_bytes`].
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "RingFields"))]
pub struct KeyRing {
    epoch: u32,
    key: SharedKey,
    pins: Vec<(u32, u32)>,
    old: Vec<(u32, SharedKey)>,
}

impl KeyRing {
    /// The ring of a channel that has just been paired: epoch 0 under `key`,
    /// no pins and no old keys.
    pub(crate) fn fresh(key: SharedKey) -> Self {
        Self {
            epoch: 0,
            key,
            pins: Vec::new(),
            old: Vec::new(),
        }
    }

    /// The ring of a channel rebuilt from a published secret: `key` as the
    /// newest, with `version` pinned to its epoch.
    pub(crate) fn restored(key: &ChannelKey, version: u32) -> Self {
        Self {
            epoch: key.epoch,
            key: key.key.clone(),
            pins: Vec::new(),
            old: Vec::new(),
        }
        .pinned(version, key)
    }

    /// The epoch of the newest key.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// The newest key and its epoch.
    pub(crate) fn current(&self) -> ChannelKey {
        ChannelKey {
            epoch: self.epoch,
            key: self.key.clone(),
        }
    }

    /// The pins as `(version, epoch)`, sorted by version.
    pub(crate) fn pins(&self) -> &[(u32, u32)] {
        &self.pins
    }

    /// Resolve the epoch carried by a message.
    pub(crate) fn lookup(&self, sequence: u32) -> Lookup {
        if sequence == self.epoch {
            return Lookup::Held(self.current());
        }
        if sequence < self.epoch {
            if let Some((epoch, key)) = self.old.iter().find(|(e, _)| *e == sequence) {
                return Lookup::Held(ChannelKey {
                    epoch: *epoch,
                    key: key.clone(),
                });
            }
            let Some((base_epoch, base)) = self.old.iter().rev().find(|(e, _)| *e < sequence)
            else {
                return Lookup::Unavailable;
            };
            if sequence - base_epoch > FORWARD_JUMP_LIMIT {
                return Lookup::Unavailable;
            }
            return Lookup::Behind(ChannelKey {
                epoch: sequence,
                key: derive(base, *base_epoch, sequence),
            });
        }
        if sequence - self.epoch > FORWARD_JUMP_LIMIT {
            return Lookup::Unavailable;
        }
        let key = derive(&self.key, self.epoch, sequence);
        let mut old = self.old.clone();
        if self.names(self.epoch) {
            old.push((self.epoch, self.key.clone()));
        }
        Lookup::Ahead {
            key: ChannelKey {
                epoch: sequence,
                key: key.clone(),
            },
            advanced: KeyRing {
                epoch: sequence,
                key,
                pins: self.pins.clone(),
                old,
            },
        }
    }

    /// The key for `epoch` when the ring holds it or can derive it from an
    /// older held key. Never moves forward.
    #[allow(dead_code)]
    pub(crate) fn key_at(&self, epoch: u32) -> Option<ChannelKey> {
        match self.lookup(epoch) {
            Lookup::Held(key) | Lookup::Behind(key) => Some(key),
            Lookup::Ahead { .. } | Lookup::Unavailable => None,
        }
    }

    /// The ring advanced by one epoch, or `None` at the last epoch. The previous
    /// newest key stays only when a pin names its epoch.
    pub(crate) fn advanced(&self) -> Option<KeyRing> {
        match self.lookup(self.epoch.checked_add(1)?) {
            Lookup::Ahead { advanced, .. } => Some(advanced),
            _ => None,
        }
    }

    /// The ring with the pin of `version` set to `key.epoch`, replacing an
    /// existing pin of that version. The key is stored when it is below the
    /// newest and not already held; old keys no pin names are then dropped.
    ///
    /// A key from an epoch above the newest cannot belong to this ring; the
    /// ring is returned unchanged.
    pub(crate) fn pinned(&self, version: u32, key: &ChannelKey) -> KeyRing {
        if key.epoch > self.epoch {
            return self.clone();
        }
        let mut ring = self.clone();
        match ring.pins.binary_search_by_key(&version, |(v, _)| *v) {
            Ok(i) => ring.pins[i].1 = key.epoch,
            Err(i) => ring.pins.insert(i, (version, key.epoch)),
        }
        if key.epoch < ring.epoch
            && let Err(i) = ring.old.binary_search_by_key(&key.epoch, |(e, _)| *e)
        {
            ring.old.insert(i, (key.epoch, key.key.clone()));
        }
        ring.drop_unnamed();
        ring
    }

    /// The ring keeping only the pins whose version passes `keep`; old keys
    /// no pin names are then dropped. The newest key always stays.
    pub(crate) fn retain_pins(&self, keep: impl Fn(u32) -> bool) -> KeyRing {
        let mut ring = self.clone();
        ring.pins.retain(|(version, _)| keep(*version));
        ring.drop_unnamed();
        ring
    }

    fn names(&self, epoch: u32) -> bool {
        self.pins.iter().any(|(_, e)| *e == epoch)
    }

    fn drop_unnamed(&mut self) {
        let pins = &self.pins;
        self.old
            .retain(|(epoch, _)| pins.iter().any(|(_, e)| e == epoch));
    }

    /// Encode as `[version u8][epoch u32 BE][key 32B][pin_count u16 BE]`,
    /// `pin_count` pins of `(version u32 BE, epoch u32 BE)`, `[old_count u16
    /// BE]` and `old_count` old keys of `(epoch u32 BE, key 32B)`.
    ///
    /// # Errors
    ///
    /// [`Error::Invariant`] when the ring holds more pins or old keys than a
    /// `u16` count can express. Nothing is truncated.
    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        let (pin_count, old_count) = self.counts()?;
        let mut out =
            Vec::with_capacity(1 + 4 + KEY_LEN + 2 + self.pins.len() * 8 + 2 + self.old.len() * 36);
        out.push(RING_VERSION);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(self.key.as_bytes());
        out.extend_from_slice(&pin_count.to_be_bytes());
        for (version, epoch) in &self.pins {
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&epoch.to_be_bytes());
        }
        out.extend_from_slice(&old_count.to_be_bytes());
        for (epoch, key) in &self.old {
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(key.as_bytes());
        }
        Ok(out)
    }

    /// The pin and old-key counts as the encoding writes them, or
    /// [`Error::Invariant`] when either does not fit in a `u16`.
    pub(crate) fn counts(&self) -> Result<(u16, u16)> {
        let pins = u16::try_from(self.pins.len()).map_err(|_| {
            Error::Invariant("key ring holds more pins than its encoding can count")
        })?;
        let old = u16::try_from(self.old.len()).map_err(|_| {
            Error::Invariant("key ring holds more old keys than its encoding can count")
        })?;
        Ok((pins, old))
    }

    /// Decode the encoding of [`KeyRing::as_bytes`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] when the version is unknown, the length does
    /// not match the counts, a pin names an epoch above the newest, pin
    /// versions are duplicated or unsorted, an old epoch is not below the
    /// newest, old epochs are duplicated or unsorted, or an old key is named
    /// by no pin.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        if reader.take(1)?[0] != RING_VERSION {
            return Err(Error::InvalidInput("unknown key ring version"));
        }
        let epoch = reader.u32()?;
        let key = reader.key()?;

        let pin_count = reader.u16()?;
        let mut pins: Vec<(u32, u32)> = Vec::new();
        for _ in 0..pin_count {
            pins.push((reader.u32()?, reader.u32()?));
        }

        let old_count = reader.u16()?;
        let mut old: Vec<(u32, SharedKey)> = Vec::new();
        for _ in 0..old_count {
            old.push((reader.u32()?, reader.key()?));
        }
        if !reader.0.is_empty() {
            return Err(Error::InvalidInput("key ring has trailing bytes"));
        }
        Self::checked(epoch, key, pins, old)
    }

    /// A ring from its parts, unchecked, for tests that need a ring no
    /// operation produces.
    #[cfg(test)]
    pub(crate) fn unchecked(
        epoch: u32,
        key: SharedKey,
        pins: Vec<(u32, u32)>,
        old: Vec<(u32, SharedKey)>,
    ) -> Self {
        Self {
            epoch,
            key,
            pins,
            old,
        }
    }

    /// A ring from its parts, refused with [`Error::InvalidInput`] when they
    /// break a rule of [`KeyRing::from_bytes`].
    fn checked(
        epoch: u32,
        key: SharedKey,
        pins: Vec<(u32, u32)>,
        old: Vec<(u32, SharedKey)>,
    ) -> Result<Self> {
        if u16::try_from(pins.len()).is_err() || u16::try_from(old.len()).is_err() {
            return Err(Error::InvalidInput(
                "key ring holds more entries than its encoding can count",
            ));
        }
        for (i, pin) in pins.iter().enumerate() {
            if pin.1 > epoch {
                return Err(Error::InvalidInput("key ring pin is above its epoch"));
            }
            if i > 0 && pins[i - 1].0 >= pin.0 {
                return Err(Error::InvalidInput(
                    "key ring pin versions are not strictly ascending",
                ));
            }
        }
        for (i, (old_epoch, _)) in old.iter().enumerate() {
            if *old_epoch >= epoch {
                return Err(Error::InvalidInput(
                    "key ring old key is not below its epoch",
                ));
            }
            if i > 0 && old[i - 1].0 >= *old_epoch {
                return Err(Error::InvalidInput(
                    "key ring old epochs are not strictly ascending",
                ));
            }
            if !pins.iter().any(|(_, e)| e == old_epoch) {
                return Err(Error::InvalidInput("key ring old key is named by no pin"));
            }
        }
        Ok(Self {
            epoch,
            key,
            pins,
            old,
        })
    }
}

/// The serialized shape of a [`KeyRing`]: its fields, checked on the way in.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
struct RingFields {
    epoch: u32,
    key: SharedKey,
    pins: Vec<(u32, u32)>,
    old: Vec<(u32, SharedKey)>,
}

#[cfg(feature = "serde")]
impl TryFrom<RingFields> for KeyRing {
    type Error = Error;

    fn try_from(fields: RingFields) -> Result<Self> {
        Self::checked(fields.epoch, fields.key, fields.pins, fields.old)
    }
}

/// Kₜₒ from Kₑ by chaining `next_key` over the epochs after `from`.
pub(crate) fn derive(key: &SharedKey, from: u32, to: u32) -> SharedKey {
    let mut key = key.clone();
    for epoch in from + 1..=to {
        key = next_key(&key, epoch);
    }
    key
}

/// A cursor over the bytes of a [`KeyRing`] encoding.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            return Err(Error::InvalidInput("key ring is too short"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn key(&mut self) -> Result<SharedKey> {
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(self.take(KEY_LEN)?);
        Ok(SharedKey::new(key))
    }
}

impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let old_epochs: Vec<u32> = self.old.iter().map(|(epoch, _)| *epoch).collect();
        f.debug_struct("KeyRing")
            .field("epoch", &self.epoch)
            .field("pins", &self.pins)
            .field("old_epochs", &old_epochs)
            .finish_non_exhaustive()
    }
}
