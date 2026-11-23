// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Stateless producers and readers for each flow's messages.
//!
//! # Channel keys and epochs
//!
//! After pairing, every message is encrypted under the channel's key, which
//! moves forward one epoch each time the owner rotates it; see
//! [`crate::types::ChannelKey`]. Each channel `produce` takes a `ChannelKey`
//! and stamps its epoch into the envelope's `sequence`. Each `extract` takes
//! the key alone: read the epoch with [`crate::derec_message::read_sequence`],
//! then use the key held at that epoch or derive it forward with
//! [`crate::types::ChannelKey::derive`].
//!
//! The primitives keep no state. Tracking each channel's newest epoch, and
//! the keys older secret versions travelled under, is the caller's job; the
//! protocol layer does it for its own channels.

pub mod discovery;
pub mod pairing;
pub mod recovery;
pub mod sharing;
pub mod unpairing;
pub mod verification;

#[cfg(test)]
pub(crate) fn make_shared_key(byte: u8) -> crate::types::SharedKey {
    crate::types::SharedKey::new([byte; 32])
}
