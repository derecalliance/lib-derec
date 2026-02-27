// SPDX-License-Identifier: Apache-2.0

/// A type alias for a channel identifier which is defined during pairing.
/// In DeRec, the `ChannelId` is the hash of the initial contact message.
/// It is also symmetric; i.e., both parties will have the same `ChannelId`.
pub type ChannelId = u64;

