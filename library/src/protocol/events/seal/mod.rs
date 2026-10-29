// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The seal that binds a [`PendingAction`](super::PendingAction) to the
//! channel it answers on.
//!
//! An action leaves the library between `process` and `accept`/`reject`, and
//! whatever comes back is acted on. The seal is an HMAC-SHA256 over what the
//! action says — its kind, channel, trace id and request — under a key
//! derived from the shared key of the channel that answers it. Only a holder
//! of that key can produce it, so an action that was altered, built by hand,
//! or moved to another channel does not verify. Nothing is stored: the key is
//! the one the secret store already holds.
//!
//! HMAC, not a bare hash: a hash has no secret and is recomputed by whoever
//! edits the action, and SHA-256 over `key || bytes` lets bytes be appended
//! under a valid tag, which a protobuf request would decode as overriding
//! fields.

use super::{ChannelRequest, FailedRequest, ReplyTarget};
use crate::types::{ChannelId, SharedKey};
use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Derives the seal key from a channel's shared key, so the channel key is
/// never used directly by a second algorithm.
const SEAL_KEY_LABEL: &[u8] = b"derec pending action seal v1";

/// The length of a seal, in bytes.
pub(crate) const SEAL_LEN: usize = 32;

/// What a seal covers beyond the channel and trace id: the request a
/// channel answers, or the failed request a reply channel answers.
pub(crate) enum Sealed<'a> {
    Request(&'a ChannelRequest),
    Failure {
        reply: &'a ReplyTarget,
        request: &'a FailedRequest,
    },
}

/// An HMAC-SHA256 tag over a [`PendingAction`](super::PendingAction).
#[derive(Clone)]
pub(crate) struct Seal([u8; SEAL_LEN]);

impl Seal {
    /// Seal `sealed`, raised on `channel_id` with `trace_id`, under `key`.
    pub(crate) fn new(
        key: &SharedKey,
        channel_id: ChannelId,
        trace_id: u64,
        sealed: Sealed<'_>,
    ) -> Self {
        let tag = mac(key, channel_id, trace_id, sealed)
            .finalize()
            .into_bytes();
        Self(tag.into())
    }

    /// Whether this seal is the one `key` gives `sealed`. Compared in
    /// constant time.
    pub(crate) fn verifies(
        &self,
        key: &SharedKey,
        channel_id: ChannelId,
        trace_id: u64,
        sealed: Sealed<'_>,
    ) -> bool {
        mac(key, channel_id, trace_id, sealed)
            .verify_slice(&self.0)
            .is_ok()
    }

    /// The tag's bytes, as a token carries them.
    #[cfg_attr(not(any(feature = "ffi", target_arch = "wasm32")), allow(dead_code))]
    pub(crate) fn as_bytes(&self) -> &[u8; SEAL_LEN] {
        &self.0
    }

    /// A tag read back from a token.
    #[cfg_attr(not(any(feature = "ffi", target_arch = "wasm32")), allow(dead_code))]
    pub(crate) fn from_bytes(bytes: [u8; SEAL_LEN]) -> Self {
        Self(bytes)
    }
}

/// The MAC over `sealed`, fed with an encoding in which every field but the
/// last has a fixed length or a length prefix, so two different actions
/// never encode alike.
fn mac(key: &SharedKey, channel_id: ChannelId, trace_id: u64, sealed: Sealed<'_>) -> HmacSha256 {
    let mut mac =
        HmacSha256::new_from_slice(&seal_key(key)[..]).expect("HMAC accepts a key of any length");
    mac.update(&channel_id.0.to_be_bytes());
    mac.update(&trace_id.to_be_bytes());
    match sealed {
        Sealed::Request(request) => {
            mac.update(&[request_tag(request)]);
            mac.update(&request_bytes(request));
        }
        Sealed::Failure { reply, request } => {
            mac.update(&[FAILURE_TAG]);
            mac.update(&reply.channel_id.0.to_be_bytes());
            mac.update(&(reply.endpoints.len() as u64).to_be_bytes());
            for endpoint in &reply.endpoints {
                let bytes = endpoint.encode_to_vec();
                mac.update(&(bytes.len() as u64).to_be_bytes());
                mac.update(&bytes);
            }
            let (tag, bytes) = failed_request(request);
            mac.update(&[tag]);
            mac.update(&bytes);
        }
    }
    mac
}

fn seal_key(key: &SharedKey) -> Zeroizing<[u8; 32]> {
    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(SEAL_KEY_LABEL);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

const FAILURE_TAG: u8 = 0xFF;

fn request_tag(request: &ChannelRequest) -> u8 {
    match request {
        ChannelRequest::StoreShare(_) => 1,
        ChannelRequest::VerifyShare(_) => 2,
        ChannelRequest::Discovery(_) => 3,
        ChannelRequest::GetShare(_) => 4,
        ChannelRequest::Unpair(_) => 5,
        ChannelRequest::UpdateChannelInfo(_) => 6,
    }
}

fn request_bytes(request: &ChannelRequest) -> Vec<u8> {
    match request {
        ChannelRequest::StoreShare(r) => r.encode_to_vec(),
        ChannelRequest::VerifyShare(r) => r.encode_to_vec(),
        ChannelRequest::Discovery(r) => r.encode_to_vec(),
        ChannelRequest::GetShare(r) => r.encode_to_vec(),
        ChannelRequest::Unpair(r) => r.encode_to_vec(),
        ChannelRequest::UpdateChannelInfo(r) => r.encode_to_vec(),
    }
}

fn failed_request(request: &FailedRequest) -> (u8, Vec<u8>) {
    match request {
        FailedRequest::StoreShare(r) => (1, r.encode_to_vec()),
        FailedRequest::VerifyShare(r) => (2, r.encode_to_vec()),
        FailedRequest::GetSecretIdsVersions(r) => (3, r.encode_to_vec()),
        FailedRequest::GetShare(r) => (4, r.encode_to_vec()),
        FailedRequest::Unpair(r) => (5, r.encode_to_vec()),
        FailedRequest::UpdateChannelInfo(r) => (6, r.encode_to_vec()),
        FailedRequest::Undecodable => (7, Vec::new()),
    }
}

#[cfg(test)]
mod tests;
