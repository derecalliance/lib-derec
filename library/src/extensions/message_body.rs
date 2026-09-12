// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! What an inbound body says about its own handling.
//!
//! Three questions get asked of every decrypted [`MessageBody`] before
//! anything acts on it: which relationship it concerns, which peer role may
//! have sent it, and which endpoints in it were chosen by the peer rather
//! than agreed at pairing. All three are answered by reading the body and
//! nothing else, so they are methods on the body.
//!
//! [`MessageBody`] is generated in `derec-proto`, so an inherent `impl` is
//! impossible from this crate. [`MessageBodyExt`] sidesteps the orphan rule the
//! same way every other trait in [`extensions`](super) does.

use derec_proto::{MessageBody, SenderKind, TransportProtocol};

/// The relationship an inbound body concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    /// Replica-bound, concerning this group member. Which member — author or
    /// target — is the flow's reading; see [`MessageBodyExt::route`].
    Replica(u64),
    /// Helper-bound: no member named, so the owner↔helper role gate applies.
    Helper,
}

/// Questions answered by reading an inbound body.
///
/// Bring the trait into scope (`use super::inbound::MessageBodyExt as _;`) and
/// call the methods on the body itself.
pub(crate) trait MessageBodyExt {
    /// Which relationship this body concerns.
    ///
    /// The discriminator is the payload's `replica_id`: present means the
    /// message is replica-bound, absent means it is helper-bound. Decryption
    /// is keyed by `channel_id` alone, so the channel it arrived on cannot
    /// answer the question — every member of a group answers on the same one.
    ///
    /// **Which** member the id names is the flow's to say, not this method's.
    /// On every body but one it is the author, which is what a reply is
    /// addressed to and what a response is attributed to. On `UnpairRequest`
    /// it is the member being *removed*: a removal is announced to every
    /// peer, so the target is the only thing they all agree on.
    ///
    /// A body that carries no `replica_id` field at all is always
    /// [`Route::Helper`]; it can only be an owner↔helper exchange.
    fn route(&self) -> Route;

    /// The peer role this body may only be sent by, or `None` when it does
    /// not have exactly one.
    ///
    /// A `Some` is gated before dispatch. A `None` means the body is
    /// **multi-valued** — legal from either relationship and meaning
    /// different things on each — so no single role can be required up
    /// front, and the owning flow applies the gate once [`Self::route`] has
    /// told it which relationship it is looking at.
    ///
    /// Store-share, discovery, get-share and unpair-request are all
    /// multi-valued for the same reason: an `Owner` peer drives them against
    /// a helper, and a group member drives the corresponding replica flow
    /// against another member. `UpdateChannelInfo` is `None` for a different
    /// reason — it is role-blind, either side may initiate it.
    fn expected_sender_role(&self) -> Option<SenderKind>;

    /// Every transport endpoint this body carries that a **peer** chose.
    ///
    /// One kind appears: `reply_to`, on the five request types that have
    /// one. It *overrides* the endpoints agreed at pairing for a single
    /// response, which is why checking only at pairing time would not be
    /// enough.
    ///
    /// # What is deliberately absent
    ///
    /// `PairRequest`, `PrePairRequest` and `UpdateChannelInfoRequest` all
    /// carry peer-chosen endpoints and none appears here. Each advertises a
    /// `supportedTransports` list, and filtering that list — applying the
    /// same `check_peer` to every entry — happens in its handler instead,
    /// where a failing entry is skipped rather than aborting the whole
    /// message. Gating them here would fail-fast on one bad entry even when
    /// a later one would have served, which for `UpdateChannelInfo` would
    /// additionally leave the peer's *stale* endpoints in place.
    ///
    /// `PrePairRequest` could not be gated here in any case: it travels in
    /// plaintext and takes its own dispatch path, which never reaches a
    /// caller of this method.
    ///
    /// Collected here so [`crate::transport::TransportPolicy`] has a single
    /// application point for what remains, rather than a copy in each
    /// response path and each handler.
    fn peer_supplied_endpoints(&self) -> impl Iterator<Item = &TransportProtocol>;
}

impl MessageBodyExt for MessageBody {
    fn route(&self) -> Route {
        let author = match self {
            MessageBody::StoreShareRequest(r) => r.replica_id,
            MessageBody::StoreShareResponse(r) => r.replica_id,
            MessageBody::GetSecretIdsVersionsRequest(r) => r.replica_id,
            MessageBody::GetSecretIdsVersionsResponse(r) => r.replica_id,
            MessageBody::GetShareRequest(r) => r.replica_id,
            MessageBody::GetShareResponse(r) => r.replica_id,
            MessageBody::UnpairRequest(r) => r.replica_id,
            _ => None,
        };
        match author {
            Some(author) => Route::Replica(author),
            None => Route::Helper,
        }
    }

    fn expected_sender_role(&self) -> Option<SenderKind> {
        match self {
            MessageBody::VerifyShareRequest(_) => Some(SenderKind::Owner),
            MessageBody::VerifyShareResponse(_) | MessageBody::UnpairResponse(_) => {
                Some(SenderKind::Helper)
            }
            // Multi-valued, or role-blind: gated by the owning flow, or not
            // at all. See the trait method's docs.
            _ => None,
        }
    }

    fn peer_supplied_endpoints(&self) -> impl Iterator<Item = &TransportProtocol> {
        use crate::extensions::advertised_endpoints::ReplyToEndpoints as _;

        let listed: Vec<&TransportProtocol> = match self {
            MessageBody::StoreShareRequest(r) => r.reply_to_endpoints(),
            MessageBody::VerifyShareRequest(r) => r.reply_to_endpoints(),
            MessageBody::GetSecretIdsVersionsRequest(r) => r.reply_to_endpoints(),
            MessageBody::GetShareRequest(r) => r.reply_to_endpoints(),
            MessageBody::UnpairRequest(r) => r.reply_to_endpoints(),
            _ => Vec::new(),
        };

        listed.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::{
        GetSecretIdsVersionsRequestMessage, GetShareResponseMessage, StoreShareRequestMessage,
        UnpairRequestMessage, UnpairResponseMessage, UpdateChannelInfoRequestMessage,
        VerifyShareRequestMessage, VerifyShareResponseMessage,
    };

    /// Every body that carries the field routes on it, so a new replica-aware
    /// message type cannot be added to the enum and silently take the helper
    /// path.
    #[test]
    fn every_replica_bearing_body_routes_on_its_author() {
        let bodies = [
            MessageBody::StoreShareRequest(StoreShareRequestMessage {
                replica_id: Some(7),
                ..Default::default()
            }),
            MessageBody::GetSecretIdsVersionsRequest(GetSecretIdsVersionsRequestMessage {
                replica_id: Some(7),
                ..Default::default()
            }),
            MessageBody::GetShareResponse(GetShareResponseMessage {
                replica_id: Some(7),
                ..Default::default()
            }),
            MessageBody::UnpairRequest(UnpairRequestMessage {
                replica_id: Some(7),
                ..Default::default()
            }),
        ];
        for body in bodies {
            assert_eq!(body.route(), Route::Replica(7), "{body:?}");
        }
    }

    /// The same bodies with the field absent are helper-bound.
    #[test]
    fn an_absent_author_is_helper_bound() {
        let body = MessageBody::StoreShareRequest(StoreShareRequestMessage {
            replica_id: None,
            ..Default::default()
        });
        assert_eq!(body.route(), Route::Helper);
    }

    /// A body with no `replica_id` field at all can only be helper-bound.
    #[test]
    fn a_body_without_the_field_is_helper_bound() {
        let body =
            MessageBody::UpdateChannelInfoRequest(UpdateChannelInfoRequestMessage::default());
        assert_eq!(body.route(), Route::Helper);
    }

    /// The gate applied before dispatch. Only the single-valued bodies name
    /// a role; naming one for a multi-valued body would reject the replica
    /// route of a message that is legal on it.
    #[test]
    fn only_single_valued_bodies_name_a_sender_role() {
        assert_eq!(
            MessageBody::VerifyShareRequest(VerifyShareRequestMessage::default())
                .expected_sender_role(),
            Some(SenderKind::Owner),
        );
        assert_eq!(
            MessageBody::VerifyShareResponse(VerifyShareResponseMessage::default())
                .expected_sender_role(),
            Some(SenderKind::Helper),
        );
        assert_eq!(
            MessageBody::UnpairResponse(UnpairResponseMessage::default()).expected_sender_role(),
            Some(SenderKind::Helper),
        );
    }

    /// Every body the owning flow gates for itself must report `None` here,
    /// or it would be refused up front on a route where it is legal.
    #[test]
    fn multi_valued_bodies_name_no_sender_role() {
        let multi_valued = [
            MessageBody::StoreShareRequest(StoreShareRequestMessage::default()),
            MessageBody::GetSecretIdsVersionsRequest(GetSecretIdsVersionsRequestMessage::default()),
            MessageBody::GetShareResponse(GetShareResponseMessage::default()),
            MessageBody::UnpairRequest(UnpairRequestMessage::default()),
            MessageBody::UpdateChannelInfoRequest(UpdateChannelInfoRequestMessage::default()),
        ];
        for body in multi_valued {
            assert_eq!(body.expected_sender_role(), None, "{body:?}");
        }
    }

    /// A `reply_to` is the one peer-chosen endpoint gated centrally, so a
    /// request carrying one must surface it.
    #[test]
    fn a_reply_to_is_reported_as_peer_supplied() {
        let endpoint = TransportProtocol {
            uri: "https://peer.example".to_owned(),
            protocol: derec_proto::Protocol::Https as i32,
        };
        let body = MessageBody::GetShareRequest(derec_proto::GetShareRequestMessage {
            reply_to_transports: vec![endpoint.clone()],
            ..Default::default()
        });
        let found: Vec<_> = body.peer_supplied_endpoints().collect();
        assert_eq!(found, vec![&endpoint]);
    }

    /// Responses carry no `reply_to`, and the pairing-time bodies are
    /// filtered by their own handlers instead — see the method's docs.
    #[test]
    fn bodies_without_a_reply_to_surface_nothing() {
        let bodies = [
            MessageBody::VerifyShareResponse(VerifyShareResponseMessage::default()),
            MessageBody::UpdateChannelInfoRequest(UpdateChannelInfoRequestMessage::default()),
        ];
        for body in bodies {
            assert_eq!(body.peer_supplied_endpoints().count(), 0, "{body:?}");
        }
    }
}
