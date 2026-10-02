// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::transport_protocol::TransportProtocolExt as _;
use derec_proto::{
    GetSecretIdsVersionsRequestMessage, GetShareRequestMessage, StoreShareRequestMessage,
    UnpairRequestMessage, VerifyShareRequestMessage,
};

/// Structural validation for a decoded request that may name its own reply
/// route, attached as a method the same way [`PairRequestMessageExt`]
/// attaches it to the pairing request.
///
/// Every flow's request can carry `reply_to_transports`: the endpoints the
/// sender wants its answer delivered to for this exchange. Bring the trait
/// into scope (`use crate::extensions::request_message::RequestMessageExt as _;`)
/// and call `request.validate()?` once the request is decrypted, before any
/// field of it is used.
///
/// [`PairRequestMessageExt`]: super::pair_request::PairRequestMessageExt
pub(crate) trait RequestMessageExt {
    /// Every endpoint in `reply_to_transports` is structurally sound: a URI
    /// that parses, with a scheme its declared protocol admits.
    ///
    /// Says nothing about whether those endpoints are *acceptable* — that is
    /// [`TransportPolicy`](crate::transport::TransportPolicy)'s decision, made
    /// later against configuration this validator cannot see.
    fn validate(&self) -> Result<(), crate::Error>;
}

macro_rules! impl_request_message_ext {
    ($($message:ty),+ $(,)?) => {
        $(
            impl RequestMessageExt for $message {
                fn validate(&self) -> Result<(), crate::Error> {
                    for endpoint in &self.reply_to_transports {
                        endpoint.validate()?;
                    }
                    Ok(())
                }
            }
        )+
    };
}

impl_request_message_ext!(
    GetSecretIdsVersionsRequestMessage,
    GetShareRequestMessage,
    StoreShareRequestMessage,
    UnpairRequestMessage,
    VerifyShareRequestMessage,
);

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::{Protocol, TransportProtocol};

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https.into(),
        }
    }

    /// Every request kind accepts sound reply-to endpoints, or none, and
    /// refuses one that is malformed.
    #[test]
    fn every_request_kind_checks_its_reply_to_endpoints() {
        fn check<M: RequestMessageExt>(with: impl Fn(Vec<TransportProtocol>) -> M) {
            assert!(with(Vec::new()).validate().is_ok());
            assert!(
                with(vec![endpoint("https://reply.example")])
                    .validate()
                    .is_ok()
            );
            assert!(with(vec![endpoint("not a uri")]).validate().is_err());
        }
        check(|reply_to_transports| GetSecretIdsVersionsRequestMessage {
            reply_to_transports,
            ..Default::default()
        });
        check(|reply_to_transports| GetShareRequestMessage {
            reply_to_transports,
            ..Default::default()
        });
        check(|reply_to_transports| StoreShareRequestMessage {
            reply_to_transports,
            ..Default::default()
        });
        check(|reply_to_transports| UnpairRequestMessage {
            reply_to_transports,
            ..Default::default()
        });
        check(|reply_to_transports| VerifyShareRequestMessage {
            reply_to_transports,
            ..Default::default()
        });
    }
}
