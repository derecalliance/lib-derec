// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, SecretKind, SecretValue,
};
use super::replicas::discovery as replica;
use crate::extensions::channel_store::ChannelStoreExt as _;
use crate::extensions::message_body::{MessageBodyExt as _, Route};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::discovery::{
        request,
        response::{self, SecretVersionEntry, VersionEntry},
    },
    protocol::{
        context::{Exchange, Local, Round},
        stores::{StoreSet, Stores},
        types::Target,
    },
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, GetSecretIdsVersionsRequestMessage, GetSecretIdsVersionsResponseMessage,
    MessageBody, SenderKind, StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn handle<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    inner: MessageBody,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    match (inner.route(), inner) {
        (Route::Replica(author), inner) => {
            replica::handle(stores, local, exchange, author, inner).await
        }
        (_, inner) => {
            let expected = match &inner {
                MessageBody::GetSecretIdsVersionsRequest(_) => SenderKind::Owner,
                _ => SenderKind::Helper,
            };
            stores
                .channels
                .require_role(local.secret_id, &[channel_id], expected)
                .await?;

            match inner {
                MessageBody::GetSecretIdsVersionsRequest(request) => on_request(exchange, request),
                MessageBody::GetSecretIdsVersionsResponse(response) => {
                    on_response(exchange, &response)
                }
                _ => Err(Error::Invariant(
                    "unexpected MessageBody variant in discovery handler",
                )),
            }
        }
    }
}

/// Dispatch a discovery request to each targeted channel.
///
/// The target is narrowed by [`Target::filter`] to channels this `secret_id`
/// actually holds — a caller-supplied id may name an unpaired channel, which
/// would otherwise trip the shared-key invariant below.
///
/// Dispatch failure is isolated per channel and surfaced as
/// `DiscoveryFailed` rather than short-circuiting the fan-out, so one
/// unreachable helper cannot suppress the rest.
#[cfg_attr(feature = "logging", tracing::instrument(skip_all, fields(trace_id = round.trace_id)))]
pub(in crate::protocol) async fn start<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    target: Target,
    round: &Round<'_>,
) -> Result<Vec<DeRecEvent>> {
    let known: Vec<ChannelId> = stores
        .channels
        .helpers_matching(
            local.secret_id,
            crate::protocol::types::HelperFilter {
                ids: target.ids(),
                ..Default::default()
            },
        )
        .await?
        .iter()
        .map(|ch| ch.channel_id)
        .collect();

    let channel_ids = target.filter(&known);

    let keys = stores
        .secrets
        .load_many(
            local.secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?;

    let events = dispatch_all(stores, local, keys, round).await;

    #[cfg(feature = "logging")]
    tracing::info!("discovery requests dispatched");

    Ok(events)
}

/// Answer a peer's discovery request with the catalog of secrets held
/// for it across every linked channel.
///
/// Entries are grouped by `secret_id`, then keyed by `version`. A helper
/// holds exactly one share per `(secret_id, version)` — a second write
/// carrying different content is refused with `VERSION_CONFLICT` rather
/// than stored alongside — so a version identifies a share unambiguously
/// and needs no writer to disambiguate it.
#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn accept<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &GetSecretIdsVersionsRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    let channel_id = exchange.channel_id;
    let secret_id = local.secret_id;

    let linked_ids = stores
        .channels
        .linked_channels(secret_id, channel_id)
        .await?;
    let all_shares = stores.shares.load_all(secret_id, &linked_ids).await?;

    let secret_list = catalog(all_shares);

    let resp = response::produce(channel_id, &secret_list, exchange.shared_key)?;

    let envelope = crate::derec_message::apply_trace_id(&resp.envelope, exchange.trace_id)?;
    let endpoint = stores
        .channels
        .resolve_response_endpoints(
            secret_id,
            channel_id,
            &crate::extensions::advertised_endpoints::reply_to_owned(request),
        )
        .await?;
    stores.transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!("discovery response sent");

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
pub(in crate::protocol) async fn reject<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    exchange: &Exchange<'_>,
    request: &GetSecretIdsVersionsRequestMessage,
    status: StatusEnum,
    memo: &str,
) -> Result<()> {
    let response = GetSecretIdsVersionsResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        secret_list: Vec::new(),
        timestamp: Some(current_timestamp()),
        // Answer on the path the request arrived on: a member asking gets a
        // member's answer, a helper exchange stays helper-bound.
        replica_id: local.replica_id.filter(|_| request.replica_id.is_some()),
    };

    crate::extensions::channel_store::send_channel_message(
        stores.channels,
        stores.transport,
        local.secret_id,
        exchange.channel_id,
        MessageBody::GetSecretIdsVersionsResponse(response),
        exchange.shared_key,
        exchange.trace_id,
        &crate::extensions::advertised_endpoints::reply_to_owned(request),
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_request(
    exchange: &Exchange<'_>,
    request: GetSecretIdsVersionsRequestMessage,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id: exchange.channel_id,
        action: PendingAction::Discovery {
            channel_id: exchange.channel_id,
            request,
            shared_key: *exchange.shared_key,
            trace_id: exchange.trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(trace_id = exchange.trace_id, channel_id = exchange.channel_id.0))
)]
fn on_response(
    exchange: &Exchange<'_>,
    response: &GetSecretIdsVersionsResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let result = response::process(response)?;

    #[cfg(feature = "logging")]
    tracing::info!(
        secrets_count = result.secret_list.len(),
        "secrets discovered"
    );

    Ok(vec![DeRecEvent::SecretsDiscovered {
        channel_id: exchange.channel_id,
        secrets: result.secret_list,
    }])
}

/// Send a request to every resolved channel, reporting each outcome.
///
/// Group a helper's stored shares into the per-secret version catalog a
/// discovery response reports.
///
/// One entry per secret, each listing every version held. Versions are
/// collected through a `BTreeMap` so the response is ordered and reproducible
/// rather than following store iteration order.
///
/// A version's description is read from the request that stored it. A share
/// whose bytes do not decode contributes an empty description rather than
/// failing the catalog: the version is still held, and refusing to report it
/// would hide state the peer needs to see. The first description wins, so a
/// re-store under the same version does not rewrite what was already reported.
fn catalog(all_shares: Vec<crate::protocol::types::Share>) -> Vec<SecretVersionEntry> {
    let mut secret_map: std::collections::HashMap<u64, std::collections::BTreeMap<u32, String>> =
        std::collections::HashMap::new();

    for share in all_shares {
        let description = StoreShareRequestMessage::decode(share.bytes.as_slice())
            .map(|msg| msg.version_description)
            .unwrap_or_default();
        secret_map
            .entry(share.secret_id)
            .or_default()
            .entry(share.version)
            .or_insert(description);
    }

    secret_map
        .into_iter()
        .map(|(secret_id, versions)| SecretVersionEntry {
            secret_id,
            versions: versions
                .into_iter()
                .map(|(version, description)| VersionEntry {
                    version,
                    description,
                })
                .collect(),
        })
        .collect()
}

/// One event per target, in the order the targets were resolved. A failure is
/// isolated to its own target: it becomes a `DiscoveryFailed` and the fan-out
/// continues, so one unreachable helper cannot suppress the rest.
async fn dispatch_all<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    keys: Vec<(ChannelId, SecretValue)>,
    round: &Round<'_>,
) -> Vec<DeRecEvent> {
    let mut events = Vec::with_capacity(keys.len());
    for (channel_id, value) in keys {
        let SecretValue::SharedKey(shared_key) = value else {
            events.push(DeRecEvent::DiscoveryFailed {
                channel_id,
                error: "channel has no shared key".to_owned(),
            });
            continue;
        };

        match dispatch_one(stores, local, channel_id, &shared_key, round).await {
            Ok(()) => {
                events.push(DeRecEvent::DiscoveryStarted {
                    channel_id,
                    trace_id: round.trace_id,
                });
                #[cfg(feature = "logging")]
                tracing::debug!(channel_id = channel_id.0, "discovery request sent");
            }
            Err(e) => {
                events.push(DeRecEvent::DiscoveryFailed {
                    channel_id,
                    error: e.to_string(),
                });
                #[cfg(feature = "logging")]
                tracing::warn!(
                    channel_id = channel_id.0,
                    error = %e,
                    "discovery request dispatch failed"
                );
            }
        }
    }
    events
}

async fn dispatch_one<S: StoreSet>(
    stores: &mut Stores<'_, S>,
    local: &Local<'_>,
    channel_id: ChannelId,
    shared_key: &SharedKey,
    round: &Round<'_>,
) -> Result<()> {
    let endpoint = stores
        .channels
        .peer_endpoints(local.secret_id, channel_id)
        .await?;
    let msg = request::produce(channel_id, shared_key, round.reply_to)?;
    let envelope = crate::derec_message::apply_trace_id(&msg.envelope, round.trace_id)?;
    stores.transport.send(&endpoint, envelope).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::Share;

    fn share(secret_id: u64, version: u32, description: &str) -> Share {
        Share {
            secret_id,
            version,
            bytes: StoreShareRequestMessage {
                version_description: description.to_owned(),
                ..Default::default()
            }
            .encode_to_vec(),
        }
    }

    /// Versions are reported in order regardless of the order the store
    /// returned them, so a peer diffing two catalogs sees a stable list.
    #[test]
    fn versions_are_reported_in_order() {
        let catalog = catalog(vec![
            share(1, 3, "third"),
            share(1, 1, "first"),
            share(1, 2, "second"),
        ]);

        let versions: Vec<u32> = catalog[0].versions.iter().map(|v| v.version).collect();
        assert_eq!(versions, vec![1, 2, 3]);
    }

    /// One entry per secret, each carrying only its own versions.
    #[test]
    fn each_secret_gets_its_own_entry() {
        let mut catalog = catalog(vec![share(1, 1, ""), share(2, 7, ""), share(1, 2, "")]);
        catalog.sort_by_key(|e| e.secret_id);

        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog[0].secret_id, 1);
        assert_eq!(catalog[0].versions.len(), 2);
        assert_eq!(catalog[1].secret_id, 2);
        assert_eq!(catalog[1].versions.len(), 1);
    }

    /// A share whose bytes do not decode is still held, so it is still
    /// reported — with an empty description rather than not at all. Dropping
    /// it would hide a version the peer needs to know about.
    #[test]
    fn an_undecodable_share_is_still_catalogued() {
        let catalog = catalog(vec![Share {
            secret_id: 1,
            version: 4,
            bytes: vec![0xFF, 0xFF, 0xFF],
        }]);

        assert_eq!(catalog[0].versions[0].version, 4);
        assert_eq!(catalog[0].versions[0].description, "");
    }

    /// A re-store under a version already present keeps the first
    /// description, so the catalog does not flip between reports.
    #[test]
    fn the_first_description_for_a_version_wins() {
        let catalog = catalog(vec![share(1, 1, "original"), share(1, 1, "later")]);

        assert_eq!(catalog[0].versions.len(), 1);
        assert_eq!(catalog[0].versions[0].description, "original");
    }
}
