// SPDX-License-Identifier: Apache-2.0

use super::super::{
    DeRecChannelStore, DeRecEvent, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    MissingPolicy, PendingAction, PendingRecovery, SecretKind, SecretValue,
};
use crate::{
    Error, Result,
    derec_message::current_timestamp,
    primitives::recovery::{RecoveryError, request, response},
    types::{ChannelId, SharedKey},
};
use derec_proto::{
    DeRecResult, DeRecSecret, GetShareRequestMessage, GetShareResponseMessage, MessageBody,
    StatusEnum, StoreShareRequestMessage,
};
use prost::Message;

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(channel_id = channel_id.0))
)]
pub(in crate::protocol) fn handle(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    inner: MessageBody,
    shared_key: SharedKey,
    inbound_trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    match inner {
        MessageBody::GetShareRequest(request) => {
            on_request(channel_id, request, shared_key, inbound_trace_id)
        }
        MessageBody::GetShareResponse(response) => {
            on_response(pending_recovery, channel_id, &response)
        }
        _ => Err(Error::Invariant(
            "unexpected MessageBody variant in recovery handler",
        )),
    }
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(skip_all, fields(secret_id = secret_id, version = version))
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn start<
    Ch: DeRecChannelStore,
    Ss: DeRecSecretStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    secret_store: &mut Ss,
    transport: &T,
    pending_recovery: &mut PendingRecovery,
    secret_id: u64,
    version: u32,
    reply_to: Option<derec_proto::TransportProtocol>,
) -> Result<()> {
    pending_recovery.insert((secret_id, version), Vec::new());

    let all_channels = channel_store.channels(secret_id).await?;
    let channel_ids: Vec<ChannelId> = all_channels.iter().map(|c| c.id).collect();
    let mut keys: std::collections::HashMap<ChannelId, SharedKey> = secret_store
        .load_many(
            secret_id,
            &channel_ids,
            SecretKind::SharedKey,
            MissingPolicy::Fail,
        )
        .await?
        .into_iter()
        .filter_map(|(cid, v)| match v {
            SecretValue::SharedKey(k) => Some((cid, k)),
            _ => None,
        })
        .collect();

    for channel in all_channels {
        let shared_key = keys
            .remove(&channel.id)
            .expect("load_many(MissingPolicy::Fail) guarantees an entry per id");

        let msg = request::produce(
            channel.id,
            secret_id,
            version,
            &shared_key,
            reply_to.clone(),
        )?;
        let envelope = super::apply_trace_id(msg.envelope, super::fresh_trace_id())?;
        transport.send(&channel.transport, envelope).await?;

        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel.id.0,
            secret_id,
            version,
            "share request sent"
        );
    }

    #[cfg(feature = "logging")]
    tracing::info!(
        secret_id,
        version,
        "share requests dispatched to all helpers"
    );

    Ok(())
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn accept<
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    T: DeRecTransport,
>(
    channel_store: &mut Ch,
    share_store: &mut Sh,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &GetShareRequestMessage,
    shared_key: &SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    let linked_ids = channel_store.linked_channels(secret_id, channel_id).await?;

    let encoded = share_store
        .load_many(secret_id, &linked_ids, &[request.version])
        .await?
        .into_iter()
        .next()
        .map(|s| s.bytes)
        .ok_or(Error::InvalidInput("no stored share for recovery request"))?;

    let stored =
        StoreShareRequestMessage::decode(encoded.as_slice()).map_err(Error::ProtobufDecode)?;

    let resp = response::produce(channel_id, request, &stored, shared_key)?;

    let envelope = super::apply_trace_id(resp.envelope, trace_id)?;
    let endpoint = super::resolve_response_endpoint(
        channel_store,
        secret_id,
        channel_id,
        request.reply_to.as_ref(),
    )
    .await?;
    transport.send(&endpoint, envelope).await?;

    #[cfg(feature = "logging")]
    tracing::info!(
        channel_id = channel_id.0,
        secret_id = request.secret_id,
        version = request.version,
        "recovery share response sent"
    );

    Ok(vec![DeRecEvent::NoOp])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
#[allow(clippy::too_many_arguments)]
pub(in crate::protocol) async fn reject<Ch: DeRecChannelStore, T: DeRecTransport>(
    channel_store: &mut Ch,
    transport: &T,
    secret_id: u64,
    channel_id: ChannelId,
    request: &GetShareRequestMessage,
    shared_key: &SharedKey,
    status: StatusEnum,
    memo: &str,
    trace_id: u64,
) -> Result<()> {
    let response = GetShareResponseMessage {
        result: Some(DeRecResult {
            status: status as i32,
            memo: memo.to_owned(),
        }),
        committed_de_rec_share: Vec::new(),
        share_algorithm: 0,
        timestamp: Some(current_timestamp()),
        secret_id: request.secret_id,
        version: request.version,
    };

    super::send_channel_message(
        channel_store,
        transport,
        secret_id,
        channel_id,
        MessageBody::GetShareResponse(response),
        shared_key,
        trace_id,
        request.reply_to.as_ref(),
    )
    .await
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = request.secret_id,
            version = request.version
        )
    )
)]
fn on_request(
    channel_id: ChannelId,
    request: GetShareRequestMessage,
    shared_key: SharedKey,
    trace_id: u64,
) -> Result<Vec<DeRecEvent>> {
    Ok(vec![DeRecEvent::ActionRequired {
        channel_id,
        action: PendingAction::GetShare {
            channel_id,
            request,
            shared_key,
            trace_id,
        },
    }])
}

#[cfg_attr(
    feature = "logging",
    tracing::instrument(
        skip_all,
        fields(
            channel_id = channel_id.0,
            secret_id = response.secret_id,
            version = response.version
        )
    )
)]
fn on_response(
    pending_recovery: &mut PendingRecovery,
    channel_id: ChannelId,
    response: &GetShareResponseMessage,
) -> Result<Vec<DeRecEvent>> {
    let key = (response.secret_id, response.version);
    let (secret_id, version) = key;

    let Some(bucket) = pending_recovery.get_mut(&key) else {
        #[cfg(feature = "logging")]
        tracing::debug!(
            channel_id = channel_id.0,
            secret_id,
            version,
            "recovery response has no matching pending recovery; dropping"
        );
        return Ok(vec![DeRecEvent::NoOp]);
    };

    bucket.push(response.clone());
    let shares_received = bucket.len();
    let inputs: Vec<&GetShareResponseMessage> = bucket.iter().collect();

    let event = match response::recover(secret_id, version, &inputs) {
        Ok(result) => {
            // Two-stage decode of the canonical protect-side wrapping
            // (`handlers::sharing::wrap_for_helper_split`):
            //   raw VSS bytes  → DeRecSecret { secret_data: <encoded Secret> }
            //   inner field    → Secret { helpers, secrets, replicas, owner_replica_id }
            // The typed `Secret` is what we hand to the application via
            // `DeRecEvent::SecretRecovered`, matching the symmetry with the
            // input-side `start(ProtectSecret, secrets: Vec<UserSecret>)`
            // call. A decode failure here means the math reconstructed
            // *something* but not a wire-shape the protocol recognises —
            // share corruption — and surfaces as
            // `RecoveryShareError`, leaving the bucket intact so further
            // shares can still arrive and retry.
            let typed_secret = match decode_recovered_secret(&result.secret_data) {
                Ok(s) => s,
                Err(e) => {
                    #[cfg(feature = "logging")]
                    tracing::warn!(
                        channel_id = channel_id.0,
                        secret_id,
                        version,
                        shares_received,
                        error = %e,
                        "recovered bytes did not decode as canonical Secret protobuf"
                    );

                    return Ok(vec![DeRecEvent::RecoveryShareError {
                        channel_id,
                        shares_received,
                        error: e.to_string(),
                    }]);
                }
            };

            pending_recovery.remove(&key);

            #[cfg(feature = "logging")]
            tracing::info!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                "secret reconstructed from shares"
            );

            DeRecEvent::SecretRecovered {
                secret: typed_secret,
            }
        }
        Err(Error::Recovery(RecoveryError::ReconstructionFailed { ref source }))
            if matches!(
                source,
                derec_cryptography::vss::DerecVSSError::InsufficientShares
            ) =>
        {
            #[cfg(feature = "logging")]
            tracing::debug!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                "reconstruction not yet possible — insufficient shares"
            );

            DeRecEvent::RecoveryShareReceived {
                channel_id,
                shares_received,
            }
        }
        Err(e) => {
            #[cfg(feature = "logging")]
            tracing::warn!(
                channel_id = channel_id.0,
                secret_id,
                version,
                shares_received,
                error = %e,
                "recovery share response received but reconstruction failed"
            );

            DeRecEvent::RecoveryShareError {
                channel_id,
                shares_received,
                error: e.to_string(),
            }
        }
    };

    Ok(vec![event])
}

/// Two-stage decode of the protect-side wrapping produced by
/// [`super::sharing::wrap_for_helper_split`]: the outer `DeRecSecret`
/// envelope (created at distribution time) carries the inner `Secret`
/// snapshot as its `secret_data` field, both as protobuf bytes.
///
/// VSS reconstructs the *outer* bytes, so this helper applies both
/// decode steps and returns the typed [`crate::protocol::types::Secret`]
/// for [`DeRecEvent::SecretRecovered`].
///
/// Errors as
/// [`RecoveryError::MalformedRecoveredSecret`](crate::primitives::recovery::RecoveryError::MalformedRecoveredSecret)
/// when either layer fails to decode — the math reconstructed
/// *something* but not a wire-shape the protocol recognises.
fn decode_recovered_secret(outer_bytes: &[u8]) -> Result<crate::protocol::types::Secret> {
    let derec_secret = DeRecSecret::decode(outer_bytes)
        .map_err(|source| RecoveryError::MalformedRecoveredSecret { source })?;
    let secret =
        crate::protocol::types::Secret::decode(derec_secret.secret_data.as_slice())
            .map_err(|source| RecoveryError::MalformedRecoveredSecret { source })?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::types::{HelperInfo, ReplicaInfo, Secret, UserSecret};
    use prost::Message;
    use std::collections::HashMap;

    /// Encode a `Secret` the same way `handlers::sharing::wrap_for_helper_split`
    /// does, producing the bytes that VSS would reconstruct on the happy
    /// path. The protect side is the canonical source of this wrapping;
    /// `decode_recovered_secret` is its inverse.
    fn encode_protect_wrapping(secret: &Secret) -> Vec<u8> {
        let derec_secret = derec_proto::DeRecSecret {
            secret_data: secret.encode_to_vec(),
            creation_time: None,
            helper_threshold_for_recovery: 2,
            helper_threshold_for_confirming_share_receipt: 2,
            helpers: Vec::new(),
        };
        derec_secret.encode_to_vec()
    }

    fn fixture_secret() -> Secret {
        Secret {
            helpers: vec![HelperInfo {
                channel_id: 7,
                transport_uri: "https://helper.example".to_owned(),
                shared_key: vec![0xAA; 32],
                communication_info: HashMap::from([("name".to_owned(), "Helper".to_owned())]),
            }],
            secrets: vec![
                UserSecret {
                    id: vec![0x01],
                    name: "wallet seed".to_owned(),
                    data: b"correct horse battery staple".to_vec(),
                },
                UserSecret {
                    id: vec![0x02],
                    name: "api token".to_owned(),
                    data: b"hunter2".to_vec(),
                },
            ],
            replicas: Some(crate::protocol::types::Replicas {
                replicas: vec![ReplicaInfo {
                    channel_id: 11,
                    transport_uri: "https://replica.example".to_owned(),
                    communication_info: HashMap::new(),
                    replica_id: 0xCAFE,
                    sender_kind: derec_proto::SenderKind::ReplicaDestination as i32,
                }],
                shared_key: vec![0x55; 32],
            }),
            owner_replica_id: 0xBEEF,
        }
    }

    #[test]
    fn decode_recovered_secret_round_trips_user_secrets() {
        let original = fixture_secret();
        let wrapped = encode_protect_wrapping(&original);

        let decoded = decode_recovered_secret(&wrapped).expect("decode must succeed");

        assert_eq!(
            decoded.secrets.len(),
            original.secrets.len(),
            "all UserSecret entries must round-trip"
        );
        for (got, want) in decoded.secrets.iter().zip(original.secrets.iter()) {
            assert_eq!(got.id, want.id, "UserSecret.id must round-trip");
            assert_eq!(got.name, want.name, "UserSecret.name must round-trip");
            assert_eq!(got.data, want.data, "UserSecret.data must round-trip");
        }

        assert_eq!(decoded.helpers.len(), 1);
        assert_eq!(decoded.helpers[0].channel_id, 7);
        let group = decoded.replicas.as_ref().expect("replicas must round-trip");
        assert_eq!(group.replicas.len(), 1);
        assert_eq!(group.replicas[0].replica_id, 0xCAFE);
        assert_eq!(decoded.owner_replica_id, 0xBEEF);
    }

    /// Empty `secret_data` inside a well-formed `DeRecSecret` decodes
    /// into a default-initialised `Secret` (all-empty rosters, no
    /// secrets). The protect side never produces this, but the decode
    /// helper must not panic if it ever sees it.
    #[test]
    fn decode_recovered_secret_handles_empty_inner_secret() {
        let wrapped = derec_proto::DeRecSecret {
            secret_data: Vec::new(),
            creation_time: None,
            helper_threshold_for_recovery: 1,
            helper_threshold_for_confirming_share_receipt: 1,
            helpers: Vec::new(),
        }
        .encode_to_vec();

        let decoded = decode_recovered_secret(&wrapped).expect("empty inner must decode");
        assert!(decoded.secrets.is_empty());
        assert!(decoded.helpers.is_empty());
    }

    #[test]
    fn decode_recovered_secret_rejects_garbage_outer_bytes() {
        // Crafted to fail the outer `DeRecSecret::decode` step — high-bit
        // bytes that don't form a valid protobuf tag.
        let garbage = vec![0xFFu8; 32];
        let err = decode_recovered_secret(&garbage).expect_err("garbage outer must fail");
        let Error::Recovery(RecoveryError::MalformedRecoveredSecret { .. }) = err else {
            panic!("expected MalformedRecoveredSecret, got {err:?}");
        };
    }
}
