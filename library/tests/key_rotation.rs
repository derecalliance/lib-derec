// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! With key rotation on, the owner advances every helper channel one epoch in
//! each sharing round that reaches the threshold, and a replica source
//! advances the group channel on each publish to replicas. The published
//! secret records each channel's epoch and key, so a restored owner and a
//! hydrated destination rebuild their key rings at that epoch and keep
//! talking to helpers that have moved on.

#[path = "support/key_rig.rs"]
mod key_rig;
#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use derec_library::protocol::types::{HelperInfo, ReplicaRole, Secret, Target, UserSecret};
use derec_library::protocol::{
    Action, AutoAcceptPolicy, ChannelRequest, DeRecEvent, DeRecFlow, IgnoreReason, PendingAction,
    SecretKind, VerifyFailureReason,
};
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use key_rig::{
    A, B, C, D1, D1_URI, D2, D2_URI, EPHEMERAL, GROUP, HELPER_A_URI, HELPER_B_URI, HELPER_C_URI,
    OWNER_URI, Party, SOURCE, SOURCE_URI, deliver_clean, k0, key_at, recover, sequence_of,
};
use protocol_doubles::run_async;

const HELPERS: [(ChannelId, &str); 3] = [(A, HELPER_A_URI), (B, HELPER_B_URI), (C, HELPER_C_URI)];

/// An owner and `n` helpers, each paired with it at epoch 0.
async fn fleet(owner: Party, n: usize) -> (Party, Vec<(ChannelId, Party)>) {
    fleet_with(owner, n, None).await
}

/// An owner and `n` helpers that accept without the application what
/// `auto_accept` names, each paired with the owner at epoch 0.
async fn fleet_with(
    owner: Party,
    n: usize,
    auto_accept: Option<AutoAcceptPolicy>,
) -> (Party, Vec<(ChannelId, Party)>) {
    let mut helpers = Vec::new();
    for &(channel_id, uri) in &HELPERS[..n] {
        owner.pair_helper(channel_id, SenderKind::Helper, uri).await;
        let helper = Party {
            auto_accept,
            ..Party::new(uri)
        };
        helper
            .pair_helper(channel_id, SenderKind::Owner, OWNER_URI)
            .await;
        helpers.push((channel_id, helper));
    }
    (owner, helpers)
}

/// Protect a new version and run it to completion with every helper.
async fn round(owner: &Party, helpers: &[(ChannelId, Party)]) {
    owner.protect().await;
    for (_, helper) in helpers {
        deliver_clean(owner, helper).await;
        deliver_clean(helper, owner).await;
    }
}

/// Verify `version` with every helper, and check every one is verified.
async fn verified(owner: &Party, helpers: &[(ChannelId, Party)], version: u32) {
    owner.verify(version).await;
    let mut events = Vec::new();
    for (_, helper) in helpers {
        deliver_clean(owner, helper).await;
        events.extend(deliver_clean(helper, owner).await);
    }
    for (channel_id, _) in helpers {
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareVerified { channel_id: c, version: v, .. }
                    if c == channel_id && *v == version
            )),
            "{channel_id:?} verified v{version}: {events:?}"
        );
    }
}

fn helper_entry(secret: &Secret, channel_id: ChannelId) -> &HelperInfo {
    secret
        .helpers
        .iter()
        .find(|h| h.channel_id == channel_id.0)
        .expect("the roster names the helper")
}

/// A device that has lost everything, restoring as the same owner.
fn fresh_owner() -> Party {
    Party::rotating(OWNER_URI)
}

#[test]
fn with_rotation_on_each_new_version_advances_every_channel() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        round(&owner, &helpers).await;
        round(&owner, &helpers).await;

        for (channel_id, helper) in &helpers {
            let ring = owner.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (2, key_at(*channel_id, 2)));
            let ring = helper.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (2, key_at(*channel_id, 2)));
            assert_eq!(helper.stored_versions(*channel_id), vec![1, 2]);
        }
    });
}

#[test]
fn with_rotation_off_the_epoch_stays() {
    run_async(async {
        let (owner, helpers) = fleet(Party::new(OWNER_URI), 2).await;
        round(&owner, &helpers).await;
        round(&owner, &helpers).await;

        for (channel_id, helper) in &helpers {
            let ring = owner.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (0, *k0(*channel_id).as_bytes()));
            assert_eq!(helper.ring(*channel_id).epoch, 0);
            assert_eq!(helper.stored_versions(*channel_id), vec![1, 2]);
        }
    });
}

#[test]
fn turning_rotation_off_keeps_the_current_key_not_k0() {
    run_async(async {
        let (mut owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        round(&owner, &helpers).await;
        round(&owner, &helpers).await;

        owner.rotation = false;
        owner.protect().await;
        for (channel_id, helper) in &helpers {
            let ring = owner.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (2, key_at(*channel_id, 2)));
            let sent = owner.take_sent_to(helper.uri);
            assert_eq!(sent.len(), 1);
            assert_eq!(sequence_of(&sent[0]), 2, "sent under K2");
            for envelope in sent {
                let events = helper.build().process(&envelope).await.expect("processed");
                assert!(
                    !events
                        .iter()
                        .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
                    "{events:?}"
                );
            }
            assert!(helper.stored_versions(*channel_id).contains(&3));
        }
    });
}

#[test]
fn the_published_secret_names_the_new_epoch_and_key() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        round(&owner, &helpers).await;
        round(&owner, &helpers).await;

        let holders: Vec<(&Party, ChannelId)> = helpers.iter().map(|(c, h)| (h, *c)).collect();
        let secret = recover(&holders, 2);
        for (channel_id, _) in &helpers {
            let entry = helper_entry(&secret, *channel_id);
            assert_eq!(entry.key_epoch, 2);
            assert_eq!(entry.shared_key, key_at(*channel_id, 2).to_vec());
        }

        let secret = recover(&holders, 1);
        for (channel_id, _) in &helpers {
            let entry = helper_entry(&secret, *channel_id);
            assert_eq!(entry.key_epoch, 1);
            assert_eq!(entry.shared_key, key_at(*channel_id, 1).to_vec());
        }
    });
}

#[test]
fn a_restore_after_rotations_talks_to_helpers() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        for _ in 0..3 {
            round(&owner, &helpers).await;
        }

        let holders: Vec<(&Party, ChannelId)> = helpers.iter().map(|(c, h)| (h, *c)).collect();
        let secret = recover(&holders, 3);
        let restored = fresh_owner();
        restored
            .build()
            .restore(&secret, 3)
            .await
            .expect("restore succeeds");
        for (channel_id, _) in &helpers {
            let ring = restored.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (3, key_at(*channel_id, 3)));
            assert_eq!(ring.pins, vec![(3, 3)]);
        }

        round(&restored, &helpers).await;
        for (channel_id, helper) in &helpers {
            assert_eq!(restored.ring(*channel_id).epoch, 4);
            assert_eq!(helper.ring(*channel_id).epoch, 4);
        }
        verified(&restored, &helpers, 4).await;
    });
}

#[test]
fn a_restore_after_rotations_brings_a_helper_that_missed_a_round_forward() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 3).await;
        round(&owner, &helpers).await;
        round(&owner, &helpers).await;
        // The helper on C misses the third round.
        owner.protect().await;
        for (channel_id, helper) in &helpers {
            if *channel_id == C {
                owner.take_sent_to(helper.uri);
                continue;
            }
            deliver_clean(&owner, helper).await;
            deliver_clean(helper, &owner).await;
        }
        assert_eq!(helpers[2].1.ring(C).epoch, 2);

        let holders: Vec<(&Party, ChannelId)> = helpers[..2].iter().map(|(c, h)| (h, *c)).collect();
        let secret = recover(&holders, 3);
        let restored = fresh_owner();
        restored
            .build()
            .restore(&secret, 3)
            .await
            .expect("restore succeeds");
        assert_eq!(restored.ring(C).epoch, 3);

        round(&restored, &helpers).await;
        let ring = helpers[2].1.ring(C);
        assert_eq!(
            (ring.epoch, ring.key),
            (4, key_at(C, 4)),
            "C followed forward"
        );
        verified(&restored, &helpers, 4).await;
    });
}

/// The design's scenario: V1 at epoch 1, V2 to V15 lost, V16 with keep V1.
/// Two helpers at epoch 16 that keep V1 with K1 pinned, and an owner that
/// lost everything and restored V1, at epoch 1.
async fn restored_at_v1_while_helpers_are_at_16() -> (Party, Vec<(ChannelId, Party)>) {
    let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
    round(&owner, &helpers).await;
    for _ in 2..=15 {
        owner.protect().await;
        owner.drop_sent();
    }
    owner.keep(1);
    round(&owner, &helpers).await;
    for (channel_id, helper) in &helpers {
        let ring = helper.ring(*channel_id);
        assert_eq!(ring.epoch, 16);
        assert_eq!(ring.pins, vec![(1, 1), (16, 16)]);
        assert_eq!(helper.stored_versions(*channel_id), vec![1, 16]);
    }

    let holders: Vec<(&Party, ChannelId)> = helpers.iter().map(|(c, h)| (h, *c)).collect();
    let secret = recover(&holders, 1);
    let restored = fresh_owner();
    restored
        .build()
        .restore(&secret, 1)
        .await
        .expect("restore succeeds");
    for (channel_id, _) in &helpers {
        let ring = restored.ring(*channel_id);
        assert_eq!((ring.epoch, ring.key), (1, key_at(*channel_id, 1)));
    }
    (restored, helpers)
}

/// The owner restores V1 on a fresh device, at epoch 1, while the helpers are
/// at 16 and hold K1 for V1. The restored owner's V2 travels under K2, which
/// each helper derives from K1; the helper answers under K2 and pins V2 to
/// epoch 2.
#[test]
fn restoring_a_kept_older_version_still_talks_to_helpers() {
    run_async(async {
        let (restored, helpers) = restored_at_v1_while_helpers_are_at_16().await;

        restored.protect().await;
        for (_, helper) in &helpers {
            let sent = restored.take_sent_to(helper.uri);
            assert_eq!(
                sent.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![2]
            );
            for envelope in sent {
                helper.build().process(&envelope).await.expect("processed");
            }
            let answer = helper.take_sent_to(OWNER_URI);
            assert_eq!(
                answer.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![2],
                "the helper answers under the request's epoch"
            );
            for envelope in answer {
                restored
                    .build()
                    .process(&envelope)
                    .await
                    .expect("processed");
            }
        }
        for (channel_id, helper) in &helpers {
            let ring = helper.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (16, key_at(*channel_id, 16)));
            assert!(ring.pins.contains(&(2, 2)), "{ring:?}");
            assert!(
                ring.old.contains(&(1, key_at(*channel_id, 1))),
                "K1 is still held: {ring:?}"
            );
            assert_eq!(helper.stored_versions(*channel_id), vec![1, 2, 16]);
        }
        verified(&restored, &helpers, 2).await;
    });
}

/// The pending action of an `ActionRequired` among `events`.
fn pending(events: Vec<DeRecEvent>) -> PendingAction {
    events
        .into_iter()
        .find_map(|e| match e {
            DeRecEvent::ActionRequired { action, .. } => Some(action),
            _ => None,
        })
        .expect("an action is raised")
}

/// A VerifyShare from the restored owner at epoch 2, to helpers at 16 that
/// derive K2 from K1, is auto-accepted and answered under K2; the owner stays
/// at epoch 2.
#[test]
fn an_auto_accepted_verification_is_answered_under_the_request_epoch() {
    run_async(async {
        let (restored, helpers) = restored_at_v1_while_helpers_are_at_16().await;
        restored.protect().await;
        for (_, helper) in &helpers {
            deliver_clean(&restored, helper).await;
            helper.drop_sent();
        }

        restored.verify(2).await;
        let mut events = Vec::new();
        for (channel_id, helper) in &helpers {
            let sent = restored.take_sent_to(helper.uri);
            assert_eq!(
                sent.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![2]
            );
            for envelope in sent {
                helper.build().process(&envelope).await.expect("processed");
            }
            let answer = helper.take_sent_to(OWNER_URI);
            assert_eq!(
                answer.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![2],
                "{channel_id:?} answers under the request's epoch"
            );
            for envelope in answer {
                events.extend(
                    restored
                        .build()
                        .process(&envelope)
                        .await
                        .expect("processed"),
                );
            }
        }
        for (channel_id, _) in &helpers {
            assert!(
                events.iter().any(|e| matches!(
                    e,
                    DeRecEvent::ShareVerified { channel_id: c, version: 2, .. } if c == channel_id
                )),
                "{channel_id:?} verified v2: {events:?}"
            );
            assert_eq!(restored.ring(*channel_id).epoch, 2, "the owner stays at 2");
        }
    });
}

/// A StoreShare under epoch 2, below the helper's newest epoch 16, that the
/// application accepts is answered under K2 and pins V2 to epoch 2.
#[test]
fn a_store_share_accepted_under_an_older_epoch_pins_that_epoch() {
    run_async(async {
        let (restored, helpers) = restored_at_v1_while_helpers_are_at_16().await;
        restored.protect().await;
        let (channel_id, helper) = &helpers[0];
        let by_hand = Party {
            auto_accept: Some(AutoAcceptPolicy::default()),
            ..helper.clone()
        };
        let action = pending(deliver_clean(&restored, &by_hand).await);
        assert!(matches!(
            action.action(),
            Action::Request(ChannelRequest::StoreShare(_))
        ));

        by_hand.build().accept(action).await.expect("accepted");
        let answer = helper.take_sent_to(OWNER_URI);
        assert_eq!(
            answer.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
            vec![2]
        );
        let ring = helper.ring(*channel_id);
        assert_eq!(ring.epoch, 16);
        assert!(ring.pins.contains(&(2, 2)), "{ring:?}");
        assert_eq!(helper.stored_versions(*channel_id), vec![1, 2, 16]);
    });
}

/// A VerifyShare raised at epoch 1 and accepted after the owner moved the
/// channel to epoch 2 is answered under K1, which the owner still holds for
/// V1.
#[test]
fn an_action_raised_before_a_rotation_is_accepted_under_its_own_epoch() {
    run_async(async {
        let (owner, helpers) = fleet_with(
            Party::rotating(OWNER_URI),
            2,
            Some(AutoAcceptPolicy {
                store_share: true,
                ..Default::default()
            }),
        )
        .await;
        round(&owner, &helpers).await;

        owner.verify(1).await;
        let (channel_id, helper) = &helpers[0];
        let action = pending(deliver_clean(&owner, helper).await);
        owner.drop_sent();
        round(&owner, &helpers).await;
        assert_eq!(helper.ring(*channel_id).epoch, 2);

        helper.build().accept(action).await.expect("accepted");
        let answer = helper.take_sent_to(OWNER_URI);
        assert_eq!(
            answer.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
            vec![1]
        );
        let events = owner
            .build()
            .process(&answer[0])
            .await
            .expect("the answer is processed");
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareVerified { channel_id: c, version: 1, .. } if c == channel_id
            )),
            "{events:?}"
        );
    });
}

/// A VerifyShare raised at epoch 1 whose channel no longer has the owner
/// role when it is accepted after the move to epoch 2 fails `REJECTED`. The
/// failure is answered under K1, the action's key: by the library when it
/// answers failures itself, or through a token the application rejects.
#[test]
fn a_failure_of_an_action_raised_before_a_rotation_is_answered_under_its_epoch() {
    for auto_respond in [true, false] {
        run_async(async move {
            let (owner, helpers) = fleet_with(
                Party::rotating(OWNER_URI),
                2,
                Some(AutoAcceptPolicy {
                    store_share: true,
                    ..Default::default()
                }),
            )
            .await;
            round(&owner, &helpers).await;

            owner.verify(1).await;
            let (channel_id, helper) = &helpers[0];
            let helper = Party {
                auto_respond,
                ..helper.clone()
            };
            let action = pending(deliver_clean(&owner, &helper).await);
            owner.drop_sent();
            round(&owner, &helpers).await;
            assert_eq!(helper.ring(*channel_id).epoch, 2);
            helper
                .pair_helper(*channel_id, SenderKind::Helper, OWNER_URI)
                .await;
            let mut secrets = helper.secrets.clone();
            derec_library::protocol::DeRecSecretStore::save(
                &mut secrets,
                key_rig::SECRET_ID,
                *channel_id,
                derec_library::protocol::SecretValue::SharedKey(
                    derec_library::types::SharedKey::new(key_at(*channel_id, 2)),
                ),
            )
            .await
            .expect("restore the key mirror");

            let events = helper.build().accept(action).await.expect("settled");
            let token = events.into_iter().find_map(|e| match e {
                DeRecEvent::RequestFailed {
                    responded,
                    status,
                    action,
                    ..
                } => {
                    assert_eq!(status, derec_proto::StatusEnum::Rejected as i32);
                    assert_eq!(responded, auto_respond);
                    Some(action)
                }
                _ => None,
            });
            let token = token.expect("the request failed");
            if !auto_respond {
                assert!(helper.take_sent_to(OWNER_URI).is_empty());
                let token = token.expect("a token the application answers");
                helper
                    .build()
                    .reject(token, derec_proto::StatusEnum::Rejected, "no")
                    .await
                    .expect("the token is answered");
            }
            let answer = helper.take_sent_to(OWNER_URI);
            assert_eq!(
                answer.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![1],
                "auto_respond {auto_respond}: answered under the action's epoch"
            );
            owner
                .build()
                .process(&answer[0])
                .await
                .expect("the answer is processed");
            assert_eq!(owner.ring(*channel_id).epoch, 2, "the owner stays at 2");
        });
    }
}

/// An action raised at epoch 0, with no version stored, outlives K0: the
/// owner's V1 moves the helper to epoch 1 and nothing pins epoch 0. Accepting
/// or rejecting it is refused as too late, and nothing is sent.
#[test]
fn an_action_whose_key_is_gone_is_refused_as_too_late() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        owner
            .build()
            .start(DeRecFlow::Discovery {
                target: Target::All,
            })
            .await
            .expect("discovery starts");
        let (channel_id, helper) = &helpers[0];
        let action = pending(deliver_clean(&owner, helper).await);
        owner.drop_sent();
        round(&owner, &helpers).await;
        let ring = helper.ring(*channel_id);
        assert_eq!(ring.epoch, 1);
        assert!(ring.old.is_empty(), "{ring:?}");

        let too_late = derec_library::Error::InvalidInput(
            "the action can no longer be answered: its channel key is no longer held",
        );
        let accepted = helper.build().accept(action.clone()).await;
        assert_eq!(
            format!("{:?}", accepted.expect_err("too late")),
            format!("{too_late:?}")
        );
        let rejected = helper
            .build()
            .reject(action, derec_proto::StatusEnum::Fail, "no")
            .await;
        assert_eq!(
            format!("{:?}", rejected.expect_err("too late")),
            format!("{too_late:?}")
        );
        assert!(helper.take_sent_to(OWNER_URI).is_empty());
    });
}

/// The owner advances while a VerifyShare answer under the previous epoch is
/// in flight: the pin of that epoch's version keeps its key.
#[test]
fn an_answer_in_flight_under_the_previous_epoch_survives_the_advance() {
    run_async(async {
        let (owner, helpers) = fleet(Party::rotating(OWNER_URI), 2).await;
        round(&owner, &helpers).await;

        owner.verify(1).await;
        let (channel_id, helper) = &helpers[0];
        deliver_clean(&owner, helper).await;
        let answer = helper.take_sent_to(OWNER_URI);
        assert_eq!(answer.len(), 1);
        assert_eq!(sequence_of(&answer[0]), 1);

        owner.protect().await;
        let ring = owner.ring(*channel_id);
        assert_eq!(ring.epoch, 2);
        assert_eq!(ring.old_epochs(), vec![1]);

        let events = owner
            .build()
            .process(&answer[0])
            .await
            .expect("the answer is processed");
        assert!(
            !events.iter().any(|e| matches!(
                e,
                DeRecEvent::MessageIgnored {
                    reason: IgnoreReason::KeyUnavailable,
                    ..
                }
            )),
            "{events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ShareVerified { version: 1, .. })),
            "{events:?}"
        );
    });
}

/// A source with helpers on `A` and `B` that never answer, and the group
/// members `others` on the group channel.
async fn source_with(others: &[(u64, &'static str)]) -> (Party, Vec<Party>) {
    let mut members = vec![(SOURCE, ReplicaRole::Source, SOURCE_URI)];
    members.extend(
        others
            .iter()
            .map(|&(id, uri)| (id, ReplicaRole::Destination, uri)),
    );
    let source = Party {
        replica_id: Some(SOURCE),
        ..Party::rotating(SOURCE_URI)
    };
    source
        .pair_helper(A, SenderKind::Helper, HELPER_A_URI)
        .await;
    source
        .pair_helper(B, SenderKind::Helper, HELPER_B_URI)
        .await;
    source.join_group(&members).await;
    let mut destinations = Vec::new();
    for &(id, uri) in others {
        let destination = Party {
            replica_id: Some(id),
            ..Party::new(uri)
        };
        destination.join_group(&members).await;
        destinations.push(destination);
    }
    (source, destinations)
}

fn roster_of(events: &[DeRecEvent]) -> Secret {
    events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::ReplicaSecretInstalled { secret, .. }
            | DeRecEvent::ReplicaSecretReceived { secret, .. } => Some(secret.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("a copy was applied: {events:?}"))
}

#[test]
fn the_group_channel_advances_on_each_publish() {
    run_async(async {
        let (source, destinations) = source_with(&[(D1, D1_URI)]).await;
        let d1 = &destinations[0];
        for epoch in 1..=2 {
            source.protect().await;
            let ring = source.ring(GROUP);
            assert_eq!((ring.epoch, ring.key), (epoch, key_at(GROUP, epoch)));
            source.take_sent_to(HELPER_A_URI);
            source.take_sent_to(HELPER_B_URI);

            let sent = source.take_sent_to(D1_URI);
            assert_eq!(
                sent.iter().map(|e| sequence_of(e)).collect::<Vec<_>>(),
                vec![epoch]
            );
            let mut events = Vec::new();
            for envelope in sent {
                events.extend(d1.build().process(&envelope).await.expect("processed"));
            }
            let roster = roster_of(&events).replicas.expect("a group");
            assert_eq!(roster.key_epoch, epoch);
            assert_eq!(roster.shared_key, key_at(GROUP, epoch).to_vec());
            assert_eq!(d1.ring(GROUP).epoch, epoch);
            deliver_clean(d1, &source).await;
        }
    });
}

#[test]
fn a_replica_destination_hydrates_the_epoch() {
    run_async(async {
        let (source, destinations) = source_with(&[(D1, D1_URI)]).await;
        let d1 = &destinations[0];
        for _ in 0..2 {
            source.protect().await;
            deliver_clean(&source, d1).await;
            deliver_clean(d1, &source).await;
        }

        for channel_id in [A, B] {
            let ring = d1.ring(channel_id);
            assert_eq!((ring.epoch, ring.key), (2, key_at(channel_id, 2)));
            assert_eq!(ring.pins, vec![(2, 2)]);
        }
        let ring = d1.ring(GROUP);
        assert_eq!((ring.epoch, ring.key), (2, key_at(GROUP, 2)));
        assert_eq!(ring.pins, vec![(2, 2)]);
    });
}

/// A joiner admitted on its pairing channel is handed the group key of a
/// group that has rotated: it answers on the group channel under the group's
/// real epoch, which the source opens.
#[test]
fn an_admitted_member_answers_under_the_group_epoch() {
    run_async(async {
        let (source, destinations) = source_with(&[(D1, D1_URI)]).await;
        let d1 = &destinations[0];
        for _ in 0..2 {
            source.protect().await;
            deliver_clean(&source, d1).await;
            deliver_clean(d1, &source).await;
        }

        source
            .join_on(EPHEMERAL, &[(D2, ReplicaRole::Destination, D2_URI)])
            .await;
        let joiner = Party {
            replica_id: Some(D2),
            ..Party::new(D2_URI)
        };
        joiner
            .join_on(EPHEMERAL, &[(SOURCE, ReplicaRole::Source, SOURCE_URI)])
            .await;

        source.protect().await;
        assert_eq!(source.ring(GROUP).epoch, 3);
        let events = deliver_clean(&source, &joiner).await;
        let roster = roster_of(&events).replicas.expect("a group");
        assert_eq!(roster.key_epoch, 3);
        let ring = joiner.ring(GROUP);
        assert_eq!((ring.epoch, ring.key), (3, key_at(GROUP, 3)));

        let ack = joiner.take_sent_to(SOURCE_URI);
        assert_eq!(ack.len(), 1);
        assert_eq!(
            sequence_of(&ack[0]),
            3,
            "the ack is under the group's epoch"
        );
        let events = source.build().process(&ack[0]).await.expect("processed");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ReplicaSecretAcked { .. })),
            "{events:?}"
        );
    });
}

#[test]
fn a_secret_without_epoch_fields_restores_at_epoch_zero() {
    run_async(async {
        let (_, helpers) = fleet(Party::new(OWNER_URI), 2).await;
        let secret = Secret {
            helpers: helpers
                .iter()
                .map(|(channel_id, helper)| HelperInfo {
                    channel_id: channel_id.0,
                    transports: key_rig::endpoint(helper.uri),
                    shared_key: k0(*channel_id).as_bytes().to_vec(),
                    weight: 1,
                    ..Default::default()
                })
                .collect(),
            secrets: vec![UserSecret {
                id: b"id".to_vec(),
                name: "name".to_owned(),
                data: b"an older secret".to_vec(),
            }],
            replicas: None,
            threshold: Some(2),
        };
        let encoded = secret.encode();
        let secret = Secret::decode(&encoded).expect("decodes");
        assert!(secret.helpers.iter().all(|h| h.key_epoch == 0));

        let restored = fresh_owner();
        restored
            .build()
            .restore(&secret, 1)
            .await
            .expect("restore succeeds");
        for (channel_id, _) in &helpers {
            let ring = restored.ring(*channel_id);
            assert_eq!((ring.epoch, ring.key), (0, *k0(*channel_id).as_bytes()));
            assert_eq!(ring.pins, vec![(1, 0)]);
        }

        round(&restored, &helpers).await;
        for (channel_id, helper) in &helpers {
            assert_eq!(helper.ring(*channel_id).epoch, 1);
        }
        verified(&restored, &helpers, 2).await;
    });
}

/// A rotating owner on `A` and `B` that is also the replica group's source.
async fn owner_in_a_group(group: &[(u64, ReplicaRole, &str)]) -> Party {
    let owner = Party {
        replica_id: Some(SOURCE),
        ..Party::rotating(OWNER_URI)
    };
    owner.pair_helper(A, SenderKind::Helper, HELPER_A_URI).await;
    owner.pair_helper(B, SenderKind::Helper, HELPER_B_URI).await;
    owner.join_group(group).await;
    owner
}

/// A publish refused by a check that sends nothing moves no helper channel:
/// the group is checked before any helper advances.
#[test]
fn a_publish_that_fails_before_sending_moves_no_helper_epoch() {
    run_async(async {
        let missing_group_key = owner_in_a_group(&[(SOURCE, ReplicaRole::Source, OWNER_URI)]).await;
        missing_group_key.secrets.data.lock().unwrap().remove(&(
            key_rig::SECRET_ID,
            GROUP.0,
            SecretKind::SharedKey as u8,
        ));
        let no_own_row = owner_in_a_group(&[(D1, ReplicaRole::Destination, D1_URI)]).await;

        for owner in [missing_group_key, no_own_row] {
            for _ in 0..3 {
                let refused = owner
                    .build()
                    .start(DeRecFlow::ProtectSecret {
                        secrets: vec![UserSecret {
                            id: b"id".to_vec(),
                            name: "name".to_owned(),
                            data: b"a secret".to_vec(),
                        }],
                        description: None,
                        weights: std::collections::HashMap::new(),
                        threshold: None,
                    })
                    .await;
                assert!(
                    matches!(refused, Err(derec_library::Error::Invariant(_))),
                    "{refused:?}"
                );
            }
            for channel_id in [A, B] {
                assert_eq!(owner.ring(channel_id).epoch, 0, "{channel_id:?}");
            }
            assert!(owner.transport.sent.lock().unwrap().is_empty());
        }
    });
}

/// A channel whose ring query the store answers with another kind gets the
/// flow's failure event, and the other channels proceed.
#[test]
fn a_misfiled_ring_fails_its_channel_in_each_fan_out() {
    run_async(async {
        let (owner, _) = fleet(fresh_owner(), 2).await;
        owner.misfile_ring(B);

        let failed_for_b = |events: &[DeRecEvent]| {
            events
                .iter()
                .filter(|e| match e {
                    DeRecEvent::VerifySharesFailed {
                        channel_id, reason, ..
                    } => *channel_id == B && *reason == VerifyFailureReason::NoSharedKey,
                    DeRecEvent::DiscoveryFailed { channel_id, .. }
                    | DeRecEvent::UpdateChannelInfoFailed { channel_id, .. }
                    | DeRecEvent::RecoverSecretFailed { channel_id, .. } => *channel_id == B,
                    _ => false,
                })
                .count()
        };
        let mentions_a = |events: &[DeRecEvent]| {
            events.iter().any(|e| {
                matches!(
                    e,
                    DeRecEvent::VerifySharesFailed { channel_id, .. }
                        | DeRecEvent::DiscoveryStarted { channel_id, .. }
                        | DeRecEvent::UpdateChannelInfoStarted { channel_id, .. }
                        | DeRecEvent::RecoverSecretStarted { channel_id, .. }
                        if *channel_id == A
                )
            })
        };

        let flows = [
            DeRecFlow::VerifyShares {
                secret_id: key_rig::SECRET_ID,
                version: 1,
                target: Target::All,
            },
            DeRecFlow::Discovery {
                target: Target::All,
            },
            DeRecFlow::UpdateChannelInfo {
                target: Target::All,
                communication_info: Some(std::collections::HashMap::from([(
                    "name".to_owned(),
                    "owner".to_owned(),
                )])),
                own_transports: Vec::new(),
            },
            DeRecFlow::RecoverSecret {
                secret_id: key_rig::SECRET_ID,
                version: 1,
            },
        ];
        for flow in flows {
            let events = owner.build().start(flow).await.expect("the flow starts");
            assert_eq!(failed_for_b(&events), 1, "{events:?}");
            assert!(mentions_a(&events), "{events:?}");
            assert_eq!(events.len(), 2, "one event per channel: {events:?}");
        }
    });
}

/// A publish whose helper ring the store misfiles is refused with an error,
/// not a panic, and sends nothing.
#[test]
fn a_misfiled_ring_refuses_a_publish_without_panicking() {
    run_async(async {
        let (owner, _) = fleet(fresh_owner(), 2).await;
        owner.misfile_ring(B);

        let refused = owner
            .build()
            .start(DeRecFlow::ProtectSecret {
                secrets: vec![UserSecret {
                    id: b"id".to_vec(),
                    name: "name".to_owned(),
                    data: b"a secret".to_vec(),
                }],
                description: None,
                weights: std::collections::HashMap::new(),
                threshold: None,
            })
            .await;
        assert!(
            matches!(refused, Err(derec_library::Error::Invariant(_))),
            "{refused:?}"
        );
        assert!(owner.transport.sent.lock().unwrap().is_empty());
    });
}
