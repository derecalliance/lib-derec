// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! A party keeps the key of every secret version it still stores on a
//! channel: a pin `(version, epoch)` names the epoch the version travelled
//! under, and the key of a pinned epoch is held until the pin goes.
//!
//! A helper pins a share before saving it and drops the pins of the versions
//! `keepVersion` removes. An owner pins a version before sending it and drops
//! the older pins once the helper confirms. A replica destination pins the
//! version it holds on the group channel; the source drops a group pin once
//! every destination has confirmed a newer version.

#[path = "support/key_rig.rs"]
mod key_rig;
#[path = "support/protocol_doubles.rs"]
mod protocol_doubles;

use derec_library::protocol::types::{ReplicaRole, Target};
use derec_library::protocol::{DeRecEvent, DeRecFlow, IgnoreReason};
use derec_proto::SenderKind;
use key_rig::{
    A, B, D1, D1_URI, D2, D2_URI, GROUP, HELPER_A_URI, HELPER_B_URI, OWNER_URI, Party, SECRET_ID,
    SOURCE, SOURCE_URI, deliver, key_at,
};
use protocol_doubles::run_async;

/// An owner paired with helpers on `A` and `B`, and the helper on `A`. The
/// helper on `B` never answers; the round needs it only to split. The owner
/// advances every channel on each new version.
async fn owner_and_helper() -> (Party, Party) {
    let owner = Party::rotating(OWNER_URI);
    owner.pair_helper(A, SenderKind::Helper, HELPER_A_URI).await;
    owner.pair_helper(B, SenderKind::Helper, HELPER_B_URI).await;
    let helper = Party::new(HELPER_A_URI);
    helper.pair_helper(A, SenderKind::Owner, OWNER_URI).await;
    (owner, helper)
}

/// The owner protects a new version with `keep`, which moves it to `epoch`,
/// and the helper on `A` stores it.
async fn share_at(owner: &Party, helper: &Party, epoch: u32, keep: u32) {
    owner.keep(keep);
    owner.protect().await;
    assert_eq!(owner.ring(A).epoch, epoch, "the owner advanced");
    let (_, errors) = deliver(owner, helper).await;
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn a_helper_pins_each_stored_version_and_prunes_with_keep_version() {
    run_async(async {
        let (owner, helper) = owner_and_helper().await;

        share_at(&owner, &helper, 1, 0).await;
        let ring = helper.ring(A);
        assert_eq!((ring.epoch, ring.key), (1, key_at(A, 1)));
        assert_eq!(ring.pins, vec![(1, 1)]);
        assert!(ring.old.is_empty());

        // Versions 2 to 15 never reached the helper.
        for _ in 2..=15 {
            owner.protect().await;
            owner.drop_sent();
        }
        share_at(&owner, &helper, 16, 1).await;
        let ring = helper.ring(A);
        assert_eq!((ring.epoch, ring.key), (16, key_at(A, 16)));
        assert_eq!(ring.pins, vec![(1, 1), (16, 16)]);
        assert_eq!(ring.old, vec![(1, key_at(A, 1))]);
        assert_eq!(helper.stored_versions(A), vec![1, 16]);

        share_at(&owner, &helper, 17, 16).await;
        let ring = helper.ring(A);
        assert_eq!((ring.epoch, ring.key), (17, key_at(A, 17)));
        assert_eq!(ring.pins, vec![(16, 16), (17, 17)]);
        assert_eq!(ring.old, vec![(16, key_at(A, 16))]);
        assert_eq!(helper.stored_versions(A), vec![16, 17]);
    });
}

#[test]
fn the_owner_keeps_a_key_until_the_helper_confirms() {
    run_async(async {
        let (owner, helper) = owner_and_helper().await;

        share_at(&owner, &helper, 1, 0).await;
        let (_, errors) = deliver(&helper, &owner).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(owner.ring(A).pins, vec![(1, 1)]);

        // Version 2 goes out, and the helper is offline.
        owner.keep(0);
        owner.protect().await;
        let ring = owner.ring(A);
        assert_eq!(ring.pins, vec![(1, 1), (2, 2)]);
        assert_eq!(ring.old, vec![(1, key_at(A, 1))]);

        let (_, errors) = deliver(&owner, &helper).await;
        assert!(errors.is_empty(), "{errors:?}");
        let (events, errors) = deliver(&helper, &owner).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DeRecEvent::ShareConfirmed { version: 2, .. })),
            "{events:?}"
        );

        let ring = owner.ring(A);
        assert_eq!(ring.pins, vec![(2, 2)]);
        assert!(ring.old.is_empty(), "K1 is no longer held: {ring:?}");
    });
}

#[test]
fn a_response_in_flight_across_a_rotation_still_decrypts() {
    run_async(async {
        let (owner, helper) = owner_and_helper().await;
        share_at(&owner, &helper, 1, 0).await;
        let (_, errors) = deliver(&helper, &owner).await;
        assert!(errors.is_empty(), "{errors:?}");

        owner
            .build()
            .start(DeRecFlow::VerifyShares {
                secret_id: SECRET_ID,
                version: 1,
                target: Target::Single(A),
            })
            .await
            .expect("verification starts");
        let (_, errors) = deliver(&owner, &helper).await;
        assert!(errors.is_empty(), "{errors:?}");
        let answer = helper.take_sent_to(OWNER_URI);
        assert_eq!(answer.len(), 1, "the helper answered");

        // A new round moves the owner to epoch 2 while the answer is in flight.
        owner.protect().await;
        assert_eq!(owner.ring(A).epoch, 2);

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
                .any(|e| matches!(e, DeRecEvent::ShareVerified { .. })),
            "{events:?}"
        );
    });
}

#[test]
fn an_interrupted_share_save_leaves_only_a_pin() {
    run_async(async {
        let (owner, helper) = owner_and_helper().await;
        share_at(&owner, &helper, 1, 0).await;

        owner.keep(1);
        owner.protect().await;
        helper.shares.set_fail_save(true);
        let _ = deliver(&owner, &helper).await;
        helper.shares.set_fail_save(false);

        assert_eq!(helper.stored_versions(A), vec![1]);
        let ring = helper.ring(A);
        assert_eq!(ring.pins, vec![(1, 1), (2, 2)], "the pin was written first");

        share_at(&owner, &helper, 3, 1).await;
        assert_eq!(helper.stored_versions(A), vec![1, 3]);
        let ring = helper.ring(A);
        assert_eq!(ring.pins, vec![(1, 1), (3, 3)]);
        assert_eq!(ring.old_epochs(), vec![1], "K2 went with its pin");
    });
}

/// A source and two destinations sharing the group channel.
async fn group() -> (Party, Party, Party) {
    let members = [
        (SOURCE, ReplicaRole::Source, SOURCE_URI),
        (D1, ReplicaRole::Destination, D1_URI),
        (D2, ReplicaRole::Destination, D2_URI),
    ];
    let party = |uri, replica_id| Party {
        uri,
        replica_id: Some(replica_id),
        rotation: replica_id == SOURCE,
        ..Default::default()
    };
    let (source, d1, d2) = (
        party(SOURCE_URI, SOURCE),
        party(D1_URI, D1),
        party(D2_URI, D2),
    );
    for p in [&source, &d1, &d2] {
        p.join_group(&members).await;
    }
    (source, d1, d2)
}

#[test]
fn a_replica_destination_pins_its_stored_versions() {
    run_async(async {
        let (source, d1, _) = group().await;

        source.protect().await;
        let (_, errors) = deliver(&source, &d1).await;
        assert!(errors.is_empty(), "{errors:?}");
        let ring = d1.ring(GROUP);
        assert_eq!((ring.epoch, ring.key), (1, key_at(GROUP, 1)));
        assert_eq!(ring.pins, vec![(1, 1)]);

        source.protect().await;
        let (_, errors) = deliver(&source, &d1).await;
        assert!(errors.is_empty(), "{errors:?}");
        let ring = d1.ring(GROUP);
        assert_eq!((ring.epoch, ring.key), (2, key_at(GROUP, 2)));
        assert_eq!(
            ring.pins,
            vec![(2, 2)],
            "a destination holds only its latest copy"
        );
        assert!(ring.old.is_empty());
    });
}

#[test]
fn a_replica_source_keeps_a_group_key_until_every_destination_confirms_newer() {
    run_async(async {
        let (source, d1, d2) = group().await;

        source.protect().await;
        for d in [&d1, &d2] {
            let (_, errors) = deliver(&source, d).await;
            assert!(errors.is_empty(), "{errors:?}");
            let (_, errors) = deliver(d, &source).await;
            assert!(errors.is_empty(), "{errors:?}");
        }
        assert_eq!(source.ring(GROUP).pins, vec![(1, 1)]);

        source.protect().await;
        let ring = source.ring(GROUP);
        assert_eq!(ring.pins, vec![(1, 1), (2, 2)]);
        assert_eq!(ring.old_epochs(), vec![1]);

        let (_, errors) = deliver(&source, &d1).await;
        assert!(errors.is_empty(), "{errors:?}");
        let (_, errors) = deliver(&d1, &source).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            source.ring(GROUP).old_epochs(),
            vec![1],
            "one destination has not confirmed"
        );

        let (_, errors) = deliver(&source, &d2).await;
        assert!(errors.is_empty(), "{errors:?}");
        let (_, errors) = deliver(&d2, &source).await;
        assert!(errors.is_empty(), "{errors:?}");
        let ring = source.ring(GROUP);
        assert_eq!(ring.pins, vec![(2, 2)]);
        assert!(ring.old.is_empty(), "{ring:?}");
    });
}

/// Protect `rounds` versions, letting only the helper on `A` answer, and
/// time out the rest of each round before the next.
#[test]
fn a_helper_that_never_answers_leaves_the_owner_a_bounded_number_of_pins() {
    run_async(async {
        let (owner, helper) = owner_and_helper().await;

        for version in 1..=20u32 {
            owner.protect().await;
            let (_, errors) = deliver(&owner, &helper).await;
            assert!(errors.is_empty(), "{errors:?}");
            let (_, errors) = deliver(&helper, &owner).await;
            assert!(errors.is_empty(), "{errors:?}");
            owner.drop_sent();
            owner.age_rounds();
            owner.tick().await;

            let silent = owner.ring(B);
            assert_eq!(silent.epoch, version);
            assert!(
                silent.pins.len() <= 1 && silent.old.len() <= 1,
                "v{version}: {silent:?}"
            );
            let answering = owner.ring(A);
            assert!(answering.pins.len() <= 2, "v{version}: {answering:?}");
        }
    });
}

/// A destination that never acknowledges does not make the source keep a
/// group pin per version, and it still follows forward on the next publish.
#[test]
fn a_member_that_stays_behind_leaves_the_source_a_bounded_number_of_group_pins() {
    run_async(async {
        let (source, d1, d2) = group().await;

        for version in 1..=12u32 {
            source.protect().await;
            let (_, errors) = deliver(&source, &d1).await;
            assert!(errors.is_empty(), "{errors:?}");
            let (_, errors) = deliver(&d1, &source).await;
            assert!(errors.is_empty(), "{errors:?}");
            source.take_sent_to(D2_URI);
            source.age_rounds();
            source.tick().await;

            let ring = source.ring(GROUP);
            assert_eq!(ring.epoch, version);
            assert!(
                ring.pins.len() <= 3 && ring.old.len() <= 2,
                "v{version}: {ring:?}"
            );
        }

        source.protect().await;
        let (_, errors) = deliver(&source, &d2).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(d2.ring(GROUP).epoch, 13, "the member followed forward");
        let (events, errors) = deliver(&d2, &source).await;
        assert!(errors.is_empty(), "{errors:?}");
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, DeRecEvent::MessageIgnored { .. })),
            "{events:?}"
        );
    });
}

/// A source whose round closes with a member behind keeps the oldest group
/// pin, so a member still at an older epoch is answered by deriving forward.
#[test]
fn a_member_behind_can_still_reach_the_source_under_its_epoch() {
    run_async(async {
        let (source, d1, d2) = group().await;

        source.protect().await;
        for d in [&d1, &d2] {
            let (_, errors) = deliver(&source, d).await;
            assert!(errors.is_empty(), "{errors:?}");
            let (_, errors) = deliver(d, &source).await;
            assert!(errors.is_empty(), "{errors:?}");
        }

        for _ in 0..5 {
            source.protect().await;
            let (_, errors) = deliver(&source, &d1).await;
            assert!(errors.is_empty(), "{errors:?}");
            let (_, errors) = deliver(&d1, &source).await;
            assert!(errors.is_empty(), "{errors:?}");
            source.take_sent_to(D2_URI);
            source.age_rounds();
            source.tick().await;
        }
        assert_eq!(d2.ring(GROUP).epoch, 1);

        d2.build()
            .start(DeRecFlow::ReplicaDiscovery)
            .await
            .expect("the member asks the group");
        let (events, errors) = deliver(&d2, &source).await;
        assert!(errors.is_empty(), "{errors:?}");
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
    });
}
