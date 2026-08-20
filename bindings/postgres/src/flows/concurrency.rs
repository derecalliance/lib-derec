// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Whether the library can be driven from a concurrent, multi-threaded
//! service — an axum or actix handler pool, say — and what the developer has
//! to do about it.
//!
//! The library takes no position on concurrency: it exposes stores as traits
//! and leaves consistency to whoever implements them. That is only a workable
//! stance if a developer can actually *reach* the natural solutions, so this
//! flow checks the two cases a REST service really has.
//!
//! **Independent partitions run in parallel with no coordination.** Different
//! users mean different `secret_id`s, which means disjoint rows in every
//! table. Handlers can run on any thread, in any order, simultaneously.
//!
//! **A scheduled tick is not a special case.** It mutates the same round state
//! an inbound response does, so it belongs under the same per-partition lock —
//! and once it is there, a timer firing mid-flight is harmless.
//!
//! **One partition needs serializing, and the application can do it.** Two
//! responses for the same in-flight round both read the accumulator, add their
//! own result and write it back. Interleaved, one update is lost and the round
//! never completes — documented on [`DeRecStateStore`][ds]. The fix is an
//! ordinary per-`secret_id` lock around the call, and it composes without the
//! library's help, which is the property being checked here.
//!
//! [ds]: derec_library::protocol::DeRecStateStore

use std::collections::HashMap;
use std::sync::Arc;

use derec_library::protocol::events::DeRecEvent;
use derec_library::protocol::types::UserSecret;
use derec_library::protocol::DeRecFlow;
use derec_library::types::ChannelId;
use derec_proto::{ContactMode, SenderKind};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::flows::assertions::{snapshot, snapshot_version};
use crate::peer::PeerOptions;
use crate::stateless::{StatelessPeer, deliver, pump};

pub async fn run() {
    println!("=== [Concurrency] parallel use on a multi-threaded runtime ===");

    independent_partitions_run_in_parallel().await;
    one_partition_serializes_under_an_application_lock().await;
    a_scheduled_tick_shares_the_same_lock_as_inbound_messages().await;

    println!("✓ Concurrency flow passed.\n");
}

/// Four users, four partitions, all driven at once on separate worker threads.
///
/// Each task builds its own protocol instances and touches only its own
/// `secret_id`. Nothing is shared and nothing is locked. The task bodies must
/// be `Send + 'static` for `tokio::spawn` to accept them at all, so this
/// failing to compile would mean the library cannot be used from a threaded
/// handler pool.
async fn independent_partitions_run_in_parallel() {
    let mut tasks = Vec::new();
    for i in 0..4u64 {
        tasks.push(tokio::spawn(async move {
            let secret_id = 0xC0FF_EE00 + i;
            let owner_db = Database::open_isolated().await;
            let helper_dbs = [
                Database::open_isolated().await,
                Database::open_isolated().await,
            ];

            let options = PeerOptions {
                secret_id,
                threshold: 2,
                replica_id: None,
            };
            let owner = StatelessPeer::new(
                owner_db.client(),
                "Owner",
                &format!("https://owner-{i}.example.com"),
                options,
            );
            // Two helpers, matching the threshold: a publish has to have
            // somewhere to put both shares or it distributes nothing.
            let helpers: Vec<StatelessPeer> = helper_dbs
                .iter()
                .enumerate()
                .map(|(h, db)| {
                    StatelessPeer::new(
                        db.client(),
                        "Helper",
                        &format!("https://helper-{i}-{h}.example.com"),
                        options,
                    )
                })
                .collect();

            for (h, helper) in helpers.iter().enumerate() {
                let contact = owner
                    .session()
                    .create_contact(
                        Some(ChannelId(700 + i * 10 + h as u64)),
                        ContactMode::InlineKeys,
                        None,
                    )
                    .await
                    .expect("create_contact");
                helper
                    .session()
                    .start(DeRecFlow::Pairing {
                        kind: SenderKind::Helper,
                        contact,
                        peer_communication_info: HashMap::new(),
                    })
                    .await
                    .expect("start(Pairing)");
                pump(&[&owner, helper]).await;
            }

            owner
                .session()
                .start(DeRecFlow::ProtectSecret {
                    secrets: vec![UserSecret {
                        id: vec![i as u8],
                        name: format!("secret-{i}"),
                        data: format!("payload for user {i}").into_bytes(),
                    }],
                    description: Some(format!("user {i}")),
                })
                .await
                .expect("start(ProtectSecret)");
            {
                let mut cast: Vec<&StatelessPeer> = vec![&owner];
                cast.extend(helpers.iter());
                pump(&cast).await;
            }

            let tables = snapshot(&owner.client(), secret_id).await;
            assert_eq!(tables.channels, 2, "user {i} owner channels");
            assert_eq!(tables.shares, 2, "user {i} owner shares");
            assert_eq!(tables.user_secrets, 1, "user {i} owner snapshot");
            assert_eq!(
                tables.protocol_state, 0,
                "user {i} left an in-flight row behind"
            );
            assert_eq!(snapshot_version(&owner.client(), secret_id).await, Some(1));

            // Held to the end of the task: the schemas are the peers' storage.
            drop((owner_db, helper_dbs));
            secret_id
        }));
    }

    let mut done = Vec::new();
    for task in tasks {
        done.push(task.await.expect("a partition task panicked"));
    }
    done.sort_unstable();
    assert_eq!(done.len(), 4, "every partition completed");
    println!("  4 users driven simultaneously on separate threads, no coordination  ✓");
}

/// Two responses for the same round, arriving at the same instant.
///
/// Both update one accumulator row by load-modify-save, so unserialized they
/// can clobber each other and leave the round permanently short of an answer.
/// The library documents that and hands the problem to the application; this
/// checks the ordinary answer — one lock per `secret_id`, held across the
/// call — is actually reachable, which requires the peer to be shareable
/// across threads in the first place.
async fn one_partition_serializes_under_an_application_lock() {
    let secret_id = 0xC0FF_EE99;
    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;

    let options = PeerOptions {
        secret_id,
        threshold: 2,
        replica_id: None,
    };
    let owner = Arc::new(StatelessPeer::new(
        owner_db.client(),
        "Owner",
        "https://owner-shared.example.com",
        options,
    ));
    let helper_a = StatelessPeer::new(
        helper_a_db.client(),
        "HelperA",
        "https://helper-a-shared.example.com",
        options,
    );
    let helper_b = StatelessPeer::new(
        helper_b_db.client(),
        "HelperB",
        "https://helper-b-shared.example.com",
        options,
    );

    for (i, helper) in [&helper_a, &helper_b].into_iter().enumerate() {
        let contact = owner
            .session()
            .create_contact(Some(ChannelId(800 + i as u64)), ContactMode::InlineKeys, None)
            .await
            .expect("create_contact");
        helper
            .session()
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact,
                peer_communication_info: HashMap::new(),
            })
            .await
            .expect("start(Pairing)");
        pump(&[&*owner, helper]).await;
    }

    // Publish, then hold both helper answers back so they can be released at
    // once — the interleaving a busy service produces by accident.
    owner
        .session()
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![7],
                name: "contended".to_owned(),
                data: b"two answers, one round".to_vec(),
            }],
            description: Some("contended round".to_owned()),
        })
        .await
        .expect("start(ProtectSecret)");

    for (endpoint, bytes) in owner.drain() {
        let target = if endpoint.uri == helper_a.uri {
            &helper_a
        } else {
            &helper_b
        };
        deliver(target, &bytes).await;
    }

    let mut answers: Vec<Vec<u8>> = Vec::new();
    for helper in [&helper_a, &helper_b] {
        for (_endpoint, bytes) in helper.drain() {
            answers.push(bytes);
        }
    }
    assert_eq!(answers.len(), 2, "both helpers answered the publish");

    let round_open = snapshot(&owner.client(), secret_id).await;
    assert_eq!(
        round_open.protocol_state, 1,
        "the round is in flight while both answers are held"
    );

    // The application's own lock, keyed by `secret_id`. In a real service this
    // is a per-secret mutex, a Postgres advisory lock, or a queue that pins a
    // partition to one worker — the library needs none of them, it only needs
    // to not prevent them.
    let gate: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    let mut tasks = Vec::new();
    for bytes in answers {
        let owner = Arc::clone(&owner);
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            let _guard = gate.lock().await;
            deliver(&owner, &bytes).await
        }));
    }

    let mut events = Vec::new();
    for task in tasks {
        events.extend(task.await.expect("a handler task panicked"));
    }

    let completions = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::SharingComplete { .. }))
        .count();
    assert_eq!(
        completions, 1,
        "the round must close exactly once; got {completions}"
    );

    let after = snapshot(&owner.client(), secret_id).await;
    assert_eq!(
        after.protocol_state, 0,
        "a completed round leaves no in-flight row"
    );
    assert_eq!(snapshot_version(&owner.client(), secret_id).await, Some(1));
    println!(
        "  2 concurrent handlers on one shared peer, serialized by an application \
         lock — round closed exactly once  ✓"
    );
}

/// A timer firing while a response is being handled.
///
/// `tick` reads and rewrites the same round state `process` does, so a service
/// that runs a scheduler alongside its handlers has a third writer to think
/// about — and the answer is the one it already has: the same per-`secret_id`
/// lock. This checks that holding both under one gate produces a single,
/// consistent outcome no matter which wins the race.
///
/// The tick is deliberately fired against a live round *inside* its window: it
/// must observe the in-flight state and leave it alone, not mistake a
/// still-arriving answer for a stalled one.
async fn a_scheduled_tick_shares_the_same_lock_as_inbound_messages() {
    let secret_id = 0xC0FF_EE77;
    let owner_db = Database::open_isolated().await;
    let helper_a_db = Database::open_isolated().await;
    let helper_b_db = Database::open_isolated().await;

    let options = PeerOptions {
        secret_id,
        threshold: 2,
        replica_id: None,
    };
    let owner = Arc::new(StatelessPeer::new(
        owner_db.client(),
        "Owner",
        "https://owner-tick.example.com",
        options,
    ));
    let helper_a = StatelessPeer::new(
        helper_a_db.client(),
        "HelperA",
        "https://helper-a-tick.example.com",
        options,
    );
    let helper_b = StatelessPeer::new(
        helper_b_db.client(),
        "HelperB",
        "https://helper-b-tick.example.com",
        options,
    );

    for (i, helper) in [&helper_a, &helper_b].into_iter().enumerate() {
        let contact = owner
            .session()
            .create_contact(Some(ChannelId(900 + i as u64)), ContactMode::InlineKeys, None)
            .await
            .expect("create_contact");
        helper
            .session()
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact,
                peer_communication_info: HashMap::new(),
            })
            .await
            .expect("start(Pairing)");
        pump(&[&*owner, helper]).await;
    }

    owner
        .session()
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![8],
                name: "ticked".to_owned(),
                data: b"a timer fires mid-round".to_vec(),
            }],
            description: Some("tick contention".to_owned()),
        })
        .await
        .expect("start(ProtectSecret)");

    for (endpoint, bytes) in owner.drain() {
        let target = if endpoint.uri == helper_a.uri {
            &helper_a
        } else {
            &helper_b
        };
        deliver(target, &bytes).await;
    }
    let mut answers: Vec<Vec<u8>> = Vec::new();
    for helper in [&helper_a, &helper_b] {
        for (_endpoint, bytes) in helper.drain() {
            answers.push(bytes);
        }
    }
    assert_eq!(answers.len(), 2, "both helpers answered");

    // Two handlers and one scheduler tick, all contending for the same
    // partition, all under the application's lock.
    let gate: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
    let mut tasks = Vec::new();
    for bytes in answers {
        let owner = Arc::clone(&owner);
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            let _guard = gate.lock().await;
            deliver(&owner, &bytes).await
        }));
    }
    {
        let owner = Arc::clone(&owner);
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            let _guard = gate.lock().await;
            owner.session().tick().await
        }));
    }

    let mut events = Vec::new();
    for task in tasks {
        events.extend(task.await.expect("a task panicked"));
    }

    // Whatever the interleaving, the round closes exactly once and the tick
    // never cuts short a helper that was still within its window.
    let completions = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::SharingComplete { .. }))
        .count();
    assert_eq!(
        completions, 1,
        "the round must close exactly once across handlers and the tick; got {completions}"
    );
    assert!(
        !events.iter().any(|e| matches!(
            e,
            DeRecEvent::ShareRejected { memo, .. } if memo == "timeout"
        )),
        "a tick inside the window must not fail a helper that answered; got {events:?}"
    );

    let after = snapshot(&owner.client(), secret_id).await;
    assert_eq!(after.protocol_state, 0, "no in-flight row survives");
    assert_eq!(snapshot_version(&owner.client(), secret_id).await, Some(1));
    println!(
        "  a scheduled tick contending with 2 handlers under one lock — round closed \
         exactly once, no premature timeout  ✓"
    );
}
