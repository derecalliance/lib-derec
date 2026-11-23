// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::SecretStoreExt as _;
use crate::protocol::tests::{InMemSecretStore, run_async};
use crate::protocol::{
    DeRecSecretStore as _, KeyRing, MissingPolicy, PairingKeyMaterial, SecretKind, SecretValue,
};
use crate::types::ChannelId;
use crate::types::SharedKey;

const SECRET_ID: u64 = 0x5EC;
const CHANNEL: ChannelId = ChannelId(7);

/// A stored shared key is returned by both reads.
#[test]
fn a_stored_key_is_read() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::SharedKey(SharedKey::new([9; 32])),
            )
            .await
            .expect("save");

        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            Some(SharedKey::new([9; 32]))
        );
        assert_eq!(
            secrets.paired_key(SECRET_ID, CHANNEL).await.expect("read"),
            crate::types::SharedKey::new([9; 32])
        );
    });
}

/// A channel holding only its pairing secret has no shared key: it is not
/// paired yet.
#[test]
fn a_channel_without_a_shared_key_is_not_paired() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::PairingSecret(PairingKeyMaterial::from_bytes(vec![1, 2, 3])),
            )
            .await
            .expect("save");

        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            None
        );
        assert!(matches!(
            secrets.paired_key(SECRET_ID, CHANNEL).await,
            Err(crate::Error::InvalidInput(_))
        ));
    });
}

fn key(byte: u8) -> SharedKey {
    SharedKey::new([byte; 32])
}

/// A ring at `epoch`, reached by advancing from epoch 0 under `key(1)`.
fn ring_at(epoch: u32) -> KeyRing {
    let mut ring = KeyRing::fresh(key(1));
    for _ in 0..epoch {
        ring = ring.advanced().expect("advances");
    }
    ring
}

/// Store `value` under `kind`, whatever kind `value` is, as a store with a
/// broken mapping would answer.
fn put_raw(secrets: &InMemSecretStore, channel: ChannelId, kind: SecretKind, value: SecretValue) {
    secrets
        .data
        .lock()
        .unwrap()
        .insert((SECRET_ID, channel.0, kind as u8), value);
}

async fn seed_key(secrets: &mut InMemSecretStore, channel: ChannelId, key: SharedKey) {
    secrets
        .save(SECRET_ID, channel, SecretValue::SharedKey(key))
        .await
        .expect("save");
}

/// A channel paired before rings existed has only its `SharedKey` row; it
/// reads as a fresh ring under that key.
#[test]
fn key_ring_without_a_ring_row_is_fresh_at_epoch_zero() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        seed_key(&mut secrets, CHANNEL, key(9)).await;

        let ring = secrets
            .key_ring(SECRET_ID, CHANNEL)
            .await
            .expect("read")
            .expect("paired");

        assert_eq!(ring, KeyRing::fresh(key(9)));
        assert_eq!(ring.epoch(), 0);
    });
}

/// A channel with no shared key has no ring, even if a ring row exists.
#[test]
fn key_ring_of_an_unpaired_channel_is_none() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        assert_eq!(
            secrets.key_ring(SECRET_ID, CHANNEL).await.expect("read"),
            None
        );

        secrets
            .save(SECRET_ID, CHANNEL, SecretValue::KeyRing(ring_at(1)))
            .await
            .expect("save");
        assert_eq!(
            secrets.key_ring(SECRET_ID, CHANNEL).await.expect("read"),
            None
        );
    });
}

#[test]
fn save_then_load_round_trips_the_ring() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let ring = ring_at(3);

        secrets
            .save_key_ring(SECRET_ID, CHANNEL, &ring)
            .await
            .expect("save");

        assert_eq!(
            secrets.key_ring(SECRET_ID, CHANNEL).await.expect("read"),
            Some(ring.clone())
        );
        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            Some(ring.current().key),
            "the SharedKey row mirrors the newest key"
        );
    });
}

/// The ring row is authoritative: a `SharedKey` row left at an older key by
/// an interrupted write does not roll the channel back.
#[test]
fn a_stale_shared_key_mirror_is_ignored() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let ring = ring_at(2);
        secrets
            .save_key_ring(SECRET_ID, CHANNEL, &ring)
            .await
            .expect("save");
        seed_key(&mut secrets, CHANNEL, key(1)).await;

        let read = secrets
            .key_ring(SECRET_ID, CHANNEL)
            .await
            .expect("read")
            .expect("paired");

        assert_eq!(read.epoch(), 2);
        assert_eq!(read.current().key, ring.current().key);
    });
}

#[test]
fn key_rings_many_mixes_rows_with_and_without_a_ring() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let (with_ring, without_ring, unpaired) = (ChannelId(1), ChannelId(2), ChannelId(3));
        let ring = ring_at(2);
        secrets
            .save_key_ring(SECRET_ID, with_ring, &ring)
            .await
            .expect("save");
        seed_key(&mut secrets, without_ring, key(8)).await;

        let ids = [with_ring, without_ring, unpaired];
        let got = secrets
            .key_rings_many(SECRET_ID, &ids, MissingPolicy::Skip)
            .await
            .expect("read");
        assert_eq!(
            got,
            vec![
                (with_ring, Some(ring)),
                (without_ring, Some(KeyRing::fresh(key(8))))
            ]
        );

        let failed = secrets
            .key_rings_many(SECRET_ID, &ids, MissingPolicy::Fail)
            .await;
        assert!(failed.is_err(), "a channel with no key fails under Fail");
    });
}

/// A value of another kind under either row leaves the channel's key
/// unresolved, rather than dropping the channel or reading it at epoch 0.
#[test]
fn key_rings_many_reports_a_wrong_kind_row_as_unresolved() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let (good, wrong_key, wrong_ring) = (ChannelId(1), ChannelId(2), ChannelId(3));
        seed_key(&mut secrets, good, key(1)).await;
        put_raw(
            &secrets,
            wrong_key,
            SecretKind::SharedKey,
            SecretValue::KeyRing(ring_at(1)),
        );
        seed_key(&mut secrets, wrong_ring, key(3)).await;
        put_raw(
            &secrets,
            wrong_ring,
            SecretKind::KeyRing,
            SecretValue::SharedKey(key(4)),
        );

        let mut got = secrets
            .key_rings_many(
                SECRET_ID,
                &[good, wrong_key, wrong_ring],
                MissingPolicy::Fail,
            )
            .await
            .expect("read");
        got.sort_by_key(|(id, _)| *id);
        assert_eq!(
            got,
            vec![
                (good, Some(KeyRing::fresh(key(1)))),
                (wrong_key, None),
                (wrong_ring, None)
            ]
        );
    });
}

/// A ring query answered with another kind is an error, not epoch 0.
#[test]
fn key_ring_with_a_wrong_kind_ring_row_is_an_error() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        seed_key(&mut secrets, CHANNEL, key(3)).await;
        put_raw(
            &secrets,
            CHANNEL,
            SecretKind::KeyRing,
            SecretValue::SharedKey(key(4)),
        );

        assert!(matches!(
            secrets.key_ring(SECRET_ID, CHANNEL).await,
            Err(crate::Error::Invariant(_))
        ));
        assert!(matches!(
            secrets.current_key(SECRET_ID, CHANNEL).await,
            Err(crate::Error::Invariant(_))
        ));
    });
}

/// A ring the encoding cannot count is refused before either row is
/// written.
#[test]
fn save_key_ring_refuses_a_ring_it_cannot_encode() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let ring = KeyRing::unchecked(
            0,
            key(1),
            (0..=u32::from(u16::MAX))
                .map(|version| (version, 0))
                .collect(),
            Vec::new(),
        );

        assert!(matches!(
            secrets.save_key_ring(SECRET_ID, CHANNEL, &ring).await,
            Err(crate::Error::Invariant(_))
        ));
        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            None,
            "nothing is written"
        );
    });
}

/// A channel with no key holds no pins: the edit never runs and nothing is
/// written.
#[test]
fn repin_leaves_a_channel_without_a_key_alone() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();

        secrets
            .repin(SECRET_ID, CHANNEL, |_| panic!("no ring to edit"))
            .await
            .expect("repin");

        assert!(secrets.data.lock().unwrap().is_empty());
    });
}

/// An edit that changes nothing writes nothing: a channel with only its
/// `SharedKey` row gains no ring row.
#[test]
fn repin_writes_nothing_when_the_pins_do_not_change() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        seed_key(&mut secrets, CHANNEL, key(9)).await;

        secrets
            .repin(SECRET_ID, CHANNEL, |ring| ring.retain_pins(|_| true))
            .await
            .expect("repin");

        let data = secrets.data.lock().unwrap();
        assert!(!data.contains_key(&(SECRET_ID, CHANNEL.0, SecretKind::KeyRing as u8)));
    });
}

/// A changed ring is saved and read back.
#[test]
fn repin_saves_a_changed_ring() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        let ring = ring_at(2);
        secrets
            .save_key_ring(SECRET_ID, CHANNEL, &ring)
            .await
            .expect("save");

        secrets
            .repin(SECRET_ID, CHANNEL, |ring| ring.pinned(5, &ring.current()))
            .await
            .expect("repin");

        assert_eq!(
            secrets.key_ring(SECRET_ID, CHANNEL).await.expect("read"),
            Some(ring.pinned(5, &ring.current()))
        );
    });
}
