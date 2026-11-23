use super::*;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

fn key(byte: u8) -> SharedKey {
    SharedKey::new([byte; 32])
}

/// Kₑ of the chain that starts at `key(7)`.
fn k(epoch: u32) -> SharedKey {
    (1..=epoch).fold(key(7), |key, e| next_key(&key, e))
}

/// A ring at `epoch` with the given pins, whose old keys are the chain keys
/// of `old_epochs`. Callers name every old epoch in `pins`.
fn ring(epoch: u32, pins: &[(u32, u32)], old_epochs: &[u32]) -> KeyRing {
    KeyRing {
        epoch,
        key: k(epoch),
        pins: pins.to_vec(),
        old: old_epochs.iter().map(|e| (*e, k(*e))).collect(),
    }
}

fn held(lookup: Lookup) -> ChannelKey {
    match lookup {
        Lookup::Held(key) => key,
        _ => panic!("expected Held"),
    }
}

fn behind(lookup: Lookup) -> ChannelKey {
    match lookup {
        Lookup::Behind(key) => key,
        _ => panic!("expected Behind"),
    }
}

fn old_epochs(ring: &KeyRing) -> Vec<u32> {
    ring.old.iter().map(|(e, _)| *e).collect()
}

#[test]
fn next_key_matches_the_hmac_definition() {
    let base = key(1);
    let mut mac = Hmac::<Sha256>::new_from_slice(base.as_bytes()).unwrap();
    mac.update(b"derec channel key v1");
    mac.update(&5u32.to_be_bytes());
    let expected: [u8; 32] = mac.finalize().into_bytes().into();
    assert_eq!(next_key(&base, 5).as_bytes(), &expected);
}

#[test]
fn next_key_differs_per_epoch_and_per_key() {
    assert_ne!(next_key(&key(1), 1), next_key(&key(1), 2));
    assert_ne!(next_key(&key(1), 1), next_key(&key(2), 1));
}

#[test]
fn ring_bytes_round_trip() {
    let ring = KeyRing {
        epoch: 0x0102_0304,
        key: key(9),
        pins: vec![(1, 5), (9, 0x0102_0304), (12, 7)],
        old: vec![(5, key(1)), (7, key(2))],
    };
    let bytes = ring.as_bytes().unwrap();
    assert_eq!(bytes.len(), 1 + 4 + 32 + 2 + 3 * 8 + 2 + 2 * 36);
    assert_eq!(&bytes[..5], &[1, 1, 2, 3, 4]);
    assert_eq!(KeyRing::from_bytes(&bytes).unwrap(), ring);

    let fresh = KeyRing::fresh(key(3));
    assert_eq!(
        KeyRing::from_bytes(&fresh.as_bytes().unwrap()).unwrap(),
        fresh
    );
}

#[test]
fn ring_from_bytes_rejects_malformed() {
    let good = ring(10, &[(1, 3), (2, 6)], &[3, 6]);
    let bytes = good.as_bytes().unwrap();
    assert!(KeyRing::from_bytes(&bytes).is_ok());
    let rejected = |ring: KeyRing| KeyRing::from_bytes(&ring.as_bytes().unwrap()).is_err();

    let mut bad = bytes.clone();
    bad[0] = 2;
    assert!(KeyRing::from_bytes(&bad).is_err(), "unknown version");

    assert!(
        KeyRing::from_bytes(&bytes[..bytes.len() - 1]).is_err(),
        "short"
    );
    let mut long = bytes.clone();
    long.push(0);
    assert!(KeyRing::from_bytes(&long).is_err(), "long");
    assert!(KeyRing::from_bytes(&[]).is_err(), "empty");
    assert!(KeyRing::from_bytes(&bytes[..10]).is_err(), "header only");

    let mut bad = good.clone();
    bad.pins.push((3, 11));
    assert!(rejected(bad), "pin epoch above the epoch");

    let mut bad = good.clone();
    bad.pins[1].0 = 1;
    assert!(rejected(bad), "duplicate pin versions");

    let mut bad = good.clone();
    bad.pins.swap(0, 1);
    assert!(rejected(bad), "unsorted pin versions");

    let mut bad = good.clone();
    bad.pins.push((3, 10));
    bad.old.push((10, k(10)));
    assert!(rejected(bad), "old epoch equal to the epoch");

    let mut bad = good.clone();
    bad.old.swap(0, 1);
    assert!(rejected(bad), "unsorted old epochs");

    let mut bad = good.clone();
    bad.old[1].0 = 3;
    assert!(rejected(bad), "duplicate old epochs");

    let mut bad = good.clone();
    bad.pins.pop();
    assert!(rejected(bad), "old key named by no pin");
}

/// A ring whose pins or old keys outnumber what a `u16` count expresses is
/// refused by the encoder rather than written with a wrapped count.
#[test]
fn a_ring_past_the_count_limit_does_not_encode() {
    let limit = u32::from(u16::MAX);
    let at_limit = KeyRing {
        epoch: 0,
        key: key(1),
        pins: (0..limit).map(|version| (version, 0)).collect(),
        old: Vec::new(),
    };
    let bytes = at_limit.as_bytes().expect("u16::MAX pins encode");
    assert_eq!(KeyRing::from_bytes(&bytes).unwrap(), at_limit);

    let mut too_many_pins = at_limit.clone();
    too_many_pins.pins.push((limit, 0));
    assert!(matches!(too_many_pins.as_bytes(), Err(Error::Invariant(_))));

    let too_many_old = KeyRing {
        epoch: limit + 1,
        key: key(1),
        pins: (0..=limit).map(|epoch| (epoch, epoch)).collect(),
        old: (0..=limit).map(|epoch| (epoch, key(2))).collect(),
    };
    assert!(matches!(too_many_old.as_bytes(), Err(Error::Invariant(_))));
}

/// The serde form is the ring's fields, and reading it back applies the
/// rules of `from_bytes`.
#[cfg(feature = "serde")]
#[test]
fn a_deserialized_ring_is_checked() {
    let good = ring(10, &[(1, 3), (2, 6)], &[3, 6]);
    let json = serde_json::to_value(&good).unwrap();
    assert_eq!(
        json.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["epoch", "key", "old", "pins"]
    );
    assert_eq!(
        serde_json::from_value::<KeyRing>(json.clone()).unwrap(),
        good
    );

    let mut bad = json.clone();
    bad["pins"] = serde_json::json!([[1, 11]]);
    assert!(
        serde_json::from_value::<KeyRing>(bad).is_err(),
        "pin above the epoch"
    );

    let mut bad = json;
    bad["pins"] = serde_json::json!([[1, 3]]);
    assert!(
        serde_json::from_value::<KeyRing>(bad).is_err(),
        "old key named by no pin"
    );
}

#[test]
fn a_fresh_ring_is_epoch_zero_and_holds_only_its_key() {
    let fresh = KeyRing::fresh(key(7));
    assert_eq!(fresh.epoch(), 0);
    assert_eq!(fresh.current().epoch, 0);
    assert_eq!(fresh.current().key, key(7));
    assert!(fresh.pins().is_empty());
    assert!(fresh.old.is_empty());
}

#[test]
fn lookup_returns_held_keys() {
    let ring = ring(9, &[(1, 4)], &[4]);
    let newest = held(ring.lookup(9));
    assert_eq!((newest.epoch, newest.key), (9, k(9)));
    let pinned = held(ring.lookup(4));
    assert_eq!((pinned.epoch, pinned.key), (4, k(4)));
    assert_eq!(ring.key_at(4).unwrap().key, k(4));
}

#[test]
fn lookup_behind_derives_from_the_nearest_lower_held_key() {
    let ring = ring(16, &[(1, 1)], &[1]);
    let two = behind(ring.lookup(2));
    assert_eq!(two.epoch, 2);
    assert_eq!(two.key, next_key(&k(1), 2));
    let fifteen = behind(ring.lookup(15));
    assert_eq!(fifteen.key, k(15));
    assert!(matches!(ring.lookup(0), Lookup::Unavailable));
    assert_eq!(ring.key_at(15).unwrap().key, k(15));
    assert!(ring.key_at(0).is_none());
}

#[test]
fn lookup_behind_is_unavailable_beyond_the_limit() {
    let ring = ring(600, &[(1, 1)], &[1]);
    assert!(matches!(ring.lookup(513), Lookup::Behind(_)));
    assert!(matches!(ring.lookup(514), Lookup::Unavailable));
}

#[test]
fn lookup_ahead_derives_and_keeps_only_a_pinned_previous_key() {
    let pinned = ring(1, &[(1, 1)], &[]);
    let Lookup::Ahead { key, advanced } = pinned.lookup(16) else {
        panic!("expected Ahead");
    };
    assert_eq!(key.epoch, 16);
    assert_eq!(key.key, k(16));
    assert_eq!(advanced.epoch(), 16);
    assert_eq!(advanced.current().key, k(16));
    assert_eq!(advanced.pins(), pinned.pins());
    assert_eq!(old_epochs(&advanced), vec![1]);
    assert_eq!(advanced.old[0].1, k(1));

    let unpinned = ring(1, &[], &[]);
    let Lookup::Ahead { advanced, .. } = unpinned.lookup(16) else {
        panic!("expected Ahead");
    };
    assert!(advanced.old.is_empty());
}

#[test]
fn lookup_behind_derives_from_the_largest_held_key_below() {
    let ring = ring(1000, &[(1, 1), (2, 600)], &[1, 600]);
    let found = behind(ring.lookup(700));
    assert_eq!(found.key, k(700));
    assert_eq!(found.key, derive(&k(600), 600, 700));
    assert!(matches!(ring.lookup(514), Lookup::Unavailable));
}

#[test]
fn lookup_ahead_keeps_existing_old_keys_in_order() {
    let ring = ring(20, &[(1, 2), (2, 9), (3, 20)], &[2, 9]);
    let Lookup::Ahead { advanced, .. } = ring.lookup(25) else {
        panic!("expected Ahead");
    };
    assert_eq!(old_epochs(&advanced), vec![2, 9, 20]);
    assert_eq!(advanced.old[2].1, k(20));
    assert_eq!(advanced.current().key, k(25));

    let unpinned = super::KeyRing {
        pins: vec![(1, 2), (2, 9)],
        ..ring
    };
    let Lookup::Ahead { advanced, .. } = unpinned.lookup(25) else {
        panic!("expected Ahead");
    };
    assert_eq!(old_epochs(&advanced), vec![2, 9]);
}

#[test]
fn lookup_beyond_the_forward_limit_is_unavailable() {
    let ring = ring(0, &[], &[]);
    assert!(matches!(ring.lookup(512), Lookup::Ahead { .. }));
    assert!(matches!(ring.lookup(513), Lookup::Unavailable));
    assert!(matches!(ring.lookup(u32::MAX), Lookup::Unavailable));

    let near_end = KeyRing {
        epoch: u32::MAX - 10,
        key: key(7),
        pins: vec![],
        old: vec![],
    };
    assert!(matches!(near_end.lookup(u32::MAX), Lookup::Ahead { .. }));
}

#[test]
fn advanced_is_none_at_the_last_epoch() {
    let ring = KeyRing {
        epoch: u32::MAX,
        key: key(7),
        pins: vec![],
        old: vec![],
    };
    assert!(ring.advanced().is_none());
    assert!(matches!(ring.lookup(u32::MAX), Lookup::Held(_)));
    assert_eq!(ring_at(3).advanced().unwrap().epoch(), 4);
}

fn ring_at(epoch: u32) -> KeyRing {
    ring(epoch, &[], &[])
}

#[test]
fn pinned_stores_a_behind_key_and_replaces_a_versions_pin() {
    let ring = ring(16, &[(1, 1)], &[1]);
    let two = behind(ring.lookup(2));
    let with_two = ring.pinned(2, &two);
    assert_eq!(with_two.pins(), &[(1, 1), (2, 2)]);
    assert_eq!(old_epochs(&with_two), vec![1, 2]);
    assert_eq!(with_two.old[1].1, k(2));

    let newest = with_two.current();
    let moved = with_two.pinned(2, &newest);
    assert_eq!(moved.pins(), &[(1, 1), (2, 16)]);
    assert_eq!(old_epochs(&moved), vec![1]);

    let ahead = ChannelKey {
        epoch: 17,
        key: k(17),
    };
    assert!(ring.pinned(3, &ahead) == ring);
}

#[test]
fn retain_pins_drops_unnamed_old_keys() {
    let ring = ring(17, &[(1, 1), (16, 16), (17, 17)], &[1, 16]);
    let kept = ring.retain_pins(|version| version >= 16);
    assert_eq!(kept.pins(), &[(16, 16), (17, 17)]);
    assert_eq!(old_epochs(&kept), vec![16]);
    assert_eq!(kept.old[0].1, k(16));
    assert_eq!(kept.current().key, k(17));
}

#[test]
fn debug_hides_every_key() {
    let mut ring = KeyRing::fresh(key(0xE7));
    ring.epoch = 3;
    ring.pins = vec![(1, 2)];
    ring.old = vec![(2, key(0xF9))];
    let shown = format!("{ring:?}");
    for hidden in ["e7", "E7", "231", "f9", "F9", "249"] {
        assert!(!shown.contains(hidden), "{hidden} leaked in {shown}");
    }
    assert!(shown.contains("epoch: 3"));
    assert!(shown.contains("(1, 2)"));
}
