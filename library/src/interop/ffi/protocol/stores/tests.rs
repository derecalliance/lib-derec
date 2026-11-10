use super::*;
use crate::protocol::KeyRing;
use crate::types::SharedKey;

fn ring() -> KeyRing {
    KeyRing::fresh(SharedKey::new([7u8; 32]))
}

#[test]
fn secret_value_record_round_trips_key_ring() {
    let value = SecretValue::KeyRing(ring());

    let record = SecretValueRecord::try_from(&value).expect("a key ring encodes");
    assert_eq!(record.kind, 3);
    assert_eq!(record.bytes, ring().as_bytes().unwrap());

    let json = serde_json::to_vec(&record).expect("record serializes");
    let decoded: SecretValueRecord = serde_json::from_slice(&json).expect("record deserializes");
    match decoded.into_value().expect("a key ring decodes") {
        SecretValue::KeyRing(back) => assert_eq!(back, ring()),
        _ => panic!("kind 3 must decode to a key ring"),
    }
}

#[test]
fn a_key_ring_record_with_bad_bytes_is_refused() {
    for bytes in [Vec::new(), vec![1u8; 3], vec![0xFFu8; 40]] {
        let record = SecretValueRecord { kind: 3, bytes };
        let err = record.into_value().err().expect("bad bytes are refused");
        assert!(err.starts_with("failed to decode KeyRing"), "{err}");
    }
}

#[test]
fn the_key_ring_kind_maps_to_three() {
    assert_eq!(secret_kind_to_u32(SecretKind::KeyRing), 3);
}
