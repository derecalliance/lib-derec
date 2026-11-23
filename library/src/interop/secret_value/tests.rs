use super::*;
use crate::protocol::KeyRing;
use crate::types::SharedKey;

fn ring() -> KeyRing {
    KeyRing::fresh(SharedKey::new([7u8; 32]))
}

#[test]
fn decode_reads_a_key_ring() {
    match decode(SecretKind::KeyRing, &ring().as_bytes().unwrap()).expect("a key ring decodes") {
        SecretValue::KeyRing(back) => assert_eq!(back, ring()),
        _ => panic!("kind 3 must decode to a key ring"),
    }
}

#[test]
fn decode_refuses_bad_key_ring_bytes() {
    for bytes in [&[][..], &[1u8; 3][..], &[0xFFu8; 40][..]] {
        assert!(decode(SecretKind::KeyRing, bytes).is_err());
    }
}

#[test]
fn decode_reads_a_shared_key() {
    match decode(SecretKind::SharedKey, &[9u8; 32]).expect("a shared key decodes") {
        SecretValue::SharedKey(key) => assert_eq!(key.as_bytes(), &[9u8; 32]),
        _ => panic!("kind 0 must decode to a shared key"),
    }
}

#[test]
fn decode_refuses_a_short_shared_key() {
    assert!(decode(SecretKind::SharedKey, &[9u8; 31]).is_err());
}

#[test]
fn decode_refuses_bad_contact_bytes() {
    assert!(decode(SecretKind::PairingContact, &[0xFFu8; 4]).is_err());
}
