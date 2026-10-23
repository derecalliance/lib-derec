//! Material produced before the move to `rand` 0.10 and `ml-kem` 0.3.
//!
//! A responder's stored secret still finishes its side of a pairing, since it
//! holds the ML-KEM shared secret rather than a key. An initiator's stored
//! decapsulation key does not: it is in the expanded form, and only the
//! 64-byte seed form is accepted. Shares helpers already hold do not verify
//! either: their Merkle commitments predate the 0.0.9 leaf and node hashing.

#[path = "fixtures/pre_rand_0_10.rs"]
mod fixture;

use ark_serialize::CanonicalDeserialize;
use derec_cryptography::pairing::{
    self, DerecPairingError, InitiatorSecretKeyMaterial, PairingContactMessageMaterial,
    PairingRequestMessageMaterial, ResponderSecretKeyMaterial, mlkem,
};
use derec_cryptography::vss::{self, Subshare, VSSShare};

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture is hex"))
        .collect()
}

fn decode<T: CanonicalDeserialize>(hex: &str) -> T {
    T::deserialize_uncompressed(bytes(hex).as_slice()).expect("fixture deserializes")
}

#[test]
fn an_expanded_decapsulation_key_is_rejected() {
    let err = mlkem::decapsulate(bytes(fixture::MLKEM_DK), bytes(fixture::MLKEM_CT))
        .expect_err("only the seed form is accepted");
    assert!(matches!(
        err,
        DerecPairingError::InvalidSize {
            expected: mlkem::DECAPSULATION_KEY_SIZE_IN_BYTES,
            got: 3168,
        }
    ));
}

#[test]
fn an_old_initiator_cannot_finish_but_an_old_responder_can() {
    let contact: PairingContactMessageMaterial = decode(fixture::CONTACT);
    let initiator: InitiatorSecretKeyMaterial = decode(fixture::INITIATOR_SECRET);
    let request: PairingRequestMessageMaterial = decode(fixture::REQUEST);
    let responder: ResponderSecretKeyMaterial = decode(fixture::RESPONDER_SECRET);

    assert!(matches!(
        pairing::finish_pairing_initiator(&initiator, &request),
        Err(DerecPairingError::InvalidSize { got: 3168, .. })
    ));
    assert_eq!(
        pairing::finish_pairing_responder(&responder, &contact)
            .unwrap()
            .to_vec(),
        bytes(fixture::PAIRING_SHARED_KEY)
    );
}

#[test]
fn shares_split_before_0_0_9_are_rejected() {
    let share = |x: &str, y: &str, ct: &str, root: &str, path: &str| VSSShare {
        subshares: vec![Subshare {
            x: bytes(x),
            y: bytes(y),
        }],
        encrypted_secret: bytes(ct),
        commitment: bytes(root),
        merkle_path: bytes(path)
            .chunks(33)
            .map(|step| (step[0] == 1, step[1..].to_vec()))
            .collect(),
    };
    let shares = vec![
        share(
            fixture::VSS_SHARE_0_X,
            fixture::VSS_SHARE_0_Y,
            fixture::VSS_SHARE_0_CIPHERTEXT,
            fixture::VSS_SHARE_0_COMMITMENT,
            fixture::VSS_SHARE_0_MERKLE_PATH,
        ),
        share(
            fixture::VSS_SHARE_1_X,
            fixture::VSS_SHARE_1_Y,
            fixture::VSS_SHARE_1_CIPHERTEXT,
            fixture::VSS_SHARE_1_COMMITMENT,
            fixture::VSS_SHARE_1_MERKLE_PATH,
        ),
        share(
            fixture::VSS_SHARE_2_X,
            fixture::VSS_SHARE_2_Y,
            fixture::VSS_SHARE_2_CIPHERTEXT,
            fixture::VSS_SHARE_2_COMMITMENT,
            fixture::VSS_SHARE_2_MERKLE_PATH,
        ),
    ];

    assert!(!shares.iter().any(vss::verify));
    let err = vss::recover(&shares).expect_err("old commitments must not open");
    assert!(matches!(err, vss::DerecVSSError::CorruptShares));
}
