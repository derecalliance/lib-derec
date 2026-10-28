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
fn an_old_initiator_no_longer_loads_but_an_old_responder_still_finishes() {
    let contact: PairingContactMessageMaterial = decode(fixture::CONTACT);
    let responder: ResponderSecretKeyMaterial = decode(fixture::RESPONDER_SECRET);

    // Initiator material from before the fingerprint nonce lacks that field.
    assert!(
        InitiatorSecretKeyMaterial::deserialize_uncompressed(
            bytes(fixture::INITIATOR_SECRET).as_slice()
        )
        .is_err()
    );
    let _: PairingRequestMessageMaterial = decode(fixture::REQUEST);

    let nonce = [9u8; 32];
    let commitment = pairing::fingerprint_commitment(
        &contact.mlkem_encapsulation_key,
        &contact.ecies_public_key,
        &nonce,
    );
    let handshake_key: [u8; 32] = bytes(fixture::PAIRING_SHARED_KEY)
        .try_into()
        .expect("fixture key is 32 bytes");
    assert_eq!(
        pairing::finish_pairing_responder(&responder, &contact, &commitment, &nonce).unwrap(),
        pairing::channel_key(&handshake_key, &nonce)
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
