//! Material produced before the move to `rand` 0.10 and `ml-kem` 0.3 must
//! keep working: decapsulation keys held in stored pairing secrets, pairings
//! a peer started on the old release, and shares helpers already hold.
//!
//! Those decapsulation keys are in the expanded form, accepted until 0.0.13;
//! the expanded-key cases go when that support is removed.

#[path = "fixtures/pre_rand_0_10.rs"]
mod fixture;

use ark_serialize::CanonicalDeserialize;
use derec_cryptography::pairing::{
    self, InitiatorSecretKeyMaterial, PairingContactMessageMaterial, PairingRequestMessageMaterial,
    ResponderSecretKeyMaterial, pairing_mlkem,
};
use derec_cryptography::vss::{self, VSSShare};
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;

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
fn an_old_decapsulation_key_opens_old_and_new_ciphertexts() {
    let dk = bytes(fixture::MLKEM_DK);
    let ek = bytes(fixture::MLKEM_EK);

    let old = pairing_mlkem::decapsulate(&dk, bytes(fixture::MLKEM_CT)).unwrap();
    assert_eq!(old.to_vec(), bytes(fixture::MLKEM_SS));

    let (ct, sent) = pairing_mlkem::encapsulate(&ek, &mut UnwrapErr(SysRng)).unwrap();
    assert_eq!(pairing_mlkem::decapsulate(&dk, &ct).unwrap(), sent);
}

#[test]
fn a_pairing_started_on_the_old_release_completes_on_the_new_one() {
    let contact: PairingContactMessageMaterial = decode(fixture::CONTACT);
    let initiator: InitiatorSecretKeyMaterial = decode(fixture::INITIATOR_SECRET);
    let request: PairingRequestMessageMaterial = decode(fixture::REQUEST);
    let responder: ResponderSecretKeyMaterial = decode(fixture::RESPONDER_SECRET);
    let expected = bytes(fixture::PAIRING_SHARED_KEY);

    assert_eq!(
        pairing::finish_pairing_initiator(&initiator, &request)
            .unwrap()
            .to_vec(),
        expected
    );
    assert_eq!(
        pairing::finish_pairing_responder(&responder, &contact)
            .unwrap()
            .to_vec(),
        expected
    );

    let (new_request, new_responder) =
        pairing::pairing_request_message([5u8; 32], &contact).unwrap();
    assert_eq!(
        pairing::finish_pairing_initiator(&initiator, &new_request).unwrap(),
        pairing::finish_pairing_responder(&new_responder, &contact).unwrap()
    );
}

#[test]
fn shares_split_on_the_old_release_still_recover() {
    let share = |x: &str, y: &str, ct: &str, root: &str, path: &str| VSSShare {
        x: bytes(x),
        y: bytes(y),
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

    assert!(shares.iter().all(vss::verify));
    assert_eq!(vss::recover(&shares).unwrap(), bytes(fixture::VSS_SECRET));
}
