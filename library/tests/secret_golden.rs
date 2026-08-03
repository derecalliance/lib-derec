// Golden conformance vectors for the secret's JSON encoding.
// DO NOT edit the *.json fixtures to make a failing assertion pass — a
// mismatch means the encoder diverged from the format; fix the encoder.

use std::collections::HashMap;
use std::io::Read as _;

use derec_library::protocol::types::{HelperInfo, ReplicaInfo, Replicas, Secret, UserSecret};
use flate2::read::GzDecoder;

fn assert_matches_golden(secret: &Secret, fixture: &[u8]) {
    let encoded = secret.encode();
    let (&major, payload) = encoded.split_first().expect("non-empty encoding");
    assert_eq!(major, 1, "golden vector is version 1");
    let mut json = Vec::new();
    GzDecoder::new(payload)
        .read_to_end(&mut json)
        .expect("payload must be valid gzip");
    // Fixtures are stored with a trailing newline for tooling friendliness.
    let expected = fixture.strip_suffix(b"\n").unwrap_or(fixture);
    assert_eq!(
        std::str::from_utf8(&json).unwrap(),
        std::str::from_utf8(expected).unwrap(),
        "encoder JSON diverged from the golden vector",
    );
}

fn golden_secret() -> Secret {
    Secret {
        helpers: vec![HelperInfo {
            channel_id: 2,
            transport_uri: "u".to_owned(),
            shared_key: vec![0x01, 0x02, 0x03],
            communication_info: HashMap::new(),
        }],
        secrets: vec![UserSecret {
            id: vec![0x0A],
            name: "n".to_owned(),
            data: vec![0x0B, 0x0C],
        }],
        replicas: None,
        owner_replica_id: 1,
    }
}

/// Exercises the full schema surface the minimal vector leaves unpinned: a
/// populated replica group, non-empty `communication_info`, and a non-zero
/// `sender_kind`. Maps carry a single entry to keep serialization
/// deterministic (`HashMap` order is unspecified for multiple entries).
fn golden_secret_full() -> Secret {
    Secret {
        helpers: vec![HelperInfo {
            channel_id: 2,
            transport_uri: "h".to_owned(),
            shared_key: vec![0x01, 0x02, 0x03],
            communication_info: HashMap::from([("k".to_owned(), "v".to_owned())]),
        }],
        secrets: vec![UserSecret {
            id: vec![0x0A],
            name: "n".to_owned(),
            data: vec![0x0B, 0x0C],
        }],
        replicas: Some(Replicas {
            replicas: vec![ReplicaInfo {
                channel_id: 3,
                transport_uri: "r".to_owned(),
                communication_info: HashMap::from([("a".to_owned(), "b".to_owned())]),
                replica_id: 4,
                sender_kind: 2,
            }],
            shared_key: vec![0x04, 0x05, 0x06],
        }),
        owner_replica_id: 1,
    }
}

#[test]
fn encoder_matches_golden_json() {
    assert_matches_golden(&golden_secret(), include_bytes!("golden/secret_v1.json"));
}

#[test]
fn encoder_matches_golden_json_full() {
    assert_matches_golden(
        &golden_secret_full(),
        include_bytes!("golden/secret_v1_full.json"),
    );
}

#[test]
fn golden_round_trips() {
    let secret = golden_secret();
    assert_eq!(Secret::decode(&secret.encode()).unwrap(), secret);
}

#[test]
fn golden_full_round_trips() {
    let secret = golden_secret_full();
    assert_eq!(Secret::decode(&secret.encode()).unwrap(), secret);
}
