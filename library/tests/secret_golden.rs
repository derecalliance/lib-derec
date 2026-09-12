// Golden conformance vectors for the secret's JSON encoding.
//
// DO NOT edit the *.json fixtures to make a failing assertion pass — a
// mismatch means the encoder diverged from the format; fix the encoder.
// The one exception is a deliberate format version bump, which adds a new
// `secret_vN.json` rather than editing an existing one.
//
// The `secret_v2*.json` vectors are frozen: v2 is no longer produced, and
// they exist to prove an older secret still *decodes*. Regenerating them
// would destroy the only evidence that a secret protected before v3 remains
// recoverable.

use std::collections::HashMap;
use std::io::Read as _;

use derec_library::protocol::types::{
    HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret,
};
use flate2::read::GzDecoder;

fn assert_matches_golden(secret: &Secret, fixture: &[u8]) {
    let encoded = secret.encode();
    let (&major, payload) = encoded.split_first().expect("non-empty encoding");
    assert_eq!(major, 3, "golden vector is version 3");
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
            transports: vec![derec_proto::TransportProtocol {
                uri: "https://u.example/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            shared_key: vec![0x01, 0x02, 0x03],
            communication_info: HashMap::new(),
        }],
        secrets: vec![UserSecret {
            id: vec![0x0A],
            name: "n".to_owned(),
            data: vec![0x0B, 0x0C],
        }],
        replicas: None,
    }
}

/// Exercises the full schema surface the minimal vector leaves unpinned: a
/// populated replica group carrying both roles, and non-empty
/// `communication_info`. Maps carry a single entry to keep serialization
/// deterministic (`HashMap` order is unspecified for multiple entries).
fn golden_secret_full() -> Secret {
    Secret {
        helpers: vec![HelperInfo {
            channel_id: 2,
            transports: vec![derec_proto::TransportProtocol {
                uri: "https://h.example/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            shared_key: vec![0x01, 0x02, 0x03],
            communication_info: HashMap::from([("k".to_owned(), "v".to_owned())]),
        }],
        secrets: vec![UserSecret {
            id: vec![0x0A],
            name: "n".to_owned(),
            data: vec![0x0B, 0x0C],
        }],
        replicas: Some(Replicas {
            channel_id: 5,
            members: vec![
                ReplicaInfo {
                    replica_id: 4,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://r.example/derec".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Source as i32,
                    communication_info: HashMap::from([("a".to_owned(), "b".to_owned())]),
                },
                ReplicaInfo {
                    replica_id: 6,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://r2.example/derec".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Destination as i32,
                    communication_info: HashMap::new(),
                },
            ],
            shared_key: vec![0x04, 0x05, 0x06],
        }),
    }
}

#[test]
fn encoder_matches_golden_json() {
    assert_matches_golden(&golden_secret(), include_bytes!("golden/secret_v3.json"));
}

#[test]
fn encoder_matches_golden_json_full() {
    assert_matches_golden(
        &golden_secret_full(),
        include_bytes!("golden/secret_v3_full.json"),
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

/// A v2 payload must still decode. These are the frozen v2 vectors, fed
/// through the current decoder: if this breaks, a secret protected before
/// the v3 format became unrecoverable.
fn assert_v2_fixture_decodes(fixture: &[u8], expected_uris: &[&str]) {
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write as _;

    let json = fixture.strip_suffix(b"\n").unwrap_or(fixture);
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(json).expect("gzip");
    let payload = enc.finish().expect("gzip");

    let mut encoded = vec![2u8];
    encoded.extend_from_slice(&payload);

    let secret = Secret::decode(&encoded).expect("a v2 payload must still decode");

    let uris: Vec<String> = secret
        .helpers
        .iter()
        .flat_map(|h| h.transports.iter().map(|t| t.uri.clone()))
        .collect();
    assert_eq!(
        uris,
        expected_uris
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>(),
        "each v2 transport_uri must lift into a one-element endpoint list",
    );
}

/// The frozen v2 vector stores `"u"` as its transport — a value with no URI
/// scheme, so no protocol can be honestly derived from it. It lifts to *no*
/// endpoint rather than a guessed one, which is the rule that keeps a
/// rehydrated peer from pointing somewhere nothing answers.
#[test]
fn v2_golden_still_decodes() {
    assert_v2_fixture_decodes(include_bytes!("golden/secret_v2.json"), &[]);
}
