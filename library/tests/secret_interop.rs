// Proves the recoverable secret can be decompressed and decoded OUTSIDE
// the protocol, using only standard gzip + JSON + base64 — the guarantee
// that makes DeRec recovery cross-application. Uses no DeRec decoder.

use std::collections::HashMap;
use std::io::Read as _;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use derec_library::protocol::types::{HelperInfo, Secret, UserSecret};
use flate2::read::GzDecoder;
use serde_json::Value;

#[test]
fn recovered_secret_decodes_without_the_protocol() {
    let secret = Secret {
        helpers: vec![HelperInfo {
            channel_id: 1_000_000,
            transport_uri: "https://helper-0.example.org/derec".to_owned(),
            shared_key: vec![0xAB; 32],
            communication_info: HashMap::from([("name".to_owned(), "Helper 0".to_owned())]),
        }],
        secrets: vec![UserSecret {
            id: vec![0xDE, 0xAD, 0xBE, 0xEF],
            name: "Gmail".to_owned(),
            data: b"correct horse battery staple".to_vec(),
        }],
        replicas: None,
        owner_replica_id: 0xAAAA_BBBB,
    };

    // The bytes a helper stores / recovery reconstructs into secret_data.
    let encoded = secret.encode();

    // --- independent decoder: version byte → gzip → JSON → base64, no DeRec code ---
    let (&major, payload) = encoded.split_first().expect("non-empty encoding");
    assert_eq!(major, 1, "version prefix");

    let mut json = Vec::new();
    GzDecoder::new(payload)
        .read_to_end(&mut json)
        .expect("payload must be valid gzip (RFC 1952)");
    let v: Value = serde_json::from_slice(&json).expect("payload must be valid JSON");

    assert_eq!(v["owner_replica_id"], "2863315899"); // 0xAAAABBBB as decimal string

    let s = &v["secrets"][0];
    assert_eq!(s["name"], "Gmail");
    let id = STANDARD.decode(s["id"].as_str().unwrap()).unwrap();
    let data = STANDARD.decode(s["data"].as_str().unwrap()).unwrap();
    assert_eq!(id, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(data, b"correct horse battery staple");

    let h = &v["helpers"][0];
    assert_eq!(h["channel_id"], "1000000");
    let key = STANDARD.decode(h["shared_key"].as_str().unwrap()).unwrap();
    assert_eq!(key, vec![0xAB; 32]);
}
