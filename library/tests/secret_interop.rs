// Proves the recoverable secret can be decompressed and decoded OUTSIDE
// the protocol, using only standard gzip + JSON + base64 — the guarantee
// that makes DeRec recovery cross-application. Uses no DeRec decoder.

use std::collections::HashMap;
use std::io::Read as _;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use derec_library::protocol::types::{
    HelperInfo, ReplicaInfo, ReplicaRole, Replicas, Secret, UserSecret,
};
use flate2::read::GzDecoder;
use serde_json::Value;

#[test]
fn recovered_secret_decodes_without_the_protocol() {
    let secret = Secret {
        helpers: vec![HelperInfo {
            channel_id: 1_000_000,
            transports: vec![derec_proto::TransportProtocol {
                uri: "https://helper-0.example.org/derec".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            shared_key: vec![0xAB; 32],
            communication_info: HashMap::from([("name".to_owned(), "Helper 0".to_owned())]),
        }],
        secrets: vec![UserSecret {
            id: vec![0xDE, 0xAD, 0xBE, 0xEF],
            name: "Gmail".to_owned(),
            data: b"correct horse battery staple".to_vec(),
        }],
        replicas: Some(Replicas {
            channel_id: 5001,
            shared_key: vec![0xCD; 32],
            members: vec![
                ReplicaInfo {
                    replica_id: 1001,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://alice.example.org/derec".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Source as i32,
                    communication_info: HashMap::new(),
                },
                ReplicaInfo {
                    replica_id: 1002,
                    transports: vec![derec_proto::TransportProtocol {
                        uri: "https://alice-2.example.org/derec".to_owned(),
                        protocol: derec_proto::Protocol::Https as i32,
                    }],
                    role: ReplicaRole::Destination as i32,
                    communication_info: HashMap::new(),
                },
            ],
        }),
    };

    // The bytes a helper stores / recovery reconstructs into secret_data.
    let encoded = secret.encode();

    // --- independent decoder: version byte → gzip → JSON → base64, no DeRec code ---
    let (&major, payload) = encoded.split_first().expect("non-empty encoding");
    assert_eq!(major, 3, "version prefix");

    let mut json = Vec::new();
    GzDecoder::new(payload)
        .read_to_end(&mut json)
        .expect("payload must be valid gzip (RFC 1952)");
    let v: Value = serde_json::from_slice(&json).expect("payload must be valid JSON");

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

    // The roster answers "who originated this secret" on its own, with no
    // separate field to consult: exactly one member carries role "Source".
    let group = &v["replicas"];
    assert_eq!(group["channel_id"], "5001");
    let members = group["members"].as_array().expect("members is an array");
    let sources: Vec<&Value> = members.iter().filter(|m| m["role"] == "Source").collect();
    assert_eq!(sources.len(), 1, "exactly one source in the roster");
    assert_eq!(sources[0]["replica_id"], "1001");
    // A roster entry carries every endpoint the member advertised, each with
    // its protocol discriminant — an independent decoder never has to infer a
    // protocol from a URI scheme.
    let endpoints = sources[0]["transports"]
        .as_array()
        .expect("transports is an array");
    assert_eq!(endpoints.len(), 1);
    assert_eq!(endpoints[0]["uri"], "https://alice.example.org/derec");
    assert_eq!(endpoints[0]["protocol"], 0, "0 is the HTTPS discriminant");
    let group_key = STANDARD
        .decode(group["shared_key"].as_str().unwrap())
        .unwrap();
    assert_eq!(group_key, vec![0xCD; 32]);
}
