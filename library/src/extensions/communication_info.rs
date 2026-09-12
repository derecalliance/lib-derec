// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// The `CommunicationInfo` ↔ `HashMap<String, String>` conversion, attached
/// to the proto type so a flow that carries communication info does not
/// restate the oneof unwrapping.
///
/// The protocol models communication info as a repeated key/value list whose
/// value is a `string`/`bytes` oneof; the core protocol models it as a plain
/// string map. Bridging the two is a property of the type, not of any one
/// flow, and it was previously written out in three places.
///
/// # Reserved keys are not this trait's business
///
/// Pairing puts the peer's `replica_id` in this same map under a reserved
/// key, and filters reserved keys out of what it hands the application. That
/// is pairing policy layered on top of this conversion, so
/// [`handlers::pairing`](crate::protocol) keeps its own pair of functions
/// rather than being expressed through these. This trait moves every entry it
/// is given, in both directions, and interprets none of them.
pub(crate) trait CommunicationInfoExt {
    /// Every string-valued entry, as a map.
    ///
    /// Entries carrying `bytes` — or no value at all — are skipped: the core
    /// protocol's map has nowhere to put them, and the alternative is failing
    /// a whole message over an entry no flow reads.
    fn to_map(&self) -> std::collections::HashMap<String, String>;

    /// The proto carrying `map` as string-valued entries.
    ///
    /// Entry order follows the map's iteration order, which is unspecified.
    /// Nothing in the protocol reads communication info positionally, so the
    /// conversion does not sort to make it deterministic.
    fn from_map(map: &std::collections::HashMap<String, String>) -> Self;
}

impl CommunicationInfoExt for derec_proto::CommunicationInfo {
    fn to_map(&self) -> std::collections::HashMap<String, String> {
        self.communication_info_entries
            .iter()
            .filter_map(|e| match &e.value {
                Some(derec_proto::communication_info_key_value::Value::StringValue(s)) => {
                    Some((e.key.to_owned(), s.to_owned()))
                }
                _ => None,
            })
            .collect()
    }

    fn from_map(map: &std::collections::HashMap<String, String>) -> Self {
        Self {
            communication_info_entries: map
                .iter()
                .map(|(k, v)| derec_proto::CommunicationInfoKeyValue {
                    key: k.to_owned(),
                    value: Some(
                        derec_proto::communication_info_key_value::Value::StringValue(v.to_owned()),
                    ),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::{CommunicationInfo, CommunicationInfoKeyValue, communication_info_key_value};
    use std::collections::HashMap;

    fn string_entry(key: &str, value: &str) -> CommunicationInfoKeyValue {
        CommunicationInfoKeyValue {
            key: key.to_owned(),
            value: Some(communication_info_key_value::Value::StringValue(
                value.to_owned(),
            )),
        }
    }

    /// The map survives a round trip through the proto unchanged. Order is
    /// unspecified in both directions, so equality is over the map.
    #[test]
    fn a_map_round_trips_through_the_proto() {
        let map = HashMap::from([
            ("nickname".to_owned(), "Alice".to_owned()),
            ("avatar".to_owned(), "https://a.example/x.png".to_owned()),
        ]);

        assert_eq!(CommunicationInfo::from_map(&map).to_map(), map);
    }

    /// A `bytes` entry has nowhere to land in a `<String, String>` map. It is
    /// skipped rather than failing the message, so an unrecognised entry
    /// cannot take down a flow that never reads it.
    #[test]
    fn a_bytes_entry_is_skipped_rather_than_refused() {
        let info = CommunicationInfo {
            communication_info_entries: vec![
                string_entry("nickname", "Alice"),
                CommunicationInfoKeyValue {
                    key: "avatar".to_owned(),
                    value: Some(communication_info_key_value::Value::BytesValue(vec![
                        0xDE, 0xAD,
                    ])),
                },
            ],
        };

        assert_eq!(
            info.to_map(),
            HashMap::from([("nickname".to_owned(), "Alice".to_owned())]),
        );
    }

    /// An entry whose oneof was never set is skipped on the same grounds.
    #[test]
    fn an_entry_with_no_value_is_skipped() {
        let info = CommunicationInfo {
            communication_info_entries: vec![CommunicationInfoKeyValue {
                key: "nickname".to_owned(),
                value: None,
            }],
        };

        assert!(info.to_map().is_empty());
    }

    /// Nothing is filtered on the way in: reserved keys are pairing's to
    /// interpret, and this conversion does not know about them.
    #[test]
    fn no_key_is_treated_as_special() {
        let map = HashMap::from([("derec.replica_id".to_owned(), "7".to_owned())]);

        assert_eq!(CommunicationInfo::from_map(&map).to_map(), map);
    }

    /// An empty map is a proto with no entries, not an absent one — whether
    /// to send `None` instead is the caller's decision.
    #[test]
    fn an_empty_map_makes_an_empty_proto() {
        assert!(
            CommunicationInfo::from_map(&HashMap::new())
                .communication_info_entries
                .is_empty()
        );
    }
}
