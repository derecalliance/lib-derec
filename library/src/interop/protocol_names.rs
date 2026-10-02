// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The enum names every binding exposes to its host.

/// Maps a transport protocol *name* to its wire discriminant.
///
/// Case-insensitive; accepts exactly `"https"` and `"grpc"` — the two
/// protocol-family names, not the four URI schemes each admits. `https://`
/// and `http://` both name `Protocol::Https`; `grpcs://` and `grpc://` both
/// name `Protocol::Grpc`.
///
/// Lives here rather than beside
/// [`crate::transport::protocol_for_scheme`](crate::transport) because names
/// only cross the binding seams (WASM and FFI): every other layer derives
/// the protocol from a URI instead of taking a bare string. Both directions
/// go through this single pair so the name/discriminant pairing cannot drift
/// between bindings.
pub(crate) fn protocol_name_to_discriminant(name: &str) -> Option<i32> {
    match name.to_lowercase().as_str() {
        "https" => Some(derec_proto::Protocol::Https.into()),
        "grpc" => Some(derec_proto::Protocol::Grpc.into()),
        _ => None,
    }
}

/// Inverse of [`protocol_name_to_discriminant`]: maps a wire discriminant
/// back to its lowercase protocol name. `None` for any discriminant outside
/// the defined `Protocol` variants.
pub(crate) fn protocol_discriminant_to_name(discriminant: i32) -> Option<&'static str> {
    match derec_proto::Protocol::try_from(discriminant).ok()? {
        derec_proto::Protocol::Https => Some("https"),
        derec_proto::Protocol::Grpc => Some("grpc"),
    }
}

/// Reads a transport `protocol` field written either as its name
/// (`"https"`, `"grpc"`) or as its wire discriminant. Names are what every
/// app-facing surface uses; the discriminant stays accepted so a binding's
/// own marshalling of a typed enum needs no name lookup. A discriminant is
/// passed through unchanged and validated where the endpoint is built.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
pub(crate) fn protocol_from_name_or_discriminant<'de, D>(de: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum NameOrDiscriminant {
        Discriminant(i32),
        Name(String),
    }
    match <NameOrDiscriminant as serde::Deserialize>::deserialize(de)? {
        NameOrDiscriminant::Discriminant(d) => Ok(d),
        NameOrDiscriminant::Name(name) => protocol_name_to_discriminant(&name).ok_or_else(|| {
            serde::de::Error::custom(format!("unknown transport protocol {name:?}"))
        }),
    }
}

/// Reads a transport `protocol` field written as its name only.
pub(crate) fn protocol_from_name<'de, D>(de: D) -> Result<i32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let name = <String as serde::Deserialize>::deserialize(de)?;
    protocol_name_to_discriminant(&name)
        .ok_or_else(|| serde::de::Error::custom(format!("unknown transport protocol {name:?}")))
}

/// Maps an unpair-ack *name* to its [`crate::protocol::UnpairAck`] variant.
///
/// Accepts exactly `"required"` and `"not_required"`, the names every binding
/// exposes, so the host passes the name through and the library decides
/// whether it is valid.
pub(crate) fn unpair_ack_from_name(name: &str) -> Option<crate::protocol::UnpairAck> {
    match name {
        "required" => Some(crate::protocol::UnpairAck::Required),
        "not_required" => Some(crate::protocol::UnpairAck::NotRequired),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Either {
        #[serde(deserialize_with = "protocol_from_name_or_discriminant")]
        protocol: i32,
    }

    #[test]
    fn a_binding_input_takes_the_name_or_the_discriminant() {
        let read = |json: &str| serde_json::from_str::<Either>(json).map(|e| e.protocol);
        assert_eq!(read(r#"{"protocol":"https"}"#).unwrap(), 0);
        assert_eq!(read(r#"{"protocol":"grpc"}"#).unwrap(), 1);
        assert_eq!(read(r#"{"protocol":1}"#).unwrap(), 1);
        assert!(read(r#"{"protocol":"ftp"}"#).is_err());
    }

    #[test]
    fn unpair_ack_names_are_exact() {
        assert_eq!(
            unpair_ack_from_name("required"),
            Some(crate::protocol::UnpairAck::Required)
        );
        assert_eq!(
            unpair_ack_from_name("not_required"),
            Some(crate::protocol::UnpairAck::NotRequired)
        );
        for alias in ["Required", "notrequired", "fire_and_forget", ""] {
            assert_eq!(unpair_ack_from_name(alias), None, "{alias:?}");
        }
    }

    #[test]
    fn every_protocol_round_trips_through_its_name() {
        for protocol in [derec_proto::Protocol::Https, derec_proto::Protocol::Grpc] {
            let name = protocol_discriminant_to_name(protocol.into()).expect("defined protocol");
            assert_eq!(protocol_name_to_discriminant(name), Some(protocol.into()));
        }
    }

    #[test]
    fn an_undefined_discriminant_has_no_name() {
        assert_eq!(protocol_discriminant_to_name(99), None);
    }
}
