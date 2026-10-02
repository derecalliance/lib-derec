// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The transport protocol names every binding exposes to its host.

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

#[cfg(test)]
mod tests {
    use super::*;

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
