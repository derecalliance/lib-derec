// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! [`DeRecProtocolConfig`]: every data setting of a
//! [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder) in one
//! value an application can load from a config file or a user record.

use std::collections::HashMap;
use std::time::Duration;

use crate::protocol::types::Timeouts;
use crate::protocol::{AutoAcceptPolicy, ExpiredChannelCleanup, UnpairAck};

/// Every data setting of a [`DeRecProtocolBuilder`](crate::protocol::DeRecProtocolBuilder),
/// each one optional, applied in one call by
/// [`with_config`](crate::protocol::DeRecProtocolBuilder::with_config).
///
/// A field left `None` is not applied: the builder keeps what it already
/// holds. A field that is set is applied through the matching `with_*`
/// setter and validated by
/// [`build`](crate::protocol::DeRecProtocolBuilder::build) under exactly
/// the rules that setter documents. Stores, the delivery transport and the
/// `secret_id` are not settings and are not carried here.
///
/// Configs layer: apply a general config, then a per-user one, then any
/// individual setter, and the last write wins per field. See
/// [`with_config`](crate::protocol::DeRecProtocolBuilder::with_config).
///
/// # Canonical JSON
///
/// With the `serde` feature the struct serializes to, and deserializes from,
/// one JSON shape — the format for config files and user records, and the
/// one every SDK accepts:
///
/// ```json
/// {
///   "threshold": 3,
///   "max_subshares": "12",
///   "timeouts": {
///     "inbound_message_secs": 300,
///     "sharing_round_secs": 60,
///     "unpair_ack_secs": 60,
///     "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
///   },
///   "parameter_range": { "min_share_size": 1, "max_share_size": 4096 },
///   "auto_accept": { "pairing": true, "store_share": true },
///   "auto_respond_on_failure": false,
///   "auto_reply_to": false,
///   "unpair_ack": "required",
///   "unsafe_connection": false,
///   "communication_info": { "name": "alice" },
///   "own_transports": [{ "uri": "https://me.example.com/derec", "protocol": "https" }],
///   "replica_id": "9007199254740993"
/// }
/// ```
///
/// - Keys are `snake_case`, and every key is optional: an absent key or a
///   `null` value leaves that setting unset.
/// - **Unknown keys are rejected**, at every level, so a misspelled key fails
///   to parse instead of being ignored.
/// - `replica_id` and `max_subshares` are `u64` values written as decimal
///   strings, which survive JSON encoders whose numbers are `f64`.
/// - `threshold` is a JSON number.
/// - `timeouts` carries whole seconds; see [`TimeoutsConfig`].
/// - `parameter_range` mirrors [`derec_proto::ParameterRange`] with
///   `snake_case` names. Each bound is a JSON number or a decimal string, and
///   an absent bound is `0` ("no bound").
/// - `auto_accept` has one boolean per flow, named as on
///   [`AutoAcceptPolicy`]; an absent flow is `false`.
/// - `unpair_ack` is `"required"` or `"not_required"`, or the discriminant
///   `0` or `1`.
/// - Each `own_transports` entry is `{uri, protocol}`, where `protocol` is
///   `"https"` or `"grpc"` (any case) or its discriminant `0` or `1`.
///
/// Serializing writes only the fields that are set, names rather than
/// discriminants, and every flow of `auto_accept` and every bound of
/// `parameter_range`.
#[derive(Clone, Debug, Default, PartialEq)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "wire::ConfigWire", into = "wire::ConfigWire")
)]
pub struct DeRecProtocolConfig {
    /// See [`with_threshold`](crate::protocol::DeRecProtocolBuilder::with_threshold).
    pub threshold: Option<usize>,
    /// See [`with_max_subshares`](crate::protocol::DeRecProtocolBuilder::with_max_subshares).
    pub max_subshares: Option<u64>,
    /// See [`with_timeouts`](crate::protocol::DeRecProtocolBuilder::with_timeouts).
    /// Merged per field; see [`TimeoutsConfig`].
    pub timeouts: Option<TimeoutsConfig>,
    /// See [`with_parameter_range`](crate::protocol::DeRecProtocolBuilder::with_parameter_range).
    pub parameter_range: Option<derec_proto::ParameterRange>,
    /// See [`with_auto_accept`](crate::protocol::DeRecProtocolBuilder::with_auto_accept).
    pub auto_accept: Option<AutoAcceptPolicy>,
    /// See [`with_auto_respond_on_failure`](crate::protocol::DeRecProtocolBuilder::with_auto_respond_on_failure).
    pub auto_respond_on_failure: Option<bool>,
    /// See [`with_auto_reply_to`](crate::protocol::DeRecProtocolBuilder::with_auto_reply_to).
    pub auto_reply_to: Option<bool>,
    /// See [`with_unpair_ack`](crate::protocol::DeRecProtocolBuilder::with_unpair_ack).
    pub unpair_ack: Option<UnpairAck>,
    /// See [`with_unsafe_connection`](crate::protocol::DeRecProtocolBuilder::with_unsafe_connection).
    pub unsafe_connection: Option<bool>,
    /// See [`with_communication_info`](crate::protocol::DeRecProtocolBuilder::with_communication_info).
    pub communication_info: Option<HashMap<String, String>>,
    /// See [`with_own_transports`](crate::protocol::DeRecProtocolBuilder::with_own_transports).
    /// An unknown `protocol` discriminant is rejected when the endpoint is
    /// parsed; structural checks (URI length, control characters, scheme)
    /// run later, at `build()`.
    pub own_transports: Option<Vec<crate::transport::TransportProtocol>>,
    /// See [`with_replica_id`](crate::protocol::DeRecProtocolBuilder::with_replica_id).
    pub replica_id: Option<u64>,
}

/// The four waiting periods of [`Timeouts`], in whole seconds, each one
/// optional.
///
/// Unlike the other nested settings of [`DeRecProtocolConfig`], this one is
/// merged per field: a field left `None` keeps the value the builder already
/// holds, so one config can set the sharing round and a later one the
/// inbound-message window without either undoing the other. The merged
/// result goes through
/// [`with_timeouts`](crate::protocol::DeRecProtocolBuilder::with_timeouts),
/// which clamps every value to at least one second.
///
/// In JSON the fields are `inbound_message_secs`, `sharing_round_secs`,
/// `unpair_ack_secs` (non-negative integers) and `expired_channels`
/// (an [`ExpiredChannelsConfig`] object).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize),
    serde(default, deny_unknown_fields)
)]
pub struct TimeoutsConfig {
    /// [`Timeouts::inbound_message`], in seconds.
    #[cfg_attr(
        any(feature = "serde", target_arch = "wasm32"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub inbound_message_secs: Option<u64>,
    /// [`Timeouts::sharing_round`], in seconds.
    #[cfg_attr(
        any(feature = "serde", target_arch = "wasm32"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub sharing_round_secs: Option<u64>,
    /// [`Timeouts::unpair_ack`], in seconds.
    #[cfg_attr(
        any(feature = "serde", target_arch = "wasm32"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub unpair_ack_secs: Option<u64>,
    /// [`Timeouts::expired_channels`].
    #[cfg_attr(
        any(feature = "serde", target_arch = "wasm32"),
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub expired_channels: Option<ExpiredChannelsConfig>,
}

/// Automatic removal of expired `Pending` channels, as the flat pair the
/// config carries. Converted by [`ExpiredChannelCleanup::new`], which
/// ignores the timeout when `enabled` is `false`.
///
/// Both fields are required in JSON: `{"enabled": true, "timeout_in_secs": 300}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "serde", target_arch = "wasm32"),
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct ExpiredChannelsConfig {
    /// Whether `process()` sweeps expired `Pending` channels itself.
    pub enabled: bool,
    /// Age, in seconds, past which a `Pending` channel is removed.
    pub timeout_in_secs: u64,
}

impl TimeoutsConfig {
    /// `base` with every field this config sets replaced.
    pub(crate) fn merged_onto(&self, base: Timeouts) -> Timeouts {
        Timeouts {
            inbound_message: self
                .inbound_message_secs
                .map_or(base.inbound_message, Duration::from_secs),
            sharing_round: self
                .sharing_round_secs
                .map_or(base.sharing_round, Duration::from_secs),
            unpair_ack: self
                .unpair_ack_secs
                .map_or(base.unpair_ack, Duration::from_secs),
            expired_channels: self.expired_channels.map_or(base.expired_channels, |e| {
                ExpiredChannelCleanup::new(e.enabled, e.timeout_in_secs)
            }),
        }
    }
}

impl DeRecProtocolConfig {
    /// `top` written over `self`, field by field, as
    /// [`with_config`](crate::protocol::DeRecProtocolBuilder::with_config)
    /// applies it to a builder: a set field replaces the held one, an unset
    /// field keeps it, and `timeouts` merges per field. A binding that holds
    /// its settings as one config until `build()` layers each call onto it.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn layer(&mut self, top: Self) {
        fn over<T>(held: &mut Option<T>, set: Option<T>) {
            if set.is_some() {
                *held = set;
            }
        }
        let Self {
            threshold,
            max_subshares,
            timeouts,
            parameter_range,
            auto_accept,
            auto_respond_on_failure,
            auto_reply_to,
            unpair_ack,
            unsafe_connection,
            communication_info,
            own_transports,
            replica_id,
        } = top;
        over(&mut self.threshold, threshold);
        over(&mut self.max_subshares, max_subshares);
        if let Some(t) = timeouts {
            let TimeoutsConfig {
                inbound_message_secs,
                sharing_round_secs,
                unpair_ack_secs,
                expired_channels,
            } = t;
            let held = self.timeouts.get_or_insert_with(TimeoutsConfig::default);
            over(&mut held.inbound_message_secs, inbound_message_secs);
            over(&mut held.sharing_round_secs, sharing_round_secs);
            over(&mut held.unpair_ack_secs, unpair_ack_secs);
            over(&mut held.expired_channels, expired_channels);
        }
        over(&mut self.parameter_range, parameter_range);
        over(&mut self.auto_accept, auto_accept);
        over(&mut self.auto_respond_on_failure, auto_respond_on_failure);
        over(&mut self.auto_reply_to, auto_reply_to);
        over(&mut self.unpair_ack, unpair_ack);
        over(&mut self.unsafe_connection, unsafe_connection);
        over(&mut self.communication_info, communication_info);
        over(&mut self.own_transports, own_transports);
        over(&mut self.replica_id, replica_id);
    }
}

#[cfg(test)]
mod layer_tests {
    use std::time::Duration;

    use super::{DeRecProtocolConfig, ExpiredChannelsConfig, TimeoutsConfig};
    use crate::protocol::UnpairAck;
    use crate::protocol::types::Timeouts;

    /// Layering B over A keeps every field B leaves unset, takes every
    /// field B sets, and merges `timeouts` per field, so one held config
    /// ends where `with_config(A)` then `with_config(B)` leaves a builder.
    #[test]
    fn layering_is_last_write_wins_per_field() {
        let mut held = DeRecProtocolConfig {
            threshold: Some(3),
            replica_id: Some(7),
            auto_reply_to: Some(true),
            timeouts: Some(TimeoutsConfig {
                sharing_round_secs: Some(30),
                expired_channels: Some(ExpiredChannelsConfig {
                    enabled: false,
                    timeout_in_secs: 10,
                }),
                ..TimeoutsConfig::default()
            }),
            ..DeRecProtocolConfig::default()
        };
        held.layer(DeRecProtocolConfig {
            threshold: Some(5),
            unpair_ack: Some(UnpairAck::NotRequired),
            timeouts: Some(TimeoutsConfig {
                inbound_message_secs: Some(90),
                ..TimeoutsConfig::default()
            }),
            ..DeRecProtocolConfig::default()
        });
        assert_eq!(
            held,
            DeRecProtocolConfig {
                threshold: Some(5),
                replica_id: Some(7),
                auto_reply_to: Some(true),
                unpair_ack: Some(UnpairAck::NotRequired),
                timeouts: Some(TimeoutsConfig {
                    inbound_message_secs: Some(90),
                    sharing_round_secs: Some(30),
                    unpair_ack_secs: None,
                    expired_channels: Some(ExpiredChannelsConfig {
                        enabled: false,
                        timeout_in_secs: 10,
                    }),
                }),
                ..DeRecProtocolConfig::default()
            }
        );
        let t = held.timeouts.expect("set").merged_onto(Timeouts::default());
        assert_eq!(t.inbound_message, Duration::from_secs(90));
        assert_eq!(t.sharing_round, Duration::from_secs(30));
        assert_eq!(t.unpair_ack, Timeouts::default().unpair_ack);
    }

    /// An empty config layers to no change.
    #[test]
    fn layering_an_empty_config_changes_nothing() {
        let original = DeRecProtocolConfig {
            threshold: Some(4),
            timeouts: Some(TimeoutsConfig {
                unpair_ack_secs: Some(12),
                ..TimeoutsConfig::default()
            }),
            ..DeRecProtocolConfig::default()
        };
        let mut held = original.clone();
        held.layer(DeRecProtocolConfig::default());
        assert_eq!(held, original);
    }
}

/// The serde form of [`DeRecProtocolConfig`]: the canonical JSON, field for
/// field, converted to and from the public types.
#[cfg(any(feature = "serde", target_arch = "wasm32"))]
mod wire {
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize};

    use super::{DeRecProtocolConfig, TimeoutsConfig};
    use crate::interop::protocol_names;
    use crate::protocol::{AutoAcceptPolicy, UnpairAck};

    #[derive(Serialize, Deserialize, Default)]
    #[serde(default, deny_unknown_fields)]
    pub(super) struct ConfigWire {
        #[serde(skip_serializing_if = "Option::is_none")]
        threshold: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        max_subshares: Option<DecimalU64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeouts: Option<TimeoutsConfig>,
        #[serde(skip_serializing_if = "Option::is_none")]
        parameter_range: Option<ParameterRangeWire>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auto_accept: Option<AutoAcceptWire>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auto_respond_on_failure: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        auto_reply_to: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        unpair_ack: Option<UnpairAckWire>,
        #[serde(skip_serializing_if = "Option::is_none")]
        unsafe_connection: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        communication_info: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        own_transports: Option<Vec<OwnTransportWire>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        replica_id: Option<DecimalU64>,
    }

    /// One boolean per flow; an absent flow takes the policy default.
    #[derive(Serialize, Deserialize)]
    #[serde(default, deny_unknown_fields)]
    struct AutoAcceptWire {
        pairing: bool,
        pre_pair: bool,
        store_share: bool,
        verify_share: bool,
        discovery: bool,
        get_share: bool,
        unpair: bool,
        update_channel_info: bool,
    }

    impl Default for AutoAcceptWire {
        fn default() -> Self {
            AutoAcceptPolicy::default().into()
        }
    }

    impl From<AutoAcceptPolicy> for AutoAcceptWire {
        fn from(p: AutoAcceptPolicy) -> Self {
            Self {
                pairing: p.pairing,
                pre_pair: p.pre_pair,
                store_share: p.store_share,
                verify_share: p.verify_share,
                discovery: p.discovery,
                get_share: p.get_share,
                unpair: p.unpair,
                update_channel_info: p.update_channel_info,
            }
        }
    }

    impl From<AutoAcceptWire> for AutoAcceptPolicy {
        fn from(p: AutoAcceptWire) -> Self {
            Self {
                pairing: p.pairing,
                pre_pair: p.pre_pair,
                store_share: p.store_share,
                verify_share: p.verify_share,
                discovery: p.discovery,
                get_share: p.get_share,
                unpair: p.unpair,
                update_channel_info: p.update_channel_info,
            }
        }
    }

    /// [`derec_proto::ParameterRange`] with `snake_case` names. Every bound
    /// defaults to `0`, the proto's "no bound".
    #[derive(Serialize, Deserialize, Default)]
    #[serde(default, deny_unknown_fields)]
    struct ParameterRangeWire {
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        min_share_size: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        max_share_size: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        min_time_between_verifications: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        max_time_between_verifications: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        min_time_between_share_updates: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        max_time_between_share_updates: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        min_unresponsive_deletion_timeout: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        max_unresponsive_deletion_timeout: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        min_unresponsive_deactivation_timeout: i64,
        #[serde(deserialize_with = "i64_from_number_or_decimal")]
        max_unresponsive_deactivation_timeout: i64,
    }

    impl From<derec_proto::ParameterRange> for ParameterRangeWire {
        fn from(r: derec_proto::ParameterRange) -> Self {
            Self {
                min_share_size: r.min_share_size,
                max_share_size: r.max_share_size,
                min_time_between_verifications: r.min_time_between_verifications,
                max_time_between_verifications: r.max_time_between_verifications,
                min_time_between_share_updates: r.min_time_between_share_updates,
                max_time_between_share_updates: r.max_time_between_share_updates,
                min_unresponsive_deletion_timeout: r.min_unresponsive_deletion_timeout,
                max_unresponsive_deletion_timeout: r.max_unresponsive_deletion_timeout,
                min_unresponsive_deactivation_timeout: r.min_unresponsive_deactivation_timeout,
                max_unresponsive_deactivation_timeout: r.max_unresponsive_deactivation_timeout,
            }
        }
    }

    impl From<ParameterRangeWire> for derec_proto::ParameterRange {
        fn from(r: ParameterRangeWire) -> Self {
            Self {
                min_share_size: r.min_share_size,
                max_share_size: r.max_share_size,
                min_time_between_verifications: r.min_time_between_verifications,
                max_time_between_verifications: r.max_time_between_verifications,
                min_time_between_share_updates: r.min_time_between_share_updates,
                max_time_between_share_updates: r.max_time_between_share_updates,
                min_unresponsive_deletion_timeout: r.min_unresponsive_deletion_timeout,
                max_unresponsive_deletion_timeout: r.max_unresponsive_deletion_timeout,
                min_unresponsive_deactivation_timeout: r.min_unresponsive_deactivation_timeout,
                max_unresponsive_deactivation_timeout: r.max_unresponsive_deactivation_timeout,
            }
        }
    }

    /// Reads an `i64` written either as a JSON number or as a decimal string.
    /// The string form carries the full `i64` range through JSON encoders
    /// whose numbers are `f64`.
    fn i64_from_number_or_decimal<'de, D>(de: D) -> Result<i64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum NumberOrDecimal {
            Number(i64),
            Decimal(String),
        }
        match NumberOrDecimal::deserialize(de)? {
            NumberOrDecimal::Number(n) => Ok(n),
            NumberOrDecimal::Decimal(s) => s
                .parse()
                .map_err(|_| serde::de::Error::custom(format!("{s:?} is not a decimal i64"))),
        }
    }

    /// `unpair_ack`: its discriminant or its name.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum UnpairAckWire {
        Code(i32),
        Name(String),
    }

    impl UnpairAckWire {
        fn resolve(self) -> Result<UnpairAck, String> {
            match self {
                Self::Code(0) => Ok(UnpairAck::Required),
                Self::Code(1) => Ok(UnpairAck::NotRequired),
                Self::Code(code) => Err(format!("invalid unpair_ack: {code}")),
                Self::Name(name) => protocol_names::unpair_ack_from_name(&name)
                    .ok_or_else(|| format!("invalid unpair_ack: {name:?}")),
            }
        }
    }

    /// One `own_transports` entry. `protocol` is read as a name or a
    /// discriminant and written as a name.
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OwnTransportWire {
        uri: String,
        #[serde(
            deserialize_with = "protocol_names::protocol_from_name_or_discriminant",
            serialize_with = "protocol_as_name"
        )]
        protocol: i32,
    }

    fn protocol_as_name<S: serde::Serializer>(
        discriminant: &i32,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match protocol_names::protocol_discriminant_to_name(*discriminant) {
            Some(name) => ser.serialize_str(name),
            None => ser.serialize_i32(*discriminant),
        }
    }

    /// A `u64` field: a decimal string. Any other JSON value is kept only
    /// so the error can name the field it was found in.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum DecimalU64 {
        Decimal(String),
        #[serde(skip_serializing)]
        NotAString(serde::de::IgnoredAny),
    }

    fn decimal_u64(field: &str, value: Option<DecimalU64>) -> Result<Option<u64>, String> {
        value
            .map(|v| match v {
                DecimalU64::Decimal(s) => s
                    .parse()
                    .map_err(|_| format!("{field} is not a decimal u64: {s:?}")),
                DecimalU64::NotAString(_) => {
                    Err(format!("{field} must be a u64 written as a decimal string"))
                }
            })
            .transpose()
    }

    impl TryFrom<ConfigWire> for DeRecProtocolConfig {
        type Error = String;

        fn try_from(w: ConfigWire) -> Result<Self, Self::Error> {
            let own_transports = w
                .own_transports
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| {
                            let protocol =
                                derec_proto::Protocol::try_from(e.protocol).map_err(|_| {
                                    format!(
                                        "unknown transport protocol discriminant {}",
                                        e.protocol
                                    )
                                })?;
                            Ok(crate::transport::TransportProtocol::new(e.uri, protocol))
                        })
                        .collect::<Result<Vec<_>, String>>()
                })
                .transpose()?;
            Ok(Self {
                threshold: w.threshold,
                max_subshares: decimal_u64("max_subshares", w.max_subshares)?,
                timeouts: w.timeouts,
                parameter_range: w.parameter_range.map(Into::into),
                auto_accept: w.auto_accept.map(Into::into),
                auto_respond_on_failure: w.auto_respond_on_failure,
                auto_reply_to: w.auto_reply_to,
                unpair_ack: w.unpair_ack.map(UnpairAckWire::resolve).transpose()?,
                unsafe_connection: w.unsafe_connection,
                communication_info: w.communication_info,
                own_transports,
                replica_id: decimal_u64("replica_id", w.replica_id)?,
            })
        }
    }

    impl From<DeRecProtocolConfig> for ConfigWire {
        fn from(c: DeRecProtocolConfig) -> Self {
            Self {
                threshold: c.threshold,
                max_subshares: c.max_subshares.map(|v| DecimalU64::Decimal(v.to_string())),
                timeouts: c.timeouts,
                parameter_range: c.parameter_range.map(Into::into),
                auto_accept: c.auto_accept.map(Into::into),
                auto_respond_on_failure: c.auto_respond_on_failure,
                auto_reply_to: c.auto_reply_to,
                unpair_ack: c.unpair_ack.map(|ack| {
                    UnpairAckWire::Name(protocol_names::unpair_ack_to_name(ack).to_owned())
                }),
                unsafe_connection: c.unsafe_connection,
                communication_info: c.communication_info,
                own_transports: c.own_transports.map(|entries| {
                    entries
                        .into_iter()
                        .map(|t| OwnTransportWire {
                            uri: t.uri,
                            protocol: t.protocol.into(),
                        })
                        .collect()
                }),
                replica_id: c.replica_id.map(|v| DecimalU64::Decimal(v.to_string())),
            }
        }
    }
}

#[cfg(all(test, any(feature = "serde", target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::protocol::{AutoAcceptPolicy, UnpairAck};
    use derec_proto::Protocol;

    const CANONICAL: &str = r#"{
        "threshold": 4,
        "max_subshares": "18446744073709551615",
        "timeouts": {
            "inbound_message_secs": 120,
            "sharing_round_secs": 30,
            "unpair_ack_secs": 45,
            "expired_channels": { "enabled": false, "timeout_in_secs": 600 }
        },
        "parameter_range": {
            "min_share_size": 1,
            "max_share_size": 4096,
            "min_time_between_verifications": 60,
            "max_time_between_verifications": 0,
            "min_time_between_share_updates": 0,
            "max_time_between_share_updates": 0,
            "min_unresponsive_deletion_timeout": 0,
            "max_unresponsive_deletion_timeout": 0,
            "min_unresponsive_deactivation_timeout": 0,
            "max_unresponsive_deactivation_timeout": 0
        },
        "auto_accept": {
            "pairing": true,
            "pre_pair": false,
            "store_share": true,
            "verify_share": false,
            "discovery": false,
            "get_share": false,
            "unpair": false,
            "update_channel_info": false
        },
        "auto_respond_on_failure": true,
        "auto_reply_to": true,
        "unpair_ack": "not_required",
        "unsafe_connection": true,
        "communication_info": { "name": "alice" },
        "own_transports": [
            { "uri": "grpcs://me.example.com:443", "protocol": "grpc" },
            { "uri": "https://me.example.com/derec", "protocol": "https" }
        ],
        "replica_id": "9007199254740993"
    }"#;

    fn parse(json: &str) -> Result<DeRecProtocolConfig, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn error_of(json: &str) -> String {
        parse(json).expect_err("must be rejected").to_string()
    }

    #[test]
    fn canonical_json_deserializes_into_every_field() {
        let c = parse(CANONICAL).expect("canonical config parses");
        assert_eq!(c.threshold, Some(4));
        assert_eq!(c.max_subshares, Some(u64::MAX));
        assert_eq!(
            c.timeouts,
            Some(TimeoutsConfig {
                inbound_message_secs: Some(120),
                sharing_round_secs: Some(30),
                unpair_ack_secs: Some(45),
                expired_channels: Some(ExpiredChannelsConfig {
                    enabled: false,
                    timeout_in_secs: 600,
                }),
            })
        );
        let range = c.parameter_range.expect("range present");
        assert_eq!(range.min_share_size, 1);
        assert_eq!(range.max_share_size, 4096);
        assert_eq!(range.min_time_between_verifications, 60);
        assert_eq!(
            c.auto_accept,
            Some(AutoAcceptPolicy {
                pairing: true,
                store_share: true,
                ..Default::default()
            })
        );
        assert_eq!(c.auto_respond_on_failure, Some(true));
        assert_eq!(c.auto_reply_to, Some(true));
        assert_eq!(c.unpair_ack, Some(UnpairAck::NotRequired));
        assert_eq!(c.unsafe_connection, Some(true));
        assert_eq!(
            c.communication_info
                .as_ref()
                .and_then(|m| m.get("name"))
                .map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            c.own_transports,
            Some(vec![
                crate::transport::TransportProtocol::new(
                    "grpcs://me.example.com:443",
                    Protocol::Grpc
                ),
                crate::transport::TransportProtocol::new(
                    "https://me.example.com/derec",
                    Protocol::Https
                ),
            ])
        );
        assert_eq!(c.replica_id, Some(9_007_199_254_740_993));
    }

    #[test]
    fn canonical_json_round_trips() {
        let c = parse(CANONICAL).expect("canonical config parses");
        let written = serde_json::to_value(&c).expect("serializes");
        let original: serde_json::Value = serde_json::from_str(CANONICAL).unwrap();
        assert_eq!(written, original);
        assert_eq!(parse(&written.to_string()).expect("re-parses"), c);
    }

    #[test]
    fn empty_object_is_the_default_and_serializes_back_to_empty() {
        let c = parse("{}").expect("empty config parses");
        assert_eq!(c, DeRecProtocolConfig::default());
        assert_eq!(serde_json::to_string(&c).unwrap(), "{}");
    }

    /// `null` reads as "not set", as the FFI config has always accepted.
    #[test]
    fn null_fields_read_as_unset() {
        let c = parse(r#"{ "replica_id": null, "max_subshares": null, "timeouts": null }"#)
            .expect("nulls parse");
        assert_eq!(c, DeRecProtocolConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected_at_every_level() {
        assert!(error_of(r#"{ "treshold": 3 }"#).contains("treshold"));
        assert!(error_of(r#"{ "secret_id": "1" }"#).contains("secret_id"));
        assert!(error_of(r#"{ "timeouts": { "sharing_round": 30 } }"#).contains("sharing_round"));
        assert!(
            error_of(r#"{ "timeouts": { "expired_channels": { "enabled": true, "timeout_in_secs": 1, "x": 1 } } }"#)
                .contains('x')
        );
        assert!(error_of(r#"{ "auto_accept": { "pair": true } }"#).contains("pair"));
        assert!(error_of(r#"{ "parameter_range": { "min_size": 1 } }"#).contains("min_size"));
        assert!(
            error_of(r#"{ "own_transports": [{ "uri": "https://a.example", "protocol": "https", "port": 1 }] }"#)
                .contains("port")
        );
    }

    /// `u64` values travel as decimal strings so they survive encoders whose
    /// numbers are `f64`; a bare JSON number or a non-decimal is refused.
    #[test]
    fn u64_fields_are_decimal_strings() {
        let c = parse(r#"{ "replica_id": "18446744073709551615", "max_subshares": "7" }"#)
            .expect("decimal strings parse");
        assert_eq!(c.replica_id, Some(u64::MAX));
        assert_eq!(c.max_subshares, Some(7));
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            serde_json::json!({ "replica_id": "18446744073709551615", "max_subshares": "7" })
        );

        assert!(error_of(r#"{ "replica_id": 5 }"#).contains("replica_id"));
        assert!(error_of(r#"{ "replica_id": "12x" }"#).contains("replica_id"));
        assert!(error_of(r#"{ "max_subshares": "-1" }"#).contains("max_subshares"));
    }

    #[test]
    fn unpair_ack_takes_its_name_or_discriminant() {
        let read = |v: &str| parse(&format!(r#"{{ "unpair_ack": {v} }}"#)).map(|c| c.unpair_ack);
        assert_eq!(read("0").unwrap(), Some(UnpairAck::Required));
        assert_eq!(read("1").unwrap(), Some(UnpairAck::NotRequired));
        assert_eq!(read(r#""required""#).unwrap(), Some(UnpairAck::Required));
        assert_eq!(
            read(r#""not_required""#).unwrap(),
            Some(UnpairAck::NotRequired)
        );
        for bad in ["2", "-1", r#""Required""#, r#""notrequired""#] {
            assert!(read(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn own_transport_protocol_takes_its_name_or_discriminant() {
        let c = parse(
            r#"{ "own_transports": [
                { "uri": "https://a.example", "protocol": 0 },
                { "uri": "grpcs://a.example:443", "protocol": "GRPC" }
            ] }"#,
        )
        .expect("both spellings parse");
        let transports = c.own_transports.expect("present");
        assert_eq!(transports[0].protocol, Protocol::Https);
        assert_eq!(transports[1].protocol, Protocol::Grpc);
        assert!(
            parse(r#"{ "own_transports": [{ "uri": "https://a.example", "protocol": "ftp" }] }"#)
                .is_err()
        );
        assert!(
            parse(r#"{ "own_transports": [{ "uri": "https://a.example", "protocol": 99 }] }"#)
                .is_err()
        );
    }

    /// A partial `auto_accept` object leaves each unnamed flow at the policy
    /// default; the object as a whole replaces the builder's policy.
    #[test]
    fn partial_auto_accept_defaults_each_absent_flow() {
        let c = parse(r#"{ "auto_accept": { "pairing": true } }"#).expect("parses");
        assert_eq!(
            c.auto_accept,
            Some(AutoAcceptPolicy {
                pairing: true,
                ..Default::default()
            })
        );
    }

    /// Parameter-range bounds accept JSON numbers or decimal strings, and an
    /// absent bound is `0`.
    #[test]
    fn parameter_range_bounds_take_numbers_or_decimal_strings() {
        let c = parse(
            r#"{ "parameter_range": {
                "min_share_size": "9007199254740993",
                "max_share_size": 4096,
                "max_unresponsive_deactivation_timeout": "-9223372036854775808"
            } }"#,
        )
        .expect("parses");
        let range = c.parameter_range.expect("present");
        assert_eq!(range.min_share_size, 9_007_199_254_740_993);
        assert_eq!(range.max_share_size, 4096);
        assert_eq!(range.max_unresponsive_deactivation_timeout, i64::MIN);
        assert_eq!(range.min_time_between_verifications, 0);
        assert!(parse(r#"{ "parameter_range": { "min_share_size": "12x" } }"#).is_err());
    }

    /// Timeouts must be whole, non-negative seconds.
    #[test]
    fn timeouts_refuse_fractional_or_negative_seconds() {
        assert!(parse(r#"{ "timeouts": { "sharing_round_secs": 1.5 } }"#).is_err());
        assert!(parse(r#"{ "timeouts": { "sharing_round_secs": -1 } }"#).is_err());
    }

    /// The JSON `derec_protocol_new` has always documented, minus
    /// `secret_id`, is a valid config.
    #[test]
    fn the_documented_ffi_config_shape_is_accepted() {
        let c = parse(
            r#"{
                "own_transports": [{ "uri": "https://example.com/derec", "protocol": "https" }],
                "threshold": 3,
                "auto_respond_on_failure": false,
                "unpair_ack": 0,
                "auto_reply_to": false,
                "auto_accept": {
                    "pairing": false, "pre_pair": false, "store_share": false,
                    "verify_share": false, "discovery": false, "get_share": false,
                    "unpair": false, "update_channel_info": false
                },
                "timeouts": {
                    "inbound_message_secs": 300,
                    "sharing_round_secs": 60,
                    "unpair_ack_secs": 60,
                    "expired_channels": { "enabled": true, "timeout_in_secs": 300 }
                },
                "unsafe_connection": false,
                "replica_id": null,
                "parameter_range": {
                    "min_share_size": 0, "max_share_size": 0,
                    "min_time_between_verifications": 0, "max_time_between_verifications": 0,
                    "min_time_between_share_updates": 0, "max_time_between_share_updates": 0,
                    "min_unresponsive_deletion_timeout": 0, "max_unresponsive_deletion_timeout": 0,
                    "min_unresponsive_deactivation_timeout": 0,
                    "max_unresponsive_deactivation_timeout": 0
                },
                "max_subshares": null
            }"#,
        )
        .expect("documented shape parses");
        assert_eq!(c.threshold, Some(3));
        assert_eq!(c.unpair_ack, Some(UnpairAck::Required));
        assert_eq!(c.replica_id, None);
        assert_eq!(c.max_subshares, None);
    }
}
