// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Pair-time validation of the [`derec_proto::ParameterRange`] each
//! side advertises.
//!
//! A value of `0` means "no bound": `min = 0` is no minimum and `max = 0`
//! is no maximum. A range is well-formed when, for every field, `min` and
//! `max` are `>= 0` and, when `max != 0`, `min <= max`.
//!
//! Two parties' ranges are compatible when both are well-formed and, for
//! every field pair, the intervals overlap — i.e. there exists at least one
//! value both parties would accept. Concretely, for any `(min, max)` pair,
//! with a `max` of `0` read as unbounded:
//! `local_min <= peer_max && peer_min <= local_max`.
//!
//! Either side passing `None` (no constraints declared) is always
//! compatible.

use super::error::PairingError;
use derec_proto::ParameterRange;

/// One `ParameterRange` field: its protocol name, a `(min, max)` accessor,
/// and the [`crate::Error::InvalidInput`] messages [`validate`] reports for it.
struct Field {
    name: &'static str,
    get: fn(&ParameterRange) -> (i64, i64),
    negative: &'static str,
    inverted: &'static str,
}

impl Field {
    /// The [`crate::Error::InvalidInput`] message for this field of `range`
    /// when it is malformed, or `None` when it is well-formed.
    fn malformed(&self, range: &ParameterRange) -> Option<&'static str> {
        let (min, max) = (self.get)(range);
        if min < 0 || max < 0 {
            Some(self.negative)
        } else if max != 0 && min > max {
            Some(self.inverted)
        } else {
            None
        }
    }
}

/// The upper bound `max` stands for: `0` is unbounded.
fn upper_bound(max: i64) -> i64 {
    if max == 0 { i64::MAX } else { max }
}

macro_rules! field {
    ($name:literal, $min:ident, $max:ident) => {
        Field {
            name: $name,
            get: |r| (r.$min, r.$max),
            negative: concat!(
                "parameter range ",
                $name,
                ": min and max must not be negative"
            ),
            inverted: concat!(
                "parameter range ",
                $name,
                ": min must not exceed max (a max of 0 means no upper bound)"
            ),
        }
    };
}

/// Every `ParameterRange` field, so each check stays a flat loop and every
/// field's name surfaces verbatim in its error.
const FIELDS: &[Field] = &[
    field!("shareSize", min_share_size, max_share_size),
    field!(
        "timeBetweenVerifications",
        min_time_between_verifications,
        max_time_between_verifications
    ),
    field!(
        "timeBetweenShareUpdates",
        min_time_between_share_updates,
        max_time_between_share_updates
    ),
    field!(
        "unresponsiveDeletionTimeout",
        min_unresponsive_deletion_timeout,
        max_unresponsive_deletion_timeout
    ),
    field!(
        "unresponsiveDeactivationTimeout",
        min_unresponsive_deactivation_timeout,
        max_unresponsive_deactivation_timeout
    ),
];

/// Checks that `range` is a well-formed local configuration.
///
/// A value of `0` means "no bound". For every field, `min` and `max` must be
/// `>= 0`, and when `max != 0`, `min <= max`. Returns the first offending
/// field as a [`crate::Error::InvalidInput`] naming it.
pub(crate) fn validate(range: &ParameterRange) -> Result<(), crate::Error> {
    for field in FIELDS {
        if let Some(message) = field.malformed(range) {
            return Err(crate::Error::InvalidInput(message));
        }
    }
    Ok(())
}

/// Returns `Ok(())` when `local` and `peer` ranges are well-formed and
/// overlap on every field, or the first failing field as a
/// [`PairingError::IncompatibleParameterRange`] carrying both sides' raw
/// values for it. When either side passes `None` the pair is
/// unconditionally compatible.
///
/// A value of `0` means "no bound": a `max` of `0` overlaps any `min` on
/// the other side. A field that is negative, or whose `min` exceeds a
/// non-zero `max`, fails on either side, under the same rule as
/// [`validate`].
///
/// Crate-private by design: compatibility is a protocol rule, so the
/// pairing primitives that receive a peer's range run it themselves
/// ([`super::request::extract`], [`super::response::produce`] and
/// [`super::response::process`]) and no binding can skip it.
pub(crate) fn check_compatibility(
    local: Option<&ParameterRange>,
    peer: Option<&ParameterRange>,
) -> Result<(), PairingError> {
    let (local, peer) = match (local, peer) {
        (Some(l), Some(p)) => (l, p),
        _ => return Ok(()),
    };

    for field in FIELDS {
        let (local_min, local_max) = (field.get)(local);
        let (peer_min, peer_max) = (field.get)(peer);
        let malformed = field.malformed(local).is_some() || field.malformed(peer).is_some();
        if malformed || local_min > upper_bound(peer_max) || peer_min > upper_bound(local_max) {
            return Err(PairingError::IncompatibleParameterRange {
                field: field.name,
                local_min,
                local_max,
                peer_min,
                peer_max,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(min: i64, max: i64) -> ParameterRange {
        ParameterRange {
            min_share_size: min,
            max_share_size: max,
            min_time_between_verifications: 0,
            max_time_between_verifications: i64::MAX,
            min_time_between_share_updates: 0,
            max_time_between_share_updates: i64::MAX,
            min_unresponsive_deletion_timeout: 0,
            max_unresponsive_deletion_timeout: i64::MAX,
            min_unresponsive_deactivation_timeout: 0,
            max_unresponsive_deactivation_timeout: i64::MAX,
        }
    }

    #[test]
    fn both_none_is_compatible() {
        assert!(check_compatibility(None, None).is_ok());
    }

    #[test]
    fn one_side_none_is_compatible() {
        let r = range(1, 100);
        assert!(check_compatibility(Some(&r), None).is_ok());
        assert!(check_compatibility(None, Some(&r)).is_ok());
    }

    #[test]
    fn overlapping_ranges_accept() {
        // local [1, 5GB] ∩ peer [500MB, 2GB] = [1GB, 2GB] — both can pick 1.5GB.
        let local = range(1_000_000_000, 5_000_000_000);
        let peer = range(500_000_000, 2_000_000_000);
        assert!(check_compatibility(Some(&local), Some(&peer)).is_ok());
    }

    #[test]
    fn disjoint_ranges_reject_with_field_name() {
        // local [1GB, 5GB], peer [10MB, 500MB] — owner.min > helper.max.
        let local = range(1_000_000_000, 5_000_000_000);
        let peer = range(10_000_000, 500_000_000);
        let err = check_compatibility(Some(&local), Some(&peer)).unwrap_err();
        match err {
            PairingError::IncompatibleParameterRange {
                field,
                local_min,
                peer_max,
                ..
            } => {
                assert_eq!(field, "shareSize");
                assert_eq!(local_min, 1_000_000_000);
                assert_eq!(peer_max, 500_000_000);
            }
            other => panic!("expected IncompatibleParameterRange, got {other:?}"),
        }
    }

    #[test]
    fn first_failing_field_wins() {
        // shareSize compatible, but verifications interval disjoint.
        let mut local = range(0, i64::MAX);
        local.min_time_between_verifications = 60;
        local.max_time_between_verifications = 600;
        let mut peer = range(0, i64::MAX);
        peer.min_time_between_verifications = 1000;
        peer.max_time_between_verifications = 2000;
        let err = check_compatibility(Some(&local), Some(&peer)).unwrap_err();
        match err {
            PairingError::IncompatibleParameterRange { field, .. } => {
                assert_eq!(field, "timeBetweenVerifications");
            }
            other => panic!("expected IncompatibleParameterRange, got {other:?}"),
        }
    }

    /// Sets one field's `(min, max)` by its protocol name, every other field
    /// left at `0` (no bound).
    fn with_field(name: &str, min: i64, max: i64) -> ParameterRange {
        let mut r = ParameterRange::default();
        let (lo, hi) = match name {
            "shareSize" => (&mut r.min_share_size, &mut r.max_share_size),
            "timeBetweenVerifications" => (
                &mut r.min_time_between_verifications,
                &mut r.max_time_between_verifications,
            ),
            "timeBetweenShareUpdates" => (
                &mut r.min_time_between_share_updates,
                &mut r.max_time_between_share_updates,
            ),
            "unresponsiveDeletionTimeout" => (
                &mut r.min_unresponsive_deletion_timeout,
                &mut r.max_unresponsive_deletion_timeout,
            ),
            "unresponsiveDeactivationTimeout" => (
                &mut r.min_unresponsive_deactivation_timeout,
                &mut r.max_unresponsive_deactivation_timeout,
            ),
            other => panic!("unknown field {other}"),
        };
        *lo = min;
        *hi = max;
        r
    }

    fn invalid_input_message(range: &ParameterRange) -> &'static str {
        match validate(range) {
            Err(crate::Error::InvalidInput(msg)) => msg,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_valid_range() {
        assert!(validate(&range(1_000, 5_000)).is_ok());
    }

    #[test]
    fn validate_accepts_all_zero_range() {
        assert!(validate(&ParameterRange::default()).is_ok());
    }

    #[test]
    fn validate_accepts_zero_max_as_no_upper_bound() {
        for field in FIELDS {
            assert!(
                validate(&with_field(field.name, 1_000, 0)).is_ok(),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn validate_accepts_equal_min_and_max() {
        for field in FIELDS {
            assert!(
                validate(&with_field(field.name, 7, 7)).is_ok(),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn validate_rejects_negative_min_naming_field() {
        for field in FIELDS {
            let msg = invalid_input_message(&with_field(field.name, -1, 10));
            assert!(msg.contains(field.name), "{msg}");
            assert!(msg.contains("negative"), "{msg}");
        }
    }

    #[test]
    fn validate_rejects_negative_max_naming_field() {
        for field in FIELDS {
            let msg = invalid_input_message(&with_field(field.name, 0, -1));
            assert!(msg.contains(field.name), "{msg}");
            assert!(msg.contains("negative"), "{msg}");
        }
    }

    #[test]
    fn validate_rejects_min_above_nonzero_max_naming_field() {
        for field in FIELDS {
            let msg = invalid_input_message(&with_field(field.name, 11, 10));
            assert!(msg.contains(field.name), "{msg}");
            assert!(msg.contains("min must not exceed max"), "{msg}");
        }
    }

    /// The field and raw `(local_min, local_max, peer_min, peer_max)` of an
    /// [`PairingError::IncompatibleParameterRange`].
    fn incompatible(
        local: &ParameterRange,
        peer: &ParameterRange,
    ) -> (&'static str, i64, i64, i64, i64) {
        match check_compatibility(Some(local), Some(peer)) {
            Err(PairingError::IncompatibleParameterRange {
                field,
                local_min,
                local_max,
                peer_min,
                peer_max,
            }) => (field, local_min, local_max, peer_min, peer_max),
            other => panic!("expected IncompatibleParameterRange, got {other:?}"),
        }
    }

    #[test]
    fn peer_zero_max_is_compatible_with_any_local_min() {
        for field in FIELDS {
            let peer = with_field(field.name, 10, 0);
            for local_min in [0, 10, 1_000_000_000, i64::MAX] {
                for local in [
                    with_field(field.name, local_min, 0),
                    with_field(field.name, local_min, local_min),
                ] {
                    assert!(
                        check_compatibility(Some(&local), Some(&peer)).is_ok(),
                        "{} local_min={local_min}",
                        field.name
                    );
                }
            }
        }
    }

    #[test]
    fn both_zero_max_is_compatible() {
        for field in FIELDS {
            let local = with_field(field.name, 1_000, 0);
            let peer = with_field(field.name, 5, 0);
            assert!(
                check_compatibility(Some(&local), Some(&peer)).is_ok(),
                "{}",
                field.name
            );
            assert!(
                check_compatibility(Some(&peer), Some(&local)).is_ok(),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn non_overlap_against_a_zero_max_still_rejects() {
        for field in FIELDS {
            let local = with_field(field.name, 100, 0);
            let peer = with_field(field.name, 10, 50);
            assert_eq!(
                incompatible(&local, &peer),
                (field.name, 100, 0, 10, 50),
                "{}",
                field.name
            );
            assert_eq!(
                incompatible(&peer, &local),
                (field.name, 10, 50, 100, 0),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn malformed_peer_range_rejects_naming_field() {
        let local = ParameterRange::default();
        for field in FIELDS {
            for (min, max) in [(-1, 10), (0, -1), (11, 10)] {
                let peer = with_field(field.name, min, max);
                assert_eq!(
                    incompatible(&local, &peer),
                    (field.name, 0, 0, min, max),
                    "{} peer=[{min}, {max}]",
                    field.name
                );
            }
        }
    }

    #[test]
    fn malformed_local_range_rejects_naming_field() {
        let peer = ParameterRange::default();
        for field in FIELDS {
            let local = with_field(field.name, 11, 10);
            assert_eq!(
                incompatible(&local, &peer),
                (field.name, 11, 10, 0, 0),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn well_formed_ranges_are_unaffected() {
        let unbounded = ParameterRange::default();
        assert!(check_compatibility(Some(&unbounded), Some(&unbounded)).is_ok());
        for field in FIELDS {
            let local = with_field(field.name, 7, 7);
            let peer = with_field(field.name, 0, 7);
            assert!(
                check_compatibility(Some(&local), Some(&peer)).is_ok(),
                "{}",
                field.name
            );
            let peer = with_field(field.name, 0, 6);
            assert_eq!(
                incompatible(&local, &peer),
                (field.name, 7, 7, 0, 6),
                "{}",
                field.name
            );
        }
    }

    #[test]
    fn validate_checks_all_five_fields() {
        let names: Vec<&str> = FIELDS.iter().map(|f| f.name).collect();
        assert_eq!(
            names,
            [
                "shareSize",
                "timeBetweenVerifications",
                "timeBetweenShareUpdates",
                "unresponsiveDeletionTimeout",
                "unresponsiveDeactivationTimeout",
            ]
        );
    }
}
