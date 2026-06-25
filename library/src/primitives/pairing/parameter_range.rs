// SPDX-License-Identifier: Apache-2.0

//! Pair-time validation of the
//! [`ParameterRange`](derec_proto::ParameterRange) each side advertises.
//!
//! Two parties' ranges are compatible when, for every field pair, the
//! intervals overlap — i.e. there exists at least one value both
//! parties would accept. Concretely, for any `(min, max)` pair:
//! `local_min <= peer_max && peer_min <= local_max`.
//!
//! Either side passing `None` (no constraints declared) is always
//! compatible.

use super::error::PairingError;
use derec_proto::ParameterRange;

/// Field-by-field accessors so the overlap check stays a flat loop and
/// every field's name surfaces verbatim in [`PairingError::IncompatibleParameterRange`].
type Accessor = (&'static str, fn(&ParameterRange) -> (i64, i64));

const FIELDS: &[Accessor] = &[
    ("shareSize", |r| (r.min_share_size, r.max_share_size)),
    (
        "timeBetweenVerifications",
        |r| (r.min_time_between_verifications, r.max_time_between_verifications),
    ),
    (
        "timeBetweenShareUpdates",
        |r| (r.min_time_between_share_updates, r.max_time_between_share_updates),
    ),
    (
        "unresponsiveDeletionTimeout",
        |r| {
            (
                r.min_unresponsive_deletion_timeout,
                r.max_unresponsive_deletion_timeout,
            )
        },
    ),
    (
        "unresponsiveDeactivationTimeout",
        |r| {
            (
                r.min_unresponsive_deactivation_timeout,
                r.max_unresponsive_deactivation_timeout,
            )
        },
    ),
];

/// Returns `Ok(())` when `local` and `peer` ranges overlap on every
/// field, or the first incompatible field as a
/// [`PairingError::IncompatibleParameterRange`]. When either side
/// passes `None` the pair is unconditionally compatible.
pub fn check_compatibility(
    local: Option<&ParameterRange>,
    peer: Option<&ParameterRange>,
) -> Result<(), PairingError> {
    let (local, peer) = match (local, peer) {
        (Some(l), Some(p)) => (l, p),
        _ => return Ok(()),
    };

    for (field, get) in FIELDS {
        let (local_min, local_max) = get(local);
        let (peer_min, peer_max) = get(peer);
        if local_min > peer_max || peer_min > local_max {
            return Err(PairingError::IncompatibleParameterRange {
                field,
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
}
