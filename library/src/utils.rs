use rand::{Rng, rng};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

pub(crate) fn generate_seed<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut entropy = Zeroizing::new([0u8; N]);
    let mut rng = rng();
    rng.fill_bytes(&mut *entropy);
    entropy
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Binding check between an outer DeRec envelope timestamp and the
/// inner request/response timestamp.
///
/// # Security
///
/// Both timestamps MUST be present **and** equal. A naive
/// `Option<T> == Option<T>` comparison would accept `(None, None)`
/// as a match (because `Option::PartialEq` returns `true` for
/// `None == None`), which lets a peer strip both timestamp fields
/// and silently bypass this binding. Proto3 makes every message
/// field optional on the wire, so this is reachable for any
/// remote peer.
///
/// Treat absence as a failure here. The remaining anti-replay
/// concerns (freshness window, per-channel monotonic nonce log) are
/// the application/protocol layer's responsibility — see the
/// per-primitive `# Security: no freshness or replay protection`
/// notes on each `extract` function for the full discussion.
pub(crate) fn verify_timestamps(
    envelope_timestamp: Option<prost_types::Timestamp>,
    timestamp: Option<prost_types::Timestamp>,
) -> Result<(), crate::Error> {
    match (envelope_timestamp, timestamp) {
        (Some(envelope_ts), Some(inner_ts)) if envelope_ts == inner_ts => Ok(()),
        (None, None) => {
            #[cfg(feature = "logging")]
            tracing::warn!("timestamp invariant violated: both envelope and inner timestamp absent");

            Err(crate::Error::Invariant(
                "Envelope and request/response timestamps are both absent; absence cannot be used to satisfy the binding check",
            ))
        }
        _ => {
            #[cfg(feature = "logging")]
            tracing::warn!("timestamp invariant violated");

            Err(crate::Error::Invariant(
                "Envelope timestamp does not match request/response timestamp",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_types::Timestamp;

    fn ts(seconds: i64) -> Timestamp {
        Timestamp { seconds, nanos: 0 }
    }

    #[test]
    fn accepts_matching_some_timestamps() {
        assert!(verify_timestamps(Some(ts(1_700_000_000)), Some(ts(1_700_000_000))).is_ok());
    }

    #[test]
    fn rejects_mismatched_some_timestamps() {
        let res = verify_timestamps(Some(ts(1_700_000_000)), Some(ts(1_700_000_001)));
        match res {
            Err(crate::Error::Invariant(msg)) => assert!(msg.contains("does not match"), "msg: {msg}"),
            other => panic!("expected Invariant mismatch, got {other:?}"),
        }
    }

    /// Regression test: `(None, None)` used to compare equal via the
    /// derived `Option::PartialEq` and silently pass the binding
    /// check. After the fix the function rejects with a distinct
    /// message specifically calling out the absence case.
    #[test]
    fn rejects_both_none() {
        let res = verify_timestamps(None, None);
        match res {
            Err(crate::Error::Invariant(msg)) => {
                assert!(msg.contains("absent"), "expected absence-specific message, got: {msg}")
            }
            other => panic!("expected Invariant for (None, None), got {other:?}"),
        }
    }

    #[test]
    fn rejects_envelope_none() {
        let res = verify_timestamps(None, Some(ts(1_700_000_000)));
        assert!(matches!(res, Err(crate::Error::Invariant(_))));
    }

    #[test]
    fn rejects_inner_none() {
        let res = verify_timestamps(Some(ts(1_700_000_000)), None);
        assert!(matches!(res, Err(crate::Error::Invariant(_))));
    }
}
