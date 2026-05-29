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

pub(crate) fn verify_timestamps(
    envelope_timestamp: Option<prost_types::Timestamp>,
    timestamp: Option<prost_types::Timestamp>,
) -> Result<(), crate::Error> {
    if envelope_timestamp != timestamp {
        #[cfg(feature = "logging")]
        tracing::warn!("timestamp invariant violated");

        return Err(crate::Error::Invariant(
            "Envelope timestamp does not match request/response timestamp",
        ));
    }

    Ok(())
}
