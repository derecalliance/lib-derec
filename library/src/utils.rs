#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use rand::{Rng, rng};
use zeroize::Zeroizing;

pub(crate) fn generate_seed<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut entropy = Zeroizing::new([0u8; N]);
    let mut rng = rng();
    rng.fill_bytes(&mut *entropy);
    entropy
}

/// Returns the current unix timestamp in seconds.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
