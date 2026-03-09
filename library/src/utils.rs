use rand::{Rng, rng};
use zeroize::Zeroizing;

pub(crate) fn generate_seed<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut entropy = Zeroizing::new([0u8; N]);
    let mut rng = rng();
    rng.fill_bytes(&mut *entropy);
    entropy
}
