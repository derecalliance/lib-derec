// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Randomness sources shared by the primitives.

use ark_ff::PrimeField;
use rand::CryptoRng;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

/// The operating system's random number generator, drawn from directly.
///
/// Nothing is buffered in the process, so a forked child never repeats its
/// parent's output.
///
/// # Panics
///
/// When the operating system cannot provide randomness.
pub(crate) fn os_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// A uniformly distributed element of the field `F`.
///
/// 64 random bytes are reduced modulo the field order. Every field used here
/// is at most 377 bits wide, so the result is within 2^-135 of uniform.
pub(crate) fn field_element<F: PrimeField, R: CryptoRng + ?Sized>(rng: &mut R) -> F {
    let mut wide = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(wide.as_mut());
    F::from_le_bytes_mod_order(wide.as_ref())
}
