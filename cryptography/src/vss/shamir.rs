// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! # Shamir Secret Sharing Implementation
//!
//! This module provides an implementation of Shamir's Secret Sharing scheme for 256-bit secret.
//! The intended purpose is to secret-share an AES key, which can be used to protect larger secrets.
//!
//! ## Overview
//!
//! Shamir's Secret Sharing allows a secret to be split into `n` shares such that any `t` out of `n`
//! shares can reconstruct the secret, but fewer than `t` shares reveal nothing about the secret.
//!
//! The implementation uses the scalar field of the `ark_bw6_761` curve, which is large enough for 256-bit secret.
//!
//! ## Public Functions
//!
//! - [`share`] - Splits a secret into `n` shares with a reconstruction threshold of `t`.
//! - [`recover`] - Recovers the original secret from a set of valid Shamir shares using Lagrange interpolation.
//!
//! ## Details
//!
//! - Each share is a tuple `(x, y)` where `x` is a random field element and `y` is the evaluation of a random
//!   degree `t-1` polynomial (with the secret as the constant term) at `x`.
//! - Serialization and deserialization of field elements is handled using compressed representations.
//! - The secret is encoded as the constant term of the polynomial and is recovered by interpolating at `x = 0`.
//!

//! Implements functions for Shamir secret sharing, as adapted
//! from the definition in Fig 7 of <https://eprint.iacr.org/2020/800.pdf>.

use ark_ff::{BigInteger, PrimeField, Zero};
use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use rand::Rng;

use super::*;

// we use the scalar field of the ark_bw6_761 curve so it is large enough for 256-bit secrets
use ark_bw6_761::Fr as F;

/// Splits a 256-bit secret into Shamir shares with a specified threshold and total number of shares.
///
/// # Arguments
///
/// * `secret` - A reference to a byte array of length `λ` representing the secret to be shared.
/// * `access` - A tuple `(t, n)` where:
///     - `t` is the reconstruction threshold (minimum number of shares required to recover the secret),
///     - `n` is the total number of shares to generate.
/// * `rng` - A mutable reference to a random number generator implementing the `Rng` trait.
///
/// # Returns
///
/// A vector of `(Vec<u8>, Vec<u8>)` tuples, where each tuple represents a Shamir share:
/// - The first element is the serialized x-coordinate (as a field element).
/// - The second element is the serialized y-coordinate (as a field element).
///
pub fn share<R: Rng>(
    secret: &[u8; λ],
    threshold: u64,
    total_shares: u64,
    rng: &mut R,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let rng_cell = std::cell::RefCell::new(rng);

    let sample_coeff = || F::rand(&mut *rng_cell.borrow_mut());
    let sample_x = || F::rand(&mut *rng_cell.borrow_mut());

    share_with_samplers(secret, threshold, total_shares, sample_coeff, sample_x)
}

/// Recovers the 256-bit secret from a set of Shamir shares.
///
/// # Arguments
///
/// * `shares` - A vector of tuples, where each tuple contains two byte vectors:
///   - The first element is the serialized x-coordinate of the share (as a field element).
///   - The second element is the serialized y-coordinate of the share (as a field element).
///
/// # Returns
///
/// * `[u8; λ]` - The recovered secret as a byte array of length λ.
///
pub fn recover(shares: Vec<(Vec<u8>, Vec<u8>)>) -> [u8; λ] {
    // let us parse all Shamir shares as field elements
    let xs: Vec<F> = shares
        .iter()
        .map(|(x, _)| F::deserialize_compressed(&x[..]).unwrap())
        .collect();

    let ys: Vec<F> = shares
        .iter()
        .map(|(_, y)| F::deserialize_compressed(&y[..]).unwrap())
        .collect();

    // compute lagrange coefficients w.r.t. x = 0.
    // we choose x = 0 because we encoded our secret at f(0)
    let lagrange_coeffs = lagrange_coefficients(&xs[..], F::from(0));

    //secret f(0) as a field element
    let secret = ys
        .iter()
        .zip(lagrange_coeffs.iter())
        .fold(F::from(0), |acc, (a, b)| acc + (a * b));

    // serialize secret into big-endian representation
    let secret_bytes = secret.into_bigint().to_bytes_be();

    // our 256 bit key should be in the below slice
    let start = secret_bytes.len() - λ;
    secret_bytes[start..start + λ].try_into().unwrap()
}

// Naive lagrange interpolation over the input x-coordinates.
// This method computes the lagrange coefficients, which should
// be used to compute an inner product with the y-coordinates.
// reference: https://en.wikipedia.org/wiki/Lagrange_polynomial
fn lagrange_coefficients(xs: &[F], x: F) -> Vec<F> {
    let mut output = Vec::new();

    for (i, &x_i) in xs.iter().enumerate() {
        let mut l_i = F::from(1);
        for (j, &x_j) in xs.iter().enumerate() {
            if i != j {
                l_i *= (x - x_j) / (x_i - x_j);
            }
        }
        output.push(l_i);
    }
    output
}

// Encodes a byte array as bit array, in a Big endian encoding.
// We iterate over each byte in the order of its index in the input x,
// and for each byte we write the bits in order from LSB to MSB.
fn bytes_to_bits_be(x: &[u8]) -> Vec<bool> {
    // convert byte array to bit array for BigInt conversion
    let mut output: Vec<bool> = Vec::new();

    for &byte in x {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) == 1;
            output.push(bit);
        }
    }

    output
}

// The whole purpose of this function is to enforce via unit tests that no x == 0 exists
// It does its job by allowing the injection of sampling functions for x (and coeff)
// See share_with_samplers_rejects_zero_x_coordinate
fn share_with_samplers<SC, SX>(
    secret: &[u8; λ],
    threshold: u64,
    total_shares: u64,
    mut sample_coeff: SC,
    mut sample_x: SX,
) -> Vec<(Vec<u8>, Vec<u8>)>
where
    SC: FnMut() -> F,
    SX: FnMut() -> F,
{
    let (t, n) = (threshold, total_shares);

    // let us sample a random degree t-1 polynomial.
    // A degree t - 1 polynomial has t coefficients,
    // which we sample at random
    let mut coeffs: Vec<F> = (0..t).map(|_| sample_coeff()).collect();

    // But we don't want a completely random polynomial,
    // but rather one whose evaluation at x=0 is the secret.
    // So, let us replace zero-th coefficient with our secret.
    let secret_bigint = BigInteger::from_bits_be(&bytes_to_bits_be(secret));
    coeffs[0] = F::from_bigint(secret_bigint).unwrap();

    // we now have all the right coefficients to define the polynomial
    let poly = DensePolynomial { coeffs };

    // let us define a function for serializing polynomial evaluations
    let encode_point = |x: &F| -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        x.serialize_compressed(&mut buffer).unwrap();
        buffer
    };

    // Shamir shares are just evaluations of our polynomial above
    (0..n)
        .map(|_| {
            // If x == 0, then (0, P(0)) = (0, secret). This check ensures that x is never zero.
            // In practice, this loop will execute only once as probability of x being 0 is
            // 1/(2^256), so having this loop executing even twice is neglegible
            let x = loop {
                let candidate = sample_x();
                if !candidate.is_zero() {
                    break candidate;
                }
            };
            let y = poly.evaluate(&x);
            (encode_point(&x), encode_point(&y))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn test_shamir_correctness() {
        // test if recovery on shares produces the shared secret

        //let seed: [u8; 32] = [0; 32];
        let mut rng = thread_rng();

        let mut seed = [0u8; 32];
        rng.fill(&mut seed);

        let mut secret: [u8; 32] = [0u8; 32];
        rng.fill(&mut secret);

        let mut rng = rand_chacha::ChaCha8Rng::from_seed(seed);

        let shares = share(&secret, 3, 5, &mut rng);
        let recovered = recover(shares);

        assert_eq!(secret, recovered);
    }

    #[test]
    fn share_with_samplers_rejects_zero_x_coordinate() {
        let scripted = vec![
            F::zero(),      // must be skipped
            F::zero(),      // must be skipped
            F::from(42u64), // used for share 0
            F::from(43u64), // used for share 1
            F::from(44u64), // used for share 2
        ];
        let mut iter = scripted.into_iter();
        let sample_x = || iter.next().expect("ran out of scripted x values");

        let mut coeff_iter = vec![F::from(1u64), F::from(2u64)].into_iter();
        let sample_coeff = || coeff_iter.next().expect("ran out of scripted coeffs");

        let secret = [7u8; λ];
        let shares = share_with_samplers(&secret, 2, 3, sample_coeff, sample_x);

        assert_eq!(shares.len(), 3);

        let actual_xs: Vec<F> = shares
            .iter()
            .map(|(x_bytes, _)| F::deserialize_compressed(&x_bytes[..]).unwrap())
            .collect();

        let expected_xs: Vec<F> = vec![F::from(42u64), F::from(43u64), F::from(44u64)];
        assert_eq!(actual_xs, expected_xs);

        // Sanity: all x != 0
        for x in &actual_xs {
            assert!(!x.is_zero());
        }
    }
}
