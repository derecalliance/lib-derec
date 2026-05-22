// SPDX-License-Identifier: Apache-2.0

pub mod discovery;
pub mod pairing;
pub mod recovery;
pub mod sharing;
pub mod unpairing;
pub mod verification;

#[cfg(test)]
pub(crate) fn make_shared_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}
