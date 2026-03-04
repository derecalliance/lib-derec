// SPDX-License-Identifier: Apache-2.0

pub mod pairing;
pub mod protos;
pub mod recovery;
pub mod sharing;
mod ts_bindings_utils;
pub mod types;
pub mod verification;

mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
