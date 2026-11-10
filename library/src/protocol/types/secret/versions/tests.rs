// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use std::io::{self, Read, Write};

use flate2::{Compression, read::GzDecoder, write::GzEncoder};

use super::{SecretError, decode, read_json};

fn gzip(parts: &[&[u8]]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    for part in parts {
        enc.write_all(part).unwrap();
    }
    enc.finish().unwrap()
}

/// Counts the inflated bytes the decoder pulls.
struct Counting<R> {
    inner: R,
    read: usize,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

/// A payload that inflates to 64 MiB of zeros from about 64 KB. It is not
/// JSON, so the decoder must refuse it after its first bytes instead of
/// inflating all of it first.
#[test]
fn a_payload_that_is_not_json_is_refused_without_inflating_it() {
    let zeros = vec![0u8; 64 << 20];
    let bomb = gzip(&[&zeros]);
    let mut counting = Counting {
        inner: GzDecoder::new(bomb.as_slice()),
        read: 0,
    };

    let result = read_json::<serde_json::Value>(&mut counting);

    assert!(matches!(result, Err(SecretError::Json(_))), "{result:?}");
    assert!(
        counting.read < 1 << 20,
        "inflated {} bytes before refusing",
        counting.read
    );
}

/// The gzip trailer is still checked once the JSON has been parsed.
#[test]
fn a_truncated_payload_is_a_decompression_error() {
    let mut payload = gzip(&[br#"{"helpers":[],"secrets":[]}"#]);
    payload.truncate(payload.len() - 4);

    let result = decode(3, &payload);

    assert!(
        matches!(result, Err(SecretError::Decompression)),
        "{result:?}"
    );
}

#[test]
fn bytes_after_the_json_are_refused() {
    let payload = gzip(&[br#"{"helpers":[],"secrets":[]} trailing"#]);

    let result = decode(3, &payload);

    assert!(matches!(result, Err(SecretError::Json(_))), "{result:?}");
}

#[test]
fn whitespace_around_the_json_is_accepted() {
    let padding = vec![b' '; 1 << 20];
    let payload = gzip(&[&padding, br#"{"helpers":[],"secrets":[]}"#, &padding]);

    assert!(decode(3, &payload).is_ok());
    assert!(decode(2, &payload).is_ok());
}
