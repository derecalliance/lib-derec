// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Reading an application's batched secret-store answer.
//!
//! A binding's `loadMany` returns one entry per requested channel, in request
//! order, with an empty entry where nothing of the requested kind is stored.
//! Turning that into the store trait's result — pairing entries with channel
//! ids, and deciding whether an empty entry is an error — happens here, once,
//! for every binding.

use crate::protocol::{MissingPolicy, SecretKind, SecretStoreError, SecretValue};
use crate::types::ChannelId;

/// Pairs each entry with the channel it was requested for and applies
/// `missing_policy` to the empty ones. An answer that does not carry exactly
/// one entry per requested channel is refused rather than guessed at.
pub(crate) fn collect<T, E: std::fmt::Display>(
    requested: &[ChannelId],
    entries: Vec<Option<T>>,
    kind: SecretKind,
    missing_policy: MissingPolicy,
    decode: impl Fn(T) -> Result<SecretValue, E>,
) -> Result<Vec<(ChannelId, SecretValue)>, SecretStoreError> {
    if entries.len() != requested.len() {
        return Err(SecretStoreError::Backend(
            format!(
                "loadMany must return one entry per requested channel: requested {}, got {}",
                requested.len(),
                entries.len()
            )
            .into(),
        ));
    }
    let mut found = Vec::with_capacity(requested.len());
    let mut missing = Vec::new();
    for (&channel_id, entry) in requested.iter().zip(entries) {
        match entry {
            None => missing.push(channel_id.0),
            Some(raw) => {
                let value = decode(raw)
                    .map_err(|e| SecretStoreError::Backend(format!("SecretValue: {e}").into()))?;
                found.push((channel_id, value));
            }
        }
    }
    if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
        return Err(SecretStoreError::MissingEntries {
            kind,
            channel_ids: missing,
        });
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Result<SecretValue, String> {
        Ok(SecretValue::SharedKey([byte; 32]))
    }

    #[test]
    fn entries_pair_with_the_channels_they_were_requested_for() {
        let ids = [ChannelId(7), ChannelId(9)];
        let got = collect(
            &ids,
            vec![Some(1u8), Some(2u8)],
            SecretKind::SharedKey,
            MissingPolicy::Fail,
            key,
        )
        .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, ChannelId(7));
        assert!(matches!(got[1].1, SecretValue::SharedKey(k) if k == [2; 32]));
    }

    #[test]
    fn the_missing_policy_decides_whether_an_empty_entry_is_an_error() {
        let ids = [ChannelId(7), ChannelId(9)];
        let skipped = collect(
            &ids,
            vec![None, Some(2u8)],
            SecretKind::SharedKey,
            MissingPolicy::Skip,
            key,
        )
        .unwrap();
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].0, ChannelId(9));

        let failed = collect(
            &ids,
            vec![None, Some(2u8)],
            SecretKind::SharedKey,
            MissingPolicy::Fail,
            key,
        );
        assert!(matches!(
            failed,
            Err(SecretStoreError::MissingEntries { channel_ids, .. }) if channel_ids == vec![7]
        ));
    }

    #[test]
    fn an_answer_of_the_wrong_length_is_refused() {
        let ids = [ChannelId(7), ChannelId(9)];
        for entries in [vec![Some(1u8)], vec![Some(1u8), Some(2u8), Some(3u8)]] {
            assert!(matches!(
                collect(
                    &ids,
                    entries,
                    SecretKind::SharedKey,
                    MissingPolicy::Skip,
                    key
                ),
                Err(SecretStoreError::Backend(_))
            ));
        }
    }
}
