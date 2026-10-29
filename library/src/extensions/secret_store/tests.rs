// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

use super::SecretStoreExt as _;
use crate::protocol::tests::{InMemSecretStore, run_async};
use crate::protocol::{DeRecSecretStore as _, PairingKeyMaterial, SecretValue};
use crate::types::ChannelId;
use crate::types::SharedKey;

const SECRET_ID: u64 = 0x5EC;
const CHANNEL: ChannelId = ChannelId(7);

/// A stored shared key is returned by both reads.
#[test]
fn a_stored_key_is_read() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::SharedKey(SharedKey::new([9; 32])),
            )
            .await
            .expect("save");

        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            Some(SharedKey::new([9; 32]))
        );
        assert_eq!(
            secrets.paired_key(SECRET_ID, CHANNEL).await.expect("read"),
            crate::types::SharedKey::new([9; 32])
        );
    });
}

/// A channel holding only its pairing secret has no shared key: it is not
/// paired yet.
#[test]
fn a_channel_without_a_shared_key_is_not_paired() {
    run_async(async {
        let mut secrets = InMemSecretStore::default();
        secrets
            .save(
                SECRET_ID,
                CHANNEL,
                SecretValue::PairingSecret(PairingKeyMaterial::from_bytes(vec![1, 2, 3])),
            )
            .await
            .expect("save");

        assert_eq!(
            secrets.shared_key(SECRET_ID, CHANNEL).await.expect("read"),
            None
        );
        assert!(matches!(
            secrets.paired_key(SECRET_ID, CHANNEL).await,
            Err(crate::Error::InvalidInput(_))
        ));
    });
}
