use crate::{
    Error,
    derec_message::extract_inner_message,
    sharing::{ProtectSecretResult, SharingError, protect_secret},
    types::ChannelId,
};
use derec_proto::{CommittedDeRecShare, DeRecShare, StoreShareRequestMessage};
use prost::Message;
use std::collections::HashMap;

fn make_channels(ids: &[u64]) -> HashMap<ChannelId, [u8; 32]> {
    let mut channels = HashMap::new();

    for id in ids {
        let mut key = [0u8; 32];
        key[24..].copy_from_slice(&id.to_be_bytes());
        channels.insert(ChannelId(*id), key);
    }

    channels
}

#[test]
fn test_protect_secret_empty_channels() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let empty_channels: HashMap<ChannelId, [u8; 32]> = HashMap::new();
    let threshold = 2;
    let version = 1;

    let result = protect_secret(
        secret_id,
        secret_data,
        &empty_channels,
        threshold,
        version,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptyChannels))
    ));
}

#[test]
fn test_protect_secret_empty_secret_id() {
    let empty_secret_id = b"";
    let secret_data = b"secret-data";
    let channels = make_channels(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(
        empty_secret_id,
        secret_data,
        &channels,
        threshold,
        version,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptySecretId))
    ));
}

#[test]
fn test_protect_secret_empty_secret_data() {
    let secret_id = b"secret-id";
    let empty_secret_data = b"";
    let channels = make_channels(&[1, 2, 3]);
    let threshold = 2;
    let version = 1;

    let result = protect_secret(
        secret_id,
        empty_secret_data,
        &channels,
        threshold,
        version,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::EmptySecretData))
    ));
}

#[test]
fn test_protect_secret_invalid_threshold_too_low() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channels(&[1, 2, 3]);
    let too_low_threshold = 1;
    let version = 1;

    let result = protect_secret(
        secret_id,
        secret_data,
        &channels,
        too_low_threshold,
        version,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 1,
            channels: 3
        }))
    ));
}

#[test]
fn test_protect_secret_invalid_threshold_too_high() {
    let secret_id = b"secret-id";
    let secret_data = b"secret-data";
    let channels = make_channels(&[1, 2, 3]);
    let too_high_threshold = 4;
    let version = 1;

    let result = protect_secret(
        secret_id,
        secret_data,
        &channels,
        too_high_threshold,
        version,
        None,
        None,
    );

    assert!(matches!(
        result,
        Err(Error::Sharing(SharingError::InvalidThreshold {
            threshold: 4,
            channels: 3
        }))
    ));
}

#[test]
fn test_protect_secret_valid_sharing() {
    let secret_id = b"my_secret_id";
    let secret_data = b"super_secret_value";
    let channels = make_channels(&[1, 2, 3]);
    let threshold = 2;
    let version = 7;
    let keep_list = [1, 2, 3];
    let description = "v7 initial distribution";

    let ProtectSecretResult { shares } = protect_secret(
        secret_id,
        secret_data,
        &channels,
        threshold,
        version,
        Some(&keep_list),
        Some(description),
    )
    .expect("protect_secret should succeed");

    assert_eq!(
        shares.len(),
        channels.len(),
        "invalid number of share envelopes given the number of channels"
    );

    for (channel_id, shared_key) in &channels {
        let wire_bytes = shares
            .get(channel_id)
            .expect("missing DeRecMessage envelope for channel");

        let (envelope, msg): (_, StoreShareRequestMessage) =
            extract_inner_message(wire_bytes, shared_key)
                .expect("failed to decrypt and decode StoreShareRequestMessage");

        assert!(
            envelope.timestamp.is_some(),
            "outer DeRecMessage envelope timestamp must be present"
        );
        assert!(
            msg.timestamp.is_some(),
            "inner StoreShareRequestMessage timestamp must be present"
        );
        assert_eq!(
            envelope.timestamp, msg.timestamp,
            "envelope timestamp must match StoreShareRequestMessage timestamp"
        );

        assert_eq!(msg.version, version);
        assert_eq!(msg.share_algorithm, 0);
        assert_eq!(msg.keep_list, keep_list.to_vec());
        assert_eq!(msg.version_description, description.to_string());

        let committed = CommittedDeRecShare::decode(&msg.share[..])
            .expect("failed to decode CommittedDeRecShare");

        let inner =
            DeRecShare::decode(&committed.de_rec_share[..]).expect("failed to decode DeRecShare");

        assert_eq!(inner.secret_id, secret_id.to_vec());
        assert_eq!(inner.version, version);

        assert!(
            !inner.encrypted_secret.is_empty(),
            "encrypted_secret must not be empty"
        );
        assert!(!inner.x.is_empty(), "share x coordinate must not be empty");
        assert!(!inner.y.is_empty(), "share y coordinate must not be empty");

        assert!(
            !committed.commitment.is_empty(),
            "commitment must not be empty"
        );
    }
}
