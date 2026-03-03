#[cfg(test)]
mod tests {
    use prost::Message;

    use crate::{
        Error,
        protos::derec_proto::{CommittedDeRecShare, DeRecShare},
        sharing::{ProtectSecretResult, SharingError, protect_secret},
        types::ChannelId,
    };

    #[test]
    fn test_protect_secret_empty_channels() {
        let secret_id = b"secret-id";
        let secret_data = b"secret-data";
        let empty_channels: Vec<ChannelId> = vec![];
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
        let channels: Vec<ChannelId> = vec![1, 2, 3];
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
        let channels: Vec<ChannelId> = vec![1, 2, 3];
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
        let channels: Vec<ChannelId> = vec![1, 2, 3];
        let too_low_threshold = 1; // invalid: must be >= 2
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
        let channels: Vec<ChannelId> = vec![1, 2, 3];
        let too_high_threshold = 4; // invalid: must be <= channels.len()
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
        let channels: Vec<ChannelId> = vec![1, 2, 3];
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
            "invalid number of shares given the number of channels"
        );

        for ch in &channels {
            let msg = shares.get(ch).expect("missing share message for channel");

            assert_eq!(msg.version, version);
            assert_eq!(msg.share_algorithm, 0);
            assert_eq!(msg.keep_list, keep_list.to_vec());
            assert_eq!(msg.version_description, description.to_string());

            let committed = CommittedDeRecShare::decode(&msg.share[..])
                .expect("failed to decode CommittedDeRecShare");

            let inner = DeRecShare::decode(&committed.de_rec_share[..])
                .expect("failed to decode DeRecShare");

            assert_eq!(inner.secret_id, secret_id.to_vec());
            assert_eq!(inner.version, version);

            assert!(!inner.encrypted_secret.is_empty());
            assert!(!inner.x.is_empty());
            assert!(!inner.y.is_empty());

            assert!(!committed.commitment.is_empty());
        }
    }
}

